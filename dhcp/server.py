"""DHCP configuration validation, message handling, and UDP server loop."""

import ipaddress
import logging
import secrets
import socket
import struct
import threading

from .protocol import (
    BOOTREQUEST,
    BROADCAST_IP,
    DHCP_ACK,
    DHCP_DECLINE,
    DHCP_DISCOVER,
    DHCP_FORCERENEW,
    DHCP_MESSAGE_TYPES,
    DHCP_NAK,
    DHCP_OFFER,
    DHCP_RELEASE,
    DHCP_REQUEST,
    MAGIC_COOKIE,
    ZERO_IP,
    encode_option,
    parse_options,
)
from .leases import LeaseManager

LOG = logging.getLogger("dhcp-server")


class DHCPServer:
    """Serve DHCP packets using a separate lease manager for address state."""

    def __init__(
        self,
        server_ip,
        pool_start,
        pool_end,
        subnet_mask,
        router=None,
        dns_servers=(),
        lease_seconds=3600,
        bind_address="0.0.0.0",
        port=67,
        lease_file="dhcp_leases.json",
        reservations=(),
        decline_hold_seconds=3600,
        domain_name=None,
        ntp_servers=(),
        interface=None,
    ):
        self.server_ip = ipaddress.IPv4Address(server_ip)
        self.network = ipaddress.IPv4Network(
            "{}/{}".format(self.server_ip, subnet_mask), strict=False
        )
        self.pool_start = ipaddress.IPv4Address(pool_start)
        self.pool_end = ipaddress.IPv4Address(pool_end)
        if self.network.num_addresses < 4:
            raise ValueError("subnet must have at least four addresses")
        if (
            int(self.pool_start) > int(self.pool_end)
            or self.pool_start not in self.network
            or self.pool_end not in self.network
            or int(self.pool_start) <= int(self.network.network_address)
            or int(self.pool_end) >= int(self.network.broadcast_address)
            or self.pool_start <= self.server_ip <= self.pool_end
        ):
            raise ValueError("address pool must be ordered, usable, and in the subnet")

        self.router = ipaddress.IPv4Address(router or self.server_ip)
        if self.router not in self.network:
            raise ValueError("router must be in the server subnet")
        self.dns_servers = tuple(ipaddress.IPv4Address(value) for value in dns_servers)
        self.ntp_servers = tuple(ipaddress.IPv4Address(value) for value in ntp_servers)
        if len(self.dns_servers) > 63 or len(self.ntp_servers) > 63:
            raise ValueError("no more than 63 DNS or NTP servers can be configured")
        self.domain_name = domain_name
        if domain_name is not None:
            try:
                encoded_domain = domain_name.encode("ascii")
            except UnicodeEncodeError as error:
                raise ValueError("domain name must contain ASCII characters") from error
            if not encoded_domain or len(encoded_domain) > 255:
                raise ValueError("domain name must be 1 to 255 ASCII bytes")

        if not 1 <= lease_seconds <= 0xFFFFFFFF:
            raise ValueError("lease duration must be between 1 and 4294967295 seconds")
        if not 1 <= decline_hold_seconds <= 0xFFFFFFFF:
            raise ValueError("decline hold must be between 1 and 4294967295 seconds")
        if not 1 <= port <= 65535:
            raise ValueError("UDP port must be between 1 and 65535")
        self.lease_seconds = lease_seconds
        self.bind_address = bind_address
        self.port = port
        if interface is not None and not interface:
            raise ValueError("DHCP interface name must not be empty")
        if interface is not None and bind_address != "0.0.0.0":
            raise ValueError(
                "--dhcp-interface requires --bind-address 0.0.0.0 to receive broadcasts"
            )
        self.interface = interface
        self.packet_callback = None
        self._socket = None
        self._socket_lock = threading.Lock()
        self.lease_manager = LeaseManager(
            network=self.network,
            server_ip=self.server_ip,
            pool_start=self.pool_start,
            pool_end=self.pool_end,
            lease_seconds=lease_seconds,
            decline_hold_seconds=decline_hold_seconds,
            lease_file=lease_file,
            reservations=reservations,
        )

    @property
    def leases(self):
        """Expose active leases for callers that inspect server state."""
        return self.lease_manager.leases

    @property
    def quarantined(self):
        """Expose declined-address quarantine state for callers and diagnostics."""
        return self.lease_manager.quarantined

    def expire_leases(self):
        """Expire leases and quarantines through the lease manager."""
        self.lease_manager.expire()

    def allocate_address(self, client):
        """Allocate an address through the lease manager."""
        return self.lease_manager.allocate(client)

    def assign_address(self, client, address):
        """Assign or renew an address through the lease manager."""
        return self.lease_manager.assign(client, address)

    def build_reply(self, header, message_type, address=None, lease_seconds=None):
        """Encode a BOOTP reply and the options advertised by this server."""
        _, htype, hlen, hops, xid, secs, flags, ciaddr, _, _, giaddr, chaddr, _, _ = header
        if message_type == DHCP_NAK:
            ciaddr = ZERO_IP
        yiaddr = address.packed if address is not None else ZERO_IP
        reply = BOOTREQUEST.pack(
            2,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            self.server_ip.packed,
            giaddr,
            chaddr,
            b"\0" * 64,
            b"\0" * 128,
        )
        options = bytearray(MAGIC_COOKIE)
        options.extend(encode_option(53, bytes((message_type,))))
        options.extend(encode_option(54, self.server_ip.packed))
        if message_type in (DHCP_OFFER, DHCP_ACK):
            options.extend(
                encode_option(
                    51,
                    struct.pack(
                        "!I", lease_seconds if lease_seconds is not None else self.lease_seconds
                    ),
                )
            )
            options.extend(encode_option(1, self.network.netmask.packed))
            options.extend(encode_option(3, self.router.packed))
            options.extend(encode_option(28, self.network.broadcast_address.packed))
            if self.dns_servers:
                options.extend(
                    encode_option(
                        6, b"".join(server.packed for server in self.dns_servers)
                    )
                )
            if self.ntp_servers:
                options.extend(
                    encode_option(
                        42, b"".join(server.packed for server in self.ntp_servers)
                    )
                )
            if self.domain_name:
                options.extend(encode_option(15, self.domain_name.encode("ascii")))
        options.append(255)
        return reply + options

    def _response_destination(self, header, message_type):
        """Choose a relay, client, or broadcast destination for a server reply."""
        giaddr = ipaddress.IPv4Address(header[10])
        ciaddr = ipaddress.IPv4Address(header[7])
        if giaddr != ipaddress.IPv4Address("0.0.0.0"):
            return str(giaddr), 67
        if (
            message_type == DHCP_NAK
            or header[6] & 0x8000
            or ciaddr == ipaddress.IPv4Address("0.0.0.0")
        ):
            return str(BROADCAST_IP), 68
        return str(ciaddr), 68

    def _log_packet(
        self,
        direction,
        packet_type,
        source_address,
        destination_address,
        client_mac=None,
    ):
        if self.packet_callback is not None:
            self.packet_callback(
                direction=direction,
                packet_type=packet_type,
                source_address=str(source_address[0]),
                destination_address=str(destination_address[0]),
                client_mac=client_mac,
            )

    def send_forcerenew(self, client, address):
        """Ask a DHCP client to renew its lease using RFC 3203 DHCPFORCERENEW."""
        if len(client) != 6:
            raise ValueError("DHCPFORCERENEW requires a six-byte Ethernet MAC")
        address = ipaddress.IPv4Address(address)
        header = BOOTREQUEST.pack(
            2,
            1,
            6,
            0,
            secrets.randbits(32),
            0,
            0,
            address.packed,
            ZERO_IP,
            self.server_ip.packed,
            ZERO_IP,
            client.ljust(16, b"\0"),
            b"\0" * 64,
            b"\0" * 128,
        )
        response = (
            header
            + MAGIC_COOKIE
            + encode_option(53, bytes((DHCP_FORCERENEW,)))
            + encode_option(54, self.server_ip.packed)
            + b"\xff"
        )
        destination = (str(address), 68)
        with self._socket_lock:
            sock = self._socket
        if sock is None:
            raise OSError("DHCP socket is not running; cannot notify the client")
        LOG.info("Sending DHCPFORCERENEW to %s for %s", address, client.hex(":"))
        sent_bytes = sock.sendto(response, destination)
        LOG.info(
            "Sent DHCPFORCERENEW (%d bytes) to %s:68 for %s",
            sent_bytes,
            address,
            client.hex(":"),
        )
        self._log_packet(
            "sent",
            "DHCPFORCERENEW",
            (str(self.server_ip), self.port),
            destination,
            client.hex(":"),
        )

    @staticmethod
    def _packet_type(packet):
        try:
            message = parse_options(packet).get(53)
        except ValueError:
            return "MALFORMED"
        if message is None or len(message) != 1:
            return "UNKNOWN"
        return DHCP_MESSAGE_TYPES.get(message[0], "UNKNOWN")

    def handle_packet(
        self,
        packet,
        sock,
        source_address=("0.0.0.0", 0),
        destination_address=None,
    ):
        """Process one DHCP client packet and send a reply when appropriate."""
        if destination_address is None or destination_address[0] == "0.0.0.0":
            destination_address = (str(self.server_ip), self.port)
        packet_type = self._packet_type(packet)
        client_mac = None
        if len(packet) >= BOOTREQUEST.size:
            packet_header = BOOTREQUEST.unpack(packet[: BOOTREQUEST.size])
            if packet_header[1] == 1 and packet_header[2] == 6:
                client_mac = packet_header[11][:6].hex(":")
        LOG.info(
            "Received %s from %s:%d on %s:%d",
            packet_type,
            source_address[0],
            source_address[1],
            destination_address[0],
            destination_address[1],
        )
        self._log_packet(
            "received",
            packet_type,
            source_address,
            destination_address,
            client_mac,
        )
        if len(packet) < BOOTREQUEST.size:
            raise ValueError("packet is shorter than the BOOTP header")
        header = BOOTREQUEST.unpack(packet[: BOOTREQUEST.size])
        op, htype, hlen = header[:3]
        if op != 1 or hlen == 0 or hlen > 16:
            raise ValueError("unsupported BOOTP request")
        if htype == 1 and hlen != 6:
            raise ValueError("invalid Ethernet hardware address length")
        options = parse_options(packet)
        message = options.get(53)
        if message is None or len(message) != 1:
            raise ValueError("missing or invalid DHCP message type")

        client = header[11][:hlen]
        message_type = message[0]
        response = None
        response_type = None
        with self.lease_manager.lock:
            if message_type == DHCP_DISCOVER:
                address = self.allocate_address(client)
                if address is None:
                    LOG.warning("Address pool exhausted; ignoring DHCPDISCOVER")
                    return
                response_type = DHCP_OFFER
                response = self.build_reply(header, response_type, address)
            elif message_type == DHCP_REQUEST:
                server_id = options.get(54)
                if server_id is not None and len(server_id) != 4:
                    raise ValueError("invalid server identifier option")
                # A client selecting another server must not be answered by this one.
                if server_id is not None and server_id != self.server_ip.packed:
                    return
                requested = options.get(50)
                if requested is not None and len(requested) != 4:
                    raise ValueError("invalid requested IP address option")

                current = self.leases.get(client)
                if requested is not None:
                    address = ipaddress.IPv4Address(requested)
                    # Selecting this server or renewing with ciaddr must match
                    # an offer/current lease, not claim an arbitrary free IP.
                    if header[7] != ZERO_IP and (
                        current is None or address != current.address
                    ):
                        address = None
                    elif server_id is not None and (
                        current is None or address != current.address
                    ):
                        address = None
                elif header[7] != ZERO_IP:
                    address = ipaddress.IPv4Address(header[7])
                    if current is None or current.address != address:
                        address = None
                else:
                    address = current.address if current is not None else None

                if self.assign_address(client, address):
                    response_type = DHCP_ACK
                    lease = self.leases.get(client)
                    lease_seconds = (
                        lease.lease_seconds
                        if lease is not None and lease.lease_seconds is not None
                        else self.lease_seconds
                    )
                    response = self.build_reply(
                        header, response_type, address, lease_seconds
                    )
                else:
                    response_type = DHCP_NAK
                    response = self.build_reply(header, response_type)
            elif message_type == DHCP_DECLINE:
                server_id = options.get(54)
                if server_id is not None and len(server_id) != 4:
                    raise ValueError("invalid server identifier option")
                if server_id is not None and server_id != self.server_ip.packed:
                    return
                declined = options.get(50)
                if declined is not None and len(declined) != 4:
                    raise ValueError("invalid declined IP address option")
                current = self.leases.get(client)
                address = (
                    ipaddress.IPv4Address(declined)
                    if declined is not None
                    else current.address if current is not None else None
                )
                if self.lease_manager.decline(client, address):
                    LOG.warning("Quarantined declined address %s", address)
                return
            elif message_type == DHCP_RELEASE:
                current = self.leases.get(client)
                address = ipaddress.IPv4Address(header[7]) if header[7] != ZERO_IP else None
                if current is not None and self.lease_manager.release(client, address):
                    LOG.info("Released address %s for client %s", current.address, client.hex())
                return
            else:
                return

        response_destination = self._response_destination(header, response_type)
        LOG.info(
            "Sending %s to %s:%d",
            DHCP_MESSAGE_TYPES[response_type],
            response_destination[0],
            response_destination[1],
        )
        sent_bytes = sock.sendto(response, response_destination)
        LOG.info(
            "Sent %s (%d bytes) to %s:%d",
            DHCP_MESSAGE_TYPES[response_type],
            sent_bytes,
            response_destination[0],
            response_destination[1],
        )
        self._log_packet(
            "sent",
            DHCP_MESSAGE_TYPES[response_type],
            destination_address,
            response_destination,
            client.hex(":"),
        )

    def serve_forever(self):
        """Bind the UDP socket and process packets until interrupted or stopped."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if self.interface is not None:
                interface_option = getattr(socket, "SO_BINDTODEVICE", None)
                if interface_option is None:
                    raise OSError(
                        "--dhcp-interface is supported only on Linux systems"
                    )
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    interface_option,
                    self.interface.encode("utf-8") + b"\0",
                )
            sock.bind((self.bind_address, self.port))
            LOG.info(
                "Listening on %s:%d%s; offering %s-%s",
                self.bind_address,
                self.port,
                " on interface {}".format(self.interface)
                if self.interface is not None
                else "",
                self.pool_start,
                self.pool_end,
            )
            with self._socket_lock:
                self._socket = sock
            try:
                while True:
                    packet, source_address = sock.recvfrom(4096)
                    try:
                        self.handle_packet(
                            packet,
                            sock,
                            source_address,
                            sock.getsockname(),
                        )
                    except (ValueError, struct.error) as error:
                        LOG.warning("Ignoring malformed DHCP packet: %s", error)
                    except OSError:
                        LOG.exception("DHCP packet handling, logging, or reply failed")
            except KeyboardInterrupt:
                LOG.info("DHCP server stopped")
            finally:
                with self._socket_lock:
                    self._socket = None
