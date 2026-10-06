"""A small IPv4 DHCP server implementing the basic DORA exchange."""

import argparse
import ipaddress
import logging
import socket
import struct
import time
from dataclasses import dataclass

LOG = logging.getLogger("dhcp-server")
# BOOTP's fixed 236-byte header; DHCP options follow its four-byte magic cookie.
BOOTREQUEST = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s")
MAGIC_COOKIE = b"\x63\x82\x53\x63"

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7


@dataclass
class Lease:
    """An in-memory client-to-address mapping with a monotonic expiry time."""

    address: ipaddress.IPv4Address
    expires_at: float


def parse_options(packet):
    """Decode DHCP options, rejecting malformed/truncated option data."""
    if len(packet) < BOOTREQUEST.size + len(MAGIC_COOKIE):
        raise ValueError("packet is shorter than the BOOTP header")
    if packet[BOOTREQUEST.size : BOOTREQUEST.size + 4] != MAGIC_COOKIE:
        raise ValueError("invalid DHCP magic cookie")

    options = {}
    offset = BOOTREQUEST.size + 4
    while offset < len(packet):
        code = packet[offset]
        offset += 1
        if code == 0:
            continue
        if code == 255:
            break
        if offset >= len(packet):
            raise ValueError("missing DHCP option length")
        length = packet[offset]
        offset += 1
        if offset + length > len(packet):
            raise ValueError("truncated DHCP option")
        options[code] = packet[offset : offset + length]
        offset += length
    return options


def encode_option(code, value):
    """Encode one DHCP option's tag, one-byte length, and payload."""
    if len(value) > 255:
        raise ValueError("DHCP option value is too long")
    return bytes((code, len(value))) + value


class DHCPServer:
    """Serve basic DHCP discovery, offer, request, and acknowledgement packets."""

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
            or self.server_ip in (self.pool_start, self.pool_end)
        ):
            raise ValueError("address pool must be ordered, usable, and in the subnet")

        self.router = ipaddress.IPv4Address(router or self.server_ip)
        if self.router not in self.network:
            raise ValueError("router must be in the server subnet")
        self.dns_servers = tuple(ipaddress.IPv4Address(value) for value in dns_servers)
        self.lease_seconds = lease_seconds
        self.bind_address = bind_address
        self.port = port
        self.leases = {}

    def expire_leases(self):
        """Discard expired leases using a clock unaffected by wall-clock changes."""
        now = time.monotonic()
        self.leases = {
            client: lease
            for client, lease in self.leases.items()
            if lease.expires_at > now
        }

    def allocate_address(self, client):
        """Reuse a client's current lease or reserve the first free pool address."""
        self.expire_leases()
        lease = self.leases.get(client)
        if lease is not None:
            return lease.address

        used = {lease.address for lease in self.leases.values()}
        for value in range(int(self.pool_start), int(self.pool_end) + 1):
            address = ipaddress.IPv4Address(value)
            if address != self.server_ip and address not in used:
                self.leases[client] = Lease(
                    address, time.monotonic() + self.lease_seconds
                )
                return address
        return None

    def assign_address(self, client, address):
        """Validate and renew a requested address without stealing another lease."""
        self.expire_leases()
        if address is None or address not in self.network:
            return False
        if not int(self.pool_start) <= int(address) <= int(self.pool_end):
            return False
        if address == self.server_ip:
            return False
        if any(
            owner != client and lease.address == address
            for owner, lease in self.leases.items()
        ):
            return False
        self.leases[client] = Lease(address, time.monotonic() + self.lease_seconds)
        return True

    def build_reply(self, request, header, message_type, address=None):
        """Preserve request identifiers and encode the BOOTP header and DHCP options."""
        _, htype, hlen, hops, xid, secs, flags, ciaddr, _, _, giaddr, chaddr, _, _ = header
        if message_type == DHCP_NAK:
            ciaddr = b"\0" * 4
        yiaddr = address.packed if address is not None else b"\0" * 4
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
            options.extend(encode_option(51, struct.pack("!I", self.lease_seconds)))
            options.extend(encode_option(1, self.network.netmask.packed))
            options.extend(encode_option(3, self.router.packed))
            if self.dns_servers:
                options.extend(
                    encode_option(
                        6, b"".join(server.packed for server in self.dns_servers)
                    )
                )
            options.extend(encode_option(28, self.network.broadcast_address.packed))
        options.append(255)
        return reply + options

    def handle_packet(self, packet, sock):
        """Process one client packet and send the appropriate response, if any."""
        if len(packet) < BOOTREQUEST.size:
            raise ValueError("packet is shorter than the BOOTP header")
        header = BOOTREQUEST.unpack(packet[: BOOTREQUEST.size])
        op, _, hlen = header[:3]
        if op != 1 or hlen == 0 or hlen > 16:
            raise ValueError("unsupported BOOTP request")
        options = parse_options(packet)
        message = options.get(53)
        if message is None or len(message) != 1:
            raise ValueError("missing or invalid DHCP message type")

        # Use only the hardware-address bytes declared by the BOOTP header.
        client = header[11][:hlen]
        message_type = message[0]
        if message_type == DHCP_DISCOVER:
            address = self.allocate_address(client)
            if address is None:
                LOG.warning("Address pool exhausted; ignoring DHCPDISCOVER")
                return
            response_type = DHCP_OFFER
            response = self.build_reply(packet, header, response_type, address)
        elif message_type == DHCP_REQUEST:
            server_id = options.get(54)
            if server_id is not None and len(server_id) != 4:
                raise ValueError("invalid server identifier option")
            if server_id is not None and server_id != self.server_ip.packed:
                return
            requested = options.get(50)
            if requested is not None and len(requested) != 4:
                raise ValueError("invalid requested IP address option")
            if requested is not None:
                address = ipaddress.IPv4Address(requested)
            elif header[7] != b"\0" * 4:
                address = ipaddress.IPv4Address(header[7])
            else:
                current = self.leases.get(client)
                address = current.address if current is not None else None

            if self.assign_address(client, address):
                response_type = DHCP_ACK
                response = self.build_reply(packet, header, response_type, address)
            else:
                self.leases.pop(client, None)
                response_type = DHCP_NAK
                response = self.build_reply(packet, header, response_type)
        elif message_type in (DHCP_RELEASE, DHCP_DECLINE):
            self.leases.pop(client, None)
            return
        else:
            return

        # Replies go to the relay when present, otherwise to the client or broadcast.
        relay_ip = ipaddress.IPv4Address(header[10])
        if response_type == DHCP_NAK:
            destination = ("255.255.255.255", 68)
        elif relay_ip != ipaddress.IPv4Address("0.0.0.0"):
            destination = (str(relay_ip), 67)
        elif header[7] != b"\0" * 4:
            destination = (str(ipaddress.IPv4Address(header[7])), 68)
        else:
            destination = ("255.255.255.255", 68)
        sock.sendto(response, destination)

    def serve_forever(self):
        """Bind the UDP socket and handle packets until interrupted."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind((self.bind_address, self.port))
            LOG.info(
                "Listening on %s:%d; offering %s-%s",
                self.bind_address,
                self.port,
                self.pool_start,
                self.pool_end,
            )
            while True:
                packet, _ = sock.recvfrom(4096)
                try:
                    self.handle_packet(packet, sock)
                except (ValueError, struct.error) as error:
                    LOG.warning("Ignoring malformed DHCP packet: %s", error)


def parse_args():
    parser = argparse.ArgumentParser(description="A minimal IPv4 DHCP server")
    parser.add_argument("--server-ip", required=True, help="IPv4 address of this server")
    parser.add_argument("--pool-start", required=True, help="First assignable IPv4 address")
    parser.add_argument("--pool-end", required=True, help="Last assignable IPv4 address")
    parser.add_argument("--subnet-mask", required=True, help="Subnet mask, e.g. 255.255.255.0")
    parser.add_argument("--router", help="Default gateway (defaults to --server-ip)")
    parser.add_argument("--dns", action="append", default=[], help="DNS server; may be repeated")
    parser.add_argument("--lease-seconds", type=int, default=3600)
    parser.add_argument("--bind-address", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=67, help="DHCP server port (default: 67)")
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = parse_args()
    if not 1 <= args.lease_seconds <= 0xFFFFFFFF:
        raise SystemExit("--lease-seconds must be between 1 and 4294967295")
    if not 1 <= args.port <= 65535:
        raise SystemExit("--port must be between 1 and 65535")
    try:
        server = DHCPServer(
            server_ip=args.server_ip,
            pool_start=args.pool_start,
            pool_end=args.pool_end,
            subnet_mask=args.subnet_mask,
            router=args.router,
            dns_servers=args.dns,
            lease_seconds=args.lease_seconds,
            bind_address=args.bind_address,
            port=args.port,
        )
        server.serve_forever()
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as error:
        raise SystemExit("Configuration error: {}".format(error))
    except OSError as error:
        raise SystemExit("Could not start DHCP server: {}".format(error))


if __name__ == "__main__":
    main()