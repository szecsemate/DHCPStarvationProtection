"""A configurable IPv4 DHCP server with persisted leases and reservations."""

import argparse
import ipaddress
import json
import logging
import os
import socket
import struct
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

LOG = logging.getLogger("dhcp-server")
# BOOTP's fixed 236-byte header; DHCP options follow its four-byte magic cookie.
BOOTREQUEST = struct.Struct("!BBBBIHH4s4s4s4s16s64s128s")
MAGIC_COOKIE = b"\x63\x82\x53\x63"
ZERO_IP = b"\0" * 4
BROADCAST_IP = ipaddress.IPv4Address("255.255.255.255")

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7


@dataclass
class Lease:
    """A client address and its monotonic expiry time."""

    address: ipaddress.IPv4Address
    expires_at: float


def parse_options(packet):
    """Decode DHCP options, rejecting malformed or truncated option data."""
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
    """Encode a DHCP option's tag, one-byte length, and payload."""
    if len(value) > 255:
        raise ValueError("DHCP option value is too long")
    return bytes((code, len(value))) + value


def parse_mac(value):
    """Parse a colon-, hyphen-, or separator-free MAC address."""
    normalized = value.replace(":", "").replace("-", "").replace(".", "")
    try:
        address = bytes.fromhex(normalized)
    except ValueError as error:
        raise ValueError("invalid MAC address {!r}".format(value)) from error
    if len(address) != 6:
        raise ValueError("MAC address must contain exactly six bytes")
    return address


def parse_reservation(value):
    """Parse a command-line reservation in MAC=IPv4 form."""
    try:
        mac, address = value.split("=", 1)
    except ValueError as error:
        raise ValueError("reservation must use MAC=IPv4 format") from error
    return parse_mac(mac), ipaddress.IPv4Address(address)


class DHCPServer:
    """Serve basic DHCP exchanges with persistent leases and static reservations."""

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
            or self.server_ip in range(int(self.pool_start), int(self.pool_end) + 1)
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
                domain_name.encode("ascii")
            except UnicodeEncodeError as error:
                raise ValueError("domain name must contain ASCII characters") from error
            if not domain_name or len(domain_name.encode("ascii")) > 255:
                raise ValueError("domain name must be 1 to 255 ASCII bytes")

        self.lease_seconds = lease_seconds
        self.decline_hold_seconds = decline_hold_seconds
        if not 1 <= lease_seconds <= 0xFFFFFFFF:
            raise ValueError("lease duration must be between 1 and 4294967295 seconds")
        if not 1 <= decline_hold_seconds <= 0xFFFFFFFF:
            raise ValueError("decline hold must be between 1 and 4294967295 seconds")
        if not 1 <= port <= 65535:
            raise ValueError("UDP port must be between 1 and 65535")
        self.bind_address = bind_address
        self.port = port
        self.lease_file = Path(lease_file) if lease_file else None
        self.reservations = {}
        self.reserved_addresses = {}
        for client, address in reservations:
            client = parse_mac(client) if isinstance(client, str) else bytes(client)
            address = ipaddress.IPv4Address(address)
            if len(client) != 6:
                raise ValueError("reservation client identifier must be a six-byte MAC")
            if (
                address not in self.network
                or address in (self.network.network_address, self.network.broadcast_address)
                or address == self.server_ip
            ):
                raise ValueError("reserved addresses must be usable addresses in the subnet")
            if client in self.reservations:
                raise ValueError("duplicate reservation for {}".format(client.hex(":")))
            if address in self.reserved_addresses:
                raise ValueError("address {} is reserved more than once".format(address))
            self.reservations[client] = address
            self.reserved_addresses[address] = client

        self.leases = {}
        self.quarantined = {}
        self._lock = threading.RLock()
        if self.lease_file is not None:
            self.load_state()

    def _lease_address_is_valid(self, client, address):
        if address is None or address not in self.network:
            return False
        if address in (self.network.network_address, self.network.broadcast_address):
            return False
        if address == self.server_ip or address in self.quarantined:
            return False
        reserved_for = self.reserved_addresses.get(address)
        if reserved_for is not None:
            return reserved_for == client
        if client in self.reservations:
            return False
        return int(self.pool_start) <= int(address) <= int(self.pool_end)

    def _persist_state(self):
        """Atomically replace the state file so interrupted writes don't corrupt it."""
        if self.lease_file is None:
            return
        now_mono = time.monotonic()
        now_wall = time.time()
        state = {
            "version": 1,
            "leases": [
                {
                    "client": client.hex(),
                    "address": str(lease.address),
                    "expires_at": now_wall + lease.expires_at - now_mono,
                }
                for client, lease in self.leases.items()
            ],
            "quarantined": [
                {"address": str(address), "expires_at": now_wall + expiry - now_mono}
                for address, expiry in self.quarantined.items()
            ],
        }
        self.lease_file.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=str(self.lease_file.parent),
                prefix=self.lease_file.name + ".",
                suffix=".tmp",
                delete=False,
            ) as state_file:
                temp_path = Path(state_file.name)
                json.dump(state, state_file, indent=2)
                state_file.write("\n")
                state_file.flush()
                os.fsync(state_file.fileno())
            os.replace(str(temp_path), str(self.lease_file))
        finally:
            if temp_path is not None and temp_path.exists():
                temp_path.unlink()

    def load_state(self):
        """Load valid, unexpired leases and quarantines from the JSON state file."""
        try:
            with self.lease_file.open("r", encoding="utf-8") as state_file:
                state = json.load(state_file)
        except FileNotFoundError:
            return
        if not isinstance(state, dict) or state.get("version") != 1:
            raise ValueError("unsupported or invalid DHCP lease file format")
        if not isinstance(state.get("leases"), list) or not isinstance(
            state.get("quarantined"), list
        ):
            raise ValueError("DHCP lease file must contain lease and quarantine lists")

        now_wall = time.time()
        now_mono = time.monotonic()
        loaded = {}
        used_addresses = set()
        for item in state["leases"]:
            try:
                client = bytes.fromhex(item["client"])
                address = ipaddress.IPv4Address(item["address"])
                remaining = float(item["expires_at"]) - now_wall
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("invalid entry in DHCP lease file") from error
            if len(client) != 6 or remaining <= 0:
                continue
            if not (remaining < float("inf")):
                raise ValueError("lease expiry must be a finite timestamp")
            if client in loaded:
                LOG.warning("Ignoring duplicate persisted lease for client %s", client.hex())
                continue
            if not self._lease_address_is_valid(client, address):
                LOG.warning("Ignoring persisted lease for invalid address %s", address)
                continue
            if address in used_addresses:
                LOG.warning("Ignoring duplicate persisted lease for %s", address)
                continue
            loaded[client] = Lease(address, now_mono + remaining)
            used_addresses.add(address)

        quarantined = {}
        for item in state["quarantined"]:
            try:
                address = ipaddress.IPv4Address(item["address"])
                remaining = float(item["expires_at"]) - now_wall
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("invalid quarantine entry in DHCP lease file") from error
            if (
                remaining > 0
                and remaining < float("inf")
                and address in self.network
                and (
                    int(self.pool_start) <= int(address) <= int(self.pool_end)
                    or address in self.reserved_addresses
                )
                and address != self.server_ip
            ):
                quarantined[address] = now_mono + remaining
        self.quarantined = quarantined
        # Declined addresses must not remain active leases after a restart.
        self.leases = {
            client: lease
            for client, lease in loaded.items()
            if lease.address not in self.quarantined
        }

    def expire_leases(self):
        """Remove expired leases and quarantines, persisting changes when needed."""
        with self._lock:
            now = time.monotonic()
            old_lease_count = len(self.leases)
            old_quarantine_count = len(self.quarantined)
            self.leases = {
                client: lease
                for client, lease in self.leases.items()
                if lease.expires_at > now
            }
            self.quarantined = {
                address: expiry
                for address, expiry in self.quarantined.items()
                if expiry > now
            }
            if (
                len(self.leases) != old_lease_count
                or len(self.quarantined) != old_quarantine_count
            ):
                self._persist_state()

    def allocate_address(self, client):
        """Return a reservation or the first free, non-quarantined pool address."""
        with self._lock:
            self.expire_leases()
            lease = self.leases.get(client)
            if lease is not None:
                return lease.address

            used = {lease.address for lease in self.leases.values()}
            reserved = self.reservations.get(client)
            if reserved is not None:
                if reserved in used or reserved in self.quarantined:
                    return None
                address = reserved
            else:
                address = None
                for value in range(int(self.pool_start), int(self.pool_end) + 1):
                    candidate = ipaddress.IPv4Address(value)
                    if (
                        candidate not in used
                        and candidate not in self.reserved_addresses
                        and candidate not in self.quarantined
                    ):
                        address = candidate
                        break
            if address is None:
                return None
            self.leases[client] = Lease(address, time.monotonic() + self.lease_seconds)
            self._persist_state()
            return address

    def assign_address(self, client, address):
        """Validate and renew an address without conflicting with another lease."""
        with self._lock:
            self.expire_leases()
            if not self._lease_address_is_valid(client, address):
                return False
            if any(
                owner != client and lease.address == address
                for owner, lease in self.leases.items()
            ):
                return False
            self.leases[client] = Lease(address, time.monotonic() + self.lease_seconds)
            self._persist_state()
            return True

    def _remove_lease(self, client):
        if self.leases.pop(client, None) is not None:
            self._persist_state()

    def build_reply(self, header, message_type, address=None):
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
            options.extend(encode_option(51, struct.pack("!I", self.lease_seconds)))
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

    def handle_packet(self, packet, sock):
        """Process one DHCP client packet and send a reply when appropriate."""
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
        with self._lock:
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
                    response = self.build_reply(header, response_type, address)
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
                if current is not None and current.address == address:
                    self.leases.pop(client, None)
                    self.quarantined[address] = (
                        time.monotonic() + self.decline_hold_seconds
                    )
                    self._persist_state()
                    LOG.warning("Quarantined declined address %s", address)
                return
            elif message_type == DHCP_RELEASE:
                current = self.leases.get(client)
                if current is not None and (
                    header[7] == ZERO_IP
                    or ipaddress.IPv4Address(header[7]) == current.address
                ):
                    self._remove_lease(client)
                return
            else:
                return

        sock.sendto(response, self._response_destination(header, response_type))

    def serve_forever(self):
        """Bind the UDP socket and process packets until interrupted or stopped."""
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
                except OSError:
                    LOG.exception("Failed to persist DHCP state or send a reply")


def parse_args():
    parser = argparse.ArgumentParser(description="A configurable IPv4 DHCP server")
    parser.add_argument("--server-ip", required=True, help="IPv4 address of this server")
    parser.add_argument("--pool-start", required=True, help="First dynamic IPv4 address")
    parser.add_argument("--pool-end", required=True, help="Last dynamic IPv4 address")
    parser.add_argument("--subnet-mask", required=True, help="Subnet mask, e.g. 255.255.255.0")
    parser.add_argument("--router", help="Default gateway (defaults to --server-ip)")
    parser.add_argument("--dns", action="append", default=[], help="DNS server; may be repeated")
    parser.add_argument("--ntp", action="append", default=[], help="NTP server; may be repeated")
    parser.add_argument("--domain-name", help="DNS domain name advertised to clients")
    parser.add_argument(
        "--reservation",
        action="append",
        default=[],
        metavar="MAC=IPv4",
        help="Static client address reservation; may be repeated",
    )
    parser.add_argument("--lease-seconds", type=int, default=3600)
    parser.add_argument("--decline-hold-seconds", type=int, default=3600)
    parser.add_argument(
        "--lease-file",
        default="dhcp_leases.json",
        help="JSON file used to persist leases and declined addresses",
    )
    parser.add_argument("--bind-address", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=67, help="UDP port (default: 67)")
    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    args = parse_args()
    if not 1 <= args.lease_seconds <= 0xFFFFFFFF:
        raise SystemExit("--lease-seconds must be between 1 and 4294967295")
    if not 1 <= args.decline_hold_seconds <= 0xFFFFFFFF:
        raise SystemExit("--decline-hold-seconds must be between 1 and 4294967295")
    if not 1 <= args.port <= 65535:
        raise SystemExit("--port must be between 1 and 65535")
    try:
        reservations = [parse_reservation(value) for value in args.reservation]
        server = DHCPServer(
            server_ip=args.server_ip,
            pool_start=args.pool_start,
            pool_end=args.pool_end,
            subnet_mask=args.subnet_mask,
            router=args.router,
            dns_servers=args.dns,
            ntp_servers=args.ntp,
            domain_name=args.domain_name,
            lease_seconds=args.lease_seconds,
            decline_hold_seconds=args.decline_hold_seconds,
            bind_address=args.bind_address,
            port=args.port,
            lease_file=args.lease_file,
            reservations=reservations,
        )
        server.serve_forever()
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as error:
        raise SystemExit("Configuration or lease-file error: {}".format(error))
    except OSError as error:
        raise SystemExit("Could not start DHCP server: {}".format(error))


if __name__ == "__main__":
    main()
