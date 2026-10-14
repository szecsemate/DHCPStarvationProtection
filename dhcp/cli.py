"""Command-line entry point for the DHCP server."""

import argparse
import ipaddress
import logging

from .protocol import parse_reservation
from .server import DHCPServer
from .siem import SIEMService


def parse_args():
    """Create the command-line parser and read the server configuration."""
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
    parser.add_argument(
        "--dhcp-interface",
        help=(
            "Linux network interface for DHCP broadcasts; use with "
            "--bind-address 0.0.0.0"
        ),
    )
    parser.add_argument("--port", type=int, default=67, help="UDP port (default: 67)")
    parser.add_argument(
        "--http-bind-address",
        default="0.0.0.0",
        help="Lease/SIEM HTTP IPv4 bind address (default: all interfaces)",
    )
    parser.add_argument(
        "--http-port", type=int, default=8080, help="Lease/SIEM HTTP port (default: 8080)"
    )
    parser.add_argument(
        "--siem-log-file",
        default="siem_events.jsonl",
        help="JSON-lines lease/SIEM audit log file",
    )
    parser.add_argument(
        "--dhcp-packet-log-file",
        default="dhcp_packets.jsonl",
        help="Separate JSON-lines log file for received and sent DHCP packets",
    )
    parser.add_argument(
        "--siem-rules-file",
        default="siem_rules.json",
        help="JSON file used to persist SIEM rules",
    )
    parser.add_argument(
        "--siem-interval",
        type=int,
        default=10,
        help="Rule evaluation interval in seconds",
    )
    return parser.parse_args()


def main():
    """Parse configuration, create the server, and run it until interrupted."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    args = parse_args()
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
            interface=args.dhcp_interface,
            lease_file=args.lease_file,
            reservations=reservations,
        )
        siem = SIEMService(
            server,
            log_file=args.siem_log_file,
            rules_file=args.siem_rules_file,
            evaluation_interval=args.siem_interval,
            packet_log_file=args.dhcp_packet_log_file,
        )
        try:
            siem.start_http(args.http_bind_address, args.http_port)
            server.serve_forever()
        finally:
            siem.close()
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as error:
        raise SystemExit("Configuration or lease-file error: {}".format(error))
    except OSError as error:
        raise SystemExit("Could not start DHCP server: {}".format(error))


if __name__ == "__main__":
    main()
