"""Command-line entry point for the DHCP server."""

import argparse
import ipaddress
import logging

from .protocol import parse_reservation
from .server import DHCPServer


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
    parser.add_argument("--port", type=int, default=67, help="UDP port (default: 67)")
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
