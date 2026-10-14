import sys
import unittest
from unittest.mock import patch

from dhcp.cli import parse_args


class CommandLineTests(unittest.TestCase):
    def test_http_bind_address_defaults_to_all_interfaces(self):
        with patch.object(
            sys,
            "argv",
            [
                "main.py",
                "--server-ip",
                "192.0.2.1",
                "--pool-start",
                "192.0.2.10",
                "--pool-end",
                "192.0.2.12",
                "--subnet-mask",
                "255.255.255.0",
            ],
        ):
            args = parse_args()

        self.assertEqual(args.http_bind_address, "0.0.0.0")
        self.assertEqual(args.dhcp_packet_log_file, "dhcp_packets.jsonl")
        self.assertEqual(args.backup_interval, 1800)
        self.assertEqual(args.backup_retention_days, 30)
        self.assertEqual(args.trust_file, "dhcp_trust.json")

    def test_http_bind_address_is_independent_from_dhcp_bind_address(self):
        with patch.object(
            sys,
            "argv",
            [
                "main.py",
                "--server-ip",
                "192.0.2.1",
                "--pool-start",
                "192.0.2.10",
                "--pool-end",
                "192.0.2.12",
                "--subnet-mask",
                "255.255.255.0",
                "--bind-address",
                "192.0.2.1",
                "--http-bind-address",
                "10.0.0.5",
                "--dhcp-packet-log-file",
                "/var/log/dhcp/packets.jsonl",
                "--dhcp-interface",
                "enp0s3",
            ],
        ):
            args = parse_args()

        self.assertEqual(args.bind_address, "192.0.2.1")
        self.assertEqual(args.http_bind_address, "10.0.0.5")
        self.assertEqual(args.dhcp_packet_log_file, "/var/log/dhcp/packets.jsonl")
        self.assertEqual(args.dhcp_interface, "enp0s3")


if __name__ == "__main__":
    unittest.main()
