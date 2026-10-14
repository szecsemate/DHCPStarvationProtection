import ipaddress
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from dhcp.protocol import (
    BOOTREQUEST,
    DHCP_ACK,
    DHCP_FORCERENEW,
    DHCP_NAK,
    DHCP_OFFER,
    DHCP_REQUEST,
    DHCP_RELEASE,
    MAGIC_COOKIE,
    parse_options,
)
from dhcp.server import DHCPServer


SERVER_IP = ipaddress.IPv4Address("192.0.2.1")
CLIENT_ONE = bytes.fromhex("020000000001")
CLIENT_TWO = bytes.fromhex("020000000002")


def client_packet(message_type, client, options=(), ciaddr="0.0.0.0", giaddr="0.0.0.0"):
    encoded_options = bytearray(MAGIC_COOKIE)
    encoded_options.extend((53, 1, message_type))
    for code, value in options:
        encoded_options.extend((code, len(value)))
        encoded_options.extend(value)
    encoded_options.append(255)
    header = BOOTREQUEST.pack(
        1,
        1,
        len(client),
        0,
        1234,
        0,
        0,
        ipaddress.IPv4Address(ciaddr).packed,
        b"\0" * 4,
        b"\0" * 4,
        ipaddress.IPv4Address(giaddr).packed,
        client.ljust(16, b"\0"),
        b"\0" * 64,
        b"\0" * 128,
    )
    return header + encoded_options


class FakeSocket:
    def __init__(self):
        self.sent = []

    def sendto(self, packet, destination):
        self.sent.append((packet, destination))


class InterruptingSocket:
    def __init__(self):
        self.options = []
        self.bound_address = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def setsockopt(self, *args):
        self.options.append(args)

    def bind(self, address):
        self.bound_address = address

    def getsockname(self):
        return ("192.0.2.1", 67)

    def recvfrom(self, size):
        raise KeyboardInterrupt


class DHCPServerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.lease_file = Path(self.temp_dir.name) / "leases.json"
        self.server = DHCPServer(
            server_ip=SERVER_IP,
            pool_start="192.0.2.10",
            pool_end="192.0.2.12",
            subnet_mask="255.255.255.0",
            lease_file=self.lease_file,
        )
        self.socket = FakeSocket()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_discover_request_and_persistent_lease(self):
        self.server.handle_packet(client_packet(1, CLIENT_ONE), self.socket)
        offer, destination = self.socket.sent.pop()
        offered_ip = ipaddress.IPv4Address(BOOTREQUEST.unpack(offer[:236])[8])
        self.assertEqual(offered_ip, ipaddress.IPv4Address("192.0.2.10"))
        self.assertEqual(parse_options(offer)[53], bytes((DHCP_OFFER,)))
        self.assertEqual(destination, ("255.255.255.255", 68))

        request = client_packet(
            3,
            CLIENT_ONE,
            (
                (50, offered_ip.packed),
                (54, SERVER_IP.packed),
            ),
        )
        self.server.handle_packet(request, self.socket)
        acknowledgement, _ = self.socket.sent.pop()
        self.assertEqual(parse_options(acknowledgement)[53], bytes((DHCP_ACK,)))
        self.assertTrue(self.lease_file.exists())

        restarted = DHCPServer(
            SERVER_IP,
            "192.0.2.10",
            "192.0.2.12",
            "255.255.255.0",
            lease_file=self.lease_file,
        )
        self.assertEqual(restarted.allocate_address(CLIENT_ONE), offered_ip)

    def test_static_reservation_and_extra_options(self):
        reserved_ip = ipaddress.IPv4Address("192.0.2.20")
        server = DHCPServer(
            SERVER_IP,
            "192.0.2.10",
            "192.0.2.12",
            "255.255.255.0",
            lease_file=self.lease_file,
            reservations=[(CLIENT_ONE, reserved_ip)],
            dns_servers=["192.0.2.53"],
            ntp_servers=["192.0.2.123"],
            domain_name="example.test",
        )
        server.handle_packet(client_packet(1, CLIENT_ONE), self.socket)
        offer, _ = self.socket.sent.pop()
        self.assertEqual(
            ipaddress.IPv4Address(BOOTREQUEST.unpack(offer[:236])[8]), reserved_ip
        )
        options = parse_options(offer)
        self.assertEqual(options[6], ipaddress.IPv4Address("192.0.2.53").packed)
        self.assertEqual(options[42], ipaddress.IPv4Address("192.0.2.123").packed)
        self.assertEqual(options[15], b"example.test")

    def test_declined_address_is_quarantined_and_persisted(self):
        address = self.server.allocate_address(CLIENT_ONE)
        decline = client_packet(
            4,
            CLIENT_ONE,
            ((50, address.packed), (54, SERVER_IP.packed)),
        )
        self.server.handle_packet(decline, self.socket)
        self.assertIn(address, self.server.quarantined)

        restarted = DHCPServer(
            SERVER_IP,
            "192.0.2.10",
            "192.0.2.12",
            "255.255.255.0",
            lease_file=self.lease_file,
        )
        self.assertIn(address, restarted.quarantined)
        self.assertNotEqual(restarted.allocate_address(CLIENT_TWO), address)

    def test_reserved_decline_quarantine_survives_restart(self):
        reserved_ip = ipaddress.IPv4Address("192.0.2.20")
        reservation = [(CLIENT_ONE, reserved_ip)]
        server = DHCPServer(
            SERVER_IP,
            "192.0.2.10",
            "192.0.2.12",
            "255.255.255.0",
            lease_file=self.lease_file,
            reservations=reservation,
        )
        server.allocate_address(CLIENT_ONE)
        server.handle_packet(
            client_packet(
                4,
                CLIENT_ONE,
                ((50, reserved_ip.packed), (54, SERVER_IP.packed)),
            ),
            self.socket,
        )

        restarted = DHCPServer(
            SERVER_IP,
            "192.0.2.10",
            "192.0.2.12",
            "255.255.255.0",
            lease_file=self.lease_file,
            reservations=reservation,
        )
        self.assertIn(reserved_ip, restarted.quarantined)
        self.assertIsNone(restarted.allocate_address(CLIENT_ONE))

    def test_renewal_ack_is_unicast_to_client_address(self):
        address = self.server.allocate_address(CLIENT_ONE)
        renewal = client_packet(3, CLIENT_ONE, ciaddr=str(address))
        self.server.handle_packet(renewal, self.socket)
        acknowledgement, destination = self.socket.sent.pop()
        self.assertEqual(parse_options(acknowledgement)[53], bytes((DHCP_ACK,)))
        self.assertEqual(destination, (str(address), 68))

    def test_request_for_another_server_is_ignored(self):
        other_server = ipaddress.IPv4Address("192.0.2.2")
        request = client_packet(3, CLIENT_ONE, ((54, other_server.packed),))
        self.server.handle_packet(request, self.socket)
        self.assertEqual(self.socket.sent, [])

    def test_unsupported_bootp_hardware_address_is_rejected(self):
        packet = bytearray(client_packet(1, CLIENT_ONE))
        packet[1] = 6
        with self.assertRaisesRegex(ValueError, "six-byte Ethernet"):
            self.server.handle_packet(bytes(packet), self.socket)

        packet = bytearray(client_packet(1, CLIENT_ONE))
        packet[2] = 5
        with self.assertRaisesRegex(ValueError, "six-byte Ethernet"):
            self.server.handle_packet(bytes(packet), self.socket)
        self.assertEqual(self.server.leases, {})

    def test_server_only_acknowledges_its_offered_address(self):
        unoffered_ip = ipaddress.IPv4Address("192.0.2.11")
        request = client_packet(
            3,
            CLIENT_ONE,
            ((50, unoffered_ip.packed), (54, SERVER_IP.packed)),
        )
        self.server.handle_packet(request, self.socket)
        response, _ = self.socket.sent.pop()
        self.assertEqual(parse_options(response)[53], bytes((DHCP_NAK,)))

    def test_decline_from_another_server_is_ignored(self):
        address = self.server.allocate_address(CLIENT_ONE)
        decline = client_packet(
            4,
            CLIENT_ONE,
            (
                (50, address.packed),
                (54, ipaddress.IPv4Address("192.0.2.2").packed),
            ),
        )
        self.server.handle_packet(decline, self.socket)
        self.assertNotIn(address, self.server.quarantined)

    def test_release_removes_only_client_lease(self):
        address = self.server.allocate_address(CLIENT_ONE)
        self.server.handle_packet(
            client_packet(DHCP_RELEASE, CLIENT_ONE, ciaddr=str(address)), self.socket
        )
        self.assertNotIn(CLIENT_ONE, self.server.leases)

    def test_relay_receives_reply_on_server_port(self):
        self.server.handle_packet(
            client_packet(1, CLIENT_ONE, giaddr="192.0.2.254"), self.socket
        )
        _, destination = self.socket.sent.pop()
        self.assertEqual(destination, ("192.0.2.254", 67))

    def test_packet_callback_records_received_and_sent_addresses_and_types(self):
        packets = []
        self.server.packet_callback = lambda **packet: packets.append(packet)
        self.server.handle_packet(
            client_packet(1, CLIENT_ONE),
            self.socket,
            ("198.51.100.25", 68),
            ("192.0.2.1", 67),
        )

        self.assertEqual(
            packets,
            [
                {
                    "direction": "received",
                    "packet_type": "DHCPDISCOVER",
                    "source_address": "198.51.100.25",
                    "destination_address": "192.0.2.1",
                    "client_mac": "02:00:00:00:00:01",
                },
                {
                    "direction": "sent",
                    "packet_type": "DHCPOFFER",
                    "source_address": "192.0.2.1",
                    "destination_address": "255.255.255.255",
                    "client_mac": "02:00:00:00:00:01",
                },
            ],
        )

    def test_forcerenew_is_unicast_and_logs_client_mac(self):
        packets = []
        self.server.packet_callback = lambda **packet: packets.append(packet)
        fake_socket = FakeSocket()
        self.server._socket = fake_socket

        self.server.send_forcerenew(CLIENT_ONE, "192.0.2.10")

        packet, destination = fake_socket.sent[0]
        self.assertEqual(destination, ("192.0.2.10", 68))
        self.assertEqual(BOOTREQUEST.unpack(packet[: BOOTREQUEST.size])[7], b"\xc0\x00\x02\x0a")
        self.assertEqual(parse_options(packet)[53], bytes((DHCP_FORCERENEW,)))
        self.assertEqual(packets[0]["packet_type"], "DHCPFORCERENEW")
        self.assertEqual(packets[0]["client_mac"], "02:00:00:00:00:01")

    def test_admin_release_quarantines_address_until_old_expiry(self):
        address = self.server.allocate_address(CLIENT_ONE)
        lease_expiry = self.server.leases[CLIENT_ONE].expires_at

        self.assertTrue(
            self.server.lease_manager.release(
                CLIENT_ONE, quarantine_until_expiry=True
            )
        )

        self.assertNotIn(CLIENT_ONE, self.server.leases)
        self.assertEqual(self.server.quarantined[address], lease_expiry)

        self.server.handle_packet(
            client_packet(DHCP_REQUEST, CLIENT_ONE, ciaddr=str(address)),
            self.socket,
        )
        response, _ = self.socket.sent[-1]
        self.assertEqual(parse_options(response)[53], bytes((DHCP_NAK,)))

        self.server.handle_packet(
            client_packet(1, CLIENT_TWO),
            self.socket,
        )
        offer, _ = self.socket.sent[-1]
        offered_address = ipaddress.IPv4Address(
            BOOTREQUEST.unpack(offer[: BOOTREQUEST.size])[8]
        )
        self.assertEqual(offered_address, ipaddress.IPv4Address("192.0.2.11"))

    def test_renewal_after_lease_extension_advertises_extended_duration(self):
        address = self.server.allocate_address(CLIENT_ONE)
        self.server.lease_manager.extend(CLIENT_ONE, 300)

        self.server.handle_packet(
            client_packet(DHCP_REQUEST, CLIENT_ONE, ciaddr=str(address)),
            self.socket,
        )

        response, _ = self.socket.sent[-1]
        lease_seconds = int.from_bytes(parse_options(response)[51], "big")
        self.assertEqual(lease_seconds, self.server.leases[CLIENT_ONE].lease_seconds)
        self.assertGreater(lease_seconds, self.server.lease_seconds)

    def test_ctrl_c_during_receive_stops_server_without_traceback(self):
        with patch("dhcp.server.socket.socket", return_value=InterruptingSocket()):
            self.server.serve_forever()

    def test_dhcp_interface_binds_device_and_listens_for_broadcasts(self):
        server = DHCPServer(
            SERVER_IP,
            "192.0.2.10",
            "192.0.2.12",
            "255.255.255.0",
            bind_address="0.0.0.0",
            interface="enp0s3",
            lease_file=None,
        )
        fake_socket = InterruptingSocket()
        with (
            patch("dhcp.server.socket.socket", return_value=fake_socket),
            patch("dhcp.server.socket.SO_BINDTODEVICE", 25, create=True),
        ):
            server.serve_forever()

        self.assertIn(
            (socket.SOL_SOCKET, 25, b"enp0s3\0"),
            fake_socket.options,
        )
        self.assertEqual(fake_socket.bound_address, ("0.0.0.0", 67))

    def test_dhcp_interface_rejects_specific_ip_bind(self):
        with self.assertRaisesRegex(ValueError, "requires --bind-address 0.0.0.0"):
            DHCPServer(
                SERVER_IP,
                "192.0.2.10",
                "192.0.2.12",
                "255.255.255.0",
                bind_address="192.0.2.1",
                interface="enp0s3",
                lease_file=None,
            )

    def test_concurrent_allocations_are_unique(self):
        clients = [index.to_bytes(6, "big") for index in range(1, 20)]
        barrier = threading.Barrier(len(clients))
        addresses = []
        addresses_lock = threading.Lock()

        def allocate(client):
            barrier.wait()
            address = self.server.allocate_address(client)
            with addresses_lock:
                addresses.append(address)

        threads = [threading.Thread(target=allocate, args=(client,)) for client in clients]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assigned = [address for address in addresses if address is not None]
        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertLessEqual(len(assigned), 3)


if __name__ == "__main__":
    unittest.main()
