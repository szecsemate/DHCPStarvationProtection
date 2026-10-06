import ipaddress
import tempfile
import threading
import unittest
from pathlib import Path

from dhcp.protocol import (
    BOOTREQUEST,
    DHCP_ACK,
    DHCP_NAK,
    DHCP_OFFER,
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
