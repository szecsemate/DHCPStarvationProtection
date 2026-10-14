import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dhcp.server import DHCPServer
from dhcp.trust import TrustManager


MAC_ONE = "02:00:00:00:00:01"
MAC_TWO = "02:00:00:00:00:02"
MAC_THREE = "02:00:00:00:00:03"


class TrustManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = Path(self.temp_dir.name) / "trust.json"
        self.trust = TrustManager(
            self.path,
            ipaddress.IPv4Address("192.0.2.10"),
            ipaddress.IPv4Address("192.0.2.12"),
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_score_uses_daily_sightings_and_successful_renewals(self):
        self.trust.observe(MAC_ONE, "2025-01-01T12:00:00+00:00")
        self.trust.observe(MAC_ONE, "2025-01-01T23:00:00+00:00")
        self.trust.observe(MAC_ONE, "2025-01-02T01:00:00+00:00")
        self.trust.record_renewal(MAC_ONE, "2025-01-02T02:00:00+00:00")

        profile = self.trust.get_profile(MAC_ONE)
        self.assertEqual(profile["sighting_days"], 2)
        self.assertEqual(profile["successful_renewals"], 1)
        self.assertEqual(profile["automatic_score"], 14)

        restarted = TrustManager(
            self.path,
            ipaddress.IPv4Address("192.0.2.10"),
            ipaddress.IPv4Address("192.0.2.12"),
        )
        self.assertEqual(restarted.get_profile(MAC_ONE), profile)

    def test_manual_score_override_can_be_changed_and_cleared(self):
        automatic = self.trust.observe(MAC_ONE)["automatic_score"]
        overridden = self.trust.set_manual_score(MAC_ONE, 100)
        self.assertEqual(overridden["score"], 100)
        self.assertEqual(overridden["score_source"], "manual")

        self.assertEqual(self.trust.set_manual_score(MAC_ONE, 0)["score"], 0)
        restored = self.trust.clear_manual_score(MAC_ONE)
        self.assertEqual(restored["score"], automatic)
        self.assertEqual(restored["score_source"], "automatic")

    def test_failed_persistence_rolls_back_manual_mutations(self):
        with patch.object(self.trust, "_save", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                self.trust.set_manual_score(MAC_ONE, 90)
        self.assertFalse(self.trust.has_profile(MAC_ONE))

        self.trust.set_manual_score(MAC_ONE, 90)
        with patch.object(self.trust, "_save", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                self.trust.clear_manual_score(MAC_ONE)
            with self.assertRaisesRegex(OSError, "disk full"):
                self.trust.remove_profile(MAC_ONE)
        self.assertEqual(self.trust.get_profile(MAC_ONE)["score"], 90)
        self.assertTrue(self.trust.has_profile(MAC_ONE))

    def test_policy_keeps_dynamic_capacity_for_trusted_clients(self):
        server = DHCPServer(
            "192.0.2.1",
            "192.0.2.10",
            "192.0.2.12",
            "255.255.255.0",
            lease_file=Path(self.temp_dir.name) / "leases.json",
        )
        server.lease_manager.allocation_guard = self.trust.allow_new_dynamic_lease

        first = server.allocate_address(bytes.fromhex("020000000001"))
        second = server.allocate_address(bytes.fromhex("020000000002"))
        deferred = server.allocate_address(bytes.fromhex("020000000003"))
        self.assertEqual(first, ipaddress.IPv4Address("192.0.2.10"))
        self.assertEqual(second, ipaddress.IPv4Address("192.0.2.11"))
        self.assertIsNone(deferred)

        trusted = self.trust.set_manual_score(MAC_THREE, 100)
        self.assertTrue(trusted["trusted"])
        self.assertEqual(
            server.allocate_address(bytes.fromhex("020000000003")),
            ipaddress.IPv4Address("192.0.2.12"),
        )

    def test_dhcp_init_reboot_assignment_obeys_trust_policy(self):
        server = DHCPServer(
            "192.0.2.1",
            "192.0.2.10",
            "192.0.2.12",
            "255.255.255.0",
            lease_file=Path(self.temp_dir.name) / "init-reboot-leases.json",
        )
        server.lease_manager.allocation_guard = self.trust.allow_new_dynamic_lease
        server.allocate_address(bytes.fromhex("020000000001"))
        server.allocate_address(bytes.fromhex("020000000002"))

        requested = ipaddress.IPv4Address("192.0.2.12")
        untrusted = bytes.fromhex("020000000003")
        self.assertFalse(
            server.assign_address(
                untrusted,
                requested,
                enforce_allocation_policy=True,
            )
        )

        self.trust.set_manual_score(MAC_THREE, 100)
        self.assertTrue(
            server.assign_address(
                untrusted,
                requested,
                enforce_allocation_policy=True,
            )
        )

    def test_reservation_is_not_blocked_by_protected_pool_policy(self):
        reserved_mac = bytes.fromhex("020000000003")
        server = DHCPServer(
            "192.0.2.1",
            "192.0.2.10",
            "192.0.2.12",
            "255.255.255.0",
            lease_file=Path(self.temp_dir.name) / "reserved-leases.json",
            reservations=[(reserved_mac, "192.0.2.20")],
        )
        server.lease_manager.allocation_guard = self.trust.allow_new_dynamic_lease
        server.allocate_address(bytes.fromhex("020000000001"))
        server.allocate_address(bytes.fromhex("020000000002"))

        self.assertEqual(
            server.allocate_address(reserved_mac),
            ipaddress.IPv4Address("192.0.2.20"),
        )


if __name__ == "__main__":
    unittest.main()
