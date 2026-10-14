import json
import http.cookiejar
import tempfile
import time
import unittest
import urllib.error
from urllib.parse import quote, urlencode
import urllib.request
from pathlib import Path
from unittest.mock import Mock

from dhcp.server import DHCPServer
from dhcp.siem import SIEMService
from tests.test_server import FakeSocket, client_packet


CLIENT_ONE = "02:00:00:00:00:01"
CLIENT_TWO = "02:00:00:00:00:02"


class SIEMServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.server = DHCPServer(
            "192.0.2.1",
            "192.0.2.10",
            "192.0.2.12",
            "255.255.255.0",
            bind_address="192.0.2.1",
            lease_file=root / "leases.json",
        )
        self.server._socket = Mock()
        self.server._socket.sendto.side_effect = lambda packet, destination: len(packet)
        self.siem = SIEMService(
            self.server,
            log_file=root / "events.jsonl",
            rules_file=root / "rules.json",
            evaluation_interval=60,
            packet_log_file=root / "packets.jsonl",
            backup_dir=root / "backups",
            backup_interval=3600,
            trust_file=root / "trust.json",
        )
        host, port = self.siem.start_http("0.0.0.0", 0)
        self.assertNotEqual(host, self.server.bind_address)
        self.base_url = "http://127.0.0.1:{}".format(port)
        self.cookies = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookies)
        )
        self.csrf_token = None
        _, login = self.request(
            "POST",
            "/api/auth/login",
            {"username": "root", "password": "root"},
        )
        self.csrf_token = login["csrf_token"]

    def tearDown(self):
        self.siem.close()
        self.temp_dir.cleanup()

    def request(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        if method not in ("GET", "HEAD") and path != "/api/auth/login" and self.csrf_token:
            request.add_header("X-CSRF-Token", self.csrf_token)
        with self.opener.open(request) as response:
            result = json.load(response)
            if path == "/api/auth/login" and response.status == 200:
                self.csrf_token = result["csrf_token"]
            return response.status, result

    def test_lease_search_management_and_json_audit(self):
        self.server.allocate_address(bytes.fromhex("020000000001"))
        status, result = self.request("GET", "/api/leases?client=" + CLIENT_ONE)
        self.assertEqual(status, 200)
        self.assertEqual(result["leases"][0]["address"], "192.0.2.10")

        _, result = self.request(
            "POST",
            "/api/leases/{}/extend".format(quote(CLIENT_ONE, safe="")),
            {"seconds": 60},
        )
        self.assertGreater(result["lease"]["remaining_seconds"], 60)
        _, result = self.request("POST", "/api/leases/{}/renew".format(CLIENT_ONE))
        self.assertEqual(result["lease"]["address"], "192.0.2.10")

        _, result = self.request(
            "PUT", "/api/leases/{}".format(CLIENT_TWO), {"address": "192.0.2.11"}
        )
        self.assertEqual(result["lease"]["address"], "192.0.2.11")
        self.request("DELETE", "/api/leases/{}".format(CLIENT_TWO))
        self.assertEqual(self.siem.list_leases({"client": CLIENT_TWO}), [])
        self.assertEqual(self.server._socket.sendto.call_count, 3)
        self.assertEqual(
            len(self.siem.packets.search({"mac": CLIENT_TWO})),
            1,
        )

        _, result = self.request("GET", "/api/logs?client=" + CLIENT_ONE)
        self.assertEqual(
            [event["event"] for event in result["events"]],
            ["lease_allocated", "lease_extended", "lease_renewed"],
        )

    def test_http_root_serves_dashboard_and_pool_stats(self):
        with urllib.request.urlopen(self.base_url + "/") as response:
            self.assertIn("text/html", response.headers["Content-Type"])
            dashboard = response.read().decode("utf-8")
        self.assertIn("Lease management", dashboard)
        self.assertIn("DHCP packet log", dashboard)
        self.assertIn("Client MAC", dashboard)
        self.assertIn("DHCPFORCERENEW", dashboard)
        self.assertIn("SIEM rules", dashboard)
        self.assertIn("Client trust", dashboard)
        self.assertIn("Protected-pool policy", dashboard)
        self.assertIn("/api/stats", dashboard)
        self.assertIn("/api/packets", dashboard)

        status, stats = self.request("GET", "/api/stats")
        self.assertEqual(status, 200)
        self.assertEqual(stats["pool_capacity"], 3)
        self.assertEqual(stats["active_leases"], 0)

    def test_rules_persist_and_starvation_rule_creates_alert(self):
        _, result = self.request("GET", "/api/rules")
        self.assertEqual(
            {rule["id"] for rule in result["rules"]},
            {
                "rapid-lease-allocation",
                "high-pool-usage",
                "unique-discover-churn",
                "per-client-discover-burst",
                "low-trust-discover-pressure",
                "protected-pool-denials",
            },
        )
        _, result = self.request(
            "POST",
            "/api/rules",
            {
                "name": "Test allocation burst",
                "type": "event_rate",
                "event_type": "lease_allocated",
                "threshold": 1,
                "window_seconds": 30,
            },
        )
        rule = result["rule"]
        self.server.allocate_address(bytes.fromhex("020000000001"))
        alerts = self.siem.evaluate_rules()
        self.assertTrue(any(alert["rule_id"] == rule["id"] for alert in alerts))

        _, result = self.request("GET", "/api/logs?event=siem_alert")
        self.assertTrue(any(event["rule_id"] == rule["id"] for event in result["events"]))
        with open(self.siem.rules_file, encoding="utf-8") as rules_file:
            state = json.load(rules_file)
        self.assertIn(rule["id"], {item["id"] for item in state["rules"]})

        self.request("PATCH", "/api/rules/{}".format(rule["id"]), {"enabled": False})
        self.request("DELETE", "/api/rules/{}".format(rule["id"]))
        self.assertNotIn(rule["id"], {rule["id"] for rule in self.siem.rules_snapshot()})

    def test_invalid_rule_is_rejected(self):
        request = urllib.request.Request(
            self.base_url + "/api/rules",
            data=json.dumps(
                {"type": "pool_usage", "threshold_percent": 101}
            ).encode("utf-8"),
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-CSRF-Token": self.csrf_token,
            },
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.opener.open(request)
        self.assertEqual(error.exception.code, 400)

    def test_management_api_requires_login_and_csrf(self):
        request = urllib.request.Request(self.base_url + "/api/stats")
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        self.assertEqual(error.exception.code, 401)

        request = urllib.request.Request(
            self.base_url + "/api/rules",
            data=b"{}",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.opener.open(request)
        self.assertEqual(error.exception.code, 403)

    def test_login_attempts_are_rate_limited(self):
        for _ in range(5):
            request = urllib.request.Request(
                self.base_url + "/api/auth/login",
                data=json.dumps(
                    {"username": "root", "password": "incorrect"}
                ).encode("utf-8"),
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request)
            self.assertEqual(error.exception.code, 401)
        request = urllib.request.Request(
            self.base_url + "/api/auth/login",
            data=json.dumps(
                {"username": "root", "password": "incorrect"}
            ).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        self.assertEqual(error.exception.code, 429)

    def test_query_language_searches_arbitrary_log_fields_and_values(self):
        self.siem.record_event(
            "lease_allocated",
            client=CLIENT_ONE,
            address="192.0.2.10",
            nested={"operator_note": "special value"},
        )
        query = urlencode(
            {
                "expr": 'event == "lease_allocated" and contains(nested.operator_note, "special")',
                "source": "events",
            }
        )
        _, result = self.request("GET", "/api/search?" + query)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["records"][0]["nested"]["operator_note"], "special value")

        query = urlencode({"expr": 'has("192.0.2.10")', "source": "all"})
        _, result = self.request("GET", "/api/search?" + query)
        self.assertTrue(any(row["event"] == "lease_allocated" for row in result["records"]))

    def test_query_language_rejects_arbitrary_code_and_unsafe_functions(self):
        for expression in (
            "__import__('os').system('echo bad')",
            "event == 'lease_allocated' and (1 / 0) > 0",
            "count_if('event == \"lease_allocated\"', 60) > 0",
        ):
            query = urlencode({"expr": expression})
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.opener.open(self.base_url + "/api/search?" + query)
            self.assertEqual(error.exception.code, 400)

    def test_query_language_bounds_numeric_field_arithmetic(self):
        self.siem.record_event("lease_allocated", metric=1e100)
        query = urlencode(
            {"expr": "metric * metric > 0", "source": "events"}
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.opener.open(self.base_url + "/api/search?" + query)
        self.assertEqual(error.exception.code, 400)

    def test_expression_rules_support_windowed_counts(self):
        self.siem.record_event("lease_allocated", client=CLIENT_ONE, address="192.0.2.10")
        self.siem.record_event("lease_allocated", client=CLIENT_TWO, address="192.0.2.11")
        _, result = self.request(
            "POST",
            "/api/rules",
            {
                "name": "Test expression",
                "type": "expression",
                "expression": 'count_if("event == \'lease_allocated\'", 60) >= 2',
                "interval_seconds": 1,
                "enabled": True,
            },
        )
        alerts = self.siem.evaluate_rules()
        self.assertTrue(any(alert["rule_id"] == result["rule"]["id"] for alert in alerts))

    def test_backup_rollback_restores_state_but_preserves_logs(self):
        client_one = bytes.fromhex("020000000001")
        client_two = bytes.fromhex("020000000002")
        self.server.allocate_address(client_one)
        self.siem.trust.set_manual_score(CLIENT_ONE, 90)
        checkpoint = self.siem.backups.create_snapshot("test")
        self.server.allocate_address(client_two)
        self.siem.trust.set_manual_score(CLIENT_ONE, 10)
        self.siem.trust.observe(CLIENT_TWO, "2025-01-01T12:00:00+00:00")
        self.siem.record_event("lease_assigned", client=CLIENT_TWO, address="192.0.2.11")

        restored = self.siem.restore_backup(checkpoint)

        self.assertIn(client_one, self.server.leases)
        self.assertNotIn(client_two, self.server.leases)
        self.assertEqual(self.siem.trust.get_profile(CLIENT_ONE)["score"], 90)
        self.assertFalse(self.siem.trust.has_profile(CLIENT_TWO))
        self.assertTrue(
            any(
                event.get("client") == CLIENT_TWO
                for event in self.siem.events.search({"event": "lease_assigned"})
            )
        )
        self.assertEqual(restored["restored"], checkpoint)
        self.assertNotEqual(restored["safety_snapshot"], checkpoint)
        self.assertGreaterEqual(len(self.siem.backups.list_snapshots()), 3)

    def test_trust_policy_and_client_management_api(self):
        _, profile = self.request(
            "PATCH",
            "/api/trust/clients/{}".format(CLIENT_ONE),
            {"manual_score": 100},
        )
        self.assertTrue(profile["profile"]["trusted"])
        _, profiles = self.request("GET", "/api/trust/clients")
        self.assertEqual(profiles["count"], 1)
        self.assertEqual(profiles["profiles"][0]["mac"], CLIENT_ONE)

        _, policy = self.request(
            "PATCH",
            "/api/trust/policy",
            {
                "occupancy_threshold_percent": 70,
                "trusted_score_threshold": 80,
            },
        )
        self.assertEqual(policy["occupancy_threshold_percent"], 70)
        _, policy = self.request("GET", "/api/trust/policy")
        self.assertEqual(policy["trusted_score_threshold"], 80)
        self.assertEqual(policy["profiles_count"], 1)

        _, profile = self.request(
            "PATCH",
            "/api/trust/clients/{}".format(CLIENT_ONE),
            {"clear_override": True},
        )
        self.assertIsNone(profile["profile"]["manual_score"])
        self.request("DELETE", "/api/trust/clients/{}".format(CLIENT_ONE))
        self.assertEqual(self.siem.trust.profile_count(), 0)

    def test_valid_discovery_and_acknowledged_renewal_update_trust(self):
        client = bytes.fromhex("020000000001")
        sock = FakeSocket()

        self.server.handle_packet(client_packet(1, client), sock)
        profile = self.siem.trust.get_profile(CLIENT_ONE)
        self.assertEqual(profile["sighting_days"], 1)
        received = self.siem.packets.search(
            {"mac": CLIENT_ONE, "direction": "received"}
        )
        self.assertEqual(received[-1]["trust_score"], 2)

        address = self.server.leases[client].address
        renewal = client_packet(3, client, ciaddr=str(address))
        self.server.handle_packet(renewal, sock)
        self.assertEqual(
            self.siem.trust.get_profile(CLIENT_ONE)["successful_renewals"],
            1,
        )
        self.assertEqual(
            self.siem.trust.get_profile(CLIENT_ONE)["automatic_score"],
            12,
        )

    def test_discovery_rules_measure_unique_bursts_and_low_trust(self):
        rules = [
            {
                "name": "Unique discovery test",
                "type": "unique_client_rate",
                "threshold": 2,
                "window_seconds": 60,
            },
            {
                "name": "Per-client burst test",
                "type": "per_client_rate",
                "threshold": 2,
                "window_seconds": 60,
            },
            {
                "name": "Low-trust discovery test",
                "type": "low_trust_discover_rate",
                "threshold": 2,
                "window_seconds": 60,
                "max_score": 30,
            },
        ]
        created = [self.siem.create_rule(rule) for rule in rules]
        self.siem.record_packet(
            direction="received",
            packet_type="DHCPDISCOVER",
            source_address="0.0.0.0",
            destination_address="255.255.255.255",
            client_mac=CLIENT_ONE,
        )
        self.siem.record_packet(
            direction="received",
            packet_type="DHCPDISCOVER",
            source_address="0.0.0.0",
            destination_address="255.255.255.255",
            client_mac=CLIENT_ONE,
        )
        self.siem.record_packet(
            direction="received",
            packet_type="DHCPDISCOVER",
            source_address="0.0.0.0",
            destination_address="255.255.255.255",
            client_mac=CLIENT_TWO,
        )

        alerts = self.siem.evaluate_rules()
        alert_ids = {alert["rule_id"] for alert in alerts}
        self.assertTrue({rule["id"] for rule in created}.issubset(alert_ids))

    def test_corrupt_backup_is_rejected_without_changing_live_state(self):
        client = bytes.fromhex("020000000001")
        self.server.allocate_address(client)
        checkpoint = self.siem.backups.create_snapshot("test")
        backup_path = self.siem.backups.directory / checkpoint
        backup_path.write_bytes(backup_path.read_bytes()[:-8])

        with self.assertRaises(ValueError):
            self.siem.restore_backup(checkpoint)
        self.assertIn(client, self.server.leases)

    def test_expired_lease_is_removed_and_logged(self):
        client = bytes.fromhex("020000000001")
        self.server.allocate_address(client)
        self.server.leases[client].expires_at = time.monotonic() - 1
        self.server.expire_leases()

        self.assertIsNone(self.siem.lease_for(client))
        events = self.siem.events.search({"event": "lease_expired"})
        self.assertEqual(events[0]["client"], CLIENT_ONE)

    def test_dhcp_packet_log_is_separate_and_searchable(self):
        packet = self.siem.record_packet(
            direction="received",
            packet_type="DHCPDISCOVER",
            source_address="198.51.100.25",
            destination_address="192.0.2.1",
            client_mac=CLIENT_ONE,
        )
        self.siem.record_packet(
            direction="sent",
            packet_type="DHCPOFFER",
            source_address="192.0.2.1",
            destination_address="255.255.255.255",
            client_mac=CLIENT_TWO,
        )

        query = urlencode(
            {
                "since": packet["timestamp"],
                "until": packet["timestamp"],
                "source": "198.51.100.25",
                "destination": "192.0.2.1",
                "type": "DHCPDISCOVER",
                "mac": CLIENT_ONE.upper(),
            }
        )
        status, result = self.request("GET", "/api/packets?" + query)
        self.assertEqual(status, 200)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["packets"][0]["packet_type"], "DHCPDISCOVER")
        self.assertEqual(result["packets"][0]["direction"], "received")
        self.assertEqual(result["packets"][0]["client_mac"], CLIENT_ONE)
        self.assertTrue(self.siem.packets.path.exists())
        self.assertEqual(self.siem.events.search({"event": "dhcp_packet"}), [])

    def test_packet_search_rejects_invalid_address_and_type(self):
        for query in (
            "source=not-an-ip",
            "type=BOGUS",
            "since=not-a-timestamp",
            "since=2025-01-02T00%3A00%3A00Z&until=2025-01-01T00%3A00%3A00Z",
        ):
            request = urllib.request.Request(
                self.base_url + "/api/packets?" + query,
                method="GET",
            )
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.opener.open(request)
            self.assertEqual(error.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
