import json
import tempfile
import time
import unittest
import urllib.error
from urllib.parse import quote, urlencode
import urllib.request
from pathlib import Path

from dhcp.server import DHCPServer
from dhcp.siem import SIEMService


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
        self.siem = SIEMService(
            self.server,
            log_file=root / "events.jsonl",
            rules_file=root / "rules.json",
            evaluation_interval=60,
            packet_log_file=root / "packets.jsonl",
        )
        host, port = self.siem.start_http("0.0.0.0", 0)
        self.assertNotEqual(host, self.server.bind_address)
        self.base_url = "http://127.0.0.1:{}".format(port)

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
        with urllib.request.urlopen(request) as response:
            return response.status, json.load(response)

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
        self.assertIn("SIEM rules", dashboard)
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
            {"rapid-lease-allocation", "high-pool-usage"},
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
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        self.assertEqual(error.exception.code, 400)

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
        )
        self.siem.record_packet(
            direction="sent",
            packet_type="DHCPOFFER",
            source_address="192.0.2.1",
            destination_address="255.255.255.255",
        )

        query = urlencode(
            {
                "since": packet["timestamp"],
                "until": packet["timestamp"],
                "source": "198.51.100.25",
                "destination": "192.0.2.1",
                "type": "DHCPDISCOVER",
            }
        )
        status, result = self.request("GET", "/api/packets?" + query)
        self.assertEqual(status, 200)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["packets"][0]["packet_type"], "DHCPDISCOVER")
        self.assertEqual(result["packets"][0]["direction"], "received")
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
                urllib.request.urlopen(request)
            self.assertEqual(error.exception.code, 400)


if __name__ == "__main__":
    unittest.main()
