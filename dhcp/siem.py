"""HTTP lease management, JSON audit logging, and scheduled SIEM rules."""

import ipaddress
import json
import logging
import os
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Union
from urllib.parse import parse_qs, unquote, urlparse

from .protocol import DHCP_MESSAGE_TYPES, parse_mac

LOG = logging.getLogger("dhcp-siem")


class EventLogError(ValueError):
    """A JSON-lines log contains an invalid record."""


EVENT_TYPES = {
    "lease_allocated",
    "lease_assigned",
    "lease_renewed",
    "lease_extended",
    "lease_released",
    "lease_declined",
    "lease_expired",
    "siem_alert",
}
DEFAULT_RULES = [
    {
        "id": "rapid-lease-allocation",
        "name": "Rapid lease allocation (DHCP starvation)",
        "type": "event_rate",
        "event_type": "lease_allocated",
        "threshold": 20,
        "window_seconds": 60,
        "enabled": True,
    },
    {
        "id": "high-pool-usage",
        "name": "High DHCP address-pool usage",
        "type": "pool_usage",
        "threshold_percent": 80,
        "enabled": True,
    },
]


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def _parse_timestamp(value, name):
    if not isinstance(value, str):
        raise ValueError("{} must be an ISO-8601 timestamp".format(name))
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("{} must be an ISO-8601 timestamp".format(name)) from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class JsonEventLog:
    """Append-only JSON-lines audit log with in-process synchronization."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()

    def append(self, event_type, **fields):
        record = {"timestamp": _timestamp(), "event": event_type, **fields}
        with self.lock:
            with self.path.open("a", encoding="utf-8") as event_file:
                event_file.write(json.dumps(record, sort_keys=True) + "\n")
                event_file.flush()
                os.fsync(event_file.fileno())
        return record

    def search(self, filters):
        records = []
        since = (
            _parse_timestamp(filters["since"], "since")
            if filters.get("since")
            else None
        )
        until = (
            _parse_timestamp(filters["until"], "until")
            if filters.get("until")
            else None
        )
        with self.lock:
            if not self.path.exists():
                return records
            with self.path.open("r", encoding="utf-8") as event_file:
                for line_number, line in enumerate(event_file, 1):
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError as error:
                        raise EventLogError(
                            "invalid JSON log record at line {}".format(line_number)
                        ) from error
                    if not isinstance(record, dict):
                        raise EventLogError(
                            "invalid log record at line {}".format(line_number)
                        )
                    if filters.get("event") and record.get("event") != filters["event"]:
                        continue
                    if filters.get("client") and record.get("client") != filters["client"]:
                        continue
                    if filters.get("address") and record.get("address") != filters["address"]:
                        continue
                    if (
                        filters.get("type")
                        and record.get("packet_type") != filters["type"]
                    ):
                        continue
                    if (
                        filters.get("mac")
                        and (record.get("client_mac") or "").lower()
                        != filters["mac"]
                    ):
                        continue
                    if (
                        filters.get("source")
                        and record.get("source_address") != filters["source"]
                    ):
                        continue
                    if (
                        filters.get("destination")
                        and record.get("destination_address") != filters["destination"]
                    ):
                        continue
                    if since or until:
                        try:
                            timestamp = _parse_timestamp(
                                record.get("timestamp", ""), "log timestamp"
                            )
                        except ValueError as error:
                            raise EventLogError(
                                "invalid timestamp at line {}".format(line_number)
                            ) from error
                        if since and timestamp < since:
                            continue
                        if until and timestamp > until:
                            continue
                    if filters.get("q") and filters["q"].lower() not in json.dumps(
                        record, sort_keys=True
                    ).lower():
                        continue
                    records.append(record)
        return records[-filters.get("limit", 100) :]


class SIEMService:
    """Expose lease state and SIEM controls over a small JSON HTTP API."""

    def __init__(
        self,
        dhcp_server,
        log_file: Union[str, os.PathLike] = "siem_events.jsonl",
        rules_file: Union[str, os.PathLike] = "siem_rules.json",
        evaluation_interval=10,
        packet_log_file: Union[str, os.PathLike] = "dhcp_packets.jsonl",
    ):
        if evaluation_interval < 1:
            raise ValueError("rule evaluation interval must be at least one second")
        self.dhcp_server = dhcp_server
        self.events = JsonEventLog(log_file)
        self.packets = JsonEventLog(packet_log_file)
        self.rules_file = Path(rules_file)
        self.evaluation_interval = evaluation_interval
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.rules = self._load_rules()
        self._last_triggered = {}
        self.dhcp_server.lease_manager.event_callback = self.record_event
        self.dhcp_server.packet_callback = self.record_packet
        self.http_server = None
        self.scheduler = threading.Thread(
            target=self._schedule_rules, name="dhcp-siem-rules", daemon=True
        )
        self.scheduler.start()

    def record_event(self, event_type, **fields):
        return self.events.append(event_type, **fields)

    def record_packet(self, **fields):
        return self.packets.append("dhcp_packet", **fields)

    def _load_rules(self):
        if not self.rules_file.exists():
            rules = [dict(rule) for rule in DEFAULT_RULES]
            self._save_rules(rules)
            return rules
        try:
            with self.rules_file.open("r", encoding="utf-8") as rules_file:
                state = json.load(rules_file)
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("could not read SIEM rules file: {}".format(error)) from error
        if not isinstance(state, dict) or state.get("version") != 1:
            raise ValueError("unsupported or invalid SIEM rules file format")
        rules = state.get("rules")
        if not isinstance(rules, list):
            raise ValueError("SIEM rules file must contain a rules list")
        return [self._validate_rule(rule) for rule in rules]

    def _save_rules(self, rules):
        self.rules_file.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=str(self.rules_file.parent),
                prefix=self.rules_file.name + ".",
                suffix=".tmp",
                delete=False,
            ) as rules_file:
                temp_path = Path(rules_file.name)
                json.dump({"version": 1, "rules": rules}, rules_file, indent=2)
                rules_file.write("\n")
                rules_file.flush()
                os.fsync(rules_file.fileno())
            os.replace(str(temp_path), str(self.rules_file))
        finally:
            if temp_path is not None and temp_path.exists():
                temp_path.unlink()

    @staticmethod
    def _validate_rule(rule):
        if not isinstance(rule, dict):
            raise ValueError("rule must be a JSON object")
        rule_type = rule.get("type")
        if rule_type == "event_rate":
            event_type = rule.get("event_type", "lease_allocated")
            threshold = rule.get("threshold")
            window = rule.get("window_seconds")
            if (
                not isinstance(event_type, str)
                or event_type not in EVENT_TYPES
                or event_type == "siem_alert"
            ):
                raise ValueError("unsupported event_type")
            if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
                raise ValueError("event-rate threshold must be a positive integer")
            if isinstance(window, bool) or not isinstance(window, int) or window < 1:
                raise ValueError("window_seconds must be a positive integer")
            result = {
                "id": str(rule.get("id") or uuid.uuid4()),
                "name": str(rule.get("name") or "Event rate rule"),
                "type": rule_type,
                "event_type": event_type,
                "threshold": threshold,
                "window_seconds": window,
                "enabled": rule.get("enabled", True),
            }
        elif rule_type == "pool_usage":
            threshold = rule.get("threshold_percent")
            if (
                isinstance(threshold, bool)
                or not isinstance(threshold, int)
                or not 1 <= threshold <= 100
            ):
                raise ValueError("threshold_percent must be between 1 and 100")
            result = {
                "id": str(rule.get("id") or uuid.uuid4()),
                "name": str(rule.get("name") or "Pool usage rule"),
                "type": rule_type,
                "threshold_percent": threshold,
                "enabled": rule.get("enabled", True),
            }
        else:
            raise ValueError("rule type must be event_rate or pool_usage")
        if not isinstance(result["enabled"], bool):
            raise ValueError("enabled must be a boolean")
        if not result["id"] or not result["name"]:
            raise ValueError("rule id and name must not be empty")
        return result

    def list_leases(self, filters):
        self.dhcp_server.expire_leases()
        now_mono = time.monotonic()
        now_wall = time.time()
        manager = self.dhcp_server.lease_manager
        with manager.lock:
            leases = [
                {
                    "client": client.hex(":"),
                    "address": str(lease.address),
                    "expires_at": datetime.fromtimestamp(
                        now_wall + lease.expires_at - now_mono, timezone.utc
                    ).isoformat(),
                    "remaining_seconds": max(0, int(lease.expires_at - now_mono)),
                }
                for client, lease in manager.leases.items()
            ]
        for key in ("client", "address"):
            if filters.get(key):
                value = filters[key].lower()
                leases = [lease for lease in leases if lease[key].lower() == value]
        if filters.get("q"):
            term = filters["q"].lower()
            leases = [
                lease
                for lease in leases
                if term in lease["client"].lower() or term in lease["address"]
            ]
        return leases

    def assign(self, client, body):
        try:
            mac = parse_mac(client)
            address = ipaddress.IPv4Address(body["address"])
        except (KeyError, TypeError, ipaddress.AddressValueError) as error:
            raise ValueError("a valid IPv4 address is required") from error
        if not self.dhcp_server.assign_address(mac, address):
            raise ValueError("address is unavailable or invalid for this client")
        return self.lease_for(mac)

    def lease_for(self, client):
        matches = self.list_leases({"client": client.hex(":")})
        return matches[0] if matches else None

    def renew(self, client):
        manager = self.dhcp_server.lease_manager
        with manager.lock:
            manager.expire()
            lease = manager.leases.get(client)
            if lease is None:
                raise KeyError("lease not found")
            address = lease.address
        if not manager.assign(client, address):
            raise ValueError("lease could not be renewed")
        self.dhcp_server.send_forcerenew(client, address)
        return self.lease_for(client)

    def extend(self, client, body):
        seconds = body.get("seconds")
        if isinstance(seconds, bool) or not isinstance(seconds, int) or not 1 <= seconds <= 0xFFFFFFFF:
            raise ValueError("seconds must be between 1 and 4294967295")
        manager = self.dhcp_server.lease_manager
        if not manager.extend(client, seconds):
            raise KeyError("lease not found")
        with manager.lock:
            lease = manager.leases[client]
            address = lease.address
        self.dhcp_server.send_forcerenew(client, address)
        return self.lease_for(client)

    def rules_snapshot(self):
        with self.lock:
            return [dict(rule) for rule in self.rules]

    def create_rule(self, rule):
        validated = self._validate_rule(rule)
        with self.lock:
            if any(existing["id"] == validated["id"] for existing in self.rules):
                raise ValueError("rule id already exists")
            self.rules.append(validated)
            self._save_rules(self.rules)
        return validated

    def update_rule(self, rule_id, changes):
        if not isinstance(changes, dict):
            raise ValueError("rule update must be a JSON object")
        with self.lock:
            for index, current in enumerate(self.rules):
                if current["id"] == rule_id:
                    updated = self._validate_rule({**current, **changes, "id": rule_id})
                    self.rules[index] = updated
                    self._save_rules(self.rules)
                    return updated
        raise KeyError("rule not found")

    def delete_rule(self, rule_id):
        with self.lock:
            updated = [rule for rule in self.rules if rule["id"] != rule_id]
            if len(updated) == len(self.rules):
                raise KeyError("rule not found")
            self.rules = updated
            self._save_rules(self.rules)

    def evaluate_rules(self):
        now = time.time()
        leases = self.list_leases({})
        pool_size = int(self.dhcp_server.pool_end) - int(self.dhcp_server.pool_start) + 1
        dynamic_leases = sum(
            int(self.dhcp_server.pool_start)
            <= int(ipaddress.IPv4Address(lease["address"]))
            <= int(self.dhcp_server.pool_end)
            for lease in leases
        )
        pool_usage = dynamic_leases * 100.0 / pool_size
        alerts = []
        with self.lock:
            rules = [dict(rule) for rule in self.rules if rule["enabled"]]
        for rule in rules:
            if rule["type"] == "event_rate":
                cutoff = datetime.fromtimestamp(
                    now - rule["window_seconds"], timezone.utc
                ).isoformat()
                count = len(
                    self.events.search(
                        {
                            "event": rule["event_type"],
                            "since": cutoff,
                            "limit": 1000000,
                        }
                    )
                )
                triggered = count >= rule["threshold"]
                detail = "{} {} events in {} seconds".format(
                    count, rule["event_type"], rule["window_seconds"]
                )
            else:
                triggered = pool_usage >= rule["threshold_percent"]
                detail = "address pool is {:.1f}% utilized".format(pool_usage)
            if not triggered:
                with self.lock:
                    self._last_triggered.pop(rule["id"], None)
                continue
            with self.lock:
                last = self._last_triggered.get(rule["id"], 0)
                if now - last < self.evaluation_interval:
                    continue
                self._last_triggered[rule["id"]] = now
            alerts.append(
                self.record_event(
                    "siem_alert",
                    rule_id=rule["id"],
                    rule_name=rule["name"],
                    severity="high" if rule["type"] == "event_rate" else "medium",
                    details=detail,
                )
            )
        return alerts

    def _schedule_rules(self):
        while not self.stop_event.wait(self.evaluation_interval):
            try:
                self.evaluate_rules()
            except (OSError, ValueError):
                LOG.exception("SIEM rule evaluation failed")

    def start_http(self, host="0.0.0.0", port=8080):
        service = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format_string, *args):
                LOG.info("HTTP %s - %s", self.address_string(), format_string % args)

            def _send(self, status, value):
                payload = json.dumps(value, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _send_dashboard(self):
                dashboard = Path(__file__).with_name("dashboard.html")
                try:
                    payload = dashboard.read_bytes()
                except OSError:
                    LOG.exception("Could not read the lease-management dashboard")
                    self._send(500, {"error": "dashboard file is unavailable"})
                    return
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(payload)

            def _body(self):
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError as error:
                    raise ValueError("invalid Content-Length") from error
                if length < 0 or length > 1024 * 1024:
                    raise ValueError("request body must be at most 1 MiB")
                try:
                    value = json.loads(self.rfile.read(length) or b"{}")
                except (json.JSONDecodeError, UnicodeDecodeError) as error:
                    raise ValueError("request body must be valid JSON") from error
                if not isinstance(value, dict):
                    raise ValueError("request body must be a JSON object")
                return value

            def _dispatch(self):
                parsed = urlparse(self.path)
                query = parse_qs(parsed.query)
                params = {key: values[-1] for key, values in query.items() if values}
                if params.get("client"):
                    params["client"] = parse_mac(params["client"]).hex(":")
                parts = [unquote(part) for part in parsed.path.split("/") if part]
                if parsed.path in ("/", "/index.html") and self.command == "GET":
                    self._send_dashboard()
                    return
                if parts == ["api", "stats"] and self.command == "GET":
                    leases = service.list_leases({})
                    capacity = (
                        int(service.dhcp_server.pool_end)
                        - int(service.dhcp_server.pool_start)
                        + 1
                    )
                    manager = service.dhcp_server.lease_manager
                    with manager.lock:
                        quarantined = len(manager.quarantined)
                    self._send(
                        200,
                        {
                            "active_leases": len(leases),
                            "pool_capacity": capacity,
                            "pool_usage_percent": round(len(leases) * 100.0 / capacity, 1),
                            "quarantined_addresses": quarantined,
                        },
                    )
                    return
                if parts == ["api", "leases"] and self.command == "GET":
                    leases = service.list_leases(params)
                    limit = service._limit(params.get("limit"), 100)
                    self._send(200, {"leases": leases[:limit], "count": len(leases)})
                    return
                if parts == ["api", "logs"] and self.command == "GET":
                    limit = service._limit(params.get("limit"), 100)
                    params["limit"] = limit
                    events = service.events.search(params)
                    self._send(200, {"events": events, "count": len(events)})
                    return
                if parts == ["api", "packets"] and self.command == "GET":
                    for field in ("source", "destination"):
                        if params.get(field):
                            try:
                                params[field] = str(ipaddress.IPv4Address(params[field]))
                            except ipaddress.AddressValueError as error:
                                raise ValueError(
                                    "{} must be an IPv4 address".format(field)
                                ) from error
                    if params.get("type") and params["type"] not in (
                        set(DHCP_MESSAGE_TYPES.values()) | {"MALFORMED", "UNKNOWN"}
                    ):
                        raise ValueError("unsupported DHCP packet type")
                    if params.get("mac"):
                        try:
                            params["mac"] = parse_mac(params["mac"]).hex(":")
                        except ValueError as error:
                            raise ValueError("mac must be a valid six-byte MAC address") from error
                    if params.get("since"):
                        params["since"] = _parse_timestamp(
                            params["since"], "since"
                        ).isoformat()
                    if params.get("until"):
                        params["until"] = _parse_timestamp(
                            params["until"], "until"
                        ).isoformat()
                    if params.get("since") and params.get("until"):
                        if _parse_timestamp(params["since"], "since") > _parse_timestamp(
                            params["until"], "until"
                        ):
                            raise ValueError("since must not be later than until")
                    params["limit"] = service._limit(params.get("limit"), 100)
                    packets = service.packets.search(params)
                    self._send(200, {"packets": packets, "count": len(packets)})
                    return
                if parts == ["api", "rules"]:
                    if self.command == "GET":
                        self._send(200, {"rules": service.rules_snapshot()})
                    elif self.command == "POST":
                        self._send(201, {"rule": service.create_rule(self._body())})
                    else:
                        self._send(405, {"error": "method not allowed"})
                    return
                if len(parts) == 3 and parts[:2] == ["api", "leases"]:
                    client = parse_mac(parts[2])
                    if self.command == "GET":
                        lease = service.lease_for(client)
                        if lease is None:
                            raise KeyError("lease not found")
                        self._send(200, {"lease": lease})
                    elif self.command == "DELETE":
                        manager = service.dhcp_server.lease_manager
                        with manager.lock:
                            manager.expire()
                            lease = manager.leases.get(client)
                            if lease is None:
                                raise KeyError("lease not found")
                            address = lease.address
                            if not manager.release(
                                client, quarantine_until_expiry=True
                            ):
                                raise KeyError("lease not found")
                        service.dhcp_server.send_forcerenew(client, address)
                        self._send(200, {"released": True})
                    elif self.command == "PUT":
                        self._send(200, {"lease": service.assign(parts[2], self._body())})
                    else:
                        self._send(405, {"error": "method not allowed"})
                    return
                if len(parts) == 4 and parts[:2] == ["api", "leases"]:
                    client = parse_mac(parts[2])
                    if self.command != "POST":
                        self._send(405, {"error": "method not allowed"})
                        return
                    if parts[3] == "renew":
                        self._send(200, {"lease": service.renew(client)})
                    elif parts[3] == "extend":
                        self._send(200, {"lease": service.extend(client, self._body())})
                    else:
                        self._send(404, {"error": "not found"})
                    return
                if len(parts) == 3 and parts[:2] == ["api", "rules"]:
                    rule_id = parts[2]
                    if self.command in ("PATCH", "PUT"):
                        self._send(
                            200, {"rule": service.update_rule(rule_id, self._body())}
                        )
                    elif self.command == "DELETE":
                        service.delete_rule(rule_id)
                        self._send(200, {"deleted": True})
                    else:
                        self._send(405, {"error": "method not allowed"})
                    return
                self._send(404, {"error": "not found"})

            def do_GET(self):
                self._handle()

            def do_POST(self):
                self._handle()

            def do_PUT(self):
                self._handle()

            def do_PATCH(self):
                self._handle()

            def do_DELETE(self):
                self._handle()

            def _handle(self):
                try:
                    self._dispatch()
                except EventLogError as error:
                    LOG.exception("Could not read the SIEM event log")
                    self._send(500, {"error": str(error)})
                except KeyError as error:
                    self._send(404, {"error": str(error.args[0])})
                except (ValueError, ipaddress.AddressValueError) as error:
                    self._send(400, {"error": str(error)})
                except OSError:
                    LOG.exception("HTTP operation failed")
                    self._send(500, {"error": "storage or network operation failed"})

        self.http_server = ThreadingHTTPServer((host, port), Handler)
        self.http_server.daemon_threads = True
        thread = threading.Thread(
            target=self.http_server.serve_forever, name="dhcp-siem-http", daemon=True
        )
        thread.start()
        LOG.info("Lease/SIEM dashboard listening on http://%s:%d", host, port)
        return self.http_server.server_address

    @staticmethod
    def _limit(value, default):
        if value is None:
            return default
        try:
            limit = int(value)
        except ValueError as error:
            raise ValueError("limit must be an integer") from error
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        return limit

    def close(self):
        self.stop_event.set()
        if self.http_server is not None:
            self.http_server.shutdown()
            self.http_server.server_close()
        self.scheduler.join(timeout=self.evaluation_interval + 1)
