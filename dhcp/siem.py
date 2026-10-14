"""HTTP lease management, JSON audit logging, and scheduled SIEM rules."""

import heapq
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
from http.cookies import CookieError
from http.cookies import SimpleCookie
from typing import Union
from urllib.parse import parse_qs, unquote, urlparse

from .auth import LoginRateLimited, SessionAuth
from .backups import BackupError, BackupManager
from .leases import LeaseManager
from .protocol import DHCP_MESSAGE_TYPES, parse_mac
from .query import QueryError, compile_expression
from .trust import TrustManager

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
    "lease_allocation_deferred",
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
    {
        "id": "unique-discover-churn",
        "name": "Rapid discovery from unique clients",
        "type": "unique_client_rate",
        "threshold": 10,
        "window_seconds": 60,
        "enabled": True,
    },
    {
        "id": "per-client-discover-burst",
        "name": "Repeated discovery burst from one client",
        "type": "per_client_rate",
        "threshold": 20,
        "window_seconds": 60,
        "enabled": True,
    },
    {
        "id": "low-trust-discover-pressure",
        "name": "Low-trust DHCP discovery pressure",
        "type": "low_trust_discover_rate",
        "max_score": 30,
        "threshold": 20,
        "window_seconds": 60,
        "enabled": True,
    },
    {
        "id": "protected-pool-denials",
        "name": "Protected-pool allocation denials",
        "type": "event_rate",
        "event_type": "lease_allocation_deferred",
        "threshold": 5,
        "window_seconds": 60,
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

    def iter_records(self):
        """Yield validated records while holding this log's writer/search lock."""
        with self.lock:
            if not self.path.exists():
                return
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
                    yield record

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
        backup_dir: Union[str, os.PathLike] = "dhcp_backups",
        backup_interval=1800,
        backup_retention_days=30,
        dashboard_password=None,
        trust_file: Union[str, os.PathLike] = "dhcp_trust.json",
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
        self._last_evaluated = {}
        self.trust = TrustManager(
            trust_file,
            self.dhcp_server.pool_start,
            self.dhcp_server.pool_end,
        )
        self.auth = SessionAuth(
            password=dashboard_password
            if dashboard_password is not None
            else os.environ.get("DHCP_DASHBOARD_PASSWORD", "root")
        )
        self.dhcp_server.lease_manager.event_callback = self.record_event
        self.dhcp_server.lease_manager.allocation_guard = (
            self.trust.allow_new_dynamic_lease
        )
        self.dhcp_server.packet_callback = self.record_packet
        self.dhcp_server.client_presence_callback = self.trust.observe
        self.dhcp_server.client_renewal_callback = self.trust.record_renewal
        self.http_server = None
        lease_file = self.dhcp_server.lease_manager.lease_file
        if lease_file is None:
            raise ValueError("dashboard backups require a persistent DHCP lease file")
        self.backups = BackupManager(
            backup_dir,
            {
                "lease_state": (lease_file, self.dhcp_server.lease_manager.lock),
                "rules": (self.rules_file, self.lock),
                "trust_state": (self.trust.path, self.trust.lock),
                "audit_log": (self.events.path, self.events.lock),
                "packet_log": (self.packets.path, self.packets.lock),
            },
            interval_seconds=backup_interval,
            retention_days=backup_retention_days,
        )
        self.scheduler = threading.Thread(
            target=self._schedule_rules, name="dhcp-siem-rules", daemon=True
        )
        self.scheduler.start()

    def record_event(self, event_type, **fields):
        return self.events.append(event_type, **fields)

    def record_packet(self, **fields):
        client_mac = fields.get("client_mac")
        if client_mac:
            profile = self.trust.get_profile(client_mac)
            fields.update(
                {
                    "trust_score": profile["score"],
                    "automatic_trust_score": profile["automatic_score"],
                    "trust_score_source": profile["score_source"],
                    "trusted": profile["trusted"],
                }
            )
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
        validated = [self._validate_rule(rule) for rule in rules]
        identifiers = [rule["id"] for rule in validated]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("SIEM rules file contains duplicate rule IDs")
        builtin_version = state.get("builtin_version", 0)
        if (
            isinstance(builtin_version, bool)
            or not isinstance(builtin_version, int)
            or builtin_version not in (0, 1)
        ):
            raise ValueError("unsupported SIEM built-in rule version")
        if builtin_version < 1:
            existing = {rule["id"] for rule in validated}
            validated.extend(
                dict(rule)
                for rule in DEFAULT_RULES
                if rule["id"] not in existing
            )
            self._save_rules(validated)
        return validated

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
                json.dump(
                    {"version": 1, "builtin_version": 1, "rules": rules},
                    rules_file,
                    indent=2,
                )
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
        elif rule_type == "expression":
            expression = rule.get("expression")
            interval = rule.get("interval_seconds", 60)
            if not isinstance(expression, str):
                raise ValueError("expression must be a string")
            compile_expression(expression, allow_count=True)
            if (
                isinstance(interval, bool)
                or not isinstance(interval, int)
                or not 1 <= interval <= 30 * 24 * 60 * 60
            ):
                raise ValueError("interval_seconds must be between 1 and 2592000")
            result = {
                "id": str(rule.get("id") or uuid.uuid4()),
                "name": str(rule.get("name") or "Expression rule"),
                "type": rule_type,
                "expression": expression,
                "interval_seconds": interval,
                "enabled": rule.get("enabled", True),
            }
        elif rule_type in (
            "unique_client_rate",
            "per_client_rate",
            "low_trust_discover_rate",
        ):
            threshold = rule.get("threshold")
            window = rule.get("window_seconds")
            if (
                isinstance(threshold, bool)
                or not isinstance(threshold, int)
                or threshold < 1
            ):
                raise ValueError("threshold must be a positive integer")
            if (
                isinstance(window, bool)
                or not isinstance(window, int)
                or not 1 <= window <= 30 * 24 * 60 * 60
            ):
                raise ValueError("window_seconds must be between 1 and 2592000")
            result = {
                "id": str(rule.get("id") or uuid.uuid4()),
                "name": str(rule.get("name") or "DHCP discovery rate rule"),
                "type": rule_type,
                "threshold": threshold,
                "window_seconds": window,
                "enabled": rule.get("enabled", True),
            }
            if rule_type == "low_trust_discover_rate":
                max_score = rule.get("max_score", 30)
                if (
                    isinstance(max_score, bool)
                    or not isinstance(max_score, int)
                    or not 0 <= max_score <= 100
                ):
                    raise ValueError("max_score must be from 0 to 100")
                result["max_score"] = max_score
        else:
            raise ValueError(
                "unsupported rule type; expected event_rate, pool_usage, expression, "
                "unique_client_rate, per_client_rate, or low_trust_discover_rate"
            )
        if not isinstance(result["enabled"], bool):
            raise ValueError("enabled must be a boolean")
        if (
            not result["id"]
            or not result["name"]
            or len(result["id"]) > 128
            or len(result["name"]) > 100
        ):
            raise ValueError("rule id and name must contain 1 to 128 and 1 to 100 characters")
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

    def trust_profiles(self, query=None, limit=1000):
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        profiles = self.trust.list_profiles(query=query, limit=limit)
        return {"profiles": profiles, "count": len(profiles)}

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

    def search_logs(self, expression, source="all", limit=100):
        """Search arbitrary audit/packet JSON fields with a safe expression."""
        if source not in ("all", "events", "packets"):
            raise ValueError("source must be all, events, or packets")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        query = compile_expression(expression)
        logs = []
        if source in ("all", "events"):
            logs.append(("audit", self.events))
        if source in ("all", "packets"):
            logs.append(("packet", self.packets))

        heap = []
        match_count = 0
        sequence = 0
        for label, event_log in logs:
            for stored_record in event_log.iter_records():
                record = dict(stored_record)
                record["source_log"] = label
                if not query.matches(record):
                    continue
                try:
                    timestamp = _parse_timestamp(
                        record.get("timestamp", ""), "log timestamp"
                    ).timestamp()
                except ValueError as error:
                    raise EventLogError("matching log record has an invalid timestamp") from error
                match_count += 1
                sequence += 1
                item = (timestamp, sequence, record)
                if len(heap) < limit:
                    heapq.heappush(heap, item)
                elif item[:2] > heap[0][:2]:
                    heapq.heapreplace(heap, item)
        matches = [
            item[2]
            for item in sorted(heap, key=lambda item: item[:2], reverse=True)
        ]
        return {"records": matches, "count": match_count}

    def _count_matching_records(self, query, window_seconds, now):
        cutoff = now - window_seconds
        count = 0
        scanned = 0
        for label, event_log in (("audit", self.events), ("packet", self.packets)):
            for stored_record in event_log.iter_records():
                scanned += 1
                if scanned > 100000:
                    raise QueryError("count_if() scan exceeded 100000 log records")
                record = dict(stored_record)
                record["source_log"] = label
                try:
                    timestamp = _parse_timestamp(
                        record.get("timestamp", ""), "log timestamp"
                    ).timestamp()
                except ValueError as error:
                    raise EventLogError(
                        "log record has an invalid timestamp"
                    ) from error
                if timestamp >= cutoff and query.matches(record):
                    count += 1
        return count

    def _discover_activity(self, window_seconds, max_score=None, now=None):
        cutoff = (time.time() if now is None else now) - window_seconds
        by_client = {}
        scanned = 0
        for record in self.packets.iter_records():
            scanned += 1
            if scanned > 100000:
                raise QueryError("discovery rule scan exceeded 100000 packet records")
            if record.get("packet_type") != "DHCPDISCOVER":
                continue
            client_mac = record.get("client_mac")
            if not isinstance(client_mac, str):
                continue
            try:
                timestamp = _parse_timestamp(
                    record.get("timestamp", ""), "packet timestamp"
                ).timestamp()
            except ValueError as error:
                raise EventLogError(
                    "packet record has an invalid timestamp"
                ) from error
            if timestamp < cutoff:
                continue
            score = record.get("trust_score", 0)
            if (
                max_score is not None
                and (isinstance(score, bool) or not isinstance(score, int)
                     or score > max_score)
            ):
                continue
            normalized_mac = client_mac.lower()
            by_client[normalized_mac] = by_client.get(normalized_mac, 0) + 1
        return {
            "unique_clients": len(by_client),
            "discoveries": sum(by_client.values()),
            "max_per_client": max(by_client.values(), default=0),
        }

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
        count_cache = {}
        for rule in rules:
            if rule["type"] == "expression":
                interval = rule["interval_seconds"]
                with self.lock:
                    last_evaluated = self._last_evaluated.get(rule["id"], 0)
                    if now - last_evaluated < interval:
                        continue
                    self._last_evaluated[rule["id"]] = now
                expression = compile_expression(
                    rule["expression"], allow_count=True
                )

                def count_callback(query, seconds):
                    key = (query.source, seconds)
                    if key not in count_cache:
                        count_cache[key] = self._count_matching_records(
                            query, seconds, now
                        )
                    return count_cache[key]

                metrics = {
                    "active_leases": len(leases),
                    "pool_capacity": pool_size,
                    "pool_usage": pool_usage,
                }
                triggered = expression.matches(metrics, count_callback)
                detail = "expression evaluated to {}".format(triggered)
                if not triggered:
                    scanned = 0
                    for label, event_log in (("audit", self.events), ("packet", self.packets)):
                        for stored_record in event_log.iter_records():
                            scanned += 1
                            if scanned > 100000:
                                raise QueryError("rule scan exceeded 100000 log records")
                            record = dict(stored_record)
                            record["source_log"] = label
                            try:
                                timestamp = _parse_timestamp(
                                    record.get("timestamp", ""), "log timestamp"
                                ).timestamp()
                            except ValueError as error:
                                raise EventLogError(
                                    "log record has an invalid timestamp"
                                ) from error
                            if timestamp < now - interval:
                                continue
                            context = dict(metrics)
                            context.update(record)
                            if expression.matches(context, count_callback):
                                triggered = True
                                detail = "expression matched a log record"
                                break
                        if triggered:
                            break
            elif rule["type"] == "event_rate":
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
            elif rule["type"] in (
                "unique_client_rate",
                "per_client_rate",
                "low_trust_discover_rate",
            ):
                activity = self._discover_activity(
                    rule["window_seconds"],
                    max_score=(
                        rule["max_score"]
                        if rule["type"] == "low_trust_discover_rate"
                        else None
                    ),
                    now=now,
                )
                if rule["type"] == "unique_client_rate":
                    observed = activity["unique_clients"]
                    label = "unique clients"
                elif rule["type"] == "per_client_rate":
                    observed = activity["max_per_client"]
                    label = "DISCOVER packets from one client"
                else:
                    observed = activity["discoveries"]
                    label = "low-trust DISCOVER packets"
                triggered = observed >= rule["threshold"]
                detail = "{} {} in {} seconds".format(
                    observed, label, rule["window_seconds"]
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
                    severity=(
                        "high"
                        if rule["type"]
                        in (
                            "event_rate",
                            "per_client_rate",
                            "low_trust_discover_rate",
                        )
                        else "medium"
                    ),
                    details=detail,
                )
            )
        return alerts

    def _schedule_rules(self):
        while True:
            with self.lock:
                expression_intervals = [
                    rule["interval_seconds"]
                    for rule in self.rules
                    if rule.get("enabled") and rule["type"] == "expression"
                ]
            interval = min(
                [self.evaluation_interval] + expression_intervals
            )
            if self.stop_event.wait(interval):
                return
            try:
                self.evaluate_rules()
            except (OSError, ValueError):
                LOG.exception("SIEM rule evaluation failed")

    def _validate_backup_payloads(self, payloads):
        manager = self.dhcp_server.lease_manager
        lease_data = payloads["lease_state"]
        if lease_data is not None:
            with tempfile.TemporaryDirectory() as temp_dir:
                lease_path = Path(temp_dir) / "leases.json"
                lease_path.write_bytes(lease_data)
                LeaseManager(
                    network=manager.network,
                    server_ip=manager.server_ip,
                    pool_start=manager.pool_start,
                    pool_end=manager.pool_end,
                    lease_seconds=manager.lease_seconds,
                    decline_hold_seconds=manager.decline_hold_seconds,
                    lease_file=lease_path,
                    reservations=list(manager.reservations.items()),
                )
        rules_data = payloads["rules"]
        if rules_data is not None:
            try:
                state = json.loads(rules_data.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise BackupError("backup SIEM rules are not valid JSON") from error
            if (
                not isinstance(state, dict)
                or state.get("version") != 1
                or not isinstance(state.get("rules"), list)
            ):
                raise BackupError("backup SIEM rules have an unsupported format")
            rules = [self._validate_rule(rule) for rule in state["rules"]]
            identifiers = [rule["id"] for rule in rules]
            if len(identifiers) != len(set(identifiers)):
                raise BackupError("backup SIEM rules contain duplicate IDs")
        trust_data = payloads.get("trust_state")
        if trust_data is not None:
            try:
                with tempfile.TemporaryDirectory() as temp_dir:
                    trust_path = Path(temp_dir) / "trust.json"
                    trust_path.write_bytes(trust_data)
                    TrustManager(
                        trust_path,
                        manager.pool_start,
                        manager.pool_end,
                    )
            except (OSError, ValueError) as error:
                raise BackupError(
                    "backup DHCP trust profiles are invalid: {}".format(error)
                ) from error

    def restore_backup(self, filename):
        """Restore lease/rule state from a verified checkpoint, retaining logs."""
        def reload_state():
            manager = self.dhcp_server.lease_manager
            manager.leases.clear()
            manager.quarantined.clear()
            manager.load_state()
            self.trust.load()
            with self.lock:
                self.rules = self._load_rules()
                self._last_evaluated.clear()
                self._last_triggered.clear()

        return self.backups.restore_state(
            filename,
            validate=self._validate_backup_payloads,
            reload_state=reload_state,
        )

    def start_http(self, host="0.0.0.0", port=8080):
        service = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format_string, *args):
                LOG.info("HTTP %s - %s", self.address_string(), format_string % args)

            def _send(self, status, value, headers=()):
                payload = json.dumps(value, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                for name, value in headers:
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(payload)

            def _session_token(self):
                cookie = SimpleCookie()
                try:
                    cookie.load(self.headers.get("Cookie", ""))
                except CookieError:
                    return None
                morsel = cookie.get("dhcp_session")
                return morsel.value if morsel is not None else None

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
                parts = [unquote(part) for part in parsed.path.split("/") if part]
                if parsed.path in ("/", "/index.html") and self.command == "GET":
                    self._send_dashboard()
                    return

                token = self._session_token()
                session = service.auth.session(token)
                if parts == ["api", "auth", "login"] and self.command == "POST":
                    credentials = self._body()
                    try:
                        result = service.auth.login(
                            self.client_address[0],
                            credentials.get("username"),
                            credentials.get("password"),
                        )
                    except LoginRateLimited as error:
                        self._send(429, {"error": str(error)})
                        return
                    if result is None:
                        self._send(401, {"error": "invalid username or password"})
                        return
                    token, csrf_token = result
                    self._send(
                        200,
                        {"authenticated": True, "csrf_token": csrf_token},
                        (
                            (
                                "Set-Cookie",
                                "dhcp_session={}; Path=/; Max-Age={}; HttpOnly; SameSite=Strict".format(
                                    token, service.auth.session_seconds
                                ),
                            ),
                        ),
                    )
                    return
                if parts == ["api", "auth", "session"] and self.command == "GET":
                    if session is None:
                        self._send(200, {"authenticated": False})
                    else:
                        self._send(
                            200,
                            {"authenticated": True, "csrf_token": session["csrf"]},
                        )
                    return
                if parsed.path.startswith("/api/") and session is None:
                    self._send(401, {"error": "authentication required"})
                    return
                if (
                    parsed.path.startswith("/api/")
                    and self.command not in ("GET", "HEAD")
                    and not service.auth.validate_csrf(
                        token, self.headers.get("X-CSRF-Token")
                    )
                ):
                    self._send(403, {"error": "valid CSRF token required"})
                    return
                if parts == ["api", "auth", "logout"] and self.command == "POST":
                    service.auth.logout(token)
                    self._send(
                        200,
                        {"authenticated": False},
                        (("Set-Cookie", "dhcp_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"),),
                    )
                    return

                query = parse_qs(parsed.query)
                params = {key: values[-1] for key, values in query.items() if values}
                if params.get("client"):
                    params["client"] = parse_mac(params["client"]).hex(":")
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
                if parts == ["api", "search"] and self.command == "GET":
                    if not params.get("expr"):
                        raise ValueError("expr query parameter is required")
                    limit = service._limit(params.get("limit"), 100)
                    result = service.search_logs(
                        params["expr"],
                        source=params.get("source", "all"),
                        limit=limit,
                    )
                    self._send(200, result)
                    return
                if parts == ["api", "trust", "policy"]:
                    if self.command == "GET":
                        policy = service.trust.policy_snapshot()
                        active_leases = service.list_leases({})
                        occupied = sum(
                            int(service.dhcp_server.pool_start)
                            <= int(ipaddress.IPv4Address(lease["address"]))
                            <= int(service.dhcp_server.pool_end)
                            for lease in active_leases
                        )
                        untrusted_limit = (
                            service.trust.untrusted_allocation_limit()
                        )
                        self._send(
                            200,
                            {
                                **policy,
                                "pool_capacity": service.trust.pool_capacity,
                                "active_pool_addresses": occupied,
                                "untrusted_allocation_limit": untrusted_limit,
                                "protected_addresses": (
                                    service.trust.pool_capacity - untrusted_limit
                                ),
                                "profiles_count": service.trust.profile_count(),
                            },
                        )
                    elif self.command in ("PUT", "PATCH"):
                        policy = service.trust.configure_policy(self._body())
                        self._send(200, policy)
                    else:
                        self._send(405, {"error": "method not allowed"})
                    return
                if parts == ["api", "trust", "clients"] and self.command == "GET":
                    limit = service._limit(params.get("limit"), 1000)
                    result = service.trust_profiles(
                        query=params.get("q"),
                        limit=limit,
                    )
                    self._send(200, result)
                    return
                if (
                    len(parts) == 4
                    and parts[:3] == ["api", "trust", "clients"]
                ):
                    try:
                        client = parse_mac(parts[3])
                    except ValueError as error:
                        raise ValueError("client must be a valid six-byte MAC address") from error
                    normalized_mac = client.hex(":")
                    if self.command == "GET":
                        if not service.trust.has_profile(client):
                            raise KeyError("client trust profile not found")
                        self._send(
                            200,
                            {"profile": service.trust.get_profile(client)},
                        )
                    elif self.command == "PATCH":
                        changes = self._body()
                        clear_override = changes.get("clear_override", False)
                        if not isinstance(clear_override, bool):
                            raise ValueError("clear_override must be a boolean")
                        if clear_override:
                            if "manual_score" in changes:
                                raise ValueError(
                                    "manual_score cannot be combined with clear_override"
                                )
                            profile = service.trust.clear_manual_score(client)
                        elif "manual_score" in changes and len(changes) == 1:
                            profile = service.trust.set_manual_score(
                                client, changes["manual_score"]
                            )
                        else:
                            raise ValueError(
                                "provide manual_score or clear_override=true"
                            )
                        self._send(200, {"profile": profile})
                    elif self.command == "DELETE":
                        service.trust.remove_profile(client)
                        self._send(200, {"removed": True, "mac": normalized_mac})
                    else:
                        self._send(405, {"error": "method not allowed"})
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
                if parts == ["api", "backups"]:
                    if self.command == "GET":
                        self._send(
                            200,
                            {"backups": service.backups.list_snapshots()},
                        )
                    elif self.command == "POST":
                        name = service.backups.create_snapshot("manual")
                        self._send(201, {"backup": name})
                    else:
                        self._send(405, {"error": "method not allowed"})
                    return
                if (
                    len(parts) == 4
                    and parts[:2] == ["api", "backups"]
                    and parts[3] == "restore"
                ):
                    if self.command != "POST":
                        self._send(405, {"error": "method not allowed"})
                        return
                    self._send(
                        200,
                        service.restore_backup(parts[2]),
                    )
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
        self.backups.close()
