"""Persistent DHCP client trust profiles and protected-pool policy."""

import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

from .protocol import parse_mac


class TrustManager:
    """Track bounded trust evidence and allocate capacity by score."""

    VERSION = 1
    DEFAULT_OCCUPANCY_THRESHOLD = 80
    DEFAULT_TRUSTED_SCORE = 60

    def __init__(self, path, pool_start, pool_end):
        self.path = Path(path)
        self.pool_start = int(pool_start)
        self.pool_end = int(pool_end)
        if self.pool_end < self.pool_start:
            raise ValueError("trust manager pool end must not precede pool start")
        self.pool_capacity = self.pool_end - self.pool_start + 1
        self.lock = threading.RLock()
        self.policy = {
            "occupancy_threshold_percent": self.DEFAULT_OCCUPANCY_THRESHOLD,
            "trusted_score_threshold": self.DEFAULT_TRUSTED_SCORE,
        }
        self.clients = {}
        self.load()

    @staticmethod
    def _validate_score(value, name):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
            raise ValueError("{} must be an integer from 0 to 100".format(name))
        return value

    @staticmethod
    def _normalize_mac(mac):
        if isinstance(mac, str):
            return parse_mac(mac).hex(":")
        value = bytes(mac)
        if len(value) != 6:
            raise ValueError("MAC address must contain exactly six bytes")
        return value.hex(":")

    def load(self):
        """Load and validate the persisted trust registry, if present."""
        with self.lock:
            self.policy = {
                "occupancy_threshold_percent": self.DEFAULT_OCCUPANCY_THRESHOLD,
                "trusted_score_threshold": self.DEFAULT_TRUSTED_SCORE,
            }
            self.clients = {}
        if not self.path.exists():
            return
        try:
            with self.path.open("r", encoding="utf-8") as trust_file:
                state = json.load(trust_file)
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError("could not read DHCP trust file: {}".format(error)) from error
        if (
            not isinstance(state, dict)
            or isinstance(state.get("version"), bool)
            or state.get("version") != self.VERSION
            or not isinstance(state.get("policy"), dict)
            or not isinstance(state.get("clients"), dict)
        ):
            raise ValueError("unsupported or invalid DHCP trust file format")
        policy = state["policy"]
        occupancy = self._validate_score(
            policy.get("occupancy_threshold_percent"),
            "occupancy_threshold_percent",
        )
        trusted_score = self._validate_score(
            policy.get("trusted_score_threshold"), "trusted_score_threshold"
        )
        clients = {}
        for mac, profile in state["clients"].items():
            try:
                normalized = self._normalize_mac(mac)
            except (TypeError, ValueError) as error:
                raise ValueError("invalid MAC address in DHCP trust file") from error
            if normalized != mac or not isinstance(profile, dict):
                raise ValueError("invalid client profile in DHCP trust file")
            renewals = profile.get("successful_renewals")
            sightings = profile.get("sighting_days")
            if (
                isinstance(renewals, bool)
                or not isinstance(renewals, int)
                or renewals < 0
                or isinstance(sightings, bool)
                or not isinstance(sightings, int)
                or sightings < 0
            ):
                raise ValueError("invalid trust evidence counts for {}".format(mac))
            last_day = profile.get("last_sighting_day")
            if last_day is not None:
                try:
                    if not isinstance(last_day, str):
                        raise ValueError
                    datetime.strptime(last_day, "%Y-%m-%d")
                except ValueError as error:
                    raise ValueError(
                        "invalid sighting day for {}".format(mac)
                    ) from error
            last_seen = profile.get("last_seen")
            if last_seen is not None and not isinstance(last_seen, str):
                raise ValueError("invalid last-seen value for {}".format(mac))
            last_renewed = profile.get("last_renewed")
            if last_renewed is not None and not isinstance(last_renewed, str):
                raise ValueError("invalid last-renewed value for {}".format(mac))
            manual_score = profile.get("manual_score")
            if manual_score is not None:
                self._validate_score(manual_score, "manual_score")
            clients[normalized] = {
                "successful_renewals": renewals,
                "sighting_days": sightings,
                "last_sighting_day": last_day,
                "last_seen": last_seen,
                "last_renewed": last_renewed,
                "manual_score": manual_score,
            }
        with self.lock:
            self.policy = {
                "occupancy_threshold_percent": occupancy,
                "trusted_score_threshold": trusted_score,
            }
            self.clients = clients

    def _save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        state = {
            "version": self.VERSION,
            "policy": dict(self.policy),
            "clients": {
                mac: dict(profile) for mac, profile in sorted(self.clients.items())
            },
        }
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=str(self.path.parent),
                prefix=self.path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as trust_file:
                temp_path = Path(trust_file.name)
                json.dump(state, trust_file, indent=2, sort_keys=True)
                trust_file.write("\n")
                trust_file.flush()
                os.fsync(trust_file.fileno())
            os.replace(str(temp_path), str(self.path))
        finally:
            if temp_path is not None and temp_path.exists():
                temp_path.unlink()

    def _profile(self, mac, profile):
        automatic_score = min(
            100,
            10 * profile["successful_renewals"] + 2 * profile["sighting_days"],
        )
        score = (
            profile["manual_score"]
            if profile["manual_score"] is not None
            else automatic_score
        )
        return {
            "mac": mac,
            "successful_renewals": profile["successful_renewals"],
            "sighting_days": profile["sighting_days"],
            "last_seen": profile["last_seen"],
            "last_renewed": profile["last_renewed"],
            "automatic_score": automatic_score,
            "manual_score": profile["manual_score"],
            "score": score,
            "score_source": "manual" if profile["manual_score"] is not None else "automatic",
            "trusted": score >= self.policy["trusted_score_threshold"],
        }

    def policy_snapshot(self):
        with self.lock:
            return dict(self.policy)

    def untrusted_allocation_limit(self):
        with self.lock:
            threshold = self.policy["occupancy_threshold_percent"]
            limit = self.pool_capacity * threshold // 100
            if threshold > 0:
                limit = max(1, limit)
            return limit

    def configure_policy(self, changes):
        if not isinstance(changes, dict) or not changes:
            raise ValueError("trust policy update must be a non-empty JSON object")
        allowed = {"occupancy_threshold_percent", "trusted_score_threshold"}
        if set(changes) - allowed:
            raise ValueError("unsupported trust policy field")
        with self.lock:
            updated = dict(self.policy)
            if "occupancy_threshold_percent" in changes:
                updated["occupancy_threshold_percent"] = self._validate_score(
                    changes["occupancy_threshold_percent"],
                    "occupancy_threshold_percent",
                )
            if "trusted_score_threshold" in changes:
                updated["trusted_score_threshold"] = self._validate_score(
                    changes["trusted_score_threshold"], "trusted_score_threshold"
                )
            previous = self.policy
            self.policy = updated
            try:
                self._save()
            except OSError:
                self.policy = previous
                raise
            return dict(self.policy)

    def observe(self, mac, timestamp=None):
        """Record at most one valid DHCP sighting for a MAC per UTC day."""
        normalized = self._normalize_mac(mac)
        observed_at = timestamp or datetime.now(timezone.utc).isoformat()
        try:
            parsed = datetime.fromisoformat(
                observed_at.replace("Z", "+00:00")
            ).astimezone(timezone.utc)
        except (AttributeError, TypeError, ValueError) as error:
            raise ValueError("sighting timestamp must be ISO-8601") from error
        day = parsed.date().isoformat()
        with self.lock:
            existed = normalized in self.clients
            profile = self.clients.setdefault(
                normalized,
                {
                    "successful_renewals": 0,
                    "sighting_days": 0,
                    "last_sighting_day": None,
                    "last_seen": None,
                    "last_renewed": None,
                    "manual_score": None,
                },
            )
            if profile["last_sighting_day"] != day:
                previous = dict(profile)
                profile["sighting_days"] += 1
                profile["last_sighting_day"] = day
                profile["last_seen"] = parsed.isoformat()
                try:
                    self._save()
                except OSError:
                    if existed:
                        self.clients[normalized] = previous
                    else:
                        self.clients.pop(normalized, None)
                    raise
            return self._profile(normalized, profile)

    def record_renewal(self, mac, timestamp=None):
        """Record a successfully acknowledged client-initiated renewal."""
        normalized = self._normalize_mac(mac)
        renewed_at = timestamp or datetime.now(timezone.utc).isoformat()
        with self.lock:
            existed = normalized in self.clients
            profile = self.clients.setdefault(
                normalized,
                {
                    "successful_renewals": 0,
                    "sighting_days": 0,
                    "last_sighting_day": None,
                    "last_seen": None,
                    "last_renewed": None,
                    "manual_score": None,
                },
            )
            previous = dict(profile)
            profile["successful_renewals"] += 1
            profile["last_renewed"] = renewed_at
            try:
                self._save()
            except OSError:
                if existed:
                    self.clients[normalized] = previous
                else:
                    self.clients.pop(normalized, None)
                raise
            return self._profile(normalized, profile)

    def get_profile(self, mac):
        normalized = self._normalize_mac(mac)
        with self.lock:
            profile = self.clients.get(normalized)
            if profile is None:
                profile = {
                    "successful_renewals": 0,
                    "sighting_days": 0,
                    "last_sighting_day": None,
                    "last_seen": None,
                    "last_renewed": None,
                    "manual_score": None,
                }
            return self._profile(normalized, profile)

    def has_profile(self, mac):
        normalized = self._normalize_mac(mac)
        with self.lock:
            return normalized in self.clients

    def profile_count(self):
        with self.lock:
            return len(self.clients)

    def list_profiles(self, query=None, limit=500):
        term = query.casefold() if query else None
        with self.lock:
            profiles = [
                self._profile(mac, profile)
                for mac, profile in self.clients.items()
                if term is None or term in mac
            ]
        profiles.sort(key=lambda item: (item["score"], item["mac"]), reverse=True)
        return profiles[:limit]

    def set_manual_score(self, mac, score):
        normalized = self._normalize_mac(mac)
        self._validate_score(score, "manual_score")
        with self.lock:
            existed = normalized in self.clients
            profile = self.clients.setdefault(
                normalized,
                {
                    "successful_renewals": 0,
                    "sighting_days": 0,
                    "last_sighting_day": None,
                    "last_seen": None,
                    "last_renewed": None,
                    "manual_score": None,
                },
            )
            previous = dict(profile)
            profile["manual_score"] = score
            try:
                self._save()
            except OSError:
                if existed:
                    self.clients[normalized] = previous
                else:
                    self.clients.pop(normalized, None)
                raise
            return self._profile(normalized, profile)

    def clear_manual_score(self, mac):
        normalized = self._normalize_mac(mac)
        with self.lock:
            profile = self.clients.get(normalized)
            if profile is None:
                raise KeyError("client trust profile not found")
            previous = dict(profile)
            profile["manual_score"] = None
            try:
                self._save()
            except OSError:
                self.clients[normalized] = previous
                raise
            return self._profile(normalized, profile)

    def remove_profile(self, mac):
        normalized = self._normalize_mac(mac)
        with self.lock:
            if normalized not in self.clients:
                raise KeyError("client trust profile not found")
            previous = self.clients.pop(normalized)
            try:
                self._save()
            except OSError:
                self.clients[normalized] = previous
                raise

    def allow_new_dynamic_lease(self, mac, occupied_count, is_reserved=False):
        """Keep a threshold-sized portion of the pool available for trusted MACs."""
        with self.lock:
            if is_reserved or self._profile_for_mac(mac)["trusted"]:
                return True
            return occupied_count < self.untrusted_allocation_limit()

    def _profile_for_mac(self, mac):
        normalized = self._normalize_mac(mac)
        profile = self.clients.get(normalized)
        if profile is None:
            profile = {
                "successful_renewals": 0,
                "sighting_days": 0,
                "last_sighting_day": None,
                "last_seen": None,
                "last_renewed": None,
                "manual_score": None,
            }
        return self._profile(normalized, profile)
