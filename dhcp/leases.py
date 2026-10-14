"""Lease allocation, reservations, quarantine, and persistent state."""

import json
import logging
import math
import os
import tempfile
import threading
import time
from pathlib import Path

import ipaddress

from .protocol import Lease, parse_mac

LOG = logging.getLogger("dhcp-server")


class LeaseManager:
    """Own lease state and persist it independently of packet processing."""

    def __init__(
        self,
        network,
        server_ip,
        pool_start,
        pool_end,
        lease_seconds,
        decline_hold_seconds,
        lease_file,
        reservations,
    ):
        self.network = network
        self.server_ip = server_ip
        self.pool_start = pool_start
        self.pool_end = pool_end
        self.lease_seconds = lease_seconds
        self.decline_hold_seconds = decline_hold_seconds
        self.lease_file = Path(lease_file) if lease_file else None
        self.reservations = {}
        self.reserved_addresses = {}
        for client, address in reservations:
            client = parse_mac(client) if isinstance(client, str) else bytes(client)
            address = ipaddress.IPv4Address(address)
            if len(client) != 6:
                raise ValueError("reservation client identifier must be a six-byte MAC")
            if (
                address not in self.network
                or address
                in (self.network.network_address, self.network.broadcast_address)
                or address == self.server_ip
            ):
                raise ValueError("reserved addresses must be usable addresses in the subnet")
            if client in self.reservations:
                raise ValueError("duplicate reservation for {}".format(client.hex(":")))
            if address in self.reserved_addresses:
                raise ValueError("address {} is reserved more than once".format(address))
            self.reservations[client] = address
            self.reserved_addresses[address] = client

        self.leases = {}
        self.quarantined = {}
        self.lock = threading.RLock()
        self.event_callback = None
        self.allocation_guard = None
        if self.lease_file is not None:
            self.load_state()

    def _record_event(self, event_type, **fields):
        if self.event_callback is not None:
            self.event_callback(event_type, **fields)

    def _address_is_valid(self, client, address):
        if address is None or address not in self.network:
            return False
        if address in (self.network.network_address, self.network.broadcast_address):
            return False
        if address == self.server_ip or address in self.quarantined:
            return False
        reserved_for = self.reserved_addresses.get(address)
        if reserved_for is not None:
            return reserved_for == client
        if client in self.reservations:
            return False
        return int(self.pool_start) <= int(address) <= int(self.pool_end)

    def _persist_state(self):
        """Atomically replace the state file so interrupted writes don't corrupt it."""
        if self.lease_file is None:
            return
        now_mono = time.monotonic()
        now_wall = time.time()
        state = {
            "version": 1,
            "leases": [
                {
                    "client": client.hex(),
                    "address": str(lease.address),
                    "expires_at": now_wall + lease.expires_at - now_mono,
                    "lease_seconds": lease.lease_seconds,
                }
                for client, lease in self.leases.items()
            ],
            "quarantined": [
                {"address": str(address), "expires_at": now_wall + expiry - now_mono}
                for address, expiry in self.quarantined.items()
            ],
        }
        self.lease_file.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            # Keep the temporary file beside the target so replace is atomic
            # on the same filesystem.
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=str(self.lease_file.parent),
                prefix=self.lease_file.name + ".",
                suffix=".tmp",
                delete=False,
            ) as state_file:
                temp_path = Path(state_file.name)
                json.dump(state, state_file, indent=2)
                state_file.write("\n")
                state_file.flush()
                os.fsync(state_file.fileno())
            os.replace(str(temp_path), str(self.lease_file))
        finally:
            if temp_path is not None and temp_path.exists():
                temp_path.unlink()

    def load_state(self):
        """Load valid, unexpired leases and quarantines from the JSON state file."""
        self.leases = {}
        self.quarantined = {}
        try:
            with self.lease_file.open("r", encoding="utf-8") as state_file:
                state = json.load(state_file)
        except FileNotFoundError:
            return
        if (
            not isinstance(state, dict)
            or isinstance(state.get("version"), bool)
            or state.get("version") != 1
        ):
            raise ValueError("unsupported or invalid DHCP lease file format")
        if not isinstance(state.get("leases"), list) or not isinstance(
            state.get("quarantined"), list
        ):
            raise ValueError("DHCP lease file must contain lease and quarantine lists")

        now_wall = time.time()
        now_mono = time.monotonic()
        loaded = {}
        used_addresses = set()
        for item in state["leases"]:
            if not isinstance(item, dict):
                raise ValueError("invalid entry in DHCP lease file")
            try:
                client = bytes.fromhex(item["client"])
                address = ipaddress.IPv4Address(item["address"])
                remaining = float(item["expires_at"]) - now_wall
            except (KeyError, TypeError, ValueError, OverflowError) as error:
                raise ValueError("invalid entry in DHCP lease file") from error
            if len(client) != 6 or remaining <= 0:
                continue
            if not math.isfinite(remaining):
                raise ValueError("lease expiry must be a finite timestamp")
            if client in loaded:
                LOG.warning("Ignoring duplicate persisted lease for client %s", client.hex())
                continue
            if not self._address_is_valid(client, address):
                LOG.warning("Ignoring persisted lease for invalid address %s", address)
                continue
            if address in used_addresses:
                LOG.warning("Ignoring duplicate persisted lease for %s", address)
                continue
            # Persist wall-clock timestamps, but use monotonic time while running
            # to avoid lease behavior changing when the system clock is adjusted.
            lease_seconds = item.get("lease_seconds")
            if lease_seconds is not None and (
                isinstance(lease_seconds, bool)
                or not isinstance(lease_seconds, int)
                or not 1 <= lease_seconds <= 0xFFFFFFFF
            ):
                raise ValueError("invalid lease duration in DHCP lease file")
            loaded[client] = Lease(address, now_mono + remaining, lease_seconds)
            used_addresses.add(address)

        quarantined = {}
        for item in state["quarantined"]:
            if not isinstance(item, dict):
                raise ValueError("invalid quarantine entry in DHCP lease file")
            try:
                address = ipaddress.IPv4Address(item["address"])
                remaining = float(item["expires_at"]) - now_wall
            except (KeyError, TypeError, ValueError, OverflowError) as error:
                raise ValueError("invalid quarantine entry in DHCP lease file") from error
            if (
                math.isfinite(remaining)
                and remaining > 0
                and address in self.network
                and (
                    int(self.pool_start) <= int(address) <= int(self.pool_end)
                    or address in self.reserved_addresses
                )
                and address != self.server_ip
            ):
                quarantined[address] = now_mono + remaining
        self.quarantined = quarantined
        # Declined addresses must not remain active leases after a restart.
        self.leases = {
            client: lease
            for client, lease in loaded.items()
            if lease.address not in self.quarantined
        }

    def expire(self):
        """Remove expired leases and quarantines, persisting changes when needed."""
        with self.lock:
            now = time.monotonic()
            old_lease_count = len(self.leases)
            old_quarantine_count = len(self.quarantined)
            expired_leases = [
                (client, lease)
                for client, lease in self.leases.items()
                if lease.expires_at <= now
            ]
            self.leases = {
                client: lease
                for client, lease in self.leases.items()
                if lease.expires_at > now
            }
            self.quarantined = {
                address: expiry
                for address, expiry in self.quarantined.items()
                if expiry > now
            }
            if (
                len(self.leases) != old_lease_count
                or len(self.quarantined) != old_quarantine_count
            ):
                self._persist_state()
            for client, lease in expired_leases:
                self._record_event(
                    "lease_expired",
                    client=client.hex(":"),
                    address=str(lease.address),
                )

    def allocate(self, client):
        """Return a reservation or the first free, non-quarantined pool address."""
        with self.lock:
            self.expire()
            lease = self.leases.get(client)
            if lease is not None:
                return lease.address

            used = {lease.address for lease in self.leases.values()}
            reserved = self.reservations.get(client)
            occupied_count = sum(
                int(self.pool_start) <= int(address) <= int(self.pool_end)
                for address in used
            )
            if self.allocation_guard is not None and not self.allocation_guard(
                client,
                occupied_count,
                reserved is not None,
            ):
                self._record_event(
                    "lease_allocation_deferred",
                    client=client.hex(":"),
                    reason="protected_pool",
                    pool_occupancy=occupied_count,
                )
                return None
            if reserved is not None:
                if reserved in used or reserved in self.quarantined:
                    return None
                address = reserved
            else:
                address = None
                for value in range(int(self.pool_start), int(self.pool_end) + 1):
                    candidate = ipaddress.IPv4Address(value)
                    if (
                        candidate not in used
                        and candidate not in self.reserved_addresses
                        and candidate not in self.quarantined
                    ):
                        address = candidate
                        break
            if address is None:
                return None
            self.leases[client] = Lease(
                address, time.monotonic() + self.lease_seconds
            )
            self._persist_state()
            self._record_event(
                "lease_allocated", client=client.hex(":"), address=str(address)
            )
            return address

    def assign(self, client, address, enforce_allocation_policy=False):
        """Validate and renew an address without conflicting with another lease."""
        with self.lock:
            self.expire()
            if not self._address_is_valid(client, address):
                return False
            previous = self.leases.get(client)
            if (
                previous is None
                and enforce_allocation_policy
                and self.allocation_guard is not None
            ):
                occupied_count = sum(
                    int(self.pool_start) <= int(lease.address) <= int(self.pool_end)
                    for lease in self.leases.values()
                )
                if not self.allocation_guard(
                    client,
                    occupied_count,
                    client in self.reservations,
                ):
                    self._record_event(
                        "lease_allocation_deferred",
                        client=client.hex(":"),
                        address=str(address),
                        reason="protected_pool",
                        pool_occupancy=occupied_count,
                    )
                    return False
            if any(
                owner != client and lease.address == address
                for owner, lease in self.leases.items()
            ):
                return False
            lease_seconds = (
                previous.lease_seconds
                if previous is not None and previous.lease_seconds is not None
                else self.lease_seconds
            )
            self.leases[client] = Lease(
                address, time.monotonic() + lease_seconds, lease_seconds
            )
            self._persist_state()
            self._record_event(
                "lease_renewed" if previous is not None else "lease_assigned",
                client=client.hex(":"),
                address=str(address),
            )
            return True

    def extend(self, client, seconds):
        """Extend an active lease by a positive number of seconds."""
        if isinstance(seconds, bool) or not isinstance(seconds, int) or not 1 <= seconds <= 0xFFFFFFFF:
            raise ValueError("lease extension must be between 1 and 4294967295 seconds")
        with self.lock:
            self.expire()
            lease = self.leases.get(client)
            if lease is None:
                return False
            lease.expires_at += seconds
            remaining = math.ceil(lease.expires_at - time.monotonic())
            if remaining > 0xFFFFFFFF:
                lease.expires_at -= seconds
                raise ValueError("extended lease exceeds the maximum DHCP lease time")
            lease.lease_seconds = remaining
            self._persist_state()
            self._record_event(
                "lease_extended",
                client=client.hex(":"),
                address=str(lease.address),
                seconds=seconds,
            )
            return True

    def release(self, client, address=None, quarantine_until_expiry=False):
        """Release a client's lease if the address agrees with its current lease."""
        with self.lock:
            current = self.leases.get(client)
            if current is None or (address is not None and address != current.address):
                return False
            self.leases.pop(client)
            if quarantine_until_expiry and current.expires_at > time.monotonic():
                self.quarantined[current.address] = current.expires_at
            self._persist_state()
            self._record_event(
                "lease_released", client=client.hex(":"), address=str(current.address)
            )
            return True

    def decline(self, client, address):
        """Quarantine a declined address only when it is leased to that client."""
        with self.lock:
            current = self.leases.get(client)
            if current is None or current.address != address:
                return False
            self.leases.pop(client)
            self.quarantined[address] = time.monotonic() + self.decline_hold_seconds
            self._persist_state()
            self._record_event(
                "lease_declined", client=client.hex(":"), address=str(address)
            )
            return True
