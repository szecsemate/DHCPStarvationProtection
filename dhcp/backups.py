"""Compressed, integrity-checked backups for DHCP service state and logs."""

import hashlib
import json
import logging
import os
import tempfile
import threading
import time
import uuid
import zipfile
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path

LOG = logging.getLogger("dhcp-backups")
MANIFEST_NAME = "manifest.json"
BACKUP_FORMAT_VERSION = 1
MAX_BACKUP_MEMBER_BYTES = 2 * 1024 * 1024 * 1024
OPTIONAL_BACKUP_SOURCES = {"trust_state"}


class BackupError(ValueError):
    """A backup archive is invalid or cannot be safely restored."""


class BackupManager:
    """Create and restore snapshots while coordinating with service writers."""

    def __init__(self, directory, sources, interval_seconds=1800, retention_days=30):
        if isinstance(interval_seconds, bool) or not isinstance(interval_seconds, int) or interval_seconds < 1:
            raise ValueError("backup interval must be a positive number of seconds")
        if isinstance(retention_days, bool) or not isinstance(retention_days, int) or retention_days < 1:
            raise ValueError("backup retention must be a positive number of days")
        self.directory = Path(directory)
        self.sources = {
            name: (Path(path), lock)
            for name, (path, lock) in sources.items()
        }
        self.interval_seconds = interval_seconds
        self.retention_days = retention_days
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.create_snapshot("startup")
        self.thread = threading.Thread(
            target=self._run, name="dhcp-backups", daemon=True
        )
        self.thread.start()

    def _locked_sources(self):
        stack = ExitStack()
        lock_order = (
            "lease_state",
            "trust_state",
            "audit_log",
            "packet_log",
            "rules",
        )
        for name in lock_order:
            if name not in self.sources:
                continue
            stack.enter_context(self.sources[name][1])
        return stack

    def create_snapshot(self, reason="scheduled"):
        """Write a complete snapshot atomically and enforce the retention age."""
        with self.lock:
            self.directory.mkdir(parents=True, exist_ok=True)
            created = datetime.now(timezone.utc)
            stamp = created.strftime("%Y%m%dT%H%M%S.%fZ")
            filename = "dhcp-backup-{}-{}.zip".format(stamp, uuid.uuid4().hex[:8])
            target = self.directory / filename
            manifest = {
                "version": BACKUP_FORMAT_VERSION,
                "created_at": created.isoformat(),
                "reason": reason,
                "sources": {},
            }
            payloads = {}
            with self._locked_sources():
                for index, name in enumerate(sorted(self.sources)):
                    path, _ = self.sources[name]
                    member = "files/{}.bin".format(index)
                    if path.exists():
                        try:
                            data = path.read_bytes()
                        except OSError:
                            LOG.exception("Could not snapshot %s", path)
                            raise
                        payloads[member] = data
                        manifest["sources"][name] = {
                            "member": member,
                            "path": str(path.resolve()),
                            "exists": True,
                            "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest(),
                        }
                    else:
                        manifest["sources"][name] = {
                            "member": None,
                            "path": str(path.resolve()),
                            "exists": False,
                            "size": 0,
                            "sha256": None,
                        }
            temp_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    dir=str(self.directory),
                    prefix=filename + ".",
                    suffix=".tmp",
                    delete=False,
                ) as temp_file:
                    temp_path = Path(temp_file.name)
                with zipfile.ZipFile(
                    str(temp_path), "w", compression=zipfile.ZIP_DEFLATED
                ) as archive:
                    archive.writestr(
                        MANIFEST_NAME,
                        json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8"),
                    )
                    for member, data in payloads.items():
                        archive.writestr(member, data)
                with temp_path.open("rb+") as archive_file:
                    os.fsync(archive_file.fileno())
                os.replace(str(temp_path), str(target))
            finally:
                if temp_path is not None and temp_path.exists():
                    temp_path.unlink()
            self.prune()
            return filename

    def _read_snapshot(self, filename):
        manifest = self._read_manifest(filename)
        path = self.directory / filename
        try:
            with zipfile.ZipFile(str(path), "r") as archive:
                payloads = {}
                for name, source in manifest["sources"].items():
                    if not source["exists"]:
                        payloads[name] = None
                        continue
                    member = source["member"]
                    if member not in archive.namelist():
                        raise BackupError("backup source data is missing")
                    info = archive.getinfo(member)
                    if info.file_size > MAX_BACKUP_MEMBER_BYTES:
                        raise BackupError("backup source exceeds the size limit")
                    data = archive.read(member)
                    if (
                        len(data) != source["size"]
                        or hashlib.sha256(data).hexdigest() != source["sha256"]
                    ):
                        raise BackupError("backup integrity check failed for {}".format(name))
                    payloads[name] = data
                for name in set(self.sources) - set(payloads):
                    payloads[name] = None
                return manifest, payloads
        except (OSError, zipfile.BadZipFile, KeyError, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise BackupError("could not read backup: {}".format(error)) from error

    def _read_manifest(self, filename):
        if (
            not isinstance(filename, str)
            or not filename.endswith(".zip")
            or Path(filename).name != filename
            or "/" in filename
            or "\\" in filename
        ):
            raise BackupError("invalid backup name")
        path = self.directory / filename
        try:
            with zipfile.ZipFile(str(path), "r") as archive:
                manifest_info = archive.getinfo(MANIFEST_NAME)
                if manifest_info.file_size > 1024 * 1024:
                    raise BackupError("backup manifest is too large")
                manifest = json.loads(archive.read(MANIFEST_NAME).decode("utf-8"))
                if (
                    not isinstance(manifest, dict)
                    or manifest.get("version") != BACKUP_FORMAT_VERSION
                    or not isinstance(manifest.get("sources"), dict)
                ):
                    raise BackupError("unsupported or invalid backup manifest")
                for name, source in manifest["sources"].items():
                    if name not in self.sources or not isinstance(source, dict):
                        raise BackupError("backup contains an unknown source")
                    if source.get("path") != str(self.sources[name][0].resolve()):
                        raise BackupError("backup was made for different configured file paths")
                    if not isinstance(source.get("exists"), bool):
                        raise BackupError("backup source manifest is invalid")
                    if source["exists"] and (
                        not isinstance(source.get("member"), str)
                        or not isinstance(source.get("size"), int)
                        or isinstance(source.get("size"), bool)
                        or source["size"] < 0
                        or not isinstance(source.get("sha256"), str)
                        or len(source["sha256"]) != 64
                    ):
                        raise BackupError("backup source manifest is invalid")
                source_names = set(manifest["sources"])
                if (
                    source_names - set(self.sources)
                    or (set(self.sources) - OPTIONAL_BACKUP_SOURCES) - source_names
                ):
                    raise BackupError("backup does not contain all required sources")
        except (OSError, zipfile.BadZipFile, KeyError, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise BackupError("could not read backup: {}".format(error)) from error
        return manifest

    def list_snapshots(self):
        """Return known snapshots, newest first, after validating their manifests."""
        snapshots = []
        for path in self.directory.glob("dhcp-backup-*.zip"):
            try:
                manifest = self._read_manifest(path.name)
                snapshots.append(
                    {
                        "name": path.name,
                        "created_at": manifest.get("created_at"),
                        "reason": manifest.get("reason", "unknown"),
                        "size_bytes": path.stat().st_size,
                    }
                )
            except (OSError, BackupError):
                LOG.warning("Ignoring invalid backup archive %s", path)
        return sorted(
            snapshots, key=lambda item: item["created_at"] or "", reverse=True
        )

    def prune(self):
        """Remove only this manager's old, timestamped ZIP snapshots."""
        cutoff = time.time() - self.retention_days * 24 * 60 * 60
        for path in self.directory.glob("dhcp-backup-*.zip"):
            try:
                if path.stat().st_mtime < cutoff:
                    path.unlink()
            except OSError:
                LOG.exception("Could not prune expired backup %s", path)

    def restore_state(self, filename, validate=None, reload_state=None):
        """Restore only lease/rule files and retain logs, protecting current state."""
        manifest, payloads = self._read_snapshot(filename)
        state_names = ("lease_state", "rules", "trust_state")
        for name in state_names:
            if name not in payloads:
                raise BackupError("backup is missing {}".format(name))
        if validate is not None:
            validate(payloads)

        safety_snapshot = self.create_snapshot("pre-rollback")
        old_payloads = {}
        with self.lock, self._locked_sources():
            for name in state_names:
                path, _ = self.sources[name]
                old_payloads[name] = path.read_bytes() if path.exists() else None
            try:
                for name in state_names:
                    path, _ = self.sources[name]
                    data = payloads[name]
                    if data is None:
                        if path.exists():
                            path.unlink()
                    else:
                        self._atomic_write(path, data)
                if reload_state is not None:
                    reload_state()
            except (OSError, ValueError) as error:
                for name in state_names:
                    path, _ = self.sources[name]
                    old_data = old_payloads[name]
                    if old_data is None:
                        if path.exists():
                            path.unlink()
                    else:
                        self._atomic_write(path, old_data)
                if reload_state is not None:
                    reload_state()
                raise BackupError(
                    "rollback failed; current state was restored from the safety copy {}: {}".format(
                        safety_snapshot, error
                    )
                ) from error
        return {
            "restored": filename,
            "safety_snapshot": safety_snapshot,
            "created_at": manifest.get("created_at"),
        }

    @staticmethod
    def _atomic_write(path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "wb",
                dir=str(path.parent),
                prefix=path.name + ".",
                suffix=".restore.tmp",
                delete=False,
            ) as target:
                temp_path = Path(target.name)
                target.write(data)
                target.flush()
                os.fsync(target.fileno())
            os.replace(str(temp_path), str(path))
        finally:
            if temp_path is not None and temp_path.exists():
                temp_path.unlink()

    def _run(self):
        while not self.stop_event.wait(self.interval_seconds):
            try:
                self.create_snapshot("scheduled")
            except (OSError, ValueError):
                LOG.exception("Scheduled backup failed")

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=self.interval_seconds + 1)
