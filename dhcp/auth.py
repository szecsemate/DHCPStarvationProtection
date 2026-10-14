"""Single-user expiring sessions for the HTTP dashboard/API."""

import hashlib
import hmac
import os
import secrets
import threading
import time
from collections import defaultdict, deque


class LoginRateLimited(ValueError):
    """The remote address exceeded the dashboard login-attempt limit."""


class SessionAuth:
    """Validate one configured user and issue in-memory cookie sessions."""

    def __init__(
        self,
        password="root",
        username="root",
        session_seconds=3600,
        max_attempts=5,
        attempt_window_seconds=300,
    ):
        if not isinstance(password, str) or not password or len(password) > 1024:
            raise ValueError("dashboard password must contain 1 to 1024 characters")
        self.username = username
        self.session_seconds = session_seconds
        self.max_attempts = max_attempts
        self.attempt_window_seconds = attempt_window_seconds
        self.salt = os.urandom(16)
        self.password_digest = self._digest(password)
        self.lock = threading.RLock()
        self.sessions = {}
        self.failed_attempts = defaultdict(deque)

    def _digest(self, password):
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.salt, 200000
        )

    def _is_limited(self, remote_address, now):
        attempts = self.failed_attempts[remote_address]
        while attempts and attempts[0] <= now - self.attempt_window_seconds:
            attempts.popleft()
        return len(attempts) >= self.max_attempts

    def login(self, remote_address, username, password):
        now = time.time()
        with self.lock:
            self.sessions = {
                token: session
                for token, session in self.sessions.items()
                if session["expires_at"] > now
            }
            if self._is_limited(remote_address, now):
                raise LoginRateLimited("too many failed logins; try again later")
            valid_fields = (
                isinstance(username, str)
                and isinstance(password, str)
                and len(username) <= 256
                and len(password) <= 1024
            )
            supplied = password if valid_fields else ""
            digest = self._digest(supplied)
            valid = (
                valid_fields
                and hmac.compare_digest(username, self.username)
                and hmac.compare_digest(digest, self.password_digest)
            )
            if not valid:
                self.failed_attempts[remote_address].append(now)
                return None
            self.failed_attempts.pop(remote_address, None)
            token = secrets.token_urlsafe(32)
            csrf_token = secrets.token_urlsafe(32)
            self.sessions[token] = {
                "csrf": csrf_token,
                "expires_at": now + self.session_seconds,
            }
            if len(self.sessions) > 1024:
                oldest = min(
                    self.sessions,
                    key=lambda session_token: self.sessions[session_token]["expires_at"],
                )
                self.sessions.pop(oldest)
            return token, csrf_token

    def session(self, token):
        if not token:
            return None
        now = time.time()
        with self.lock:
            current = self.sessions.get(token)
            if current is None:
                return None
            if current["expires_at"] <= now:
                self.sessions.pop(token, None)
                return None
            return dict(current)

    def validate_csrf(self, token, csrf_token):
        current = self.session(token)
        return bool(
            current
            and isinstance(csrf_token, str)
            and hmac.compare_digest(current["csrf"], csrf_token)
        )

    def logout(self, token):
        if token:
            with self.lock:
                self.sessions.pop(token, None)
