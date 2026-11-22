"""Signed policy from the control plane: polled, verified, applied while the
application runs, and kept on local disk so a restart during a control plane
outage resumes at the last verified policy (sections 11.2 and 15)."""
from __future__ import annotations

import os
import threading
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Callable

from ._runtime import IvarError
from .core import verify_policy_bundle

if TYPE_CHECKING:
    from .guardian import Guardian


def read_state(path: str | None) -> str | None:
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip() or None
    except OSError:
        return None


def write_state(path: str | None, archive: str) -> None:
    if not path:
        return
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(archive.strip())
    os.replace(tmp, path)


class PolicyRefresher:
    """Polls `<control_url>/v1/policy/bundle` and applies newer signed policy.
    A bundle that fails verification, is older, or is refused by the engine
    leaves the current policy in force and raises a `policy_rejected` alert."""

    def __init__(self, guardian: "Guardian", control_url: str, keyring: dict, every_s: float, state_file: str | None,
                 alert: Callable[[str, str], None]) -> None:
        self.g, self.url, self.keyring, self.every_s, self.state_file, self.alert = guardian, control_url.rstrip("/"), keyring, every_s, state_file, alert
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread = threading.Thread(target=self._run, name="ivar-policy", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.refresh()
            self._stop.wait(self.every_s)

    def refresh(self) -> bool:
        """One poll; True when a newer policy was applied."""
        with self._lock:
            have = int(self.g.policy.get("version", 0))
            query = urllib.parse.urlencode({"have": have, "sensor": self.g.sensor_id})
            try:
                with urllib.request.urlopen(f"{self.url}/v1/policy/bundle?{query}", timeout=5) as res:
                    if res.status != 200:
                        return False
                    archive = res.read().decode()
            except Exception:
                # Control plane down or erroring: the last verified policy stays.
                return False
            return self.apply(archive, "control_plane")

    def apply(self, archive: str, source: str) -> bool:
        have = int(self.g.policy.get("version", 0))
        try:
            policy = verify_policy_bundle(archive, self.keyring, have)
        except IvarError as e:
            self.alert("policy_rejected", f"signed policy from {source} refused, current policy kept: {e}")
            return False
        if int(policy.get("version", 0)) <= have:
            return False
        try:
            self.g.adopt_policy(policy)
        except IvarError as e:
            self.alert("policy_rejected", f"policy {policy.get('version')} refused by the engine, current policy kept: {e}")
            return False
        try:
            write_state(self.state_file, archive)
        except OSError as e:
            self.alert("policy_state", f"policy {policy.get('version')} applied but not saved: {e}")
        self.alert("policy_applied", f"policy {policy.get('version')} ({policy.get('policy_version', '')}) applied from {source}")
        return True
