"""The decision core, the sensor fast path, the action sink and intent tokens."""

from __future__ import annotations

import time
from typing import Any

from ._runtime import Runtime, runtime


def now_ms() -> int:
    return int(time.time() * 1000)


def default_policy(rt: Runtime | None = None) -> dict[str, Any]:
    return (rt or runtime()).call("policy.default", {"now_ms": now_ms()})


def verify_policy_bundle(archive_base64: str, keyring: dict, current_version: int = 0, rt: Runtime | None = None) -> dict[str, Any]:
    """Verified PolicyContent, or IvarError. Rollback and expired bundles are refused."""
    return (rt or runtime()).call("policy.verify", {"archive_base64": archive_base64, "keyring": keyring, "current_version": current_version, "now_ms": now_ms()})


class _Handle:
    kind = ""

    def __init__(self, rt: Runtime, handle: int) -> None:
        self._rt, self._handle = rt, handle

    def _call(self, op: str, args: dict[str, Any] | None = None) -> Any:
        return self._rt.call(f"{self.kind}.{op}", args, self._handle)

    def close(self) -> None:
        self._rt.call("free", {}, self._handle)


class Core(_Handle):
    """The full decision core, embedded. Use it off the request path."""

    kind = "core"

    @classmethod
    def create(cls, policy: dict, redaction_key_hex: str = "00", rt: Runtime | None = None) -> "Core":
        rt = rt or runtime()
        return cls(rt, rt.call("core.new", {"policy": policy, "redaction_key_hex": redaction_key_hex})["handle"])

    def process(self, event: dict, now: int | None = None) -> dict[str, Any]:
        return self._call("process", {"event": event, "now_ms": now if now is not None else now_ms()})

    def update_policy(self, policy: dict, now: int | None = None) -> None:
        self._call("update_policy", {"policy": policy, "now_ms": now if now is not None else now_ms()})

    def evidence(self) -> list:
        return self._call("evidence")

    def incidents(self) -> list:
        return self._call("incidents")


class LocalSensor(_Handle):
    """Known attacks are blocked here, with no round trip (section 7.1)."""

    kind = "sensor"

    @classmethod
    def create(cls, policy: dict, rt: Runtime | None = None) -> "LocalSensor":
        rt = rt or runtime()
        return cls(rt, rt.call("sensor.new", {"policy": policy})["handle"])

    def decide(self, event: dict, now: int | None = None) -> dict[str, Any]:
        return self._call("decide", {"event": event, "now_ms": now if now is not None else now_ms()})

    def push_verdict(self, verdict: dict) -> bool:
        return self._call("push_verdict", {"verdict": verdict})["ok"]

    def update_policy(self, policy: dict) -> None:
        """Adopt a newer verified policy, keeping cached verdicts."""
        self._call("update_policy", {"policy": policy})


class Sink(_Handle):
    """The action sink: intent binding, consequence invariants and time locks."""

    kind = "sink"

    @classmethod
    def create(cls, root_public_key: str, step_keys: dict[str, str], invariants: list, default_mode: str = "observe", modes: dict[str, str] | None = None, rt: Runtime | None = None) -> "Sink":
        rt = rt or runtime()
        h = rt.call("sink.new", {"root_public_key": root_public_key, "step_keys": step_keys, "invariants": invariants, "default_mode": default_mode, "modes": modes or {}})["handle"]
        return cls(rt, h)

    def guard(self, request: dict, now: int | None = None) -> dict[str, Any]:
        return self._call("guard", {"request": request, "now_ms": now if now is not None else now_ms()})

    def cancel(self, lock_id: str, owner: str, request: dict) -> dict[str, Any]:
        return self._call("cancel", {"lock_id": lock_id, "owner": owner, "request": request})

    def release_due(self, now: int | None = None) -> list:
        return self._call("release_due", {"now_ms": now if now is not None else now_ms()})


def mint_intent(root_seed_hex: str, intent_id: str, action: str, subject: str, limits: dict[str, int], ttl_ms: int = 300_000, rt: Runtime | None = None) -> dict[str, str]:
    return (rt or runtime()).call("intent.mint", {"root_seed_hex": root_seed_hex, "intent_id": intent_id, "action": action, "subject": subject, "limits": limits, "expiry_ms": now_ms() + ttl_ms})


def attest_step(step_seed_hex: str, step: str, token: str, root_public_key: str, narrowing: dict | None = None, rt: Runtime | None = None) -> str:
    return (rt or runtime()).call("intent.attest", {"step_seed_hex": step_seed_hex, "step": step, "token": token, "root_public_key": root_public_key, "narrowing": narrowing or {}})["token"]


def step_public_key(step_seed_hex: str, rt: Runtime | None = None) -> str:
    return (rt or runtime()).call("intent.step_public_key", {"step_seed_hex": step_seed_hex})["public_key"]
