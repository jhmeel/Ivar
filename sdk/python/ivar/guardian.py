"""Framework independent SDK logic shared by the ASGI and WSGI middleware.

Observe mode records decisions without affecting a request. In enforce mode
known attacks are blocked in the SDK from cached, signed policy and verdicts
from the core apply to later requests. Scoring runs off the request path on a
worker thread. A fault fails open on public routes and closed on admin routes.
"""

from __future__ import annotations

import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from .core import Core, LocalSensor, Sink, default_policy, now_ms
from .events import API_ACTIVITY, AUTHENTICATION, HTTP_ACTIVITY, build_event

log = logging.getLogger("ivar")


@dataclass
class RequestInfo:
    method: str
    path: str
    client_ip: str
    headers: dict[str, str]
    body_keys: list[str] = field(default_factory=list)
    identity: str = ""
    session: str = ""
    roles: list[str] = field(default_factory=list)
    tenant: str = ""


@dataclass
class Decision:
    """What the middleware should do with the request."""

    action: str  # allow, block, challenge, throttle, unavailable
    status: int = 200
    verdict: dict | None = None
    body: dict | None = None


class Guardian:
    def __init__(
        self,
        mode: str = "observe",
        policy: dict | None = None,
        core_url: str | None = None,
        core_token: str | None = None,
        redaction_key: str = "",
        sensor_id: str = "python-sdk",
        admin_prefixes: tuple[str, ...] = ("/admin",),
        on_alert: Callable[[str, str], None] | None = None,
        budget_ms: float = 1.0,
        control_url: str | None = None,
        policy_keyring: dict | None = None,
        policy_refresh_s: float = 30.0,
        policy_state_file: str | None = None,
    ) -> None:
        if mode not in ("observe", "enforce"):
            raise ValueError("mode must be observe or enforce")
        self.mode = mode
        self.policy = policy or default_policy()
        self.redaction_key = redaction_key
        self.sensor_id = sensor_id
        self.admin_prefixes = admin_prefixes
        self.budget_ms = budget_ms
        self.alert = on_alert or (lambda kind, msg: log.warning("ivar %s: %s", kind, msg))
        self.sensor = LocalSensor.create(self.policy)
        self._warm()
        self.core = None if core_url else Core.create(self.policy, redaction_key or "00")
        self.core_url = core_url
        self.core_token = core_token
        self.refresher = None
        if control_url or policy_state_file:
            if not policy_keyring:
                raise ValueError("policy_keyring is required with control_url or policy_state_file")
            from .policy import PolicyRefresher, read_state
            self.refresher = PolicyRefresher(self, control_url or "", policy_keyring, policy_refresh_s, policy_state_file, self.alert)
            # A policy saved before a restart wins when it is newer and verifies.
            saved = read_state(policy_state_file)
            if saved:
                self.refresher.apply(saved, "state_file")
            if control_url:
                self.refresher.start()
        self._q: queue.Queue = queue.Queue(maxsize=10_000)
        self._worker = threading.Thread(target=self._drain, name="ivar-scoring", daemon=True)
        self._worker.start()

    def adopt_policy(self, policy: dict) -> None:
        """Switch to a newer verified policy. Cached verdicts are kept."""
        self.sensor.update_policy(policy)
        if self.core is not None:
            self.core.update_policy(policy)
        self.policy = policy

    def _warm(self) -> None:
        """Run the fast path on a plain read and a write with body fields, so the
        first real request does not pay for the WebAssembly code's first run."""
        samples = [
            {"activity_name": "http.request", "http_request": {"http_method": "GET", "url_path": "/"}, "src_endpoint": {"ip": "192.0.2.1"}, "ivar": {}},
            {"activity_name": "http.request", "http_request": {"http_method": "POST", "url_path": "/login", "body_keys": ["email", "password"]},
             "actor": {"user": {"uid": "kh_warm"}}, "src_endpoint": {"ip": "192.0.2.1"}, "ivar": {}},
        ]
        for i in range(200):
            self.sensor.decide(samples[i % 2])

    def _event(self, info: RequestInfo, activity: str, class_uid: int, **kw: Any) -> dict:
        return build_event(
            sensor_id=self.sensor_id, activity=activity, class_uid=class_uid, now=now_ms(), method=info.method, path=info.path,
            client_ip=info.client_ip, user_agent=info.headers.get("user-agent", ""), body_keys=info.body_keys, identity=info.identity,
            session=info.session, roles=info.roles, tenant=info.tenant, request_id=info.headers.get("x-request-id", ""),
            redaction_key=self.redaction_key, **kw,
        )

    def inspect(self, info: RequestInfo) -> Decision:
        started = time.perf_counter()
        admin = any(info.path.startswith(p) for p in self.admin_prefixes)
        try:
            local = self.sensor.decide(self._event(info, "http.request", HTTP_ACTIVITY))
        except Exception as e:  # noqa: BLE001
            if admin:
                self.alert("sdk_fault", f"admin route failed closed: {e}")
                return Decision("unavailable", 503, body={"error": "security check unavailable"})
            self.alert("fail_open", str(e))
            return Decision("allow")
        elapsed = (time.perf_counter() - started) * 1000
        if elapsed > self.budget_ms:
            self.alert("budget_exceeded", f"local decision took {elapsed:.3f} ms")
        v = local.get("verdict")
        if not v or self.mode != "enforce" or v.get("mode") != "enforce":
            return Decision("allow", verdict=v)
        d = v["decision"]
        if d in ("block", "contain", "refuse"):
            return Decision("block", 403, v, {"error": "request blocked", "verdict_id": v["verdict_id"]})
        if d == "challenge":
            return Decision("challenge", 401, v, {"error": "step up verification required", "verdict_id": v["verdict_id"]})
        if d == "throttle":
            return Decision("throttle", 429, v, {"error": "slow down", "verdict_id": v["verdict_id"]})
        return Decision("allow", verdict=v)

    def report_request(self, info: RequestInfo, status: int) -> None:
        self._submit(self._event(info, "http.request", HTTP_ACTIVITY, status=status))

    def report_login(self, info: RequestInfo, success: bool, account: str) -> None:
        self._submit(self._event(info, "auth.login", AUTHENTICATION, success=success, target=f"user:{account}"))

    def report_action(self, info: RequestInfo, name: str, value: float = 0, records: int = 0, destructive: bool = False, attributes: dict | None = None) -> None:
        self._submit(self._event(info, "business.action", API_ACTIVITY, business_action=name, value=value, records=records, destructive=destructive, attributes=attributes))

    def _submit(self, event: dict) -> None:
        try:
            self._q.put_nowait(event)
        except queue.Full:
            self.alert("fail_open", "event buffer full, oldest dropped")

    def _drain(self) -> None:
        failing = False
        while True:
            # Everything queued so far goes in one request, up to 500 events.
            batch = [self._q.get()]
            while len(batch) < 500:
                try:
                    batch.append(self._q.get_nowait())
                except queue.Empty:
                    break
            try:
                if self.core is not None:
                    for ev in batch:
                        for v in self.core.process(ev).get("verdicts", []):
                            self.sensor.push_verdict(v)
                else:
                    headers = {"content-type": "application/json"}
                    if self.core_token:
                        headers["authorization"] = f"Bearer {self.core_token}"
                    req = urllib.request.Request(f"{self.core_url.rstrip('/')}/v1/events", json.dumps({"sensor_id": self.sensor_id, "events": batch}).encode(), headers)
                    with urllib.request.urlopen(req, timeout=2) as r:
                        for v in json.loads(r.read()).get("verdicts", []):
                            self.sensor.push_verdict(v)
                failing = False
            except urllib.error.HTTPError as e:
                if not failing:
                    refused = e.code in (401, 403)
                    self.alert("sdk_fault", f"the core refused this sensor's token (HTTP {e.code}): check core_token and the sensor id it is issued for" if refused else f"the core answered HTTP {e.code}")
                failing = True
            except Exception as e:  # noqa: BLE001
                if not failing:
                    self.alert("sdk_fault", f"the core is unreachable, events are not scored until it returns: {e}")
                failing = True
            finally:
                for _ in batch:
                    self._q.task_done()

    def flush(self) -> None:
        self._q.join()

    def sink(self, action: str, root_public_key: str, step_keys: dict[str, str], intent_binding: str | None = None) -> "ActionGuard":
        modes = dict(self.policy.get("intent_binding") or {})
        if intent_binding:
            modes[action] = intent_binding
        return ActionGuard(self, action, Sink.create(root_public_key, step_keys, self.policy.get("invariants", []), modes.get(action, "observe"), modes))


class ActionGuard:
    """Guard one high consequence action. Fails closed."""

    def __init__(self, g: Guardian, action: str, sink: Sink) -> None:
        self.g, self.action, self.sink = g, action, sink

    def check(self, info: RequestInfo, intent_token: str | None, value: float = 0, records: int = 0, destructive: bool = False, subject: str | None = None) -> Decision:
        req = {"action": self.action, "subject": subject or info.session or info.identity, "identity": info.identity, "business": info.tenant,
               "value_moved": value, "records_read": records, "destructive": destructive, "intent_token": intent_token}
        try:
            d = self.sink.guard(req)
        except Exception as e:  # noqa: BLE001
            self.g.alert("sdk_fault", f"action sink failed closed: {e}")
            return Decision("unavailable", 503, body={"error": "action check unavailable"})
        o = d["outcome"]
        self.g.report_action(info, self.action, value, records, destructive, {"sink_outcome": o["outcome"]})
        if o["outcome"] == "executes":
            if d.get("would_refuse"):
                self.g.alert("action_refused", f"observe: would refuse {self.action}: {d['would_refuse']}")
            return Decision("allow", body=d)
        if o["outcome"] == "refused":
            self.g.alert("action_refused", o["reason"])
            return Decision("block", 403, body={"error": "no valid intent chain for this action"})
        if o["outcome"] == "blocked_alert":
            self.g.alert("invariant_breach", o["invariant_id"])
            return Decision("block", 409, body={"error": "consequence limit reached", "invariant": o["invariant_id"]})
        self.g.alert("time_lock", o["lock"]["lock_id"])
        return Decision("held", 202, body={"status": "held", "lock_id": o["lock"]["lock_id"], "release_at": o["lock"]["release_at"]})
