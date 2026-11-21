"""Building OCSF SecurityEvents with the IVAR extension from HTTP requests."""

from __future__ import annotations

import hashlib
import hmac
import itertools
import re
from typing import Any, Iterable

_seq = itertools.count(1)
_FORBIDDEN = re.compile(r"(pass(word|wd)?|secret|token|otp|one_time|pin$|cvv|cvc|card(_?number)?|pan$|authorization|cookie|api_?key|private_?key)", re.I)

HTTP_ACTIVITY = 4002
AUTHENTICATION = 3002
API_ACTIVITY = 6003


def keyed_hash(key_hex: str, value: str) -> str:
    """Matches ivar_core::redact::keyed_hash."""
    if not value or value.startswith("kh_") or not key_hex:
        return value
    return "kh_" + hmac.new(bytes.fromhex(key_hex), value.encode(), hashlib.sha256).hexdigest()[:24]


def safe_attributes(attrs: dict[str, Any] | None) -> dict[str, str]:
    return {k: str(v)[:512] for k, v in (attrs or {}).items() if not _FORBIDDEN.search(k)}


def build_event(
    *,
    sensor_id: str,
    activity: str,
    class_uid: int,
    now: int,
    method: str = "",
    path: str = "",
    client_ip: str = "",
    user_agent: str = "",
    body_keys: Iterable[str] = (),
    status: int = 0,
    identity: str = "",
    session: str = "",
    roles: Iterable[str] = (),
    tenant: str = "",
    request_id: str = "",
    redaction_key: str = "",
    success: bool | None = None,
    target: str = "",
    business_action: str = "",
    value: float = 0,
    records: int = 0,
    destructive: bool = False,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if target.startswith("user:") and redaction_key:
        target = "user:" + keyed_hash(redaction_key, target[5:])
    return {
        "class_uid": class_uid,
        "category_uid": class_uid // 1000,
        "activity_id": 1,
        "type_uid": class_uid * 100 + 1,
        "time": now,
        "severity_id": 1,
        "status_id": 2 if success is False else 1,
        "activity_name": activity,
        "metadata": {"version": "1.3.0", "product": {"name": "ivar", "vendor_name": "ivar", "version": "0.1.0"}, "extensions": [{"name": "ivar", "uid": "999", "version": "1.0.0"}]},
        "actor": {
            "user": {"uid": keyed_hash(redaction_key, identity), "type": "human"} if identity else None,
            "session": {"uid": session} if session else None,
            "authorizations": ",".join(roles),
        },
        "src_endpoint": {"ip": client_ip},
        "http_request": {"http_method": method, "url_path": path, "user_agent": user_agent[:256], "body_keys": list(body_keys)[:64]} if method else None,
        "http_response": {"code": status} if status else None,
        "ivar": {
            "sensor_id": sensor_id,
            "sensor_type": "app_sdk",
            "observation_point": "app_sdk",
            "sensor_seq": next(_seq),
            "request_id": request_id,
            "business_action": business_action,
            "target_entity": target,
            "value_moved": value,
            "records_read": records,
            "destructive": destructive,
            "tenant": tenant,
            "attributes": safe_attributes(attributes),
        },
    }
