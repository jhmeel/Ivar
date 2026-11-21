"""ASGI middleware for FastAPI and Starlette.

    from ivar.asgi import IvarMiddleware
    app.add_middleware(IvarMiddleware, mode="observe", identity=lambda scope: scope.get("user_id"))
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

from .guardian import Guardian, RequestInfo

Scope = dict[str, Any]


def _headers(scope: Scope) -> dict[str, str]:
    return {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}


class IvarMiddleware:
    def __init__(self, app: Callable, mode: str = "observe", identity: Callable[[Scope], str | None] = lambda s: None,
                 session: Callable[[Scope], str | None] = lambda s: None, roles: Callable[[Scope], list[str]] = lambda s: [],
                 guardian: Guardian | None = None, **guardian_options: Any) -> None:
        self.app = app
        self.identity, self.session, self.roles = identity, session, roles
        self.guardian = guardian or Guardian(mode=mode, **guardian_options)

    def info(self, scope: Scope) -> RequestInfo:
        client = scope.get("client") or ("", 0)
        return RequestInfo(method=scope.get("method", ""), path=scope.get("path", ""), client_ip=client[0], headers=_headers(scope),
                           identity=self.identity(scope) or "", session=self.session(scope) or "", roles=self.roles(scope) or [])

    async def __call__(self, scope: Scope, receive: Callable[[], Awaitable[dict]], send: Callable[[dict], Awaitable[None]]) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        info = self.info(scope)
        scope.setdefault("state", {})["ivar"] = (self.guardian, info)
        decision = self.guardian.inspect(info)
        if decision.action != "allow":
            body = json.dumps(decision.body or {}).encode()
            headers = [(b"content-type", b"application/json")]
            if decision.action == "challenge":
                headers.append((b"www-authenticate", b"step-up"))
            await send({"type": "http.response.start", "status": decision.status, "headers": headers})
            await send({"type": "http.response.body", "body": body})
            self.guardian.report_request(info, decision.status)
            return
        status = {"code": 0}

        async def wrapped(message: dict) -> None:
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        await self.app(scope, receive, wrapped)
        self.guardian.report_request(info, status["code"])
