"""WSGI middleware for Flask and Django.

    from ivar.wsgi import IvarWSGIMiddleware
    app.wsgi_app = IvarWSGIMiddleware(app.wsgi_app, mode="observe", identity=lambda environ: environ.get("REMOTE_USER"))
"""

from __future__ import annotations

import json
from typing import Any, Callable, Iterable

from .guardian import Guardian, RequestInfo


class IvarWSGIMiddleware:
    def __init__(self, app: Callable, mode: str = "observe", identity: Callable[[dict], str | None] = lambda e: None,
                 session: Callable[[dict], str | None] = lambda e: None, guardian: Guardian | None = None, **guardian_options: Any) -> None:
        self.app, self.identity, self.session = app, identity, session
        self.guardian = guardian or Guardian(mode=mode, **guardian_options)

    def __call__(self, environ: dict, start_response: Callable) -> Iterable[bytes]:
        headers = {k[5:].replace("_", "-").lower(): v for k, v in environ.items() if k.startswith("HTTP_")}
        info = RequestInfo(method=environ.get("REQUEST_METHOD", ""), path=environ.get("PATH_INFO", ""), client_ip=environ.get("REMOTE_ADDR", ""),
                           headers=headers, identity=self.identity(environ) or "", session=self.session(environ) or "")
        environ["ivar"] = (self.guardian, info)
        decision = self.guardian.inspect(info)
        if decision.action != "allow":
            start_response(f"{decision.status} Blocked", [("content-type", "application/json")])
            self.guardian.report_request(info, decision.status)
            return [json.dumps(decision.body or {}).encode()]
        seen = {"code": 0}

        def sr(status: str, hdrs: list, exc_info: Any = None) -> Any:
            seen["code"] = int(status.split()[0])
            return start_response(status, hdrs, exc_info)

        try:
            return self.app(environ, sr)
        finally:
            self.guardian.report_request(info, seen["code"])
