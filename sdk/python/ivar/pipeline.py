"""Data pipeline sensor (section 8.3): dataset loaders, notebooks and model registries.

Sees code execution during data or model loading; blocks workers, loaders and
outbound connections. A malicious dataset (Hugging Face, 16 July 2026) runs
code while it is being loaded: unpickling into os or subprocess, exec of
embedded code, or a network call home. Inside `guarded_load`, Python audit
hooks see each of those, report it, and in enforce mode refuse it.

    from ivar.pipeline import PipelineSensor
    sensor = PipelineSensor(mode="enforce", report=send_to_core)
    with sensor.guarded_load("community/dataset", allow_hosts={"huggingface.co"}):
        ds = load_dataset("community/dataset")
"""

from __future__ import annotations

import contextlib
import contextvars
import itertools
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

_active: contextvars.ContextVar["_Load | None"] = contextvars.ContextVar("ivar_load", default=None)
_seq = itertools.count(1)
_installed = False
_sensors: list["PipelineSensor"] = []

DANGEROUS_GLOBALS = {
    ("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"), ("posix", "system"), ("nt", "system"),
    ("subprocess", "Popen"), ("subprocess", "call"), ("subprocess", "run"), ("subprocess", "check_output"),
    ("builtins", "eval"), ("builtins", "exec"), ("builtins", "compile"), ("builtins", "__import__"),
    ("socket", "socket"), ("runpy", "run_path"), ("runpy", "run_module"), ("importlib", "import_module"),
    ("webbrowser", "open"), ("shutil", "rmtree"),
}
CODE_EVENTS = {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn", "os.startfile", "ctypes.dlopen"}
# Imports also raise the "exec" audit event, so dynamic code is caught at
# compile time instead: source compiled from a string, not from a file.
DYNAMIC_SOURCES = {"<string>", "<unknown>"}


class LoadBlocked(PermissionError):
    """Raised inside a guarded load when the sensor refuses an operation."""


@dataclass
class _Load:
    name: str
    sensor: "PipelineSensor"
    allow_hosts: set[str]
    findings: list[dict] = field(default_factory=list)


def _hook(event: str, args: tuple) -> None:
    load = _active.get()
    if load is None:
        return
    detail: dict[str, Any] | None = None
    if event == "pickle.find_class":
        module, name = args[0], args[1]
        if (module, name) in DANGEROUS_GLOBALS or module in ("os", "posix", "nt", "subprocess"):
            detail = {"kind": "unpickle_dangerous_global", "target": f"{module}.{name}"}
    elif event in CODE_EVENTS:
        detail = {"kind": "code_execution", "target": event}
    elif event == "compile":
        filename = args[1] if len(args) > 1 else ""
        if str(filename) in DYNAMIC_SOURCES and not load.sensor.allow_exec:
            detail = {"kind": "code_execution", "target": "compile of embedded source"}
    elif event == "socket.connect":
        address = args[1] if len(args) > 1 else None
        host = address[0] if isinstance(address, tuple) and address else str(address)
        if host not in load.allow_hosts:
            detail = {"kind": "outbound_connection", "target": str(host)}
    elif event == "socket.getaddrinfo":
        host = args[0] if args else ""
        if host and host not in load.allow_hosts and host not in ("localhost", "127.0.0.1"):
            detail = {"kind": "outbound_lookup", "target": str(host)}
    if detail is None:
        return
    load.findings.append(detail)
    load.sensor._emit(load.name, detail)
    if load.sensor.mode == "enforce":
        raise LoadBlocked(f"ivar: {detail['kind']} ({detail['target']}) refused while loading {load.name}")


class PipelineSensor:
    def __init__(self, mode: str = "observe", report: Callable[[dict], None] | None = None, sensor_id: str = "pipeline-1", worker: str = "", allow_exec: bool = False) -> None:
        if mode not in ("observe", "enforce"):
            raise ValueError("mode must be observe or enforce")
        self.mode, self.report, self.sensor_id, self.allow_exec = mode, report or (lambda e: None), sensor_id, allow_exec
        self.worker = worker or f"pipeline-worker-{id(self):x}"
        global _installed
        if not _installed:
            sys.addaudithook(_hook)
            _installed = True
        _sensors.append(self)

    def _emit(self, dataset: str, detail: dict) -> None:
        code_exec = detail["kind"] in ("unpickle_dangerous_global", "code_execution")
        event = {
            "class_uid": 6003, "category_uid": 6, "activity_id": 1, "time": int(time.time() * 1000), "status_id": 1,
            "activity_name": "dataset.load" if code_exec else "net.connect",
            "actor": {"user": {"uid": self.worker, "type": "service"}},
            "ivar": {
                "sensor_id": self.sensor_id, "sensor_type": "data_pipeline", "observation_point": "data_pipeline", "sensor_seq": next(_seq),
                "egress_destination": "" if code_exec else detail["target"],
                "attributes": {"dataset": dataset, "code_execution": "true" if code_exec else "false", "detail": detail["kind"], "target": detail["target"], "enforced": "blocked" if self.mode == "enforce" else "observed"},
            },
        }
        try:
            self.report(event)
        except Exception:  # noqa: BLE001 - reporting must never break the hook
            pass

    @contextlib.contextmanager
    def guarded_load(self, name: str, allow_hosts: set[str] | None = None) -> Iterator[_Load]:
        load = _Load(name, self, set(allow_hosts or ()))
        token = _active.set(load)
        try:
            yield load
        finally:
            _active.reset(token)
