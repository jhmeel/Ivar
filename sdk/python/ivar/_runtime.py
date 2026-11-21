"""Loads the C ABI WebAssembly core and calls it with JSON requests."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import wasmtime

_WASM = Path(__file__).parent / "_wasm" / "ivar_core.wasm"


class IvarError(RuntimeError):
    pass


class Runtime:
    """One WebAssembly instance. Calls are serialised with a lock."""

    _engine: wasmtime.Engine | None = None
    _module: wasmtime.Module | None = None

    def __init__(self, wasm_path: Path | None = None) -> None:
        if Runtime._engine is None:
            Runtime._engine = wasmtime.Engine()
            Runtime._module = wasmtime.Module.from_file(Runtime._engine, str(wasm_path or _WASM))
        self._store = wasmtime.Store(Runtime._engine)
        wasi = wasmtime.WasiConfig()
        self._store.set_wasi(wasi)
        linker = wasmtime.Linker(Runtime._engine)
        linker.define_wasi()
        self._instance = linker.instantiate(self._store, Runtime._module)
        exports = self._instance.exports(self._store)
        init = exports.get("_initialize")
        if init is not None:
            init(self._store)
        self._memory = exports["memory"]
        self._alloc = exports["ivar_alloc"]
        self._free = exports["ivar_free"]
        self._call = exports["ivar_call"]
        self._lock = threading.Lock()

    def call(self, op: str, args: dict[str, Any] | None = None, handle: int | None = None) -> Any:
        req: dict[str, Any] = {"op": op, "args": args or {}}
        if handle is not None:
            req["handle"] = handle
        data = json.dumps(req).encode()
        with self._lock:
            ptr = self._alloc(self._store, len(data))
            self._memory.write(self._store, data, ptr)
            packed = self._call(self._store, ptr, len(data))
            self._free(self._store, ptr, len(data))
            out_ptr, out_len = packed >> 32, packed & 0xFFFFFFFF
            raw = self._memory.read(self._store, out_ptr, out_ptr + out_len)
            self._free(self._store, out_ptr, max(out_len, 1))
        value = json.loads(bytes(raw))
        if isinstance(value, dict) and "error" in value and len(value) == 1:
            raise IvarError(value["error"])
        return value


_shared: Runtime | None = None


def runtime() -> Runtime:
    global _shared
    if _shared is None:
        _shared = Runtime()
    return _shared
