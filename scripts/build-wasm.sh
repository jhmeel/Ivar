#!/usr/bin/env bash
# Build the decision core to WebAssembly and generate bindings for Node
# (application SDKs) and the browser (replay viewer).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -p ivar-wasm --target wasm32-unknown-unknown --release
WASM=target/wasm32-unknown-unknown/release/ivar_wasm.wasm
wasm-bindgen --target nodejs --out-dir sdk/node/core-wasm "$WASM"
wasm-bindgen --target web --out-dir replay-viewer/pkg "$WASM"
# The C ABI module for every other WebAssembly runtime.
cargo build -p ivar-abi --target wasm32-wasip1 --release
ABI=target/wasm32-wasip1/release/ivar_abi.wasm
mkdir -p sdk/python/ivar/_wasm sdk/go/wasm sdk/php/wasm sdk/java/src/main/resources sdk/dotnet/Ivar/wasm
for d in sdk/python/ivar/_wasm sdk/go/wasm sdk/php/wasm sdk/java/src/main/resources sdk/dotnet/Ivar/wasm; do
  cp "$ABI" "$d/ivar_core.wasm"
done
echo "built $(du -h "$WASM" | cut -f1) core"
