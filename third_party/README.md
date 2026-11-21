# Third party code

## biscuit-auth 6.0.0

Vendored from crates.io with one change in `src/time.rs`: the WebAssembly
`Instant` shim (which calls `performance.now()` through wasm-bindgen) applies
only to `wasm32-unknown-unknown`. On `wasm32-wasip1` the standard library
clock is used, because WASI provides clocks natively. This lets the same
intent verification run in the C ABI module that the Python, Go, Java, .NET
and PHP SDKs load. License: Apache-2.0, see `biscuit-auth/LICENSE`.
