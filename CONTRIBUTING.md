# Contributing to IVAR

Thank you for helping. Issues, fixes, new sensors, connectors and SDKs are
all welcome.

## Before you start

* For anything larger than a small fix, open an issue first so the design
  can be agreed before the work.
* Security issues go through the private process in `SECURITY.md`, never a
  public issue.

## Building and testing

```bash
scripts/build-wasm.sh                     # the core to WebAssembly for the SDKs and console
cargo test --workspace --locked           # Rust
(cd go && go vet ./... && go test ./...)  # control plane and connectors
deploy/local/up.sh && python3 deploy/local/smoke_test.py   # end to end through real Envoy
```

Each SDK has its own tests under `sdk/<language>`; CI runs all of them
(`.github/workflows/ci.yml`).

## Rules the code keeps

* Every decision is made by the one core: SDKs and filters call it, they do
  not reimplement it.
* New behaviour starts in observe. Anything that can block, contain or
  refuse must respect both the component's mode and the signed policy.
* Payload values and identifiers are redacted at the sensor; never send raw
  values to the core.
* A change that weakens protection must still need two policy keys.
* Add a scenario to `replay-library/` for new detections, and keep every
  existing scenario passing.

## Licence of contributions

By contributing you agree that your contribution is licensed under the
Apache License 2.0, as stated in section 5 of the `LICENSE`, and that you
have the right to submit it.
