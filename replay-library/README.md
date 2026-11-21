# Attack replay library

Every incident in the design specification becomes a repeatable test
(section 4.2), and every attack on the IVAR itself is a test case
(section 16.1). A new rule, plugin, policy bundle or AI model must pass the
whole library before activation, and the learning loop retrains detectors
only after the retrained detector passes it.

Run it with:

```bash
cargo run -p ivar-server --bin ivar-replay-library -- replay-library
```

| Folder | Content |
| --- | --- |
| `incidents/` | The 2026 incidents from section 4 and the worked example from section 10.2 |
| `self-defence/` | Attacks on the IVAR from section 16.1 |

Some section 16.1 cases are about parts other than the decision core, so
they are tested where those parts live:

| Attack | Test |
| --- | --- |
| Forced circuit breaker | `crates/ivar-core/src/safeguards/circuit_breaker.rs` and `crates/ivar-core/tests/self_defence.rs` |
| Induced fail open | `crates/ivar-core/src/failure/fail_open.rs` |
| Policy rollback | `control-plane/internal/tuf` tests |
| Baseline poisoning | `crates/ivar-core/tests/self_defence.rs` |
| Silent plugin | `crates/ivar-plugin-host` drift tests |
