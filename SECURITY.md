# Security policy

IVAR is security software, so reports of weaknesses in it are especially
welcome.

## Reporting a vulnerability

Please do not open a public issue. Report privately through GitHub:
**Security** tab, then **Report a vulnerability** (a private security
advisory). Include what you found, how to reproduce it, and the impact you
expect.

You will get an acknowledgement, and fixes are published with credit to the
reporter unless you ask otherwise.

## In scope

Anything that lets an attacker get past IVAR or turn it against its users:
bypassing the local fast path or the core, forging or rolling back a signed
policy, weakening policy with one key, breaking the evidence hash chain or a
replay's verification, evading intent binding, leaking unredacted payloads
or identifiers, and the attacks on IVAR itself described in section 16.1 of
the specification (`replay-library/self-defence`).

## Status

IVAR has not had an external security review or a production scale load
test (see "Verification status" in the README). Evaluate it in observe mode
before relying on it to block.
