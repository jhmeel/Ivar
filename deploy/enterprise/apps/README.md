# The enterprise test estate's applications

One small payments API, written six times, each protected by that language's
IVAR SDK installed from a release. The campaign (`../campaign.py`) runs the
same attacks against all of them.

Every app serves:

| Route | What it does |
|---|---|
| `GET /healthz` | liveness |
| `POST /login` | `{email, password}`; reports the login to IVAR |
| `GET /accounts/{id}` | the caller's own account only |
| `PATCH /users/{id}` | `{name, role}`; `role` is privileged in `openapi.yaml`, and the app has a mass assignment bug on purpose |
| `POST /payouts/intent` | mints and attests an intent chain for `{amount}` |
| `POST /payouts` | `{amount, account}`, behind the SDK's payout guard |
| `GET /admin/users` | admins only |

Users are `user1@corp.test` to `user200@corp.test` with password `pw<n>`.
Settings come from the environment: `PORT`, `IVAR_CORE_URL`, `IVAR_MODE`,
`IVAR_DIR` (policy bundle, keyring, redaction key), `SENSOR_ID`, and the
intent seeds `IVAR_ROOT_SEED`, `IVAR_STEP_SESSION`, `IVAR_STEP_LEDGER`,
`IVAR_STEP_PAYOUT`.
