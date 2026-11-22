"""The test shop API in Python with FastAPI and the ivar ASGI middleware."""
import hashlib
import json
import os
import secrets

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from ivar import INTENT_HEADER, attest_step, mint_intent, step_public_key, verify_policy_bundle
from ivar.asgi import IvarMiddleware

D = os.environ["IVAR_DIR"]
read = lambda f: open(f"{D}/{f}").read()  # noqa: E731
H = lambda s: hashlib.sha256(s.encode()).hexdigest()  # noqa: E731

USERS = {f"user{i}@corp.test": {"id": f"u{i}", "password": H(f"pw{i}"), "roles": ["admin"] if i == 1 else ["customer"], "balance": 100000} for i in range(1, 201)}
SESSIONS: dict[str, dict] = {}
STEPS = {"authenticated_session": os.environ["IVAR_STEP_SESSION"], "ledger_entry": os.environ["IVAR_STEP_LEDGER"], "payout_instruction": os.environ["IVAR_STEP_PAYOUT"]}
STEP_KEYS = {k: step_public_key(s) for k, s in STEPS.items()}
ROOT = os.environ["IVAR_ROOT_SEED"]
ROOT_PUB = mint_intent(ROOT, "boot", "payout", "boot", {"amount": 1})["root_public_key"]


def header(scope, name):
    return dict(scope["headers"]).get(name.encode(), b"").decode() or None


def user_of(scope):
    return SESSIONS.get(header(scope, "x-session") or "")


app = FastAPI()
app.add_middleware(
    IvarMiddleware,
    mode=os.environ.get("IVAR_MODE", "enforce"),
    identity=lambda scope: (user_of(scope) or {}).get("id"),
    session=lambda scope: header(scope, "x-session"),
    roles=lambda scope: (user_of(scope) or {}).get("roles", []),
    policy=verify_policy_bundle(read("policy.bundle"), json.loads(read("keyring.json"))),
    core_url=os.environ.get("IVAR_CORE_URL"),
    core_token=os.environ.get("IVAR_CORE_TOKEN"),
    redaction_key=read("keys/redaction.hex").strip(),
    sensor_id=os.environ.get("SENSOR_ID", "shop-python"),
    on_alert=lambda kind, msg: print(json.dumps({"ivar_alert": kind, "message": msg}), flush=True),
    control_url=os.environ.get("IVAR_CONTROL_URL"),
    policy_keyring=json.loads(read("keyring.json")),
    policy_refresh_s=2,
    policy_state_file=f"{D}/policy.state",
)
_guard = None


def need_user(request: Request):
    u = user_of(request.scope)
    return u, (None if u else JSONResponse({"error": "login required"}, status_code=401))


@app.get("/healthz")
def healthz():
    return PlainTextResponse("ok")


@app.post("/login")
async def login(request: Request):
    guardian, info = request.scope["state"]["ivar"]
    body = await request.json()
    u = USERS.get(str(body.get("email")))
    ok = bool(u) and u["password"] == H(str(body.get("password", "")))
    guardian.report_login(info, success=ok, account=str(body.get("email", "")))
    if not ok:
        return JSONResponse({"error": "invalid credentials"}, status_code=401)
    sid = f"ses_{secrets.token_hex(12)}"
    SESSIONS[sid] = u
    return {"session": sid}


@app.get("/accounts/{uid}")
def account(uid: str, request: Request):
    u, err = need_user(request)
    if err:
        return err
    return {"id": uid, "balance": u["balance"]} if u["id"] == uid else JSONResponse({"error": "not your account"}, status_code=403)


@app.patch("/users/{uid}")
async def update(uid: str, request: Request):
    u, err = need_user(request)
    if err:
        return err
    body = await request.json()
    if body.get("role"):
        u["roles"].append(body["role"])
    return {"id": u["id"], "roles": u["roles"]}


@app.post("/payouts/intent")
async def intent(request: Request):
    u, err = need_user(request)
    if err:
        return err
    body = await request.json()
    t = mint_intent(ROOT, f"int_{secrets.token_hex(6)}", "payout", header(request.scope, "x-session"), {"amount": int(body["amount"])})["token"]
    for k, s in STEPS.items():
        t = attest_step(s, k, t, ROOT_PUB)
    return {"intent": t, "header": INTENT_HEADER}


@app.post("/payouts")
async def payout(request: Request):
    global _guard
    u, err = need_user(request)
    if err:
        return err
    guardian, info = request.scope["state"]["ivar"]
    _guard = _guard or guardian.sink("payout", ROOT_PUB, STEP_KEYS)
    body = await request.json()
    d = _guard.check(info, request.headers.get(INTENT_HEADER), value=float(body.get("amount", 0)))
    if d.action != "allow":
        return JSONResponse(d.body or {}, status_code=d.status)
    u["balance"] -= float(body["amount"])
    return {"sent": True}


@app.get("/admin/users")
def admin(request: Request):
    u, err = need_user(request)
    if err:
        return err
    return {"users": len(USERS)} if "admin" in u["roles"] else JSONResponse({"error": "admins only"}, status_code=403)
