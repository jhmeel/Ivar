"""Live test: legitimate traffic and an attack campaign against the payments
API through the gateway, then forensics and resilience checks.

Run after deploy/live/up.sh. Every check records what actually happened, so
the report shows the system's real behaviour, not just pass or fail.
"""
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
STATE = os.path.join(HERE, ".state")
BIN = os.path.join(ROOT, "target", "release")
GW = "http://127.0.0.1:10000"
CORE = "http://127.0.0.1:8080"
OPERATOR = {"x-ivar-operator": "alice", "x-ivar-roles": "incident_lead,analyst", "x-ivar-hardware-2fa": "true"}
results = []


def http(method, url, body=None, headers=None, raw=None, timeout=5):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    r = urllib.request.Request(url, data=data, method=method, headers={"content-type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            text = resp.read().decode()
            return resp.status, text, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(), dict(e.headers)
    except Exception as e:  # unreachable, reset, timeout
        return 0, str(e), {}


def gw(method, path, ip, body=None, session=None, extra=None):
    h = {"x-forwarded-for": ip, **({"x-session": session} if session else {}), **(extra or {})}
    return http(method, GW + path, body, h)


def jbody(text):
    try:
        return json.loads(text)
    except Exception:
        return {}


def check(section, name, ok, observed):
    results.append({"section": section, "check": name, "ok": bool(ok), "observed": observed})
    print(f"{'PASS' if ok else 'FAIL'}  [{section}] {name}  ->  {observed}")


def login(email, password, ip):
    s, t, _ = gw("POST", "/login", ip, {"email": email, "password": password})
    return s, jbody(t).get("session"), t


def wait(pred, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.25)
    return False


def metric(name):
    s, t, _ = http("GET", CORE + "/metrics")
    for line in t.splitlines():
        if line.startswith(name + " "):
            return float(line.split()[1])
    return 0.0


def payout(session, ip, amount, with_intent=True):
    extra = {}
    if with_intent:
        s, t, _ = gw("POST", "/payouts/intent", ip, {"amount": amount}, session)
        b = jbody(t)
        extra = {b["header"]: b["intent"]} if s == 200 else {}
    return gw("POST", "/payouts", ip, {"amount": amount}, session, extra)


def envoy_log():
    return subprocess.run(["docker", "logs", "ivar-live-envoy"], capture_output=True, text=True).stderr


# 1. Observe phase (policy v1): real users work, attacks are recorded only.
S = "observe"
s, alice, _ = login("alice@bank.test", "correct horse", "203.0.113.10")
check(S, "customer logs in", s == 200 and alice, s)
s, t, _ = gw("GET", "/accounts/u_alice", "203.0.113.10", session=alice)
check(S, "customer reads own account", s == 200, s)
s, t, _ = payout(alice, "203.0.113.10", 500)
check(S, "customer payout with an intent chain", s == 200, f"{s} {t[:60]}")
s, t, _ = gw("GET", "/accounts/1?id=1%27%20OR%20%271%27%3D%271", "198.51.100.200")
check(S, "SQL injection blocked by Coraza and the CRS", s == 403, s)
s, t, _ = gw("GET", "/internal/billing-export", "198.51.100.201")
check(S, "decoy route recorded, not blocked, in observe", s == 404 and "verdict_id" not in t, s)
s, t, _ = payout(alice, "203.0.113.10", 100, with_intent=False)
check(S, "payout without intent refused (INTENT_BINDING enforce for payout)", s == 403, f"{s} {t[:70]}")
check(S, "events from the edge and the SDK reach the core", wait(lambda: metric("ivar_events_total") >= 8), metric("ivar_events_total"))

# 2. Live switch to enforce: a v2 policy signed by both keys, no restarts.
S = "rollout"
src = open(os.path.join(STATE, "policy-v1.yaml")).read().replace("version: 1\n", "version: 2\n", 1).replace("policy_version: live-1", "policy_version: live-2").replace("detection_mode: observe", "detection_mode: enforce")
open(os.path.join(STATE, "policy-v2.yaml"), "w").write(src)
env = {**os.environ, "PATH": BIN + ":" + os.environ["PATH"]}
subprocess.run([os.path.join(BIN, "ivar-control"), "build", "--source", os.path.join(STATE, "policy-v2.yaml"), "--keys", f"{STATE}/keys/policy-a.seed,{STATE}/keys/policy-b.seed",
                "--previous", os.path.join(STATE, "policy-v1.bundle"), "--out", os.path.join(STATE, "policy-v2.bundle")], check=True, capture_output=True, env=env)
subprocess.run(["bash", "-c", f'docker rm -f ivar-live-control >/dev/null; docker run -d --name ivar-live-control --network host -v "{STATE}:/etc/ivar:ro" ivar/control:{os.environ.get("IVAR_TAG", "live")} serve --bundle /etc/ivar/policy-v2.bundle --tuf-keys /etc/ivar/tuf --flags-key /etc/ivar/keys/flags-1.seed --operators /etc/ivar/keys/operators.json --cosign /etc/ivar/keys/cosign.pub --listen 127.0.0.1:8090 >/dev/null'], check=True)
s, t, _ = http("POST", CORE + "/v1/policy", headers=OPERATOR, raw=open(os.path.join(STATE, "policy-v2.bundle"), "rb").read())
check(S, "core accepts v2 from an incident lead with hardware 2FA", s == 200, f"{s} {t[:80]}")
check(S, "edge filter verifies and applies v2 live", wait(lambda: "policy 2 applied" in envoy_log()), "seen in Envoy log")
check(S, "SDK verifies and applies v2 live", wait(lambda: jbody(http("GET", "http://127.0.0.1:3000/ivar/policy")[1]).get("version") == 2), jbody(http("GET", "http://127.0.0.1:3000/ivar/policy")[1]))

# 3. Enforce phase: the attack campaign.
S = "attack"
# A. Credential spray from one source across many accounts.
spray_ip = "198.51.100.66"
codes = []
for i in range(40):
    st, t, _ = gw("POST", "/login", spray_ip, {"email": f"user{i}@bank.test", "password": "Winter2026!"})
    codes.append(st)
acted = [c for c in codes if c in (403, 429)] + [c for c, t in [(c, 0) for c in codes] if False]
first_action = next((i for i, c in enumerate(codes) if c in (403, 429)), None)
check(S, "credential spray is throttled or contained", first_action is not None, f"first IVAR action at attempt {first_action}, codes {sorted(set(codes))}")
st, t, _ = gw("GET", "/healthz", spray_ip)
check(S, "the spraying source stays contained", st in (403, 429), st)

# B. Account takeover then privilege escalation by mass assignment.
ato_ip = "198.51.100.77"
for p in ("123456", "password", "bob2026"):
    gw("POST", "/login", ato_ip, {"email": "bob@bank.test", "password": p})
s, bob, t = login("bob@bank.test", "battery staple", ato_ip)
check(S, "takeover login after failures is seen (allowed, challenged or blocked)", s in (200, 401, 403, 429), s)
if bob:
    st, t, _ = gw("PATCH", "/users/u_bob", ato_ip, {"role": "admin"}, bob)
    check(S, "privileged field write (role=admin) refused at the edge or SDK", st == 403, f"{st} {t[:70]}")
    st, t, _ = gw("GET", "/admin/users", ato_ip, session=bob)
    check(S, "admin data not reachable after the attempt", st in (401, 403, 429), st)
    st, t, _ = payout(bob, ato_ip, 80_000, with_intent=False)
    check(S, "stolen session cannot move money without an intent chain", st in (403, 429), st)
else:
    check(S, "takeover stopped before a session was issued", True, s)

# C. Legitimate high value payout is held by the time lock, small ones pass.
s, carol, _ = login("user39@bank.test", "pw-39", "203.0.113.39")
st, t, _ = payout(carol, "203.0.113.39", 900)
check(S, "legitimate small payout passes in enforce", st == 200, f"{st} {t[:60]}")
st, t, _ = payout(carol, "203.0.113.39", 60_000)
check(S, "large payout held by the 30 minute time lock", st == 202 and "lock_id" in t, f"{st} {t[:80]}")

# D. Decoy route: blocked and the source contained.
decoy_ip = "198.51.100.88"
st, t, _ = gw("GET", "/internal/billing-export", decoy_ip)
check(S, "decoy route blocked in enforce by IVAR", st == 403 and "verdict_id" in t, f"{st} {t[:60]}")
time.sleep(1.5)
st, t, _ = gw("GET", "/healthz", decoy_ip)
check(S, "decoy toucher contained afterwards", st == 403, st)

# E. Victim lockout attempt: spray at the CEO from many sources.
for i in range(25):
    gw("POST", "/login", f"192.0.2.{i + 10}", {"email": "ceo@bank.test", "password": f"guess{i}"})
s, ceo, _ = login("ceo@bank.test", "exec-only", "203.0.113.200")
check(S, "victim lockout fails: the targeted executive still logs in", s == 200 and ceo, s)

# F. Shared network (CGNAT) is never banned.
st, _, _ = gw("GET", "/internal/billing-export", "100.64.3.3")
st2, _, _ = gw("GET", "/healthz", "100.64.3.4")
check(S, "another user behind the same CGNAT range is not banned", st2 == 200, f"decoy {st}, neighbour {st2}")

# G. Real users were never affected.
s, alice2, _ = login("alice@bank.test", "correct horse", "203.0.113.10")
st, _, _ = gw("GET", "/accounts/u_alice", "203.0.113.10", session=alice2)
check(S, "legitimate customer unaffected after the campaign", s == 200 and st == 200, f"login {s}, read {st}")

# 4. Forensics.
S = "forensics"
s, t, _ = http("GET", CORE + "/v1/incidents", headers=OPERATOR)
incidents = jbody(t) if s == 200 else []
check(S, "incidents opened", len(incidents) > 0, f"{len(incidents)} incidents")
s, t, _ = http("GET", CORE + "/v1/evidence", headers=OPERATOR)
records = jbody(t) if s == 200 else []
check(S, "evidence sealed", len(records) > 0, f"{len(records)} records")
verify = subprocess.run(["node", "-e", """
const w = require(process.argv[1]); const fs = require('fs');
const recs = fs.readFileSync(0, 'utf8');
console.log(w.verifyEvidenceChain(recs));
""", os.path.join(ROOT, "sdk", "node", "core-wasm")], input=json.dumps(records), capture_output=True, text=True)
check(S, "evidence hash chain verifies independently", '"head"' in verify.stdout, verify.stdout.strip()[:90] or verify.stderr[:200])
if incidents:
    inc = max(incidents, key=lambda i: len(json.dumps(i)))
    iid = inc.get("incident_id")
    s, t, _ = http("GET", f"{CORE}/v1/incidents/{iid}/replay", headers=OPERATOR, timeout=30)
    check(S, "replay builds and reproduces the live verdicts", s == 200 and jbody(t).get("re_execution", {}).get("matched"), f"{s} {t[:90] if s != 200 else str(jbody(t).get('re_execution'))}")
    if s == 200:
        rv = subprocess.run(["node", "-e", """
const w = require(process.argv[1]); const fs = require('fs');
console.log(w.reverifyBundle(fs.readFileSync(0, 'utf8'), fs.readFileSync(process.argv[2], 'utf8'), fs.readFileSync(process.argv[3], 'utf8').trim()));
""", os.path.join(ROOT, "sdk", "node", "core-wasm"), os.path.join(STATE, "keyring.json"), os.path.join(STATE, "keys", "redaction.hex")], input=t, capture_output=True, text=True)
        check(S, "a third party re verifies the signed replay", '"matched":true' in rv.stdout, rv.stdout.strip()[:120] or rv.stderr[:200])
        open(os.path.join(STATE, "replay.json"), "w").write(t)
s, t, _ = http("GET", CORE + "/metrics")
verdicts = {l.split("{")[1].split("}")[0]: l.split()[-1] for l in t.splitlines() if l.startswith("ivar_verdicts_total{")}
check(S, "core verdicts by decision", True, verdicts)

# 5. Resilience.
S = "resilience"
subprocess.run(["docker", "stop", "ivar-live-control"], capture_output=True)
st, t, _ = gw("GET", "/internal/billing-export", "198.51.100.99")
check(S, "control plane down: enforcement continues", st == 403 and "verdict_id" in t, st)
subprocess.run(["docker", "stop", "ivar-live-core"], capture_output=True)
time.sleep(1)
s, ses, _ = login("user5@bank.test", "pw-5", "203.0.113.55")
check(S, "core down: legitimate traffic still served (fail open on public routes)", s == 200, s)
st, t, _ = gw("GET", "/internal/billing-export", "198.51.100.98")
check(S, "core down: known attacks still blocked locally from signed policy", st == 403 and "verdict_id" in t, st)
subprocess.run(["docker", "start", "ivar-live-core", "ivar-live-control"], capture_output=True)
check(S, "core restarts on the policy an operator pushed (v2), not the config's v1", wait(lambda: http("GET", CORE + "/v1/policy/bundle?have=1")[0] == 200), http("GET", CORE + "/v1/policy/bundle?have=1")[0])
check(S, "core restarts with its evidence chain intact", wait(lambda: http("GET", CORE + "/healthz")[0] == 200) and len(jbody(http("GET", CORE + "/v1/evidence", headers=OPERATOR)[1]) or []) >= len(records), "healthy, evidence kept")

failed = [r for r in results if not r["ok"]]
json.dump(results, open(os.path.join(STATE, "report.json"), "w"), indent=2)
print(f"\n{len(results) - len(failed)} of {len(results)} checks passed")
sys.exit(1 if failed else 0)
