"""End to end test of the local stack through a real Envoy.

Run after up.sh. It checks, in order:
  1. observe policy: traffic passes and events reach the core;
  2. a stronger v2 policy signed by both policy keys rolls out through the
     control plane and the filter verifies and applies it live;
  3. enforce: positive security refuses a write to a privileged field at the
     edge, declared traffic still passes;
  4. a weakening v3 signed by only one key is refused by the filter, which
     keeps enforcing v2;
  5. a control plane outage leaves the last signed policy in force;
  6. with Coraza ahead (CORAZA_WASM), the Core Rule Set blocks injection and
     each block reaches the core as an engine alert.
"""
import base64
import io
import json
import os
import tarfile
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
STATE = os.path.join(HERE, ".state")
BIN = os.path.join(ROOT, "target", "release")
GATEWAY = "http://127.0.0.1:10000"
failures = []


def req(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(GATEWAY + path, data=data, method=method, headers={"content-type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f" ({detail})" if detail and not ok else ""))
    if not ok:
        failures.append(name)


def envoy_log():
    return subprocess.run(["docker", "logs", "ivar-envoy"], capture_output=True, text=True).stderr


def wait_for(pred, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.25)
    return False


def metric(name):
    with urllib.request.urlopen("http://127.0.0.1:8080/metrics") as r:
        for line in r.read().decode().splitlines():
            if line.startswith(name + " "):
                return float(line.split()[1])
    return 0.0


def build(version, mode, keys, extra=""):
    src = os.path.join(STATE, f"policy-v{version}.yaml")
    text = open(os.path.join(ROOT, "deploy", "policy", "policy.yaml")).read()
    text = text.replace("version: 1\n", f"version: {version}\n", 1).replace("policy_version: payments-2026.11.1", f"policy_version: payments-2026.11.{version}")
    text = text.replace("detection_mode: observe", f"detection_mode: {mode}") + extra
    open(src, "w").write(text)
    for f in ("time-locks.yaml", "openapi.yaml"):
        open(os.path.join(STATE, f), "w").write(open(os.path.join(ROOT, "deploy", "policy", f)).read())
    out = os.path.join(STATE, f"policy-v{version}.bundle")
    args = [os.path.join(BIN, "ivar-control"), "build", "--source", src, "--keys", ",".join(os.path.join(STATE, "keys", k + ".seed") for k in keys), "--out", out]
    if version > 1:
        args += ["--previous", os.path.join(STATE, f"policy-v{version - 1}.bundle") if version > 2 else os.path.join(STATE, "policy.bundle")]
    subprocess.run(args, check=True, capture_output=True, env={**os.environ, "PATH": BIN + ":" + os.environ["PATH"]})
    return out


def drop_signature(bundle_path, out_path):
    """A bundle the control plane would never sign: one signature removed."""
    raw = base64.b64decode(open(bundle_path).read().strip())
    src = tarfile.open(fileobj=io.BytesIO(raw))
    buf = io.BytesIO()
    dst = tarfile.open(fileobj=buf, mode="w")
    for m in src.getmembers():
        data = src.extractfile(m).read()
        if m.name == "signatures.json":
            data = json.dumps(json.loads(data)[:1]).encode()
            m.size = len(data)
        dst.addfile(m, io.BytesIO(data))
    dst.close()
    open(out_path, "w").write(base64.b64encode(buf.getvalue()).decode())
    return out_path


def serve_control(bundle):
    pid_file = os.path.join(STATE, "control.pid")
    if os.path.exists(pid_file):
        subprocess.run(["kill", open(pid_file).read().strip()], capture_output=True)
        time.sleep(0.5)
    if bundle is None:
        os.remove(pid_file)
        return
    p = subprocess.Popen([os.path.join(BIN, "ivar-control"), "serve", "--bundle", bundle, "--tuf-keys", os.path.join(STATE, "tuf"),
                          "--flags-key", os.path.join(STATE, "keys", "flags-1.seed"), "--operators", os.path.join(STATE, "operators.json"),
                          "--cosign", os.path.join(STATE, "keys", "cosign.pub"), "--listen", "127.0.0.1:8090"],
                         stdout=open(os.path.join(STATE, "control.log"), "a"), stderr=subprocess.STDOUT)
    open(pid_file, "w").write(str(p.pid))


# 1. Observe.
before = metric("ivar_events_total")
s, _ = req("GET", "/accounts/42")
check("observe: declared request passes", s == 200, s)
s, _ = req("POST", "/payouts", {"amount": 5, "account": "acc-1", "is_admin": True})
check("observe: undeclared field is recorded, not refused", s == 200, s)
check("observe: edge events reach the core", wait_for(lambda: metric("ivar_events_total") >= before + 2), metric("ivar_events_total"))

# 2. Live rollout of a stronger policy signed by both keys.
v2 = build(2, "enforce", ["policy-a", "policy-b"])
serve_control(v2)
check("rollout: filter verifies and applies v2", wait_for(lambda: "policy 2 applied" in envoy_log()), envoy_log()[-400:])

# 3. Enforce.
s, body = req("PATCH", "/users/7", {"role": "admin"})
check("enforce: privileged field write refused at the edge", s == 403, f"{s} {body}")
check("enforce: refusal cites a verdict", "verdict_id" in body, body)
s, _ = req("PATCH", "/users/8", {"name": "Ada"}, {"x-forwarded-for": "203.0.113.50"})
check("enforce: declared profile update passes", s == 200, s)
s, _ = req("POST", "/payouts", {"amount": 5, "account": "acc-1"}, {"x-forwarded-for": "203.0.113.51"})
check("enforce: declared payout passes", s == 200, s)

# 4. A weakening change signed by one key is refused by the control plane
# and, if forged, by the filter, which keeps enforcing v2.
try:
    build(3, "observe", ["policy-a"])
    check("weakening: control plane refuses a one key weakening", False, "it signed")
except subprocess.CalledProcessError as e:
    check("weakening: control plane refuses a one key weakening", b"two named policy keys" in e.stderr + e.stdout, e.stderr)
v3 = drop_signature(build(3, "observe", ["policy-a", "policy-b"]), os.path.join(STATE, "policy-v3-forged.bundle"))
serve_control(v3)
check("weakening: forged v3 refused by the filter", wait_for(lambda: "two named policy keys" in envoy_log()), envoy_log()[-400:])
s, _ = req("PATCH", "/users/9", {"role": "admin"}, {"x-forwarded-for": "203.0.113.60"})
check("weakening: filter keeps enforcing v2", s == 403, s)

# 5. Control plane outage: last signed policy stays in force.
serve_control(None)
time.sleep(2)
s, _ = req("PATCH", "/users/10", {"role": "admin"}, {"x-forwarded-for": "203.0.113.70"})
check("outage: last signed policy still enforced", s == 403, s)
s, _ = req("GET", "/accounts/9", headers={"x-forwarded-for": "203.0.113.71"})
check("outage: declared traffic still passes", s == 200, s)
serve_control(os.path.join(STATE, "policy-v2.bundle"))

# 6. Coraza with the OWASP Core Rule Set ahead of the IVAR filter.
if os.path.exists(os.path.join(STATE, "coraza.wasm")):
    serve_control(os.path.join(STATE, "policy-v2.bundle"))
    before = metric("ivar_events_total")
    s, _ = req("GET", "/accounts/1?id=1%27%20OR%20%271%27%3D%271", headers={"x-forwarded-for": "203.0.113.80"})
    check("coraza: SQL injection blocked by the Core Rule Set", s == 403, s)
    s, _ = req("GET", "/accounts/2", headers={"x-forwarded-for": "203.0.113.81"})
    check("coraza: clean request passes both filters", s == 200, s)
    s, _ = req("PATCH", "/users/11", {"role": "admin"}, {"x-forwarded-for": "203.0.113.82"})
    check("coraza: IVAR positive security still applies behind Coraza", s == 403, s)

    def coraza_event_reached_core():
        r = urllib.request.Request("http://127.0.0.1:8080/v1/evidence", headers={"x-ivar-operator": "smoke", "x-ivar-roles": "analyst", "x-ivar-hardware-2fa": "true"})
        recs = json.load(urllib.request.urlopen(r))
        return any("coraza.crs_block" in json.dumps(x.get("payload", {})) for x in recs)

    check("coraza: the block reaches the core as an engine alert", wait_for(coraza_event_reached_core), metric("ivar_events_total") - before)

print(f"{'all checks passed' if not failures else str(len(failures)) + ' checks failed'}")
sys.exit(1 if failures else 0)
