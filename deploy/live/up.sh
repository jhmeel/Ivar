#!/usr/bin/env bash
# Installs IVAR on this host as a live server, from the release images:
#   ivar-core and ivar-control containers, Envoy with Coraza and the CRS
#   ahead of the IVAR edge filter, and a real Express payments API using the
#   SDK behind it. Fresh keys, a signed policy and confirmed operator
#   decisions (marked as a live test, not production).
#
#   CORAZA_WASM=coraza-proxy-wasm.wasm deploy/live/up.sh
#   deploy/live/up.sh down
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
state="$here/.state"
bin="$root/target/release"
tag="${IVAR_TAG:-live}"

down() {
  docker rm -f ivar-live-core ivar-live-control ivar-live-envoy >/dev/null 2>&1 || true
  [ -f "$state/app.pid" ] && kill "$(cat "$state/app.pid")" 2>/dev/null || true
  rm -f "$state/app.pid"
}
if [ "${1:-}" = "down" ]; then down; exit 0; fi
down
: "${CORAZA_WASM:?set CORAZA_WASM to a coraza-proxy-wasm build}"
# Refuse to start over something already listening: a stale process would
# answer in place of the fresh install and every result would be wrong.
for port in 3000 8080 8090 9901 10000; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then echo "port $port is already in use; stop whatever holds it first" >&2; exit 1; fi
done

mkdir -p "$state/keys" "$state/tuf" "$state/data" "$state/app"
cargo build --release -q -p ivar-server --manifest-path "$root/Cargo.toml"
(cd "$root/go" && go build -o "$bin/ivar-control" ./cmd/ivar-control)

gen() { [ -f "$1" ] || "$bin/ivar-core" keygen "$1" >/dev/null; }
for k in policy-a policy-b flags-1 evidence-0 action-0 operator-alice operator-bob; do gen "$state/keys/$k.seed"; done
for k in root1 root2 targets1 targets2 snapshot timestamp; do gen "$state/tuf/$k.seed"; done
[ -f "$state/keys/redaction.hex" ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$state/keys/redaction.hex"
[ -f "$state/keys/cosign.pub" ] || { openssl ecparam -name prime256v1 -genkey -noout -out "$state/keys/cosign.key"; openssl ec -in "$state/keys/cosign.key" -pubout -out "$state/keys/cosign.pub" 2>/dev/null; }
cp "$state/keys/evidence-0.seed" "$state/keys/evidence.seed"; cp "$state/keys/action-0.seed" "$state/keys/action.seed"

"$bin/ivar-core" keyring "$state/keyring.json" "$state/keys/policy-a.seed=policy" "$state/keys/policy-b.seed=policy" \
  "$state/keys/flags-1.seed=flags" "$state/keys/evidence-0.seed=evidence+replay" "$state/keys/action-0.seed=action"
"$bin/ivar-core" keyring "$state/policy-keyring.json" "$state/keys/policy-a.seed=policy" "$state/keys/policy-b.seed=policy"
pub() { "$bin/ivar-core" keyring /dev/stdout "$1=operator" | python3 -c 'import json,sys; print(list(json.load(sys.stdin)["keys"].values())[0][0]["bytes"])'; }
printf '{"alice":"%s","bob":"%s"}\n' "$(pub "$state/keys/operator-alice.seed")" "$(pub "$state/keys/operator-bob.seed")" > "$state/keys/operators.json"

# Policy v1 (observe), with the seven decisions confirmed for this test.
cp "$here/openapi.yaml" "$root/deploy/policy/time-locks.yaml" "$state/"
sed 's/confirmed_by: ""/confirmed_by: "live test operator (not production)"/; s/confirmed_on: ""/confirmed_on: "'"$(date -u +%F)"'"/' "$root/deploy/policy/operator-decisions.yaml" > "$state/operator-decisions.yaml"
cp "$here/policy.yaml" "$state/policy-v1.yaml"
PATH="$bin:$PATH" "$bin/ivar-control" validate --source "$state/policy-v1.yaml" --library "$root/replay-library" >/dev/null
PATH="$bin:$PATH" "$bin/ivar-control" build --source "$state/policy-v1.yaml" --keys "$state/keys/policy-a.seed,$state/keys/policy-b.seed" --out "$state/policy-v1.bundle" >/dev/null
cp "$state/policy-v1.bundle" "$state/policy.bundle"

cat > "$state/core.yaml" <<YAML
http_listen: 127.0.0.1:8080
grpc_listen: 127.0.0.1:7443
data_dir: /var/lib/ivar
policy_bundle: /etc/ivar/policy.bundle
keyring: /etc/ivar/keyring.json
evidence_key_seed_file: /etc/ivar/keys/evidence.seed
action_key_seed_file: /etc/ivar/keys/action.seed
redaction_key_hex_file: /etc/ivar/keys/redaction.hex
public_url: http://127.0.0.1:8080
expected_layers: [edge, app_sdk, host, network, database]
YAML
chmod -R a+rX "$state"; chown -R 65532:65532 "$state/data"

docker run -d --name ivar-live-core --network host -v "$state:/etc/ivar:ro" -v "$state/data:/var/lib/ivar" \
  -e IVAR_SHARD=0 -e IVAR_SHARDS=1 "ivar/core:$tag" serve --config /etc/ivar/core.yaml >/dev/null
start_control() {
  docker rm -f ivar-live-control >/dev/null 2>&1 || true
  docker run -d --name ivar-live-control --network host -v "$state:/etc/ivar:ro" "ivar/control:$tag" serve \
    --bundle "/etc/ivar/$1" --tuf-keys /etc/ivar/tuf --flags-key /etc/ivar/keys/flags-1.seed \
    --operators /etc/ivar/keys/operators.json --cosign /etc/ivar/keys/cosign.pub --listen 127.0.0.1:8090 >/dev/null
}
start_control policy.bundle

# The edge filter comes out of its release OCI image.
cid=$(docker create "ivar/edge-filter:$tag" x); docker cp "$cid:/plugin.wasm" "$state/ivar_edge_filter.wasm" >/dev/null; docker rm "$cid" >/dev/null
cp "$CORAZA_WASM" "$state/coraza.wasm"

# exec makes the backgrounded subshell become node, so the saved PID is
# node's own and down really stops it.
(cd "$here/app" && exec env IVAR_CORE_URL=http://127.0.0.1:8080 IVAR_CONTROL_URL=http://127.0.0.1:8090 \
  IVAR_POLICY_BUNDLE="$state/policy-v1.bundle" IVAR_KEYRING="$state/policy-keyring.json" IVAR_REDACTION_KEY="$state/keys/redaction.hex" \
  IVAR_STATE_DIR="$state/app" IVAR_TRUSTED_PROXIES="loopback,$(hostname -I | awk '{print $1}')" PORT=3000 node server.js > "$state/app.log" 2>&1) &
echo $! > "$state/app.pid"

APP_PORT=3000 CORAZA_WASM=1 IVAR_MODE=enforce python3 "$root/deploy/local/envoy_config.py" "$state" > "$state/envoy.yaml"
docker run -d --name ivar-live-envoy --network host -v "$state:/etc/ivar:ro" envoyproxy/envoy:v1.33.2 \
  envoy -c /etc/ivar/envoy.yaml --log-level info --component-log-level wasm:info >/dev/null

ready() { for _ in $(seq 1 150); do curl -sf "$1" >/dev/null && return 0; sleep 0.2; done; echo "not ready: $1" >&2; return 1; }
ready http://127.0.0.1:8080/healthz; ready http://127.0.0.1:8090/healthz; ready http://127.0.0.1:3000/healthz; ready http://127.0.0.1:9901/ready
kill -0 "$(cat "$state/app.pid")" 2>/dev/null || { echo "the payments API exited; see $state/app.log" >&2; exit 1; }
echo "live: gateway http://127.0.0.1:10000 -> payments API :3000 | core :8080 | control :8090"
