#!/usr/bin/env bash
# Brings up a local IVAR stack: the core, the control plane, a demo upstream
# and Envoy carrying the IVAR edge filter, all signed with fresh keys.
#
#   deploy/local/up.sh            build, generate keys, start everything
#   CORAZA_WASM=coraza-proxy-wasm.wasm deploy/local/up.sh   with Coraza and the CRS ahead
#   deploy/local/up.sh down       stop it
#
# State (keys, bundle, evidence) lives in deploy/local/.state.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
state="$here/.state"
bin="$root/target/release"

if [ "${1:-}" = "down" ]; then
  for p in "$state"/*.pid; do [ -f "$p" ] && kill "$(cat "$p")" 2>/dev/null || true; rm -f "$p"; done
  docker rm -f ivar-envoy >/dev/null 2>&1 || true
  exit 0
fi

mkdir -p "$state/keys" "$state/tuf" "$state/data"
cargo build --release -q -p ivar-server -p ivar-edge-filter --manifest-path "$root/Cargo.toml"
cargo build --release -q -p ivar-edge-filter --target wasm32-wasip1 --manifest-path "$root/Cargo.toml"
(cd "$root/go" && go build -o "$bin/ivar-control" ./cmd/ivar-control && go build -o "$bin/ivar-connector" ./cmd/ivar-connector)

gen() { [ -f "$1" ] || "$bin/ivar-core" keygen "$1" >/dev/null; }
for k in policy-a policy-b flags-1 evidence-0 action-0 operator-alice operator-bob; do gen "$state/keys/$k.seed"; done
for k in root1 root2 targets1 targets2 snapshot timestamp; do gen "$state/tuf/$k.seed"; done
[ -f "$state/keys/redaction.hex" ] || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$state/keys/redaction.hex"
[ -f "$state/keys/cosign.key" ] || { openssl ecparam -name prime256v1 -genkey -noout -out "$state/keys/cosign.key"; openssl ec -in "$state/keys/cosign.key" -pubout -out "$state/keys/cosign.pub" 2>/dev/null; }

"$bin/ivar-core" keyring "$state/keyring.json" \
  "$state/keys/policy-a.seed=policy" "$state/keys/policy-b.seed=policy" \
  "$state/keys/flags-1.seed=flags" "$state/keys/evidence-0.seed=evidence+replay" "$state/keys/action-0.seed=action"
"$bin/ivar-core" keyring "$state/policy-keyring.json" "$state/keys/policy-a.seed=policy" "$state/keys/policy-b.seed=policy"
pub() { "$bin/ivar-core" keyring /dev/stdout "$1=operator" | python3 -c 'import json,sys; print(list(json.load(sys.stdin)["keys"].values())[0][0]["bytes"])'; }
printf '{"alice":"%s","bob":"%s"}\n' "$(pub "$state/keys/operator-alice.seed")" "$(pub "$state/keys/operator-bob.seed")" > "$state/operators.json"

PATH="$bin:$PATH" "$bin/ivar-control" build --source "$root/deploy/policy/policy.yaml" \
  --keys "$state/keys/policy-a.seed,$state/keys/policy-b.seed" --out "$state/policy.bundle"

cat > "$state/core.yaml" <<YAML
http_listen: 127.0.0.1:8080
grpc_listen: 127.0.0.1:7443
data_dir: $state/data
policy_bundle: $state/policy.bundle
keyring: $state/keyring.json
evidence_key_seed_file: $state/keys/evidence-0.seed
action_key_seed_file: $state/keys/action-0.seed
redaction_key_hex_file: $state/keys/redaction.hex
public_url: http://127.0.0.1:8080
expected_layers: [edge, app_sdk, host, network, database]
YAML

start() { local name="$1"; shift; "$@" >"$state/$name.log" 2>&1 & echo $! > "$state/$name.pid"; }
start core "$bin/ivar-core" serve --config "$state/core.yaml"
start control "$bin/ivar-control" serve --bundle "$state/policy.bundle" --tuf-keys "$state/tuf" \
  --flags-key "$state/keys/flags-1.seed" --operators "$state/operators.json" --cosign "$state/keys/cosign.pub" --listen 127.0.0.1:8090
start upstream python3 "$here/upstream.py" 9000

python3 "$here/envoy_config.py" "$state" > "$state/envoy.yaml"
cp "$root/target/wasm32-wasip1/release/ivar_edge_filter.wasm" "$state/ivar_edge_filter.wasm"
# Coraza with the OWASP Core Rule Set ahead of the IVAR filter: set
# CORAZA_WASM to a coraza-proxy-wasm build (github.com/corazawaf/coraza-proxy-wasm).
if [ -n "${CORAZA_WASM:-}" ]; then cp "$CORAZA_WASM" "$state/coraza.wasm"; else rm -f "$state/coraza.wasm"; fi
docker rm -f ivar-envoy >/dev/null 2>&1 || true
docker run -d --name ivar-envoy --network host -v "$state:/etc/ivar:ro" envoyproxy/envoy:v1.33.2 \
  envoy -c /etc/ivar/envoy.yaml --log-level info --component-log-level wasm:info >/dev/null

ready() { for _ in $(seq 1 100); do curl -sf "$1" >/dev/null && return 0; sleep 0.2; done; return 1; }
for url in http://127.0.0.1:8080/healthz http://127.0.0.1:8090/healthz http://127.0.0.1:9901/ready; do
  ready "$url" || { echo "not ready: $url (logs in $state)" >&2; exit 1; }
done
echo "IVAR local stack up: gateway http://127.0.0.1:10000, core :8080, control :8090, envoy admin :9901"
