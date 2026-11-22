#!/usr/bin/env bash
# The enterprise test estate, built the way a customer installs IVAR:
#
#   three core shards behind a round robin load balancer, the control plane
#   serving signed policy, Envoy with Coraza and the OWASP Core Rule Set ahead
#   of the IVAR edge filter, and the same payments API in six languages, each
#   installed from its SDK package (an npm tarball, a wheel, a Go module, a
#   jar and pom, a NuGet package, a Composer zip).
#
# Every component authenticates to the core with its own sensor token, and
# operator requests need the SSO proxy's token.
#
#   CORAZA_WASM=coraza-proxy-wasm.wasm deploy/enterprise/up.sh     build from this checkout and start
#   deploy/enterprise/up.sh down
#   deploy/enterprise/up.sh restart <app> [bundle]                 restart one app, optionally on another policy bundle
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
state="$here/.state"
art="$state/artifacts"
version="$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)"
bin="$root/target/release"
APPS="node python go java dotnet php"

stop() { if [ -f "$state/pids/$1" ]; then kill "$(cat "$state/pids/$1")" 2>/dev/null || true; fi; rm -f "$state/pids/$1"; }
down() {
  for p in "$state"/pids/*; do if [ -e "$p" ]; then stop "$(basename "$p")"; fi; done
  docker rm -f ivar-enterprise-envoy >/dev/null 2>&1 || true
}
start() { # name, log file, command...
  local name=$1; shift
  ( exec "$@" ) >"$state/logs/$name.log" 2>&1 &
  echo $! > "$state/pids/$name"
}
ready() { for _ in $(seq 1 300); do curl -sf "$1" >/dev/null && return 0; sleep 0.2; done; echo "not ready: $1" >&2; tail -20 "$state/logs/$2.log" >&2; return 1; }

port_of() { case $1 in node) echo 3101;; python) echo 3102;; go) echo 3103;; java) echo 3104;; dotnet) echo 3105;; php) echo 3106;; esac; }

start_app() { # app, policy bundle
  local app=$1 bundle=${2:-$state/policy.bundle} port; port=$(port_of "$1")
  local d="$state/run-$app"; mkdir -p "$d/keys"
  cp "$bundle" "$d/policy.bundle"; cp "$state/policy-keyring.json" "$d/keyring.json"; cp "$state/keys/redaction.hex" "$d/keys/"
  rm -f "$d/policy.state" "$d/policy.state.checked"
  local envs=(IVAR_DIR="$d" PORT="$port" IVAR_CORE_URL=http://127.0.0.1:8080 IVAR_CONTROL_URL="${IVAR_CONTROL_URL-http://127.0.0.1:8090}" IVAR_CORE_TOKEN="$(cat "$state/tokens/$app.token")" IVAR_MODE=enforce
    SENSOR_ID="shop-$app" IVAR_ROOT_SEED="$(cat "$state/keys/intent-root.seed")" IVAR_STEP_SESSION="$(cat "$state/keys/step-session.seed")"
    IVAR_STEP_LEDGER="$(cat "$state/keys/step-ledger.seed")" IVAR_STEP_PAYOUT="$(cat "$state/keys/step-payout.seed")")
  stop "$app"
  case $app in
    node) start node env "${envs[@]}" node "$state/apps/node/server.js" ;;
    python) start python env "${envs[@]}" "$state/apps/python/venv/bin/uvicorn" --app-dir "$state/apps/python" app:app --host 127.0.0.1 --port "$port" --proxy-headers --forwarded-allow-ips 127.0.0.1 --log-level warning ;;
    go) start go env "${envs[@]}" IVAR_TRUSTED_PROXIES=127.0.0.1 "$state/apps/go/shop" ;;
    java) start java env "${envs[@]}" java -cp "$state/apps/java/target/classes:$(cat "$state/apps/java/cp.txt")" shop.Main ;;
    dotnet) start dotnet env "${envs[@]}" dotnet "$state/apps/dotnet/out/shop.dll" ;;
    php) start php env "${envs[@]}" PHP_CLI_SERVER_WORKERS=8 IVAR_WASMTIME_LIB="$WASMTIME_LIB" php -d ffi.enable=1 -S "127.0.0.1:$port" -t "$state/apps/php" "$state/apps/php/index.php" ;;
  esac
  ready "http://127.0.0.1:$port/healthz" "$app"
}

if [ "${1:-}" = "down" ]; then down; exit 0; fi
WASMTIME_LIB=$(python3 -c 'import wasmtime,os;print(os.path.join(os.path.dirname(wasmtime.__file__),"linux-x86_64","_libwasmtime.so"))')
if [ "${1:-}" = "restart" ]; then start_app "$2" "${3:-}"; exit 0; fi
: "${CORAZA_WASM:?set CORAZA_WASM to a coraza-proxy-wasm build}"
down
for port in 8080 8081 8082 8083 8090 9901 3101 3102 3103 3104 3105 3106 10001 10002 10003 10004 10005 10006; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then echo "port $port is already in use" >&2; exit 1; fi
done
rm -rf "$state"; mkdir -p "$state"/{keys,tuf,tokens,pids,logs,apps} "$art"

echo "== building the release artifacts from this checkout ($version)"
( cd "$root"
  cargo build --release --locked -q -p ivar-server
  cargo build --release --locked -q -p ivar-edge-filter --target wasm32-wasip1
  (cd go && go build -o "$bin/ivar-control" ./cmd/ivar-control)
  scripts/build-wasm.sh >/dev/null
  (cd sdk/node/core-wasm && npm pack -s --pack-destination "$art" >/dev/null)
  (cd sdk/node/express && npm ci -s && npm run -s build && cp package.json package.json.orig \
    && npm pkg set "dependencies.@ivar/core-wasm=file:$art/ivar-core-wasm-$version.tgz" && npm pack -s --pack-destination "$art" >/dev/null; mv package.json.orig package.json)
  python3 -m build -q --wheel --outdir "$art" sdk/python >/dev/null 2>&1
  (cd sdk/java && mvn -q -B package -DskipTests && cp target/ivar-java-$version.jar "$art/" && cp pom.xml "$art/ivar-java-$version.pom")
  dotnet pack -v q sdk/dotnet/Ivar -c Release -o "$art" >/dev/null
  (cd sdk/php && zip -qr "$art/ivar-php-$version.zip" composer.json src wasm) )
cp "$root/target/wasm32-wasip1/release/ivar_edge_filter.wasm" "$state/"
cp "$CORAZA_WASM" "$state/coraza.wasm"

echo "== keys, tokens and policy"
gen() { "$bin/ivar-core" keygen "$1" >/dev/null; }
for k in policy-a policy-b flags-1 evidence-0 evidence-1 evidence-2 action-0 operator-alice operator-bob intent-root step-session step-ledger step-payout; do gen "$state/keys/$k.seed"; done
for k in root1 root2 targets1 targets2 snapshot timestamp; do gen "$state/tuf/$k.seed"; done
head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$state/keys/redaction.hex"
openssl ecparam -name prime256v1 -genkey -noout -out "$state/keys/cosign.key"; openssl ec -in "$state/keys/cosign.key" -pubout -out "$state/keys/cosign.pub" 2>/dev/null
"$bin/ivar-core" keyring "$state/keyring.json" "$state/keys/policy-a.seed=policy" "$state/keys/policy-b.seed=policy" "$state/keys/flags-1.seed=flags" \
  "$state/keys/evidence-0.seed=evidence+replay" "$state/keys/evidence-1.seed=evidence+replay" "$state/keys/evidence-2.seed=evidence+replay" "$state/keys/action-0.seed=action"
"$bin/ivar-core" keyring "$state/policy-keyring.json" "$state/keys/policy-a.seed=policy" "$state/keys/policy-b.seed=policy"
pub() { "$bin/ivar-core" keyring /dev/stdout "$1=operator" | python3 -c 'import json,sys; print(list(json.load(sys.stdin)["keys"].values())[0][0]["bytes"])'; }
printf '{"alice":"%s","bob":"%s"}\n' "$(pub "$state/keys/operator-alice.seed")" "$(pub "$state/keys/operator-bob.seed")" > "$state/operators.json"
for app in $APPS; do "$bin/ivar-core" token sensor "$state/tokens/sensor-tokens.json" "$app" "shop-$app" > "$state/tokens/$app.token"; done
"$bin/ivar-core" token sensor "$state/tokens/sensor-tokens.json" edge "edge-*" > "$state/tokens/edge.token"
"$bin/ivar-core" token proxy "$state/tokens/proxy-token.sha256" > "$state/tokens/proxy.token"
cp "$root"/deploy/policy/*.yaml "$state/"
# The shop serves a few routes the sample API leaves out; declare them, so
# refusing undeclared routes in the enforce phase leaves the shop working.
cat >> "$state/openapi.yaml" <<'YAML'
  /payouts/intent:
    post:
      requestBody:
        content:
          application/json:
            schema: { type: object, properties: { amount: { type: number } } }
  /admin/users:
    get: {}
  /healthz:
    get: {}
YAML
# v1 observe (rollout phase 1) and v2 enforce, both signed by both policy keys.
sed 's/^version: .*/version: 1/; s/^policy_version: .*/policy_version: enterprise-1/' "$root/deploy/policy/policy.yaml" > "$state/policy.yaml"
(cd "$state" && PATH="$bin:$PATH" "$bin/ivar-control" validate --source policy.yaml --library "$root/replay-library" >/dev/null \
  && "$bin/ivar-control" build --source policy.yaml --keys keys/policy-a.seed,keys/policy-b.seed --out policy-v1.bundle >/dev/null \
  && sed 's/^version: .*/version: 2/; s/^policy_version: .*/policy_version: enterprise-2/; s/  detection_mode: observe/  detection_mode: enforce/; s/  refuse_undeclared_routes: false/  refuse_undeclared_routes: true/' policy.yaml > policy-v2.yaml \
  && "$bin/ivar-control" build --source policy-v2.yaml --keys keys/policy-a.seed,keys/policy-b.seed --out policy-v2.bundle >/dev/null)
cp "$state/policy-v1.bundle" "$state/policy.bundle"

echo "== core: three shards behind the load balancer"
echo '[8081, 8082, 8083]' > "$state/shards.json"
for n in 0 1 2; do
  mkdir -p "$state/shard$n"
  cat > "$state/shard$n.yaml" <<YAML
http_listen: 127.0.0.1:808$((n + 1))
grpc_listen: 127.0.0.1:748$((n + 1))
data_dir: $state/shard$n
policy_bundle: $state/policy.bundle
keyring: $state/keyring.json
evidence_key_seed_file: $state/keys/evidence-$n.seed
action_key_seed_file: $state/keys/action-0.seed
redaction_key_hex_file: $state/keys/redaction.hex
public_url: http://127.0.0.1:8080
expected_layers: [edge, app_sdk]
console_dir: $root/replay-viewer
sensor_tokens_file: $state/tokens/sensor-tokens.json
operator_proxy_token_file: $state/tokens/proxy-token.sha256
shard_peers: [http://127.0.0.1:8081, http://127.0.0.1:8082, http://127.0.0.1:8083]
YAML
  start "core$n" env IVAR_SHARD=$n IVAR_SHARDS=3 "$bin/ivar-core" serve --config "$state/shard$n.yaml"
done
for n in 0 1 2; do ready "http://127.0.0.1:808$((n + 1))/healthz" "core$n"; done
start control "$bin/ivar-control" serve --bundle "$state/policy.bundle" --tuf-keys "$state/tuf" --flags-key "$state/keys/flags-1.seed" \
  --operators "$state/operators.json" --cosign "$state/keys/cosign.pub" --listen 127.0.0.1:8090
ready http://127.0.0.1:8090/healthz control

echo "== applications, each installed from its package"
cp -r "$here/apps/." "$state/apps/"
( cd "$state/apps/node" && npm init -y >/dev/null && npm install -s "$art/ivar-express-$version.tgz" express@5.1.0 >/dev/null )
( cd "$state/apps/python" && python3 -m venv venv && venv/bin/pip install -q "$art"/ivar-"$version"-py3-none-any.whl fastapi==0.115.6 uvicorn==0.34.0 )
( cd "$state/apps/go" && go mod init shop.test >/dev/null 2>&1 && go mod edit -require "github.com/jhmeel/ivar/sdk/go@v$version" -replace "github.com/jhmeel/ivar/sdk/go=$root/sdk/go" && go mod tidy >/dev/null 2>&1 && go build -o shop . )
( cd "$state/apps/java" && mvn -q -B install:install-file -Dfile="$art/ivar-java-$version.jar" -DpomFile="$art/ivar-java-$version.pom" \
  && mvn -q -B -Divar.version="$version" compile dependency:build-classpath -Dmdep.outputFile=cp.txt )
# The package version does not change between local builds; drop the cached copy.
rm -rf "${NUGET_PACKAGES:-$HOME/.nuget/packages}/ivar.aspnetcore"
( cd "$state/apps/dotnet" && dotnet new nugetconfig >/dev/null && dotnet nuget add source "$art" --name ivar-release --configfile nuget.config >/dev/null \
  && dotnet publish -v q -c Release -o out -p:IvarVersion="$version" >/dev/null )
( cd "$state/apps/php" && cat > composer.json <<JSON
{
  "repositories": [{ "type": "package", "package": { "name": "ivar/ivar-php", "version": "$version",
    "dist": { "url": "$art/ivar-php-$version.zip", "type": "zip" },
    "require": { "php": ">=8.1", "ext-ffi": "*", "ext-json": "*" }, "autoload": { "psr-4": { "Ivar\\\\": "src/" } } } }],
  "require": { "ivar/ivar-php": "$version" }
}
JSON
  composer --no-cache install -q --no-interaction )
echo '[{"name":"node","port":3101,"gateway":10001},{"name":"python","port":3102,"gateway":10002},{"name":"go","port":3103,"gateway":10003},{"name":"java","port":3104,"gateway":10004},{"name":"dotnet","port":3105,"gateway":10005},{"name":"php","port":3106,"gateway":10006}]' > "$state/apps.json"
for app in $APPS; do start_app "$app"; done

echo "== Envoy: Coraza and the Core Rule Set, then IVAR, in front of every app"
python3 "$here/envoy.py" "$state" > "$state/envoy.yaml"
docker run -d --name ivar-enterprise-envoy --network host -v "$state:$state:ro" envoyproxy/envoy:v1.33.2 \
  envoy -c "$state/envoy.yaml" --log-level warning --component-log-level wasm:info >/dev/null
ready http://127.0.0.1:9901/ready envoy || docker logs ivar-enterprise-envoy 2>&1 | tail -20
for g in 10001 10002 10003 10004 10005 10006; do ready "http://127.0.0.1:$g/healthz" envoy; done
echo "enterprise estate up: gateways :10001 to :10006 | core load balancer :8080 over shards :8081 to :8083 | control :8090 | console http://127.0.0.1:8081/console/"
