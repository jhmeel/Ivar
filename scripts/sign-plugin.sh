#!/usr/bin/env bash
# Sign a plugin with Sigstore cosign in key mode.
# Usage: scripts/sign-plugin.sh manifest.yaml plugin.wasm cosign.key > plugin.sig
# The signed payload binds the manifest and the artifact by digest, exactly as
# ivar_plugin_host::signature::signing_payload builds it.
set -euo pipefail
manifest="$1"; artifact="$2"; key="$3"
payload="$(mktemp)"
{
  printf 'ivar.plugin.v1\n'
  printf 'manifest sha256:%s\n' "$(sha256sum "$manifest" | cut -d' ' -f1)"
  printf 'artifact sha256:%s\n' "$(sha256sum "$artifact" | cut -d' ' -f1)"
} > "$payload"
cosign sign-blob --yes --key "$key" --output-signature /dev/stdout "$payload"
rm -f "$payload"
