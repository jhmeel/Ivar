# Plugins

Responder plugins (section 14). Each runs as a separate process with scoped
credentials: the plugin host clears the environment, passes only the secrets
the manifest names (as `IVAR_SECRET_<NAME>`), sets a memory limit, and
enforces the manifest timeout on every call. One JSON request per line on
stdin, one JSON reply per line on stdout.

All responders here are served by `ivar-connector respond <provider>` from
the Go connectors. `okta-responder/plugin.yaml` is the manifest from the
specification, unchanged.

| Plugin | Command | Actions |
|---|---|---|
| okta-responder | `ivar-connector respond okta --org https://<org>.okta.com` | session.revoke, user.suspend |
| entra-responder | `ivar-connector respond entra` | session.revoke, user.suspend, oauth_grant.revoke |
| workspace-responder | `ivar-connector respond workspace` | oauth_grant.revoke |
| salesforce-responder | `ivar-connector respond salesforce` | user.suspend, user.lock |
| github-responder | `ivar-connector respond github` | oauth_grant.revoke, api_key.suspend |
| aws-responder | `ivar-connector respond aws --isolation-group <sg>` | api_key.suspend, host.isolate |
| gcp-responder | `ivar-connector respond gcp` | api_key.suspend |
| azure-responder | `ivar-connector respond azure` | trust_edge.narrow |

Before activation every plugin passes the lifecycle: signature verified
(`scripts/sign-plugin.sh` signs with a cosign key), permissions checked
against the registry policy, shadow mode, canary, then active. A plugin that
crashes, exceeds its limits or requests undeclared access is disabled and
raises an alert; one whose verdicts drift returns to shadow mode.
