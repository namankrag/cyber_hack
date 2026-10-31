#!/bin/sh
# AgentShield container entrypoint.
#
# Trust/provenance (the "can't fake trust" demo, HMAC-signed single-use tokens)
# requires AGENTSHIELD_HARNESS_SECRET. If the operator did not set one, generate
# an ephemeral per-process secret so the full demo works out of the box. Set it
# explicitly (env / render.yaml / compose) for tokens that persist across
# restarts and are shared across replicas.
set -e

if [ -z "${AGENTSHIELD_HARNESS_SECRET}" ]; then
  AGENTSHIELD_HARNESS_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
  export AGENTSHIELD_HARNESS_SECRET
  echo "[entrypoint] AGENTSHIELD_HARNESS_SECRET was not set; generated an ephemeral one for this process so provenance tokens / the trust demo work. Set it explicitly for persistence across restarts and replicas." >&2
fi

exec uvicorn agentshield.gateway.app:app \
  --host "${AGENTSHIELD_BIND_HOST:-0.0.0.0}" \
  --port "${PORT:-8000}"
