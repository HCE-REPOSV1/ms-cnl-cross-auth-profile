#!/bin/sh
set -e

if [ -n "${VAULT_TOKEN:-}" ] && [ -n "${VAULT_SECRET_PATH:-}" ]; then
  echo "[vault] Cargando secretos desde ${VAULT_SECRET_PATH}..."

  VAULT_URL="${VAULT_ADDR:-http://localhost:8200}"
  CLEAN_PATH="${VAULT_SECRET_PATH#secret/data/}"

  VAULT_JSON=$(wget -qO- \
    --header "X-Vault-Token: ${VAULT_TOKEN}" \
    "${VAULT_URL}/v1/secret/data/${CLEAN_PATH}") || {
    echo "[vault] ERROR: No se pudo conectar a Vault en ${VAULT_URL}"
    exit 1
  }

  eval "$(echo "$VAULT_JSON" | node -e "
    const d = [];
    process.stdin.on('data', c => d.push(c));
    process.stdin.on('end', () => {
      const secrets = JSON.parse(d.join('')).data.data;
      Object.entries(secrets).forEach(([k, v]) => {
        process.stdout.write('export ' + k + '=' + JSON.stringify(String(v)) + '\n');
      });
    });
  ")"

  echo "[vault] Secretos cargados correctamente"
fi

exec node dist/main
