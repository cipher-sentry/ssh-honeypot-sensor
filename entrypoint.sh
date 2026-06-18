#!/bin/sh
chown -R honeypot:honeypot /app/logs 2>/dev/null || true
# La host_key montada desde el host puede venir con permisos que el usuario
# 'honeypot' no puede leer (p. ej. 600 root si la generó install.sh como root).
# La ajustamos antes de bajar privilegios para evitar PermissionError.
if [ -f /app/host_key ]; then
  chown honeypot:honeypot /app/host_key 2>/dev/null || chmod 0644 /app/host_key 2>/dev/null || true
fi
# node_identity puede venir montada :ro en 700 root (la crea node.sh). El usuario
# 'honeypot' no la lee, pero el entrypoint (root) sí: cargamos el node_id y lo pasamos
# por env, para que el sensor se atribuya a su cuenta sin tocar permisos en el host.
NODE_ID="${NODE_ID:-}"
if [ -z "$NODE_ID" ] && [ -f /app/node_identity/id ]; then
  NODE_ID=$(cat /app/node_identity/id 2>/dev/null | tr -d '[:space:]')
fi
# Llave del nodo (node_key): autentica al nodo (cabecera X-Node-Key). AUTO-PROVISIÓN:
# si falta, la genera root aquí (node_identity va rw) y la persiste; así cualquier nodo
# queda protegido en su primer arranque sin que el usuario toque nada. La pasamos por env
# porque el usuario 'honeypot' no puede leer node_identity/.
if [ ! -f /app/node_identity/node_key ]; then
  mkdir -p /app/node_identity 2>/dev/null || true
  python3 -c "import secrets;print(secrets.token_urlsafe(24))" > /app/node_identity/node_key 2>/dev/null
  chmod 600 /app/node_identity/node_key 2>/dev/null || true
fi
NODE_KEY="${NODE_KEY:-}"
if [ -z "$NODE_KEY" ] && [ -f /app/node_identity/node_key ]; then
  NODE_KEY=$(cat /app/node_identity/node_key 2>/dev/null | tr -d '[:space:]')
fi
exec su honeypot -s /bin/sh -c "NODE_ID='$NODE_ID' NODE_KEY='$NODE_KEY' exec python3 honeypot.py"
