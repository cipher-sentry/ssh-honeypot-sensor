#!/usr/bin/env bash
# ──────────────────────────────────────────────────────
# Nombre:      node.sh
# Descripción: Gestión y orientación de un nodo honeypot. Elige el puerto solo
#              (22 si está libre, si no 2222), muestra estado, actividad y los
#              siguientes pasos (incluido el dashboard).
# Uso:         bash node.sh [comando]
# Comandos:
#   status   Estado + orientación (por defecto si no se pasa comando).
#   up       Arranca el honeypot. Puerto: HONEYPOT_PORT, o 22 si libre, o 2222.
#   enroll   Genera la identidad del nodo y muestra su código de enrolamiento.
#   down     Para el honeypot.
#   logs     Sigue los logs del contenedor en vivo.
#   test     Comprueba la conexión SSH al honeypot en su puerto real.
#   update   Descarga la última versión publicada (release) y reconstruye.
#   help     Esta ayuda.
# ──────────────────────────────────────────────────────
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

C_CY='\033[1;36m'; C_GR='\033[1;32m'; C_YE='\033[1;33m'; C_RE='\033[1;31m'
C_DIM='\033[0;90m'; C_BD='\033[1m'; C_NC='\033[0m'
LOG="$SCRIPT_DIR/logs/sessions.jsonl"
IDDIR="$SCRIPT_DIR/node_identity"
# Respaldo estable de la identidad, FUERA del directorio de instalación, para que el nodo
# conserve su DNI (node_id/código) aunque se reinstale en un directorio nuevo.
IDBACKUP="${CIPHERSENTRY_IDENTITY_HOME:-$HOME/.ciphersentry}/node_identity"
DC="docker compose"; [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null && DC="sudo docker compose"

# ── Identidad del nodo (Sprint 005 · Fase 0) ─────────────────────────────────
# Genera node_id (UUID) + par ed25519 propio (privada local, nunca viaja) +
# código de enrolamiento. Independiente del host_key. Idempotente.
_ensure_identity() {
  mkdir -p "$IDDIR"
  # Si este directorio es nuevo pero existe un respaldo estable de una instalación previa,
  # RESTAURA la identidad → el nodo conserva su mismo DNI tras reinstalar (no hay que
  # volver a enrolar ni se parte el histórico).
  if [ ! -f "$IDDIR/id" ] && [ -f "$IDBACKUP/id" ]; then
    cp -a "$IDBACKUP/." "$IDDIR/" 2>/dev/null && printf "  ${C_GR}✓${C_NC} Identidad anterior restaurada (mismo nodo).\n" || true
  fi
  # Llave secreta del nodo (auto-generada, NUNCA editada a mano). Idempotente; se crea
  # también para nodos que ya tenían identidad (al actualizar). Autentica al nodo (X-Node-Key).
  if [ ! -f "$IDDIR/node_key" ]; then
    (python3 -c "import secrets;print(secrets.token_urlsafe(24))" 2>/dev/null \
      || head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n') > "$IDDIR/node_key"
  fi
  if [ -f "$IDDIR/id" ]; then _fix_identity_perms; _backup_identity; return 0; fi
  local nid
  nid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null \
        || python3 -c 'import uuid;print(uuid.uuid4())' 2>/dev/null)
  printf '%s\n' "$nid" > "$IDDIR/id"
  ssh-keygen -q -t ed25519 -f "$IDDIR/key" -N "" -C "ciphersentry-node-$nid" 2>/dev/null
  local hx host
  hx=$(printf '%s' "$nid" | tr -d '-' | tr 'a-z' 'A-Z')
  host=$(hostname 2>/dev/null | tr 'a-z' 'A-Z' | tr -cd 'A-Z0-9' | cut -c1-8)
  printf '%s-%s-%s-%s\n' "${host:-NODE}" "${hx:0:4}" "${hx:4:4}" "${hx:8:4}" > "$IDDIR/enroll_code"
  _fix_identity_perms
  _backup_identity
}

# Copia la identidad al respaldo estable (fuera del dir de instalación). Idempotente.
_backup_identity() {
  [ -f "$IDDIR/id" ] || return 0
  mkdir -p "$IDBACKUP" 2>/dev/null || return 0
  cp -a "$IDDIR/." "$IDBACKUP/" 2>/dev/null || true
  chmod 700 "$(dirname "$IDBACKUP")" "$IDBACKUP" 2>/dev/null || true
}

# El contenedor corre como usuario NO-root (honeypot) y monta node_identity en :ro.
# El `id`/código NO son secretos (el id se deriva del código que el usuario comparte);
# deben ser legibles para que el sensor cargue su node_id. La clave privada sigue 600.
_fix_identity_perms() {
  chmod 755 "$IDDIR" 2>/dev/null
  # node_key 644 (no 600): el contenedor corre como usuario no-root y debe leerla;
  # protegida al nivel del host (acceso local al nodo = control del nodo).
  chmod 644 "$IDDIR/id" "$IDDIR/enroll_code" "$IDDIR/key.pub" "$IDDIR/node_key" 2>/dev/null
  chmod 600 "$IDDIR/key" 2>/dev/null
}
_node_id()     { [ -f "$IDDIR/id" ] && cat "$IDDIR/id"; }
_enroll_code() { [ -f "$IDDIR/enroll_code" ] && cat "$IDDIR/enroll_code"; }

# ── Versión de la sonda (fuente única: fichero VERSION del bundle) ───────────
REPO_SLUG="cipher-sentry/ssh-honeypot-sensor"
_version()  { [ -f "$SCRIPT_DIR/VERSION" ] && sed -n '1p' "$SCRIPT_DIR/VERSION" | tr -d ' \r' || echo "0.0.0"; }
_codename() { [ -f "$SCRIPT_DIR/VERSION" ] && sed -n '2p' "$SCRIPT_DIR/VERSION" | tr -d '\r' | sed 's/^ *//;s/ *$//'; }
# Último tag publicado en GitHub (vacío si no hay red). Acota a 5s para no colgar status.
_latest_release() {
  curl -s -m 5 "https://api.github.com/repos/$REPO_SLUG/releases/latest" 2>/dev/null \
    | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 \
    | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'
}

_running()     { $DC ps --format '{{.State}}' 2>/dev/null | grep -q running; }
_mapped_port() { $DC ps --format '{{.Ports}}' 2>/dev/null | grep -oE '(0\.0\.0\.0|\*):[0-9]+->2222' | grep -oE ':[0-9]+' | tr -d ':' | head -1; }
_local_ip()    { hostname -I 2>/dev/null | awk '{print $1}'; }
_sessions()    { [ -f "$LOG" ] && grep -c '"event": *"connection"' "$LOG" 2>/dev/null || echo 0; }

# ¿Hay algo escuchando ya en este puerto TCP del host?
_port_in_use() { ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }

# URL efectiva de la Shell API (env SHELL_API_URL, o config.yaml).
_api_url() {
  local u="${SHELL_API_URL:-}"
  [ -z "$u" ] && u=$(grep -E '^[[:space:]]*shell_api_url:' config.yaml 2>/dev/null \
    | sed -E 's/^[^:]*:[[:space:]]*"?([^"#[:space:]]+).*/\1/' | head -1)
  echo "$u"
}
# ¿Responde la Shell API? echo ok|fail|unknown
_api_check() {
  local u; u="$(_api_url)"; [ -z "$u" ] && { echo unknown; return; }
  local hu="${u/host.docker.internal/localhost}"
  curl -s -m 3 "$hu/v1/health" 2>/dev/null | grep -q session && echo ok || echo fail
}
# URL del dashboard central. Prioridad: DASHBOARD_URL env → dashboard_url en config.yaml
# → derivación del api_url (legacy, solo funciona con IP:puerto).
_dashboard_url() {
  local d="${DASHBOARD_URL:-}"
  [ -z "$d" ] && d=$(grep -E '^[[:space:]]*dashboard_url:' config.yaml 2>/dev/null \
    | sed -E 's/^[^:]*:[[:space:]]*"?([^"#[:space:]]+).*/\1/' | head -1)
  [ -n "$d" ] && { echo "$d"; return; }
  # Fallback si no hay dashboard_url: del shell_api_url. Modelo por dominios
  # (api.dominio → app.dominio) o legacy IP:puerto (→ :8080).
  local u; u="$(_api_url)"; [ -z "$u" ] && return
  if echo "$u" | grep -qE '://api\.'; then
    echo "$u" | sed -E 's#://api\.#://app.#'
  else
    echo "$u" | sed -E 's#(://[^:/]+):[0-9]+.*#\1:8080#'
  fi
}
# ¿Está configurada la SHELL_API_KEY? Prioridad: env → config.yaml → ok | unset
_key_check() {
  local k="${SHELL_API_KEY:-}"
  [ -z "$k" ] && k=$(grep -E '^[[:space:]]*shell_api_key:' config.yaml 2>/dev/null \
    | sed -E 's/^[^:]*:[[:space:]]*"?([^"#[:space:]]+).*/\1/' | head -1)
  [ -n "$k" ] && [ "$k" != "free-demo" ] && echo ok || echo unset
}

# ¿Está este nodo ENROLADO? (vinculación real por node_id, no por API key). Pregunta
# al panel. Devuelve: yes | no | unknown (sin red/panel). Acota a 5s.
_enroll_check() {
  local du code r; du="$(_dashboard_url)"; code="$(_enroll_code)"
  [ -z "$du" ] || [ -z "$code" ] && { echo unknown; return; }
  r=$(curl -s -m 5 "$du/api/public/node-enrolled?code=$code" 2>/dev/null)
  if echo "$r" | grep -q '"enrolled"[[:space:]]*:[[:space:]]*true'; then echo yes
  elif echo "$r" | grep -q '"enrolled"'; then echo no
  else echo unknown; fi
}

# Puerto a usar al ARRANCAR: HONEYPOT_PORT si se fija; si nuestro honeypot ya está
# en 22 se mantiene; si no, 22 si está libre, o 2222 si lo ocupa otro servicio.
_pick_port() {
  if [ -n "${HONEYPOT_PORT:-}" ]; then echo "${HONEYPOT_PORT}"; return; fi
  if _running && [ "$(_mapped_port)" = "22" ]; then echo 22; return; fi
  if _port_in_use 22; then echo 2222; else echo 22; fi
}

# Puerto REAL: el mapeado si corre; si no, el que se usaría al arrancar.
_effective_port() { if _running; then _mapped_port; else _pick_port; fi; }

cmd_status() {
  local ip eport p; ip="$(_local_ip)"; [ -z "$ip" ] && ip="<ip-del-nodo>"
  eport="$(_effective_port)"; [ -z "$eport" ] && eport=22
  printf "${C_CY}╔══════════════════════════════════════════════════╗${C_NC}\n"
  printf "${C_CY}║   CipherSentry · Nodo Honeypot                    ║${C_NC}\n"
  printf "${C_CY}╚══════════════════════════════════════════════════╝${C_NC}\n\n"

  # Versión + codename + chequeo de actualización (sirve para saber si el nodo
  # corre la versión esperada).
  local ver cod latest; ver="$(_version)"; cod="$(_codename)"; latest="$(_latest_release)"
  if [ -n "$latest" ] && [ "$latest" != "$ver" ]; then
    printf "  Versión:  ${C_BD}v%s${C_NC} «%s»   ${C_YE}⚠ hay v%s${C_NC} ${C_DIM}→ bash node.sh update${C_NC}\n" "$ver" "$cod" "$latest"
  elif [ -n "$latest" ]; then
    printf "  Versión:  ${C_BD}v%s${C_NC} «%s»   ${C_GR}✓ al día${C_NC}\n" "$ver" "$cod"
  else
    printf "  Versión:  ${C_BD}v%s${C_NC} «%s»\n" "$ver" "$cod"
  fi

  if _running; then
    printf "  Estado:   ${C_GR}● corriendo${C_NC}  ·  puerto ${C_BD}%s${C_NC}\n" "$eport"
  else
    printf "  Estado:   ${C_RE}○ parado${C_NC}   ·  arráncalo con  ${C_BD}bash node.sh up${C_NC}\n"
  fi
  printf "  Sesiones capturadas: ${C_BD}%s${C_NC}\n" "$(_sessions)"
  printf "  Logs:     ${C_DIM}%s${C_NC}\n" "$LOG"

  # Shell API — sin ella el honeypot acepta el login pero cierra la sesión.
  local api url; api="$(_api_check)"; url="$(_api_url)"
  case "$api" in
    ok)   printf "  Shell API: ${C_GR}● alcanzable${C_NC}  ${C_DIM}%s${C_NC}\n" "$url" ;;
    fail) printf "  Shell API: ${C_RE}○ NO alcanzable${C_NC}  ${C_DIM}%s${C_NC}\n" "${url:-(sin configurar)}"
          printf "             ${C_YE}↳ El honeypot acepta el login pero cierra la sesión.${C_NC}\n"
          printf "             ${C_DIM}Revisa shell_api_url en config.yaml.${C_NC}\n" ;;
    *)    printf "  Shell API: ${C_YE}? sin determinar${C_NC}\n" ;;
  esac
  # URL con IP directa — inestable si la infra cambia
  if echo "$url" | grep -qE '://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'; then
    printf "  ${C_YE}!${C_NC} shell_api_url apunta a una IP directa — puede dejar de funcionar si cambia la infra.\n"
    printf "     ${C_DIM}Usa el dominio estable en config.yaml:  shell_api_url: \"https://api.ciphersentry.yoire.com\"${C_NC}\n"
  fi
  # Atribución El Enjambre — vinculación REAL por node_id (preguntada al panel),
  # no por la API key (que es solo transporte compartido).
  local enr; enr="$(_enroll_check)"
  if [ "$enr" = "yes" ]; then
    printf "  Enjambre:  ${C_GR}● vinculado${C_NC}  ${C_DIM}(nodo enrolado a tu cuenta)${C_NC}\n"
  elif [ "$enr" = "no" ]; then
    local _ec; _ec="$(_enroll_code)"
    local _he; _he=$(hostname 2>/dev/null | tr 'a-z' 'A-Z' | tr -cd 'A-Z0-9' | cut -c1-16)
    local _du; _du="$(_dashboard_url)"
    printf "  Enjambre:  ${C_YE}⚠ nodo no vinculado${C_NC}\n"
    if [ -n "$_ec" ] && [ -n "$_du" ]; then
      printf "             ${C_DIM}Abre en tu navegador:${C_NC}\n"
      printf "             ${C_CY}%s/enroll.html?code=%s&name=%s${C_NC}\n" \
        "$_du" "$_ec" "${_he:-node}"
    fi
    printf "             ${C_DIM}(no necesitas API key: la vinculación es por node_id)${C_NC}\n"
  else
    printf "  Enjambre:  ${C_DIM}? vinculación no comprobable (sin acceso al panel)${C_NC}\n"
  fi

  printf "\n${C_BD}¿Qué hacer ahora?${C_NC}\n"
  printf "  ${C_CY}•${C_NC} Ver la actividad en vivo:   ${C_BD}bash node.sh logs${C_NC}\n"
  printf "  ${C_CY}•${C_NC} Probarlo tú mismo:           ${C_BD}ssh test@%s -p %s${C_NC}  ${C_DIM}(cualquier contraseña)${C_NC}\n" "$ip" "$eport"
  printf "  ${C_CY}•${C_NC} Comprobación rápida local:   ${C_BD}bash node.sh test${C_NC}\n"
  printf "  ${C_CY}•${C_NC} Parar / arrancar:            ${C_BD}bash node.sh down${C_NC} | ${C_BD}up${C_NC}\n"

  local durl; durl="$(_dashboard_url)"
  printf "\n${C_BD}Dashboard${C_NC} ${C_DIM}(panel web de monitorización)${C_NC}\n"
  if [ -n "$durl" ]; then
    printf "  Panel central:  ${C_BD}%s${C_NC}  ${C_DIM}(entra con tu token)${C_NC}\n" "$durl/login.html"
  fi
  printf "  Actividad de ${C_BD}ESTE${C_NC} nodo, aquí mismo:  ${C_BD}bash node.sh logs${C_NC}\n"
  printf "  ${C_DIM}El Enjambre muestra la actividad de este nodo (sesiones, IPs, comandos/mes).${C_NC}\n\n"
}

cmd_up() {
  local port; port="$(_pick_port)"
  if [ -n "${HONEYPOT_PORT:-}" ]; then
    printf "  ${C_CY}▸${C_NC} Puerto fijado por HONEYPOT_PORT: ${C_BD}%s${C_NC}\n" "$port"
  elif [ "$port" = "2222" ]; then
    printf "\n  \033[1;30;43m  ⚠  PUERTO 22 OCUPADO — EL HONEYPOT USARÁ EL 2222  \033[0m\n\n"
    printf "  ${C_YE}${C_BD}Importante:${C_NC} los atacantes escanean sobre todo el ${C_BD}22${C_NC}; en 2222 capturarás ${C_BD}menos${C_NC}.\n"
    printf "  ${C_DIM}Para usar el 22: libera el puerto (mueve tu SSH de admin a otro) y reinicia, o ${C_BD}HONEYPOT_PORT=22 bash node.sh up${C_NC}${C_DIM}.${C_NC}\n"
  else
    printf "  ${C_GR}✓${C_NC} Puerto 22 libre → el honeypot escuchará en ${C_BD}22${C_NC}.\n"
  fi
  HONEYPOT_PORT="$port" $DC up -d --build && echo && cmd_status
}

cmd_update() {
  local url="https://github.com/$REPO_SLUG/releases/latest/download/sensor.tar.gz"
  printf "  ${C_CY}▸${C_NC} Versión actual: ${C_BD}v%s${C_NC} «%s». Descargando la última…\n" "$(_version)" "$(_codename)"
  local tmp; tmp="$(mktemp -d)" || return 1
  if ! curl -fsSL -m 60 "$url" -o "$tmp/sensor.tar.gz"; then
    printf "  ${C_RE}✗${C_NC} No se pudo descargar %s\n" "$url"; rm -rf "$tmp"; return 1
  fi
  if ! tar -xzf "$tmp/sensor.tar.gz" -C "$tmp" 2>/dev/null; then
    printf "  ${C_RE}✗${C_NC} El paquete descargado está corrupto.\n"; rm -rf "$tmp"; return 1
  fi
  # Los ficheros vienen bajo el prefijo 'sensor/'. Sustituimos solo el CÓDIGO;
  # NO se tocan config.yaml (tu key/URL), node_identity/ ni logs/.
  # Usamos `mv` (no `cp`): reemplaza el inode, así el bash que está EJECUTANDO este
  # mismo node.sh sigue leyendo el inode viejo intacto y no se corrompe a media ejecución.
  local src="$tmp/sensor"; [ -d "$src" ] || src="$tmp"
  local f
  for f in VERSION api_client.py config.py honeypot.py logger.py ssh_server.py \
           sftp_server.py node.sh entrypoint.sh Dockerfile docker-compose.yml requirements.txt; do
    [ -f "$src/$f" ] && mv -f "$src/$f" "$SCRIPT_DIR/$f"
  done
  chmod +x "$SCRIPT_DIR/node.sh" "$SCRIPT_DIR/entrypoint.sh" 2>/dev/null
  rm -rf "$tmp"
  printf "  ${C_GR}✓${C_NC} Actualizado a ${C_BD}v%s${C_NC} «%s». Reconstruyendo el contenedor…\n" "$(_version)" "$(_codename)"
  cmd_up
  printf "\n  ${C_YE}▸${C_NC} ${C_DIM}El estado de arriba lo dibuja la versión ANTERIOR (aún en memoria).${C_NC}\n"
  printf "    ${C_DIM}Vuelve a ejecutar ${C_BD}bash node.sh${C_NC}${C_DIM} para verlo con la versión nueva.${C_NC}\n"
}

cmd_enroll() {
  _ensure_identity
  local durl; durl="$(_dashboard_url)"
  local code; code="$(_enroll_code)"
  local host_enc; host_enc=$(hostname 2>/dev/null | tr 'a-z' 'A-Z' | tr -cd 'A-Z0-9' | cut -c1-16)
  printf "${C_CY}╔══════════════════════════════════════════════════╗${C_NC}\n"
  printf "${C_CY}║   Conectar este honeypot a tu cuenta              ║${C_NC}\n"
  printf "${C_CY}╚══════════════════════════════════════════════════╝${C_NC}\n\n"
  printf "  Abre este enlace en tu navegador:\n\n"
  if [ -n "$durl" ] && [ -n "$code" ]; then
    printf "  ${C_CY}${C_BD}%s/enroll.html?code=%s&name=%s${C_NC}\n\n" \
      "$durl" "$code" "${host_enc:-node}"
  fi
  printf "  ${C_DIM}Entra o crea cuenta → el nodo se conecta solo.${C_NC}\n\n"
  printf "  Una vez vinculado, copia tu ${C_BD}API key${C_NC} ${C_DIM}(Mi cuenta → API key)${C_NC}\n"
  printf "  y ponla en ${C_BD}config.yaml${C_NC}:\n"
  printf "       ${C_BD}shell_api_key: \"<tu-key>\"${C_NC}\n"
  printf "       ${C_BD}bash node.sh down && bash node.sh up${C_NC}\n\n"
  printf "  ${C_DIM}La clave privada del nodo se queda aquí, nunca viaja.${C_NC}\n\n"
}

case "${1:-status}" in
  status) cmd_status ;;
  up)     cmd_up ;;
  update) cmd_update ;;
  enroll) cmd_enroll ;;
  down)   $DC down ;;
  logs)   $DC logs -f ;;
  test)
    port="$(_effective_port)"; [ -z "$port" ] && port=22
    echo "Probando ssh test@127.0.0.1 -p $port …"
    # Clave desechable (el honeypot acepta cualquier pubkey) + SHELL interactiva:
    # las sesiones shell nunca se bloquean (los EXEC sí, durante la ventana de captura).
    K="$(mktemp -u)"; ssh-keygen -q -t ed25519 -f "$K" -N "" 2>/dev/null
    out=$(printf 'id\nexit\n' | ssh -tt -i "$K" -o IdentitiesOnly=yes \
        -o PreferredAuthentications=publickey -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 \
        -p "$port" test@127.0.0.1 2>&1)
    rm -f "$K" "$K.pub"
    echo "$out" | grep -vE "Warning: Permanently|Connection to .* closed" | head -8
    if echo "$out" | grep -q "uid="; then
      printf "${C_GR}✓ El honeypot sirve sesiones correctamente.${C_NC}\n"
    else
      printf "${C_YE}! Conecta pero la sesión no responde → revisa la Shell API (bash node.sh status).${C_NC}\n"
    fi ;;
  help|-h|--help)
    sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' ;;
  *)
    echo "Uso: bash node.sh [status|up|enroll|down|logs|test|help]"; exit 1 ;;
esac
