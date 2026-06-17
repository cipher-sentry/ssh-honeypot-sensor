# CipherSentry SSH Honeypot

Honeypot SSH ligero de código abierto. Acepta conexiones de atacantes, captura credenciales y metadatos, y delega toda la emulación de comandos en el **CipherSentry Shell API** — el cerebro privado del sistema.

> Este proyecto es el cliente público (MIT). El engine de emulación (70+ comandos, VFS Debian 12, pipelines, REPLs) no está incluido — vive en la Shell API.

---

## Arquitectura

```
Atacante
  │  SSH (puerto 2222)
  ▼
ssh-honeypot-sensor      ← este proyecto (código abierto)
  · acepta conexión SSH
  · captura: IP, usuario, contraseña, cliente SSH
  · reenvía cada comando a la Shell API
  · devuelve la respuesta al atacante
  · registra todo en logs/sessions.jsonl
        │
        │  HTTP  (X-API-Key)
        ▼
CipherSentry Shell API   ← privado, no incluido
  · engine de emulación completo
  · VFS Debian 12 aislado por sesión
  · 70+ comandos simulados
```

---

## Despliegue de un nodo nuevo

Instalación en una línea — instala Docker si falta, descarga el sensor y lo arranca:

```bash
curl -fsSL https://ciphersentry.yoire.com/install.sh | bash
```

Para vincular el nodo a tu cuenta desde el inicio, pásale tu key:

```bash
curl -fsSL https://ciphersentry.yoire.com/install.sh | bash -s -- --key <tu-key>
```

Tras instalar, gestiona el nodo con `node.sh` (desde el directorio de instalación):

```bash
bash node.sh up      # arranca (elige puerto: 22 si libre, si no 2222)
bash node.sh         # estado, actividad y orientación
```

**Funciona desde el minuto cero:** el cliente viene con la Shell API central de
CipherSentry preconfigurada, así que un nodo recién instalado ya emula comandos.

**Vincular el nodo a tu cuenta (atribución):** la identidad del nodo es su `node_id`
(se genera local; su clave privada nunca viaja). Para que tus capturas cuenten en tu
cuenta y tu plan:

```bash
bash node.sh enroll          # imprime tu código (p. ej. NODO-A1B2-C3D4-E5F6)
# → entra/crea cuenta en el dashboard → El Enjambre → Añadir nodo → pega el código
```

A partir de ahí el engine atribuye por `node_id`. **No tienes que configurar ninguna
API key por cuenta**: el acceso a la Shell API usa una key de transporte compartida
(`SHELL_API_KEY`, por defecto `free-demo`) que **no** es tu credencial ni fija tu tier.

---

## Configuración

### config.yaml

El nodo viene **preconfigurado** y funciona desde el minuto cero sin tocar nada. El único campo que puede interesar cambiar es `shell_api_key` si quieres vincular las sesiones a tu cuenta.

```yaml
# CipherSentry Honeypot Client — configuración
host: "0.0.0.0"
port: 2222
host_key_file: "host_key"
ssh_banner: "Debian GNU/Linux 12"
ssh_version: "OpenSSH_8.4p1 Debian-5+deb11u1"
accept_any_password: true
fake_hostname: "web-srv-01"
log_dir: "logs"
verbose: false

# Ventana de captura de credenciales: durante [start_minute, end_minute) de cada
# hora se bloquean los EXEC (comandos sueltos) para registrar credencial + comando
# sin servirlos. Las sesiones SHELL interactivas se permiten SIEMPRE (son el oro).
credential_capture:
  enabled: true
  start_minute: 45   # de xx:45
  end_minute: 60     # a xx:00 (60 = en punto)

# Shell API central — preconfigurada, el nodo funciona desde el minuto cero.
# Sobrescribible con SHELL_API_URL (env o .env).
shell_api_url: "https://api.ciphersentry.yoire.com"

# URL del panel web (opcional). Si no se indica, node.sh la deriva del api_url.
# dashboard_url: "https://app.ciphersentry.yoire.com"

# Tu API key de El Enjambre. Cámbiala por la tuya para que las sesiones aparezcan
# en tu cuenta. Encuéntrala en: El Enjambre → Mi cuenta → API key.
# Sin cambiarla las sesiones se capturan igualmente pero en modo anónimo.
shell_api_key: "free-demo"
```

### Ventana de captura de credenciales

Durante `[start_minute, end_minute)` de cada hora, el honeypot **bloquea los
comandos no interactivos (EXEC, `ssh host "cmd"`)**: registra la credencial y el
comando intentado en un evento `exec_blocked`, pero **no** lo ejecuta. Esto fuerza
a los bots a seguir probando credenciales. Las **sesiones SHELL interactivas se
permiten siempre a la primera** — son las más valiosas y nunca se bloquean.
Fuera de la ventana, los EXEC se ejecutan con normalidad.

### Variables de entorno

| Variable | Descripción | Default |
|----------|-------------|---------|
| `HONEYPOT_PORT` | Puerto SSH | `2222` |
| `SHELL_API_URL` | URL de la Shell API | `https://api.ciphersentry.yoire.com` |
| `SHELL_API_KEY` | API key para la Shell API | `free-demo` |
| `NODE_ID` | Identidad del nodo (granularidad por nodo en El Enjambre) | `node_identity/id` |
| `HONEYPOT_VERBOSE` | Log detallado (`1`/`0`) | `0` |

Las variables de entorno tienen prioridad sobre `config.yaml`.

**`NODE_ID`** — identidad del nodo que se envía a la Shell API en cada sesión para que
la actividad se contabilice **por nodo** (no solo por cuenta). Si no se define, se lee
automáticamente de `node_identity/id` (generado por `node.sh`). Con Docker, monta
`./node_identity` (ya incluido en `docker-compose.yml`) o pasa `NODE_ID` por `.env`.

---

## Shell API

Este honeypot requiere una instancia de **CipherSentry Shell API** para funcionar. Sin ella, no puede emular comandos.

- Tier **Free** (10.000 comandos/mes): gratuito
- Tiers de pago para despliegues con tráfico real

Más información: [ciphersentry.yoire.com](https://ciphersentry.yoire.com/)

---

## Logs

Cada evento se registra en `logs/sessions.jsonl` en formato JSON Lines, compatible con el dashboard de CipherSentry. Si el nodo tiene `node_id`, **todos** los eventos lo llevan (incluidos los previos a la sesión como `probe` y `connection`), para que el panel pueda atribuir toda la actividad al nodo.

Tipos de evento: `connection`, `credential_probe`, `probe`, `exec_blocked`, `channel_fingerprint`, `disconnect`, `privilege_escalation`, y los eventos SFTP: `sftp_session`, `sftp_upload`, `sftp_download`, `sftp_list`, `sftp_delete`.

---

## SFTP

El honeypot implementa el subsistema **SFTP/SCP**, así que clientes en modo
"Files" (p. ej. Termius) pueden conectar y navegar sin error. Cada sesión SFTP
opera en un **sandbox temporal aislado** (chroot) sembrado con un árbol Debian 12
creíble; nada toca el filesystem real del host ni otras sesiones.

**Captura de uploads a prueba de borrado.** Cuando un atacante sube un fichero, sus
bytes se copian **en el momento de la escritura** a una cuarentena separada del
sandbox:

```
logs/sftp_uploads/<session_id>/<timestamp>_<uniq>_<nombre>
```

- El fichero capturado **se conserva aunque el atacante lo borre o renombre**
  después (un dropper que se ejecuta y se autoelimina queda igualmente guardado).
- Se conserva **cada versión** subida, no solo la última.
- Cada upload registra un evento `sftp_upload` con `path`, `size`, `sha256` y la
  ruta de cuarentena. Los borrados quedan como `sftp_delete` (evidencia de tapado
  de huellas).
- **Nada de lo subido se ejecuta jamás** — se almacena como dato inerte.

La cuarentena vive bajo `logs/` (no se sube a git; no se expone por SFTP).

---

## Compatibilidad con clientes SSH

Probado con OpenSSH y con clientes móviles. La compatibilidad con **Termius (Android, libssh2)**
requirió varios ajustes en el manejo de asyncssh. Puntos clave:

- `keyboard-interactive` deshabilitado (asyncssh lo anuncia por defecto sin handler).
- `ssh_version` sin prefijo `SSH-2.0-` (asyncssh ya lo añade).
- Los *window-change* del cliente se entregan como excepción `TerminalSizeChanged` en stdin
  y deben ignorarse, no tratarse como fin de sesión.

---

## Licencia

MIT — © CipherSentry S.L.
