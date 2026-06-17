# CipherSentry SSH Honeypot

Honeypot SSH ligero de código abierto. Acepta conexiones de atacantes, captura credenciales y metadatos, y delega toda la emulación de comandos en el **CipherSentry Shell API** — el cerebro privado del sistema.

> Este proyecto es el cliente público (MIT). El engine de emulación (70+ comandos, VFS Debian 12, pipelines, REPLs) no está incluido — vive en la Shell API.

---

## Arquitectura

```
Atacante
  │  SSH (puerto 2222)
  ▼
ssh-honeypot-public      ← este proyecto (código abierto)
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

Este es un repositorio independiente, así que basta clonarlo:

```bash
git clone https://TU_TOKEN@github.com/m4ndingo/ssh-honeypot-public.git
cd ssh-honeypot-public
bash install.sh --docker -y          # instala Docker + construye imagen (o: bash install.sh → venv)
bash node.sh up                      # arranca (elige puerto: 22 si libre, si no 2222)
bash node.sh                         # estado, actividad y orientación
```

> `TU_TOKEN` es un PAT de GitHub con lectura del repo (privado).

**Funciona desde el minuto cero:** el cliente viene con la Shell API central de
CipherSentry preconfigurada, así que un nodo recién clonado ya emula comandos.

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

El cliente es ligero: delega *toda* la emulación en la Shell API. Para apuntar a
**otra** Shell API (la tuya propia), crea un `.env` en este directorio — el
`docker-compose` lo usa por encima de `config.yaml`:

```bash
cat > .env <<EOF
SHELL_API_URL=http://IP_DE_TU_SHELL_API:8090
EOF
```

`bash node.sh status` te dice si la Shell API es alcanzable. Debe serlo por red desde
el nodo (idealmente VPN/TLS).

`bash node.sh` muestra si el honeypot está corriendo, su puerto, las sesiones
capturadas, si la **Shell API es alcanzable**, cómo probarlo y cómo verlo en el
dashboard. Comandos: `node.sh status | up | down | logs | test | help`.

---

## Instalación

Requiere **Python 3.9+**.

```bash
git clone <repo>
cd ssh-honeypot-public
```

### Opción recomendada: script de instalación

`install.sh` automatiza todo el proceso: crea el entorno virtual, sortea el
bloqueo PEP 668 (*externally-managed*), instala las dependencias y genera la
host key si falta.

```bash
bash install.sh            # crea .venv/ e instala dependencias
bash install.sh -y         # además instala python3-venv vía apt si falta
bash install.sh --system   # instalación global (--break-system-packages, sin venv)
bash install.sh --help     # todas las opciones
```

Si falta el paquete `python3-venv` (error `ensurepip is not available`), el script
muestra el comando exacto a ejecutar; o instálalo automáticamente relanzando con `-y`.

Al terminar, arranca con el Python del entorno virtual:

```bash
.venv/bin/python honeypot.py --port 2222 --verbose
```

### Alternativa: pasos manuales (venv)

En distribuciones modernas (Debian 12+, Ubuntu 23.04+) Python está marcado como
*externally-managed* (PEP 668) y un `pip install` directo falla con el error
`externally-managed-environment`. La forma limpia de instalar las dependencias es
con un entorno virtual:

```bash
# El paquete python3-venv puede no estar instalado. Si lo está, omite esta línea.
# El error típico es: "ensurepip is not available ... apt install python3.13-venv"
sudo apt install python3-venv          # o python3.13-venv según tu versión

python3 -m venv .venv                  # crea el entorno en .venv/
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

Para usarlo, activa el entorno (o invoca el binario del venv directamente):

```bash
source .venv/bin/activate              # luego: python honeypot.py
# o sin activar:
.venv/bin/python honeypot.py
```

### Alternativa: instalación global

Si prefieres instalar a nivel de sistema (no recomendado, puede interferir con
paquetes gestionados por la distribución):

```bash
pip install -r requirements.txt --break-system-packages
```

> **Nota:** los comandos de la sección _Uso_ usan `python3` asumiendo que el
> entorno virtual está activado. Si no lo activas, sustituye `python3` por
> `.venv/bin/python`.

---

## Uso

### Arrancar (desarrollo)

```bash
# Requiere Shell API corriendo en localhost:8090
python3 honeypot.py

# Puerto personalizado y log detallado
python3 honeypot.py --port 2222 --verbose

# Config alternativa
python3 honeypot.py --config /etc/ciphersentry/config.yaml
```

### Arrancar con Docker (producción)

```bash
# La Shell API debe ser accesible desde el contenedor
SHELL_API_URL=http://tu-api:8090 SHELL_API_KEY=tu-key docker compose up -d --build

# Ver logs
docker compose logs -f

# Parar
docker compose down
```

---

## Configuración

### config.yaml

```yaml
host: "0.0.0.0"
port: 2222
host_key_file: "host_key"
ssh_banner: "Debian GNU/Linux 12"
ssh_version: "OpenSSH_8.4p1 Debian-5+deb11u1"   # sin prefijo SSH-2.0- (asyncssh lo añade)
accept_any_password: true
fake_hostname: "web-srv-01"
log_dir: "logs"
shell_api_url: "http://localhost:8090"
shell_api_key: "tu-api-key"
verbose: false

# Ventana de captura de credenciales (opcional)
credential_capture:
  enabled: true
  start_minute: 45   # de xx:45
  end_minute: 60     # a xx:00
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
| `SHELL_API_URL` | URL de la Shell API | `http://localhost:8090` |
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

Más información: [ciphersentry.io](https://ciphersentry.io)

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
requirió varios ajustes en el manejo de asyncssh; los detalles técnicos de cada bug y su
corrección están documentados en [`BUGS.md`](BUGS.md). Puntos clave:

- `keyboard-interactive` deshabilitado (asyncssh lo anuncia por defecto sin handler).
- `ssh_version` sin prefijo `SSH-2.0-` (asyncssh ya lo añade).
- Los *window-change* del cliente se entregan como excepción `TerminalSizeChanged` en stdin
  y deben ignorarse, no tratarse como fin de sesión.

---

## Licencia

MIT — © CipherSentry S.L.
