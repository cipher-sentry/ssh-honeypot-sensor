# ──────────────────────────────────────────────────────
# Nombre:      ssh_server.py
# Descripción: Servidor SSH del honeypot ligero. Acepta conexiones y delega
#              toda la emulación en la Shell API vía HTTP.
# ──────────────────────────────────────────────────────
import asyncio
import asyncssh
import os
import time
import uuid
from datetime import datetime

from api_client import ShellAPIClient, ShellAPIError
from config import Config
from logger import AuditLogger
from sftp_server import make_sftp_factory


# ─── Diccionarios de conexión (conn_id → dato) ────────────────────────────────

_conn_passwords: dict = {}
_conn_clients: dict = {}
_conn_auth_methods: dict = {}
_shell_started_conns: set = set()


def _en_ventana_captura(cfg: Config) -> bool:
    """True si el reloj está en la ventana de captura de credenciales
    [start_minute, end_minute) de la hora. Soporta rangos que cruzan la hora."""
    cc = getattr(cfg, "credential_capture", {}) or {}
    if not cc.get("enabled"):
        return False
    start = int(cc.get("start_minute", 45))
    end = int(cc.get("end_minute", 60))
    minute = datetime.now().minute
    if start <= end:
        return start <= minute < end
    return minute >= start or minute < end  # cruza el cambio de hora


# ─── LineReader ───────────────────────────────────────────────────────────────

class LineReader:
    """Lee una línea del terminal con eco, backspace e historial."""

    def __init__(self, stdin, stdout):
        self.stdin = stdin
        self.stdout = stdout
        self._history: list = []
        self._hist_idx: int = 0

    async def readline(self, prompt: str) -> str | None:
        await self._w(prompt)
        buf = ""
        cursor = 0
        escape = ""

        while True:
            try:
                data = await asyncio.wait_for(self.stdin.read(1), timeout=300)
            except asyncio.TimeoutError:
                await self._w("\r\nSession timeout.\r\n")
                return None
            except asyncssh.TerminalSizeChanged:
                # Window resize — ignore and keep reading
                continue
            except asyncssh.BreakReceived:
                # Ctrl+C break signal from client
                await self._w("^C\r\n")
                await self._w(prompt)
                buf = ""
                cursor = 0
                continue
            except (asyncssh.SignalReceived, Exception):
                return None

            if not data:
                return None

            if data == "\x04":  # Ctrl+D
                if not buf:
                    return None
                continue

            if data == "\x03":  # Ctrl+C
                await self._w("^C\r\n")
                await self._w(prompt)
                buf = ""
                cursor = 0
                continue

            if data in ("\r", "\n"):
                await self._w("\r\n")
                if buf.strip():
                    self._history.append(buf)
                    self._hist_idx = len(self._history)
                return buf

            if data == "\x1b":  # secuencia escape
                escape = "\x1b"
                try:
                    n1 = await asyncio.wait_for(self.stdin.read(1), timeout=0.1)
                    if n1:
                        escape += n1
                        if n1 == "[":
                            n2 = await asyncio.wait_for(self.stdin.read(1), timeout=0.1)
                            if n2:
                                escape += n2
                except asyncio.TimeoutError:
                    pass
                if escape == "\x1b[A" and self._hist_idx > 0:  # flecha arriba
                    self._hist_idx -= 1
                    await self._clear(prompt, cursor)
                    buf = self._history[self._hist_idx]
                    cursor = len(buf)
                    await self._w(buf)
                elif escape == "\x1b[B":  # flecha abajo
                    if self._hist_idx < len(self._history) - 1:
                        self._hist_idx += 1
                        await self._clear(prompt, cursor)
                        buf = self._history[self._hist_idx]
                        cursor = len(buf)
                        await self._w(buf)
                    elif self._hist_idx == len(self._history) - 1:
                        self._hist_idx += 1
                        await self._clear(prompt, cursor)
                        buf = ""
                        cursor = 0
                elif escape == "\x1b[C" and cursor < len(buf):
                    cursor += 1
                    await self._w("\x1b[C")
                elif escape == "\x1b[D" and cursor > 0:
                    cursor -= 1
                    await self._w("\x1b[D")
                continue

            if data in ("\x7f", "\x08"):  # backspace
                if cursor > 0:
                    buf = buf[:cursor - 1] + buf[cursor:]
                    cursor -= 1
                    await self._w("\x08")
                    rest = buf[cursor:] + " "
                    await self._w(rest + "\x1b[" + str(len(rest)) + "D")
                continue

            if data == "\x15":  # Ctrl+U — borrar línea
                await self._clear(prompt, cursor)
                buf = ""
                cursor = 0
                continue

            if data == "\t":  # tab — sin completado (engine no disponible)
                continue

            if len(data) == 1 and ord(data) >= 32:
                buf = buf[:cursor] + data + buf[cursor:]
                cursor += 1
                if cursor == len(buf):
                    await self._w(data)
                else:
                    await self._w(data + buf[cursor:] + f"\x1b[{len(buf) - cursor}D")

    async def _w(self, text: str):
        self.stdout.write(text.replace("\n", "\r\n") if isinstance(text, str) else text)

    async def _clear(self, prompt: str, cursor: int):
        await self._w("\x1b[2K\r" + prompt)


# ─── Shell session ────────────────────────────────────────────────────────────

async def run_shell(process: asyncssh.SSHServerProcess,
                    config: Config,
                    logger: AuditLogger,
                    api: ShellAPIClient):
    conn = process.get_extra_info("connection")
    username = process.get_extra_info("username") or "root"
    peername = process.get_extra_info("peername") or ("0.0.0.0", 0)
    src_ip, src_port = peername[0], peername[1]

    session_id = uuid.uuid4().hex[:8]
    start_time = time.time()

    conn_id = id(conn) if conn else None
    password = _conn_passwords.get(conn_id, "") if conn_id else ""
    client_version = _conn_clients.get(conn_id, "") if conn_id else ""
    auth_method = _conn_auth_methods.get(conn_id, "password") if conn_id else "password"

    logger.connection(session_id, src_ip, src_port, username, password,
                      client_version=client_version, auth_method=auth_method)

    # Fingerprint de canal
    channel_reqs = []
    try:
        term = process.term_type
        sz = process.term_size or (0, 0, 0, 0)
        if term:
            channel_reqs.append({"type": "pty", "term": term,
                                  "cols": sz[0], "rows": sz[1]})
    except Exception:
        pass
    try:
        exec_cmd = process.command
        if exec_cmd:
            channel_reqs.append({"type": "exec", "command": exec_cmd})
        else:
            channel_reqs.append({"type": "shell"})
    except Exception:
        pass
    if channel_reqs:
        logger.channel_fingerprint(session_id, channel_reqs)

    stdin = process.stdin
    stdout = process.stdout

    # Comando no interactivo (ssh host "cmd")
    exec_cmd = process.command

    # Para sesiones shell: enviar MOTD antes del API call para que clientes
    # con probe PTY (ej. Termius) reciban datos dentro de su ventana de espera.
    if exec_cmd is None:
        stdout.write(f"Welcome to {config.fake_hostname}.\r\n")
        stdout.write(f"Last login: {_random_last_login()} from {_random_last_ip()}\r\n")
        stdout.write(f"{username}@{config.fake_hostname}:~# ")

    # Estado de captura del nodo en este instante (lo reportamos al engine para que el
    # dashboard muestre si está "capturando todo" o "solo credenciales").
    _cap_mode = _en_ventana_captura(config)

    # Crear sesión en la API usando el mismo session_id del SSH
    try:
        sess_data = await api.create_session(username, src_ip, src_port, session_id,
                                             capture_mode=_cap_mode)
    except Exception as e:
        logger.logger.error(f"[{session_id}] API create_session error: {e}")
        process.exit(1)
        return

    api_session_id = sess_data["session_id"]
    current_prompt = sess_data["prompt"]

    if exec_cmd is not None:
        # Ventana de captura: bloqueamos los EXEC para registrar credencial +
        # comando sin servirlos. Las sesiones SHELL interactivas NO se tocan.
        if _cap_mode:
            logger.exec_blocked(session_id, src_ip, username, password, exec_cmd)
            # El comando NO se ejecuta, pero SÍ se captura en el engine (intel central
            # con node_id, buscable por el cliente). Un exec_blocked ya no pierde la traza.
            try:
                await api.capture_command(api_session_id, exec_cmd)
            except Exception:
                pass
            await api.close_session(api_session_id)
            logger.disconnect(session_id, time.time() - start_time, "exec_blocked")
            process.exit(127)
            return
        try:
            res = await api.exec_command(api_session_id, exec_cmd)
            if res.get("stdout"):
                stdout.write(res["stdout"].replace("\n", "\r\n"))
            if res.get("stderr"):
                process.stderr.write(res["stderr"].replace("\n", "\r\n"))
            process.exit(res.get("exit_code", 0))
        except Exception:
            process.exit(1)
        finally:
            await api.close_session(api_session_id)
            logger.disconnect(session_id, time.time() - start_time, "exec")
        return

    reader = LineReader(stdin, stdout)
    # If we already sent an initial prompt before the API call (for Termius Phase 1
    # probe compatibility), skip re-sending the prompt on the very first readline.
    _skip_first_prompt = (exec_cmd is None)

    try:
        while True:
            display_prompt = "" if _skip_first_prompt else current_prompt
            _skip_first_prompt = False
            line = await reader.readline(display_prompt)
            if line is None:
                break

            line_stripped = line.strip()
            if not line_stripped:
                continue

            # Ejecutar en la API
            try:
                res = await api.exec_command(api_session_id, line_stripped)
            except ShellAPIError as e:
                if e.status_code == 429:
                    stdout.write(f"\r\n{e.detail}\r\n")
                    break
                logger.logger.warning(f"[{session_id}] API exec error: {e}")
                stdout.write("\r\n")
                continue
            except Exception as e:
                logger.logger.error(f"[{session_id}] API unreachable: {e}")
                stdout.write("\r\nbash: connection to shell engine lost\r\n")
                break

            current_prompt = res.get("prompt", current_prompt)

            # needs_password (sudo, su, passwd)
            if res.get("needs_password"):
                password_entered = await _read_password(
                    res.get("password_prompt", "[sudo] password: "),
                    stdin, stdout
                )
                logger.privilege_escalation(session_id, line_stripped, password_entered)
                # Enviamos la contraseña como siguiente línea — la API la procesa
                try:
                    res2 = await api.exec_command(api_session_id, password_entered)
                    current_prompt = res2.get("prompt", current_prompt)
                    _write_output(res2, stdout)
                except Exception:
                    pass
                continue

            # needs_subshell — el prompt ya viene actualizado desde la API
            # No hace falta lógica extra; la API mantiene el estado del subshell.

            # Salida normal
            _write_output(res, stdout)

            # exit/logout — la API maneja el estado; si el prompt vuelve al raíz
            # y el comando era exit, terminamos la sesión SSH
            if line_stripped.split()[0] in ("exit", "logout"):
                stdout.write("logout\r\n")
                break

    except Exception as e:
        if config.verbose:
            logger.logger.error(f"[{session_id}] Shell error: {e}")
    finally:
        try:
            process.exit(0)
        except Exception:
            pass
        await api.close_session(api_session_id)
        logger.disconnect(session_id, time.time() - start_time)


def _write_output(res: dict, stdout):
    """Escribe stdout + stderr de la respuesta de la API al terminal SSH."""
    out = res.get("stdout", "")
    err = res.get("stderr", "")
    if out:
        stdout.write(out.replace("\n", "\r\n"))
    if err:
        stdout.write(err.replace("\n", "\r\n"))


async def _read_password(prompt: str, stdin, stdout) -> str:
    """Lee una contraseña sin eco."""
    stdout.write(prompt)
    buf = ""
    try:
        while True:
            data = await asyncio.wait_for(stdin.read(1), timeout=60)
            if not data or data in ("\r", "\n"):
                break
            if data in ("\x7f", "\x08"):
                buf = buf[:-1]
            elif len(data) == 1 and ord(data) >= 32:
                buf += data
    except asyncio.TimeoutError:
        pass
    stdout.write("\r\n")
    return buf


def _random_last_login() -> str:
    import random
    from datetime import datetime, timedelta
    d = datetime.now() - timedelta(
        days=random.randint(1, 30),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
    )
    return d.strftime("%a %b %d %H:%M:%S %Y")


def _random_last_ip() -> str:
    import random
    return f"10.0.{random.randint(0,255)}.{random.randint(1,254)}"


async def _register_cred_probe(api: ShellAPIClient, username: str,
                                src_ip: str, src_port: int, session_id: str):
    """Registra una sesión CRED_PROBE en el engine (create + close inmediato)
    para que IP y credencial aparezcan en el dashboard / El Enjambre."""
    try:
        sess = await api.create_session(username, src_ip, src_port,
                                        session_id=session_id, capture_mode=True)
        await api.close_session(sess["session_id"])
    except Exception:
        pass


# ─── HoneypotSSHServer ────────────────────────────────────────────────────────

class HoneypotSSHServer(asyncssh.SSHServer):

    def __init__(self, config: Config, logger: AuditLogger, api: ShellAPIClient):
        self._config = config
        self._logger = logger
        self._api = api
        self._conn_id = None
        self._conn = None
        self._username = None
        self._auth_begun = False
        self._src_ip = "?"
        self._src_port = 0

    def connection_made(self, conn):
        self._conn = conn
        self._conn_id = id(conn)
        peername = conn.get_extra_info("peername") or ("?", 0)
        self._src_ip, self._src_port = peername[0], peername[1]
        self._logger.logger.info(f"TCP connect from {self._src_ip}:{self._src_port}")

    def connection_lost(self, exc):
        shell_opened = False
        saved_password = ""
        saved_client_ver = ""
        saved_auth_method = "password"
        if self._conn_id is not None:
            saved_password = _conn_passwords.pop(self._conn_id, "")
            saved_client_ver = _conn_clients.pop(self._conn_id, "")
            saved_auth_method = _conn_auth_methods.pop(self._conn_id, "password")
            shell_opened = self._conn_id in _shell_started_conns
            _shell_started_conns.discard(self._conn_id)
        if not self._auth_begun:
            client_ver = ""
            try:
                client_ver = self._conn.get_extra_info("client_version") or ""
            except Exception:
                pass
            self._logger.probe(self._src_ip, self._src_port, client_ver)
        elif self._username and not shell_opened:
            cred_sid = uuid.uuid4().hex[:8]
            self._logger.credential_probe(
                self._src_ip, self._src_port,
                self._username, saved_password, saved_client_ver,
                auth_method=saved_auth_method, session_id=cred_sid,
            )
            try:
                loop = asyncio.get_event_loop()
                loop.create_task(_register_cred_probe(
                    self._api, self._username, self._src_ip, self._src_port,
                    cred_sid,
                ))
            except Exception:
                pass

    def begin_auth(self, username):
        self._username = username
        self._auth_begun = True
        return True

    def password_auth_supported(self):
        return True

    def kbdint_auth_supported(self):
        return False

    def validate_password(self, username, password):
        if self._conn_id is not None:
            _conn_passwords[self._conn_id] = password
            client_ver = ""
            try:
                client_ver = self._conn.get_extra_info("client_version") or ""
            except Exception:
                pass
            _conn_clients[self._conn_id] = client_ver
            _conn_auth_methods[self._conn_id] = "password"
        if self._config.accept_any_password:
            return True
        for cred in self._config.credentials:
            if cred.get("username") == username and cred.get("password") == password:
                return True
        return False

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        if self._conn_id is not None:
            client_ver = ""
            try:
                client_ver = self._conn.get_extra_info("client_version") or ""
            except Exception:
                pass
            _conn_clients[self._conn_id] = client_ver
            _conn_auth_methods[self._conn_id] = "pubkey"
        return self._config.accept_any_password


# ─── create_server ────────────────────────────────────────────────────────────

async def create_server(config: Config, logger: AuditLogger, api: ShellAPIClient):
    key_file = config.host_key_file
    if os.path.exists(key_file):
        server_host_keys = [key_file]
    else:
        logger.logger.info(f"Generating host key → {key_file}")
        key = asyncssh.generate_private_key("ssh-ed25519")
        key.write_private_key(key_file)
        key.write_public_key(key_file + ".pub")
        server_host_keys = [key_file]

    def server_factory():
        return HoneypotSSHServer(config, logger, api)

    async def _run_shell(process):
        conn = process.get_extra_info("connection")
        conn_id = id(conn) if conn else None
        if conn_id is not None:
            _shell_started_conns.add(conn_id)
        await run_shell(process, config, logger, api)

    server = await asyncssh.create_server(
        server_factory,
        config.host,
        config.port,
        server_host_keys=server_host_keys,
        process_factory=_run_shell,
        sftp_factory=make_sftp_factory(config, logger),
        allow_scp=True,
        server_version=config.ssh_version,
        login_timeout=120,
        keepalive_interval=30,
        keepalive_count_max=3,
        encoding="utf-8",
        line_editor=False,
    )

    logger.logger.info(f"SSH honeypot listening on {config.host}:{config.port}")
    return server
