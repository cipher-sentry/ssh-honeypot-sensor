# ──────────────────────────────────────────────────────
# Nombre:      logger.py
# Descripción: AuditLogger JSON Lines — mismo formato que ssh-honeypot
# ──────────────────────────────────────────────────────
import gzip
import json
import logging
import shutil
import time
import uuid
from datetime import datetime
from pathlib import Path


class AuditLogger:
    """JSON-Lines audit logger. Formato idéntico al de ssh-honeypot."""

    def __init__(self, log_dir: str, log_file: str = "sessions.jsonl",
                 rotate_days: int = 30, verbose: bool = False,
                 node_id: str = ""):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.log_dir / log_file
        self.rotate_days = rotate_days
        self.verbose = verbose
        # Identidad del nodo: TODO evento de este log pertenece a este nodo. Se estampa
        # en cada línea (incluidos los previos a la sesión: probe, connection…), para
        # que el panel pueda atribuir también los banner-grabs y conexiones sin shell.
        self.node_id = node_id or ""
        self._rotate_old_logs()

        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(level=level,
                            format="%(asctime)s [%(levelname)s] %(message)s")
        self.logger = logging.getLogger("honeypot")

    def _write(self, event: dict):
        event.setdefault("ts", datetime.utcnow().isoformat() + "Z")
        if self.node_id:
            event.setdefault("node_id", self.node_id)
        line = json.dumps(event, ensure_ascii=False) + "\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)
        if self.verbose:
            self.logger.debug(line.strip())

    def _rotate_old_logs(self):
        cutoff = time.time() - self.rotate_days * 86400
        for p in self.log_dir.glob("*.jsonl.gz"):
            if p.stat().st_mtime < cutoff:
                p.unlink()
        if self.log_path.exists() and self.log_path.stat().st_size > 100 * 1024 * 1024:
            rotated = self.log_path.with_suffix(
                f'.{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.jsonl'
            )
            shutil.move(str(self.log_path), str(rotated))
            with open(rotated, "rb") as f_in, gzip.open(str(rotated) + ".gz", "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)
            rotated.unlink()

    def connection(self, session_id: str, ip: str, port: int,
                   username: str, password: str, client_version: str = "",
                   auth_method: str = "password"):
        self._write({
            "event": "connection", "session_id": session_id,
            "src_ip": ip, "src_port": port,
            "username": username, "password": password,
            "client_version": client_version, "auth_method": auth_method,
        })
        self.logger.info(f"[{session_id}] CONNECT {ip}:{port} user={username!r} pass={password!r}")

    def probe(self, ip: str, port: int, client_version: str = ""):
        self._write({"event": "probe", "src_ip": ip, "src_port": port,
                     "client_version": client_version})
        self.logger.info(f"PROBE {ip}:{port} client={client_version!r}")

    def credential_probe(self, ip: str, port: int, username: str,
                         password: str, client_version: str = "",
                         auth_method: str = "password", session_id: str = None):
        sid = session_id or uuid.uuid4().hex[:8]
        self._write({
            "event": "credential_probe",
            "session_id": sid,
            "src_ip": ip, "src_port": port,
            "username": username, "password": password,
            "client_version": client_version, "auth_method": auth_method,
        })
        self.logger.info(f"CRED_PROBE {ip} user={username!r} auth={auth_method}")

    def exec_blocked(self, session_id: str, src_ip: str, username: str,
                     password: str, command: str):
        """EXEC bloqueado durante la ventana de captura de credenciales.
        Registra la credencial y el comando que el atacante quería ejecutar."""
        self._write({"event": "exec_blocked", "session_id": session_id,
                     "src_ip": src_ip, "username": username,
                     "password": password, "command": command})
        self.logger.warning(
            f"[{session_id}] EXEC_BLOCKED {src_ip} user={username!r} "
            f"cmd={command!r} (ventana de captura)")

    def disconnect(self, session_id: str, duration: float, reason: str = "closed"):
        self._write({"event": "disconnect", "session_id": session_id,
                     "duration_s": round(duration, 2), "reason": reason})
        self.logger.info(f"[{session_id}] DISCONNECT after {duration:.1f}s ({reason})")

    def command(self, session_id: str, cwd: str, raw: str, cmd: str, args: list):
        self._write({"event": "command", "session_id": session_id,
                     "cwd": cwd, "raw": raw, "cmd": cmd, "args": args})

    def output(self, session_id: str, stdout: str, stderr: str = "", exit_code: int = 0):
        self._write({"event": "output", "session_id": session_id,
                     "stdout": stdout, "stderr": stderr, "exit_code": exit_code})

    def privilege_escalation(self, session_id: str, target_user: str, password: str):
        self._write({"event": "privilege_escalation", "session_id": session_id,
                     "target_user": target_user, "password_entered": password})
        self.logger.warning(f"[{session_id}] PRIVESC → user={target_user!r}")

    def channel_fingerprint(self, session_id: str, requests: list):
        self._write({"event": "channel_fingerprint", "session_id": session_id,
                     "requests": requests})

    # ── Eventos SFTP ──────────────────────────────────────────────────────
    def sftp_session(self, session_id: str, src_ip: str, username: str):
        self._write({"event": "sftp_session", "session_id": session_id,
                     "src_ip": src_ip, "username": username})
        self.logger.info(f"[{session_id}] SFTP_SESSION {src_ip} user={username!r}")

    def sftp_upload(self, session_id: str, src_ip: str, path: str,
                    size: int, sha256: str, stored: str):
        """Fichero subido por SFTP y CAPTURADO en cuarentena (a prueba de borrado)."""
        self._write({"event": "sftp_upload", "session_id": session_id,
                     "src_ip": src_ip, "path": path, "size": size,
                     "sha256": sha256, "stored": stored})
        self.logger.warning(
            f"[{session_id}] SFTP_UPLOAD {src_ip} {path!r} ({size}B sha256={sha256[:12]}…) → {stored}")

    def sftp_download(self, session_id: str, src_ip: str, path: str):
        self._write({"event": "sftp_download", "session_id": session_id,
                     "src_ip": src_ip, "path": path})
        self.logger.info(f"[{session_id}] SFTP_DOWNLOAD {src_ip} {path!r}")

    def sftp_list(self, session_id: str, src_ip: str, path: str):
        self._write({"event": "sftp_list", "session_id": session_id,
                     "src_ip": src_ip, "path": path})

    def sftp_delete(self, session_id: str, src_ip: str, path: str, kind: str = "remove"):
        """Borrado/renombrado por SFTP. La copia capturada NO se ve afectada."""
        self._write({"event": "sftp_delete", "session_id": session_id,
                     "src_ip": src_ip, "path": path, "kind": kind})
        self.logger.warning(f"[{session_id}] SFTP_DELETE ({kind}) {src_ip} {path!r}")
