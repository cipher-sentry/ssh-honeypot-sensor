# ──────────────────────────────────────────────────────
# Nombre:      sftp_server.py
# Descripción: Subsistema SFTP del honeypot. Cada sesión SFTP opera en un
#              sandbox temporal (chroot) sembrado con un árbol Debian creíble,
#              aislado del filesystem real del host. (Fase 1)
#              La Fase 2 añadirá captura de uploads a prueba de borrado.
# ──────────────────────────────────────────────────────
import asyncssh
import hashlib
import os
import re
import shutil
import tempfile
import time
import uuid


def _safe_username(username: str) -> str:
    """Sanitiza el usuario para usarlo como nombre de carpeta (el usuario lo
    controla el atacante → evitar path traversal al sembrar el sandbox)."""
    safe = re.sub(r"[^A-Za-z0-9_-]", "", username or "")[:32]
    return safe or "user"


def _seed_sandbox(root: str, username: str) -> None:
    """Siembra un árbol Debian 12 mínimo y creíble dentro del sandbox."""
    home = "root" if username == "root" else "home/" + _safe_username(username)
    for d in ("etc", "var/log", "var/www/html", "tmp", "usr/local/bin", home):
        os.makedirs(os.path.join(root, d), exist_ok=True)

    files = {
        "etc/hostname": "web-srv-01\n",
        "etc/os-release": (
            'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
            'NAME="Debian GNU/Linux"\nVERSION_ID="12"\n'
            'VERSION="12 (bookworm)"\nID=debian\n'
        ),
        "etc/motd": "Welcome to web-srv-01\n",
        "var/www/html/index.html": "<html><body>It works!</body></html>\n",
        "var/log/auth.log": "",
        home + "/.bashrc": "# ~/.bashrc\n",
        home + "/.profile": "# ~/.profile\n",
    }
    for path, content in files.items():
        fp = os.path.join(root, path)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w", encoding="utf-8") as f:
            f.write(content)


class HoneypotSFTPServer(asyncssh.SFTPServer):
    """SFTP falso: chroot a un sandbox por sesión, sembrado con un árbol Debian.

    Nada de lo que el atacante haga toca el filesystem real del host ni otras
    sesiones. En la Fase 2 se interceptan las escrituras para capturar uploads.
    """

    def __init__(self, chan, config, logger):
        self._config = config
        self._logger = logger
        self._username = chan.get_extra_info("username") or "root"
        peer = chan.get_extra_info("peername") or ("?", 0)
        self._src_ip = peer[0]
        self._session_id = uuid.uuid4().hex[:8]

        self._sandbox = tempfile.mkdtemp(prefix="hpsftp_")
        try:
            _seed_sandbox(self._sandbox, self._username)
        except Exception:
            pass

        # Cuarentena de uploads — FUERA del sandbox y nunca expuesta por SFTP.
        # Persiste aunque el atacante borre/renombre el fichero después.
        log_dir = getattr(config, "log_dir", "logs")
        self._quarantine = os.path.join(log_dir, "sftp_uploads", self._session_id)
        # Estado por handle de escritura: id(file_obj) -> dict
        self._captures = {}
        # Ruta virtual por handle abierto: id(file_obj) -> str (para logging)
        self._paths = {}

        super().__init__(chan, chroot=self._sandbox)

        try:
            logger.sftp_session(self._session_id, self._src_ip, self._username)
        except Exception:
            pass

    # ── Helpers ───────────────────────────────────────────────────────────
    def _vpath(self, path: bytes) -> str:
        """Ruta tal como la ve el atacante (relativa al chroot), para logging."""
        try:
            p = path.decode("utf-8", "replace") if isinstance(path, bytes) else str(path)
        except Exception:
            p = repr(path)
        return p if p.startswith("/") else "/" + p

    # ── Captura de uploads (a prueba de borrado) ──────────────────────────
    def open(self, path, pflags, attrs):
        file_obj = super().open(path, pflags, attrs)
        vpath = self._vpath(path)
        self._paths[id(file_obj)] = vpath
        # ¿Apertura para escritura? → es un upload; abrimos copia en cuarentena.
        is_write = bool(pflags & (asyncssh.FXF_WRITE | asyncssh.FXF_APPEND))
        if is_write:
            try:
                os.makedirs(self._quarantine, exist_ok=True)
                stamp = time.strftime("%Y%m%d_%H%M%S")
                base = os.path.basename(vpath) or "unnamed"
                base = re.sub(r"[^A-Za-z0-9_.-]", "_", base)[:80]
                # Sufijo único: conserva CADA versión aunque coincidan nombre y segundo.
                uniq = uuid.uuid4().hex[:6]
                stored = os.path.join(self._quarantine, f"{stamp}_{uniq}_{base}")
                qf = open(stored, "wb")
                self._captures[id(file_obj)] = {
                    "q": qf, "path": vpath, "stored": stored,
                    "hash": hashlib.sha256(), "size": 0,
                }
            except Exception:
                pass  # nunca romper la sesión por la captura
        return file_obj

    def write(self, file_obj, offset, data):
        n = super().write(file_obj, offset, data)
        cap = self._captures.get(id(file_obj))
        if cap is not None:
            try:
                cap["q"].seek(offset)
                cap["q"].write(data)
                cap["hash"].update(data)
                cap["size"] = max(cap["size"], offset + len(data))
            except Exception:
                pass
        return n

    def close(self, file_obj):
        cap = self._captures.pop(id(file_obj), None)
        if cap is not None:
            try:
                cap["q"].close()
                self._logger.sftp_upload(
                    self._session_id, self._src_ip, cap["path"],
                    cap["size"], cap["hash"].hexdigest(), cap["stored"])
            except Exception:
                pass
        self._paths.pop(id(file_obj), None)
        return super().close(file_obj)

    def read(self, file_obj, offset, size):
        # Solo registramos el primer read de cada fichero (offset 0).
        if offset == 0:
            try:
                self._logger.sftp_download(self._session_id, self._src_ip,
                                           self._paths.get(id(file_obj), "?"))
            except Exception:
                pass
        return super().read(file_obj, offset, size)

    def scandir(self, path):
        try:
            self._logger.sftp_list(self._session_id, self._src_ip, self._vpath(path))
        except Exception:
            pass
        return super().scandir(path)

    def remove(self, path):
        # El borrado solo afecta al sandbox; la copia en cuarentena permanece.
        try:
            self._logger.sftp_delete(self._session_id, self._src_ip,
                                     self._vpath(path), "remove")
        except Exception:
            pass
        return super().remove(path)

    def rename(self, oldpath, newpath):
        try:
            self._logger.sftp_delete(self._session_id, self._src_ip,
                                     f"{self._vpath(oldpath)} → {self._vpath(newpath)}",
                                     "rename")
        except Exception:
            pass
        return super().rename(oldpath, newpath)

    def posix_rename(self, oldpath, newpath):
        try:
            self._logger.sftp_delete(self._session_id, self._src_ip,
                                     f"{self._vpath(oldpath)} → {self._vpath(newpath)}",
                                     "rename")
        except Exception:
            pass
        return super().posix_rename(oldpath, newpath)

    def exit(self):
        """Limpia el sandbox temporal al cerrar la sesión SFTP.
        La cuarentena de uploads NO se borra — es la evidencia capturada."""
        for cap in list(self._captures.values()):
            try:
                cap["q"].close()
            except Exception:
                pass
        self._captures.clear()
        try:
            super().exit()
        finally:
            shutil.rmtree(self._sandbox, ignore_errors=True)


def make_sftp_factory(config, logger):
    """Devuelve el factory que asyncssh invoca con el channel SFTP."""
    def factory(chan):
        return HoneypotSFTPServer(chan, config, logger)
    return factory
