# ──────────────────────────────────────────────────────
# Nombre:      config.py
# Descripción: Carga config.yaml y variables de entorno → dataclass Config
# ──────────────────────────────────────────────────────
from dataclasses import dataclass, field
from pathlib import Path
import os
import yaml


def _read_version():
    """Versión + codename de la sonda (fuente única: fichero VERSION del bundle).
    Permite saber, en node.sh y en el dashboard, qué versión corre cada nodo."""
    try:
        lines = (Path(__file__).resolve().parent / "VERSION").read_text().splitlines()
        return (lines[0].strip() or "0.0.0", lines[1].strip() if len(lines) > 1 else "")
    except Exception:
        return ("0.0.0", "")


SENSOR_VERSION, SENSOR_CODENAME = _read_version()


@dataclass
class Config:
    host: str = "0.0.0.0"
    port: int = 2222
    host_key_file: str = "host_key"
    ssh_banner: str = "Debian GNU/Linux 12"
    ssh_version: str = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"
    accept_any_password: bool = True
    credentials: list = field(default_factory=list)
    fake_hostname: str = "web-srv-01"
    shell_api_url: str = "http://localhost:8090"
    shell_api_key: str = "free-demo"
    node_id: str = ""
    log_dir: str = "logs"
    verbose: bool = False
    # Ventana de captura de credenciales: bloquea EXEC en [start_minute, end_minute)
    # de cada hora; las sesiones SHELL interactivas se permiten siempre.
    credential_capture: dict = field(default_factory=dict)


def load_config(path: str = "config.yaml") -> Config:
    data = {}
    if Path(path).exists():
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

    cfg = Config(
        host=data.get("host", "0.0.0.0"),
        port=int(data.get("port", 2222)),
        host_key_file=data.get("host_key_file", "host_key"),
        ssh_banner=data.get("ssh_banner", "Debian GNU/Linux 12"),
        ssh_version=data.get("ssh_version", "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1"),
        accept_any_password=data.get("accept_any_password", True),
        credentials=data.get("credentials", []),
        fake_hostname=data.get("fake_hostname", "web-srv-01"),
        shell_api_url=data.get("shell_api_url", "http://localhost:8090"),
        shell_api_key=data.get("shell_api_key", "free-demo"),
        node_id=data.get("node_id", ""),
        log_dir=data.get("log_dir", "logs"),
        verbose=data.get("verbose", False),
        credential_capture=data.get("credential_capture", {}),
    )

    # Variables de entorno tienen prioridad sobre config.yaml
    if os.environ.get("HONEYPOT_PORT"):
        cfg.port = int(os.environ["HONEYPOT_PORT"])
    if os.environ.get("SHELL_API_URL"):
        cfg.shell_api_url = os.environ["SHELL_API_URL"]
    if os.environ.get("SHELL_API_KEY"):
        cfg.shell_api_key = os.environ["SHELL_API_KEY"]
    if os.environ.get("NODE_ID"):
        cfg.node_id = os.environ["NODE_ID"]
    if os.environ.get("HONEYPOT_VERBOSE", "").lower() in ("1", "true", "yes"):
        cfg.verbose = True

    # Identidad del nodo: si no viene por config/env, se intenta leer del
    # node_identity/ generado por node.sh (Sprint 005).
    if not cfg.node_id:
        id_file = Path(__file__).parent / "node_identity" / "id"
        try:
            cfg.node_id = id_file.read_text(encoding="utf-8").strip()
        except Exception:
            cfg.node_id = ""

    return cfg
