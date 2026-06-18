# ──────────────────────────────────────────────────────
# Nombre:      api_client.py
# Descripción: Cliente HTTP async para CipherSentry Shell API
# ──────────────────────────────────────────────────────
import httpx


class ShellAPIError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class ShellAPIClient:
    """
    Cliente async para la Shell API.
    Crear una instancia por proceso; reutiliza el httpx.AsyncClient interno.
    """

    def __init__(self, base_url: str, api_key: str, timeout: float = 15.0,
                 node_id: str = None, sensor_version: str = "", node_key: str = ""):
        self._base = base_url.rstrip("/")
        self._node_id = node_id or None
        self._sensor_version = sensor_version or ""
        self._headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json",
        }
        # Llave secreta del nodo: autentica al nodo ante el central (impide suplantarlo).
        if node_key:
            self._headers["X-Node-Key"] = node_key
        self._client = httpx.AsyncClient(timeout=timeout)

    async def aclose(self):
        await self._client.aclose()

    async def capture_command(self, session_id: str, line: str):
        """Registra en el engine un comando CAPTURADO pero no ejecutado (ventana de
        captura de credenciales): la traza se guarda centralmente (intel) sin emularse."""
        r = await self._client.post(
            f"{self._base}/v1/capture",
            headers=self._headers,
            json={"session_id": session_id, "line": line},
        )
        self._raise(r)
        return r.json()

    def _raise(self, r: httpx.Response):
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail", r.text)
            except Exception:
                detail = r.text
            raise ShellAPIError(r.status_code, detail)

    async def create_session(self, username: str, src_ip: str, src_port: int,
                             session_id: str = None, capture_mode: bool = None,
                             password: str = "", auth_method: str = "password",
                             client_version: str = "") -> dict:
        body = {"username": username, "src_ip": src_ip, "src_port": src_port,
                # Credencial intentada en el login SSH: viaja al engine para que la sesión
                # quede atribuida con su password/método también en nodos remotos (no solo
                # en el log local de la sonda).
                "password": password, "auth_method": auth_method,
                "client_version": client_version}
        if session_id:
            body["session_id"] = session_id
        if capture_mode is not None:
            # Estado de la ventana de captura de credenciales (para el dashboard).
            body["capture_mode"] = bool(capture_mode)
        if self._node_id:
            body["node_id"] = self._node_id
        if self._sensor_version:
            # Versión de la sonda → el engine la guarda por nodo (visibilidad en el dashboard).
            body["sensor_version"] = self._sensor_version
        r = await self._client.post(
            f"{self._base}/v1/session",
            headers=self._headers,
            json=body,
        )
        self._raise(r)
        return r.json()

    async def exec_command(self, session_id: str, line: str) -> dict:
        r = await self._client.post(
            f"{self._base}/v1/exec",
            headers=self._headers,
            json={"session_id": session_id, "line": line},
        )
        self._raise(r)
        return r.json()

    async def close_session(self, session_id: str) -> None:
        try:
            await self._client.delete(
                f"{self._base}/v1/session/{session_id}",
                headers=self._headers,
            )
        except Exception:
            pass
