#!/usr/bin/env python3
# ──────────────────────────────────────────────────────
# Nombre:      honeypot.py
# Descripción: Entry point del honeypot SSH ligero CipherSentry
# Uso:         python3 honeypot.py [--port 2222] [--verbose] [--config config.yaml]
# ──────────────────────────────────────────────────────
import argparse
import asyncio
import signal
import sys

from api_client import ShellAPIClient
from config import load_config, SENSOR_VERSION, SENSOR_CODENAME
from logger import AuditLogger
from ssh_server import create_server


async def main():
    parser = argparse.ArgumentParser(description="CipherSentry SSH Honeypot (cliente ligero)")
    parser.add_argument("--port", type=int, help="Puerto SSH (sobreescribe config.yaml)")
    parser.add_argument("--verbose", action="store_true", help="Log detallado")
    parser.add_argument("--config", default="config.yaml", help="Ruta al config.yaml")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.port:
        config.port = args.port
    if args.verbose:
        config.verbose = True

    logger = AuditLogger(config.log_dir, verbose=config.verbose,
                         node_id=config.node_id)
    api = ShellAPIClient(config.shell_api_url, config.shell_api_key,
                         node_id=config.node_id, sensor_version=SENSOR_VERSION)

    logger.logger.info(f"Sonda CipherSentry v{SENSOR_VERSION} «{SENSOR_CODENAME}»")
    logger.logger.info(f"Shell API: {config.shell_api_url}")
    if config.node_id:
        logger.logger.info(f"Node ID: {config.node_id}")

    server = await create_server(config, logger, api)

    loop = asyncio.get_running_loop()
    stop = loop.create_future()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set_result, None)

    logger.logger.info("Honeypot activo. Ctrl+C para detener.")
    await stop

    logger.logger.info("Apagando...")
    server.close()
    await server.wait_closed()
    await api.aclose()
    logger.logger.info("Parado.")


if __name__ == "__main__":
    asyncio.run(main())
