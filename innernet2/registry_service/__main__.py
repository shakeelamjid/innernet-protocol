"""Run the registry: python -m innernet2.registry_service [--host 0.0.0.0] [--port 8080]"""
from __future__ import annotations

import argparse
import logging

import uvicorn

from .app import create_app
from .config import Settings


def main() -> None:
    parser = argparse.ArgumentParser(description="INNERNET provider registry (IRM-1 draft)")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = Settings.from_env()
    uvicorn.run(create_app(settings), host=args.host, port=args.port, proxy_headers=settings.trust_proxy,
                forwarded_allow_ips="*" if settings.trust_proxy else None, server_header=False)


if __name__ == "__main__":
    main()
