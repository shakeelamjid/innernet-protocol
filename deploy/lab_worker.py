"""Runs exactly one local-laboratory node in its own HTTP process."""
from __future__ import annotations
import argparse
import uvicorn
from innernet2.node import create_app


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dir", required=True)
    p.add_argument("--port", type=int, required=True)
    args = p.parse_args()
    if not 19401 <= args.port <= 19409:
        raise ValueError("lab port outside expected range")
    # Docker publishes the service ONLY on host loopback; never expose it publicly.
    uvicorn.run(create_app(args.dir), host="0.0.0.0", port=args.port,
                log_level="error", workers=1, access_log=False, proxy_headers=False)


if __name__ == "__main__":
    main()
