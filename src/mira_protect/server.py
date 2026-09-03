from __future__ import annotations

import argparse
import os

import uvicorn


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mira-protect-server",
        description="Run the Mira Protect control plane",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("MIRA_BIND_HOST", "127.0.0.1"),
        help="Bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("MIRA_BIND_PORT", "8080")),
        help="TCP port (default: 8080)",
    )
    parser.add_argument(
        "--log-level",
        choices=("critical", "error", "warning", "info", "debug", "trace"),
        default=os.getenv("MIRA_LOG_LEVEL", "info"),
    )
    parser.add_argument("--reload", action="store_true", help="Enable Uvicorn reload for local development")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    uvicorn.run(
        "mira_protect.app:app",
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
