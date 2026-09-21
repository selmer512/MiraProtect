from __future__ import annotations

import argparse
import os
import ssl

import uvicorn

from .security import validate_server_security


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


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
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable Uvicorn reload for local development",
    )
    parser.add_argument(
        "--ssl-certfile",
        default=os.getenv("MIRA_TLS_CERT_FILE"),
        help="TLS server certificate PEM file",
    )
    parser.add_argument(
        "--ssl-keyfile",
        default=os.getenv("MIRA_TLS_KEY_FILE"),
        help="TLS server private key PEM file",
    )
    parser.add_argument(
        "--ssl-client-ca-file",
        default=os.getenv("MIRA_TLS_CLIENT_CA_FILE"),
        help="CA bundle used to validate client certificates when mTLS is enabled",
    )
    parser.add_argument(
        "--require-client-cert",
        action="store_true",
        default=_as_bool(os.getenv("MIRA_TLS_REQUIRE_CLIENT_CERT", "false")),
        help="Require client certificates (mTLS)",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
        raise SystemExit("Both --ssl-certfile and --ssl-keyfile are required when enabling TLS.")
    if args.require_client_cert and not args.ssl_client_ca_file:
        raise SystemExit("--ssl-client-ca-file is required when --require-client-cert is enabled.")

    try:
        validate_server_security(
            bind_host=args.host,
            ssl_certfile=args.ssl_certfile,
            ssl_keyfile=args.ssl_keyfile,
        )
    except (RuntimeError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc

    os.environ["MIRA_BIND_HOST"] = str(args.host)
    os.environ["MIRA_EFFECTIVE_TLS"] = "true" if args.ssl_certfile and args.ssl_keyfile else "false"

    uvicorn.run(
        "mira_protect.app:app",
        host=args.host,
        port=args.port,
        log_level=args.log_level,
        reload=args.reload,
        ssl_certfile=args.ssl_certfile,
        ssl_keyfile=args.ssl_keyfile,
        ssl_ca_certs=args.ssl_client_ca_file,
        ssl_cert_reqs=ssl.CERT_REQUIRED if args.require_client_cert else ssl.CERT_NONE,
    )


if __name__ == "__main__":
    main()
