"""CLI for the minimal VPN-like protocol.

This exposes two subcommands:

- server: listens for a VPN client and forwards to a fixed target
- client: listens locally and forwards through the VPN server
"""
from __future__ import annotations

import argparse

from vpn_protocol import run_client, run_server


def _add_server_subcommand(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("server", help="run VPN server")
    parser.add_argument("--listen-host", default="0.0.0.0", help="host/IP to listen on")
    parser.add_argument("--listen-port", type=int, default=9000, help="TCP port to listen on")
    parser.add_argument("--target-host", required=True, help="target host to forward to")
    parser.add_argument("--target-port", type=int, required=True, help="target port to forward to")
    parser.add_argument("--passphrase", required=True, help="shared secret passphrase")
    parser.add_argument("--salt", default="", help="optional salt for key derivation")
    parser.add_argument(
        "--iterations", type=int, default=100_000, help="PBKDF2 iterations for key stretching (default: 100000)"
    )
    parser.add_argument("--compress", action="store_true", help="enable payload compression when beneficial")
    parser.add_argument(
        "--rekey-interval",
        type=int,
        default=0,
        help="rotate session key every N frames (0 disables rotation)",
    )
    parser.set_defaults(func=_run_server)


def _add_client_subcommand(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser("client", help="run VPN client")
    parser.add_argument("--listen-host", default="127.0.0.1", help="local host to listen on")
    parser.add_argument("--listen-port", type=int, default=10000, help="local port to listen on")
    parser.add_argument("--server-host", default="127.0.0.1", help="VPN server host")
    parser.add_argument("--server-port", type=int, default=9000, help="VPN server port")
    parser.add_argument("--passphrase", required=True, help="shared secret passphrase")
    parser.add_argument("--salt", default="", help="optional salt for key derivation")
    parser.add_argument(
        "--iterations", type=int, default=100_000, help="PBKDF2 iterations for key stretching (default: 100000)"
    )
    parser.add_argument("--compress", action="store_true", help="enable payload compression when beneficial")
    parser.add_argument(
        "--rekey-interval",
        type=int,
        default=0,
        help="rotate session key every N frames (0 disables rotation)",
    )
    parser.set_defaults(func=_run_client)


def _run_server(args: argparse.Namespace) -> None:
    run_server(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        target_host=args.target_host,
        target_port=args.target_port,
        passphrase=args.passphrase,
        salt=args.salt,
        iterations=args.iterations,
        compress=args.compress,
        rekey_interval=args.rekey_interval or None,
    )


def _run_client(args: argparse.Namespace) -> None:
    run_client(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        server_host=args.server_host,
        server_port=args.server_port,
        passphrase=args.passphrase,
        salt=args.salt,
        iterations=args.iterations,
        compress=args.compress,
        rekey_interval=args.rekey_interval or None,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Educational VPN-like tunnel")
    subparsers = parser.add_subparsers(dest="cmd", required=True)
    _add_server_subcommand(subparsers)
    _add_client_subcommand(subparsers)

    args = parser.parse_args()
    func = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        raise SystemExit(1)
    func(args)


if __name__ == "__main__":  # pragma: no cover
    main()
