#!/usr/bin/env python3
"""
CSC4026Z Chat Client — entry point.

Usage
-----
Cleartext endpoint (port 51825):
    python main.py [--username NAME]

Encrypted endpoint (port 51820, requires your student keypair):
    python main.py --encrypted --private-key-hex <hex> --public-key-hex <hex>

    Or set the environment variables:
        CHAT_PRIVATE_KEY_HEX   — your 64-char hex-encoded static private key
        CHAT_PUBLIC_KEY_HEX    — your 64-char hex-encoded static public key

Retrieve your personal keypair from https://csc4026z.link/keys
"""

import argparse
import asyncio
import logging
import os
import sys

from chat_client.client import ChatClient
from chat_client.ui import run_ui


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='CSC4026Z Chat Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        '--username', '-u',
        default=None,
        help='Set your username on the server immediately after connecting.',
    )
    parser.add_argument(
        '--encrypted', '-e',
        action='store_true',
        default=False,
        help='Use the encrypted WireGuard endpoint (port 51820).',
    )
    parser.add_argument(
        '--private-key-hex',
        default=None,
        help=(
            '64-character hex-encoded static private key '
            '(required with --encrypted).'
        ),
    )
    parser.add_argument(
        '--public-key-hex',
        default=None,
        help=(
            '64-character hex-encoded static public key '
            '(required with --encrypted).'
        ),
    )
    parser.add_argument(
        '--debug', '-d',
        action='store_true',
        default=False,
        help='Enable debug logging.',
    )
    return parser.parse_args()


async def _main() -> None:
    args = _parse_args()

    log_level = logging.DEBUG if args.debug else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    )

    # Resolve encryption keys
    private_key_hex = (
        args.private_key_hex
        or os.environ.get('CHAT_PRIVATE_KEY_HEX', '')
    )
    public_key_hex = (
        args.public_key_hex
        or os.environ.get('CHAT_PUBLIC_KEY_HEX', '')
    )

    if args.encrypted:
        if not private_key_hex or not public_key_hex:
            print(
                'Error: --encrypted requires a static keypair.\n'
                'Provide --private-key-hex and --public-key-hex, or set\n'
                '  CHAT_PRIVATE_KEY_HEX and CHAT_PUBLIC_KEY_HEX\n'
                'Retrieve your keypair from https://csc4026z.link/keys',
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            client_static_private = bytes.fromhex(private_key_hex)
            client_static_public  = bytes.fromhex(public_key_hex)
        except ValueError as exc:
            print(f'Error parsing keypair: {exc}', file=sys.stderr)
            sys.exit(1)

        if len(client_static_private) != 32 or len(client_static_public) != 32:
            print(
                'Error: keys must each be exactly 32 bytes (64 hex chars).',
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        client_static_private = b''
        client_static_public  = b''

    client = ChatClient(
        use_encryption=args.encrypted,
        client_static_private=client_static_private,
        client_static_public=client_static_public,
    )

    # If a username was provided connect immediately; otherwise the user can
    # type /connect in the interactive UI.
    if args.username:
        try:
            await client.connect(args.username)
        except Exception as exc:
            print(f'Could not connect: {exc}', file=sys.stderr)
            sys.exit(1)

    await run_ui(client)


def main() -> None:
    """Synchronous wrapper for the async main function."""
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
