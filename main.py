#!/usr/bin/env python3
"""
CSC4026Z Chat Client — entry point.

Usage
-----
Cleartext endpoint (port 51825):
    python main.py [--username NAME]

Encrypted endpoint (port 51820, using your Base64 student private key):
    python main.py --encrypted --private-key-b64 <base64>

Encrypted endpoint (legacy hex format):
    python main.py --encrypted --private-key-hex <hex> --public-key-hex <hex>

    Or set the environment variables:
        CHAT_PRIVATE_KEY_HEX   — your 64-char hex-encoded static private key
        CHAT_PUBLIC_KEY_HEX    — your 64-char hex-encoded static public key

Retrieve your personal keypair from https://csc4026z.link/keys
"""

import argparse
import asyncio
import base64
import logging
import os
import sys

import nacl.public

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
        '--private-key-b64',
        default=None,
        help=(
            'Base64-encoded 32-byte static private key '
            '(required with --encrypted; public key is derived automatically).'
        ),
    )
    parser.add_argument(
        '--private-key-hex',
        default=None,
        help=(
            '64-character hex-encoded static private key '
            '(alternative to --private-key-b64; requires --public-key-hex).'
        ),
    )
    parser.add_argument(
        '--public-key-hex',
        default=None,
        help=(
            '64-character hex-encoded static public key '
            '(only needed together with --private-key-hex).'
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
        if args.private_key_b64:
            # Base64 path: decode private key and derive public key automatically
            try:
                client_static_private = base64.b64decode(args.private_key_b64)
            except Exception as exc:
                print(f'Error decoding Base64 private key: {exc}', file=sys.stderr)
                sys.exit(1)
            if len(client_static_private) != 32:
                print(
                    f'Error: Base64-decoded private key must be exactly 32 bytes '
                    f'(got {len(client_static_private)}).',
                    file=sys.stderr,
                )
                sys.exit(1)
            try:
                client_static_public = bytes(
                    nacl.public.PrivateKey(client_static_private).public_key
                )
            except Exception as exc:
                print(f'Error deriving public key from private key: {exc}', file=sys.stderr)
                sys.exit(1)
        elif private_key_hex and public_key_hex:
            # Hex path (legacy / explicit)
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
            print(
                'Error: --encrypted requires a static keypair.\n'
                'Provide --private-key-b64 <base64_private_key>, or\n'
                '  --private-key-hex <hex> --public-key-hex <hex>\n'
                'Or set CHAT_PRIVATE_KEY_HEX and CHAT_PUBLIC_KEY_HEX.\n'
                'Retrieve your keypair from https://csc4026z.link/keys',
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