# CSC4026Z Chat Client

A terminal-based chat client for the CSC4026Z course chat server. It supports both a plaintext connection and an encrypted WireGuard-based connection using Curve25519 keypairs.

## Setup

```bash
pip install -r requirements.txt
```

## Running the client

### Plaintext (port 51825)

```bash
python3 main.py --username <name>
```

### Encrypted via WireGuard (port 51820)

Retrieve your personal keypair from `https://csc4026z.link/keys`, then pass your Base64-encoded private key:

```bash
python3 main.py --encrypted --username <name> --private-key-b64 <base64_private_key>
```

The public key is derived automatically from the private key.

#### Legacy hex format

```bash
python3 main.py --encrypted --username <name> \
    --private-key-hex <64-char-hex> \
    --public-key-hex <64-char-hex>
```

Or use environment variables instead of flags:

```bash
export CHAT_PRIVATE_KEY_HEX=<64-char-hex>
export CHAT_PUBLIC_KEY_HEX=<64-char-hex>
python3 main.py --encrypted --username <name>
```

## All flags

| Flag | Short | Description |
|------|-------|-------------|
| `--username` | `-u` | Set your username on connect |
| `--encrypted` | `-e` | Use the encrypted WireGuard endpoint |
| `--private-key-b64` | | Base64-encoded 32-byte private key |
| `--private-key-hex` | | Hex-encoded private key (legacy, requires `--public-key-hex`) |
| `--public-key-hex` | | Hex-encoded public key (used with `--private-key-hex`) |
| `--debug` | `-d` | Enable debug logging |

If `--username` is omitted, you can connect manually from within the UI using `/connect`.
