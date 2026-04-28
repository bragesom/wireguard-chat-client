"""
WireGuard handshake and transport message implementation.

Implements the simplified WireGuard protocol described in the CSC4026Z spec:
  Section 5.4.2  — Sending an initiation handshake
  Section 5.4.3  — Handling the handshake response
  Section 5.4.4  — Cookie MACs (mac1 only, mac2 = zeros)
  Section 5.4.5  — Key derivation
  Section 5.4.6  — Transport data messages
"""

import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from .crypto import (
    AEAD, AEAD_decrypt,
    DH, DH_Generate,
    Hash, MixHash, Mac, Hmac,
    Kdf1, Kdf2, Kdf3,
    Timestamp,
)

# ---------------------------------------------------------------------------
# WireGuard protocol constants
# ---------------------------------------------------------------------------

# Noise protocol framework identifiers (Section 5.4.1)
CONSTRUCTION = b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s'
IDENTIFIER   = b'WireGuard v1 zx2c4 Jason@zx2c4.com'
LABEL_MAC1   = b'mac1----'

# Message type bytes
MSG_INITIATION = 1
MSG_RESPONSE   = 2
MSG_TRANSPORT  = 4

# Pre-shared key (unused — all zeros per the spec when PSK is not set)
PSK_ZERO = b'\x00' * 32


# ---------------------------------------------------------------------------
# Public server static key
# ---------------------------------------------------------------------------

SERVER_STATIC_PUBLIC_KEY = (
    b'f,^\xc0Cb\xf3\x937\xbf\x11\x14"\xed\x13\x0b'
    b'\x9f\xe7\xaf;\x94\xb0p\x13\xe1\x94\xdd\x85\xcf\x01\x0bC'
)


# ---------------------------------------------------------------------------
# Transport session state
# ---------------------------------------------------------------------------

@dataclass
class WireGuardSession:
    """Holds all mutable state for an established WireGuard session.

    ``sending_key`` and ``receiving_key`` must be provided explicitly;
    they have no safe defaults.
    """

    # Transport keys — must be set during key derivation
    sending_key:   bytes
    receiving_key: bytes

    # Our sender index and the server's sender index
    local_index:  int = 0
    remote_index: int = 0

    # Nonce counters
    send_counter: int = 0
    recv_counter: int = 0


# ---------------------------------------------------------------------------
# Initiation message (Section 5.4.2)
# ---------------------------------------------------------------------------

def build_initiation(
    client_static_private: bytes,
    client_static_public:  bytes,
    server_static_public:  bytes = SERVER_STATIC_PUBLIC_KEY,
) -> tuple[bytes, int, bytes, bytes, bytes, bytes]:
    """Construct a WireGuard handshake initiation message.

    Returns:
        (msg_bytes, sender_index, ephemeral_private, ephemeral_public,
         chain_key, hash)
        The chain_key and hash are carried forward into
        ``consume_response()``.
    """
    # --- Initialise chaining key and hash ---
    chain_key = Hash(CONSTRUCTION)
    h = MixHash(chain_key, IDENTIFIER)
    h = MixHash(h, server_static_public)

    # --- Generate ephemeral keypair ---
    e_priv, e_pub = DH_Generate()

    # chain_key = Kdf1(chain_key, E_I_pub)
    chain_key = Kdf1(chain_key, e_pub)

    # hash = Hash(hash || E_I_pub)
    h = MixHash(h, e_pub)

    # (chain_key, key1) = Kdf2(chain_key, DH(E_I_priv, S_R_pub))
    chain_key, key1 = Kdf2(chain_key, DH(e_priv, server_static_public))

    # msg_static = AEAD(key1, 0, S_I_pub, hash)
    msg_static = AEAD(key1, 0, client_static_public, h)

    # hash = Hash(hash || msg_static)
    h = MixHash(h, msg_static)

    # (chain_key, key2) = Kdf2(chain_key, DH(S_I_priv, S_R_pub))
    chain_key, key2 = Kdf2(chain_key, DH(client_static_private, server_static_public))

    # msg_timestamp = AEAD(key2, 0, Timestamp(), hash)
    msg_timestamp = AEAD(key2, 0, Timestamp(), h)

    # hash = Hash(hash || msg_timestamp)
    h = MixHash(h, msg_timestamp)

    # --- Build raw message (before MACs) ---
    sender_index = int.from_bytes(os.urandom(4), 'little')

    msg_header = struct.pack(
        '<B3sI32s48s28s',
        MSG_INITIATION,
        b'\x00\x00\x00',
        sender_index,
        e_pub,
        msg_static,
        msg_timestamp,
    )

    # --- MAC fields (Section 5.4.4) ---
    mac1_key = Hash(LABEL_MAC1 + server_static_public)
    mac1     = Mac(mac1_key, msg_header)
    mac2     = b'\x00' * 16   # not implemented

    msg = msg_header + mac1 + mac2

    return msg, sender_index, e_priv, e_pub, chain_key, h


# ---------------------------------------------------------------------------
# Response message (Section 5.4.3)
# ---------------------------------------------------------------------------

def consume_response(
    response_bytes: bytes,
    client_static_private: bytes,
    ephemeral_private: bytes,
    ephemeral_public:  bytes,
    chain_key: bytes,
    h:         bytes,
) -> WireGuardSession:
    """Parse and authenticate a WireGuard handshake response.

    Args:
        response_bytes:        Raw bytes received from the server.
        client_static_private: Our static private key.
        ephemeral_private:     Our ephemeral private key (from initiation).
        ephemeral_public:      Our ephemeral public key (from initiation).
        chain_key:             Chaining key carried over from initiation.
        h:                     Hash value carried over from initiation.

    Returns:
        A WireGuardSession with derived transport keys.

    Raises:
        ValueError: on unexpected message type, length, or MAC failure.
    """
    # Minimal length check: type(1)+reserved(3)+sender(4)+receiver(4)+
    #                       ephemeral(32)+empty(16)+mac1(16)+mac2(16) = 92
    if len(response_bytes) < 92:
        raise ValueError(
            f"Response too short: {len(response_bytes)} bytes (expected ≥ 92)"
        )

    msg_type = response_bytes[0]
    if msg_type != MSG_RESPONSE:
        raise ValueError(f"Unexpected message type {msg_type!r} (expected 2)")

    # Unpack fields
    # type(1), reserved(3), sender(4), receiver(4), ephemeral(32),
    # empty_enc(16), mac1(16), mac2(16)
    (_, reserved, remote_index, local_index,
     e_r_pub, empty_enc) = struct.unpack_from('<B3sII32s16s', response_bytes, 0)

    # --- Replicate the responder's key schedule ---

    # chain_key = Kdf1(chain_key, E_R_pub)
    chain_key = Kdf1(chain_key, e_r_pub)

    # hash = Hash(hash || E_R_pub)
    h = MixHash(h, e_r_pub)

    # chain_key = Kdf1(chain_key, DH(E_I_priv, E_R_pub))
    chain_key = Kdf1(chain_key, DH(ephemeral_private, e_r_pub))

    # chain_key = Kdf1(chain_key, DH(S_I_priv, E_R_pub))
    chain_key = Kdf1(chain_key, DH(client_static_private, e_r_pub))

    # (chain_key, tmp, key3) = Kdf3(chain_key, Q)   Q = PSK = 0^32
    chain_key, tmp, key3 = Kdf3(chain_key, PSK_ZERO)

    # hash = Hash(hash || tmp)
    h = MixHash(h, tmp)

    # Verify/decrypt empty field
    decrypted_empty = AEAD_decrypt(key3, 0, empty_enc, h)
    if decrypted_empty != b'':
        raise ValueError("Handshake response authentication failed")

    # hash = Hash(hash || empty_enc)   (use the ciphertext, i.e., the tag)
    h = MixHash(h, empty_enc)

    # --- Derive transport keys (Section 5.4.5) ---
    sending_key, receiving_key = Kdf2(chain_key, b'')

    session = WireGuardSession(
        sending_key=sending_key,
        receiving_key=receiving_key,
        local_index=local_index,
        remote_index=remote_index,
        send_counter=0,
        recv_counter=0,
    )
    return session


# ---------------------------------------------------------------------------
# Transport messages (Section 5.4.6)
# ---------------------------------------------------------------------------

def encrypt_transport(session: WireGuardSession, plaintext: bytes) -> bytes:
    """Encrypt a plaintext payload into a WireGuard transport message.

    Args:
        session:   Active WireGuardSession (send_counter is incremented).
        plaintext: Raw bytes to encrypt (no padding required per the spec).

    Returns:
        Complete transport message bytes ready to send.
    """
    counter = session.send_counter

    # msg_packet = AEAD(T_I_send, N_I_send, P, ε)
    ciphertext = AEAD(session.sending_key, counter, plaintext, b'')

    # type(1), reserved(3), receiver(4), counter(8), packet(...)
    msg = struct.pack(
        '<B3sIQ',
        MSG_TRANSPORT,
        b'\x00\x00\x00',
        session.remote_index,
        counter,
    ) + ciphertext

    session.send_counter += 1
    return msg


def decrypt_transport(session: WireGuardSession, msg_bytes: bytes) -> bytes:
    """Decrypt a received WireGuard transport message.

    Args:
        session:   Active WireGuardSession (recv_counter is NOT auto-updated;
                   caller may update it from the message's counter field).
        msg_bytes: Raw transport message bytes from the server.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: on unexpected message type or authentication failure.
    """
    if msg_bytes[0] != MSG_TRANSPORT:
        raise ValueError(
            f"Unexpected message type {msg_bytes[0]!r} (expected 4)"
        )

    # type(1), reserved(3), receiver(4), counter(8) → 16 bytes header
    _type, _reserved, _receiver, counter = struct.unpack_from(
        '<B3sIQ', msg_bytes, 0
    )
    ciphertext = msg_bytes[16:]

    plaintext = AEAD_decrypt(session.receiving_key, counter, ciphertext, b'')
    return plaintext
