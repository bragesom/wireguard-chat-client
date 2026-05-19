"""
WireGuard cryptographic primitives.

Implements the functions described in the WireGuard paper (sections 5.4.x):
  DH, DH_Generate, AEAD, Hash, MixHash, Mac, Hmac, Kdf1, Kdf2, Kdf3, Timestamp
"""

import hashlib
import hmac as _hmac
import struct
import time
from typing import Optional

import nacl.bindings
import nacl.public
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ---------------------------------------------------------------------------
# Diffie–Hellman (Curve25519)
# ---------------------------------------------------------------------------

def DH(private_key: bytes, public_key: bytes) -> bytes:
    """Perform a Diffie-Hellman operation on Curve25519."""
    return nacl.bindings.crypto_scalarmult(n=private_key, p=public_key)


def DH_Generate():
    """Generate a Curve25519 keypair.

    Returns:
        (private_key_bytes, public_key_bytes)
    """
    private_key = nacl.public.PrivateKey.generate()
    return (bytes(private_key), bytes(private_key.public_key))


# ---------------------------------------------------------------------------
# Hash / MixHash
# ---------------------------------------------------------------------------

def Hash(data: bytes) -> bytes:
    """BLAKE2s with 32-byte (256-bit) output."""
    return hashlib.blake2s(data, digest_size=32).digest()


def MixHash(data1: bytes, data2: bytes) -> bytes:
    """Hash(data1 || data2) — convenience wrapper used throughout the spec."""
    return Hash(data1 + data2)


# ---------------------------------------------------------------------------
# MAC (keyed BLAKE2s, 16-byte output)
# ---------------------------------------------------------------------------

def Mac(key: bytes, data: bytes) -> bytes:
    """Keyed BLAKE2s with 16-byte digest (used for WireGuard mac1/mac2)."""
    return hashlib.blake2s(data, key=key, digest_size=16).digest()


# ---------------------------------------------------------------------------
# HMAC-BLAKE2s (32-byte output)
# ---------------------------------------------------------------------------

def Hmac(key: bytes, data: bytes) -> bytes:
    """HMAC using BLAKE2s as the underlying hash function (32-byte output)."""
    return _hmac.new(key, data, digestmod=hashlib.blake2s).digest()


# ---------------------------------------------------------------------------
# Key Derivation Functions (HKDF-style using HMAC-BLAKE2s)
# ---------------------------------------------------------------------------

def Kdf1(key: bytes, input_data: bytes) -> bytes:
    """Derive one 32-byte key from (key, input_data)."""
    t0 = Hmac(key, input_data)
    t1 = Hmac(t0, b'\x01')
    return t1


def Kdf2(key: bytes, input_data: bytes):
    """Derive two 32-byte keys from (key, input_data).

    Returns:
        (t1, t2) as a tuple of bytes objects.
    """
    t0 = Hmac(key, input_data)
    t1 = Hmac(t0, b'\x01')
    t2 = Hmac(t0, t1 + b'\x02')
    return t1, t2


def Kdf3(key: bytes, input_data: bytes):
    """Derive three 32-byte keys from (key, input_data).

    Returns:
        (t1, t2, t3) as a tuple of bytes objects.
    """
    t0 = Hmac(key, input_data)
    t1 = Hmac(t0, b'\x01')
    t2 = Hmac(t0, t1 + b'\x02')
    t3 = Hmac(t0, t2 + b'\x03')
    return t1, t2, t3


# ---------------------------------------------------------------------------
# AEAD (ChaCha20-Poly1305 IETF, 96-bit nonce)
# ---------------------------------------------------------------------------

def _make_nonce(counter: int) -> bytes:
    """Build a 12-byte nonce from a 64-bit little-endian counter."""
    return b'\x00\x00\x00\x00' + struct.pack('<Q', counter)


def AEAD(key: bytes, counter: int, plaintext: bytes, auth_data: bytes) -> bytes:
    """Encrypt plaintext with ChaCha20-Poly1305.

    Args:
        key:       32-byte symmetric key.
        counter:   64-bit integer counter (becomes the last 8 bytes of nonce).
        plaintext: data to encrypt.
        auth_data: additional authenticated data.

    Returns:
        ciphertext + 16-byte authentication tag.
    """
    aead = ChaCha20Poly1305(key)
    nonce = _make_nonce(counter)
    return aead.encrypt(nonce, plaintext, auth_data)


def AEAD_decrypt(key: bytes, counter: int, ciphertext: bytes, auth_data: bytes) -> bytes:
    """Decrypt ciphertext with ChaCha20-Poly1305.

    Args:
        key:        32-byte symmetric key.
        counter:    64-bit integer counter (becomes the last 8 bytes of nonce).
        ciphertext: ciphertext + 16-byte authentication tag.
        auth_data:  additional authenticated data.

    Returns:
        Decrypted plaintext.

    Raises:
        cryptography.exceptions.InvalidTag: if authentication fails.
    """
    aead = ChaCha20Poly1305(key)
    nonce = _make_nonce(counter)
    return aead.decrypt(nonce, ciphertext, auth_data)


# ---------------------------------------------------------------------------
# TAI64N Timestamp
# ---------------------------------------------------------------------------

def Timestamp(t: Optional[float] = None) -> bytes:
    """Return a 12-byte TAI64N timestamp.

    Format: 8-byte big-endian seconds (with 2^62 TAI offset) +
            4-byte big-endian nanoseconds.

    Args:
        t: Unix timestamp as a float.  Uses ``time.time()`` when omitted.
    """
    if t is None:
        t = time.time()
    seconds = int(t)
    nanoseconds = int((t - seconds) * 1_000_000)
    # TAI64 epoch offset: 2^62
    tai_seconds = (1 << 62) + seconds + 10  # TAI-UTC offset at Unix epoch (1970)
    return struct.pack('>QI', tai_seconds, nanoseconds)
