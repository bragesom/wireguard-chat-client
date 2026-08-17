
import hashlib
import hmac
import struct
import time
from typing import Optional

import nacl.bindings
import nacl.public
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def DH(private_key, public_key):
    return nacl.bindings.crypto_scalarmult(n=private_key, p=public_key)

def DH_Generate():
    private_key = nacl.public.PrivateKey.generate()
    return (bytes(private_key), bytes(private_key.public_key))


def Hash(text) -> bytes:
    return hashlib.blake2s(text).digest()


def MixHash(data1: bytes, data2: bytes) -> bytes:
    return Hash(data1 + data2)


def Mac(key, input) -> bytes:
    # blake2s takes its message positionally; passing it as data= is a TypeError
    return hashlib.blake2s(input, key=key, digest_size=16).digest()


def Hmac(key: bytes, data: bytes) -> bytes:
    # stdlib hmac doesn't support blake2s directly
    return hmac.new(key, data, hashlib.blake2s).digest()


def Kdf_n(key, input, n):
    t0 = Hmac(key, input)
    t1 = Hmac(t0, b'\x01')
    kdf = [t1] * n
    for i in range(1, n):
        kdf[i] = Hmac(t0, kdf[i-1] + bytes([i + 1]))
    return tuple(kdf)

Kdf1 = lambda key, input: Kdf_n(key, input, 1)[0]
Kdf2 = lambda key, input: Kdf_n(key, input, 2)
Kdf3 = lambda key, input: Kdf_n(key, input, 3)


def _make_nonce(counter: int) -> bytes:
    """Build a 12-byte nonce from a 64-bit little-endian counter."""
    return b'\x00\x00\x00\x00' + struct.pack('<Q', counter)


def AEAD(key: bytes, counter: int, plaintext: bytes, auth_data: bytes) -> bytes:
    """Encrypt with ChaCha20-Poly1305; returns ciphertext + 16-byte tag."""
    return ChaCha20Poly1305(key).encrypt(_make_nonce(counter), plaintext, auth_data)


def AEAD_decrypt(key: bytes, counter: int, ciphertext: bytes, auth_data: bytes) -> bytes:
    """Decrypt with ChaCha20-Poly1305; raises InvalidTag on auth failure."""
    return ChaCha20Poly1305(key).decrypt(_make_nonce(counter), ciphertext, auth_data)


def Timestamp(t: Optional[float] = None) -> bytes:
    """12-byte TAI64N timestamp: 8-byte big-endian seconds + 4-byte nanoseconds."""
    if t is None:
        t = time.time()
    seconds = int(t)
    nanoseconds = int((t - seconds) * 1_000_000)
    tai_seconds = (1 << 62) + seconds + 10  # TAI-UTC offset at Unix epoch (1970)
    return struct.pack('>QI', tai_seconds, nanoseconds)
