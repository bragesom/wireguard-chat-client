"""
Tests for WireGuard cryptographic functions and handshake construction.

Run with:
    python -m pytest tests/ -v
or:
    python tests/test_crypto.py
"""

import struct
import sys
import os
import unittest

# Make sure the package is importable from the repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from chat_client.crypto import (
    DH, DH_Generate,
    AEAD, AEAD_decrypt,
    Hash, MixHash, Mac, Hmac,
    Kdf1, Kdf2, Kdf3,
    Timestamp,
)
from chat_client.protocol import encode, decode, connect_request, ping_request


class TestHash(unittest.TestCase):
    def test_construction(self):
        """Hash of the WireGuard construction identifier."""
        result   = Hash(b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s')
        expected = (
            b'`\xe2m\xae\xf3\'\xef\xc0.\xc35\xe2\xa0%\xd2\xd0'
            b'\x16\xebB\x06\xf8rw\xf5-8\xd1\x98\x8bx\xcd6'
        )
        self.assertEqual(result, expected)

    def test_output_length(self):
        self.assertEqual(len(Hash(b'hello')), 32)


class TestMixHash(unittest.TestCase):
    def test_sample(self):
        result   = MixHash(b'a' * 50, b'b' * 50)
        expected = (
            b'#B\x17\x17\xbe=\xfcc\xd6\xb5@81\t\x8dh'
            b'\x88\x9b\xb3\xa8\xb9\xb2n\n\x02\r:\xcb\xbe\xb0\xa7\xee'
        )
        self.assertEqual(result, expected)

    def test_equals_hash_concat(self):
        a = b'foo'
        b_ = b'bar'
        self.assertEqual(MixHash(a, b_), Hash(a + b_))


class TestMac(unittest.TestCase):
    _KEY   = b':\xb6\x90\xbd\n:\x18Z88"\xd8a\x08\x9f\xa7\x9c\xc7\xcb\x01\x99-\xfd\x9cGX\xdc\x9dO\x0c\xb3@'
    _INPUT = b'I am a message without a MAC, but only for now.'
    _EXPECTED = b'*\xbd\x8ak4%\xe4\xb0\xe7\x96\xe5z\x14q\xdd!'

    def test_sample(self):
        self.assertEqual(Mac(self._KEY, self._INPUT), self._EXPECTED)

    def test_output_length(self):
        self.assertEqual(len(Mac(self._KEY, b'x')), 16)


class TestHmac(unittest.TestCase):
    _KEY      = b':\xb6\x90\xbd\n:\x18Z88"\xd8a\x08\x9f\xa7\x9c\xc7\xcb\x01\x99-\xfd\x9cGX\xdc\x9dO\x0c\xb3@'
    _INPUT    = b'I am a message without an HMAC, but only for now.'
    _EXPECTED = (
        b'\x1ew,:\x03\xdd\x0b\x1e\x96\n\x00J\x8c\xe1QzQ\xff\xb8\x02'
        b'\xcb\xa29\xa8{\x00\x07(\xa6\xc0\x07\xde'
    )

    def test_sample(self):
        self.assertEqual(Hmac(self._KEY, self._INPUT), self._EXPECTED)

    def test_output_length(self):
        self.assertEqual(len(Hmac(self._KEY, b'x')), 32)


class TestKdf(unittest.TestCase):
    _KEY   = b':\xb6\x90\xbd\n:\x18Z88"\xd8a\x08\x9f\xa7\x9c\xc7\xcb\x01\x99-\xfd\x9cGX\xdc\x9dO\x0c\xb3@'
    _INPUT = b'Choose your LLM adventure folks.'

    _KDF1_EXPECTED = (
        b'0fO\x0e\x0f\xb2\xf4\xaa\xcc\x14\x9c\x84\x8a\xb0D\xd3'
        b'i\xa6\xac\xbf\xae\xdc^\xd0-D"64X\x93W'
    )
    _KDF2_T2_EXPECTED = (
        b'\xaa\x9b\x0fh\xf9\x99z\\%\\\x0f\x8c9L\x7f~<\x1f\xa9G'
        b'\x9d \x1dw\xba\xc3\x96\x9e\xbb\x8f\x12&'
    )
    _KDF3_T3_EXPECTED = (
        b'\\\xfb\xc9\xf8!\x88\x03\xa1u\xa8!gUk\xfd\x8b4E|\n5'
        b'\x89\xb1\xb6\xc1\x1a\x8f\xae?\\\xac)'
    )

    def test_kdf1(self):
        self.assertEqual(Kdf1(self._KEY, self._INPUT), self._KDF1_EXPECTED)

    def test_kdf2_first_equals_kdf1(self):
        t1, _ = Kdf2(self._KEY, self._INPUT)
        self.assertEqual(t1, self._KDF1_EXPECTED)

    def test_kdf2_second(self):
        _, t2 = Kdf2(self._KEY, self._INPUT)
        self.assertEqual(t2, self._KDF2_T2_EXPECTED)

    def test_kdf3_third(self):
        _, _, t3 = Kdf3(self._KEY, self._INPUT)
        self.assertEqual(t3, self._KDF3_T3_EXPECTED)


class TestAEAD(unittest.TestCase):
    _KEY       = b':\xb6\x90\xbd\n:\x18Z88"\xd8a\x08\x9f\xa7\x9c\xc7\xcb\x01\x99-\xfd\x9cGX\xdc\x9dO\x0c\xb3@'
    _PLAINTEXT = b'attack at dawn'
    _AUTHDATA  = (
        b'\x8e2\x89\xe2\x14\xfd\x16\x19o\x06\xc9\xb2\xd9\xe8F\xfd'
        b'\xdaf\xdc\xa4\xf9\xe9\x98\xbc\xd8x\xb9\x90\x1e\n\xac\x98'
    )
    _CIPHERTEXT = (
        b'\xfbv\x84\xea\xd0S\n\xc1\x16\x9et\xd5\xa4/\xeee'
        b'\x9a\xa9MR\xe3\xd5p3\x85\r\xce\x15r\xcd'
    )

    def test_encrypt(self):
        ct = AEAD(self._KEY, 0, self._PLAINTEXT, self._AUTHDATA)
        self.assertEqual(ct, self._CIPHERTEXT)

    def test_decrypt(self):
        pt = AEAD_decrypt(self._KEY, 0, self._CIPHERTEXT, self._AUTHDATA)
        self.assertEqual(pt, self._PLAINTEXT)

    def test_roundtrip(self):
        key       = b'a' * 32
        plaintext = b'hello world'
        auth      = b'associated data'
        ct = AEAD(key, 42, plaintext, auth)
        pt = AEAD_decrypt(key, 42, ct, auth)
        self.assertEqual(pt, plaintext)

    def test_tag_length(self):
        ct = AEAD(b'k' * 32, 0, b'x', b'')
        self.assertEqual(len(ct), len(b'x') + 16)


class TestDH(unittest.TestCase):
    _PRIVATE = b'\xb0)e\xdbZ\x01\x8f\x0f\xf5\x91\x88<\xab\x15\x14\x95\xb3\x92\xbd&3\xfe\x18<\x8f\xd6P\xeb\xd0k\xdb\x7f'
    _PUBLIC  = b'\x14\xde\xd1\x90m?\x0eaBa\xbb\xf8\\\x08\xdd\xfd\x08\xa7?^\x9f\xcb\x16Y\xdf\xa1\\B\x9d\t7k'
    _EXPECTED = b'p\x06\xe4\x7f\xce\x87\x88\xe2\xb9\xd1\xb0\xb7\xf3\x0e}\xb1\xc6{g\xae\x17\x8b\x17{\x91}\x05&\x0cl\xbd:'

    def test_sample(self):
        self.assertEqual(DH(self._PRIVATE, self._PUBLIC), self._EXPECTED)

    def test_server_public_key(self):
        server_pub = (
            b'f,^\xc0Cb\xf3\x937\xbf\x11\x14"\xed\x13\x0b'
            b'\x9f\xe7\xaf;\x94\xb0p\x13\xe1\x94\xdd\x85\xcf\x01\x0bC'
        )
        expected = (
            b'\x1a\x7f=\xf5w\xcd\xfe\xdb\xdd\xf1\xbd\xcd$\xa4\xc3\xbc'
            b'lLk*\xbf\x0ec\xb1\x1b\x13\xfd\xebK"\x84\x0f'
        )
        self.assertEqual(DH(self._PRIVATE, server_pub), expected)

    def test_generate_returns_32_byte_keys(self):
        priv, pub = DH_Generate()
        self.assertEqual(len(priv), 32)
        self.assertEqual(len(pub), 32)

    def test_diffie_hellman_symmetry(self):
        """DH(a_priv, b_pub) == DH(b_priv, a_pub)."""
        a_priv, a_pub = DH_Generate()
        b_priv, b_pub = DH_Generate()
        self.assertEqual(DH(a_priv, b_pub), DH(b_priv, a_pub))


class TestTimestamp(unittest.TestCase):
    def test_length(self):
        ts = Timestamp()
        self.assertEqual(len(ts), 12)

    def test_structure(self):
        import time
        t      = time.time()
        ts     = Timestamp(t)
        tai_s, nanos = struct.unpack('>QI', ts)
        unix_s = tai_s - (1 << 62)
        self.assertAlmostEqual(unix_s, int(t), delta=1)
        self.assertGreaterEqual(nanos, 0)
        self.assertLess(nanos, 1_000_000_000)


class TestInitiationConstruction(unittest.TestCase):
    """Verify the WireGuard initiation construction against the worked example."""

    def test_initiation_intermediate_values(self):
        """Step through the initiation construction from the problem statement."""
        from chat_client.crypto import (
            Hash, MixHash, Kdf1, Kdf2, DH, AEAD, AEAD_decrypt,
        )

        client_private = (
            b'\x99x\x93eP\xdd\xb7h\xd5dJ\xc7\xa5~\x83\xbd'
            b'X\x04M\xe29\x15\xe2\xf1\xe8\xd8VFk0\xf8\xa1'
        )
        server_public  = (
            b'f,^\xc0Cb\xf3\x937\xbf\x11\x14"\xed\x13\x0b'
            b'\x9f\xe7\xaf;\x94\xb0p\x13\xe1\x94\xdd\x85\xcf\x01\x0bC'
        )
        E_I_priv = (
            b'\xac\x03\x18b0\xc4\xf7\xd4*\xa7-\x81&\xfb\xc7\xb3'
            b'PG0\xae\xa4y0\x90\xe2\xe4\xe2\xa0g\\\x83\xb6'
        )
        E_I_pub = (
            b"\xb1\x13\xb4\xd3\x00R'\x8b\x80\xd1\xcc\xc8X\x1bYf"
            b"(4\xce&\xd0V\xde\x97\xff\xba2$u\x9b\xe3G"
        )

        chain_key = Hash(b'Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s')
        h         = MixHash(chain_key, b'WireGuard v1 zx2c4 Jason@zx2c4.com')
        h         = MixHash(h, server_public)

        chain_key = Kdf1(chain_key, E_I_pub)
        h         = MixHash(h, E_I_pub)

        chain_key, key1 = Kdf2(chain_key, DH(E_I_priv, server_public))

        # Verify key1 from worked example
        self.assertEqual(
            key1,
            b'S%mJ\xe2\xc4AS\xc4\xfcX\x88\x86\xa0\th'
            b'\xf5\xfb5\xffO\x08}\xae\xdeS7$D\x9b\xa8j',
        )

        # Verify chain_key after step 6
        self.assertEqual(
            chain_key,
            b'\xb9\xb7\xc6[$4\xc1\xb1\xb8O\xd5\xf42\xb4\xd8\xa2'
            b'5\xea\xda\xba\xc4\x0e\xfd\xe5\xc5\xb1\xa4Ga\xd8\xb54',
        )


class TestWireGuardTransport(unittest.TestCase):
    """Test that encrypt/decrypt round-trips work for transport messages."""

    def test_transport_roundtrip(self):
        from chat_client.wireguard import (
            WireGuardSession, encrypt_transport, decrypt_transport,
        )
        import os

        key = os.urandom(32)
        session = WireGuardSession(
            sending_key=key,
            receiving_key=key,
            local_index=1,
            remote_index=2,
        )

        plaintext = b'Hello, server!'
        msg = encrypt_transport(session, plaintext)

        # Counter was incremented
        self.assertEqual(session.send_counter, 1)

        # Create a "receive" session with same keys
        recv_session = WireGuardSession(
            sending_key=key,
            receiving_key=key,
            local_index=2,
            remote_index=1,
        )
        recovered = decrypt_transport(recv_session, msg)
        self.assertEqual(recovered, plaintext)

    def test_transport_message_structure(self):
        from chat_client.wireguard import (
            WireGuardSession, encrypt_transport, MSG_TRANSPORT,
        )
        import os

        key = os.urandom(32)
        session = WireGuardSession(
            sending_key=key,
            receiving_key=key,
            local_index=1,
            remote_index=99,
        )

        msg = encrypt_transport(session, b'test')
        # type byte
        self.assertEqual(msg[0], MSG_TRANSPORT)
        # reserved
        self.assertEqual(msg[1:4], b'\x00\x00\x00')
        # receiver index (little-endian uint32)
        import struct
        receiver = struct.unpack_from('<I', msg, 4)[0]
        self.assertEqual(receiver, 99)


class TestProtocol(unittest.TestCase):
    def test_connect_request_roundtrip(self):
        data, handle = connect_request()
        msg = decode(data)
        self.assertEqual(msg['request_type'], 1)
        self.assertEqual(msg['request_handle'], handle)

    def test_encode_decode_roundtrip(self):
        original = {'key': 'value', 'number': 42, 'list': [1, 2, 3]}
        self.assertEqual(decode(encode(original)), original)

    def test_ping_includes_session(self):
        session = b'test-session-id'
        data, handle = ping_request(session)
        msg = decode(data)
        self.assertEqual(msg['request_type'], 3)
        self.assertEqual(msg['session'], session)
        self.assertEqual(msg['request_handle'], handle)


if __name__ == '__main__':
    unittest.main(verbosity=2)
