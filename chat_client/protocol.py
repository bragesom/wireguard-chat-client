"""
Chat protocol message definitions and helpers.

All messages are encoded with MessagePack as specified.  Every request
(except CONNECT) must include the ``session`` field obtained from the server
during the CONNECT handshake.

Request type constants may need to be updated once the full protocol
documentation is available — they are grouped here for easy maintenance.
"""

import random
import msgpack


# ---------------------------------------------------------------------------
# Request type constants
# ---------------------------------------------------------------------------

REQUEST_CONNECT         = 1
REQUEST_DISCONNECT      = 2
REQUEST_PING            = 3
REQUEST_SET_USERNAME    = 4
REQUEST_LIST_CHANNELS   = 5
REQUEST_LIST_USERS      = 6
REQUEST_USER_INFO       = 7
REQUEST_CHANNEL_INFO    = 8
REQUEST_JOIN_CHANNEL    = 9
REQUEST_LEAVE_CHANNEL   = 10
REQUEST_SEND_MESSAGE    = 11
REQUEST_SEND_DM         = 12
REQUEST_CREATE_CHANNEL  = 13


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def new_handle() -> int:
    """Generate a random request handle (0 ≤ handle < 2^32)."""
    return random.randrange(0, 2 ** 32)


def encode(data: dict) -> bytes:
    """Pack *data* using MessagePack."""
    return msgpack.packb(data, use_bin_type=True)


def decode(data: bytes) -> dict:
    """Unpack MessagePack-encoded *data* into a Python dict."""
    return msgpack.unpackb(data, raw=False)


# ---------------------------------------------------------------------------
# Request builders
# ---------------------------------------------------------------------------

def connect_request() -> tuple[bytes, int]:
    """Build a CONNECT request.

    Returns:
        (encoded_bytes, request_handle)
    """
    handle = new_handle()
    msg = {'request_type': REQUEST_CONNECT, 'request_handle': handle}
    return encode(msg), handle


def disconnect_request(session: bytes) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_DISCONNECT,
        'request_handle': handle,
        'session': session,
    }
    return encode(msg), handle


def ping_request(session: bytes) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_PING,
        'request_handle': handle,
        'session': session,
    }
    return encode(msg), handle


def set_username_request(session: bytes, username: str) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_SET_USERNAME,
        'request_handle': handle,
        'session': session,
        'username': username,
    }
    return encode(msg), handle


def list_channels_request(session: bytes) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_LIST_CHANNELS,
        'request_handle': handle,
        'session': session,
    }
    return encode(msg), handle


def list_users_request(session: bytes) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_LIST_USERS,
        'request_handle': handle,
        'session': session,
    }
    return encode(msg), handle


def user_info_request(session: bytes, username: str) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_USER_INFO,
        'request_handle': handle,
        'session': session,
        'username': username,
    }
    return encode(msg), handle


def channel_info_request(session: bytes, channel: str) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_CHANNEL_INFO,
        'request_handle': handle,
        'session': session,
        'channel': channel,
    }
    return encode(msg), handle


def join_channel_request(session: bytes, channel: str) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_JOIN_CHANNEL,
        'request_handle': handle,
        'session': session,
        'channel': channel,
    }
    return encode(msg), handle


def leave_channel_request(session: bytes, channel: str) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_LEAVE_CHANNEL,
        'request_handle': handle,
        'session': session,
        'channel': channel,
    }
    return encode(msg), handle


def send_message_request(
    session: bytes, channel: str, message: str
) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_SEND_MESSAGE,
        'request_handle': handle,
        'session': session,
        'channel': channel,
        'message': message,
    }
    return encode(msg), handle


def send_dm_request(
    session: bytes, recipient: str, message: str
) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_SEND_DM,
        'request_handle': handle,
        'session': session,
        'recipient': recipient,
        'message': message,
    }
    return encode(msg), handle


def create_channel_request(
    session: bytes, channel: str, description: str = ''
) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_CREATE_CHANNEL,
        'request_handle': handle,
        'session': session,
        'channel': channel,
        'description': description,
    }
    return encode(msg), handle
