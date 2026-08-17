"""MessagePack encoding for the chat protocol's request messages."""

import random
import msgpack

REQUEST_CONNECT         = 1
REQUEST_DISCONNECT      = 2
REQUEST_PING            = 3
REQUEST_CREATE_CHANNEL  = 4
REQUEST_LIST_CHANNELS   = 5
REQUEST_CHANNEL_INFO    = 6
REQUEST_JOIN_CHANNEL    = 7
REQUEST_LEAVE_CHANNEL   = 8
REQUEST_SEND_MESSAGE    = 9
REQUEST_WHOIS           = 10   # Query info about another user
REQUEST_WHOAMI          = 11   # Query your own username
REQUEST_SEND_DM         = 12
REQUEST_SET_USERNAME    = 13
REQUEST_LIST_USERS      = 14   # Paginated user list (optional channel filter)



def new_handle() -> int:
    """Generate a random request handle (0 ≤ handle < 2^32)."""
    return random.randrange(0, 2 ** 32)


def encode(data: dict) -> bytes:
    """Pack *data* using MessagePack."""
    return msgpack.packb(data, use_bin_type=True)


def decode(data: bytes) -> dict:
    """Unpack MessagePack-encoded *data* into a Python dict."""
    return msgpack.unpackb(data, raw=False)


def connect_request() -> tuple[bytes, int]:
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


def list_channels_request(session: bytes, offset: int = 0) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_LIST_CHANNELS,
        'request_handle': handle,
        'session': session,
    }
    if offset:
        msg['offset'] = offset
    return encode(msg), handle


def list_users_request(session: bytes, channel: str = None, offset: int = 0) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_LIST_USERS,
        'request_handle': handle,
        'session': session,
    }
    if channel:
        msg['channel'] = channel
    if offset:
        msg['offset'] = offset
    return encode(msg), handle


def whoami_request(session: bytes) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_WHOAMI,
        'request_handle': handle,
        'session': session,
    }
    return encode(msg), handle


def whois_request(session: bytes, username: str) -> tuple[bytes, int]:
    handle = new_handle()
    msg = {
        'request_type': REQUEST_WHOIS,
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
        'to_username': recipient,   # server field name is to_username
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