"""
Asyncio-based chat client event loop.

Architecture
============
The client runs three concurrent tasks:

1. ``_receive_loop`` — polls the UDP socket for incoming packets, decodes
   them, and dispatches server-pushed notifications to registered callbacks.

2. ``_ping_loop``    — sends a PING request every 30 seconds to keep the
   session alive.

3. ``_input_loop``   — reads lines from stdin without blocking the event loop
   and calls the command dispatcher.

Both the cleartext endpoint (port 51825) and the encrypted endpoint
(port 51820, via WireGuard) are supported.  Pass ``use_encryption=True`` to
``ChatClient`` to use the encrypted endpoint.
"""

import asyncio
import logging
import os
import socket
import struct
import time
from typing import Callable, Optional

import msgpack

from . import protocol as proto
from .wireguard import (
    WireGuardSession,
    build_initiation,
    consume_response,
    decrypt_transport,
    encrypt_transport,
    SERVER_STATIC_PUBLIC_KEY,
    MSG_RESPONSE,
    MSG_TRANSPORT,
)

logger = logging.getLogger(__name__)

# Server connection details
SERVER_HOST      = 'csc4026z.link'
PORT_CLEARTEXT   = 51825
PORT_ENCRYPTED   = 51820

# Ping interval in seconds (server expires sessions after 60 s of silence)
PING_INTERVAL = 30

# UDP receive buffer size
UDP_BUFFER_SIZE = 4096


class ChatClient:
    """Asynchronous chat client that communicates with the CSC4026Z server.

    Args:
        use_encryption: If True connect to the WireGuard-encrypted endpoint.
        client_static_private: 32-byte private key for WireGuard (required
            when ``use_encryption`` is True).
        client_static_public:  32-byte public key corresponding to the above.
    """

    def __init__(
        self,
        use_encryption:        bool  = False,
        client_static_private: bytes = b'',
        client_static_public:  bytes = b'',
    ):
        self.use_encryption        = use_encryption
        self.client_static_private = client_static_private
        self.client_static_public  = client_static_public

        # Network
        self._sock: Optional[socket.socket] = None
        self._server_addr: tuple[str, int]  = (
            SERVER_HOST,
            PORT_ENCRYPTED if use_encryption else PORT_CLEARTEXT,
        )

        # Session state (set after CONNECT response)
        self.session:  Optional[bytes] = None

        # WireGuard state (set after handshake)
        self._wg_session: Optional[WireGuardSession] = None

        # Pending requests: {handle: asyncio.Future}
        self._pending: dict[int, asyncio.Future] = {}

        # Registered server-push callbacks: list of callables that receive
        # the decoded server message dict.
        self._callbacks: list[Callable[[dict], None]] = []

        # Background tasks
        self._tasks: list[asyncio.Task] = []

        # Whether the client is running
        self._running = False

        # Username (local state)
        self.username: Optional[str] = None

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def on_message(self, callback: Callable[[dict], None]) -> None:
        """Register a callback for server-pushed notifications."""
        self._callbacks.append(callback)

    async def connect(self, username: Optional[str] = None) -> dict:
        """Open the UDP socket, perform optional WireGuard handshake, and send
        CONNECT.

        Args:
            username: Optional username to set immediately after connecting.

        Returns:
            The CONNECT response dict from the server.
        """
        # Create a non-blocking UDP socket
        loop = asyncio.get_running_loop()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(False)

        if self.use_encryption:
            await self._wireguard_handshake(loop)

        # Start receive loop before sending CONNECT so the response is picked up
        self._running = True
        self._tasks = [
            asyncio.create_task(self._receive_loop()),
            asyncio.create_task(self._ping_loop()),
        ]

        # Send CONNECT
        data, handle = proto.connect_request()
        response = await self._request(data, handle)

        # Server returns a session identifier
        self.session = response.get('session')
        logger.debug('Connected, session=%s', self.session)

        if username:
            await self.set_username(username)

        return response

    async def disconnect(self) -> None:
        """Send DISCONNECT and clean up."""
        if self.session:
            data, handle = proto.disconnect_request(self.session)
            try:
                await asyncio.wait_for(self._request(data, handle), timeout=3.0)
            except (asyncio.TimeoutError, Exception):
                pass

        await self._shutdown()

    async def set_username(self, username: str) -> dict:
        """Change the client's username on the server."""
        self._require_session()
        data, handle = proto.set_username_request(self.session, username)
        response = await self._request(data, handle)
        if response.get('success', True):
            self.username = username
        return response

    async def list_channels(self, offset: int = 0) -> dict:
        """Fetch the list of available channels."""
        self._require_session()
        data, handle = proto.list_channels_request(self.session, offset)
        return await self._request(data, handle)

    async def list_users(self) -> dict:
        """Fetch the list of connected users."""
        self._require_session()
        data, handle = proto.list_users_request(self.session)
        return await self._request(data, handle)

    async def whoami(self) -> dict:
        """Get your own current username."""
        self._require_session()
        data, handle = proto.whoami_request(self.session)
        return await self._request(data, handle)

    async def user_info(self, username: str) -> dict:
        """Get information about a specific user (WHOIS)."""
        self._require_session()
        data, handle = proto.whois_request(self.session, username)
        return await self._request(data, handle)

    async def channel_info(self, channel: str) -> dict:
        """Get information about a specific channel."""
        self._require_session()
        data, handle = proto.channel_info_request(self.session, channel)
        return await self._request(data, handle)

    async def join_channel(self, channel: str) -> dict:
        """Join a channel."""
        self._require_session()
        data, handle = proto.join_channel_request(self.session, channel)
        return await self._request(data, handle)

    async def leave_channel(self, channel: str) -> dict:
        """Leave a channel."""
        self._require_session()
        data, handle = proto.leave_channel_request(self.session, channel)
        return await self._request(data, handle)

    async def send_message(self, channel: str, message: str) -> dict:
        """Send a message to a channel."""
        self._require_session()
        data, handle = proto.send_message_request(self.session, channel, message)
        return await self._request(data, handle)

    async def send_dm(self, recipient: str, message: str) -> dict:
        """Send a direct message to another user."""
        self._require_session()
        data, handle = proto.send_dm_request(self.session, recipient, message)
        return await self._request(data, handle)

    async def create_channel(self, channel: str, description: str = '') -> dict:
        """Create a new channel."""
        self._require_session()
        data, handle = proto.create_channel_request(
            self.session, channel, description
        )
        return await self._request(data, handle)

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _require_session(self) -> None:
        if not self.session:
            raise RuntimeError('Not connected — call connect() first.')

    async def _request(
        self, data: bytes, handle: int, timeout: float = 5.0
    ) -> dict:
        """Send *data* to the server and await the matching response."""
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._pending[handle] = future

        try:
            self._send_raw(data)
            return await asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            raise asyncio.TimeoutError(
                f'No response from server (handle={handle})'
            )
        finally:
            self._pending.pop(handle, None)

    def _send_raw(self, payload: bytes) -> None:
        """Wrap *payload* in WireGuard transport if needed, then send."""
        if self.use_encryption and self._wg_session:
            packet = encrypt_transport(self._wg_session, payload)
        else:
            packet = payload
        self._sock.sendto(packet, self._server_addr)

    def _dispatch(self, msg: dict) -> None:
        """Route a decoded server message to a pending future or a callback."""
        response_handle = msg.get('response_handle')

        if response_handle and response_handle in self._pending:
            future = self._pending[response_handle]
            if not future.done():
                future.set_result(msg)
        else:
            # Server-pushed notification (no matching request)
            for cb in self._callbacks:
                try:
                    cb(msg)
                except Exception:
                    logger.exception('Exception in message callback')

    # -----------------------------------------------------------------------
    # Background loops
    # -----------------------------------------------------------------------

    async def _receive_loop(self) -> None:
        """Continuously receive UDP packets and process them."""
        loop = asyncio.get_running_loop()
        while self._running:
            try:
                data = await loop.sock_recv(self._sock, UDP_BUFFER_SIZE)
            except (asyncio.CancelledError, OSError):
                break
            except Exception:
                logger.exception('Error in receive loop')
                continue

            try:
                if self.use_encryption and self._wg_session:
                    if len(data) < 1:
                        continue
                    if data[0] == MSG_TRANSPORT:
                        payload = decrypt_transport(self._wg_session, data)
                    else:
                        logger.warning(
                            'Unexpected WireGuard message type %d', data[0]
                        )
                        continue
                else:
                    payload = data

                msg = proto.decode(payload)
                self._dispatch(msg)
            except Exception:
                logger.exception('Failed to process incoming packet')

    async def _ping_loop(self) -> None:
        """Send a PING every PING_INTERVAL seconds (fire-and-forget)."""
        while self._running:
            await asyncio.sleep(PING_INTERVAL)
            if not self._running or not self.session:
                break
            try:
                self._send_ping()
            except Exception:
                logger.exception('Error sending PING')

    def _send_ping(self) -> None:
        """Build and send a PING without waiting for a response."""
        data, _handle = proto.ping_request(self.session)
        self._send_raw(data)
        # No pending entry created — pings are fire-and-forget.

    # -----------------------------------------------------------------------
    # WireGuard handshake
    # -----------------------------------------------------------------------

    async def _wireguard_handshake(self, loop: asyncio.AbstractEventLoop) -> None:
        """Perform the simplified WireGuard handshake with the server."""
        if not self.client_static_private or not self.client_static_public:
            raise ValueError(
                'client_static_private and client_static_public are required '
                'for the encrypted endpoint.'
            )

        # Build and send initiation
        (init_msg, sender_index,
         e_priv, e_pub,
         chain_key, h) = build_initiation(
            self.client_static_private,
            self.client_static_public,
        )
        self._sock.sendto(init_msg, self._server_addr)
        logger.debug('Sent WireGuard initiation (sender_index=%d)', sender_index)

        # Wait for response (allow up to 5 seconds)
        deadline = loop.time() + 5.0
        while loop.time() < deadline:
            remaining = deadline - loop.time()
            try:
                response_data = await asyncio.wait_for(
                    loop.sock_recv(self._sock, UDP_BUFFER_SIZE),
                    timeout=remaining,
                )
            except asyncio.TimeoutError:
                raise ConnectionError(
                    'WireGuard handshake timed out waiting for response'
                )

            if len(response_data) >= 1 and response_data[0] == MSG_RESPONSE:
                break
        else:
            raise ConnectionError('WireGuard handshake failed')

        # Process response and derive transport keys
        self._wg_session = consume_response(
            response_data,
            self.client_static_private,
            e_priv,
            e_pub,
            chain_key,
            h,
        )
        logger.debug(
            'WireGuard handshake complete '
            '(remote_index=%d)', self._wg_session.remote_index
        )

    # -----------------------------------------------------------------------
    # Cleanup
    # -----------------------------------------------------------------------

    async def _shutdown(self) -> None:
        """Cancel background tasks and close the socket."""
        self._running = False

        for task in self._tasks:
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()

        if self._sock:
            self._sock.close()
            self._sock = None

        self.session = None
        self._wg_session = None
