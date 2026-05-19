"""
Command-line user interface for the CSC4026Z chat client.

Supported commands
==================
/connect [username]         — Connect to the server (optionally set username)
/disconnect                 — Disconnect from the server
/username <name>            — Change your username
/channels                   — List available channels
/users                      — List connected users
/userinfo <name>            — Get info about a user
/channelinfo <channel>      — Get info about a channel
/join <channel>             — Join a channel
/leave <channel>            — Leave a channel
/create <channel> [desc]    — Create a new channel
/msg <channel> <text>       — Send a message to a channel
/dm <user> <text>           — Send a direct message to a user
/help                       — Show this help text
/quit                       — Quit the application

While connected to a channel you can also type plain text to send a message
to your *current* channel (set with /join).
"""

import asyncio
import logging
import sys
from dataclasses import dataclass, field
from typing import Callable, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from .client import ChatClient

logger = logging.getLogger(__name__)
console = Console()


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _print_error(msg: str) -> None:
    console.print(f'[bold red]Error:[/bold red] {msg}')


def _print_info(msg: str) -> None:
    console.print(f'[bold cyan]Info:[/bold cyan] {msg}')


def _print_success(msg: str) -> None:
    console.print(f'[bold green]OK:[/bold green] {msg}')


def _render_response(data: dict) -> None:
    """Render a generic server response dict in a human-friendly way."""
    if 'error' in data:
        _print_error(str(data['error']))
        return

    rtype = data.get('response_type')

    # Channels list (CHANNEL_LIST response_type=26)
    if rtype == 26 or 'channels' in data:
        table = Table(title='Channels', box=box.SIMPLE)
        table.add_column('Name', style='bold cyan')
        for ch in data.get('channels', []):
            table.add_row(str(ch))
        if data.get('next_page'):
            table.add_row('[dim]… more pages[/dim]')
        console.print(table)
        return

    # Users list (USER_LIST response_type=35)
    if rtype == 35 or 'users' in data:
        table = Table(title='Connected Users', box=box.SIMPLE)
        table.add_column('Username', style='bold green')
        for user in data.get('users', []):
            table.add_row(str(user))
        if data.get('next_page'):
            table.add_row('[dim]… more pages[/dim]')
        console.print(table)
        return

    # Channel info (CHANNEL_INFO response_type=27)
    if rtype == 27:
        members = ', '.join(str(m) for m in data.get('members', []))
        panel_text = (
            f"[bold]Channel:[/bold] {data.get('channel', '')}\n"
            f"[bold]Description:[/bold] {data.get('description', '')}\n"
            f"[bold]Members:[/bold] {members}"
        )
        console.print(Panel(panel_text, title='Channel Info'))
        return

    # WHOIS (response_type=31)
    if rtype == 31:
        channels = ', '.join(str(c) for c in data.get('channels', []))
        panel_text = (
            f"[bold]Username:[/bold] {data.get('username', '')}\n"
            f"[bold]Transport:[/bold] {data.get('transport', '')}\n"
            f"[bold]Channels:[/bold] {channels}\n"
        )
        pub_key = data.get('wireguard_public_key', '')
        if pub_key:
            panel_text += f"[bold]WireGuard key:[/bold] {pub_key}\n"
        console.print(Panel(panel_text, title='User Info'))
        return

    # WHOAMI (response_type=32)
    if rtype == 32:
        _print_info(f"Your username: {data.get('username', '?')}")
        return

    # SET_USERNAME (response_type=34)
    if rtype == 34:
        _print_success(
            f"Username changed: {data.get('old_username')} → {data.get('new_username')}"
        )
        return

    # CHANNEL_CREATE (response_type=25)
    if rtype == 25:
        _print_success(
            f"Channel #{data.get('channel')} created. "
            f"Description: {data.get('description', '')}"
        )
        return

    # Generic key-value fallback
    filtered = {k: v for k, v in data.items() if k != 'response_handle'}
    if filtered:
        console.print(filtered)


# ---------------------------------------------------------------------------
# Mutable UI state
# ---------------------------------------------------------------------------

@dataclass
class UIState:
    """Holds mutable state shared between the UI and notification callbacks."""
    current_channel: Optional[str] = None


# ---------------------------------------------------------------------------
# Server-push notification handler
# ---------------------------------------------------------------------------

def make_notification_handler(state: 'UIState') -> Callable[[dict], None]:
    """Return a callback that pretty-prints unsolicited server messages."""
    def handler(msg: dict) -> None:
        rtype = msg.get('response_type')

        # CHANNEL_MESSAGE (30) — unsolicited when others post
        if rtype == 30:
            console.print(
                f'[bold magenta][#{msg.get("channel")}][/bold magenta] '
                f'[bold]{msg.get("username")}[/bold]: {msg.get("message")}'
            )
            return

        # USER_MESSAGE / DM (33) — unsolicited for recipient
        if rtype == 33:
            console.print(
                f'[bold yellow][DM from {msg.get("from_username")}][/bold yellow]'
                f': {msg.get("message")}'
            )
            return

        # CHANNEL_JOIN (28) — unsolicited when another user joins
        if rtype == 28:
            console.print(
                f'[dim]* {msg.get("username")} joined #{msg.get("channel")}[/dim]'
            )
            return

        # CHANNEL_LEAVE (29) — unsolicited when another user leaves
        if rtype == 29:
            console.print(
                f'[dim]* {msg.get("username")} left #{msg.get("channel")}[/dim]'
            )
            return

        # SET_USERNAME (34) — unsolicited when another user in your channel renames
        if rtype == 34:
            console.print(
                f'[dim]* {msg.get("old_username")} is now known as '
                f'{msg.get("new_username")}[/dim]'
            )
            return

        # SERVER_MESSAGE (36)
        if rtype == 36:
            console.print(
                f'[bold blue][Server][/bold blue] {msg.get("message")}'
            )
            return

        # SERVER_SHUTDOWN (37)
        if rtype == 37:
            console.print(
                f'[bold red][Server shutting down][/bold red] {msg.get("message")}'
            )
            return

        # Silence PING responses (24) — fire-and-forget, no display needed
        if rtype == 24:
            return

        # Fallback for anything unrecognised
        if msg:
            console.print(f'[dim]Server: {msg}[/dim]')

    return handler


# ---------------------------------------------------------------------------
# Command parser and dispatcher
# ---------------------------------------------------------------------------

async def handle_command(
    line: str,
    client: ChatClient,
    state: UIState,
) -> bool:
    """Parse and dispatch a single input line.

    Returns:
        True to keep running, False to quit.
    """
    line = line.strip()
    if not line:
        return True

    # Non-command: send to current channel
    if not line.startswith('/'):
        if state.current_channel:
            try:
                await client.send_message(state.current_channel, line)
            except Exception as exc:
                _print_error(str(exc))
        else:
            _print_error(
                'Not in a channel.  Use /join <channel> first, '
                'or /msg <channel> <text>.'
            )
        return True

    # --- Commands ---
    parts = line.split(maxsplit=2)
    cmd   = parts[0].lower()

    if cmd in ('/quit', '/exit', '/q'):
        return False

    if cmd == '/help':
        console.print(Panel(__doc__, title='Help', border_style='blue'))
        return True

    if cmd == '/connect':
        username = parts[1] if len(parts) > 1 else None
        try:
            resp = await client.connect(username)
            _print_success(f'Connected. Session={resp.get("session")}')
            if username:
                _print_success(f'Username set to {username!r}')
        except Exception as exc:
            _print_error(f'Connect failed: {exc}')
        return True

    if cmd == '/disconnect':
        try:
            await client.disconnect()
            _print_info('Disconnected.')
        except Exception as exc:
            _print_error(str(exc))
        return True

    if cmd == '/username':
        if len(parts) < 2:
            _print_error('Usage: /username <name>')
            return True
        try:
            resp = await client.set_username(parts[1])
            _print_success(f'Username changed to {parts[1]!r}')
            _render_response(resp)
        except Exception as exc:
            _print_error(str(exc))
        return True

    if cmd == '/channels':
        try:
            resp = await client.list_channels()
            _render_response(resp)
        except Exception as exc:
            _print_error(str(exc))
        return True

    if cmd == '/users':
        try:
            resp = await client.list_users()
            _render_response(resp)
        except Exception as exc:
            _print_error(str(exc))
        return True

    if cmd == '/userinfo':
        if len(parts) < 2:
            _print_error('Usage: /userinfo <username>')
            return True
        try:
            resp = await client.user_info(parts[1])
            _render_response(resp)
        except Exception as exc:
            _print_error(str(exc))
        return True

    if cmd == '/channelinfo':
        if len(parts) < 2:
            _print_error('Usage: /channelinfo <channel>')
            return True
        try:
            resp = await client.channel_info(parts[1])
            _render_response(resp)
        except Exception as exc:
            _print_error(str(exc))
        return True

    if cmd == '/join':
        if len(parts) < 2:
            _print_error('Usage: /join <channel>')
            return True
        channel = parts[1]
        try:
            resp = await client.join_channel(channel)
            state.current_channel = channel
            _print_success(f'Joined #{channel}')
            _render_response(resp)
        except Exception as exc:
            _print_error(str(exc))
        return True

    if cmd == '/leave':
        if len(parts) < 2:
            if state.current_channel:
                channel = state.current_channel
            else:
                _print_error('Usage: /leave <channel>')
                return True
        else:
            channel = parts[1]
        try:
            resp = await client.leave_channel(channel)
            if state.current_channel == channel:
                state.current_channel = None
            _print_success(f'Left #{channel}')
            _render_response(resp)
        except Exception as exc:
            _print_error(str(exc))
        return True

    if cmd == '/create':
        if len(parts) < 2:
            _print_error('Usage: /create <channel> [description]')
            return True
        channel = parts[1]
        desc    = parts[2] if len(parts) > 2 else ''
        try:
            resp = await client.create_channel(channel, desc)
            _print_success(f'Channel #{channel} created')
            _render_response(resp)
        except Exception as exc:
            _print_error(str(exc))
        return True

    if cmd == '/msg':
        # /msg <channel> <text>
        if len(parts) < 3:
            _print_error('Usage: /msg <channel> <text>')
            return True
        channel = parts[1]
        text    = parts[2]
        try:
            await client.send_message(channel, text)
        except Exception as exc:
            _print_error(str(exc))
        return True

    if cmd == '/dm':
        # /dm <user> <text>
        if len(parts) < 3:
            _print_error('Usage: /dm <user> <text>')
            return True
        user = parts[1]
        text = parts[2]
        try:
            await client.send_dm(user, text)
        except Exception as exc:
            _print_error(str(exc))
        return True

    _print_error(f'Unknown command {cmd!r}.  Type /help for help.')
    return True


# ---------------------------------------------------------------------------
# Main input loop
# ---------------------------------------------------------------------------

async def run_ui(client: ChatClient) -> None:
    """Run the interactive UI event loop.

    Reads lines from stdin using a thread executor so the event loop is not
    blocked.
    """
    loop  = asyncio.get_running_loop()
    state = UIState()

    # Register the server-push notification handler
    client.on_message(make_notification_handler(state))

    console.print(
        Panel(
            '[bold cyan]CSC4026Z Chat Client[/bold cyan]\n'
            'Type [bold]/help[/bold] for a list of commands.\n'
            'Type [bold]/connect [username][/bold] to start.',
            border_style='cyan',
        )
    )

    def _prompt() -> str:
        channel = state.current_channel
        prefix  = f'[#{channel}] ' if channel else ''
        return f'{prefix}> '

    while True:
        try:
            # Read a line without blocking the event loop
            line = await loop.run_in_executor(None, input, _prompt())
        except (EOFError, KeyboardInterrupt):
            console.print('\n[dim]Exiting…[/dim]')
            break

        keep_going = await handle_command(line, client, state)
        if not keep_going:
            break

    # Clean up
    if client.session:
        await client.disconnect()
