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

    # Channels list
    if 'channels' in data:
        table = Table(title='Channels', box=box.SIMPLE)
        table.add_column('Name', style='bold cyan')
        table.add_column('Description')
        table.add_column('Members', justify='right')
        for ch in data['channels']:
            if isinstance(ch, dict):
                name  = str(ch.get('name', ''))
                desc  = str(ch.get('description', ''))
                count = str(ch.get('member_count', ch.get('members', '')))
                table.add_row(name, desc, count)
            else:
                table.add_row(str(ch), '', '')
        console.print(table)
        return

    # Users list
    if 'users' in data:
        table = Table(title='Connected Users', box=box.SIMPLE)
        table.add_column('Username', style='bold green')
        table.add_column('Info')
        for user in data['users']:
            if isinstance(user, dict):
                table.add_row(str(user.get('username', '')),
                              str(user.get('info', '')))
            else:
                table.add_row(str(user), '')
        console.print(table)
        return

    # Channel info
    if 'channel' in data and 'description' in data:
        panel_text = (
            f"[bold]Channel:[/bold] {data['channel']}\n"
            f"[bold]Description:[/bold] {data.get('description', '')}\n"
        )
        if 'members' in data:
            members = ', '.join(str(m) for m in data['members'])
            panel_text += f"[bold]Members:[/bold] {members}"
        console.print(Panel(panel_text, title='Channel Info'))
        return

    # User info
    if 'username' in data and ('info' in data or 'joined' in data):
        panel_text = f"[bold]Username:[/bold] {data['username']}\n"
        for k, v in data.items():
            if k not in ('username', 'response_handle', 'request_handle'):
                panel_text += f"[bold]{k}:[/bold] {v}\n"
        console.print(Panel(panel_text, title='User Info'))
        return

    # Generic key-value output
    filtered = {
        k: v for k, v in data.items()
        if k not in ('response_handle',)
    }
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
        msg_type = msg.get('type') or msg.get('message_type') or ''

        # Channel message
        if 'channel' in msg and 'message' in msg and 'sender' in msg:
            channel = msg['channel']
            sender  = msg['sender']
            text    = msg['message']
            console.print(
                f'[bold magenta][{channel}][/bold magenta] '
                f'[bold]{sender}[/bold]: {text}'
            )
            return

        # Direct message
        if 'message' in msg and 'sender' in msg and 'channel' not in msg:
            sender = msg['sender']
            text   = msg['message']
            console.print(
                f'[bold yellow][DM from {sender}][/bold yellow]: {text}'
            )
            return

        # User joined/left a channel
        if 'joined' in msg or 'left' in msg:
            action  = 'joined' if 'joined' in msg else 'left'
            who     = msg.get('user', msg.get('username', '?'))
            channel = msg.get('channel', '?')
            console.print(
                f'[dim]* {who} {action} #{channel}[/dim]'
            )
            return

        # Fallback
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
