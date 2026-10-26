"""The welcome screen: what greets you when you found or visit a castle."""

from __future__ import annotations

import os
import sys
from typing import TextIO

TITLE = [
    "██████╗ ███████╗██████╗     ██████╗ █████╗ ███████╗████████╗██╗     ███████╗",
    "██╔══██╗██╔════╝██╔══██╗   ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██║     ██╔════╝",
    "██████╔╝█████╗  ██║  ██║   ██║     ███████║███████╗   ██║   ██║     █████╗",
    "██╔══██╗██╔══╝  ██║  ██║   ██║     ██╔══██║╚════██║   ██║   ██║     ██╔══╝",
    "██║  ██║███████╗██████╔╝   ╚██████╗██║  ██║███████║   ██║   ███████╗███████╗",
    "╚═╝  ╚═╝╚══════╝╚═════╝     ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝",
]
ASCII_TITLE = ["R E D   C A S T L E"]

CASTLE = [
    r"            /\ ",
    r"           /##\ ",
    r"          /####\ ",
    r"         |######|",
    r"         |#|  |#|",
    r"      /\ |#|  |#| /\ ",
    r"     /##\|#|  |#|/##\ ",
    r"    |####|_|__|_|####|",
    r"    |  |_|_|  |_|_|  |",
    r" ___|_|  |  /\  |  |_|___",
    r"|  _   _ | /  \ | _   _  |",
    r"| | | | ||/    \|| | | | |",
    r"| |_| |_||      ||_| |_| |",
    r"   /____||______||____\ ",
]

TAGLINE = "AI agents may ask to delete things. Only a human decides."


class Style:
    def __init__(self, color: bool) -> None:
        self.color = color

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def red(self, text: str) -> str:
        return self._wrap("1;31", text)

    def dim(self, text: str) -> str:
        return self._wrap("90", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def cyan(self, text: str) -> str:
        return self._wrap("36", text)


def supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") or not getattr(stream, "isatty", lambda: False)():
        return False
    if os.name != "nt":
        return os.environ.get("TERM") != "dumb"
    try:  # switch the Windows console into ANSI mode
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))  # VIRTUAL_TERMINAL_PROCESSING
    except Exception:  # noqa: BLE001
        return False


def _can_encode(stream: TextIO, text: str) -> bool:
    try:
        text.encode(getattr(stream, "encoding", None) or "ascii")
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def art(style: Style, stream: TextIO) -> str:
    """The title in block letters with the castle beneath it."""
    title = TITLE if _can_encode(stream, TITLE[0]) else ASCII_TITLE
    width = max(len(line) for line in title)
    castle_indent = " " * max(0, (width - len(CASTLE[10])) // 2)
    lines = [style.red(line) for line in title]
    lines.append("")
    lines.extend(style.dim(castle_indent + line.rstrip()) for line in CASTLE)
    lines.append("")
    lines.append(style.bold(TAGLINE.center(width).rstrip()))
    return "\n".join(lines)


def _commands(style: Style, prog: str, rows: list[tuple[str, str]], width: int = 0) -> list[str]:
    width = width or max(len(f"{prog} {command}") for command, _ in rows)
    return [f"    {style.cyan(f'{prog} {command}'.ljust(width))}   {text}" for command, text in rows]


def welcome(prog: str, *, castle_here: bool, stream: TextIO | None = None) -> str:
    """The screen shown when the command is run without arguments."""
    stream = stream or sys.stdout
    style = Style(supports_color(stream))
    lines = [art(style, stream), ""]
    if castle_here:
        lines.append(style.bold("  A castle stands here."))
        lines += _commands(style, prog, [
            ("status", "is it running, what awaits you, is the Chronicle intact"),
            ("start / stop", "run silently in the background, or close the gates"),
            ("throne review", "decide on quarantined objects, case by case"),
            ("agent add <name>", "register another agent and get its token"),
            ("chronicle show -f", "watch every decision as it happens"),
        ])
    else:
        start = [
            ("init", "found a castle in this folder"),
            ("agent add <name>", "register an agent and get its token"),
            ("start", "run silently in the background"),
            ("notify test", "check that desktop notifications reach you"),
        ]
        decide = [
            ("throne review", "approve, restore or freeze - case by case"),
            ("status", "what is running and what awaits you"),
        ]
        width = max(len(f"{prog} {command}") for command, _ in start + decide)
        lines.append(style.bold("  Getting started"))
        lines += _commands(style, prog, start, width)
        lines.append("")
        lines.append(style.bold("  When a notification arrives"))
        lines += _commands(style, prog, decide, width)
    lines.append("")
    lines.append(f"  Try it without risk: {style.cyan(f'{prog} demo')}    All commands: {style.cyan(f'{prog} --help')}")
    return "\n".join(lines)


def founded(prog: str, root: str, realm: str, state: str, *, stream: TextIO | None = None) -> str:
    """The screen shown right after 'init'."""
    stream = stream or sys.stdout
    style = Style(supports_color(stream))
    lines = [
        art(style, stream),
        "",
        style.bold("  Your castle is founded."),
        f"    castle   {root}",
        f"    realm    {realm}   {style.dim('(what agents can see and ask to delete)')}",
        f"    state    {state}   {style.dim('(database, keys, quarantine, log - keep it private)')}",
        "",
        style.bold("  Configure it") + style.dim("  - edit redcastle.toml"),
        f"    {style.cyan('[storage]')}   a folder on disk (default) or an S3 bucket",
        f"    {style.cyan('[moat]')}      objects that can never be deleted, rate limits",
        f"    {style.cyan('[judge]')}     which paths count as risky, and how risky",
        f"    {style.cyan('[notify]')}    when the castle notifies you",
        "",
        style.bold("  Next steps"),
        *_commands(style, prog, [
            ("agent add <name>", "register an agent and get its token"),
            ('traps plant "backups/passwords.txt"', "plant a canary no honest agent would touch"),
            ("start", "run silently in the background"),
            ("notify test", "check that desktop notifications reach you"),
        ]),
        "",
        f"  Then connect your agent over HTTP or MCP - see the README.    All commands: {style.cyan(f'{prog} --help')}",
    ]
    return "\n".join(lines)
