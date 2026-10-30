"""Running the castle silently in the background: pid file, stop flag, process checks.

A running server also holds the gate, an OS lock on a file in the state folder.
The system lets go of it when the process dies, however that happens, so unlike
a pid - which can come back as some other program - it cannot go stale.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from .config import Config

# Windows process creation flags
DETACHED_PROCESS = 0x00000008
CREATE_NEW_PROCESS_GROUP = 0x00000200
CREATE_BREAKAWAY_FROM_JOB = 0x01000000


def pid_path(config: Config) -> Path:
    return config.state_dir / "castle.pid"


def stop_path(config: Config) -> Path:
    return config.state_dir / "castle.stop"


def log_path(config: Config) -> Path:
    return config.state_dir / "castle.log"


def gate_path(config: Config) -> Path:
    return config.state_dir / "castle.gate"


def _lock_gate(gate: BinaryIO) -> bool:
    """Try to take the lock; never waits."""
    try:
        if os.name == "nt":
            import msvcrt

            gate.seek(0)
            msvcrt.locking(gate.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(gate, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock_gate(gate: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        with contextlib.suppress(OSError):
            gate.seek(0)
            msvcrt.locking(gate.fileno(), msvcrt.LK_UNLCK, 1)
    gate.close()


@contextlib.contextmanager
def holding_gate(config: Config) -> Iterator[None]:
    """Claim the castle for this process, or raise OSError if a server already holds it."""
    with gate_path(config).open("ab") as gate:
        if not _lock_gate(gate):
            raise OSError("another castle is already running from this folder")
        try:
            yield
        finally:
            _unlock_gate(gate)


def gate_held(config: Config) -> bool:
    with gate_path(config).open("ab") as gate:
        if not _lock_gate(gate):
            return True
        _unlock_gate(gate)
        return False


def pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        # os.kill(pid, 0) would send CTRL_C_EVENT on Windows, so ask the kernel instead.
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            return bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def running(config: Config) -> tuple[int, str] | None:
    """(pid, "host:port") of a running castle server, or None (stale pid files are removed)."""
    path = pid_path(config)
    try:
        fields = path.read_text("utf-8").split()
        pid, address = int(fields[0]), fields[1]
    except (OSError, ValueError, IndexError):
        return None
    if pid_alive(pid) and gate_held(config):
        return pid, address
    path.unlink(missing_ok=True)
    return None


def running_pid(config: Config) -> int | None:
    found = running(config)
    return found[0] if found else None


def write_pid(config: Config, host: str, port: int) -> None:
    pid_path(config).write_text(f"{os.getpid()} {host}:{port}\n", "utf-8")


def clear_pid(config: Config) -> None:
    try:
        if int(pid_path(config).read_text("utf-8").split()[0]) == os.getpid():
            pid_path(config).unlink()
    except (OSError, ValueError, IndexError):
        pass


def launch_background(config: Config, extra_args: list[str]) -> subprocess.Popen:
    """Start 'redcastle serve --quiet' detached from this terminal, without a window."""
    stop_path(config).unlink(missing_ok=True)
    executable = sys.executable
    kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "cwd": str(config.state_dir),  # with -P below: nothing is ever loaded from a folder others can write to
        "close_fds": True,
    }
    if os.name == "nt":
        windowless = Path(executable).with_name("pythonw.exe")
        if windowless.exists():
            executable = str(windowless)
    else:
        kwargs["start_new_session"] = True
    # Make sure the child finds this package even when it is run from a source checkout.
    package_parent = str(Path(__file__).resolve().parent.parent)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in (package_parent, env.get("PYTHONPATH")) if p)
    kwargs["env"] = env
    command = [executable, "-P", "-m", "redcastle", "--root", str(config.root), "serve", "--quiet", *extra_args]
    if os.name != "nt":
        return subprocess.Popen(command, **kwargs)
    flags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    try:
        # Outlive the terminal (or IDE) that started us, if its job object allows it.
        return subprocess.Popen(command, creationflags=flags | CREATE_BREAKAWAY_FROM_JOB, **kwargs)
    except OSError:
        return subprocess.Popen(command, creationflags=flags, **kwargs)


def stop(config: Config, timeout: float = 15) -> str:
    """Ask the background castle to close; force it after ``timeout`` seconds.

    Returns "not running", "stopped" or "killed".
    """
    pid = running_pid(config)
    if pid is None:
        return "not running"
    stop_path(config).write_text("stop\n", "utf-8")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            stop_path(config).unlink(missing_ok=True)
            return "stopped"
        time.sleep(0.25)
    if running_pid(config) != pid:  # let go of the gate in the meantime
        stop_path(config).unlink(missing_ok=True)
        return "stopped"
    with contextlib.suppress(OSError):  # it may just have exited
        os.kill(pid, getattr(signal, "SIGKILL", signal.SIGTERM))  # Windows has no SIGKILL; there SIGTERM is final
    stop_path(config).unlink(missing_ok=True)
    pid_path(config).unlink(missing_ok=True)
    return "killed"
