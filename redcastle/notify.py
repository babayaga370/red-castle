"""Desktop notifications: the Watchtower's horn.

The castle runs silently and only makes a sound when a human is needed: an
object awaits judgement, an alert is raised, or decisions have waited too long.
Bursts are gathered into one notification so a busy agent does not flood the
screen.

Windows uses native toast notifications through Windows PowerShell, macOS uses
``osascript`` and Linux ``notify-send``. No extra packages are needed. Set the
environment variable ``REDCASTLE_NOTIFY=off`` to write notifications to the log
instead (useful for CI).
"""

from __future__ import annotations

import base64
import html
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable

from .config import NotifyConfig

log = logging.getLogger("redcastle.notify")

# (title, line 1, line 2, urgent) -> None
Sender = Callable[[str, str, str, bool], None]

SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}
REVIEW_HINT = "Run: redcastle throne review"
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")

# The AppUserModelID of Windows PowerShell - registered on every Windows 10/11
# machine, so toasts can be shown without installing a shortcut.
_WINDOWS_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
_CREATE_NO_WINDOW = 0x08000000

# The texts arrive through environment variables and are XML-escaped here, so
# nothing an agent writes (an object key, say) can inject markup or code.
_WINDOWS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] > $null
function esc($s) { [System.Security.SecurityElement]::Escape([string]$s) }
$scenario = ''
if ($env:RC_URGENT -eq '1') { $scenario = ' scenario="urgent"' }
$xml = '<toast' + $scenario + '><visual><binding template="ToastGeneric">' +
       '<text>' + (esc $env:RC_TITLE) + '</text>' +
       '<text>' + (esc $env:RC_LINE1) + '</text>' +
       '<text>' + (esc $env:RC_LINE2) + '</text>' +
       '</binding></visual></toast>'
$doc = New-Object Windows.Data.Xml.Dom.XmlDocument
$doc.LoadXml($xml)
$toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:RC_APPID).Show($toast)
"""


def _clean(text: str, limit: int = 180) -> str:
    text = _CONTROL.sub(" ", text).strip()
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _windows_toast(title: str, line1: str, line2: str, urgent: bool) -> None:
    script = base64.b64encode(_WINDOWS_SCRIPT.encode("utf-16-le")).decode("ascii")
    env = dict(os.environ)
    env.update(RC_TITLE=title, RC_LINE1=line1, RC_LINE2=line2, RC_URGENT="1" if urgent else "0", RC_APPID=_WINDOWS_APP_ID)
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", script],
        env=env, capture_output=True, timeout=30, creationflags=_CREATE_NO_WINDOW, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode("utf-8", "replace").strip() or f"exit code {result.returncode}")


def _macos_notification(title: str, line1: str, line2: str, urgent: bool) -> None:
    script = [
        "-e", "on run argv",
        "-e", "display notification (item 3 of argv) with title (item 1 of argv) subtitle (item 2 of argv)",
        "-e", "end run",
    ]
    subprocess.run(["osascript", *script, title, line1, line2], capture_output=True, timeout=30, check=True)


def _linux_notification(title: str, line1: str, line2: str, urgent: bool) -> None:
    body = html.escape("\n".join(x for x in (line1, line2) if x))  # notify-send understands some markup
    subprocess.run(
        ["notify-send", "-a", "Red Castle", "-u", "critical" if urgent else "normal", title, body],
        capture_output=True, timeout=30, check=True,
    )


def _log_only(title: str, line1: str, line2: str, urgent: bool) -> None:
    log.warning("NOTIFY%s: %s | %s | %s", " (urgent)" if urgent else "", title, line1, line2)


def desktop_sender() -> Sender:
    """The best way to reach a human on this machine."""
    if os.environ.get("REDCASTLE_NOTIFY", "").lower() in {"off", "0", "false", "log"}:
        return _log_only
    if sys.platform == "win32" and shutil.which("powershell.exe"):
        return _windows_toast
    if sys.platform == "darwin" and shutil.which("osascript"):
        return _macos_notification
    if shutil.which("notify-send"):
        return _linux_notification
    return _log_only


class Notifier:
    def __init__(self, config: NotifyConfig, sender: Sender | None = None) -> None:
        self.config = config
        self.sender = sender or desktop_sender()
        self._lock = threading.Lock()
        self._alerts: list[tuple[str, str]] = []   # (severity, message)
        self._awaiting: list[dict] = []            # quarantined cases
        self._timer: threading.Timer | None = None
        self._last_reminder = 0.0

    # -- what the Watchtower reports -------------------------------------------

    def alert(self, severity: str, message: str) -> None:
        threshold = SEVERITY_RANK.get(self.config.min_severity, 1)
        if self.config.enabled and SEVERITY_RANK.get(severity, 1) >= threshold:
            self._queue(lambda: self._alerts.append((severity, message)))

    def awaiting(self, case: dict) -> None:
        if self.config.enabled and self.config.on_quarantine:
            self._queue(lambda: self._awaiting.append(case))

    def remind(self, pending: list[dict], now: float | None = None) -> bool:
        """Remind the human about cases that have waited longer than the interval."""
        interval = self.config.remind_interval_minutes * 60
        if not self.config.enabled or interval <= 0 or not pending:
            return False
        now = time.time() if now is None else now
        waiting = [c for c in pending if now - c["created_at"] >= interval]
        if not waiting or now - self._last_reminder < interval:
            return False
        self._last_reminder = now
        minutes = self.config.remind_interval_minutes
        noun = "object has" if len(waiting) == 1 else "objects have"
        self._send("Red Castle: still waiting for you", f"{len(waiting)} {noun} waited over {minutes} min in quarantine.",
                   REVIEW_HINT, urgent=False)
        return True

    # -- batching -------------------------------------------------------------

    def _queue(self, add: Callable[[], None]) -> None:
        with self._lock:
            add()
            if self.config.batch_seconds > 0:
                if self._timer is None:
                    self._timer = threading.Timer(self.config.batch_seconds, self.flush)
                    self._timer.daemon = True
                    self._timer.start()
                return
        self.flush()

    def flush(self) -> None:
        """Send whatever has been gathered as one notification."""
        with self._lock:
            alerts, awaiting = self._alerts, self._awaiting
            self._alerts, self._awaiting = [], []
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        if alerts or awaiting:
            self._send(*compose(alerts, awaiting))

    def _send(self, title: str, line1: str, line2: str, urgent: bool) -> None:
        try:
            self.sender(_clean(title, 80), _clean(line1), _clean(line2), urgent)
        except Exception as exc:  # noqa: BLE001 - a failed notification must never break the castle
            log.warning("Could not show a notification (%s): %s - %s", exc, title, line1)


def compose(alerts: list[tuple[str, str]], awaiting: list[dict]) -> tuple[str, str, str, bool]:
    """Turn a batch into (title, line 1, line 2, urgent)."""
    urgent = any(severity == "critical" for severity, _ in alerts)
    if alerts and not awaiting:
        if len(alerts) == 1:
            return ("Red Castle: ALERT" if urgent else "Red Castle: warning"), alerts[0][1], REVIEW_HINT, urgent
        return f"Red Castle: {len(alerts)} alerts", alerts[0][1], f"+ {len(alerts) - 1} more - redcastle watchtower alerts", urgent
    if awaiting and not alerts:
        if len(awaiting) == 1:
            case = awaiting[0]
            flag = " - the agent UNDERESTIMATED the risk" if case.get("flag") == "underestimated" else ""
            return (
                "Red Castle: awaiting your judgement",
                f"{case['agent']} wants to delete {case['object_key']}",
                f"Judge risk {case['judge_score']} ({case['judge_level']}), agent said {case['agent_score']}{flag}. "
                + REVIEW_HINT,
                False,
            )
        agents = sorted({c["agent"] for c in awaiting})
        flagged = sum(1 for c in awaiting if c.get("flag") == "underestimated")
        extra = f", {flagged} with underestimated risk" if flagged else ""
        return (
            f"Red Castle: {len(awaiting)} objects await your judgement",
            f"From {', '.join(agents)}{extra}.",
            REVIEW_HINT,
            False,
        )
    noun = "object awaits" if len(awaiting) == 1 else "objects await"
    return (
        f"Red Castle: {len(alerts)} alert(s), {len(awaiting)} awaiting judgement",
        alerts[0][1],
        f"{len(awaiting)} {noun} your judgement. {REVIEW_HINT}",
        urgent,
    )
