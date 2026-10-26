"""Command line: found the castle, run it silently, and hold court in the terminal."""

from __future__ import annotations

import argparse
import getpass
import logging
import logging.handlers
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from . import __version__, banner, daemon
from .castle import Castle, found_castle
from .config import CONFIG_FILE, ConfigError, load_config, load_secrets
from .executioner import ExecutionRefused
from .gateway import GatewayError
from .registry import Status
from .throne import ThroneError
from .util import iso

log = logging.getLogger("redcastle.cli")


def _table(rows: list[list[Any]], headers: list[str], width: int = 48) -> str:
    def cell(value: Any) -> str:
        text = "" if value is None else str(value)
        return text if len(text) <= width else text[: width - 3] + "..."

    cells = [headers] + [[cell(v) for v in row] for row in rows]
    widths = [max(len(r[i]) for r in cells) for i in range(len(headers))]
    lines = ["  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in cells]
    lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)


def _age(ts: float) -> str:
    seconds = max(0, int(time.time() - ts))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def _open(args: argparse.Namespace) -> Castle:
    return Castle.open(args.root)


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        return "q"


# -- founding and agents --------------------------------------------------------


def _prog() -> str:
    """How the user started us, so the hints we print can be copied as they are."""
    return "python -m redcastle" if Path(sys.argv[0]).name == "__main__.py" else "redcastle"


def cmd_welcome(args: argparse.Namespace) -> int:
    castle_here = (Path(args.root) / CONFIG_FILE).exists() and load_config(args.root).secrets_path.exists()
    print(banner.welcome(_prog(), castle_here=castle_here))
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    with found_castle(args.root, realm=args.realm) as castle:
        cfg = castle.config
        where = cfg.realm_path if cfg.storage.backend == "local" else f"s3://{cfg.storage.bucket}/{cfg.storage.prefix}"
        print(banner.founded(_prog(), str(cfg.root), str(where), str(cfg.state_dir)))
    return 0


def cmd_agent_add(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        token = castle.registry.add_agent(args.name)
        castle.chronicle.record("castle", "agent.registered", agent=args.name)
    print(f"Agent '{args.name}' registered. Its token (shown only once):")
    print(f"  {token}")
    return 0


def cmd_agent_list(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        agents = castle.registry.list_agents()
    rows = [[a["name"], a["status"], iso(a["created_at"]), a["frozen_reason"]] for a in agents]
    print(_table(rows, ["AGENT", "STATUS", "REGISTERED", "FROZEN BECAUSE"], width=70) if rows else "No agents yet.")
    return 0


# -- running ----------------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    from .api import serve

    castle = _open(args)
    config = castle.config
    if args.quiet:
        handler = logging.handlers.RotatingFileHandler(
            daemon.log_path(config), maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)
    host = args.host or config.server.host
    port = args.port or config.server.port
    if not args.quiet:
        print(f"Red Castle is open. Gateway for agents: http://{host}:{port}/api/v1")
        print("Desktop notifications tell you when something needs you. Press Ctrl+C to close the gates.")
    try:
        serve(castle, host, port)
    except OSError as exc:
        log.error("Cannot open the gateway on %s:%d: %s", host, port, exc)
        if not args.quiet:
            print(f"error: cannot open the gateway on {host}:{port}: {exc}", file=sys.stderr)
        return 1
    finally:
        castle.close()
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    config = load_config(args.root)
    load_secrets(config.secrets_path)  # fail here, not silently in the background, if there is no castle
    found = daemon.running(config)
    if found:
        print(f"Red Castle is already running (pid {found[0]}) on http://{found[1]}.")
        return 0
    extra = []
    if args.host:
        extra += ["--host", args.host]
    if args.port:
        extra += ["--port", str(args.port)]
    process = daemon.launch_background(config, extra)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        found = daemon.running(config)
        if found:
            break
        if process.poll() is not None:
            break
        time.sleep(0.2)
    if not found:
        print("error: the castle did not start.", file=sys.stderr)
        log_file = daemon.log_path(config)
        if log_file.exists():
            tail = log_file.read_text("utf-8", "replace").splitlines()[-5:]
            print("Last lines of the log:", *("  " + line for line in tail), sep="\n", file=sys.stderr)
        return 1
    print(f"Red Castle is running silently in the background (pid {found[0]}).")
    print(f"  Gateway for agents: http://{found[1]}/api/v1")
    print(f"  Log:                {daemon.log_path(config)}")
    print("You will get a desktop notification when something needs you. Stop it with: redcastle stop")
    return 0


def cmd_stop(args: argparse.Namespace) -> int:
    outcome = daemon.stop(load_config(args.root))
    print({
        "not running": "Red Castle is not running.",
        "stopped": "Red Castle has closed its gates.",
        "killed": "Red Castle did not respond and was stopped forcibly.",
    }[outcome])
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        found = daemon.running(castle.config)
        pending = castle.throne.pending()
        agents = castle.registry.list_agents()
        since = time.time() - 86400
        alerts = [a for a in castle.watchtower.alerts(500) if a["ts"] and a["ts"] >= iso(since)]
        verification = castle.chronicle.verify()
    frozen = [a["name"] for a in agents if a["status"] == "frozen"]
    critical = sum(1 for a in alerts if a["severity"] == "critical")
    print("Castle:      " + (f"running silently (pid {found[0]}) on http://{found[1]}"
                             if found else "not running - start it with: redcastle start"))
    print(f"Quarantine:  {len(pending)} awaiting judgement" + (" - run: redcastle throne review" if pending else ""))
    print(f"Agents:      {len(agents)}" + (f", frozen: {', '.join(frozen)}" if frozen else ""))
    print(f"Alerts 24h:  {critical} critical, {len(alerts) - critical} other" + (
        " - see: redcastle watchtower alerts" if alerts else ""))
    print("Chronicle:   " + (f"intact ({verification.entries} entries)" if verification.ok
                             else f"BROKEN at entry {verification.broken_at}: {verification.problem}"))
    return 0 if verification.ok else 1


def cmd_mcp(args: argparse.Namespace) -> int:
    from .mcp_server import HttpAgentPort, LocalAgentPort, MCPServer

    token = args.agent_token or os.environ.get("REDCASTLE_AGENT_TOKEN")
    if not token:
        print("An agent token is required (REDCASTLE_AGENT_TOKEN or --agent-token).", file=sys.stderr)
        return 2
    if args.gateway:
        MCPServer(HttpAgentPort(args.gateway, token)).serve()
        return 0
    with _open(args) as castle:
        MCPServer(LocalAgentPort(castle, token)).serve()
    return 0


# -- the Throne Room ----------------------------------------------------------------


def _describe(case: dict) -> list[str]:
    size = f"{case['size']} bytes" if case["size"] is not None else "size unknown"
    lines = [
        f"Case {case['id']}  [{case['status']}]  {_age(case['created_at'])} ago",
        f"  object:     {case['object_key']}  ({size})",
        f"  agent:      {case['agent']}",
        f"  reason:     {case['reason']}",
    ]
    if case["judge_score"] is not None:
        flag = f"  <-- agent {case['flag'].upper()} the risk" if case["flag"] else ""
        lines.append(f"  risk:       agent {case['agent_score']}, Judge {case['judge_score']} ({case['judge_level']}){flag}")
        lines.extend(f"      {f['points']:+4d}  {f['why']}" for f in case["judge_factors"] or [])
    else:
        lines.append(f"  risk:       agent {case['agent_score']}")
    if case["status_reason"]:
        lines.append(f"  note:       {case['status_reason']}")
    if case["decided_by"]:
        note = f" - {case['decision_note']}" if case["decision_note"] else ""
        lines.append(f"  decided by: {case['decided_by']} at {iso(case['decided_at'])}{note}")
    return lines


def cmd_throne_list(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        status = None if args.status == "all" else args.status
        cases = castle.registry.list_requests(status=status, limit=args.limit, oldest_first=True)
    if not cases:
        print("The quarantine is empty." if status == Status.QUARANTINED else "Nothing here.")
        return 0
    rows = [
        [
            c["id"], c["agent"], c["object_key"], c["agent_score"],
            f"{c['judge_score']} {c['judge_level']}" if c["judge_score"] is not None else "",
            c["flag"] or "", c["status"], _age(c["created_at"]),
        ]
        for c in cases
    ]
    print(_table(rows, ["CASE", "AGENT", "OBJECT", "AGENT RISK", "JUDGE RISK", "FLAG", "STATUS", "AGE"]))
    return 0


def cmd_throne_show(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        case = castle.throne.case(args.id)
        entries = castle.chronicle.entries(100, request_id=args.id)
    print("\n".join(_describe(case)))
    print("  chronicle:")
    for entry in reversed(entries):
        print(f"    #{entry['seq']:<5} {entry['ts'][:19]}  {entry['actor']:<18} {entry['event']}")
    return 0


def cmd_throne_review(args: argparse.Namespace) -> int:
    """Walk through the quarantine one case at a time."""
    with _open(args) as castle:
        pending = castle.throne.pending()
        if not pending:
            print("The quarantine is empty. Nothing awaits your judgement.")
            return 0
        print(f"{len(pending)} object(s) await your judgement. Deciding as '{args.by}'.")
        for index, item in enumerate(pending, start=1):
            case = castle.registry.get_request(item["id"])
            if case["status"] != Status.QUARANTINED:  # e.g. restored when its agent was frozen
                continue
            print(f"\n[{index}/{len(pending)}] " + "\n".join(_describe(case)))
            while True:
                choice = _ask(f"  [a]pprove (delete forever)  [r]estore  [s]kip  [f]reeze {case['agent']}  [q]uit > ").lower()
                try:
                    if choice in ("a", "approve"):
                        if _ask(f"  Delete '{case['object_key']}' permanently? Type 'yes': ").lower() != "yes":
                            print("  Not deleted.")
                            continue
                        castle.throne.approve(case["id"], by=args.by)
                        print("  Deleted permanently by the Executioner.")
                    elif choice in ("r", "restore"):
                        note = _ask("  Note (optional): ")
                        castle.throne.restore(case["id"], by=args.by, note="" if note == "q" else note)
                        print("  Restored.")
                    elif choice in ("f", "freeze"):
                        reason = _ask(f"  Why freeze {case['agent']}? ")
                        restore_all = _ask("  Also restore everything it has in quarantine? [y/N] ").lower().startswith("y")
                        result = castle.throne.freeze(case["agent"], by=args.by, reason=reason, restore_all=restore_all)
                        print(f"  {case['agent']} is frozen" + (f"; restored {len(result['restored'])} object(s)."
                                                               if result["restored"] else "."))
                    elif choice in ("s", "skip", ""):
                        print("  Skipped.")
                    elif choice in ("q", "quit"):
                        print(f"\n{len(castle.throne.pending())} object(s) still await judgement.")
                        return 0
                    else:
                        print("  Choose a, r, s, f or q.")
                        continue
                except ThroneError as exc:
                    print(f"  ! {exc}")
                break
        remaining = len(castle.throne.pending())
        print("\nThe quarantine is empty." if not remaining else f"\n{remaining} object(s) still await judgement.")
    return 0


def cmd_throne_approve(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        case = castle.throne.case(args.id)
        if not args.yes:
            print("\n".join(_describe(case)))
            if _ask("Delete it permanently? This cannot be undone. Type 'yes': ").lower() != "yes":
                print("Nothing was done.")
                return 1
        case = castle.throne.approve(args.id, by=args.by, note=args.note)
    print(f"Approved. The Executioner deleted '{case['object_key']}'.")
    return 0


def cmd_throne_restore(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        case = castle.throne.restore(args.id, by=args.by, note=args.note, target_key=args.as_key)
    print(f"Restored '{case['object_key']}'." + (f" {case['status_reason']}" if case["status_reason"] else ""))
    return 0


def cmd_throne_freeze(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        result = castle.throne.freeze(args.agent, by=args.by, reason=args.reason, restore_all=args.restore_all)
    print(f"Agent '{args.agent}' is frozen." + (" (It already was.)" if result["was_already_frozen"] else ""))
    for request_id in result["restored"]:
        print(f"  restored {request_id}")
    for failure in result["failed"]:
        print(f"  could not restore {failure['request_id']}: {failure['error']}")
    return 0


def cmd_throne_unfreeze(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        result = castle.throne.unfreeze(args.agent, by=args.by, note=args.note)
    print(f"Agent '{args.agent}' is active." + (" (It already was.)" if result["was_already_active"] else ""))
    return 0


def cmd_executioner_run(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        results = castle.executioner.run_pending()
    if not results:
        print("No approved cases are waiting for the Executioner.")
    for request_id, outcome in results:
        print(f"{request_id}: {outcome}")
    return 1 if any(outcome != "executed" for _, outcome in results) else 0


# -- the Chronicle, the Watchtower and the Traps --------------------------------


def _entry_line(entry: dict) -> str:
    about = entry["data"].get("request_id") or entry["data"].get("agent") or entry["data"].get("key") or ""
    return f"#{entry['seq']:<6} {entry['ts'][:19].replace('T', ' ')}  {entry['actor']:<20} {entry['event']:<26} {about}"


def cmd_chronicle_show(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        entries = list(reversed(castle.chronicle.entries(args.limit, request_id=args.request)))
        if not entries and not args.follow:
            print("The Chronicle is empty.")
        for entry in entries:
            print(_entry_line(entry))
        if not args.follow:
            return 0
        print("-- following the Chronicle, Ctrl+C to stop --", file=sys.stderr)
        last = castle.chronicle.head()
        seq = last["seq"] if last else 0
        try:
            while True:
                time.sleep(1)
                for entry in castle.chronicle.after(seq):
                    seq = entry["seq"]
                    if not args.request or entry["data"].get("request_id") == args.request:
                        print(_entry_line(entry), flush=True)
        except KeyboardInterrupt:
            return 0


def cmd_chronicle_verify(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        result = castle.chronicle.verify()
        head = castle.chronicle.head()
    if result.ok:
        print(f"The Chronicle is intact: {result.entries} entries.")
        if head:
            print(f"Head: #{head['seq']} {head['hash']}")
        return 0
    print(f"THE CHRONICLE IS BROKEN at entry {result.broken_at}: {result.problem}.")
    print(f"The first {result.entries} entries are intact.")
    return 1


def cmd_watchtower_status(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        status = castle.watchtower.status()
    rows = [
        [a["name"], a["status"], a["requests_24h"], a["rejections_24h"], a["underestimates_7d"]]
        for a in status["agents"]
    ]
    print(_table(rows, ["AGENT", "STATUS", "REQUESTS 24H", "REJECTED 24H", "UNDERESTIMATES 7D"]) if rows else "No agents.")
    print()
    print("Cases: " + (", ".join(f"{k} {v}" for k, v in sorted(status["cases"].items())) or "none"))
    head = status["chronicle_head"]
    print(f"Chronicle: {head['seq']} entries, head {head['hash'][:16]}..." if head else "Chronicle: empty")
    return 0


def cmd_watchtower_alerts(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        alerts = castle.watchtower.alerts(args.limit)
    rows = [[a["ts"], a["severity"], a["kind"], a["message"]] for a in reversed(alerts)]
    print(_table(rows, ["WHEN (UTC)", "SEVERITY", "KIND", "MESSAGE"], width=90) if rows else "No alerts.")
    return 0


def cmd_watchtower_patrol(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        report = castle.patrol()
    print(f"Checked {report['chronicle_entries']} chronicle entries, {report['canaries']} canaries, "
          f"{report['quarantined']} quarantined objects.")
    if report["ok"]:
        print("All is well.")
        return 0
    for problem in report["problems"]:
        print(f"  ! {problem['message']}")
    return 1


def cmd_traps_plant(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        result = castle.traps.plant(args.key, note=args.note)
    verb = "Planted a decoy at" if result["created"] else "Turned the existing object into a canary:"
    print(f"{verb} '{result['key']}'.")
    return 0


def cmd_traps_list(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        canaries = castle.traps.list()
    rows = [[c["key"], iso(c["planted_at"]), c["note"]] for c in canaries]
    print(_table(rows, ["CANARY", "PLANTED", "NOTE"], width=70) if rows else "No canaries planted.")
    return 0


def cmd_traps_remove(args: argparse.Namespace) -> int:
    with _open(args) as castle:
        removed = castle.traps.remove(args.key)
    print(f"'{args.key}' is no longer a canary (the object itself was left alone)." if removed else "No such canary.")
    return 0 if removed else 1


def cmd_notify_test(args: argparse.Namespace) -> int:
    from .notify import desktop_sender

    sender = desktop_sender()
    names = {
        "_windows_toast": "a Windows notification",
        "_macos_notification": "a macOS notification",
        "_linux_notification": "notify-send",
        "_log_only": "the log only (no desktop notifier found, or REDCASTLE_NOTIFY=off)",
    }
    print(f"Sending a test notification via {names.get(sender.__name__, sender.__name__)}...")
    try:
        sender("Red Castle: test", "Notifications work.", "You will see this when something needs you.", False)
    except Exception as exc:  # noqa: BLE001
        print(f"error: the notification failed: {exc}", file=sys.stderr)
        return 1
    print("Sent. If nothing appeared, check the system's notification settings (Focus Assist / Do Not Disturb).")
    return 0


# -- demo -------------------------------------------------------------------------


def cmd_demo(args: argparse.Namespace) -> int:
    logging.disable(logging.CRITICAL)

    def step(text: str) -> None:
        print(f"\n== {text}")

    def show(view: dict) -> None:
        judge = view.get("judge")
        extra = f" | Judge: {judge['risk_score']} ({judge['risk_level']}, {judge['assessment']})" if judge else ""
        print(f"   -> {view['status']}: {view['message']}{extra}")

    def notification(title: str, line1: str, line2: str, urgent: bool) -> None:
        print(f"   [notification{' - urgent' if urgent else ''}] {title} | {line1} | {line2}")

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        with found_castle(Path(tmp) / "castle") as castle:
            castle.notifier.sender = notification  # print instead of popping up desktop notifications
            castle.config.notify.batch_seconds = 0
            realm = castle.config.realm_path
            files = {
                "notes/old-draft.tmp": b"scratch",
                "reports/q3-summary.docx": b"quarterly numbers",
                "config/prod.env": b"API_URL=https://example.invalid",
            }
            old = time.time() - 30 * 86400
            for key, data in files.items():
                path = realm / key
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                os.utime(path, (old, old))
            castle.traps.plant("backups/passwords-DO-NOT-DELETE.txt")
            agent = castle.registry.add_agent("demo-agent")
            gw, throne = castle.gateway, castle.throne

            step("The agent looks around")
            for obj in gw.list_objects(agent)["objects"]:
                print(f"   {obj['key']}")

            step("The agent asks to delete notes/old-draft.tmp (claims risk 5)")
            first = gw.request_deletion(agent, "notes/old-draft.tmp", "Temporary draft, superseded by the final", 5)
            show(first)
            print(f"   still on disk? {(realm / 'notes/old-draft.tmp').exists()} - hidden in quarantine instead")

            step("A human approves it in the terminal (redcastle throne review)")
            done = throne.approve(first["request_id"], by="demo-human")
            print(f"   -> {done['status']}: the Executioner deleted it permanently")

            step("The agent asks to delete config/prod.env (claims risk 5)")
            second = gw.request_deletion(agent, "config/prod.env", "Looks unused", 5)
            show(second)

            step("The human disagrees and restores it")
            restored = throne.restore(second["request_id"], by="demo-human", note="still used in production")
            print(f"   -> {restored['status']}: back on disk = {(realm / 'config/prod.env').exists()}")

            step("The agent reaches for backups/passwords-DO-NOT-DELETE.txt - a canary")
            show(gw.request_deletion(agent, "backups/passwords-DO-NOT-DELETE.txt", "Old backup, cleaning up", 10))
            print(f"   agent status: {castle.registry.get_agent('demo-agent')['status']}")

            step("The frozen agent tries again")
            show(gw.request_deletion(agent, "reports/q3-summary.docx", "Outdated report from last quarter", 20))

            step("The Chronicle")
            for entry in reversed(castle.chronicle.entries(100)):
                print(f"   #{entry['seq']:<3} {entry['actor']:<20} {entry['event']}")
            result = castle.chronicle.verify()
            print(f"   verified: {'intact' if result.ok else 'BROKEN'} ({result.entries} entries)")
    return 0


# -- argument parsing -------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_prog(),
        description="Red Castle - AI agents may ask to delete things. Only a human decides.",
        epilog=f"Run '{_prog()}' without a command for the getting-started guide.",
    )
    parser.add_argument("--root", default=os.environ.get("REDCASTLE_HOME", "."),
                        help="folder holding redcastle.toml and .redcastle/ (default: current folder or $REDCASTLE_HOME)")
    parser.add_argument("-v", "--verbose", action="store_true", help="log more")
    parser.add_argument("--version", action="version", version=f"redcastle {__version__}")
    parser.set_defaults(func=cmd_welcome)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    me = getpass.getuser()

    p = sub.add_parser("init", help="found a new castle in --root")
    p.add_argument("--realm", default="realm", help="folder the agents may see (local backend)")
    p.set_defaults(func=cmd_init)

    agent = sub.add_parser("agent", help="register and list agents").add_subparsers(dest="sub", required=True)
    p = agent.add_parser("add", help="register an agent and print its token")
    p.add_argument("name")
    p.set_defaults(func=cmd_agent_add)
    agent.add_parser("list", help="list agents").set_defaults(func=cmd_agent_list)

    p = sub.add_parser("start", help="run the castle silently in the background")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.set_defaults(func=cmd_start)
    sub.add_parser("stop", help="stop the background castle").set_defaults(func=cmd_stop)
    sub.add_parser("status", help="is it running, what awaits you, is the Chronicle intact").set_defaults(
        func=cmd_status)

    p = sub.add_parser("serve", help="run the castle in this terminal (foreground)")
    p.add_argument("--host")
    p.add_argument("--port", type=int)
    p.add_argument("--quiet", action="store_true", help="print nothing; log to .redcastle/castle.log")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("mcp", help="run an MCP server (stdio) for one agent")
    p.add_argument("--agent-token", help="the agent's token (prefer $REDCASTLE_AGENT_TOKEN)")
    p.add_argument("--gateway", help="URL of the running castle; without it the castle is opened in-process")
    p.set_defaults(func=cmd_mcp)

    throne = sub.add_parser("throne", help="the Throne Room: decide on quarantined objects").add_subparsers(
        dest="sub", required=True)
    p = throne.add_parser("review", help="go through the quarantine case by case")
    p.add_argument("--by", default=me, help=f"your name (default: {me})")
    p.set_defaults(func=cmd_throne_review)
    p = throne.add_parser("list", help="list cases (default: those waiting in quarantine)")
    p.add_argument("--status", default=Status.QUARANTINED, choices=[*Status.ALL, "all"])
    p.add_argument("--limit", type=int, default=200)
    p.set_defaults(func=cmd_throne_list)
    p = throne.add_parser("show", help="show one case with the Judge's reasoning")
    p.add_argument("id")
    p.set_defaults(func=cmd_throne_show)
    p = throne.add_parser("approve", help="approve: the Executioner permanently deletes the object")
    p.add_argument("id")
    p.add_argument("--by", default=me, help=f"your name (default: {me})")
    p.add_argument("--note", default="")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    p.set_defaults(func=cmd_throne_approve)
    p = throne.add_parser("restore", help="decline: put the object back")
    p.add_argument("id")
    p.add_argument("--by", default=me)
    p.add_argument("--note", default="")
    p.add_argument("--as", dest="as_key", help="restore under another key")
    p.set_defaults(func=cmd_throne_restore)
    p = throne.add_parser("freeze", help="freeze an agent")
    p.add_argument("agent")
    p.add_argument("--by", default=me)
    p.add_argument("--reason", default="")
    p.add_argument("--restore-all", action="store_true", help="also restore everything it has in quarantine")
    p.set_defaults(func=cmd_throne_freeze)
    p = throne.add_parser("unfreeze", help="let a frozen agent submit requests again")
    p.add_argument("agent")
    p.add_argument("--by", default=me)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_throne_unfreeze)

    executioner = sub.add_parser("executioner", help="the Executioner").add_subparsers(dest="sub", required=True)
    executioner.add_parser("run", help="carry out approved cases that are still pending").set_defaults(
        func=cmd_executioner_run)

    chronicle = sub.add_parser("chronicle", help="the Chronicle").add_subparsers(dest="sub", required=True)
    p = chronicle.add_parser("show", help="show recent entries")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--request", help="only entries about this case")
    p.add_argument("-f", "--follow", action="store_true", help="keep printing new entries as they happen")
    p.set_defaults(func=cmd_chronicle_show)
    chronicle.add_parser("verify", help="verify the hash chain").set_defaults(func=cmd_chronicle_verify)

    tower = sub.add_parser("watchtower", help="the Watchtower").add_subparsers(dest="sub", required=True)
    tower.add_parser("status", help="agents, cases and the Chronicle at a glance").set_defaults(
        func=cmd_watchtower_status)
    p = tower.add_parser("alerts", help="recent alerts")
    p.add_argument("--limit", type=int, default=30)
    p.set_defaults(func=cmd_watchtower_alerts)
    tower.add_parser("patrol", help="check the Chronicle, canaries and quarantine now").set_defaults(
        func=cmd_watchtower_patrol)

    traps = sub.add_parser("traps", help="the Traps (canaries)").add_subparsers(dest="sub", required=True)
    p = traps.add_parser("plant", help="make KEY a canary (writes a decoy if it does not exist)")
    p.add_argument("key")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_traps_plant)
    traps.add_parser("list", help="list canaries").set_defaults(func=cmd_traps_list)
    p = traps.add_parser("remove", help="stop treating KEY as a canary")
    p.add_argument("key")
    p.set_defaults(func=cmd_traps_remove)

    notify = sub.add_parser("notify", help="desktop notifications").add_subparsers(dest="sub", required=True)
    notify.add_parser("test", help="send a test notification").set_defaults(func=cmd_notify_test)

    sub.add_parser("demo", help="walk through the whole flow in a throw-away castle").set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except AttributeError:  # missing (pythonw) or not a text stream
            pass
    args = build_parser().parse_args(argv)
    level = logging.DEBUG if args.verbose else logging.INFO if args.command == "serve" else logging.WARNING
    logging.basicConfig(level=level, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        return args.func(args)
    except (ConfigError, ThroneError, GatewayError, ExecutionRefused, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
