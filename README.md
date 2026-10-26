<div align="center">

<pre>
██████╗ ███████╗██████╗     ██████╗ █████╗ ███████╗████████╗██╗     ███████╗
██╔══██╗██╔════╝██╔══██╗   ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██║     ██╔════╝
██████╔╝█████╗  ██║  ██║   ██║     ███████║███████╗   ██║   ██║     █████╗
██╔══██╗██╔══╝  ██║  ██║   ██║     ██╔══██║╚════██║   ██║   ██║     ██╔══╝
██║  ██║███████╗██████╔╝   ╚██████╗██║  ██║███████║   ██║   ███████╗███████╗
╚═╝  ╚═╝╚══════╝╚═════╝     ╚═════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚══════╝
</pre>

**AI agents may ask to delete things. Only a human decides.**

[![tests](https://github.com/babayaga370/red-castle/actions/workflows/tests.yml/badge.svg)](https://github.com/babayaga370/red-castle/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![python](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

</div>

Red Castle is a guarded deletion pipeline for AI agents. An agent never deletes anything
itself: it asks the castle, the object is hidden in quarantine, and a human approves or
restores it from the terminal. The castle runs silently in the background and only speaks
up, with a desktop notification, when a human is needed.

```
AI Agent
    │  "I want to delete X"  (cannot delete it themselves)
    ▼
[The Gateway]       receives deletion requests via API or MCP tools
    ▼
[The Judge]         calculates its own risk score and compares it with the agent's
    ▼
[The Quarantine]    the object is hidden but still exists
    ▼
[The Throne Room]   a human approves, restores, or freezes the agent (in the terminal)
    ▼
[The Executioner]   the only role in the world authorized to permanently delete
    ▼
[The Chronicle]     tamper-evident log of every decision

Around the wall:
[The Moat]          guardrails
[The Watchtower]    monitoring and desktop notifications
[The Traps]         canaries
```

Pure Python standard library. No dependencies, except `boto3` if you use the S3 backend.

## Quick start

```bash
git clone https://github.com/babayaga370/red-castle.git
```

```bash
cd red-castle
```

```bash
pip install .
```

Or skip the install and use `python -m redcastle` in place of `redcastle` below.

```bash
redcastle demo
```

The demo walks through the whole flow in a throw-away castle: quarantine, approval,
restore, a sprung trap, a frozen agent and the Chronicle. Nothing on your machine is touched.

To set up a real castle, go to the folder that should hold it and run:

```bash
redcastle init
```

`init` greets you with the castle and a short guide. It creates `redcastle.toml` (the
configuration), `realm/` (the folder agents can see and ask to delete from) and
`.redcastle/` (database, keys, quarantine and log; keep it private).

```bash
redcastle agent add claude
```

```bash
redcastle start
```

```bash
redcastle notify test
```

That's it: the castle runs silently in the background, and agents reach it at
`http://127.0.0.1:8750/api/v1`. When something needs you, a notification pops up, and you
answer it with:

```bash
redcastle throne review
```

Running `redcastle` without a command shows the welcome screen and the most useful commands.
Every command accepts `--root <folder>` (or `REDCASTLE_HOME`) when the castle lives elsewhere.

## Running silently

| Command | |
|---|---|
| `redcastle start` | Start the castle detached from the terminal, with no window (`pythonw` on Windows). It keeps running when the terminal closes. |
| `redcastle status` | Is it running? How many cases await you? Any alerts in the last day? Is the Chronicle intact? |
| `redcastle stop` | Ask the castle to close its gates; forced after 15 seconds if it does not answer. |
| `redcastle serve` | Run in the foreground of this terminal (Ctrl+C to stop). `--quiet` logs only to `.redcastle/castle.log`. |

The castle does not start at login by itself. To make it, schedule
`pythonw -m redcastle --root <folder> serve --quiet` with Windows Task Scheduler (or launchd / systemd).

## Notifications

The Watchtower stays quiet unless a human is needed:

- **An object is waiting in quarantine.** The notification names the agent and the object,
  shows the Judge's and the agent's risk scores, and says if the agent underestimated the risk.
- **Alerts** (urgent): an agent reached for a canary, an agent was frozen, a canary
  vanished behind the castle's back, the Chronicle or the quarantine was tampered with, or the
  Executioner refused to act.
- **Reminders** when cases have waited longer than `remind_interval_minutes`.

Everything that happens within `batch_seconds` is gathered into one notification, so a busy
agent cannot flood your screen. Rejected requests (bad keys, missing objects …) stay quiet.

Windows uses native toast notifications through Windows PowerShell (they show
"Windows PowerShell" as the sender), macOS uses `osascript` and Linux `notify-send`. Without
any of these, notifications go to the log; `REDCASTLE_NOTIFY=off` forces that, for CI for
example.

```toml
[notify]
enabled = true
on_quarantine = true          # notify when an object awaits your judgement
min_severity = "warning"      # "warning" or "critical"
batch_seconds = 3
remind_interval_minutes = 60  # 0 = never
```

Nothing shows up? Check the system's notification settings and Focus Assist / Do Not Disturb.

## The Throne Room, in your terminal

```bash
redcastle throne review
```

The review goes through the quarantine one case at a time. For each case it shows the
object, the agent, its reason, both risk scores and the Judge's reasoning:

```
[1/2] Case rc-6c9b6e01fd01  [quarantined]  4m ago
  object:     config/prod.env  (31 bytes)
  agent:      claude
  reason:     Looks unused
  risk:       agent 5, Judge 70 (high)  <-- agent UNDERESTIMATED the risk
       +10  permanent deletion is never risk-free
       +35  path matches sensitive pattern '*.env'
       +20  path matches sensitive pattern '*prod*'
        +5  terse justification
  [a]pprove (delete forever)  [r]estore  [s]kip  [f]reeze claude  [q]uit >
```

Approving asks you to type `yes`. Every decision is recorded under your name (your
username, or `--by`).

| Command | |
|---|---|
| `redcastle throne list` | Cases waiting in quarantine (`--status all` for everything) |
| `redcastle throne show <id>` | One case, the Judge's reasoning and its Chronicle entries |
| `redcastle throne approve <id>` | Approve; the Executioner deletes the object permanently |
| `redcastle throne restore <id> [--as KEY]` | Decline and put the object back |
| `redcastle throne freeze <agent> [--restore-all]` | Freeze an agent (and optionally restore all it asked for) |
| `redcastle throne unfreeze <agent>` | Let it submit requests again |
| `redcastle chronicle show --follow` | Watch every decision as it happens |
| `redcastle chronicle verify` | Verify the hash chain |
| `redcastle watchtower alerts` / `patrol` | Recent alerts / check canaries, quarantine and Chronicle now |
| `redcastle traps plant <key>` | Plant a canary |
| `redcastle executioner run` | Carry out approved cases that are still pending |

The Throne Room exists only in the terminal. There is no web interface and no admin API,
so nobody can approve a deletion over the network.

## For agents: HTTP API

Every call needs `Authorization: Bearer <agent token>`.

| Method | Path | |
|---|---|---|
| GET | `/api/v1/objects?prefix=` | Visible objects (quarantined ones are hidden) |
| POST | `/api/v1/deletion-requests` | `{"object_key", "reason", "risk_score"}` → 202 quarantined, 403 rejected |
| GET | `/api/v1/deletion-requests` | Your own requests (`?status=`) |
| GET | `/api/v1/deletion-requests/{id}` | Status of one of your requests |

```bash
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"object_key":"logs/app-2025.log","reason":"Last year log, already archived","risk_score":10}' http://127.0.0.1:8750/api/v1/deletion-requests
```

## For agents: MCP

`redcastle mcp` is an MCP server over stdio with the tools `list_objects`,
`request_deletion`, `get_deletion_request` and `list_my_deletion_requests`. No tool can
delete, approve or restore anything.

Point it at the running castle with `--gateway`. The agent's process then holds nothing but
its own token and cannot reach the database or the keys. For Claude Code, in `.mcp.json`:

```json
{
  "mcpServers": {
    "red-castle": {
      "command": "redcastle",
      "args": ["mcp", "--gateway", "http://127.0.0.1:8750"],
      "env": { "REDCASTLE_AGENT_TOKEN": "rc_agent_..." }
    }
  }
}
```

Without `--gateway` the castle is opened in-process (needs `--root` and access to `.redcastle/`).

## How it works

### Life of a request

```
received ──► rejected     (Moat: frozen agent, invalid key, protected object, rate limit …)
         ──► trapped      (a canary: the agent is frozen and only ever sees "rejected")
         ──► failed       (storage error; nothing was deleted)
         ──► quarantined ──► approved ──► executed
                         └─► restored
```

### The roles in the code

| Role | File | What it does |
|---|---|---|
| Gateway | [gateway.py](redcastle/gateway.py) | Authenticates the agent and walks the request through the castle. Has no delete function. |
| Judge | [judge.py](redcastle/judge.py) | Its own 0–100 risk score with explained factors; flags agents that under- or overestimate. |
| Quarantine | [quarantine.py](redcastle/quarantine.py) | Moves the object out of sight and records its checksum. |
| Throne Room | [throne.py](redcastle/throne.py) | Approve (seals the decision with an HMAC), restore, freeze or unfreeze agents. |
| Executioner | [executioner.py](redcastle/executioner.py) | Holds the only storage handle with `can_purge=True`; checks seal and checksum before deleting. |
| Chronicle | [chronicle.py](redcastle/chronicle.py) | Hash-chained, HMAC-signed log; SQLite triggers refuse UPDATE and DELETE. |
| Moat | [moat.py](redcastle/moat.py) | Frozen agents, key validation, protected patterns, required reason and score, rate limits. |
| Watchtower | [watchtower.py](redcastle/watchtower.py), [notify.py](redcastle/notify.py) | Alerts, automatic freezes, patrols, reminders, desktop notifications, webhook. |
| Traps | [traps.py](redcastle/traps.py) | Canaries. Asking to delete one freezes the agent on the spot. |

Storage backends: [local folder](redcastle/storage/local.py) and [S3](redcastle/storage/s3.py).
Background mode: [daemon.py](redcastle/daemon.py).

### The Judge

The Judge starts at 10 points and adds or subtracts for:

- sensitive paths (`*.env`, `*secret*`, `*backup*`, `*.db`, `*prod*` …) and low-value ones (`*.tmp`, `*.log`, `__pycache__` …)
- size (≥ 1 / 10 / 100 MB), and whether the object changed in the last hour or day
- the agent's behaviour: bursts of requests, earlier underestimates
- a terse reason

If the Judge's score is at least `discrepancy_threshold` (25) above the agent's own, the
request is flagged as **underestimated**. The notification says so, and three of those
within an hour freeze the agent. Patterns and weights live in `redcastle.toml`.

### Around the wall

- **Moat:** see `[moat]` in `redcastle.toml`. The castle's own files (`.redcastle/`,
  `redcastle.toml`) are never reachable, even if the realm is the castle's own folder.
- **Watchtower:** freezes an agent on a sprung trap, after 5 Moat rejections within
  10 minutes, or after 3 underestimates within an hour. The running castle patrols every
  minute: the Chronicle must verify, every canary must be in place and unchanged, and every
  quarantined object must match its checksum. Each new problem raises an urgent
  notification. An optional `webhook_url` receives alerts as JSON.
- **Traps:** `redcastle traps plant "backups/db-dump-prod.sql"` writes a decoy with fake
  credentials, or turns an existing object into a canary.

### S3

```toml
[storage]
backend = "s3"
bucket = "my-bucket"
prefix = "data/"                      # what agents can see
quarantine_prefix = ".redcastle-quarantine/"
profile = "redcastle"                 # the castle's AWS profile
executioner_profile = "redcastle-executioner"
```

Quarantine copies the object to `quarantine_prefix` and removes the original. With
**bucket versioning enabled**, that removal is only a delete marker, so nothing is lost.
Suggested IAM roles:

- **Agent:** no S3 permissions at all, or read-only with an explicit `Deny` on `s3:DeleteObject*`.
- **Castle (`profile`):** `s3:ListBucket`, `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`, and an explicit `Deny` on `s3:DeleteObjectVersion`.
- **Executioner (`executioner_profile`):** `s3:DeleteObject`, `s3:DeleteObjectVersion`, `s3:ListBucketVersions`, `s3:GetObject`.

The only irreversible call in the whole system is then made with the Executioner's keys.

## Security model and limits

- **The Chronicle is tamper-*evident*, not tamper-proof.** Someone holding both the database
  and `secrets.json` can rewrite history. Publish the head from `redcastle chronicle verify`
  (sequence number and hash) somewhere else now and then to detect truncation too.
- **Run the castle as a different OS user than the agent.** An agent with file access to
  `.redcastle/` could run `throne approve` itself. With the local backend, an agent with a
  shell can also delete files in `realm/` directly; the Traps and the patrols detect and
  report that, but cannot prevent it. Real isolation needs separate users or containers, or
  S3 with IAM.
- Agent tokens are stored only as SHA-256 hashes. Text written by agents (such as object
  keys) is XML-escaped before it reaches a notification.
- The HTTP server listens on `127.0.0.1` by default and has no TLS. Put a TLS-terminating
  reverse proxy in front of it before exposing it to a network.

## Development

```bash
python -m unittest discover -s tests -t .
```

CI runs the tests on Windows, macOS and Linux with Python 3.11–3.14.

## License

[MIT](LICENSE)
