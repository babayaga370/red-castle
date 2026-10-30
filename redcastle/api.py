"""HTTP interface: the agents' Gateway API.

Humans hold court in the terminal (``redcastle throne ...``); there is no
web interface and no admin endpoint here.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from . import __version__, daemon
from .castle import Castle
from .gateway import GatewayError
from .registry import Status

log = logging.getLogger("redcastle.api")
MAX_BODY = 64 * 1024
SOCKET_TIMEOUT = 30  # seconds a silent client may keep a connection open
MAX_CONNECTIONS = 64  # at a time; the rest are turned away rather than given a thread each
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")

# HTTP status for the agent's view of a fresh request
REQUEST_STATUS_CODES = {Status.QUARANTINED: 202, Status.REJECTED: 403, Status.FAILED: 502}

ROUTES = [
    (method, re.compile(pattern), handler)
    for method, pattern, handler in [
        ("GET", r"/", "root"),
        ("GET", r"/health", "health"),
        ("GET", r"/api/v1/objects", "objects"),
        ("POST", r"/api/v1/deletion-requests", "create_request"),
        ("GET", r"/api/v1/deletion-requests", "my_requests"),
        ("GET", r"/api/v1/deletion-requests/([\w-]+)", "my_request"),
    ]
]


class BadRequest(Exception):
    pass


class CastleHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    # On Windows SO_REUSEADDR lets another process bind the same port and
    # intercept agents' traffic, so only reuse addresses elsewhere.
    allow_reuse_address = os.name != "nt"

    def __init__(self, address: tuple[str, int], castle: Castle) -> None:
        self.castle = castle
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, CastleRequestHandler)

    def verify_request(self, request: Any, client_address: Any) -> bool:
        return self._slots.acquire(blocking=False)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class CastleRequestHandler(BaseHTTPRequestHandler):
    server: CastleHTTPServer
    server_version = f"RedCastle/{__version__}"
    timeout = SOCKET_TIMEOUT

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def log_message(self, format: str, *args: Any) -> None:
        log.info("%s %s", self.address_string(), format % args)

    # -- plumbing -------------------------------------------------------------

    @property
    def castle(self) -> Castle:
        return self.server.castle

    def _dispatch(self, method: str) -> None:
        url = urlsplit(self.path)
        path = url.path.rstrip("/") or "/"
        self.query = {k: v[-1] for k, v in parse_qs(url.query).items()}
        path_exists = False
        for route_method, pattern, handler in ROUTES:
            match = pattern.fullmatch(path)
            if not match:
                continue
            path_exists = True
            if route_method != method:
                continue
            try:
                status, payload = getattr(self, handler)(*match.groups())
            except GatewayError as exc:
                self._send(exc.http_status, {"error": exc.code, "message": str(exc)})
            except BadRequest as exc:
                self._send(400, {"error": "bad_request", "message": str(exc)})
            except Exception:  # noqa: BLE001
                log.exception("Unhandled error on %s %s", method, path)
                self._send(500, {"error": "internal_error", "message": "Internal error."})
            else:
                self._send(status, payload)
            return
        if path_exists:
            self._send(405, {"error": "method_not_allowed", "message": f"{method} is not allowed here."})
        else:
            self._send(404, {"error": "not_found", "message": "No such endpoint."})

    def _send(self, status: int, payload: Any) -> None:
        # A file name that is not valid Unicode goes out as a JSON escape, not as a crash.
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8", "backslashreplace")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionError, TimeoutError):  # the client hung up; nobody is left to tell
            self.close_connection = True

    def _token(self) -> str | None:
        scheme, _, token = self.headers.get("Authorization", "").partition(" ")
        return (token.strip() or None) if scheme.lower() == "bearer" else None

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError as exc:
            raise BadRequest("Invalid Content-Length.") from exc
        if length > MAX_BODY:
            raise BadRequest("The request body is too large.")
        try:
            raw = self.rfile.read(length) if length > 0 else b""
        except TimeoutError as exc:
            raise BadRequest("Timed out waiting for the request body.") from exc
        if len(raw) < length:  # a lost connection is no request, and must be no strike against the agent
            raise BadRequest("The connection closed before the whole body arrived.")
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            raise BadRequest("The body must be JSON.") from exc
        if not isinstance(data, dict):
            raise BadRequest("The body must be a JSON object.")
        return data

    def _int(self, name: str, default: int, maximum: int) -> int:
        try:
            value = int(self.query.get(name, default))
        except ValueError as exc:
            raise BadRequest(f"'{name}' must be an integer.") from exc
        return max(1, min(value, maximum))

    # -- handlers -------------------------------------------------------------

    def root(self) -> tuple[int, Any]:
        return 200, {"name": "Red Castle", "version": __version__, "gateway": "/api/v1"}

    def health(self) -> tuple[int, Any]:
        return 200, {"ok": True}

    def objects(self) -> tuple[int, Any]:
        return 200, self.castle.gateway.list_objects(
            self._token(), self.query.get("prefix", ""), self._int("limit", 1000, 1000), self.query.get("after", "")
        )

    def create_request(self) -> tuple[int, Any]:
        token = self._token()
        self.castle.gateway.authenticate(token)  # strangers do not get to make us wait for anything
        body = self._body()  # read before the lock: a slow client must only ever delay itself
        with self.castle.lock:
            view = self.castle.gateway.request_deletion(
                token, body.get("object_key", body.get("key")), body.get("reason"), body.get("risk_score")
            )
        return REQUEST_STATUS_CODES.get(view["status"], 200), view

    def my_requests(self) -> tuple[int, Any]:
        requests = self.castle.gateway.list_requests(
            self._token(), status=self.query.get("status"), limit=self._int("limit", 100, 1000)
        )
        return 200, {"requests": requests}

    def my_request(self, request_id: str) -> tuple[int, Any]:
        return 200, self.castle.gateway.get_request(self._token(), request_id)


def serve(castle: Castle, host: str, port: int) -> None:
    """Run the Gateway until Ctrl+C or 'redcastle stop'.

    Meanwhile the Watchtower patrols in the background, and the server watches
    for the stop flag that 'redcastle stop' leaves in the state folder.
    """
    if host not in LOCAL_HOSTS:
        log.warning("The gateway on %s has no TLS: agent tokens travel in the clear without a reverse proxy.", host)
    with daemon.holding_gate(castle.config):
        _run(castle, CastleHTTPServer((host, port), castle))


def _run(castle: Castle, server: CastleHTTPServer) -> None:
    config = castle.config
    host, port = server.server_address[:2]
    stop = threading.Event()
    interval = config.watchtower.patrol_interval_seconds

    def patrol_loop() -> None:
        failing = False
        while not stop.wait(interval):
            try:
                castle.patrol()
                failing = False
            except Exception as exc:  # noqa: BLE001
                log.exception("The Watchtower's patrol failed")
                if not failing:  # a blind Watchtower is itself something a human must hear about
                    failing = True
                    with contextlib.suppress(Exception):
                        castle.watchtower.alert("critical", "patrol_failed", f"The Watchtower's patrol failed: {exc}.")

    def stop_flag_loop() -> None:
        flag = daemon.stop_path(config)
        while not stop.wait(1):
            if flag.exists():
                log.info("Stop requested - closing the gates.")
                flag.unlink(missing_ok=True)
                server.shutdown()
                return

    daemon.stop_path(config).unlink(missing_ok=True)  # left by a castle that died mid-stop
    daemon.write_pid(config, host, port)
    if interval > 0:
        threading.Thread(target=patrol_loop, name="watchtower", daemon=True).start()
    threading.Thread(target=stop_flag_loop, name="stop-flag", daemon=True).start()
    log.info("Gateway open on http://%s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        server.server_close()
        daemon.clear_pid(config)
        log.info("Gates closed.")
