"""MCP (Model Context Protocol) server that exposes the Gateway as tools.

Runs over stdio: newline-delimited JSON-RPC 2.0. The tools let an agent look
around and *ask* for deletions - there is no tool that deletes, approves or
restores anything.

Two ways to reach the castle:

* ``HttpAgentPort`` talks to a running ``redcastle serve``. The MCP process
  then holds nothing but the agent's token (recommended).
* ``LocalAgentPort`` opens the castle in-process (handy for a single machine).
"""

from __future__ import annotations

import json
import logging
import sys
import urllib.error
import urllib.request
from typing import Any, BinaryIO, Protocol
from urllib.parse import quote, urlencode

from . import __version__
from .gateway import GatewayError
from .registry import Status

log = logging.getLogger("redcastle.mcp")

PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")

INSTRUCTIONS = (
    "Red Castle guards this storage. You cannot delete anything yourself. "
    "Use request_deletion to ask: the object is hidden in quarantine and a human decides in the "
    "Throne Room whether it is permanently deleted or restored. Give an honest risk_score from 0 "
    "to 100 - the Judge computes its own score, and repeatedly underestimating the risk gets "
    "you frozen."
)

TOOLS: list[dict] = [
    {
        "name": "list_objects",
        "title": "List objects",
        "description": "List the objects you can see. Objects waiting in quarantine are hidden.",
        "inputSchema": {
            "type": "object",
            "properties": {"prefix": {"type": "string", "description": "Only keys starting with this, e.g. 'reports/'."}},
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "request_deletion",
        "title": "Request deletion",
        "description": (
            "Ask Red Castle to delete one object. Nothing is deleted right away: the object is hidden "
            "in quarantine until a human approves (permanent deletion) or restores it. Use "
            "get_deletion_request to follow up."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "object_key": {"type": "string", "description": "Key of the object, exactly as list_objects shows it."},
                "reason": {"type": "string", "description": "Why it should be deleted. The human reads this."},
                "risk_score": {
                    "type": "integer", "minimum": 0, "maximum": 100,
                    "description": "Your honest estimate of how risky deleting it is (0 = harmless, 100 = disastrous).",
                },
            },
            "required": ["object_key", "reason", "risk_score"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False},
    },
    {
        "name": "get_deletion_request",
        "title": "Get deletion request",
        "description": "Show the current status of one of your deletion requests.",
        "inputSchema": {
            "type": "object",
            "properties": {"request_id": {"type": "string"}},
            "required": ["request_id"],
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "list_my_deletion_requests",
        "title": "List my deletion requests",
        "description": "List your deletion requests, newest first.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {
                    "type": "string",
                    "enum": [Status.QUARANTINED, Status.APPROVED, Status.EXECUTED, Status.RESTORED,
                             Status.REJECTED, Status.FAILED],
                },
            },
        },
        "annotations": {"readOnlyHint": True, "openWorldHint": False},
    },
]


class AgentPort(Protocol):
    def list_objects(self, prefix: str) -> dict: ...
    def request_deletion(self, object_key: Any, reason: Any, risk_score: Any) -> dict: ...
    def get_request(self, request_id: str) -> dict: ...
    def list_requests(self, status: str | None) -> list[dict]: ...


class LocalAgentPort:
    def __init__(self, castle: Any, token: str) -> None:
        self.castle = castle
        self.token = token

    def list_objects(self, prefix: str) -> dict:
        with self.castle.lock:
            return self.castle.gateway.list_objects(self.token, prefix)

    def request_deletion(self, object_key: Any, reason: Any, risk_score: Any) -> dict:
        with self.castle.lock:
            return self.castle.gateway.request_deletion(self.token, object_key, reason, risk_score)

    def get_request(self, request_id: str) -> dict:
        with self.castle.lock:
            return self.castle.gateway.get_request(self.token, request_id)

    def list_requests(self, status: str | None) -> list[dict]:
        with self.castle.lock:
            return self.castle.gateway.list_requests(self.token, status)


class HttpAgentPort:
    def __init__(self, base_url: str, token: str, timeout: float = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _call(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            with exc:
                try:
                    payload = json.loads(exc.read() or b"{}")
                except ValueError:
                    payload = {}
            return exc.code, payload
        except urllib.error.URLError as exc:
            raise GatewayError(
                "gateway_unreachable", f"Cannot reach the Red Castle gateway at {self.base_url}: {exc.reason}", 503
            ) from exc

    @staticmethod
    def _expect(status: int, payload: dict, ok: tuple[int, ...] = (200,)) -> dict:
        if status in ok and "error" not in payload:
            return payload
        raise GatewayError(payload.get("error", "error"), payload.get("message", f"HTTP {status}"), status)

    def list_objects(self, prefix: str) -> dict:
        return self._expect(*self._call("GET", "/api/v1/objects?" + urlencode({"prefix": prefix})))

    def request_deletion(self, object_key: Any, reason: Any, risk_score: Any) -> dict:
        body = {"object_key": object_key, "reason": reason, "risk_score": risk_score}
        # 202 = quarantined, 403 = rejected, 502 = failed: all carry the request's view.
        return self._expect(*self._call("POST", "/api/v1/deletion-requests", body), ok=(200, 202, 403, 502))

    def get_request(self, request_id: str) -> dict:
        return self._expect(*self._call("GET", f"/api/v1/deletion-requests/{quote(request_id, safe='')}"))

    def list_requests(self, status: str | None) -> list[dict]:
        query = "?" + urlencode({"status": status}) if status else ""
        return self._expect(*self._call("GET", f"/api/v1/deletion-requests{query}"))["requests"]


class InvalidParams(Exception):
    pass


def _error(msg_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def _tool_result(data: dict, *, is_error: bool = False) -> dict:
    return {
        "content": [{"type": "text", "text": json.dumps(data, indent=2, ensure_ascii=False)}],
        "structuredContent": data,
        "isError": is_error,
    }


class MCPServer:
    def __init__(self, port: AgentPort) -> None:
        self.port = port

    def handle(self, message: Any) -> dict | list | None:
        if isinstance(message, list):  # JSON-RPC batch (older protocol versions)
            responses = [r for r in (self._handle_one(m) for m in message) if r is not None]
            return responses or None
        return self._handle_one(message)

    def _handle_one(self, message: Any) -> dict | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, -32600, "Invalid Request")
        method = message.get("method")
        if not isinstance(method, str) or "id" not in message:
            return None  # a notification, or a response to a request we never send
        msg_id = message["id"]
        params = message.get("params") or {}
        try:
            if method == "initialize":
                result = self._initialize(params)
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                result = self._call_tool(params)
            else:
                return _error(msg_id, -32601, f"Method not found: {method}")
        except InvalidParams as exc:
            return _error(msg_id, -32602, str(exc))
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _initialize(self, params: dict) -> dict:
        requested = params.get("protocolVersion")
        return {
            "protocolVersion": requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "red-castle", "title": "Red Castle", "version": __version__},
            "instructions": INSTRUCTIONS,
        }

    def _call_tool(self, params: dict) -> dict:
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            raise InvalidParams("Tool arguments must be an object.")
        tools = {
            "list_objects": self._list_objects,
            "request_deletion": self._request_deletion,
            "get_deletion_request": self._get_request,
            "list_my_deletion_requests": self._list_requests,
        }
        if name not in tools:
            raise InvalidParams(f"Unknown tool: {name}")
        try:
            return _tool_result(tools[name](args))
        except GatewayError as exc:
            return _tool_result({"error": exc.code, "message": str(exc)}, is_error=True)
        except Exception as exc:  # noqa: BLE001
            log.exception("Tool %s failed", name)
            return _tool_result({"error": "internal_error", "message": str(exc)}, is_error=True)

    @staticmethod
    def _require(args: dict, *names: str) -> None:
        missing = [n for n in names if n not in args]
        if missing:
            raise GatewayError("missing_arguments", f"Missing required argument(s): {', '.join(missing)}.")

    def _list_objects(self, args: dict) -> dict:
        return self.port.list_objects(str(args.get("prefix") or ""))

    def _request_deletion(self, args: dict) -> dict:
        self._require(args, "object_key", "reason", "risk_score")
        return self.port.request_deletion(args["object_key"], args["reason"], args["risk_score"])

    def _get_request(self, args: dict) -> dict:
        self._require(args, "request_id")
        return self.port.get_request(str(args["request_id"]))

    def _list_requests(self, args: dict) -> dict:
        return {"requests": self.port.list_requests(args.get("status") or None)}

    def serve(self, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> None:
        stdin = stdin or sys.stdin.buffer
        stdout = stdout or sys.stdout.buffer
        for raw in stdin:
            line = raw.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                response: Any = _error(None, -32700, "Parse error")
            else:
                response = self.handle(message)
            if response is not None:
                stdout.write(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
                stdout.flush()
