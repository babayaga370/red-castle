"""The HTTP Gateway and the MCP server."""

from __future__ import annotations

import io
import json
import threading
import unittest
import urllib.error
import urllib.request

from redcastle.api import CastleHTTPServer
from redcastle.mcp_server import TOOLS, HttpAgentPort, LocalAgentPort, MCPServer
from redcastle.registry import Status

from .helpers import CastleTestCase


class HttpTests(CastleTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.server = CastleHTTPServer(("127.0.0.1", 0), self.castle)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def call(self, method: str, path: str, token: str | None = None, body: dict | None = None) -> tuple[int, dict]:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            with exc:
                return exc.code, json.loads(exc.read() or b"{}")

    def test_agent_request_and_human_decision(self) -> None:
        self.put("old.log")
        status, view = self.call("POST", "/api/v1/deletion-requests", self.token,
                                 {"object_key": "old.log", "reason": "Rotated log file, no longer needed", "risk_score": 5})
        self.assertEqual(status, 202)
        self.assertEqual(view["status"], Status.QUARANTINED)

        self.castle.throne.approve(view["request_id"], by="alice")  # the human decides in the terminal

        status, mine = self.call("GET", f"/api/v1/deletion-requests/{view['request_id']}", self.token)
        self.assertEqual(mine["status"], Status.EXECUTED)
        status, listing = self.call("GET", "/api/v1/deletion-requests?status=executed", self.token)
        self.assertEqual(len(listing["requests"]), 1)

    def test_rejections_return_403(self) -> None:
        status, view = self.call("POST", "/api/v1/deletion-requests", self.token,
                                 {"object_key": "../x", "reason": "trying to escape", "risk_score": 5})
        self.assertEqual(status, 403)
        self.assertEqual(view["reason_code"], "invalid_key")

    def test_authentication(self) -> None:
        self.assertEqual(self.call("GET", "/api/v1/objects")[0], 401)
        self.assertEqual(self.call("GET", "/api/v1/objects", "wrong")[0], 401)
        self.assertEqual(self.call("GET", "/api/v1/objects", self.token)[0], 200)

    def test_no_web_interface_or_admin_api(self) -> None:
        for path in ("/throne", "/throne/api/cases", "/admin"):
            self.assertEqual(self.call("GET", path, self.token)[0], 404, path)

    def test_mcp_over_http(self) -> None:
        self.put("x.tmp")
        server = MCPServer(HttpAgentPort(self.base, self.token))
        result = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "request_deletion",
            "arguments": {"object_key": "x.tmp", "reason": "Temporary file from a build", "risk_score": 0},
        }})["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["status"], Status.QUARANTINED)

        bad = MCPServer(HttpAgentPort(self.base, "wrong-token"))
        result = bad.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                             "params": {"name": "list_objects", "arguments": {}}})["result"]
        self.assertTrue(result["isError"])


class McpTests(CastleTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.server = MCPServer(LocalAgentPort(self.castle, self.token))

    def rpc(self, method: str, params: dict | None = None, msg_id: int = 1) -> dict:
        return self.server.handle({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})

    def test_initialize_and_list_tools(self) -> None:
        init = self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "test", "version": "1"}})["result"]
        self.assertEqual(init["protocolVersion"], "2025-06-18")
        self.assertIn("tools", init["capabilities"])
        names = {t["name"] for t in self.rpc("tools/list")["result"]["tools"]}
        self.assertEqual(names, {"list_objects", "request_deletion", "get_deletion_request", "list_my_deletion_requests"})
        # No tool may delete, approve or restore.
        for tool in TOOLS:
            self.assertFalse(tool["annotations"].get("destructiveHint", False))

    def test_request_and_follow_up(self) -> None:
        self.put("a.txt")
        call = self.rpc("tools/call", {"name": "request_deletion", "arguments": {
            "object_key": "a.txt", "reason": "Duplicate of b.txt", "risk_score": 10}})["result"]
        request_id = call["structuredContent"]["request_id"]
        status = self.rpc("tools/call", {"name": "get_deletion_request", "arguments": {"request_id": request_id}})
        self.assertEqual(status["result"]["structuredContent"]["status"], Status.QUARANTINED)
        listing = self.rpc("tools/call", {"name": "list_objects", "arguments": {}})["result"]["structuredContent"]
        self.assertNotIn("a.txt", [o["key"] for o in listing["objects"]])

    def test_missing_arguments_are_a_tool_error_not_a_strike(self) -> None:
        result = self.rpc("tools/call", {"name": "request_deletion", "arguments": {"object_key": "a.txt"}})["result"]
        self.assertTrue(result["isError"])
        self.assertEqual(self.castle.registry.list_requests(), [])

    def test_protocol_errors(self) -> None:
        self.assertEqual(self.rpc("nope")["error"]["code"], -32601)
        self.assertEqual(self.rpc("tools/call", {"name": "delete_everything"})["error"]["code"], -32602)
        self.assertIsNone(self.server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_stdio_loop(self) -> None:
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2099-01-01"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "ping"},
        ]
        stdin = io.BytesIO(b"".join(json.dumps(m).encode() + b"\n" for m in lines) + b"not json\n")
        stdout = io.BytesIO()
        self.server.serve(stdin, stdout)
        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual([r.get("id") for r in responses], [1, 2, None])
        self.assertEqual(responses[0]["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(responses[2]["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()
