"""The HTTP Gateway and the MCP server."""

from __future__ import annotations

import http.server
import io
import json
import os
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

from redcastle.api import CastleHTTPServer, CastleRequestHandler
from redcastle.gateway import GatewayError
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

    def stalled(self, token: str | None = None) -> socket.socket:
        """A client that promises a body and then goes quiet."""
        sock = socket.create_connection(self.server.server_address[:2], timeout=10)
        auth = f"Authorization: Bearer {token}\r\n" if token else ""
        sock.sendall(f"POST /api/v1/deletion-requests HTTP/1.0\r\n{auth}Content-Length: 100\r\n\r\n".encode())
        return sock

    def test_a_stalled_client_holds_up_nobody(self) -> None:
        self.put("old.log")
        with self.stalled(self.token):
            time.sleep(0.2)
            status, _ = self.call("POST", "/api/v1/deletion-requests", self.token,
                                  {"object_key": "old.log", "reason": "Rotated log file, no longer needed", "risk_score": 5})
        self.assertEqual(status, 202)

    def test_a_client_that_never_finishes_its_body_is_cut_off(self) -> None:
        with mock.patch.object(CastleRequestHandler, "timeout", 0.2), self.stalled(self.token) as sock:
            self.assertIn(b" 400 ", sock.recv(200))

    def test_a_lost_connection_is_no_strike_against_the_agent(self) -> None:
        with self.stalled(self.token) as sock:
            sock.shutdown(socket.SHUT_WR)  # the body never comes
            self.assertIn(b" 400 ", sock.recv(200))
        self.assertEqual(self.call("POST", "/api/v1/deletion-requests", self.token)[0], 400)  # no body at all
        self.assertEqual(self.castle.registry.list_requests(), [])

    def test_strangers_are_turned_away_before_their_body_is_read(self) -> None:
        with self.stalled() as sock:
            self.assertIn(b" 401 ", sock.recv(200))

    def test_connections_are_capped(self) -> None:
        with mock.patch("redcastle.api.MAX_CONNECTIONS", 1):
            server = CastleHTTPServer(("127.0.0.1", 0), self.castle)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        with socket.create_connection(server.server_address[:2], timeout=5) as held:
            held.sendall(b"GET /health")  # never finished, so it keeps the only slot
            time.sleep(0.2)
            with socket.create_connection(server.server_address[:2], timeout=5) as turned_away:
                try:
                    self.assertEqual(turned_away.recv(100), b"")
                except ConnectionError:
                    pass
        deadline = time.time() + 5
        while time.time() < deadline:  # and the slot comes back
            with socket.create_connection(server.server_address[:2], timeout=5) as sock:
                sock.sendall(b"GET /health HTTP/1.0\r\n\r\n")
                try:
                    if sock.recv(100).startswith(b"HTTP/1.0 200"):
                        return
                except ConnectionError:
                    pass
            time.sleep(0.05)
        self.fail("the slot was never released")

    def test_absurdly_nested_json_is_just_bad_json(self) -> None:
        body = b"[" * 60000
        request = urllib.request.Request(
            self.base + "/api/v1/deletion-requests", data=body, method="POST",
            headers={"Authorization": f"Bearer {self.token}"},
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=10)
        with caught.exception:
            self.assertEqual(caught.exception.code, 400)

    def test_the_gateway_answers_while_a_deletion_is_being_decided(self) -> None:
        with self.castle.lock:  # held by a request that is busy moving a huge file, say
            self.assertEqual(self.call("GET", "/health")[0], 200)
            self.assertEqual(self.call("GET", "/api/v1/objects", self.token)[0], 200)
            self.assertEqual(self.call("GET", "/api/v1/deletion-requests", self.token)[0], 200)

    def test_listing_comes_in_pages(self) -> None:
        self.put("a.txt")
        self.put("b.txt")
        _, first = self.call("GET", "/api/v1/objects?limit=1", self.token)
        self.assertTrue(first["truncated"])
        _, second = self.call("GET", f"/api/v1/objects?limit=1&after={first['next_after']}", self.token)
        self.assertEqual([o["key"] for o in second["objects"]], ["b.txt"])

    def test_listing_pages_through_mcp(self) -> None:
        self.put("a.txt")
        self.put("b.txt")
        port = HttpAgentPort(self.base, self.token)
        self.assertEqual([o["key"] for o in port.list_objects("", "a.txt")["objects"]], ["b.txt"])

    @unittest.skipIf(os.name == "nt", "Windows file names are always valid Unicode")
    def test_a_file_name_that_is_not_unicode_does_not_break_the_listing(self) -> None:
        try:
            with open(os.fsencode(self.realm) + b"/\xff.txt", "wb"):
                pass
        except OSError:
            self.skipTest("this file system insists on valid names")
        self.put("a.txt")
        status, listing = self.call("GET", "/api/v1/objects", self.token)
        self.assertEqual(status, 200)
        self.assertEqual(len(listing["objects"]), 2)

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


class TokenSafetyTests(unittest.TestCase):
    def test_a_redirect_never_carries_the_token_elsewhere(self) -> None:
        received: list[str | None] = []

        class Elsewhere(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                received.append(self.headers.get("Authorization"))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args: object) -> None:
                pass

        class Redirecting(Elsewhere):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{elsewhere.server_address[1]}/stolen")
                self.send_header("Content-Length", "0")
                self.end_headers()

        elsewhere = http.server.HTTPServer(("127.0.0.1", 0), Elsewhere)
        redirecting = http.server.HTTPServer(("127.0.0.1", 0), Redirecting)
        for server in (elsewhere, redirecting):
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        port = HttpAgentPort(f"http://127.0.0.1:{redirecting.server_address[1]}", "rc_agent_secret")
        with self.assertRaises(GatewayError):
            port.list_objects("")
        self.assertEqual(received, [])


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

    def test_malformed_messages_do_not_end_the_session(self) -> None:
        lines = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": [1]},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": ["unhashable"]}},
            {"jsonrpc": "2.0", "id": 3, "method": "ping"},
        ]
        stdout = io.BytesIO()
        self.server.serve(io.BytesIO(b"".join(json.dumps(m).encode() + b"\n" for m in lines)), stdout)
        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual([r["error"]["code"] for r in responses[:2]], [-32602, -32602])
        self.assertEqual(responses[2]["result"], {})

    def test_unexpected_failures_are_answered_not_fatal(self) -> None:
        with mock.patch.object(self.server, "_initialize", side_effect=RuntimeError("boom")):
            self.assertEqual(self.rpc("initialize")["error"]["code"], -32603)

    def test_internal_errors_tell_the_agent_nothing(self) -> None:
        with mock.patch.object(self.gw, "list_objects", side_effect=OSError(r"C:\private\castle.db is locked")):
            result = self.rpc("tools/call", {"name": "list_objects"})["result"]
        self.assertTrue(result["isError"])
        self.assertNotIn("private", json.dumps(result))

    def test_absurdly_nested_json_is_just_a_parse_error(self) -> None:
        stdout = io.BytesIO()
        self.server.serve(io.BytesIO(b"[" * 200000 + b'\n{"jsonrpc": "2.0", "id": 2, "method": "ping"}\n'), stdout)
        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["result"], {})

    def test_broken_unicode_cannot_break_the_output(self) -> None:
        call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_objects"}}
        stdout = io.BytesIO()
        with mock.patch.object(self.server.port, "list_objects", return_value={"objects": [{"key": "\udcff.txt"}]}):
            self.server.serve(io.BytesIO(json.dumps(call).encode() + b"\n"), stdout)
        listing = json.loads(stdout.getvalue())["result"]["structuredContent"]
        self.assertEqual(listing["objects"][0]["key"], "\udcff.txt")

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
