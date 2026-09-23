"""Mock upstream astra-mcp (mode Opus) pour smoke local claude-opus-mcp.

- Sans auth (comme le Python : isolation systemd).
- Sert initialize / tools/list (3 outils) / tools/call opus_health /
  resources/list / prompts/list.
- Usage: python mock_upstream.py <port>
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18794

TOOLS = [
    {"name": "opus_health", "description": "Sante", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "opus_think", "description": "Delegation", "inputSchema": {"type": "object", "properties": {}}},
    {"name": "opus_session", "description": "Sessions", "inputSchema": {"type": "object", "properties": {}}},
]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.send_header("mcp-session-id", "mock-astra-session")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/mcp":
            self.send_response(404)
            self.end_headers()
            return
        ln = int(self.headers.get("Content-Length", 0))
        try:
            data = json.loads(self.rfile.read(ln) or b"{}")
        except ValueError:
            self._send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse"}})
            return
        rid = data.get("id")
        method = data.get("method")
        if method == "initialize":
            self._send({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2025-11-25",
                "serverInfo": {"name": "astra-mcp", "version": "mock"},
                "capabilities": {"tools": {}}}})
        elif method == "tools/list":
            self._send({"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}})
        elif method == "tools/call" and (data.get("params") or {}).get("name") == "opus_health":
            self._send({"jsonrpc": "2.0", "id": rid, "result": {
                "content": [{"type": "text", "text": "ok"}]}})
        elif method in ("resources/list",):
            self._send({"jsonrpc": "2.0", "id": rid, "result": {"resources": []}})
        elif method in ("prompts/list",):
            self._send({"jsonrpc": "2.0", "id": rid, "result": {"prompts": []}})
        else:
            self._send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "mock: non gere"}})


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
