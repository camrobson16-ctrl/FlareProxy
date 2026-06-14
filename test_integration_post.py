import unittest
import threading
import json
import time
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import os

from flareproxy import GracefulHTTPServer, ProxyHTTPRequestHandler

# Simple dummy FlareSolverr that echoes a solved response
class DummyFSRHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length) if content_length > 0 else b""
        # return a minimal FlareSolverr-like JSON
        resp = {
            "status": 200,
            "solution": {
                "response": "DUMMY_OK",
                "contentType": "text/plain"
            }
        }
        data = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def find_free_port():
    s = socket.socket()
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestIntegrationPost(unittest.TestCase):
    def setUp(self):
        # start dummy FlareSolverr
        self.fsr_port = find_free_port()
        self.fsr_server = HTTPServer(("127.0.0.1", self.fsr_port), DummyFSRHandler)
        self.fsr_thread = threading.Thread(target=self.fsr_server.serve_forever, daemon=True)
        self.fsr_thread.start()
        time.sleep(0.05)

        # start proxy
        self.proxy_port = find_free_port()
        os.environ["FLARESOLVERR_URL"] = f"http://127.0.0.1:{self.fsr_port}/v1"
        self.proxy_server = GracefulHTTPServer(("127.0.0.1", self.proxy_port), ProxyHTTPRequestHandler)
        self.proxy_thread = threading.Thread(target=self.proxy_server.serve_forever, daemon=True)
        self.proxy_thread.start()
        time.sleep(0.05)

    def tearDown(self):
        try:
            self.proxy_server.shutdown()
        except Exception:
            pass
        try:
            self.fsr_server.shutdown()
        except Exception:
            pass

    def test_post_through_proxy_returns_dummy(self):
        proxies = {"http": f"http://127.0.0.1:{self.proxy_port}", "https": f"http://127.0.0.1:{self.proxy_port}"}
        resp = requests.post("http://example.test/some", proxies=proxies, json={"a": 1}, timeout=5)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.text, "DUMMY_OK")


if __name__ == "__main__":
    unittest.main()
