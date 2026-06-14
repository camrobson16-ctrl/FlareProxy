# (updated)
import json
import os
import socket
import signal
import threading
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, urlunparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configuration via env vars
PORT = int(os.getenv("FLAREPROXY_PORT", "8080"))
TUNNEL_POLICY = os.getenv("FLAREPROXY_TUNNEL_POLICY", "raw")  # raw or flaresolverr
LOG_LEVEL = os.getenv("FLAREPROXY_LOG_LEVEL", "INFO")

# Setup structured logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("flareproxy")

# Create a requests.Session with retries/timeouts
session = requests.Session()
retries = Retry(total=3, backoff_factor=0.5, status_forcelist=(429, 502, 503, 504))
adapter = HTTPAdapter(max_retries=retries)
session.mount("http://", adapter)
session.mount("https://", adapter)


# Headers to forward (whitelist) and hop-by-hop headers to strip
FORWARD_WHITELIST = {
    "User-Agent",
    "Accept",
    "Accept-Language",
    "Cookie",
    "Referer",
    "Authorization",
    "Accept-Encoding",
}
HOP_BY_HOP = {
    "Connection",
    "Keep-Alive",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "TE",
    "Trailers",
    "Transfer-Encoding",
    "Upgrade",
}


def get_flaresolverr_url() -> str:
    """Read FLARESOLVERR_URL lazily so tests can set env before running the proxy."""
    return os.getenv("FLARESOLVERR_URL", "http://flaresolverr:8191/v1")


def build_target_url(raw_path: str, headers) -> str:
    parsed = urlparse(raw_path)
    if not parsed.scheme:
        host = headers.get("Host") if headers is not None else None
        scheme = "http"
        path = raw_path
        if host:
            parsed = urlparse(f"{scheme}://{host}{path}")
        else:
            parsed = urlparse(f"{scheme}://{raw_path}")
    if parsed.scheme != "https":
        parsed = parsed._replace(scheme="https")
    return urlunparse(parsed)


def prepare_forward_headers(in_headers) -> dict:
    result = {}
    for key in in_headers:
        if key is None:
            continue
        if key in HOP_BY_HOP:
            continue
        if key in FORWARD_WHITELIST:
            result[key] = in_headers[key]
    return result


def extract_request_body(method: str, headers, rfile) -> tuple:
    if method.upper() not in ("POST", "PUT", "PATCH"):
        return None, None
    content_length = headers.get("Content-Length")
    if content_length is None:
        return None, None
    try:
        length = int(content_length)
        body = rfile.read(length)
        content_type = headers.get("Content-Type", "application/octet-stream")
        return body, content_type
    except Exception:
        return None, None


def build_flaresolverr_payload(method: str, raw_path: str, headers, rfile) -> dict:
    target_url = build_target_url(raw_path, headers)
    forward_headers = prepare_forward_headers(headers)
    body_bytes, body_content_type = extract_request_body(method, headers, rfile)

    payload = {
        "cmd": "request.get",
        "url": target_url,
        "maxTimeout": 60000,
    }
    if forward_headers:
        payload["headers"] = forward_headers
    if body_bytes is not None:
        payload["method"] = "POST"
        payload["postData"] = {
            "content": body_bytes.decode("utf-8", errors="replace"),
            "contentType": body_content_type or "application/octet-stream",
        }
    return payload


class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):
    server_version = "FlareProxy/0.1"

    def send_json_error(self, status: int, message: str):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        payload = {"error": message}
        body = json.dumps(payload).encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_request(self):
        if self.path == "/healthz" and self.command == "GET":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"status": "ok"}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        try:
            payload = build_flaresolverr_payload(self.command, self.path, self.headers, self.rfile)
            logger.debug("FlareSolverr payload: %s", payload)

            # Use lazy getter here so tests that set FLARESOLVERR_URL after import work
            fsr = session.post(get_flaresolverr_url(), headers={"Content-Type": "application/json"}, json=payload, timeout=65)

            if fsr.status_code >= 500:
                logger.error("FlareSolverr returned %d", fsr.status_code)
                self.send_json_error(502, "Upstream FlareSolverr error")
                return

            try:
                fsr_json = fsr.json()
            except ValueError:
                fsr_json = None

            if fsr_json and isinstance(fsr_json, dict):
                solved = fsr_json.get("solution", {}).get("response", "")
                content_type = fsr_json.get("solution", {}).get("contentType", "text/html; charset=utf-8")
                status = fsr_json.get("status", fsr.status_code) if "status" in fsr_json else fsr.status_code
            else:
                solved = fsr.text
                content_type = fsr.headers.get("Content-Type", "text/html; charset=utf-8")
                status = fsr.status_code

            body = solved.encode("utf-8") if isinstance(solved, str) else solved

            self.send_response(status if 100 <= status < 600 else 200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        except requests.exceptions.RequestException as re:
            logger.exception("Network/request error: %s", re)
            self.send_json_error(504, "Timeout or network error with upstream")
        except Exception as e:
            logger.exception("Unexpected error handling request")
            self.send_json_error(500, str(e))

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def do_PUT(self):
        self.handle_request()

    def do_PATCH(self):
        self.handle_request()

    def do_CONNECT(self):
        if TUNNEL_POLICY.lower() == "flaresolverr":
            logger.info("Requested CONNECT but policy=Flaresolverr; falling back to raw tunnel")
        host_port = self.path
        try:
            host, sep, port_str = host_port.partition(":")
            port = int(port_str) if port_str else 443
            remote_sock = socket.create_connection((host, port), timeout=10)
        except Exception:
            self.send_error(502, "Bad Gateway")
            return

        self.send_response(200, "Connection Established")
        self.end_headers()

        client_sock = self.connection

        def forward(src: socket.socket, dst: socket.socket):
            try:
                while True:
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except Exception:
                    pass

        t1 = threading.Thread(target=forward, args=(client_sock, remote_sock), daemon=True)
        t2 = threading.Thread(target=forward, args=(remote_sock, client_sock), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        try:
            remote_sock.close()
        except Exception:
            pass

    def log_message(self, format, *args):
        logger.info("%s - - [%s] %s", self.client_address[0], self.log_date_time_string(), format % args)


class GracefulHTTPServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass):
        super().__init__(server_address, RequestHandlerClass)
        self._shutdown_event = threading.Event()

    def serve_forever(self, poll_interval=0.5):
        logger.info("Server starting on port %d", PORT)
        try:
            while not self._shutdown_event.is_set():
                self.handle_request()
        finally:
            logger.info("Server stopped")

    def shutdown(self):
        self._shutdown_event.set()
        super().shutdown()


def _signal_handler(signum, frame):
    logger.info("Signal %s received, shutting down", signum)
    global httpd
    try:
        httpd.shutdown()
    except Exception:
        pass


if __name__ == "__main__":
    server_address = ("", PORT)
    httpd = GracefulHTTPServer(server_address, ProxyHTTPRequestHandler)
    signal.signal(signal.SIGINT, _signal_handler)
    try:
        signal.signal(signal.SIGTERM, _signal_handler)
    except Exception:
        pass
    httpd.serve_forever()