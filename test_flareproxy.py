import unittest
from unittest.mock import patch, MagicMock
from flareproxy import (
    build_target_url,
    prepare_forward_headers,
    extract_request_body,
)
import io


class TestBuildTargetUrl(unittest.TestCase):
    def test_absolute_http_becomes_https(self):
        url = "http://example.com/some/path?x=1"
        result = build_target_url(url, {})
        self.assertTrue(result.startswith("https://"))
        self.assertIn("example.com/some/path", result)

    def test_absolute_https_keeps_https(self):
        url = "https://secure.example.com/"
        result = build_target_url(url, {})
        self.assertEqual(result, "https://secure.example.com/")

    def test_path_with_host_header(self):
        path = "/foo/bar?q=1"
        headers = {"Host": "example.org"}
        result = build_target_url(path, headers)
        self.assertEqual(result, "https://example.org/foo/bar?q=1")

    def test_path_without_host_uses_raw(self):
        path = "somehost/path"
        result = build_target_url(path, {})
        self.assertTrue(result.startswith("https://"))


class TestHeaderForwarding(unittest.TestCase):
    def test_prepare_forward_headers_filters_hop_by_hop_and_whitelist(self):
        headers = {
            "User-Agent": "UA",
            "Accept": "text/html",
            "Connection": "keep-alive",
            "Proxy-Authorization": "secret",
            "X-Custom": "value",
            "Cookie": "a=1",
        }
        forwarded = prepare_forward_headers(headers)
        self.assertIn("User-Agent", forwarded)
        self.assertIn("Accept", forwarded)
        self.assertIn("Cookie", forwarded)
        self.assertNotIn("Connection", forwarded)
        self.assertNotIn("Proxy-Authorization", forwarded)
        self.assertNotIn("X-Custom", forwarded)

    def test_prepare_forward_headers_empty(self):
        self.assertEqual(prepare_forward_headers({}), {})


class DummyHandler:
    def __init__(self, body_bytes, content_type=None):
        self.rfile = io.BytesIO(body_bytes)
        self.headers = {}
        if content_type:
            self.headers["Content-Type"] = content_type
        self.headers["Content-Length"] = str(len(body_bytes))


class TestBodyExtraction(unittest.TestCase):
    def test_extract_post_body(self):
        body = b'{"a":1}'
        handler = DummyHandler(body, "application/json")
        content, content_type = extract_request_body("POST", handler.headers, handler.rfile)
        self.assertEqual(content, body)
        self.assertEqual(content_type, "application/json")

    def test_no_body_for_get(self):
        handler = DummyHandler(b"")
        content, content_type = extract_request_body("GET", handler.headers, handler.rfile)
        self.assertIsNone(content)
        self.assertIsNone(content_type)


if __name__ == "__main__":
    unittest.main()