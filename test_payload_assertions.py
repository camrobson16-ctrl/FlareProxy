import unittest
import io
from flareproxy import build_flaresolverr_payload


class DummyRfile:
    def __init__(self, data: bytes):
        self._io = io.BytesIO(data)

    def read(self, n=-1):
        return self._io.read(n)


class TestPayloadConstruction(unittest.TestCase):
    def test_payload_contains_postdata_and_headers(self):
        method = "POST"
        path = "http://example.com/test"
        headers = {
            "Host": "example.com",
            "Content-Length": "11",
            "Content-Type": "application/json",
            "User-Agent": "unittest-agent",
            "Accept": "application/json",
            "Connection": "keep-alive",
        }
        body = b'{"a":1}'
        rfile = DummyRfile(body)

        payload = build_flaresolverr_payload(method, path, headers, rfile)

        self.assertEqual(payload["cmd"], "request.get")
        self.assertIn("url", payload)
        self.assertEqual(payload["method"], "POST")
        self.assertIn("postData", payload)
        self.assertEqual(payload["postData"]["content"], body.decode("utf-8"))
        # User-Agent and Accept should be forwarded; Connection should be stripped
        self.assertIn("headers", payload)
        self.assertIn("User-Agent", payload["headers"])
        self.assertIn("Accept", payload["headers"])
        self.assertNotIn("Connection", payload["headers"])


if __name__ == "__main__":
    unittest.main()
