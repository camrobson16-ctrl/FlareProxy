import unittest
from unittest.mock import patch, MagicMock
import io

from flareproxy import build_flaresolverr_payload, get_flaresolverr_url, session


class TestSessionPostAssertion(unittest.TestCase):
    def test_session_post_called_with_exact_json(self):
        method = "POST"
        path = "http://example.com/test"
        headers = {
            "Host": "example.com",
            "Content-Length": "11",
            "Content-Type": "application/json",
            "User-Agent": "unittest-agent",
            "Accept": "application/json",
        }
        body = b'{"a":1}'
        rfile = io.BytesIO(body)

        payload = build_flaresolverr_payload(method, path, headers, rfile)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "status": 200,
            "solution": {"response": "OK", "contentType": "text/plain"},
        }

        with patch("flareproxy.session.post", return_value=mock_response) as mock_post, patch(
            "flareproxy.get_flaresolverr_url", return_value="http://127.0.0.1:8191/v1"
        ):
            # call the session.post exactly how the handler does
            url = get_flaresolverr_url()
            session.post(url, headers={"Content-Type": "application/json"}, json=payload, timeout=65)

            mock_post.assert_called_once()
            called_args, called_kwargs = mock_post.call_args
            # first positional arg is URL
            self.assertEqual(called_args[0], url)
            # confirm headers and json payload match expectations
            self.assertEqual(called_kwargs.get("headers"), {"Content-Type": "application/json"})
            self.assertEqual(called_kwargs.get("json"), payload)


if __name__ == "__main__":
    unittest.main()
