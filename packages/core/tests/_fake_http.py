"""
A urlopen stand-in for the write-path tests.

Both the frozen v0.5.0 reference and the new client ultimately call
`urlopen(request, timeout=...)`, so one fake drives both and the contract
assertions can inspect exactly what reached the wire. No network, ever.

Stdlib only.
"""
import io
import json
import urllib.error


class _Response:
    def __init__(self, body, headers=None, status=200):
        self._body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.headers = headers or {}
        self.status = status

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeHTTP:
    """Records every request; replays a scripted sequence of HTTP errors.

    `error_codes` is consumed one per call. Once exhausted, calls succeed with
    `response`. `calls` holds {"method", "url", "payload"} per request so a test
    can assert on the exact JSON body GitHub would have received.
    """

    def __init__(self, error_codes=(), response=None, headers=None):
        self.calls = []
        self._errors = list(error_codes or ())
        self.response = {"id": 12345} if response is None else response
        self.headers = headers or {}

    def __call__(self, req, timeout=None):
        payload = None
        if getattr(req, "data", None):
            payload = json.loads(req.data.decode("utf-8"))
        self.calls.append({
            "method": req.get_method(),
            "url": req.full_url,
            "payload": payload,
        })
        if self._errors:
            code = self._errors.pop(0)
            raise urllib.error.HTTPError(
                req.full_url, code, "scripted failure", self.headers,
                io.BytesIO(json.dumps(
                    {"message": "Validation Failed",
                     "errors": [{"resource": "PullRequestReviewComment",
                                 "field": "line", "code": "invalid"}]}
                ).encode()),
            )
        return _Response(self.response, self.headers)

    def review_payloads(self):
        """Every JSON body POSTed to .../pulls/{n}/reviews."""
        return [c["payload"] for c in self.calls
                if c["method"] == "POST" and c["url"].endswith("/reviews")]
