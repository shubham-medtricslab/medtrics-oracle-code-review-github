#!/usr/bin/env python3
"""
The GitHub write client.

`github_write.py:79-89` wrapped a bare `urllib.request.urlopen`:

    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))

A 422 or a 403 from that raises `urllib.error.HTTPError`, which is not a
`GitHubError`, so the `except GitHubError` at `:145` never saw it. The caller
got an unhandled traceback - no retry, no secondary-rate-limit backoff, no
degradation. All of that logic existed, but only on the READ client's `_get`
(`github_client.py:102-121`); the write path never got it.

So this client:

  * catches `urllib.error.HTTPError` on every request and converts it to
    `GitHubWriteError`, which carries the status and the parsed response body.
    A caller handling a 422 needs the `errors` array to say anything useful;
    a bare exception string is not enough;
  * honours `Retry-After` and `X-RateLimit-Reset` on 403 and 429, which is how
    GitHub signals a secondary rate limit, and backs off on 5xx;
  * does NOT retry a 422. A 422 is deterministic - the same payload will be
    rejected the same way - so retrying it just wastes the run. Degrading the
    payload is the poster's job, not the transport's;
  * takes its endpoint and its token from `aireview.auth`, injected. Nothing
    here reads a file, and in particular nothing reads a `.env` from a
    checkout.

`opener` and `sleep` are injectable so the tests never touch the network and
never actually sleep.

Stdlib only.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

try:  # pragma: no cover - import shape differs under the test harness only
    from ..auth import Endpoint, PUBLIC_API
except ImportError:  # pragma: no cover
    from aireview.auth import Endpoint, PUBLIC_API

__all__ = ["GitHubWriteClient", "GitHubWriteError", "MAX_RETRIES"]

MAX_RETRIES = 5
INITIAL_BACKOFF = 2.0
MAX_BACKOFF = 60.0
TIMEOUT = 30
USER_AGENT = "ai-code-review"
API_VERSION = "2022-11-28"

# Deterministic failures. Retrying cannot change the outcome, and on
# `POST /pulls/{n}/reviews` a retry would risk a duplicate review if the first
# attempt actually succeeded behind a timeout.
_NO_RETRY = frozenset({400, 401, 404, 410, 422})
_RATE_LIMITED = frozenset({403, 429})


class GitHubWriteError(Exception):
    """A typed, catchable GitHub failure.

    `status` and `payload` are the point: the poster has to distinguish a 422
    (degrade to summary-only) from a 403 (give up) from a 404 (the pull
    request is gone), and it cannot do that from a string.
    """

    def __init__(self, status, message, payload=None):
        super().__init__(f"GitHub API {status}: {message}")
        self.status = status
        self.payload = payload or {}

    @property
    def is_validation_error(self):
        return self.status == 422


class GitHubWriteClient:
    """Read and write the few endpoints the poster needs.

    Reads are here as well as writes because posting correctly REQUIRES them:
    the live head has to be re-read before posting, and the bot's own existing
    comments have to be reconciled against. Neither is optional.
    """

    def __init__(self, token_provider, endpoint=None, *,
                 opener=None, sleep=None):
        self._tokens = token_provider
        self._endpoint = endpoint if endpoint is not None else Endpoint(PUBLIC_API)
        self._opener = opener or urllib.request.urlopen
        self._sleep = sleep or time.sleep

    # -- transport --------------------------------------------------------- #
    def _request(self, method, path, payload=None, params=None):
        url = str(self._endpoint) + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        body = json.dumps(payload).encode("utf-8") if payload is not None else None

        backoff = INITIAL_BACKOFF
        last = None
        for attempt in range(MAX_RETRIES):
            # Resolved per attempt: an installation token lives one hour, and
            # a run that backed off through a rate limit can outlive one.
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header("Authorization", f"Bearer {self._tokens.token()}")
            req.add_header("Accept", "application/vnd.github+json")
            req.add_header("X-GitHub-Api-Version", API_VERSION)
            req.add_header("User-Agent", USER_AGENT)
            if body is not None:
                req.add_header("Content-Type", "application/json")
            try:
                with self._opener(req, timeout=TIMEOUT) as resp:
                    raw = resp.read().decode("utf-8")
                    headers = getattr(resp, "headers", {}) or {}
                    return (json.loads(raw) if raw else None), headers
            except urllib.error.HTTPError as exc:
                last = exc
                parsed = _read_error_body(exc)
                if exc.code in _NO_RETRY:
                    raise GitHubWriteError(
                        exc.code, parsed.get("message") or exc.reason, parsed
                    ) from None
                if exc.code in _RATE_LIMITED:
                    self._sleep(min(_rate_limit_wait(exc, backoff), MAX_BACKOFF))
                    backoff *= 2
                    continue
                if 500 <= exc.code < 600:
                    self._sleep(min(backoff, MAX_BACKOFF))
                    backoff *= 2
                    continue
                raise GitHubWriteError(
                    exc.code, parsed.get("message") or exc.reason, parsed
                ) from None
            except urllib.error.URLError as exc:
                last = exc
                self._sleep(min(backoff, MAX_BACKOFF))
                backoff *= 2
                continue

        raise GitHubWriteError(getattr(last, "code", 0),
                               f"exhausted {MAX_RETRIES} retries: {last}")

    def _get_paginated(self, path, params=None, cap_pages=10):
        params = dict(params or {})
        params.setdefault("per_page", 100)
        out = []
        for page in range(1, cap_pages + 1):
            params["page"] = page
            data, headers = self._request("GET", path, params=params)
            if not isinstance(data, list):
                return out
            out.extend(data)
            link = (headers or {}).get("Link") if hasattr(headers, "get") else None
            if not link or 'rel="next"' not in link:
                break
        return out

    # -- the endpoints the poster needs ------------------------------------ #
    def get_pull(self, repo, pr):
        data, _ = self._request("GET", f"/repos/{repo}/pulls/{pr}")
        return data or {}

    def live_head_sha(self, repo, pr):
        """The head SHA as GitHub sees it right now.

        Read immediately before posting. Every position in the review was
        computed against a specific SHA, and a push in between makes all of
        them stale.
        """
        return ((self.get_pull(repo, pr) or {}).get("head") or {}).get("sha")

    def list_review_comments(self, repo, pr):
        """Every inline review comment on the pull request.

        Used to reconcile against what is ACTUALLY posted rather than what the
        local dedup store believes was posted. Those differ after a crashed
        run, a lost cache, or a human deleting a comment.
        """
        return self._get_paginated(f"/repos/{repo}/pulls/{pr}/comments")

    def create_review(self, repo, pr, payload):
        """POST one review.

        Takes the whole payload rather than unpacking it into positional
        arguments. That is not style: `create_review(repo, pr, event, body,
        comments)` at `github_write.py:93` is precisely how `commit_id` was
        dropped - the caller computed it and the signature had nowhere to put
        it. A single dict cannot lose a field on the way through.
        """
        data, _ = self._request("POST", f"/repos/{repo}/pulls/{pr}/reviews",
                                payload=payload)
        return data or {}

    def create_issue_comment(self, repo, pr, body):
        data, _ = self._request("POST", f"/repos/{repo}/issues/{pr}/comments",
                                payload={"body": body})
        return data or {}


def _read_error_body(exc):
    try:
        raw = exc.read().decode("utf-8", "ignore")
    except Exception:  # noqa: BLE001 - the body is best-effort context
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return {"message": raw[:300]}
    return parsed if isinstance(parsed, dict) else {"message": str(parsed)[:300]}


def _rate_limit_wait(exc, fallback):
    """How long GitHub asked us to wait.

    `Retry-After` is what a secondary rate limit sends; `X-RateLimit-Reset` is
    what a primary one sends. Ignoring both and retrying immediately is how an
    app gets its installation suspended.
    """
    headers = getattr(exc, "headers", None)
    get = headers.get if hasattr(headers, "get") else (lambda _k: None)
    retry_after = get("Retry-After")
    if retry_after:
        try:
            return max(0, int(retry_after))
        except (TypeError, ValueError):
            pass
    reset = get("X-RateLimit-Reset")
    if reset:
        try:
            return max(0, int(reset) - int(time.time())) + 1
        except (TypeError, ValueError):
            pass
    return fallback
