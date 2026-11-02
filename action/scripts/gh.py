#!/usr/bin/env python3
"""
A tiny stdlib-only GitHub REST client, used only by the check-run lifecycle.

Scope is deliberately narrow. This client never posts review content -- that is
`packages/core`'s `post` phase, which runs in its own step with its own token.
This module exists so the Actions layer can create and, above all, *finish* the
check run that gates merges, without taking a dependency that a `pip install`
could fail to resolve mid-incident.

Retry policy is tuned for the one failure that actually matters: a check run
left `in_progress`. A required check stuck pending makes every open pull request
unmergeable, which is strictly worse than a missing review, so completion
attempts retry hard and treat "already completed" as success.
"""
from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.request

DEFAULT_API = "https://api.github.com"
USER_AGENT = "ai-code-review-action"

# 5xx and 429 are transient. 403 is included because GitHub returns it for
# secondary rate limits, which are also transient.
RETRY_STATUS = frozenset({403, 408, 429, 500, 502, 503, 504})


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str, body: str = ""):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {message}")


def api_url() -> str:
    return (os.environ.get("GITHUB_API_URL") or DEFAULT_API).rstrip("/")


def request(
    method: str,
    path: str,
    *,
    token: str,
    payload: dict | None = None,
    attempts: int = 5,
    base_delay: float = 1.0,
    timeout: float = 30.0,
) -> dict:
    """One REST call with bounded exponential backoff and jitter.

    Raises GitHubError on a non-retryable status or after the last attempt.
    `urllib.error.HTTPError` is always caught here; letting it escape as a
    traceback was one of the verified v0.5.0 write-path bugs and there is no
    reason to repeat it in a different module.
    """
    url = path if path.startswith("http") else f"{api_url()}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    last: Exception | None = None

    for attempt in range(1, attempts + 1):
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", USER_AGENT)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8") or "{}"
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")
            except Exception:  # pragma: no cover - best effort only
                pass
            last = GitHubError(exc.code, exc.reason or "error", body)
            if exc.code not in RETRY_STATUS or attempt == attempts:
                raise last from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = exc
            if attempt == attempts:
                raise GitHubError(0, f"network failure: {exc}") from None

        delay = min(base_delay * (2 ** (attempt - 1)), 20.0)
        time.sleep(delay + random.uniform(0, 0.5))

    raise GitHubError(0, f"exhausted retries: {last}")  # pragma: no cover


def split_repo(repo: str) -> tuple[str, str]:
    if repo.count("/") != 1 or not all(repo.split("/")):
        raise ValueError(f"repo must be 'owner/name', got {repo!r}")
    owner, name = repo.split("/")
    return owner, name
