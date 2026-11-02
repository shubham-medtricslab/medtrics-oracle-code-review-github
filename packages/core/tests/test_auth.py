#!/usr/bin/env python3
"""
Auth hardening tests.

The headline case: a pull request that commits a `.env` file must not be able to
redirect the parent's authenticated POST. In v0.5.0 it could, because
`github_client.py:45` included `os.getcwd()/.env` in the discovery list and
`:72` let `GITHUB_API_URL` from that file win whenever the process env did not
set it (which is the normal case - it ships commented out).

Stdlib only. Run: python3 packages/core/tests/test_auth.py
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from aireview.auth import (  # noqa: E402
    AuthError, Endpoint, EnvToken, PUBLIC_API, StaticToken,
    assert_no_credentials_in_workspace, resolve,
)

_passed = 0
_failed = []


def check(name, fn):
    global _passed
    try:
        fn()
    except AssertionError as e:
        _failed.append(f"{name}: {e}")
    except Exception as e:  # noqa: BLE001
        _failed.append(f"{name}: unexpected {type(e).__name__}: {e}")
    else:
        _passed += 1


# --------------------------------------------------------------------------- #
# THE regression: a committed .env cannot move the endpoint
# --------------------------------------------------------------------------- #
def test_dotenv_in_cwd_cannot_redirect_the_api():
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, ".env"), "w") as fh:
            fh.write("GITHUB_API_URL=https://attacker.example\n")
            fh.write("GITHUB_TOKEN=ghs_attacker_planted\n")
        cwd = os.getcwd()
        os.chdir(tmp)
        try:
            endpoint = Endpoint()
            assert str(endpoint) == PUBLIC_API, (
                f"a .env in cwd changed the endpoint to {endpoint}"
            )
            provider = StaticToken("ghs_real_token")
            assert provider.token() == "ghs_real_token", (
                "a .env in cwd must not supply or override the token"
            )
        finally:
            os.chdir(cwd)


def test_attacker_endpoint_rejected_even_if_injected():
    for bad in ("https://attacker.example",
                "https://api.github.com.evil.tld",
                "http://api.github.com",
                "https://evil/?x=api.github.com"):
        try:
            Endpoint(bad)
        except AuthError:
            continue
        raise AssertionError(f"accepted hostile endpoint {bad!r}")


def test_public_and_enterprise_endpoints_accepted():
    assert str(Endpoint()) == PUBLIC_API
    assert str(Endpoint("https://api.github.com")) == PUBLIC_API
    assert str(Endpoint("https://acme.ghe.com")) == "https://acme.ghe.com"


# --------------------------------------------------------------------------- #
# Token sourcing is explicit
# --------------------------------------------------------------------------- #
def test_env_token_requires_the_named_var():
    var = "AIREVIEW_TEST_TOKEN_ABSENT"
    os.environ.pop(var, None)
    try:
        EnvToken(var).token()
    except AuthError:
        return
    raise AssertionError("missing token must raise, not default to something")


def test_env_token_reads_only_the_named_var():
    var = "AIREVIEW_TEST_TOKEN_PRESENT"
    os.environ[var] = "ghs_from_process_env"
    try:
        assert EnvToken(var).token() == "ghs_from_process_env"
    finally:
        os.environ.pop(var, None)


def test_empty_static_token_rejected():
    for bad in ("", "   "):
        try:
            StaticToken(bad)
        except AuthError:
            continue
        raise AssertionError(f"accepted empty token {bad!r}")


def test_resolve_fails_fast_on_missing_token():
    var = "AIREVIEW_TEST_TOKEN_MISSING2"
    os.environ.pop(var, None)
    try:
        resolve(token_provider=EnvToken(var))
    except AuthError:
        return
    raise AssertionError("resolve must fail fast when the token is absent")


# --------------------------------------------------------------------------- #
# The credential-on-disk leak from the clone URL
# --------------------------------------------------------------------------- #
def test_credentials_in_url_clone_is_detected():
    """Proves the leak is real, and that our detector catches it.

    This is the v0.5.0 clone form. git persists the URL verbatim in
    .git/config as remote.origin.url, inside the workspace the reviewer
    agents hold Read and Grep over.
    """
    token = "ghs_leaky_token_value"
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        subprocess.run(["git", "init", "-q", src], check=True)
        subprocess.run(["git", "-C", src, "config", "user.email", "t@t.t"], check=True)
        subprocess.run(["git", "-C", src, "config", "user.name", "t"], check=True)
        open(os.path.join(src, "f.txt"), "w").write("hello\n")
        subprocess.run(["git", "-C", src, "add", "-A"], check=True)
        subprocess.run(["git", "-C", src, "commit", "-qm", "init"], check=True)

        ws = os.path.join(tmp, "ws")
        # Mimic the v0.5.0 clone URL shape against a local path.
        subprocess.run(["git", "clone", "-q", src, ws], check=True)
        subprocess.run(
            ["git", "-C", ws, "remote", "set-url", "origin",
             f"https://x-access-token:{token}@github.com/o/r.git"], check=True)

        hits = assert_no_credentials_in_workspace(ws, token)
        assert hits, "detector failed to find the token that git persisted"
        assert any(h.endswith(os.path.join(".git", "config")) for h in hits), (
            f"expected .git/config among {hits}"
        )

        # And the remediation: a tokenless remote leaves nothing behind.
        subprocess.run(
            ["git", "-C", ws, "remote", "set-url", "origin",
             "https://github.com/o/r.git"], check=True)
        assert not assert_no_credentials_in_workspace(ws, token), (
            "token still present after stripping it from the remote URL"
        )


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            check(_name, _fn)
    for f in _failed:
        print("FAIL " + f)
    print(f"{_passed} passed, {len(_failed)} failed")
    raise SystemExit(1 if _failed else 0)
