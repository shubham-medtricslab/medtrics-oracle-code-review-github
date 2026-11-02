#!/usr/bin/env python3
"""
The write-path contract, bound to the NEW implementation.

The same mixins `test_legacy_reference_bugs.py` runs as expected failures.
Everything here must pass, and the pair is the proof: identical assertions,
failing against the v0.5.0 code and passing against this one.

Run: python3 -m unittest tests.test_write_path
Stdlib only.
"""
import os
import sys
import tempfile
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.dirname(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from _fake_http import FakeHTTP, _Response  # noqa: E402
from _fixtures import HEAD_SHA  # noqa: E402
from write_path_contract import (  # noqa: E402
    DedupContract, HunkWalkerContract, PostContract,
)

from aireview.github.client import GitHubWriteClient, GitHubWriteError  # noqa: E402
from aireview.github.hunks import commentable_lines  # noqa: E402
from aireview.github.post import post_review  # noqa: E402
from aireview.pipeline.dedup import JsonDedupStore, dedup_key  # noqa: E402


class _Token:
    def token(self):
        return "ghs_test"

    def describe(self):
        return "test"


class _Endpoint:
    def __str__(self):
        return "https://api.github.com"


def build_client(http):
    """A real GitHubWriteClient over a fake transport.

    Deliberately the real client, not a stub: bug 5 is a property of the
    client's exception handling, and a stub would assert nothing about it.
    `sleep` is a no-op so the retry/backoff path runs instantly.
    """
    return GitHubWriteClient(_Token(), _Endpoint(), opener=http,
                             sleep=lambda _s: None)


def _path_of(url):
    """The URL path without its query string.

    `_get_paginated` appends `?per_page=100&page=1`, so matching on the full
    URL silently routes the comments GET to the default branch - which is how
    the first version of this fake made reconciliation look broken when it was
    not.
    """
    return urllib.parse.urlsplit(url).path


class _HeadAwareHTTP(FakeHTTP):
    """FakeHTTP that also answers GET /pulls/{n} and GET .../comments."""

    def __init__(self, *, live_head, review_errors=(), existing_comments=()):
        super().__init__()
        self._review_errors = list(review_errors)
        self._live_head = live_head
        self._existing = list(existing_comments)

    def __call__(self, req, timeout=None):
        path = _path_of(req.full_url)
        method = req.get_method()
        if method == "GET" and path.endswith("/comments"):
            self.calls.append({"method": method, "url": req.full_url,
                               "payload": None})
            return _json_response(self._existing)
        if method == "GET" and "/pulls/" in path and not path.endswith("/reviews"):
            self.calls.append({"method": method, "url": req.full_url,
                               "payload": None})
            return _json_response({"head": {"sha": self._live_head}})
        if method == "POST" and path.endswith("/reviews"):
            self._errors = self._review_errors
        return super().__call__(req, timeout=timeout)


def _json_response(body):
    return _Response(body)


# --------------------------------------------------------------------------- #
class TestNewHunkWalker(HunkWalkerContract, unittest.TestCase):

    def commentable(self, prfetch, path):
        return commentable_lines(prfetch, path)


# --------------------------------------------------------------------------- #
class TestNewPoster(PostContract, unittest.TestCase):

    def attempt(self, *, findings, summary_body="S", head_sha=HEAD_SHA,
                live_head=HEAD_SHA, http_errors=(), verdict="approve",
                max_comments=50, dry_run=False):
        # `verdict` is accepted and ignored on purpose: post_review has no
        # verdict parameter at all, which is how the APPROVE path is closed
        # structurally rather than by policy.
        http = _HeadAwareHTTP(live_head=live_head, review_errors=http_errors)
        client = build_client(http)
        outcome = None
        try:
            outcome = post_review(
                client, repo="acme/widgets", pr=42, head_sha=head_sha,
                findings=findings, summary_body=summary_body,
                dry_run=dry_run, max_comments=max_comments)
        except GitHubWriteError:
            pass  # typed and catchable: the contract's requirement
        return {"outcome": outcome, "sent": http.review_payloads()}

    # -- behaviour both implementations would need, so not in the mixin ---- #
    def test_dry_run_posts_nothing_and_returns_the_plan(self):
        r = self.attempt(findings=[self.positioned_finding()], dry_run=True)
        self.assertEqual(r["sent"], [])
        outcome = r["outcome"]
        self.assertFalse(outcome["posted"])
        self.assertEqual(outcome["plan"]["commit_id"], HEAD_SHA)
        self.assertEqual(len(outcome["plan"]["comments"]), 1)
        self.assertIn("dry_run", outcome["notes"])

    def test_non_positionable_findings_go_into_the_body(self):
        f = self.positioned_finding(positionable=False, line=9999,
                                    message="floats to the summary")
        r = self.attempt(findings=[f])
        self.assertEqual(r["sent"][0]["comments"], [])
        self.assertIn("floats to the summary", r["sent"][0]["body"])
        self.assertEqual(r["outcome"]["fallback"], 1)

    def test_findings_over_the_cap_are_demoted_not_dropped(self):
        findings = [self.positioned_finding(dedup_key=f"k{i}",
                                            line=40 + (i % 6),
                                            message=f"finding-{i}")
                    for i in range(8)]
        r = self.attempt(findings=findings, max_comments=3)
        sent = r["sent"][0]
        self.assertEqual(len(sent["comments"]), 3)
        self.assertEqual(r["outcome"]["fallback"], 5)
        for i in range(8):
            blob = sent["body"] + repr(sent["comments"])
            self.assertIn(f"finding-{i}", blob,
                          "a finding past the cap was dropped entirely")

    def test_already_live_comment_is_not_reposted(self):
        """The local store is not the authority on what is on the PR."""
        live = [{"id": 77, "body": "old\n<!-- aireview:key=livekey -->"}]
        http = _HeadAwareHTTP(live_head=HEAD_SHA, existing_comments=live)
        outcome = post_review(
            build_client(http), repo="acme/widgets", pr=42, head_sha=HEAD_SHA,
            findings=[self.positioned_finding(dedup_key="livekey",
                                              message="ALREADY-ON-THE-PR"),
                      self.positioned_finding(dedup_key="other", line=43,
                                              message="genuinely new")],
            summary_body="S", dry_run=False)
        posted = http.review_payloads()[0]
        self.assertNotIn("ALREADY-ON-THE-PR", repr(posted))
        self.assertIn("genuinely new", repr(posted))
        self.assertEqual(outcome["skipped_duplicates"], 1)

    def test_a_regression_is_reposted_even_though_its_comment_is_live(self):
        """A `same_finding_resolved` finding is exempt from reconciliation.

        GitHub does not delete a comment when the code is fixed; it marks it
        outdated. So the key stays live forever, and suppressing on liveness
        alone would mean a regression is never announced.
        """
        live = [{"id": 77, "body": "old\n<!-- aireview:key=regressed -->"}]
        http = _HeadAwareHTTP(live_head=HEAD_SHA, existing_comments=live)
        post_review(
            build_client(http), repo="acme/widgets", pr=42, head_sha=HEAD_SHA,
            findings=[self.positioned_finding(
                dedup_key="regressed", message="came back",
                dedup_verdict="same_finding_resolved")],
            summary_body="S", dry_run=False)
        posted = http.review_payloads()[0]
        self.assertIn("came back", repr(posted))
        self.assertIn("regressed", repr(posted))

    def test_review_id_and_comment_map_are_returned(self):
        live = [{"id": 501, "body": "x\n<!-- aireview:key=k-positioned -->"}]
        http = _HeadAwareHTTP(live_head=HEAD_SHA)
        client = build_client(http)
        # Comments appear only after the POST, as on a real PR.
        original = http.__call__

        def after_post(req, timeout=None):
            if (req.get_method() == "GET"
                    and _path_of(req.full_url).endswith("/comments")):
                return _json_response(live if http.review_payloads() else [])
            return original(req, timeout=timeout)

        client._opener = after_post
        outcome = post_review(client, repo="acme/widgets", pr=42,
                              head_sha=HEAD_SHA,
                              findings=[self.positioned_finding()],
                              summary_body="S", dry_run=False)
        self.assertTrue(outcome["posted"])
        self.assertEqual(outcome["review_id"], 12345)
        self.assertEqual(outcome["key_to_comment_id"], {"k-positioned": 501})

    def test_a_403_is_a_typed_error_not_a_traceback(self):
        http = _HeadAwareHTTP(live_head=HEAD_SHA, review_errors=[403] * 8)
        with self.assertRaises(GitHubWriteError) as ctx:
            post_review(build_client(http), repo="acme/widgets", pr=42,
                        head_sha=HEAD_SHA,
                        findings=[self.positioned_finding()],
                        summary_body="S", dry_run=False)
        self.assertIn("exhausted", str(ctx.exception))

    def test_an_unconfirmable_head_refuses_to_post(self):
        """If we cannot read the live head we do not guess.

        A stale review is worse than a late one: it comments on lines that no
        longer exist, under the bot's name, with no way for a reader to tell.
        """
        class _Blind:
            def live_head_sha(self, repo, pr):
                raise GitHubWriteError(500, "upstream down")

            def create_review(self, repo, pr, payload):
                raise AssertionError("posted despite an unreadable head")

        outcome = post_review(_Blind(), repo="acme/widgets", pr=42,
                              head_sha=HEAD_SHA,
                              findings=[self.positioned_finding()],
                              summary_body="S", dry_run=False)
        self.assertFalse(outcome["posted"])
        self.assertTrue(outcome["head_moved"])


# --------------------------------------------------------------------------- #
class TestNewDedup(DedupContract, unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def new_store(self):
        return JsonDedupStore(os.path.join(self._tmp.name, "store.json"))

    def dkey(self, *, path, principle_id, evidence, line=1,
             rulepack_version="1.0.0"):
        # `line` and `rulepack_version` are accepted and ignored. That is the
        # fix, not an oversight: see contracts/write_api.py.
        return dedup_key(path=path, principle_id=principle_id,
                         evidence=evidence)

    def classify(self, store, findings, *, repo, pr):
        return store.classify(findings, repo=repo, pr=pr)

    def record_posted(self, store, *, repo, pr, mapping):
        store.record_posted(repo=repo, pr=pr, key_to_comment_id=mapping)

    def tombstone_absent(self, store, *, repo, pr, seen_keys):
        store.tombstone_absent(repo=repo, pr=pr, seen_keys=seen_keys)


if __name__ == "__main__":
    unittest.main(verbosity=2)
