#!/usr/bin/env python3
"""
The write-path contract, bound to the FROZEN v0.5.0 reference.

Every inherited test is decorated `unittest.expectedFailure`, so a green run of
this module means "all five defects are still demonstrably present in the code
we replaced". If someone edits `legacy_reference.py` into working order, these
become unexpected successes and the suite goes red - which is correct, because
the reference would no longer be evidence of anything.

To see the defects fail with their real messages rather than as expected
failures:

    AIREVIEW_SHOW_LEGACY_FAILURES=1 python3 -m unittest \\
        tests.test_legacy_reference_bugs -v

Stdlib only.
"""
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
if os.path.dirname(HERE) not in sys.path:
    sys.path.insert(0, os.path.dirname(HERE))

import legacy_reference as legacy  # noqa: E402
from _fake_http import FakeHTTP  # noqa: E402
from _fixtures import HEAD_SHA, mixed_pr  # noqa: E402
from write_path_contract import (  # noqa: E402
    DedupContract, HunkWalkerContract, PostContract,
)

SHOW_FAILURES = os.environ.get("AIREVIEW_SHOW_LEGACY_FAILURES") == "1"


def expect_failures(cls):
    """Mark every inherited contract test on `cls` as an expected failure.

    Done here rather than with a decorator per method so the contract module
    stays implementation-agnostic: it states the requirement once, and only
    this binding knows that the v0.5.0 subject cannot meet it.
    """
    if SHOW_FAILURES:
        return cls
    for name in dir(cls):
        if not name.startswith("test_"):
            continue
        fn = getattr(cls, name)
        if callable(fn):
            setattr(cls, name, unittest.expectedFailure(fn))
    return cls


# --------------------------------------------------------------------------- #
@expect_failures
class TestLegacyHunkWalker(HunkWalkerContract, unittest.TestCase):
    """github_write.py:34-56 - bugs 2 and 3."""

    def commentable(self, prfetch, path):
        return legacy.added_and_context_lines(prfetch, path)


# --------------------------------------------------------------------------- #
@expect_failures
class TestLegacyPoster(PostContract, unittest.TestCase):
    """github_write.py:91-147 - bugs 1, 4 and 5, plus the APPROVE path, the
    absent head re-read, the absent comment cap and the unenforced dedup."""

    def attempt(self, *, findings, summary_body="S", head_sha=HEAD_SHA,
                live_head=HEAD_SHA, http_errors=(), verdict="approve",
                max_comments=50, dry_run=False):
        pr = mixed_pr()
        pr["shas"]["head"] = head_sha
        payload = legacy.build_review_payload(pr, findings, summary_body, verdict)
        http = FakeHTTP(error_codes=http_errors)
        outcome = None
        if not dry_run:
            # v0.5.0 never re-reads the live head, so `live_head` has nowhere to
            # go. That absence is the bug the contract tests for.
            with mock.patch.object(legacy.urllib.request, "urlopen", http):
                outcome = legacy.legacy_main_post(
                    legacy.LegacyWriter(), "acme/widgets", 42, payload)
        return {"outcome": outcome, "sent": http.review_payloads()}


# --------------------------------------------------------------------------- #
@expect_failures
class TestLegacyDedup(DedupContract, unittest.TestCase):
    """finding_dedup.py:23-25, :45-46, :49-77."""

    def new_store(self):
        return {}

    def dkey(self, *, path, principle_id, evidence, line=1,
             rulepack_version="1.0.0"):
        return legacy.legacy_dedup_key(
            {"path": path, "line": line, "principle_id": principle_id,
             "evidence": evidence},
            rulepack_version,
        )

    def classify(self, store, findings, *, repo, pr):
        # Faithful to main() with --save: classify both reads the store and
        # rewrites it wholesale, and `repo` is simply not part of the key.
        out, new_store = legacy.legacy_classify(findings, pr, "", store=store)
        store.clear()
        store.update(new_store)
        for f in out:
            if "existing_thread_id" in f:
                f["existing_comment_id"] = f["existing_thread_id"]
        return out

    def record_posted(self, store, *, repo, pr, mapping):
        # persist_threads (finding_dedup.py:80-90), in memory.
        cur = store.setdefault(legacy.legacy_mr_key(pr, ""), {})
        for k, tid in mapping.items():
            cur.setdefault(k, {"state": "open"})
            cur[k]["thread_id"] = tid

    def tombstone_absent(self, store, *, repo, pr, seen_keys):
        # v0.5.0 has no such concept. Nothing in the pipeline ever set
        # state='resolved', which is precisely why the same_finding_resolved
        # branch at :62-63 is dead code.
        return None


if __name__ == "__main__":
    unittest.main(verbosity=2)
