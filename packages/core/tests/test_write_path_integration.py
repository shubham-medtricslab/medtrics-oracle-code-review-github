#!/usr/bin/env python3
"""
The write path against real rulepack data, and against the frozen schema.

Three things hand-written fixtures cannot check:

  1. That a validated finding actually conforms to
     `contracts/run-record.schema.json`, including its
     `additionalProperties: false`. A field we invent, or one we fail to
     emit, is caught here rather than by a consumer.
  2. That the two FA-009 detectors - the real reason `detector_key` exists -
     stay distinct through keying and posting.
  3. That the detectors and the writer agree about line numbers. This is the
     divergence the unified walker exists to remove, and it can only be
     tested by running both.

Run: python3 -m unittest tests.test_write_path_integration
Stdlib only.
"""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
for p in (HERE, os.path.dirname(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import _fixtures as fx  # noqa: E402
from aireview.github.hunks import commentable_lines, iter_added_lines  # noqa: E402
from aireview.github.post import post_review  # noqa: E402
from aireview.github.validate import validate_agent_output  # noqa: E402
from aireview.pipeline.dedup import JsonDedupStore, dedup_key  # noqa: E402

SCHEMA_PATH = os.path.join(REPO_ROOT, "contracts", "run-record.schema.json")


def _finding_schema():
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        schema = json.load(fh)
    return schema["properties"]["findings"]["items"]


# --------------------------------------------------------------------------- #
class TestFindingsConformToTheFrozenSchema(unittest.TestCase):
    """A hand-rolled check of the parts that bite.

    No jsonschema library - `packages/core` is stdlib-only - so this asserts
    the three properties that actually catch mistakes: no invented fields
    (`additionalProperties: false`), every required field present, and every
    enum respected.
    """

    def setUp(self):
        self.schema = _finding_schema()
        pr = fx.mixed_pr()
        raw = json.dumps({"findings": [
            {"principle_id": "TS-009", "detector_key": "ts-009-any",
             "rulepack_id": "base", "rulepack_version": "1.0.0",
             "severity": "medium", "surface": "typescript",
             "enforcement": "established", "path": fx.PLUSPLUS_PATH,
             "line": 42, "message": "m", "headline": "h", "evidence": "e"},
            {"principle_id": "GIT-001", "rulepack_id": "base",
             "severity": "low", "surface": "commits", "path": None,
             "line": None, "message": "no file"},
        ]})
        self.result = validate_agent_output(
            raw, prfetch=pr,
            allowed_paths=frozenset({fx.PLUSPLUS_PATH}),
            blocking_enabled=False)

    def test_no_finding_carries_a_field_the_schema_forbids(self):
        allowed = set(self.schema["properties"])
        self.assertFalse(self.schema.get("additionalProperties", True),
                         "schema no longer forbids extra properties; this "
                         "test is checking something that stopped mattering")
        for f in self.result["findings"]:
            self.assertEqual(set(f) - allowed, set(),
                             f"fields not in the schema: {set(f) - allowed}")

    def test_every_required_field_is_present(self):
        for f in self.result["findings"]:
            for name in self.schema["required"]:
                self.assertIn(name, f)

    def test_every_enum_is_respected(self):
        for f in self.result["findings"]:
            for name, spec in self.schema["properties"].items():
                if "enum" in spec and f.get(name) is not None:
                    self.assertIn(f[name], spec["enum"], name)

    def test_nullable_fields_are_emitted_as_null_not_omitted(self):
        """`detector_key` is typed ["string", "null"]. Emitting null when a
        reviewer raised the finding unaided is more useful than omitting the
        key, because a consumer can then tell "no detector" from "this run
        predates the field".
        """
        unaided = self.result["findings"][1]
        self.assertIn("detector_key", unaided)
        self.assertIsNone(unaided["detector_key"])
        self.assertEqual(self.result["findings"][0]["detector_key"],
                         "ts-009-any")


# --------------------------------------------------------------------------- #
class TestFA009PairStaysDistinct(unittest.TestCase):
    """The case `detector_key` exists for.

    Two detectors legitimately emit principle FA-009 at different severities.
    v0.5.0 derived the emitted id with `rid.split("b")[0]`, collapsing
    `FA-009b` into `FA-009`; downstream, a dedup key of
    (path, principle_id, evidence) then merges them whenever they land on the
    same line with the same evidence - and the more severe one is the one
    that disappears.
    """

    PATH = "src/domains/forms/hooks/useForm.ts"
    EVIDENCE = "import { x } from '@/core/thing';"

    def _pair(self):
        return [
            {"principle_id": "FA-009", "detector_key": "fa-009-banned-import",
             "rulepack_id": "base", "severity": "high", "surface": "frontend",
             "path": self.PATH, "line": 5, "message": "banned import path",
             "evidence": self.EVIDENCE},
            {"principle_id": "FA-009", "detector_key": "fa-009-deep-domain",
             "rulepack_id": "base", "severity": "low", "surface": "frontend",
             "path": self.PATH, "line": 5, "message": "deep domain import",
             "evidence": self.EVIDENCE},
        ]

    def test_identical_findings_from_two_detectors_get_two_keys(self):
        keys = {dedup_key(path=f["path"], principle_id=f["principle_id"],
                          evidence=f["evidence"],
                          detector_key=f["detector_key"])
                for f in self._pair()}
        self.assertEqual(len(keys), 2,
                         "the two FA-009 detectors collapsed into one key; "
                         "the high-severity finding would be lost")

    def test_without_detector_key_they_would_collapse(self):
        """The counterfactual, asserted so the reason for the field is not
        something a reader has to take on trust."""
        keys = {dedup_key(path=f["path"], principle_id=f["principle_id"],
                          evidence=f["evidence"])
                for f in self._pair()}
        self.assertEqual(len(keys), 1)

    def test_both_survive_validation_and_posting(self):
        patch = ("@@ -3,2 +3,3 @@\n"
                 " import a from 'a';\n"
                 f"+{self.EVIDENCE}\n"
                 " export function useForm() {")
        pr = fx.prfetch((self.PATH, patch))
        result = validate_agent_output(
            json.dumps({"findings": self._pair()}), prfetch=pr,
            allowed_paths=frozenset({self.PATH}), blocking_enabled=False)
        self.assertEqual(len(result["findings"]), 2)
        self.assertEqual(result["verdict"], "request_changes",
                         "the high-severity half of the pair was lost")

        sent = []

        class _Client:
            def live_head_sha(self, repo, pr_):
                return fx.HEAD_SHA

            def create_review(self, repo, pr_, payload):
                sent.append(payload)
                return {"id": 1}

        outcome = post_review(_Client(), repo="acme/widgets", pr=1,
                              head_sha=fx.HEAD_SHA,
                              findings=result["findings"],
                              summary_body="S", dry_run=False)
        self.assertEqual(outcome["skipped_duplicates"], 0)
        self.assertEqual(len(sent[0]["comments"]), 2)

    def test_a_genuine_intra_run_duplicate_is_collapsed(self):
        """The other half of the same concern: two findings that really are
        the same finding must not become two identical comments on one line,
        because only one of them could ever be recorded against the key.
        """
        same = self._pair()[0]
        store = JsonDedupStore(None)
        findings = store.classify([dict(same), dict(same)],
                                  repo="acme/widgets", pr=1)
        for f in findings:
            f["positionable"] = False
        outcome = post_review(object(), repo="acme/widgets", pr=1,
                              head_sha=fx.HEAD_SHA, findings=findings,
                              summary_body="S", dry_run=True)
        self.assertEqual(outcome["skipped_duplicates"], 1)
        self.assertEqual(outcome["fallback"], 1)


# --------------------------------------------------------------------------- #
class TestDetectorAndWriterAgreeOnLineNumbers(unittest.TestCase):
    """The divergence itself, across module boundaries.

    `contracts/write_api.py` calls `walk_hunk` "THE SINGLE SOURCE OF TRUTH for
    diff line numbering", shared by detectors and writer, precisely because
    two walks that disagree produce a comment on the wrong line with no error
    anywhere. This test fails if a second walk is ever reintroduced.
    """

    # A hunk containing both shapes that break a naive walk: an added line
    # whose source begins '++', and a removed line whose source begins '--'.
    PATCH = ("@@ -40,3 +40,5 @@ export async function withRetry() {\n"
             "   const a = 1;\n"
             "---legacy;\n"
             "+++attempts;\n"
             "+  const x: any = 1;\n"
             "+  console.log('debug');\n"
             "   return a;")
    PATH = "src/x.service.ts"

    def setUp(self):
        self.pr = fx.prfetch((self.PATH, self.PATCH))

    def test_the_unified_walker_numbers_this_hunk_correctly(self):
        self.assertEqual(
            [(line, text) for _p, line, text in iter_added_lines(self.pr)],
            [(41, "++attempts;"),
             (42, "  const x: any = 1;"),
             (43, "  console.log('debug');")])

    def test_every_detected_line_is_one_the_writer_will_accept(self):
        commentable = commentable_lines(self.pr, self.PATH)
        for _p, line, text in iter_added_lines(self.pr):
            self.assertIn(line, commentable, f"{line}: {text!r}")

    def test_the_rulepack_detector_walk_agrees_with_the_unified_walker(self):
        """FIXED. Was a live defect in `aireview/rulepack/detect.py`.

        That module carried the v0.5.0 detector walk verbatim, so once the
        writer's walk was corrected the two disagreed - the divergence the
        unified walker exists to remove had simply moved file. On the hunk
        above the old walk produced:

            detector walk : [(43, '  const x: any = 1;'),
                             (44, "  console.log('debug');")]
            unified walker: [(41, '++attempts;'),
                             (42, '  const x: any = 1;'),
                             (43, "  console.log('debug');")]

        `++attempts;` was never yielded, because
        `startswith("+") and not startswith("+++")` excluded it, so no
        detector could fire on a line beginning '++'. And `---legacy;`, a
        REMOVED line, failed the `not startswith("---")` guard, fell through
        to the context branch and advanced the new-file counter, shifting
        everything after it.

        The off-by-one did not raise. Both 43 and 44 are in the writer's
        commentable set, so GitHub would accept the comment and place it on
        the wrong line of code under the bot's name, silently - strictly
        worse than the v0.5.0 bug it descended from, because a correct writer
        no longer rejects the bad position. Fixing one of two disagreeing
        walks is less safe than fixing neither.

        Found and reported by the write-path workstream against another
        workstream's file, recorded here as `expectedFailure` rather than
        fixed across an ownership boundary. `detect.py` now delegates to
        `iter_added_lines` and the decorator is gone. Leave this test
        undecorated: it is what stops a second walk being reintroduced.
        """
        from aireview.rulepack.detect import added_lines
        self.assertEqual(
            [(line, text) for _p, line, text in added_lines(self.pr)],
            [(line, text) for _p, line, text in iter_added_lines(self.pr)],
            "the detector walk and the unified walker disagree: a finding "
            "will be reported on a line the writer happily accepts, so the "
            "comment lands on the wrong code with no error anywhere",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
