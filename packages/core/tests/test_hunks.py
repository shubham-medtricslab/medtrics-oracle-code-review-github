#!/usr/bin/env python3
"""
Unified hunk walker: unit tests plus a property test over generated patches.

The property test is the important half. The two v0.5.0 walks were each
plausible when read against a handful of hand-written examples; what they could
not survive was being checked against a diff whose correct answer was derived
independently. So: generate a random old file and a random edit script, render
a real unified hunk from them, and assert the walker reconstructs the exact
line numbering that the edit script already knows.

`random` is seeded, so a failure is reproducible from the printed seed.

Run: python3 -m unittest tests.test_hunks
Stdlib only.
"""
import os
import random
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.dirname(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import _fixtures as fx  # noqa: E402
from aireview.github.hunks import (  # noqa: E402
    commentable_lines, iter_added_lines, line_in_diff, walk_file_hunks,
    walk_hunk,
)


class TestWalkHunk(unittest.TestCase):

    def test_added_context_and_removed_numbering(self):
        text = ("@@ -10,3 +10,3 @@\n"
                " keep\n"
                "-gone\n"
                "+fresh\n"
                " tail")
        got = [(d["kind"], d["new_line"], d["old_line"], d["text"])
               for d in walk_hunk(text, 10, 10, path="f.ts")]
        self.assertEqual(got, [
            ("context", 10, 10, "keep"),
            # The removed line is old line 11: the context line before it
            # advanced BOTH counters. Its new_line is None - it does not
            # exist in the new file.
            ("removed", None, 11, "gone"),
            ("added", 11, None, "fresh"),
            # new 12 (context + added), old 12 (context + removed).
            ("context", 12, 12, "tail"),
        ])

    def test_removed_line_whose_source_starts_with_minusminus(self):
        """github_write.py:45 skipped '---' without advancing. On the removed
        side that silently drops the line and desyncs old-side numbering - a
        deleted SQL comment ('-- note') or a decrement is enough to trigger it.
        This is the half of bug 2 that `commentable_lines` cannot see.
        """
        text = ("@@ -5,3 +5,1 @@\n"
                "---- legacy note\n"
                "--count;\n"
                " survivor")
        got = [(d["kind"], d["old_line"], d["new_line"], d["text"])
               for d in walk_hunk(text, 5, 5, path="x.sql")]
        self.assertEqual(got, [
            ("removed", 5, None, "--- legacy note"),
            ("removed", 6, None, "-count;"),
            ("context", 7, 5, "survivor"),
        ])

    def test_added_line_whose_source_starts_with_plusplus(self):
        lines = list(walk_hunk(fx.PLUSPLUS_PATCH, 40, 40, path=fx.PLUSPLUS_PATH))
        added = {d["new_line"]: d["text"] for d in lines if d["kind"] == "added"}
        self.assertEqual(added, fx.PLUSPLUS_ADDED)

    def test_no_newline_marker_and_trailing_token_are_not_lines(self):
        lines = list(walk_hunk(fx.NONEWLINE_PATCH, 1, 1, path=fx.NONEWLINE_PATH))
        self.assertEqual([d["new_line"] for d in lines], [1, 2, 3])
        self.assertNotIn("\\ No newline at end of file",
                         [d["text"] for d in lines])

    def test_blank_context_line_that_lost_its_marker_still_counts(self):
        """Some producers strip the trailing space off a blank context line.
        Dropping it (as the trailing-token guard must not do) would shift every
        subsequent line up by one.
        """
        text = "@@ -1,3 +1,3 @@\n a\n\n+c"
        got = [(d["kind"], d["new_line"]) for d in walk_hunk(text, 1, 1)]
        self.assertEqual(got, [("context", 1), ("context", 2), ("added", 3)])

    def test_empty_and_headerless_input_are_harmless(self):
        self.assertEqual(list(walk_hunk("", 1, 1)), [])
        self.assertEqual([d["kind"] for d in walk_hunk("+only", 7, 7)], ["added"])

    def test_only_one_trailing_empty_token_is_dropped(self):
        """"\\n" is two tokens: a blank line and the newline artifact. Exactly
        one is dropped, which is what keeps a genuine blank context line at the
        end of a hunk from shifting everything after it. Degenerate input like
        this never reaches us from GitHub - a real `unified_text` starts with
        '@@' - but the asymmetry is the whole of bug 3, so it is pinned.
        """
        self.assertEqual([d["kind"] for d in walk_hunk("\n", 1, 1)], ["context"])
        self.assertEqual([d["kind"] for d in walk_hunk("\n\n", 1, 1)],
                         ["context", "context"])


class TestCommentableLines(unittest.TestCase):

    def test_pure_deletion_hunk_has_nothing_commentable(self):
        pr = fx.prfetch((fx.DELETION_PATH, fx.DELETION_PATCH))
        self.assertEqual(commentable_lines(pr, fx.DELETION_PATH), set())

    def test_multi_hunk_file(self):
        pr = fx.ordinary_pr()
        got = commentable_lines(pr, fx.ORDINARY_PATH)
        self.assertEqual(got, {10, 11, 12, 13, 14, 15, 16, 81, 82, 83})

    def test_unknown_path_is_empty_not_an_error(self):
        self.assertEqual(commentable_lines(fx.mixed_pr(), "no/such/file.ts"), set())

    def test_line_in_diff_rejects_non_integers_and_bools(self):
        pr = fx.plusplus_pr()
        self.assertTrue(line_in_diff(pr, fx.PLUSPLUS_PATH, 42))
        self.assertFalse(line_in_diff(pr, fx.PLUSPLUS_PATH, "42"))
        self.assertFalse(line_in_diff(pr, fx.PLUSPLUS_PATH, True))
        self.assertFalse(line_in_diff(pr, fx.PLUSPLUS_PATH, None))
        self.assertFalse(line_in_diff(pr, None, 42))

    def test_binary_file_with_no_patch_is_empty(self):
        pr = {"diffs": [{"file_new_path": "logo.png", "is_binary": True,
                         "hunks": []}]}
        self.assertEqual(commentable_lines(pr, "logo.png"), set())


class TestDetectorWriterAgreement(unittest.TestCase):
    """The divergence itself, asserted directly.

    v0.5.0 had two walks; the whole point of this module is that there is now
    one. These tests fail loudly if a second walk ever reappears.
    """

    def test_every_added_line_is_commentable(self):
        pr = fx.mixed_pr()
        for path, line, _text in iter_added_lines(pr):
            self.assertIn(
                line, commentable_lines(pr, path),
                f"detector reported an added line at {path}:{line} that the "
                f"writer would refuse to position a comment on",
            )

    def test_commentable_is_exactly_added_plus_context(self):
        pr = fx.mixed_pr()
        for d in pr["diffs"]:
            path = d["file_new_path"]
            expected = {dl["new_line"] for dl in walk_file_hunks(pr, path)
                        if dl["kind"] in ("added", "context")}
            self.assertEqual(commentable_lines(pr, path), expected, path)


# --------------------------------------------------------------------------- #
# Property test
# --------------------------------------------------------------------------- #
# Source lines chosen to include exactly the shapes that broke v0.5.0.
_SOURCE_POOL = [
    "const a = 1;",
    "++attempts;",            # added -> '+++attempts;'
    "--attempts;",            # removed -> '---attempts;'
    "-- a SQL comment",       # removed -> '--- a SQL comment'
    "+= 1;",
    "@@ not a header",
    "\\ not a marker",
    "",                       # blank line
    "  indented();",
    "return;",
]


def _render_hunk(old_lines, ops, old_start, new_start):
    """Render a unified hunk and return (text, expected_lines).

    `expected_lines` is derived from the edit script, NOT from any walker, so
    the property test has an independent oracle.
    """
    body, expected = [], []
    old_no, new_no = old_start, new_start
    old_count = new_count = 0
    src = iter(old_lines)
    for op in ops:
        if op == "context":
            t = next(src)
            body.append(" " + t)
            expected.append(("context", new_no, old_no, t))
            old_no += 1
            new_no += 1
            old_count += 1
            new_count += 1
        elif op == "removed":
            t = next(src)
            body.append("-" + t)
            expected.append(("removed", None, old_no, t))
            old_no += 1
            old_count += 1
        else:  # added
            t = random.choice(_SOURCE_POOL)
            body.append("+" + t)
            expected.append(("added", new_no, None, t))
            new_no += 1
            new_count += 1
    header = f"@@ -{old_start},{old_count} +{new_start},{new_count} @@"
    return "\n".join([header] + body), expected, old_count, new_count


class TestWalkHunkProperties(unittest.TestCase):

    CASES = 400

    def test_walker_matches_an_independently_derived_oracle(self):
        for seed in range(self.CASES):
            with self.subTest(seed=seed):
                random.seed(seed)
                old_start = random.randint(1, 500)
                new_start = random.randint(1, 500)
                n = random.randint(1, 12)
                ops = [random.choice(("context", "removed", "added"))
                       for _ in range(n)]
                need = sum(1 for o in ops if o in ("context", "removed"))
                old_lines = [random.choice(_SOURCE_POOL) for _ in range(need)]
                text, expected, oc, nc = _render_hunk(
                    old_lines, ops, old_start, new_start)
                # Half the time the hunk arrives with the trailing artifacts
                # that bug 3 was about.
                if seed % 2:
                    text += "\n\\ No newline at end of file\n"

                got = [(d["kind"], d["new_line"], d["old_line"], d["text"])
                       for d in walk_hunk(text, new_start, old_start)]
                self.assertEqual(got, expected, f"seed={seed}\n{text}")

    def test_commentable_never_leaves_the_declared_new_range(self):
        for seed in range(self.CASES):
            with self.subTest(seed=seed):
                random.seed(10_000 + seed)
                old_start = random.randint(1, 500)
                new_start = random.randint(1, 500)
                ops = [random.choice(("context", "removed", "added"))
                       for _ in range(random.randint(1, 12))]
                need = sum(1 for o in ops if o in ("context", "removed"))
                old_lines = [random.choice(_SOURCE_POOL) for _ in range(need)]
                text, _expected, oc, nc = _render_hunk(
                    old_lines, ops, old_start, new_start)
                if seed % 3 == 0:
                    text += "\n"
                pr = {"diffs": [{
                    "file_new_path": "f.ts", "file_old_path": "f.ts",
                    "hunks": [{
                        "line_range_old": [old_start,
                                           old_start + max(oc - 1, 0)],
                        "line_range_new": [new_start,
                                           new_start + max(nc - 1, 0)],
                        "unified_text": text,
                    }],
                }]}
                hi = new_start + max(nc - 1, 0)
                for line in commentable_lines(pr, "f.ts"):
                    self.assertTrue(
                        new_start <= line <= hi,
                        f"seed={seed} line {line} outside "
                        f"[{new_start},{hi}]\n{text}",
                    )


if __name__ == "__main__":
    unittest.main(verbosity=2)
