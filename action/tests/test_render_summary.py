#!/usr/bin/env python3
"""
Tests for the merge gate.

These are the highest-value tests in this workstream. Everything else here is
packaging; this module decides whether a pull request can be merged, and the
expensive mistakes are all mistakes of omission -- a path that falls through to
`success`, a conclusion that blocks when it should not.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import render_summary as rs  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


class ConclusionTableTest(unittest.TestCase):
    """The table, exhaustively. Every outcome, both modes."""

    def setUp(self):
        self.complete = fixture("run-record.complete.json")
        self.incomplete = fixture("run-record.incomplete.json")

    def test_every_outcome_is_non_blocking_when_blocking_is_off(self):
        # The defining property of the default mode. If any outcome can block
        # with blocking disabled, the default is a lie.
        for outcome in rs.OUTCOMES:
            for record in (self.complete, self.incomplete, None):
                conclusion = rs.map_conclusion(outcome, blocking=False, record=record)
                self.assertIn(
                    conclusion,
                    rs.NON_BLOCKING_CONCLUSIONS,
                    f"{outcome} concluded {conclusion} with blocking off",
                )

    def test_no_failure_path_can_conclude_success(self):
        # Failing open means "no answer", not "reviewed and clean". A green
        # check nobody earned is the same class of error as letting the bot
        # approve.
        failure_outcomes = (
            "policy_refusal",
            "agent_failed",
            "timed_out",
            "cancelled",
            "infra_error",
        )
        clean = dict(self.complete, check_conclusion="success", findings=[])
        for outcome in failure_outcomes:
            for blocking in (True, False):
                self.assertEqual(
                    rs.map_conclusion(outcome, blocking=blocking, record=clean),
                    "neutral",
                    f"{outcome} (blocking={blocking}) must be neutral",
                )

    def test_blocking_off_never_emits_success_even_on_a_clean_run(self):
        clean = dict(self.complete, check_conclusion="success", findings=[])
        self.assertEqual(rs.map_conclusion("ok", blocking=False, record=clean), "neutral")

    def test_blocking_on_passes_through_the_records_conclusion(self):
        self.assertEqual(
            rs.map_conclusion("ok", blocking=True, record=self.complete), "failure"
        )

    def test_blocking_on_still_fails_open_on_an_agent_crash(self):
        # An outage must not make every open pull request unmergeable. This is
        # the deliberate asymmetry: blocking mode blocks on findings, never on
        # infrastructure.
        self.assertEqual(
            rs.map_conclusion("agent_failed", blocking=True, record=None), "neutral"
        )

    def test_incomplete_run_cannot_conclude_success(self):
        # The fixture carries status=incomplete with check_conclusion=success,
        # which is exactly the contradiction the clamp exists for: a truncated
        # diff is unreviewed, not clean.
        self.assertEqual(self.incomplete["check_conclusion"], "success")
        self.assertEqual(
            rs.map_conclusion("ok", blocking=True, record=self.incomplete), "neutral"
        )

    def test_cancelled_never_concludes_cancelled(self):
        # cancel-in-progress fires on every push by design. Concluding
        # `cancelled` would block the branch on a busy day.
        for blocking in (True, False):
            self.assertEqual(
                rs.map_conclusion("cancelled", blocking=blocking, record=self.complete),
                "neutral",
            )

    def test_timeout_never_concludes_timed_out(self):
        for blocking in (True, False):
            self.assertEqual(
                rs.map_conclusion("timed_out", blocking=blocking, record=self.complete),
                "neutral",
            )

    def test_skips_conclude_skipped(self):
        for outcome in ("skipped_draft", "skipped_fork", "skipped_disabled"):
            self.assertEqual(
                rs.map_conclusion(outcome, blocking=True, record=None), "skipped"
            )

    def test_unknown_outcome_does_not_block(self):
        self.assertEqual(
            rs.map_conclusion("not-a-real-outcome", blocking=True, record=self.complete),
            "neutral",
        )

    def test_a_record_proposing_a_blocking_conclusion_is_clamped(self):
        # Core should never emit these, but the gate does not get to assume
        # its input is well-formed.
        for bogus in ("cancelled", "timed_out", "approve", "", None, 7):
            record = dict(self.complete, check_conclusion=bogus)
            self.assertEqual(
                rs.map_conclusion("ok", blocking=True, record=record), "neutral"
            )

    def test_action_required_survives_in_blocking_mode(self):
        record = dict(self.complete, check_conclusion="action_required")
        self.assertEqual(
            rs.map_conclusion("ok", blocking=True, record=record), "action_required"
        )

    def test_every_emitted_conclusion_is_a_valid_github_conclusion(self):
        for outcome in rs.OUTCOMES:
            for blocking in (True, False):
                for record in (self.complete, self.incomplete, None, {}):
                    self.assertIn(
                        rs.map_conclusion(outcome, blocking=blocking, record=record),
                        rs.VALID_CONCLUSIONS,
                    )


class TruncationTest(unittest.TestCase):
    def test_short_text_is_untouched(self):
        self.assertEqual(rs.truncate("hello"), "hello")

    def test_long_text_fits_under_the_github_limit(self):
        text = "x" * 200_000
        out = rs.truncate(text)
        self.assertLessEqual(len(out), rs.MAX_OUTPUT_CHARS)

    def test_truncation_is_marked_not_silent(self):
        # A silently clipped review reads like a complete one, which is the
        # whole problem with truncation.
        out = rs.truncate("y" * 200_000)
        self.assertIn("Truncated", out)

    def test_truncation_prefers_a_line_boundary(self):
        text = ("line\n" * 50_000)
        out = rs.truncate(text)
        body = out[: -len(rs.TRUNCATION_MARKER)]
        self.assertTrue(body.endswith("line"))

    def test_a_giant_summary_is_capped(self):
        record = fixture("run-record.complete.json")
        record["summary_markdown"] = "z" * 300_000
        rendered = rs.render("ok", record, None, {"blocking": False, "dry_run": True})
        self.assertLessEqual(len(rendered["summary"]), rs.MAX_OUTPUT_CHARS)
        self.assertLessEqual(len(rendered["text"]), rs.MAX_OUTPUT_CHARS)


class AnnotationTest(unittest.TestCase):
    def test_only_positionable_findings_become_annotations(self):
        record = fixture("run-record.complete.json")
        annotations = rs.build_annotations(record)
        self.assertEqual(len(annotations), 2)
        self.assertTrue(all(a["start_line"] for a in annotations))

    def test_annotations_are_ordered_most_severe_first(self):
        # If only the first 50 survive the request cap, they must be the 50
        # that matter.
        record = fixture("run-record.complete.json")
        annotations = rs.build_annotations(record)
        self.assertEqual(annotations[0]["annotation_level"], "failure")
        self.assertEqual(annotations[1]["annotation_level"], "warning")

    def test_annotation_titles_respect_the_255_char_cap(self):
        record = fixture("run-record.complete.json")
        record["findings"][0]["principle_id"] = "P" * 1000
        annotation = rs.build_annotations(record)[0]
        self.assertLessEqual(len(annotation["title"]), rs.MAX_TITLE_CHARS)

    def test_annotation_messages_respect_the_64kb_cap(self):
        record = fixture("run-record.complete.json")
        record["findings"][0]["message"] = "m" * 200_000
        annotation = rs.build_annotations(record)[0]
        self.assertLessEqual(len(annotation["message"]), rs.MAX_ANNOTATION_MESSAGE_CHARS)


class SummaryContentTest(unittest.TestCase):
    def test_incompleteness_is_stated_plainly(self):
        record = fixture("run-record.incomplete.json")
        rendered = rs.render("ok", record, None, {"blocking": False, "dry_run": True})
        self.assertIn("Incomplete", rendered["summary"])
        self.assertIn("300 of 1240", rendered["summary"])
        self.assertIn("`rls`", rendered["summary"])

    def test_partial_dimensions_are_named(self):
        record = fixture("run-record.incomplete.json")
        summary = rs.render("ok", record, None, {"blocking": False, "dry_run": False})["summary"]
        self.assertIn("did not finish", summary)

    def test_dry_run_is_disclosed(self):
        record = fixture("run-record.complete.json")
        summary = rs.render("ok", record, None, {"blocking": False, "dry_run": True})["summary"]
        self.assertIn("Dry run", summary)

    def test_advisory_mode_is_disclosed(self):
        record = fixture("run-record.complete.json")
        summary = rs.render("ok", record, None, {"blocking": False, "dry_run": False})["summary"]
        self.assertIn("Advisory", summary)

    def test_config_notes_reach_the_summary(self):
        # The "your config change was ignored" message has to be visible, or
        # the base-ref rule looks like the reviewer ignoring the author.
        record = fixture("run-record.complete.json")
        notes = {"notes": ["This pull request modifies `.github/ai-review.yml`."]}
        summary = rs.render("ok", record, notes, {"blocking": True, "dry_run": False})["summary"]
        self.assertIn("modifies `.github/ai-review.yml`", summary)

    def test_fork_skip_explains_itself(self):
        rendered = rs.render("skipped_fork", None, None, {"blocking": False, "dry_run": True})
        self.assertEqual(rendered["conclusion"], "skipped")
        self.assertIn("fork", rendered["summary"])

    def test_failure_summary_says_it_is_not_a_pass(self):
        rendered = rs.render(
            "agent_failed", None, None,
            {"blocking": True, "dry_run": False, "failure_detail": "exit 2"},
        )
        self.assertEqual(rendered["conclusion"], "neutral")
        self.assertIn("must not block a merge", rendered["summary"])
        self.assertIn("exit 2", rendered["summary"])

    def test_summary_leads_with_the_findings_headline(self):
        # In non-blocking mode every conclusion is `neutral`, so the check's
        # colour distinguishes nothing. The first line has to.
        dirty = rs.render(
            "ok", fixture("run-record.complete.json"), None,
            {"blocking": False, "dry_run": True},
        )["summary"]
        clean_record = dict(fixture("run-record.complete.json"), findings=[])
        clean = rs.render(
            "ok", clean_record, None, {"blocking": False, "dry_run": True}
        )["summary"]

        self.assertTrue(dirty.startswith("## 3 findings"), dirty[:80])
        self.assertTrue(clean.startswith("## No findings"), clean[:80])
        self.assertNotEqual(dirty.splitlines()[0], clean.splitlines()[0])

    def test_title_reports_counts(self):
        record = fixture("run-record.complete.json")
        self.assertEqual(
            rs.build_title("ok", record), "3 findings (1 critical, 1 medium, 1 low)"
        )

    def test_title_flags_incompleteness(self):
        record = fixture("run-record.incomplete.json")
        self.assertIn("incomplete", rs.build_title("ok", record))


if __name__ == "__main__":
    unittest.main()
