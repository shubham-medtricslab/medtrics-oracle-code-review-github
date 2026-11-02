#!/usr/bin/env python3
"""
Tests for the "never leave a check run in_progress" guarantee.

The network layer is stubbed, because what is being tested is the fallback
ladder, not HTTP. Each test removes one more capability and asserts the check
still reaches `completed`:

    tier 1  rich PATCH
    tier 2  PATCH with output dropped       (422 on the rich payload)
    tier 3  POST an already-completed run   (no id, or both PATCHes failed)
    tier 4  exit 2 and name what is stuck   (everything failed)
"""
import json
import os
import sys
import tempfile
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts")
sys.path.insert(0, SCRIPTS)

import check_run  # noqa: E402
import gh  # noqa: E402

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class FakeAPI:
    """Records calls and replays a scripted sequence of outcomes."""

    def __init__(self, script=None):
        self.calls = []
        self.script = list(script or [])

    def __call__(self, method, path, *, token, payload=None, **kw):
        self.calls.append({"method": method, "path": path, "payload": payload})
        if self.script:
            outcome = self.script.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        return {"id": 999}

    @property
    def completions(self):
        return [
            c for c in self.calls
            if (c["payload"] or {}).get("status") == "completed"
        ]


class Args:
    def __init__(self, **kw):
        defaults = dict(
            repo="medtrics/example",
            check_run_id="12345",
            name="AI Review",
            sha="1" * 40,
            outcome="ok",
            run_record=os.path.join(FIXTURES, "run-record.complete.json"),
            notes="",
            blocking="false",
            dry_run="true",
            run_url="https://example.invalid/run/1",
            failure_detail="",
        )
        defaults.update(kw)
        for key, value in defaults.items():
            setattr(self, key, value)


class CompletionLadderTest(unittest.TestCase):
    def setUp(self):
        self._request = gh.request
        self._outputs = os.environ.pop("GITHUB_OUTPUT", None)
        self._tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        )
        self._tmp.close()
        os.environ["GITHUB_OUTPUT"] = self._tmp.name
        os.environ["GITHUB_TOKEN"] = "fake-token"

    def tearDown(self):
        gh.request = self._request
        check_run.gh.request = self._request
        os.unlink(self._tmp.name)
        if self._outputs is None:
            os.environ.pop("GITHUB_OUTPUT", None)
        else:
            os.environ["GITHUB_OUTPUT"] = self._outputs

    def install(self, api):
        check_run.gh.request = api
        return api

    def step_outputs(self):
        with open(self._tmp.name, encoding="utf-8") as fh:
            return dict(
                line.split("=", 1) for line in fh.read().splitlines() if "=" in line
            )

    # --- tier 1 ----------------------------------------------------------
    def test_tier1_rich_patch(self):
        api = self.install(FakeAPI())
        self.assertEqual(check_run.cmd_complete(Args()), 0)
        self.assertEqual(len(api.completions), 1)
        payload = api.completions[0]["payload"]
        self.assertEqual(api.completions[0]["method"], "PATCH")
        self.assertEqual(payload["conclusion"], "neutral")
        self.assertIn("summary", payload["output"])
        self.assertIn("annotations", payload["output"])

    # --- tier 2 ----------------------------------------------------------
    def test_tier2_drops_output_when_the_rich_payload_is_rejected(self):
        # Oversized or malformed output is the likeliest cause of a 422. The
        # conclusion matters more than the prose, so shed the prose.
        api = self.install(FakeAPI([gh.GitHubError(422, "Unprocessable"), {"id": 1}]))
        self.assertEqual(check_run.cmd_complete(Args()), 0)
        self.assertEqual(len(api.calls), 2)
        self.assertNotIn("output", api.calls[1]["payload"])
        self.assertEqual(api.calls[1]["payload"]["status"], "completed")

    # --- tier 3 ----------------------------------------------------------
    def test_tier3_posts_a_completed_run_when_there_is_no_id(self):
        # Check creation failed earlier. A late check beats a missing gate.
        api = self.install(FakeAPI())
        self.assertEqual(check_run.cmd_complete(Args(check_run_id="")), 0)
        self.assertEqual(len(api.calls), 1)
        self.assertEqual(api.calls[0]["method"], "POST")
        self.assertEqual(api.calls[0]["payload"]["status"], "completed")
        self.assertEqual(api.calls[0]["payload"]["head_sha"], "1" * 40)

    def test_tier3_posts_a_completed_run_when_both_patches_fail(self):
        api = self.install(
            FakeAPI([
                gh.GitHubError(422, "Unprocessable"),
                gh.GitHubError(500, "Server Error"),
                {"id": 77},
            ])
        )
        self.assertEqual(check_run.cmd_complete(Args()), 0)
        self.assertEqual(api.calls[-1]["method"], "POST")
        self.assertEqual(api.calls[-1]["payload"]["status"], "completed")

    # --- tier 4 ----------------------------------------------------------
    def test_tier4_exits_two_when_nothing_works(self):
        api = self.install(
            FakeAPI([
                gh.GitHubError(500, "a"),
                gh.GitHubError(500, "b"),
                gh.GitHubError(500, "c"),
            ])
        )
        self.assertEqual(check_run.cmd_complete(Args()), 2)
        self.assertEqual(len(api.calls), 3)

    # --- the invariant itself --------------------------------------------
    def test_every_outcome_reaches_a_completed_state(self):
        import render_summary

        for outcome in render_summary.OUTCOMES:
            api = self.install(FakeAPI())
            code = check_run.cmd_complete(Args(outcome=outcome))
            self.assertEqual(code, 0, outcome)
            self.assertEqual(len(api.completions), 1, outcome)
            self.assertEqual(api.completions[0]["payload"]["status"], "completed")

    def test_no_request_ever_leaves_status_in_progress(self):
        import render_summary

        for outcome in render_summary.OUTCOMES:
            api = self.install(FakeAPI())
            check_run.cmd_complete(Args(outcome=outcome, blocking="true"))
            for call in api.calls:
                self.assertNotEqual(
                    (call["payload"] or {}).get("status"), "in_progress", outcome
                )

    def test_outcome_ok_without_a_record_degrades_instead_of_claiming_ok(self):
        api = self.install(FakeAPI())
        code = check_run.cmd_complete(
            Args(outcome="ok", run_record="/nonexistent.json", blocking="true")
        )
        self.assertEqual(code, 0)
        payload = api.completions[0]["payload"]
        self.assertEqual(payload["conclusion"], "neutral")
        self.assertIn("unavailable", payload["output"]["title"].lower())

    # --- limits ----------------------------------------------------------
    def test_at_most_fifty_annotations_per_request(self):
        with open(
            os.path.join(FIXTURES, "run-record.complete.json"), encoding="utf-8"
        ) as fh:
            record = json.load(fh)
        template = record["findings"][0]
        record["findings"] = [
            dict(template, dedup_key=str(i), line=i + 1) for i in range(140)
        ]
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(record, fh)
            path = fh.name
        try:
            api = self.install(FakeAPI())
            check_run.cmd_complete(Args(run_record=path))
            for call in api.calls:
                annotations = ((call["payload"] or {}).get("output") or {}).get(
                    "annotations", []
                )
                self.assertLessEqual(len(annotations), 50)
            self.assertGreater(len(api.calls), 1, "overflow batches should be sent")
        finally:
            os.unlink(path)

    def test_outputs_are_emitted_for_the_action(self):
        self.install(FakeAPI())
        check_run.cmd_complete(Args(blocking="true"))
        outputs = self.step_outputs()
        self.assertEqual(outputs["conclusion"], "failure")
        self.assertEqual(outputs["verdict"], "request_changes")


class CreateTest(unittest.TestCase):
    def setUp(self):
        self._request = gh.request
        os.environ["GITHUB_TOKEN"] = "fake-token"
        os.environ.pop("GITHUB_OUTPUT", None)

    def tearDown(self):
        check_run.gh.request = self._request

    def test_create_opens_in_progress(self):
        api = FakeAPI()
        check_run.gh.request = api

        class A:
            repo = "medtrics/example"
            sha = "a" * 40
            name = "AI Review"
            details_url = "https://example.invalid"

        self.assertEqual(check_run.cmd_create(A()), 0)
        self.assertEqual(api.calls[0]["payload"]["status"], "in_progress")

    def test_create_failing_is_not_fatal(self):
        # The finalizer can still post an already-completed run, so a failed
        # creation must not take the job down with it.
        check_run.gh.request = FakeAPI([gh.GitHubError(403, "Forbidden")])

        class A:
            repo = "medtrics/example"
            sha = "a" * 40
            name = "AI Review"
            details_url = ""

        self.assertEqual(check_run.cmd_create(A()), 1)


class ReapTest(unittest.TestCase):
    def setUp(self):
        self._request = gh.request
        os.environ["GITHUB_TOKEN"] = "fake-token"

    def tearDown(self):
        check_run.gh.request = self._request

    class A:
        repo = "medtrics/example"
        sha = "b" * 40
        name = "AI Review"
        conclusion = "neutral"
        title = "t"
        summary = "s"

    def test_reap_completes_stuck_runs(self):
        api = FakeAPI([
            {"check_runs": [
                {"id": 1, "status": "in_progress"},
                {"id": 2, "status": "completed"},
                {"id": 3, "status": "queued"},
            ]},
            {}, {},
        ])
        check_run.gh.request = api
        self.assertEqual(check_run.cmd_reap(self.A()), 0)
        patched = [c for c in api.calls if c["method"] == "PATCH"]
        self.assertEqual(len(patched), 2)
        for call in patched:
            self.assertEqual(call["payload"]["status"], "completed")
            self.assertEqual(call["payload"]["conclusion"], "neutral")

    def test_reap_is_a_no_op_when_nothing_is_stuck(self):
        check_run.gh.request = FakeAPI([
            {"check_runs": [{"id": 1, "status": "completed"}]}
        ])
        self.assertEqual(check_run.cmd_reap(self.A()), 1)


if __name__ == "__main__":
    unittest.main()
