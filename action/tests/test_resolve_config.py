#!/usr/bin/env python3
"""
Tests for base-ref config resolution.

These build real git repositories in a temp directory rather than mocking
`git`, because the thing under test *is* the ref arithmetic. A mock would
happily agree with a wrong merge-base.

The central scenario is the attack: a contributor edits `.github/ai-review.yml`
in their own pull request to weaken the review. The resolver must read the
base-branch version and say so.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import resolve_config  # noqa: E402


class Args:
    """Stand-in for the argparse namespace."""

    def __init__(self, **kw):
        defaults = dict(
            repo_dir="",
            head_sha="",
            base_sha="",
            base_ref="main",
            config_path=".github/ai-review.yml",
            out="",
            notes_out="",
            enabled="true",
            dry_run="true",
            blocking="false",
            kill_switch="false",
            rulepacks="",
            model_tier="",
            severity_floor="",
            max_changed_files="",
            reviewer_timeout_seconds="",
            max_budget_usd="",
        )
        defaults.update(kw)
        for key, value in defaults.items():
            setattr(self, key, value)


def git(repo, *args):
    return subprocess.run(
        ["git", "-C", repo, *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def write(repo, path, text):
    full = os.path.join(repo, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as fh:
        fh.write(text)


class RepoFixture:
    """A base branch with a config, and a feature branch off it."""

    def __init__(self, base_config, head_config=None, base_ref="main"):
        self.dir = tempfile.mkdtemp(prefix="aireview-cfg-")
        self.base_ref = base_ref
        git(self.dir, "init", "-q", "-b", base_ref)
        git(self.dir, "config", "user.email", "t@example.com")
        git(self.dir, "config", "user.name", "t")

        write(self.dir, "README.md", "base\n")
        if base_config is not None:
            write(self.dir, ".github/ai-review.yml", base_config)
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "base")
        self.base_sha = git(self.dir, "rev-parse", "HEAD")

        git(self.dir, "checkout", "-q", "-b", "feature")
        write(self.dir, "src.txt", "change\n")
        if head_config is not None:
            write(self.dir, ".github/ai-review.yml", head_config)
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "feature")
        self.head_sha = git(self.dir, "rev-parse", "HEAD")

    def advance_base(self, config):
        """Move the base branch forward, so its tip is no longer the merge-base."""
        git(self.dir, "checkout", "-q", self.base_ref)
        write(self.dir, ".github/ai-review.yml", config)
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "base moves on")
        git(self.dir, "checkout", "-q", "feature")

    def args(self, **kw):
        return Args(
            repo_dir=self.dir,
            head_sha=self.head_sha,
            base_sha=self.base_sha,
            base_ref=self.base_ref,
            **kw,
        )


BASE_CONFIG = "severity_floor: medium\nrulepacks:\n  - core\n"
WEAKENED_CONFIG = "severity_floor: critical\ndry_run: true\nblocking: false\n"


class BaseRefTest(unittest.TestCase):
    def test_config_comes_from_the_base_not_the_head(self):
        # THE attack: weaken the reviewer in the pull request being reviewed.
        repo = RepoFixture(BASE_CONFIG, WEAKENED_CONFIG)
        doc, notes = resolve_config.resolve(repo.args())

        self.assertEqual(doc["repo_layer_source"], "base-ref")
        self.assertEqual(doc["repo_layer"]["severity_floor"], "medium")
        self.assertNotIn("dry_run", doc["repo_layer"])
        self.assertTrue(notes["modified_in_pr"])

    def test_the_author_is_told_their_config_change_was_ignored(self):
        repo = RepoFixture(BASE_CONFIG, WEAKENED_CONFIG)
        _, notes = resolve_config.resolve(repo.args())
        joined = " ".join(notes["notes"])
        self.assertIn("modifies", joined)
        self.assertIn("ignored", joined)

    def test_unmodified_config_is_not_flagged(self):
        repo = RepoFixture(BASE_CONFIG, BASE_CONFIG)
        _, notes = resolve_config.resolve(repo.args())
        self.assertFalse(notes["modified_in_pr"])

    def test_merge_base_is_used_not_the_moving_base_tip(self):
        # Someone else merges to the base branch while this PR is open. The
        # policy applied must stay stable for this (base, head) pair.
        repo = RepoFixture(BASE_CONFIG, None)
        repo.advance_base("severity_floor: low\n")
        doc, notes = resolve_config.resolve(repo.args())
        self.assertEqual(doc["repo_layer"]["severity_floor"], "medium")
        self.assertEqual(notes["config_ref"], repo.base_sha)

    def test_a_config_added_by_the_pr_does_not_take_effect(self):
        repo = RepoFixture(None, WEAKENED_CONFIG)
        doc, notes = resolve_config.resolve(repo.args())
        self.assertIsNone(doc["repo_layer"])
        self.assertIn("only takes effect once it is merged", " ".join(notes["notes"]))

    def test_no_config_anywhere_is_normal(self):
        repo = RepoFixture(None, None)
        doc, notes = resolve_config.resolve(repo.args())
        self.assertIsNone(doc["repo_layer"])
        self.assertEqual(doc["repo_layer_source"], "base-ref")
        self.assertFalse(notes["config_present"])

    def test_unparseable_base_config_degrades_rather_than_failing(self):
        # One malformed YAML file must not take the reviewer offline.
        repo = RepoFixture("severity_floor: medium\nseverity_floor: low\n")
        doc, notes = resolve_config.resolve(repo.args())
        self.assertIsNone(doc["repo_layer"])
        self.assertIsNotNone(notes["parse_error"])
        self.assertIn("could not be parsed", " ".join(notes["notes"]))

    def test_unresolvable_base_reports_pr_head_and_never_guesses(self):
        # If we cannot establish a trusted ref, say so and let core refuse the
        # layer. Claiming "base-ref" here would defeat the entire mechanism.
        repo = RepoFixture(BASE_CONFIG, WEAKENED_CONFIG)
        args = repo.args()
        args.base_ref = ""
        args.base_sha = "0" * 40
        doc, notes = resolve_config.resolve(args)
        self.assertEqual(doc["repo_layer_source"], "pr-head")
        self.assertFalse(notes["repo_layer_applied"])
        self.assertIn("NOT applied", " ".join(notes["notes"]))

    def test_a_branch_name_with_shell_metacharacters_is_harmless(self):
        # `git check-ref-format` forbids spaces, `~`, `^`, `:`, `?`, `*`, `[`
        # and `\` -- but permits `;`, `&`, `|`, `$`, backticks, parentheses and
        # both quote characters. The space restriction is not a defence either:
        # `$IFS` substitutes for one. So the payload below is a branch name an
        # outside contributor can genuinely open a pull request from, and it
        # must never reach a shell.
        marker = os.path.join(tempfile.gettempdir(), "aireview-pwned")
        if os.path.exists(marker):  # pragma: no cover - leftover from a failure
            os.unlink(marker)
        nasty = 'evil";touch$IFS' + marker + ";#"
        self.assertEqual(
            subprocess.run(
                ["git", "check-ref-format", "--branch", nasty],
                capture_output=True,
            ).returncode,
            0,
            "the payload must be a legal branch name or this test proves nothing",
        )

        repo = RepoFixture(BASE_CONFIG, None, base_ref=nasty)
        doc, _ = resolve_config.resolve(repo.args())
        self.assertEqual(doc["repo_layer"]["severity_floor"], "medium")
        self.assertFalse(os.path.exists(marker), "branch name reached a shell")


class OrgLayerTest(unittest.TestCase):
    def test_org_layer_carries_the_safety_switches(self):
        repo = RepoFixture(BASE_CONFIG)
        doc, _ = resolve_config.resolve(
            repo.args(dry_run="false", blocking="true", kill_switch="false")
        )
        self.assertEqual(doc["org_layer"]["dry_run"], False)
        self.assertEqual(doc["org_layer"]["blocking_mode"], True)
        self.assertEqual(doc["org_layer"]["enabled"], True)

    def test_blank_inputs_are_omitted_rather_than_sent_as_empty_strings(self):
        # An omitted key lets core apply its own default; an empty string
        # would override it with nonsense.
        repo = RepoFixture(BASE_CONFIG)
        doc, _ = resolve_config.resolve(repo.args())
        self.assertNotIn("model_tier", doc["org_layer"])
        self.assertNotIn("severity_floor", doc["org_layer"])
        self.assertNotIn("max_budget_usd", doc["org_layer"])

    def test_rulepacks_input_accepts_commas_and_newlines(self):
        repo = RepoFixture(BASE_CONFIG)
        doc, _ = resolve_config.resolve(repo.args(rulepacks="core, security\nux"))
        self.assertEqual(doc["org_layer"]["rulepacks"], ["core", "security", "ux"])

    def test_an_invalid_severity_floor_is_rejected_loudly(self):
        repo = RepoFixture(BASE_CONFIG)
        with self.assertRaises(SystemExit):
            resolve_config.resolve(repo.args(severity_floor="catastrophic"))

    def test_repo_layer_is_passed_through_verbatim_not_filtered(self):
        # Key-level enforcement lives in core, which has the adversarial tests
        # for it. Two implementations of one security rule drift.
        repo = RepoFixture("dry_run: false\nblocking_mode: true\nseverity_floor: low\n")
        doc, _ = resolve_config.resolve(repo.args())
        self.assertEqual(doc["repo_layer"]["dry_run"], False)
        self.assertEqual(doc["repo_layer"]["blocking_mode"], True)


class CliTest(unittest.TestCase):
    def test_cli_writes_both_documents(self):
        repo = RepoFixture(BASE_CONFIG, WEAKENED_CONFIG)
        out = os.path.join(repo.dir, "out", "resolved-config.json")
        notes_out = os.path.join(repo.dir, "out", "config-notes.json")
        code = resolve_config.main(
            [
                "--repo-dir", repo.dir,
                "--head-sha", repo.head_sha,
                "--base-sha", repo.base_sha,
                "--base-ref", repo.base_ref,
                "--out", out,
                "--notes-out", notes_out,
            ]
        )
        self.assertEqual(code, 0)
        with open(out, encoding="utf-8") as fh:
            doc = json.load(fh)
        self.assertEqual(
            sorted(doc), ["org_layer", "repo_layer", "repo_layer_source"]
        )
        self.assertEqual(doc["repo_layer_source"], "base-ref")
        with open(notes_out, encoding="utf-8") as fh:
            self.assertIn("notes", json.load(fh))


if __name__ == "__main__":
    unittest.main()
