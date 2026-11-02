#!/usr/bin/env python3
"""
Read the review config from the BASE ref and hand core a layered JSON document.

Why the base ref and not the PR head: the config decides how hard the reviewer
looks. If it were read from the head, a contributor could disable the security
surface, raise the severity floor, or flip `dry_run` in the very pull request
that needs reviewing -- and the review would dutifully apply the weakened
policy. So the only version that is ever *applied* is the one already merged
into the base branch, resolved at the merge-base of base and head.

Why a merge-base rather than the tip of the base branch: the tip moves under
the PR. The merge-base is the commit this PR actually diverged from, so the
policy applied is stable for a given (base, head) pair and does not silently
change because somebody else merged something.

This script does NOT enforce which keys a repo may set. That rule lives in
`packages/core/aireview/config.py`, which has the adversarial tests for it.
Two implementations of one security rule drift, and the tested one wins. What
this script owns is strictly:

  1. which ref the repo layer came from, reported honestly as
     `repo_layer_source` ("base-ref" or "pr-head"), and
  2. turning YAML into JSON, because core is stdlib-only and cannot parse YAML.

`repo_layer_source` is load-bearing for core: a `pr-head` layer is parsed for
reporting but never applied. If the merge-base cannot be established, this
script reports "pr-head" and lets core refuse it. It never guesses "base-ref".

Exit codes:
  0  resolved (including "no config file", which is the normal case)
  2  could not write output / unusable invocation
A malformed repo config is NOT an error here: it is reported as a note with a
null repo layer, so one bad YAML file cannot take the reviewer offline.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import minyaml  # noqa: E402

SEVERITIES = ("info", "low", "medium", "high", "critical")
MODEL_TIERS = ("economy", "standard", "premium")


def _git(repo_dir: str, *args: str) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", "-C", repo_dir, *args],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _blob_at(repo_dir: str, rev: str, path: str) -> str | None:
    """Contents of `path` at `rev`, or None when absent at that rev."""
    code, out, _ = _git(repo_dir, "show", f"{rev}:{path}")
    return out if code == 0 else None


def resolve_merge_base(repo_dir: str, base_ref: str, base_sha: str, head_sha: str):
    """Best available merge-base, plus a note explaining how we got it.

    Tries, in order: merge-base(remote base branch, head), merge-base(base_sha,
    head), then base_sha alone. Only the first two are true merge-bases; the
    fallback is recorded so the summary can say what actually happened.
    """
    candidates = []
    if base_ref:
        candidates.append(f"refs/remotes/origin/{base_ref}")
        candidates.append(base_ref)
    if base_sha:
        candidates.append(base_sha)

    for cand in candidates:
        code, out, _ = _git(repo_dir, "merge-base", cand, head_sha)
        sha = out.strip()
        if code == 0 and sha:
            return sha, f"merge-base of `{cand}` and head"

    if base_sha:
        code, _, _ = _git(repo_dir, "cat-file", "-e", f"{base_sha}^{{commit}}")
        if code == 0:
            return base_sha, "base SHA from the event payload (merge-base unavailable)"
    return None, "no reachable base commit"


def _typed(value, kind):
    """Coerce an action input, returning None when it is blank/absent."""
    if value is None:
        return None
    text = str(value).strip()
    if text == "":
        return None
    if kind is bool:
        low = text.lower()
        if low in ("true", "1", "yes", "on"):
            return True
        if low in ("false", "0", "no", "off"):
            return False
        raise SystemExit(f"not a boolean: {value!r}")
    if kind is int:
        return int(text)
    if kind is float:
        return float(text)
    return text


def _list_input(value):
    """Split a comma- and/or newline-delimited action input."""
    if not value:
        return None
    items = []
    for chunk in str(value).replace(",", "\n").split("\n"):
        item = chunk.strip()
        if item and item not in items:
            items.append(item)
    return items or None


def build_org_layer(args) -> dict:
    """Org/workflow-controlled policy. Core treats these keys as org-only."""
    layer: dict = {
        "enabled": _typed(args.enabled, bool),
        "dry_run": _typed(args.dry_run, bool),
        "blocking_mode": _typed(args.blocking, bool),
        "kill_switch": _typed(args.kill_switch, bool),
    }
    optional = {
        "rulepacks": _list_input(args.rulepacks),
        "model_tier": _typed(args.model_tier, str),
        "severity_floor": _typed(args.severity_floor, str),
        "max_changed_files": _typed(args.max_changed_files, int),
        "reviewer_timeout_seconds": _typed(args.reviewer_timeout_seconds, int),
        "max_budget_usd": _typed(args.max_budget_usd, float),
    }
    for key, value in optional.items():
        if value is not None:
            layer[key] = value

    floor = layer.get("severity_floor")
    if floor is not None and floor not in SEVERITIES:
        raise SystemExit(f"severity_floor must be one of {SEVERITIES}, got {floor!r}")
    tier = layer.get("model_tier")
    if tier is not None and tier not in MODEL_TIERS:
        raise SystemExit(f"model_tier must be one of {MODEL_TIERS}, got {tier!r}")
    return {k: v for k, v in layer.items() if v is not None}


def resolve(args) -> tuple[dict, dict]:
    """-> (document for core, notes for the check-run summary)."""
    notes: list[str] = []
    org_layer = build_org_layer(args)

    base_point, how = resolve_merge_base(
        args.repo_dir, args.base_ref, args.base_sha, args.head_sha
    )

    repo_layer = None
    source = "pr-head"
    parse_error = None
    present = False
    modified_in_pr = False

    if base_point is None:
        # Cannot establish a trusted ref. Report the head layer honestly and let
        # core refuse to apply it. Guessing "base-ref" here would be the exact
        # bug this whole script exists to prevent.
        notes.append(
            "Could not resolve a base commit for this pull request "
            f"({how}). The repo config was NOT applied; org policy alone is in effect."
        )
        head_text = _blob_at(args.repo_dir, args.head_sha, args.config_path)
        if head_text is not None:
            present = True
            try:
                repo_layer = minyaml.parse(head_text) or {}
            except minyaml.YamlError as exc:
                parse_error = str(exc)
        return (
            {
                "org_layer": org_layer,
                "repo_layer": repo_layer if isinstance(repo_layer, dict) else None,
                "repo_layer_source": "pr-head",
            },
            {
                "notes": notes,
                "config_path": args.config_path,
                "config_present": present,
                "config_ref": None,
                "config_ref_how": how,
                "modified_in_pr": None,
                "parse_error": parse_error,
                "repo_layer_applied": False,
            },
        )

    source = "base-ref"
    base_text = _blob_at(args.repo_dir, base_point, args.config_path)
    head_text = _blob_at(args.repo_dir, args.head_sha, args.config_path)

    if base_text is None and head_text is None:
        notes.append(
            f"No `{args.config_path}` on the base branch; running with org defaults."
        )
    elif base_text is None and head_text is not None:
        present = True
        modified_in_pr = True
        notes.append(
            f"This pull request adds `{args.config_path}`. A review config only "
            "takes effect once it is merged to the base branch, so this run used "
            "org defaults."
        )
    else:
        present = True
        modified_in_pr = head_text is not None and head_text != base_text
        try:
            parsed = minyaml.parse(base_text)
            if parsed is None:
                parsed = {}
            if not isinstance(parsed, dict):
                raise minyaml.YamlError("top level of the config must be a mapping")
            repo_layer = parsed
        except minyaml.YamlError as exc:
            parse_error = str(exc)
            notes.append(
                f"`{args.config_path}` at `{base_point[:7]}` could not be parsed "
                f"({exc}). Org policy alone is in effect for this run."
            )
        if modified_in_pr:
            notes.append(
                f"This pull request modifies `{args.config_path}`. Review policy was "
                f"read from the base branch at `{base_point[:7]}` ({how}); the "
                "pull request's version was ignored."
            )

    return (
        {
            "org_layer": org_layer,
            "repo_layer": repo_layer,
            "repo_layer_source": source,
        },
        {
            "notes": notes,
            "config_path": args.config_path,
            "config_present": present,
            "config_ref": base_point,
            "config_ref_how": how,
            "modified_in_pr": modified_in_pr,
            "parse_error": parse_error,
            "repo_layer_applied": repo_layer is not None,
        },
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Resolve the review config from the base ref into layered JSON."
    )
    parser.add_argument("--repo-dir", required=True, help="PR checkout directory")
    parser.add_argument("--head-sha", required=True)
    parser.add_argument("--base-sha", default="")
    parser.add_argument("--base-ref", default="", help="base branch name, e.g. main")
    parser.add_argument("--config-path", default=".github/ai-review.yml")
    parser.add_argument("--out", required=True, help="resolved-config.json")
    parser.add_argument("--notes-out", required=True, help="config-notes.json")

    # Org-controlled inputs. Blank means "unset"; core supplies its own default.
    parser.add_argument("--enabled", default="true")
    parser.add_argument("--dry-run", default="true")
    parser.add_argument("--blocking", default="false")
    parser.add_argument("--kill-switch", default="false")
    parser.add_argument("--rulepacks", default="")
    parser.add_argument("--model-tier", default="")
    parser.add_argument("--severity-floor", default="")
    parser.add_argument("--max-changed-files", default="")
    parser.add_argument("--reviewer-timeout-seconds", default="")
    parser.add_argument("--max-budget-usd", default="")

    args = parser.parse_args(argv)

    document, notes = resolve(args)

    try:
        for path, payload in ((args.out, document), (args.notes_out, notes)):
            parent = os.path.dirname(os.path.abspath(path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2, sort_keys=True)
                fh.write("\n")
    except OSError as exc:
        print(f"resolve_config: cannot write output: {exc}", file=sys.stderr)
        return 2

    print(
        "resolve_config: repo_layer_source="
        f"{document['repo_layer_source']} applied={notes['repo_layer_applied']} "
        f"ref={notes['config_ref'] or '-'}"
    )
    for note in notes["notes"]:
        print(f"  note: {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
