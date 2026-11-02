#!/usr/bin/env python3
"""
Turn a run record into check-run output, and decide the check conclusion.

The check-run conclusion is the merge gate. Not the review state -- reviews are
posted as COMMENT only, deliberately, because a GitHub App's approval counts
toward `required_approving_review_count` and the bot must never be able to
satisfy a human-review requirement. So this module is where "does this block a
merge?" is actually decided, and the mapping is written out as an explicit
table rather than left to fall out of control flow.

Three rules the table encodes, in order of how much damage getting them wrong
would do:

1. **Infrastructure failure never blocks.** An agent crash, an API outage, a
   timeout or a cancelled run concludes `neutral`, even in blocking mode. A
   check stuck or failing during an outage makes every open pull request
   unmergeable; a missing review does not. Fail open.

2. **Failing open never means `success`.** `neutral` says "no answer"; `success`
   says "reviewed and clean". Emitting a green check nobody earned is the same
   class of mistake as letting the bot approve, so no error path can reach
   `success`.

3. **Non-blocking is the default, and it is absolute.** With blocking mode off
   every review outcome concludes `neutral`. Only explicit skips use `skipped`.
   `failure` and `action_required` are reachable only when a repo has opted in.

Of the eight check-run conclusions, `failure`, `cancelled`, `timed_out` and
`action_required` block a required check; `success`, `neutral` and `skipped` do
not. This module only ever emits from the non-blocking set unless blocking mode
is on, and never emits `cancelled` or `timed_out` at all -- a superseded run
(the normal result of push debouncing, which we cause on purpose with
`cancel-in-progress`) must not wedge the branch.

GitHub's documented limits are enforced here rather than discovered via a 422:
`output.summary` and `output.text` cap at 65,535 characters each, annotations
at 50 per request, annotation `message` at 64 KB and titles at 255 characters.
Truncation is explicit and marked, because a silently clipped review reads like
a complete one.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

MAX_OUTPUT_CHARS = 65_535
MAX_TITLE_CHARS = 255
MAX_ANNOTATIONS_PER_REQUEST = 50
MAX_ANNOTATION_MESSAGE_CHARS = 64_000
TRUNCATION_MARKER = "\n\n---\n_Truncated: this output hit GitHub's 65,535-character limit._"

# Conclusions that block a merge when the check is required.
BLOCKING_CONCLUSIONS = frozenset({"failure", "cancelled", "timed_out", "action_required"})
NON_BLOCKING_CONCLUSIONS = frozenset({"success", "neutral", "skipped"})
VALID_CONCLUSIONS = BLOCKING_CONCLUSIONS | NON_BLOCKING_CONCLUSIONS

# Outcomes the action can report. Everything that is not a completed review is
# named, so no code path falls through to a default.
OUTCOMES = (
    "ok",              # core ran to completion; use the run record
    "policy_refusal",  # core exit 1: disabled, kill switch, over caps
    "agent_failed",    # core exit 2, or a run record we could not read
    "timed_out",       # the reviewer exceeded its wall clock
    "cancelled",       # superseded by a newer push, or the job was cancelled
    "skipped_draft",
    "skipped_fork",
    "skipped_disabled",
    "infra_error",     # checkout, config, token minting, anything else
)

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_ANNOTATION_LEVEL = {
    "critical": "failure",
    "high": "failure",
    "medium": "warning",
    "low": "notice",
    "info": "notice",
}

_SKIP_REASON = {
    "skipped_draft": "This pull request is a draft. Mark it ready for review to run the reviewer.",
    "skipped_fork": (
        "This pull request comes from a fork. Fork pull requests run with a read-only "
        "token and no secrets by design, so the reviewer is skipped. See the action's "
        "README for why `pull_request_target` is not used."
    ),
    "skipped_disabled": "AI review is disabled for this repository.",
}

_FAIL_OPEN_REASON = {
    "agent_failed": "The reviewer did not complete, so there is no result to report.",
    "timed_out": "The reviewer exceeded its time budget, so there is no result to report.",
    "cancelled": (
        "This run was superseded by a newer commit, or was cancelled. The newer run "
        "carries the review."
    ),
    "infra_error": "The review job failed before the reviewer ran.",
    "policy_refusal": "The reviewer declined to run under current policy.",
}


# --------------------------------------------------------------------------- #
# Conclusion mapping -- the merge gate
# --------------------------------------------------------------------------- #
def map_conclusion(outcome: str, *, blocking: bool, record: dict | None) -> str:
    """The explicit table. Every branch is named; there is no implicit default."""
    if outcome not in OUTCOMES:
        # An unknown outcome is itself a bug, and a bug must not block merges.
        return "neutral"

    if outcome in ("skipped_draft", "skipped_fork", "skipped_disabled"):
        return "skipped"

    # Rule 1 and 2: every non-review outcome fails open to `neutral`, never to
    # `success`, regardless of blocking mode.
    if outcome in ("agent_failed", "timed_out", "cancelled", "infra_error", "policy_refusal"):
        return "neutral"

    # outcome == "ok" from here down.
    if not blocking:
        # Rule 3. Non-blocking means non-blocking for every review outcome,
        # including a clean one: we do not hand out a green check in a mode
        # whose entire point is that the bot's opinion is advisory.
        return "neutral"

    if not isinstance(record, dict):
        return "neutral"

    proposed = record.get("check_conclusion")
    if proposed not in VALID_CONCLUSIONS:
        return "neutral"
    if proposed in ("cancelled", "timed_out"):
        # Not in the run-record schema's enum, but clamp defensively: these
        # block, and nothing about a completed review should produce them.
        return "neutral"

    # An incomplete run must never read as clean. The run-record schema says so
    # for the verdict; the same must hold for the gate.
    if record.get("status") != "complete" and proposed == "success":
        return "neutral"

    return proposed


# --------------------------------------------------------------------------- #
# Truncation
# --------------------------------------------------------------------------- #
def truncate(text: str, limit: int = MAX_OUTPUT_CHARS, marker: str = TRUNCATION_MARKER) -> str:
    """Clip to `limit` characters, leaving room for a visible marker.

    Prefers to cut at a line boundary so the output does not end mid-sentence.
    """
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    budget = limit - len(marker)
    if budget <= 0:
        return text[:limit]
    head = text[:budget]
    newline = head.rfind("\n")
    if newline > budget * 0.6:
        head = head[:newline]
    return head + marker


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #
def _counts(findings) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for finding in findings:
        sev = finding.get("severity")
        if sev in counts:
            counts[sev] += 1
    return counts


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def build_title(outcome: str, record: dict | None) -> str:
    if outcome in _SKIP_REASON:
        return {
            "skipped_draft": "Skipped - draft pull request",
            "skipped_fork": "Skipped - fork pull request",
            "skipped_disabled": "Skipped - review disabled",
        }[outcome]
    if outcome == "timed_out":
        return "Review unavailable - timed out"
    if outcome == "cancelled":
        return "Review superseded"
    if outcome == "policy_refusal":
        return "Review not run - policy"
    if outcome in ("agent_failed", "infra_error") or not isinstance(record, dict):
        return "Review unavailable"

    findings = record.get("findings") or []
    counts = _counts(findings)
    if not findings:
        title = "No findings"
    else:
        parts = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts[s]]
        title = f"{_plural(len(findings), 'finding')} ({', '.join(parts)})"
    if record.get("status") == "incomplete":
        title += " - incomplete"
    return title[:MAX_TITLE_CHARS]


def _banner_lines(record: dict | None, notes: dict | None, context: dict) -> list[str]:
    """Caveats that must be visible before anyone reads the findings."""
    lines: list[str] = []
    completeness = (record or {}).get("completeness") or {}

    if completeness.get("diff_truncated"):
        seen = completeness.get("files_seen")
        total = completeness.get("files_total")
        scope = f" ({seen} of {total} files)" if seen is not None and total else ""
        reason = completeness.get("truncation_reason")
        lines.append(
            f"**Incomplete:** the diff was truncated{scope}"
            + (f" - {reason}" if reason else "")
            + ". Unreviewed changes are not the same as reviewed-and-clean."
        )
    partial = completeness.get("partial_dimensions") or []
    if partial:
        lines.append(
            "**Incomplete:** these reviewer surfaces did not finish: "
            + ", ".join(f"`{p}`" for p in partial)
            + "."
        )
    if (record or {}).get("status") == "incomplete" and not lines:
        lines.append("**Incomplete:** this run did not cover the full change set.")

    for note in (notes or {}).get("notes") or []:
        lines.append(str(note))

    if context.get("dry_run"):
        lines.append(
            "**Dry run:** findings were computed but nothing was posted to the pull request."
        )
    if not context.get("blocking"):
        lines.append(
            "**Advisory:** blocking mode is off, so this check reports `neutral` whatever "
            "it finds and cannot prevent a merge."
        )
    for err in ((record or {}).get("errors") or [])[:5]:
        lines.append(f"**Error:** {err}")
    return lines


def _findings_section(findings) -> str:
    if not findings:
        return ""
    chunks = ["", "### Findings", ""]
    by_sev: dict[str, list] = {s: [] for s in SEVERITY_ORDER}
    for finding in findings:
        by_sev.setdefault(finding.get("severity", "info"), []).append(finding)
    for sev in SEVERITY_ORDER:
        group = by_sev.get(sev) or []
        if not group:
            continue
        chunks.append(f"**{sev.capitalize()}**")
        chunks.append("")
        for finding in group:
            where = finding.get("path") or "(no file)"
            if finding.get("line"):
                where += f":{finding['line']}"
            advisory = " _(advisory)_" if finding.get("advisory") else ""
            principle = finding.get("principle_id") or "?"
            headline = finding.get("headline") or finding.get("message") or ""
            headline = " ".join(str(headline).split())
            if len(headline) > 400:
                headline = headline[:397] + "..."
            chunks.append(f"- `{principle}` `{where}`{advisory} - {headline}")
        chunks.append("")
    return "\n".join(chunks)


def build_summary(outcome: str, record: dict | None, notes: dict | None, context: dict) -> str:
    lines: list[str] = []

    if outcome in _SKIP_REASON:
        lines.append(_SKIP_REASON[outcome])
        lines.append("")
        lines.append("This check is informational and does not block merging.")
        return truncate("\n".join(lines))

    if outcome != "ok" or not isinstance(record, dict):
        lines.append(_FAIL_OPEN_REASON.get(outcome, "The review did not complete."))
        lines.append("")
        lines.append(
            "The check concluded `neutral` rather than failing: an unavailable reviewer "
            "must not block a merge, and it must not claim a clean result either."
        )
        detail = context.get("failure_detail")
        if detail:
            lines.append("")
            lines.append("```")
            lines.append(str(detail)[:4000])
            lines.append("```")
        if context.get("run_url"):
            lines.append("")
            lines.append(f"[Job log]({context['run_url']})")
        return truncate("\n".join(lines))

    findings = record.get("findings") or []
    counts = _counts(findings)
    verdict = record.get("verdict", "comment")
    risk = record.get("risk") or {}
    cost = record.get("cost") or {}
    timings = record.get("timings") or {}

    # The headline goes first and stands alone. In non-blocking mode the
    # conclusion is `neutral` whatever the reviewer found, so the check's
    # colour carries no signal at all -- this line is the only thing in the
    # UI distinguishing "nothing found" from "two criticals".
    lines.append(f"## {build_title(outcome, record)}")
    lines.append("")

    header = [f"**Verdict:** `{verdict}`"]
    if risk.get("band"):
        score = risk.get("score")
        header.append(f"**Risk:** {risk['band']}" + (f" ({score})" if score is not None else ""))
    if cost.get("model"):
        header.append(f"**Model:** `{cost['model']}`")
    if cost.get("total_usd") is not None:
        header.append(f"**Cost:** ${float(cost['total_usd']):.2f}")
    if timings.get("total_seconds") is not None:
        header.append(f"**Took:** {float(timings['total_seconds']):.0f}s")
    lines.append(" · ".join(header))
    lines.append("")

    banners = _banner_lines(record, notes, context)
    if banners:
        for banner in banners:
            lines.append(f"> {banner}")
            lines.append(">")
        lines.append("")

    if findings:
        present = [s for s in SEVERITY_ORDER if counts[s]]
        lines.append("| Severity | Count |")
        lines.append("| --- | --- |")
        for sev in present:
            lines.append(f"| {sev} | {counts[sev]} |")
        lines.append(f"| **total** | **{len(findings)}** |")
    else:
        lines.append("No findings at or above the configured severity floor.")
    lines.append("")

    summary_markdown = record.get("summary_markdown")
    if summary_markdown:
        lines.append(str(summary_markdown).strip())
        lines.append("")

    lines.append(_findings_section(findings))

    if context.get("run_url"):
        lines.append("")
        lines.append(f"[Job log]({context['run_url']})")

    return truncate("\n".join(lines))


def build_text(record: dict | None, context: dict) -> str:
    """The long-form pane: provenance a reviewer needs to reproduce the run."""
    if not isinstance(record, dict):
        return ""
    lines = ["### Run details", ""]
    for label, value in (
        ("run_id", record.get("run_id")),
        ("head_sha", record.get("head_sha")),
        ("base_sha", record.get("base_sha")),
        ("status", record.get("status")),
        ("verdict", record.get("verdict")),
        ("check_conclusion (proposed by core)", record.get("check_conclusion")),
        ("check conclusion (posted)", context.get("conclusion")),
        ("blocking mode", "on" if context.get("blocking") else "off"),
        ("dry run", "yes" if context.get("dry_run") else "no"),
        ("fork", "yes" if record.get("is_fork") else "no"),
        ("config ref", (context.get("notes") or {}).get("config_ref")),
        ("config source", (context.get("notes") or {}).get("config_ref_how")),
    ):
        if value not in (None, ""):
            lines.append(f"- **{label}:** `{value}`")

    connectors = record.get("connectors") or {}
    if connectors:
        lines.append("")
        lines.append("### Connectors")
        lines.append("")
        for name in sorted(connectors):
            lines.append(f"- `{name}`: {connectors[name]}")

    per_stage = (record.get("timings") or {}).get("per_stage_seconds") or {}
    if per_stage:
        lines.append("")
        lines.append("### Stage timings")
        lines.append("")
        for name in sorted(per_stage):
            lines.append(f"- `{name}`: {float(per_stage[name]):.1f}s")

    non_positionable = [
        f for f in (record.get("findings") or []) if not f.get("positionable")
    ]
    if non_positionable:
        lines.append("")
        lines.append("### Findings without a diff position")
        lines.append("")
        lines.append(
            "These could not be anchored to a commentable line, so they appear here "
            "rather than inline."
        )
        lines.append("")
        for finding in non_positionable:
            where = finding.get("path") or "(no file)"
            lines.append(
                f"- `{finding.get('principle_id', '?')}` `{where}` - "
                + " ".join(str(finding.get("message") or "").split())[:1000]
            )

    return truncate("\n".join(lines))


def build_annotations(record: dict | None, limit: int = MAX_ANNOTATIONS_PER_REQUEST * 4) -> list:
    """Inline annotations, most severe first, capped.

    Annotations are a convenience layer on top of the review comments core
    posts; they are capped and ordered so that if only 50 survive, they are the
    50 that matter.
    """
    if not isinstance(record, dict):
        return []
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    candidates = [
        f
        for f in (record.get("findings") or [])
        if f.get("positionable") and f.get("path") and f.get("line")
    ]
    candidates.sort(key=lambda f: (rank.get(f.get("severity"), 99), str(f.get("path"))))

    annotations = []
    for finding in candidates[:limit]:
        line = int(finding["line"])
        message = str(finding.get("message") or "")
        if finding.get("evidence"):
            message += "\n\nEvidence:\n" + str(finding["evidence"])
        annotations.append(
            {
                "path": str(finding["path"]),
                "start_line": line,
                "end_line": line,
                "annotation_level": _ANNOTATION_LEVEL.get(finding.get("severity"), "notice"),
                "message": message[:MAX_ANNOTATION_MESSAGE_CHARS],
                "title": (
                    f"{finding.get('severity', 'info')}: {finding.get('principle_id', '')}"
                )[:MAX_TITLE_CHARS],
            }
        )
    return annotations


def render(outcome: str, record: dict | None, notes: dict | None, context: dict) -> dict:
    conclusion = map_conclusion(outcome, blocking=bool(context.get("blocking")), record=record)
    enriched = dict(context)
    enriched["conclusion"] = conclusion
    enriched["notes"] = notes
    return {
        "conclusion": conclusion,
        "title": build_title(outcome, record),
        "summary": build_summary(outcome, record, notes, enriched),
        "text": build_text(record, enriched) if outcome == "ok" else "",
        "annotations": build_annotations(record) if outcome == "ok" else [],
        "verdict": (record or {}).get("verdict", "") if outcome == "ok" else "",
    }


def _load_json(path: str | None):
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"render_summary: could not read {path}: {exc}", file=sys.stderr)
        return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Render check-run output from a run record.")
    parser.add_argument("--outcome", required=True, choices=list(OUTCOMES))
    parser.add_argument("--run-record", default="")
    parser.add_argument("--notes", default="")
    parser.add_argument("--blocking", default="false")
    parser.add_argument("--dry-run", default="true")
    parser.add_argument("--run-url", default="")
    parser.add_argument("--failure-detail", default="")
    parser.add_argument("--out", required=True, help="path for the rendered JSON")
    args = parser.parse_args(argv)

    record = _load_json(args.run_record) if args.run_record else None
    notes = _load_json(args.notes) if args.notes else None
    outcome = args.outcome
    if outcome == "ok" and not isinstance(record, dict):
        # The record is the contract. Without it there is nothing to report, and
        # claiming "ok" would be a lie.
        outcome = "agent_failed"

    rendered = render(
        outcome,
        record,
        notes,
        {
            "blocking": str(args.blocking).lower() in ("true", "1", "yes", "on"),
            "dry_run": str(args.dry_run).lower() in ("true", "1", "yes", "on"),
            "run_url": args.run_url,
            "failure_detail": args.failure_detail,
        },
    )

    parent = os.path.dirname(os.path.abspath(args.out))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(rendered, fh, indent=2)
        fh.write("\n")
    print(f"render_summary: outcome={outcome} conclusion={rendered['conclusion']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
