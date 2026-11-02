#!/usr/bin/env python3
"""
The output validator - the trust boundary.

The agent's output is DATA. It is never instructions, and it is never trusted
to decide anything. Concretely:

  * The VERDICT is recomputed here from the findings that survive validation.
    A model emitting `"verdict": "approve"` has no effect, and there is no
    `approve` member in the enum for it to reach anyway - a GitHub App's
    approval counts toward `required_approving_review_count`, so the bot must
    never be able to satisfy a human-review requirement.

  * The DEDUP KEY is recomputed here too, which the contract does not spell
    out but follows from the same rule: a model that chose its own key could
    collide with another finding's key and silently suppress it.

  * `positionable` is recomputed. The model's claim about whether a line is
    commentable is irrelevant; only the hunk walker knows.

  * A path must be BYTE-EQUAL to a member of the PR files list, and must
    independently survive the lexical checks (no '..', not absolute) and, when
    a checkout is available, the symlink check. The lexical checks run FIRST
    and are not redundant: they hold even if `allowed_paths` is itself
    poisoned upstream.

Rejection vs demotion, which are not the same decision:

    REJECTED    the finding is unusable or unsafe - unknown path, bad
                severity, no text. It is recorded in `rejected` for audit and
                never posted.
    DEMOTED     the finding is real but cannot be positioned. It becomes
                `positionable: false` and goes in the summary body. Dropping
                it would lose a real review comment to a line-number detail.

Stdlib only.
"""
import json
import os

from .hunks import commentable_lines
from .sanitize import (
    MAX_EVIDENCE, MAX_HEADLINE, MAX_MESSAGE, MAX_SUMMARY, sanitize_code,
    sanitize_prose,
)

try:  # pragma: no cover - import shape differs under the test harness only
    from ..pipeline.dedup import dedup_key
except ImportError:  # pragma: no cover
    from aireview.pipeline.dedup import dedup_key

__all__ = [
    "ADVISORY_ENFORCEMENTS", "AgentOutputError", "SEVERITIES",
    "SEVERITY_RANK", "VERDICT_FOR_SEVERITY", "validate_agent_output",
]


class AgentOutputError(Exception):
    """Agent output could not be parsed or was structurally wrong.

    Raised rather than swallowed. A malformed response is a FAILED run, not a
    clean review with no findings - the two are indistinguishable to a reader
    of the pull request, and only one of them is true.
    """


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITIES = frozenset(SEVERITY_RANK)
ENFORCEMENTS = frozenset({"established", "partial", "missing"})
ADVISORY_ENFORCEMENTS = frozenset({"partial", "missing"})

# Deterministic and total. Exposed so the mapping is reviewable rather than
# buried in a conditional. There is no `approve`, by design.
VERDICT_FOR_SEVERITY = {
    "critical": "request_changes",
    "high": "request_changes",
    "medium": "needs_discussion",
    "low": "comment",
    "info": "comment",
}
DEFAULT_VERDICT = "comment"

MAX_PRINCIPLE_ID = 64
MAX_FINDINGS = 500
# Rough per-finding overhead of headings, fences and the marker, used when
# budgeting the total body.
_RENDER_OVERHEAD = 160


# --------------------------------------------------------------------------- #
# path checks
# --------------------------------------------------------------------------- #
def _lexical_path_problem(path):
    """Checks that hold regardless of what `allowed_paths` contains."""
    if not isinstance(path, str) or not path:
        return "path_not_a_string"
    if "\x00" in path:
        return "path_contains_nul"
    normalized = path.replace("\\", "/")
    if normalized.startswith("/"):
        return "absolute_path"
    if len(path) > 1 and path[1] == ":":        # C:\... on Windows
        return "absolute_path"
    if normalized.startswith("~"):
        return "home_relative_path"
    if ".." in normalized.split("/"):
        return "path_traversal"
    return None


def _symlink_problem(path, checkout_root):
    """Reject a path that is, or is reached through, a symlink.

    A pull request can add `docs/notes.md -> /etc/passwd`, and a reviewer
    agent holding Read would happily quote it back into a public comment.
    Every component is checked, not just the leaf, because the link can be a
    parent directory.

    Skipped entirely when `checkout_root` is None - there is no filesystem to
    resolve against, so only the lexical checks apply. That degradation is
    explicit here so nobody later assumes symlinks were always checked.
    """
    if not checkout_root:
        return None
    try:
        root = os.path.realpath(checkout_root)
        current = root
        for part in path.split("/"):
            if not part:
                continue
            current = os.path.join(current, part)
            if os.path.islink(current):
                return "path_is_symlink"
        resolved = os.path.realpath(os.path.join(root, path))
        if resolved != root and not resolved.startswith(root + os.sep):
            return "path_escapes_checkout"
    except OSError:
        return "path_unresolvable"
    return None


def _coerce_line(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


# --------------------------------------------------------------------------- #
# budget
# --------------------------------------------------------------------------- #
def _estimated_size(findings, summary):
    total = len(summary)
    for f in findings:
        total += _RENDER_OVERHEAD
        total += len(f.get("message") or "")
        total += len(f.get("headline") or "")
        total += len(f.get("evidence") or "")
    return total


def _enforce_total_budget(findings, summary, limit):
    """Bring the whole review under GitHub's body limit, worst material first.

    Order is deliberate. Evidence goes before prose because a reader can
    re-derive evidence from the diff but cannot re-derive the explanation, and
    low-severity findings are trimmed before high-severity ones. A 422 from an
    over-length body would destroy the entire review, so something has to give
    - the only question is what.
    """
    if _estimated_size(findings, summary) <= limit:
        return summary

    order = sorted(findings, key=lambda f: SEVERITY_RANK.get(f.get("severity"), 0))
    for f in order:
        if _estimated_size(findings, summary) <= limit:
            return summary
        if f.get("evidence"):
            f["evidence"] = None

    for f in order:
        if _estimated_size(findings, summary) <= limit:
            return summary
        message = f.get("message") or ""
        if len(message) > 200:
            f["message"] = message[:200].rstrip() + " […truncated]"

    if _estimated_size(findings, summary) > limit:
        overflow = _estimated_size(findings, summary) - limit
        summary = summary[:max(0, len(summary) - overflow - 80)].rstrip()
        summary += "\n\n_Summary truncated to fit GitHub's review size limit._"
    return summary


# --------------------------------------------------------------------------- #
# the validator
# --------------------------------------------------------------------------- #
def validate_agent_output(
    raw,
    *,
    prfetch,
    allowed_paths,
    blocking_enabled,
    max_body_chars=65_535,
    default_rulepack_id="unknown",
    checkout_root=None,
    allowed_rulepack_ids=None,
):
    """Turn untrusted agent output into a safe, ready-to-post finding set.

    `allowed_rulepack_ids` is an addition to the frozen signature, with a
    default that preserves the contract's behaviour. The contract requires
    that "a finding naming an unknown rulepack is rejected", which needs a set
    of known ids to test against; when None, only the SHAPE of `rulepack_id`
    is checked and membership is not enforced.
    """
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", "replace")
    if not isinstance(raw, str):
        raise AgentOutputError(f"expected a JSON string, got {type(raw).__name__}")

    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as exc:
        # Strict. No fence-stripping, no "find the first {". A response we had
        # to guess at is a response we cannot reason about.
        raise AgentOutputError(f"agent output is not valid JSON: {exc}") from None

    if not isinstance(parsed, dict):
        raise AgentOutputError(
            f"agent output must be a JSON object, got {type(parsed).__name__}")
    raw_findings = parsed.get("findings")
    if raw_findings is None or not isinstance(raw_findings, list):
        raise AgentOutputError("agent output has no `findings` array")

    allowed_paths = frozenset(allowed_paths or ())
    accepted, rejected = [], []
    commentable_cache = {}

    for index, item in enumerate(raw_findings[:MAX_FINDINGS]):
        def reject(reason):
            rejected.append({"index": index, "reason": reason, "finding": item})

        if not isinstance(item, dict):
            reject("not_an_object")
            continue

        principle_id = item.get("principle_id")
        if not isinstance(principle_id, str) or not principle_id.strip():
            reject("missing_principle_id")
            continue
        if len(principle_id) > MAX_PRINCIPLE_ID:
            reject("principle_id_too_long")
            continue

        severity = item.get("severity")
        if severity not in SEVERITIES:
            # Not coerced. A model inventing "blocker" must not be silently
            # read as critical, and reading it as info would hide a real one.
            reject(f"invalid_severity:{severity!r}")
            continue

        enforcement = item.get("enforcement")
        if enforcement is not None and enforcement not in ENFORCEMENTS:
            reject(f"invalid_enforcement:{enforcement!r}")
            continue

        rulepack_id = item.get("rulepack_id")
        if rulepack_id is None:
            rulepack_id = default_rulepack_id
        elif not isinstance(rulepack_id, str) or not rulepack_id.strip():
            reject("invalid_rulepack_id")
            continue
        elif allowed_rulepack_ids is not None and rulepack_id not in allowed_rulepack_ids:
            reject(f"unknown_rulepack_id:{rulepack_id!r}")
            continue

        path = item.get("path")
        line = _coerce_line(item.get("line"))
        positionable = False
        if path is not None:
            problem = _lexical_path_problem(path)
            if problem is None and path not in allowed_paths:
                problem = "path_not_in_pr"
            if problem is None:
                problem = _symlink_problem(path, checkout_root)
            if problem:
                reject(problem)
                continue
            if line is not None:
                if path not in commentable_cache:
                    commentable_cache[path] = commentable_lines(prfetch, path)
                positionable = line in commentable_cache[path]
        else:
            line = None

        message = sanitize_prose(item.get("message"), max_chars=MAX_MESSAGE)
        headline = sanitize_prose(item.get("headline"), max_chars=MAX_HEADLINE)
        if not message and not headline:
            reject("no_message_or_headline")
            continue

        evidence_raw = item.get("evidence")
        evidence = sanitize_code(evidence_raw, max_chars=MAX_EVIDENCE) or None

        # Both consumed into the dedup key AND emitted. A run record that
        # cannot say which of two detectors sharing a principle id fired
        # makes that collision invisible at diagnosis time, which is the
        # same problem one step later.
        detector_key = item.get("detector_key")
        if not isinstance(detector_key, str) or not detector_key.strip():
            detector_key = None

        finding = {
            # Recomputed from the ORIGINAL evidence, not the sanitized form:
            # sanitization is presentation, and tightening it later must not
            # re-key every finding on every open pull request.
            "dedup_key": dedup_key(path=path or "", principle_id=principle_id,
                                   evidence=evidence_raw if isinstance(evidence_raw, str) else "",
                                   detector_key=detector_key),
            "principle_id": principle_id,
            "detector_key": detector_key,
            "rulepack_id": rulepack_id,
            "severity": severity,
            "surface": item.get("surface") if isinstance(item.get("surface"), str)
                       else "unknown",
            "message": message or headline,
            "positionable": positionable,
            "path": path,
            "line": line,
            "evidence": evidence,
            "headline": headline or None,
            # Recomputed. A model cannot opt a finding out of counting toward
            # the verdict by labelling itself advisory, nor into it.
            "advisory": enforcement in ADVISORY_ENFORCEMENTS,
        }
        if enforcement is not None:
            finding["enforcement"] = enforcement
        if isinstance(item.get("rulepack_version"), str):
            finding["rulepack_version"] = item["rulepack_version"]
        accepted.append(finding)

    if len(raw_findings) > MAX_FINDINGS:
        rejected.append({"index": MAX_FINDINGS,
                         "reason": f"too_many_findings:{len(raw_findings)}",
                         "finding": None})

    summary_markdown = sanitize_prose(parsed.get("summary_markdown"),
                                      max_chars=MAX_SUMMARY)
    summary_markdown = _enforce_total_budget(accepted, summary_markdown,
                                             max_body_chars)

    verdict = _recompute_verdict(accepted)
    check_conclusion = _check_conclusion(accepted, blocking_enabled, prfetch)

    return {
        "findings": accepted,
        "rejected": rejected,
        "verdict": verdict,
        "check_conclusion": check_conclusion,
        "summary_markdown": summary_markdown,
    }


def _recompute_verdict(findings):
    """Max severity over NON-ADVISORY findings. Model input is not consulted."""
    worst = -1
    for f in findings:
        if f.get("advisory"):
            continue
        worst = max(worst, SEVERITY_RANK.get(f.get("severity"), 0))
    if worst < 0:
        return DEFAULT_VERDICT
    for name, rank in SEVERITY_RANK.items():
        if rank == worst:
            return VERDICT_FOR_SEVERITY[name]
    return DEFAULT_VERDICT


def _check_conclusion(findings, blocking_enabled, prfetch):
    """The actual merge gate.

    `neutral` unless the repository opted into blocking mode; `failure` only
    when blocking is on AND a non-advisory critical exists.

    An incomplete run never reports `success`. We did not look at the whole
    change, so a green check would be a claim we cannot support - and a green
    check is exactly what a truncating pull request is fishing for.
    """
    completeness = (prfetch or {}).get("completeness") or {}
    incomplete = bool(completeness.get("diff_truncated")
                      or completeness.get("partial_dimensions"))
    if not blocking_enabled:
        return "neutral"
    criticals = [f for f in findings
                 if f.get("severity") == "critical" and not f.get("advisory")]
    if criticals:
        return "failure"
    return "neutral" if incomplete else "success"
