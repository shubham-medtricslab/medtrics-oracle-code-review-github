#!/usr/bin/env python3
"""
Posting exactly one COMMENT review.

Everything here exists because of a specific way v0.5.0 got this wrong.

**`commit_id` is always sent.** `github_write.py:116` computed it,
`create_review` at `:93` built `{"event","body","comments"}`, and `main` at
`:141` called `create_review(repo, prn, payload["event"], payload["body"],
payload["comments"])`. The field was computed and then dropped on the floor,
so GitHub defaulted to the latest commit and the review anchored to whatever
head happened to be current - which, on an active branch, is not the head the
positions were computed against. The client takes a whole payload dict now,
so there is no signature for a field to fall out of.

**The live head is re-read first.** Even with `commit_id` correct, a push
between fetch and post invalidates every position. We refuse rather than post
a review about code that no longer exists, and the caller requeues.

**A 422 degrades instead of destroying the review.** `POST /pulls/{n}/reviews`
is ATOMIC. One invalid position rejects the entire request and nothing is
posted - not the other comments, not the summary. So on 422 we retry once with
every inline comment demoted into the summary body and flag `degraded`. The
review is always delivered; only its precision degrades.

**`urllib.error.HTTPError` cannot escape.** The client converts it to
`GitHubWriteError`; this module catches the raw form too, defensively, because
`client` is duck-typed and a future caller may pass something thinner.

**Dedup is enforced here, in code.** v0.5.0 computed a dedup verdict and then
left acting on it to the model's discretion in a prompt. A policy that only
holds when the model cooperates is not a policy.

**And the local store is not believed.** Before posting we read the bot's own
existing comments off the pull request and skip anything already there. The
store says what we think we posted; the pull request says what is posted. They
diverge after a crashed run, a lost cache, or a human deleting a comment.

There is NO `APPROVE` path. The event is the constant `"COMMENT"` and is not a
parameter, because a GitHub App's approval counts toward
`required_approving_review_count`. `github_write.py:100` mapped a caller's
verdict string straight to an event, which made that one keyword away.

Stdlib only.
"""
import urllib.error

from .client import GitHubWriteError
from .render import (
    extract_dedup_key, render_demoted_section, render_finding_comment,
)
from .sanitize import truncate_body
from .validate import SEVERITY_RANK

__all__ = ["REVIEW_EVENT", "post_review"]

# The only review event this system can emit. A constant, not an argument.
REVIEW_EVENT = "COMMENT"

SKIP_VERDICTS = frozenset({"same_finding_same_state"})


def _sort_key(finding):
    """Most severe first, so the comment cap drops the least important."""
    return (-SEVERITY_RANK.get(finding.get("severity"), 0),
            finding.get("path") or "",
            finding.get("line") or 0)


def _live_posted_keys(client, repo, pr):
    """Dedup keys already present in the bot's own comments on this PR.

    Best-effort: a client without `list_review_comments`, or an API error,
    means we fall back to the local store alone. Failing to reconcile risks a
    duplicate comment; refusing to post because we could not reconcile risks
    saying nothing at all. The first is the better failure.
    """
    lister = getattr(client, "list_review_comments", None)
    if not callable(lister):
        return frozenset(), "no_reconciliation_available"
    try:
        comments = lister(repo, pr) or []
    except (GitHubWriteError, urllib.error.HTTPError, OSError) as exc:
        return frozenset(), f"reconciliation_failed:{exc}"
    keys = {extract_dedup_key(c.get("body")) for c in comments
            if isinstance(c, dict)}
    keys.discard(None)
    return frozenset(keys), None


def post_review(
    client,
    *,
    repo,
    pr,
    head_sha,
    findings,
    summary_body,
    dry_run,
    max_comments=50,
):
    """Post exactly one COMMENT review. See the module docstring for why."""
    notes = []
    skipped_duplicates = 0

    # 1. Dedup, enforced here rather than requested of the model.
    #    Two passes, because there are two ways to be a duplicate: a finding
    #    already posted on a previous run, and two findings in THIS run that
    #    share a key. The second happens when two detectors emit the same
    #    principle on the same line with the same evidence; posting both puts
    #    two identical comments on one line, and only one of them would ever
    #    be recorded against the key.
    candidates = []
    seen_this_run = set()
    for f in findings:
        if f.get("dedup_verdict") in SKIP_VERDICTS:
            skipped_duplicates += 1
            continue
        key = f.get("dedup_key")
        if key and key in seen_this_run:
            skipped_duplicates += 1
            continue
        if key:
            seen_this_run.add(key)
        candidates.append(f)

    # 2. Reconcile against what is actually on the pull request. A regression
    #    (`same_finding_resolved`) is deliberately exempt: its comment is
    #    still on the PR, marked outdated, and the whole point of detecting a
    #    regression is to say so again.
    live_keys, note = _live_posted_keys(client, repo, pr)
    if note:
        notes.append(note)
    if live_keys:
        kept = []
        for f in candidates:
            if (f.get("dedup_key") in live_keys
                    and f.get("dedup_verdict") != "same_finding_resolved"):
                skipped_duplicates += 1
                continue
            kept.append(f)
        candidates = kept

    # 3. Split by positionability, then cap.
    ordered = sorted(candidates, key=_sort_key)
    positionable = [f for f in ordered if f.get("positionable")
                    and f.get("path") and isinstance(f.get("line"), int)
                    and not isinstance(f.get("line"), bool)]
    demoted = [f for f in ordered if f not in positionable]

    if len(positionable) > max_comments:
        demoted = demoted + positionable[max_comments:]
        positionable = positionable[:max_comments]
        notes.append(f"comment_cap_applied:{max_comments}")

    comments = [{"path": f["path"], "line": f["line"], "side": "RIGHT",
                 "body": render_finding_comment(f)}
                for f in positionable]

    body = _compose_body(summary_body, demoted,
                         heading="Findings not attached to a diff line")

    plan = {
        "event": REVIEW_EVENT,
        "commit_id": head_sha,
        "comments": comments,
        "body": body,
        "positioned_keys": [f.get("dedup_key") for f in positionable],
        "demoted_keys": [f.get("dedup_key") for f in demoted],
    }
    outcome = {
        "posted": False,
        "review_id": None,
        "positioned": len(comments),
        "fallback": len(demoted),
        "degraded": False,
        "skipped_duplicates": skipped_duplicates,
        "head_moved": False,
        "key_to_comment_id": {},
        "notes": notes,
        "plan": plan,
    }

    if dry_run:
        notes.append("dry_run")
        return outcome

    # 4. The head race. Everything above was computed against `head_sha`.
    moved = _head_moved(client, repo, pr, head_sha, notes)
    if moved:
        outcome["head_moved"] = True
        return outcome

    # 5. Post, degrading rather than losing the review on a 422.
    payload = {
        "event": REVIEW_EVENT,
        "commit_id": head_sha,
        "body": truncate_body(body),
        "comments": comments,
    }
    try:
        result = _create_review(client, repo, pr, payload)
    except _Validation as exc:
        notes.append(f"422_degraded:{exc.detail}")
        degraded_body = _compose_body(
            summary_body, demoted + positionable,
            heading="Findings (inline positioning was rejected by GitHub)")
        payload = {
            "event": REVIEW_EVENT,
            "commit_id": head_sha,
            "body": truncate_body(degraded_body),
            "comments": [],
        }
        try:
            result = _create_review(client, repo, pr, payload)
        except _Validation as exc2:
            # The body itself is unacceptable. Nothing further to degrade to,
            # and silently swallowing it would report a review that does not
            # exist.
            raise GitHubWriteError(422, f"review rejected twice: {exc2.detail}",
                                   exc2.payload) from None
        outcome["degraded"] = True
        outcome["positioned"] = 0
        outcome["fallback"] = len(demoted) + len(positionable)

    outcome["posted"] = True
    outcome["review_id"] = result.get("id") if isinstance(result, dict) else None

    # 6. Record what reached the PR, by marker, so the caller can persist a
    #    key -> comment id map. Best-effort; a failure here costs a redundant
    #    reconciliation next run, nothing more.
    if not outcome["degraded"]:
        outcome["key_to_comment_id"] = _map_posted_comments(
            client, repo, pr, plan["positioned_keys"])
    return outcome


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
class _Validation(Exception):
    """Internal: a 422, normalised across both exception shapes."""

    def __init__(self, detail, payload=None):
        super().__init__(detail)
        self.detail = detail
        self.payload = payload or {}


def _create_review(client, repo, pr, payload):
    """Call the client, normalising every failure shape.

    `client` is duck-typed, so both `GitHubWriteError` and a raw
    `urllib.error.HTTPError` are handled. The second should be impossible with
    our own client and is caught anyway: an uncaught `HTTPError` here is
    exactly bug 5, and the cost of the extra clause is two lines.
    """
    try:
        return client.create_review(repo, pr, payload)
    except GitHubWriteError as exc:
        if exc.status == 422:
            raise _Validation(_describe_422(exc.payload), exc.payload) from None
        raise
    except urllib.error.HTTPError as exc:
        if exc.code == 422:
            raise _Validation(f"HTTP 422 {exc.reason}") from None
        raise GitHubWriteError(exc.code, exc.reason) from None


def _describe_422(payload):
    errors = (payload or {}).get("errors") or []
    fields = [f"{e.get('resource', '?')}.{e.get('field', '?')}"
              for e in errors if isinstance(e, dict)]
    return ", ".join(fields[:5]) or (payload or {}).get("message") or "422"


def _head_moved(client, repo, pr, head_sha, notes):
    reader = getattr(client, "live_head_sha", None)
    if not callable(reader):
        notes.append("head_recheck_unavailable")
        return False
    try:
        live = reader(repo, pr)
    except (GitHubWriteError, urllib.error.HTTPError, OSError) as exc:
        # Cannot confirm the head. Do not post: the whole point is that a
        # stale position is worse than a late review.
        notes.append(f"head_recheck_failed:{exc}")
        return True
    if live and head_sha and live != head_sha:
        notes.append(f"head_moved:{head_sha}->{live}")
        return True
    return False


def _map_posted_comments(client, repo, pr, expected_keys):
    lister = getattr(client, "list_review_comments", None)
    if not callable(lister) or not expected_keys:
        return {}
    try:
        comments = lister(repo, pr) or []
    except (GitHubWriteError, urllib.error.HTTPError, OSError):
        return {}
    wanted = set(expected_keys)
    out = {}
    for c in comments:
        if not isinstance(c, dict):
            continue
        key = extract_dedup_key(c.get("body"))
        if key in wanted and c.get("id") is not None:
            out[key] = c["id"]
    return out


def _compose_body(summary_body, demoted, *, heading):
    body = summary_body or ""
    section = render_demoted_section(demoted, heading=heading)
    if section:
        body = body + "\n" + section
    return body
