"""
FROZEN CONTRACT v1 - write path and hunk walker.

Signatures only. `write-path-hardening` implements these in
`packages/core/aireview/github/`; nobody changes this file without the lead.

Why this exists: the original plan called the v0.5.0 write path "already written
and tested" and proposed porting it unchanged. Five bugs were then verified in it.
It is new work, and these signatures encode the fixes.

Stdlib only. No third-party imports anywhere under packages/core.
"""
from typing import Iterator, Literal, Optional, Protocol, Sequence, TypedDict

Severity = Literal["info", "low", "medium", "high", "critical"]
Verdict = Literal["comment", "request_changes", "needs_discussion"]
# NOTE: no "approve". A GitHub App approval counts toward
# required_approving_review_count, so the bot must never be able to satisfy a
# human-review requirement. See contracts/run-record.schema.json.


# --------------------------------------------------------------------------- #
# 1. The unified hunk walker - ONE implementation, shared by detectors and writer
# --------------------------------------------------------------------------- #
class DiffLine(TypedDict):
    path: str
    new_line: Optional[int]   # None for removed lines
    old_line: Optional[int]
    kind: Literal["added", "removed", "context"]
    text: str


def walk_hunk(unified_text: str, new_start: int, old_start: int,
              *, path: str = "") -> Iterator[DiffLine]:
    """Walk one hunk, yielding every line with correct new/old numbering.

    `path` is keyword-only and populates `DiffLine.path`. Added in contract v1.1;
    the positional signature is unchanged.

    THE SINGLE SOURCE OF TRUTH for diff line numbering. `detectors.py:29-35` and
    `github_write.py:44-51` each walked this text differently, so the detector
    and the writer disagreed about which line a finding was on.

    Required behaviour, each covered by a regression test:
      - A line whose SOURCE TEXT starts with '+++' or '---' is an ordinary
        added/removed line and MUST advance the counter. Only a true file header
        is skipped, and GitHub's `patch` field contains no file headers at all.
      - A trailing empty token from `.split("\\n")` is NOT a diff line.
      - A '\\ No newline at end of file' marker is NOT a diff line.
      - '@@' hunk headers are skipped and do not advance counters.
      - Removed lines advance `old_line` only; added lines advance `new_line`
        only; context lines advance both.
    """
    raise NotImplementedError


def commentable_lines(prfetch: dict, path: str) -> set[int]:
    """New-file line numbers GitHub will accept an inline comment on.

    Added + context lines only. MUST be built from `walk_hunk`. Must not contain
    any line past the end of a hunk - the old implementation emitted phantom
    lines, and GitHub rejects them.
    """
    raise NotImplementedError


# --------------------------------------------------------------------------- #
# 2. The output validator - the trust boundary
# --------------------------------------------------------------------------- #
class ValidationResult(TypedDict):
    findings: list[dict]       # conforming to run-record.schema.json #/findings
    rejected: list[dict]       # {finding, reason} - audited, never posted
    verdict: Verdict           # RECOMPUTED, never taken from the model
    check_conclusion: str
    summary_markdown: str      # SANITIZED model prose, contract v1.1


def validate_agent_output(
    raw: str,
    *,
    prfetch: dict,
    allowed_paths: frozenset[str],
    blocking_enabled: bool,
    max_body_chars: int = 65_535,
    default_rulepack_id: str = "unknown",
    checkout_root: Optional[str] = None,
) -> ValidationResult:
    """Turn untrusted agent output into a safe, posted-ready finding set.

    The agent's output is DATA, never instructions. Every rule below is a test.

      - Parse strictly; malformed JSON is a run failure, not a silent empty review.
      - `verdict` is RECOMPUTED from max non-advisory finding severity. A model
        that emits `"verdict": "approve"` must not influence the outcome.
      - `path` must be byte-equal to a member of `allowed_paths` (the PR files
        list). Reject '..', absolute paths, and symlinks.
      - `line` must be in `commentable_lines(prfetch, path)`; otherwise the
        finding is demoted to `positionable: false`, not dropped.
      - Advisory findings (enforcement missing/partial) never drive the verdict.
      - Sanitize every string that reaches a review body:
          * neutralize ``` so attacker source cannot escape the evidence fence
          * strip raw HTML
          * defang '@' followed by a word character
          * enforce per-field and total length caps
        This includes `summary_markdown`. The model's prose is as untrusted as
        the diff it was derived from, and it lands in the review body verbatim.
      - `default_rulepack_id` fills `rulepack_id` when a finding omits it, since
        run-record requires that field. A finding naming an unknown rulepack is
        rejected, not silently relabelled.
      - `checkout_root`, when given, is the directory paths are resolved against
        for the symlink check. Without it, symlink detection is skipped and only
        the lexical checks apply - so pass it whenever a checkout exists.
    """
    raise NotImplementedError


# --------------------------------------------------------------------------- #
# 3. Dedup - content-anchored, not position-anchored
# --------------------------------------------------------------------------- #
def dedup_key(*, path: str, principle_id: str, evidence: str) -> str:
    """Stable across pushes that move the finding.

    MUST NOT include a line number: a line-anchored key reclassifies every
    finding as `new` after any edit above it, re-posting the whole review on
    every push. MUST NOT include rulepack_version: that would re-key every
    finding on every open PR when a pack is bumped. Version is carried as a
    separate field, so a bump is a migration rather than a mass re-post.
    """
    raise NotImplementedError


class DedupStore(Protocol):
    """Scoped per (repo, pr). Keeps tombstones so `resolved` detection is real -
    nothing in v0.5.0 ever set state='resolved', making that branch dead code."""

    def classify(self, findings: Sequence[dict], *, repo: str, pr: int) -> list[dict]: ...
    def record_posted(self, *, repo: str, pr: int, key_to_comment_id: dict[str, int]) -> None: ...
    def tombstone_absent(self, *, repo: str, pr: int, seen_keys: frozenset[str]) -> None: ...


# --------------------------------------------------------------------------- #
# 4. Posting
# --------------------------------------------------------------------------- #
class PostOutcome(TypedDict):
    posted: bool
    review_id: Optional[int]
    positioned: int
    fallback: int
    degraded: bool          # True when a 422 forced summary-only
    skipped_duplicates: int


def post_review(
    client,
    *,
    repo: str,
    pr: int,
    head_sha: str,
    findings: Sequence[dict],
    summary_body: str,
    dry_run: bool,
    max_comments: int = 50,
) -> PostOutcome:
    """Post exactly one COMMENT review.

      - `commit_id=head_sha` is ALWAYS sent. v0.5.0 computed it and dropped it
        (`github_write.py:116` vs `:141`/`:93`), so GitHub silently defaulted to
        the latest commit and reviews anchored to the wrong SHA.
      - Re-read the live PR head first; if it moved, do not post - return
        `posted: False` and let the caller requeue.
      - `POST /pulls/{n}/reviews` is ATOMIC: one bad position 422s the entire
        review. On 422, retry ONCE with every inline comment demoted into the
        summary body, and set `degraded: True`. Never lose the review.
      - Catch `urllib.error.HTTPError`. v0.5.0 only caught `GitHubError`, so a
        422/403 escaped as an unhandled traceback.
      - Enforce `max_comments`; the remainder goes to the summary body.
      - Skip findings whose dedup verdict is `same_finding_same_state`. v0.5.0
        left this to the model's discretion rather than enforcing it in code.
      - `dry_run` returns the full plan and posts nothing.
    """
    raise NotImplementedError
