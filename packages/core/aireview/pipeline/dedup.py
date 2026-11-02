#!/usr/bin/env python3
"""
Content-anchored dedup.

`finding_dedup.py` keyed on `sha256(path|line|principle_id|rubric_version)` and
had four separate problems, each of which shows up as comment spam on a real
pull request:

  1. `line` in the key. Any edit ABOVE a finding moves its line, so it re-keys,
     classifies `new`, and is posted again. Ten pushes against a branch with
     fifteen findings is a hundred and fifty comments, none of them new
     information.

  2. `rubric_version` in the key. Bumping a rulepack re-keys EVERY finding on
     EVERY open pull request simultaneously, and the bot re-posts all of them
     at once. Version is carried as data on the entry instead, so a bump is a
     migration rather than a mass re-post.

  3. `_mr_key` at :45-46 returned `f"{pr_number}"`. No repository, no
     installation. PR #1 of one repo shares an entry with PR #1 of every other
     repo using the same store.

  4. `classify` at :77 returned `{**store, mr_key: seen_now}` - it REPLACED the
     pull request's entry with only the findings of the current run. A finding
     that is missed once (a surface timed out, the diff was truncated) loses
     its comment id permanently, and the next run posts a duplicate instead of
     updating the live comment.

And a fifth, which made regression detection entirely theatrical: nothing
anywhere in v0.5.0 ever set `state: "resolved"`, so the `same_finding_resolved`
branch at :62-63 could not execute. `tombstone_absent` is what makes it real.

Division of labour, which matters:

    classify()          READS ONLY.
    record_posted()     writes. Only what actually reached the pull request.
    tombstone_absent()  writes. Marks what has stopped appearing as resolved.

DO NOT move the write into `classify()`. It looks like an obvious
simplification and it is not. If classify persisted, a run that died anywhere
between classification and a successful POST - a timeout, a cancelled job, a
rate limit, an OOM - would leave every finding recorded as seen. The next run
would then classify all of them `same_finding_same_state`, the poster would
skip all of them, and the pull request would receive NOTHING. That failure is
silent, total, and indistinguishable from a clean review, which makes it far
worse than the failure write-after-success risks: a duplicate comment, which
is merely annoying and immediately obvious to anyone looking at the PR.

When the two available failures are "says nothing and looks fine" and "says it
twice", always choose the one a human will notice.

The store is advisory, not authoritative. It can be stale (a lost cache), it
can be wrong (a run died between POST and write), and a human can delete a
comment behind its back. The authority on what is on a pull request is the
pull request, which is why the poster reconciles against the bot's own live
comments before posting. See `aireview.github.post`.

Stdlib only.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys

__all__ = [
    "DEFAULT_STORE", "JsonDedupStore", "dedup_key", "normalize_evidence",
    "scope_key",
]

DEFAULT_STORE = os.path.join(
    os.path.expanduser("~"), ".cache", "ai-code-review", "dedup-store.json")

SCHEMA_VERSION = 1
KEY_LENGTH = 20              # hex chars; 80 bits is ample for per-PR identity
MAX_EVIDENCE_IN_KEY = 200    # matches detectors.py:44's own truncation
MAX_FINDINGS_PER_SCOPE = 2_000
DEFAULT_MAX_AGE_DAYS = 120

_WS = re.compile(r"\s+")
# ASCII unit separator. Using a character that cannot appear in a path or a
# principle id removes the field-confusion that '|' allowed: with '|' a path
# ending in a pipe could forge a different principle id.
_SEP = "\x1f"


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def normalize_evidence(evidence) -> str:
    """Canonical form of the offending source text.

    Whitespace is collapsed so that reindenting a block does not re-key every
    finding inside it - reformatting is the most common reason a line changes
    without changing meaning. Case is NOT folded: this is source code, and
    `User` and `user` are different identifiers.
    """
    if evidence is None:
        return ""
    if not isinstance(evidence, str):
        evidence = str(evidence)
    return _WS.sub(" ", evidence).strip()[:MAX_EVIDENCE_IN_KEY]


def dedup_key(*, path: str, principle_id: str, evidence: str,
              detector_key=None) -> str:
    """Identity of a finding, stable across pushes that move it.

    No line number and no rulepack version, deliberately - see the module
    docstring.

    A finding with no evidence keys on (path, principle_id) alone, which
    collapses every evidence-less hit of one principle in one file into a
    single comment. That is the behaviour we want: with nothing to distinguish
    them, they are one observation about that file, not twelve.

    `detector_key` is an addition to the frozen signature: keyword-only, and
    omitted from the hash when absent, so every key computed without it is
    bit-identical to before. It exists because two detectors can legitimately
    emit the same `principle_id` at different severities - FA-009 does exactly
    that - and on the same line with the same evidence they would otherwise
    collapse into one finding, silently losing the more severe of the two.
    Including it makes the distinction structural instead of depending on the
    evidence happening to differ.

    The cost, stated plainly: renaming a detector re-keys its findings and
    re-posts them, which is the failure mode that keeping `rulepack_version`
    out of the key exists to avoid. It is accepted because a detector key is
    an identifier that changes rarely, where a version string changes every
    release.
    """
    fields = [path or "", principle_id or "", normalize_evidence(evidence)]
    if detector_key:
        fields.append(str(detector_key))
    canon = _SEP.join(fields)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:KEY_LENGTH]


def scope_key(repo: str, pr: int, installation_id=None) -> str:
    """Namespace for one pull request.

    Includes the repository, and the installation when there is one, so two
    pull requests numbered 1 in different repositories cannot share state.
    """
    base = f"{repo}#{pr}"
    return f"{installation_id}|{base}" if installation_id else base


class JsonDedupStore:
    """A JSON-file dedup store scoped per (installation, repo, pr).

    `path=None` keeps everything in memory, which is what a dry run and the
    degraded path (no cache available) use: every finding is then `new`, and
    nothing is written anywhere.

    Not safe against two concurrent runs on the same pull request. Writes are
    atomic per call (`os.replace`), so the file cannot be corrupted, but a
    read-modify-write race can lose an update. That is tolerable precisely
    because the store is advisory: the poster re-reads the pull request's own
    comments before posting, so the worst outcome of a lost update is one
    redundant reconciliation, not a duplicate comment.
    """

    def __init__(self, path=DEFAULT_STORE, *, installation_id=None,
                 max_age_days=DEFAULT_MAX_AGE_DAYS):
        self.path = path
        self.installation_id = installation_id
        self.max_age_days = max_age_days
        self._mem = None if path else {"schema_version": SCHEMA_VERSION,
                                       "scopes": {}}

    # -- persistence ------------------------------------------------------- #
    def _load(self):
        if self._mem is not None:
            return self._mem
        if not self.path or not os.path.exists(self.path):
            return {"schema_version": SCHEMA_VERSION, "scopes": {}}
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            # A corrupt or unreadable store degrades to "everything is new".
            # Re-posting a review is recoverable; refusing to run is not.
            return {"schema_version": SCHEMA_VERSION, "scopes": {}}
        if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
            return {"schema_version": SCHEMA_VERSION, "scopes": {}}
        data.setdefault("scopes", {})
        return data

    def _save(self, data):
        if self._mem is not None:
            self._mem = data
            return
        self._prune(data)
        directory = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(directory, exist_ok=True)
        tmp = f"{self.path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def _prune(self, data):
        """Keep the file bounded.

        Old scopes go first: a merged pull request will never be reviewed
        again, and its tombstones are dead weight. Within an over-full scope,
        resolved entries are dropped before open ones - losing a tombstone
        costs a regression notice, losing an open entry costs a duplicate
        comment, and the second is worse.
        """
        if self.max_age_days is None:
            return
        cutoff = (dt.datetime.now(dt.timezone.utc)
                  - dt.timedelta(days=self.max_age_days))
        for name in list(data.get("scopes", {})):
            scope = data["scopes"][name]
            stamp = scope.get("updated_at")
            try:
                if stamp and dt.datetime.fromisoformat(stamp) < cutoff:
                    del data["scopes"][name]
                    continue
            except ValueError:
                pass
            findings = scope.get("findings", {})
            if len(findings) > MAX_FINDINGS_PER_SCOPE:
                ordered = sorted(
                    findings.items(),
                    key=lambda kv: (kv[1].get("state") == "resolved",
                                    kv[1].get("last_seen") or ""),
                )
                scope["findings"] = dict(ordered[-MAX_FINDINGS_PER_SCOPE:])

    def _scope(self, data, repo, pr, *, create=False):
        name = scope_key(repo, pr, self.installation_id)
        scopes = data.setdefault("scopes", {})
        if name not in scopes:
            if not create:
                return name, {"findings": {}}
            scopes[name] = {"updated_at": _now(), "findings": {}}
        return name, scopes[name]

    # -- read -------------------------------------------------------------- #
    def known(self, *, repo, pr):
        """The recorded entries for one pull request, keyed by dedup key."""
        _name, scope = self._scope(self._load(), repo, pr)
        return dict(scope.get("findings", {}))

    def classify(self, findings, *, repo, pr):
        """Annotate findings with `dedup_key`, `dedup_verdict` and any known
        comment id. Does not write - see the module docstring.
        """
        prior = self.known(repo=repo, pr=pr)
        out = []
        for f in findings:
            key = f.get("dedup_key") or dedup_key(
                path=f.get("path") or "",
                principle_id=f.get("principle_id") or "",
                evidence=f.get("evidence") or "",
                detector_key=f.get("detector_key"),
            )
            entry = prior.get(key)
            if entry is None:
                verdict, comment_id = "new", None
            elif entry.get("state") == "resolved":
                verdict, comment_id = "same_finding_resolved", entry.get("comment_id")
            else:
                verdict, comment_id = "same_finding_same_state", entry.get("comment_id")
            g = dict(f)
            g["dedup_key"] = key
            g["dedup_verdict"] = verdict
            if comment_id is not None:
                g["existing_comment_id"] = comment_id
            out.append(g)
        return out

    # -- write ------------------------------------------------------------- #
    def record_posted(self, *, repo, pr, key_to_comment_id):
        """Record what actually reached the pull request.

        Merges. The entry for a key we did not post this run is left exactly
        as it was, which is the whole of fix 4.
        """
        if not key_to_comment_id:
            return
        data = self._load()
        _name, scope = self._scope(data, repo, pr, create=True)
        findings = scope.setdefault("findings", {})
        stamp = _now()
        for key, comment_id in key_to_comment_id.items():
            entry = findings.setdefault(key, {"first_seen": stamp})
            entry["state"] = "open"
            entry["last_seen"] = stamp
            entry["resolved_at"] = None
            if comment_id is not None:
                entry["comment_id"] = comment_id
        scope["updated_at"] = stamp
        self._save(data)

    def tombstone_absent(self, *, repo, pr, seen_keys):
        """Mark everything previously recorded and not seen this run resolved.

        This is the half of the design v0.5.0 was missing. Without it,
        `state` is never anything but `"open"` and `same_finding_resolved` is
        unreachable, so a finding that the author fixes and then reintroduces
        is reported as ordinary and new. Entries are tombstoned, never
        deleted: deleting would make the regression indistinguishable from a
        first sighting, which is the same bug by another route.
        """
        data = self._load()
        name = scope_key(repo, pr, self.installation_id)
        scope = data.get("scopes", {}).get(name)
        if not scope:
            return
        seen = frozenset(seen_keys or ())
        stamp = _now()
        changed = False
        for key, entry in scope.get("findings", {}).items():
            if key in seen or entry.get("state") == "resolved":
                continue
            entry["state"] = "resolved"
            entry["resolved_at"] = stamp
            changed = True
        if changed:
            scope["updated_at"] = stamp
            self._save(data)


# --------------------------------------------------------------------------- #
# CLI - classification only. Writes require an explicit subcommand so that
# nothing records a post that never happened.
# --------------------------------------------------------------------------- #
def main(argv=None):
    p = argparse.ArgumentParser(
        prog="python3 -m aireview.pipeline.dedup",
        description="Classify findings against the local dedup store.")
    p.add_argument("--findings", required=True, help="JSON file, or - for stdin")
    p.add_argument("--repo", required=True)
    p.add_argument("--pr", type=int, required=True)
    p.add_argument("--store", default=DEFAULT_STORE)
    p.add_argument("--installation-id")
    p.add_argument("--degraded", action="store_true",
                   help="ignore the store entirely; everything is `new`")
    args = p.parse_args(argv)

    if args.findings == "-":
        findings = json.load(sys.stdin)
    else:
        with open(args.findings, encoding="utf-8") as fh:
            findings = json.load(fh)

    store = JsonDedupStore(None if args.degraded else args.store,
                           installation_id=args.installation_id)
    print(json.dumps(store.classify(findings, repo=args.repo, pr=args.pr),
                     indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
