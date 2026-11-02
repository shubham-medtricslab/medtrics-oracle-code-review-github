"""
FROZEN v0.5.0 REFERENCE. Test subject only - never imported by production code.

Why this file exists: the five write-path bugs were verified by reading
`medtrics-oracle-code-review` v0.5.0, which is a read-only repo that will not be
vendored. Without a copy of the broken code, "this test failed before the fix"
is a claim in a report rather than something the suite can prove.

So the SAME contract assertions in `write_path_contract.py` are run twice: once
against the functions below, where every one of them is decorated
`unittest.expectedFailure`, and once against the new implementation, where they
must pass. If someone ever "fixes" the code in this file, the expected failures
become unexpected successes and the suite goes red - which is the point. Do not
repair the bugs here.

Each function is copied verbatim from the cited path, with only the import
plumbing adapted so it runs standalone.
"""
import hashlib
import json
import urllib.request


# --------------------------------------------------------------------------- #
# BUG 2 + BUG 3
# skills/github-write/scripts/github_write.py:34-56
# --------------------------------------------------------------------------- #
def added_and_context_lines(prfetch, path):
    """Return the set of NEW-file line numbers that are part of the diff for `path`
    (added or context lines) - the only lines GitHub accepts a comment on."""
    lines = set()
    for d in prfetch.get("diffs", []):
        p = d.get("file_new_path") or d.get("file_old_path")
        if p != path:
            continue
        for h in d.get("hunks", []):
            new_no = h.get("line_range_new", [0, 0])[0]
            for raw in h.get("unified_text", "").split("\n"):
                if raw.startswith("@@") or raw.startswith("+++") or raw.startswith("---"):
                    continue
                if raw.startswith("-"):
                    continue  # old-only line, no new number
                # added or context line - commentable
                lines.add(new_no)
                new_no += 1
    return lines


def line_in_diff(prfetch, path, line):
    return line in added_and_context_lines(prfetch, path)


# --------------------------------------------------------------------------- #
# The DETECTOR's divergent walk of the same text.
# skills/detectors/scripts/detectors.py:20-35
# --------------------------------------------------------------------------- #
def detector_added_lines(prfetch):
    """Yield (path, new_line_no, text) for every ADDED line in the diff."""
    for d in prfetch.get("diffs", []):
        path = d.get("file_new_path") or d.get("file_old_path")
        for h in d.get("hunks", []):
            new_no = h.get("line_range_new", [0, 0])[0]
            for raw in h.get("unified_text", "").split("\n"):
                if raw.startswith("@@"):
                    continue
                if raw.startswith("+") and not raw.startswith("+++"):
                    yield path, new_no, raw[1:]
                    new_no += 1
                elif raw.startswith("-") and not raw.startswith("---"):
                    continue  # removed line: don't advance new counter
                else:
                    new_no += 1  # context line


# --------------------------------------------------------------------------- #
# BUG 1 - commit_id computed then discarded
# skills/github-write/scripts/github_write.py:59-117 and :141
# --------------------------------------------------------------------------- #
def plan_comments(prfetch, findings):
    positioned, fallback = [], []
    for f in findings:
        if f.get("path") and f.get("line") and line_in_diff(prfetch, f["path"], f["line"]):
            positioned.append(f)
        else:
            fallback.append(f)
    return {"positioned": positioned, "fallback": fallback}


VERDICT_TO_EVENT = {"approve": "APPROVE", "request_changes": "REQUEST_CHANGES",
                    "needs_discussion": "COMMENT", None: "COMMENT"}


def build_review_payload(prfetch, findings, summary_body, verdict):
    plan = plan_comments(prfetch, findings)
    head_sha = prfetch.get("shas", {}).get("head")
    comments = [{"path": f["path"], "line": f["line"], "side": "RIGHT",
                 "body": f.get("_rendered_body") or f.get("message", "")}
                for f in plan["positioned"]]
    body = summary_body
    if plan["fallback"]:
        body += "\n\n---\n**Findings not attached to a diff line:**\n"
        for f in plan["fallback"]:
            body += f"\n- `{f.get('principle_id')}` {f.get('path')}:{f.get('line')} - {f.get('message','')}"
    return {"event": VERDICT_TO_EVENT.get(verdict, "COMMENT"), "body": body,
            "comments": comments, "commit_id": head_sha,
            "counts": {"positioned": len(comments), "fallback": len(plan["fallback"])}}


class LegacyGitHubError(Exception):
    def __init__(self, status, message):
        super().__init__(f"GitHub API {status}: {message}")
        self.status = status


class LegacyWriter:
    """github_write.py:73-97, with the GitHubClient dependency reduced to
    (api, token) so it runs standalone. `_post` and `create_review` are verbatim."""

    def __init__(self, api="https://api.github.com", token="t"):
        self.api = api
        self.token = token

    def _post(self, path, payload):
        url = self.api + path
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "medtrics-oracle-code-review/0.1")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def create_review(self, repo, pr, event, body, comments):
        """One pull-request review with inline comments."""
        payload = {"event": event, "body": body, "comments": comments}
        return self._post(f"/repos/{repo}/pulls/{pr}/reviews", payload)


def legacy_main_post(writer, repo, prn, payload):
    """github_write.py:139-147 - the call site that drops commit_id and whose
    `except GitHubError` cannot see a urllib HTTPError."""
    try:
        res = writer.create_review(repo, prn, payload["event"], payload["body"],
                                   payload["comments"])
        return {"posted": True, "review_id": res.get("id"), "counts": payload["counts"]}
    except LegacyGitHubError as e:
        return {"posted": False, "error": str(e)}


# --------------------------------------------------------------------------- #
# BUG 4 is a property of the GitHub API (POST /pulls/{n}/reviews is atomic) plus
# the absence of any degradation path above: legacy_main_post has no retry.
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# DEDUP - skills/finding-dedup/scripts/finding_dedup.py:23-25, :45-46, :49-77
# --------------------------------------------------------------------------- #
def legacy_dedup_key(finding, rubric_version="1.0.0"):
    canon = (f"{finding.get('path','')}|{finding.get('line','')}|"
             f"{finding.get('principle_id','')}|{rubric_version}")
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]


def legacy_mr_key(pr_number, head_sha):
    return f"{pr_number}"


def legacy_classify(findings, pr_number, head_sha, rubric_version="1.0.0", store=None):
    """finding_dedup.py:49-77 with the on-disk load/save replaced by an in-memory
    dict so the test needs no filesystem. The keying and the `{**store, ...}`
    replacement on the final line are verbatim."""
    store = {} if store is None else store
    prior = store.get(legacy_mr_key(pr_number, head_sha), {})
    out = []
    seen_now = {}
    for f in findings:
        k = legacy_dedup_key(f, rubric_version)
        state = f.get("state", "open")
        if k in prior:
            prev = prior[k]
            if prev.get("state") == "resolved" and state == "open":
                verdict = "same_finding_resolved"
            else:
                verdict = "same_finding_same_state"
            thread_id = prev.get("thread_id")
        else:
            verdict = "new"
            thread_id = None
        g = dict(f)
        g["dedup_key"] = k
        g["dedup_verdict"] = verdict
        if thread_id:
            g["existing_thread_id"] = thread_id
        out.append(g)
        seen_now[k] = {"state": state, "thread_id": thread_id}
    return out, {**store, legacy_mr_key(pr_number, head_sha): seen_now}


# --------------------------------------------------------------------------- #
# RENDERER - skills/thread-poster/scripts/render_body.py:15-29
# The unescaped fence at :22-23 is the evidence-injection vector.
# --------------------------------------------------------------------------- #
def legacy_render_finding_body(f):
    sev = f.get("severity", "low")
    adv = " - advisory" if f.get("enforcement") in ("missing", "partial") else ""
    head = f.get("headline") or f.get("message", "")
    lines = [f"**`{f.get('principle_id')}` - {sev}**{adv}", "", head]
    if f.get("message") and f.get("headline") and f["message"] != head:
        lines += ["", f.get("message")]
    if f.get("evidence"):
        lines += ["", "```", str(f["evidence"]), "```"]
    return "\n".join(lines)
