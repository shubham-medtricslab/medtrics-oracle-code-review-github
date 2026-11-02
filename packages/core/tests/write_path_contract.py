"""
The write-path regression contract, as assertions, independent of implementation.

Every assertion in this module is one of the verified v0.5.0 defects stated as
the behaviour we require instead. Each mixin is run twice:

  * `test_legacy_reference_bugs.py` binds it to the frozen v0.5.0 code in
    `legacy_reference.py` and decorates every inherited test
    `unittest.expectedFailure`.
  * `test_write_path.py` binds it to the new implementation, where they pass.

That is what makes "this test failed before the fix" checkable six months from
now instead of a sentence in a report. It also traps the reverse mistake: if a
bug is ever reintroduced into the legacy reference's fixed counterpart, or the
legacy reference is "tidied up", the expected failures turn into unexpected
successes and the suite goes red.

Rule for adding to these mixins: an assertion belongs here ONLY if the legacy
reference fails it. Anything both implementations satisfy goes in the
new-implementation-only module, otherwise `expectedFailure` reports an
unexpected success.

Set AIREVIEW_SHOW_LEGACY_FAILURES=1 to drop the expectedFailure decorators and
see the five defects fail with their real messages.

Stdlib only.
"""
import urllib.error

from _fixtures import (
    HEAD_SHA, NONEWLINE_PATH, OTHER_SHA, PLUSPLUS_COMMENTABLE, PLUSPLUS_PATH,
    mixed_pr, nonewline_pr, plusplus_pr,
)


# --------------------------------------------------------------------------- #
# Hunk walking - bugs 2 and 3
# --------------------------------------------------------------------------- #
class HunkWalkerContract:
    """Subject must implement `commentable(prfetch, path) -> set[int]`."""

    def commentable(self, prfetch, path):
        raise NotImplementedError

    # -- BUG 2 ------------------------------------------------------------- #
    def test_bug2_added_line_starting_with_plusplus_does_not_desync(self):
        """github_write.py:45 skips any line starting '+++' WITHOUT advancing
        the counter. GitHub's `patch` has no file headers, so the only thing
        that matches is an added source line beginning '++' - here a C-style
        pre-increment. Everything after it in the hunk is then off by one and
        the hunk's last line drops out of the commentable set entirely.
        """
        got = self.commentable(plusplus_pr(), PLUSPLUS_PATH)
        self.assertEqual(
            got, PLUSPLUS_COMMENTABLE,
            f"hunk covers new lines 40-45; walker produced {sorted(got)}. "
            f"Missing {sorted(PLUSPLUS_COMMENTABLE - got)}, which is the "
            f"off-by-one introduced by the '++attempts;' added line.",
        )

    # The mirror branch, `raw.startswith('---')`, is deliberately NOT asserted
    # here. A diff line can only begin '---' if it is a REMOVED line whose
    # source starts '--', so skipping it without advancing damages old-side
    # numbering only and is invisible to `commentable_lines`. It is still wrong
    # - the unified walker reports old_line - so it is covered directly in
    # test_hunks.py rather than through this mixin, which may only contain
    # assertions the legacy reference actually fails.

    # -- BUG 3 ------------------------------------------------------------- #
    def test_bug3_no_newline_marker_is_not_a_diff_line(self):
        r"""'\ No newline at end of file' is diff metadata. github_write.py:45-48
        guards neither it nor the trailing empty token, so it is treated as a
        context line, enters the commentable set, AND advances the counter.
        """
        got = self.commentable(nonewline_pr(), NONEWLINE_PATH)
        self.assertNotIn(
            4, got,
            r"line 4 is the '\ No newline at end of file' marker counted as a "
            r"commentable line; the hunk ends at new line 3 and GitHub 422s "
            r"a comment on 4.",
        )

    def test_bug3_trailing_empty_token_is_not_a_diff_line(self):
        """`unified_text.split("\\n")` on text ending in a newline yields a
        trailing "". It matches none of the skip conditions, so it is counted
        as a context line one past everything real.
        """
        got = self.commentable(nonewline_pr(), NONEWLINE_PATH)
        self.assertNotIn(
            5, got,
            'line 5 is the trailing "" from .split("\\n") counted as a '
            "commentable line",
        )

    def test_commentable_lines_never_exceed_the_hunk_new_range(self):
        """The general form of bug 3: a position the walker approves and GitHub
        rejects. No commentable line may fall outside some hunk's declared
        new-side range.
        """
        pr = mixed_pr()
        for d in pr["diffs"]:
            path = d["file_new_path"]
            ranges = [tuple(h["line_range_new"]) for h in d["hunks"]]
            for line in sorted(self.commentable(pr, path)):
                self.assertTrue(
                    any(lo <= line <= hi for lo, hi in ranges),
                    f"{path}:{line} is outside every hunk range {ranges} - "
                    f"GitHub will reject a comment there",
                )


# --------------------------------------------------------------------------- #
# Posting - bugs 1, 4 and 5
# --------------------------------------------------------------------------- #
class PostContract:
    """Subject must implement:

        attempt(*, findings, summary_body="S", head_sha=HEAD_SHA,
                live_head=HEAD_SHA, http_errors=(), verdict="approve",
                max_comments=50, dry_run=False) -> {"outcome": dict|None,
                                                    "sent": [payload, ...]}

    `sent` is every JSON body that reached POST /repos/{repo}/pulls/{n}/reviews.
    `http_errors` is a list of status codes to raise on successive POSTs.
    """

    def attempt(self, **kwargs):
        raise NotImplementedError

    def positioned_finding(self, **over):
        f = {
            "dedup_key": "k-positioned",
            "principle_id": "TS-009",
            "rulepack_id": "core",
            "severity": "medium",
            "surface": "typescript",
            "path": PLUSPLUS_PATH,
            "line": 42,
            "positionable": True,
            "message": "`any` type usage is banned.",
            "evidence": "  const b = 2;",
            "dedup_verdict": "new",
        }
        f.update(over)
        return f

    # -- BUG 1 ------------------------------------------------------------- #
    def test_bug1_commit_id_reaches_the_wire(self):
        """github_write.py:116 puts commit_id in the payload dict, :141 calls
        create_review(repo, prn, event, body, comments), and :93 rebuilds
        {"event","body","comments"}. commit_id is computed and discarded, so
        GitHub defaults to the latest commit and the review anchors to the
        wrong SHA. tests/test_github_write.py:50 asserts commit_id is in the
        dict - a green test over a live bug.
        """
        r = self.attempt(findings=[self.positioned_finding()])
        self.assertTrue(r["sent"], "nothing was POSTed to the reviews endpoint")
        self.assertEqual(
            r["sent"][0].get("commit_id"), HEAD_SHA,
            f"commit_id absent from the POSTed body; keys sent were "
            f"{sorted(r['sent'][0])}. GitHub will silently anchor the review "
            f"to whatever head is current at post time.",
        )

    # -- BUG 4 ------------------------------------------------------------- #
    def test_bug4_a_422_degrades_to_summary_only_instead_of_losing_the_review(self):
        """POST /pulls/{n}/reviews is atomic: one invalid position 422s the
        whole request and nothing is posted. The review must survive as a
        summary-only comment with degraded=True, not vanish.
        """
        findings = [self.positioned_finding(),
                    self.positioned_finding(dedup_key="k2", line=43,
                                            message="second finding text")]
        r = self.attempt(findings=findings, http_errors=[422])
        outcome = r["outcome"]
        self.assertIsNotNone(outcome, "poster returned nothing after a 422")
        self.assertTrue(
            outcome.get("posted"),
            "a single bad position destroyed the entire review; nothing posted",
        )
        self.assertTrue(
            outcome.get("degraded"),
            "review posted after a 422 but not flagged degraded",
        )
        self.assertGreaterEqual(len(r["sent"]), 2, "no retry was attempted")
        retry = r["sent"][-1]
        self.assertEqual(retry.get("comments"), [],
                         "retry still carried inline comments")
        self.assertIn("second finding text", retry.get("body", ""),
                      "a finding was dropped instead of demoted into the body")

    # -- BUG 5 ------------------------------------------------------------- #
    def test_bug5_httperror_never_escapes_the_poster(self):
        """github_write.py:79-89 wraps bare urllib.request.urlopen, so a 422 or
        403 raises urllib.error.HTTPError - which is not a GitHubError, so the
        `except GitHubError` at :145 misses it. Unhandled traceback, no retry,
        no secondary-rate-limit backoff. The retry/backoff logic exists only on
        the read client's _get (github_client.py:102-121).
        """
        for code in (404, 422):
            try:
                self.attempt(findings=[self.positioned_finding()],
                             http_errors=[code] * 8)
            except urllib.error.HTTPError as e:
                raise AssertionError(
                    f"urllib.error.HTTPError({e.code}) escaped the poster "
                    f"uncaught - the caller gets a traceback instead of a "
                    f"typed, catchable failure"
                ) from None
            except AssertionError:
                raise
            except Exception:
                pass  # a typed error is the acceptable outcome

    # -- no APPROVE path, enforced in code ---------------------------------- #
    def test_no_caller_supplied_verdict_can_produce_an_approve_event(self):
        """github_write.py:100 maps verdict 'approve' -> event 'APPROVE'. A
        GitHub App approval counts toward required_approving_review_count, so
        the bot must never be able to satisfy a human-review requirement. The
        event is structurally COMMENT; it is not a policy the caller chooses.
        """
        r = self.attempt(findings=[self.positioned_finding()], verdict="approve")
        self.assertTrue(r["sent"])
        self.assertEqual(
            r["sent"][0].get("event"), "COMMENT",
            f"posted event {r['sent'][0].get('event')!r}; the only permitted "
            f"review event is COMMENT",
        )

    # -- head race ---------------------------------------------------------- #
    def test_refuses_to_post_when_the_live_head_has_moved(self):
        """A push between fetch and post makes every computed position stale.
        Posting anyway anchors comments to lines that no longer exist.
        """
        r = self.attempt(findings=[self.positioned_finding()],
                         head_sha=HEAD_SHA, live_head=OTHER_SHA)
        self.assertEqual(r["sent"], [],
                         "posted a review computed against a stale head")
        self.assertFalse((r["outcome"] or {}).get("posted"))

    # -- dedup enforcement -------------------------------------------------- #
    def test_same_finding_same_state_is_skipped_in_code(self):
        """v0.5.0 computed the dedup verdict and then left acting on it to the
        model's discretion. An unchanged finding must not be re-posted, and
        that must be enforced by the poster, not requested in a prompt.
        """
        findings = [
            self.positioned_finding(dedup_key="dup",
                                    dedup_verdict="same_finding_same_state",
                                    message="ALREADY-POSTED"),
            self.positioned_finding(dedup_key="fresh", line=43,
                                    message="brand new finding"),
        ]
        r = self.attempt(findings=findings)
        self.assertTrue(r["sent"])
        blob = repr(r["sent"][0])
        self.assertNotIn("ALREADY-POSTED", blob,
                         "re-posted a finding already on the PR unchanged")
        self.assertIn("brand new finding", blob)
        self.assertEqual((r["outcome"] or {}).get("skipped_duplicates"), 1)

    # -- comment cap -------------------------------------------------------- #
    def test_max_comments_is_enforced(self):
        """An uncapped review can bury a PR. The remainder belongs in the
        summary body, not dropped and not posted inline.
        """
        findings = [self.positioned_finding(dedup_key=f"k{i}",
                                            line=40 + (i % 6),
                                            message=f"finding {i}")
                    for i in range(60)]
        r = self.attempt(findings=findings, max_comments=5)
        self.assertTrue(r["sent"])
        self.assertLessEqual(
            len(r["sent"][0].get("comments", [])), 5,
            "posted more inline comments than max_comments allows",
        )


# --------------------------------------------------------------------------- #
# Dedup
# --------------------------------------------------------------------------- #
class DedupContract:
    """Subject must implement new_store / dkey / classify / record_posted /
    tombstone_absent as thin adapters over its own API."""

    def new_store(self):
        raise NotImplementedError

    def dkey(self, *, path, principle_id, evidence, line=1,
             rulepack_version="1.0.0"):
        raise NotImplementedError

    def classify(self, store, findings, *, repo, pr):
        raise NotImplementedError

    def record_posted(self, store, *, repo, pr, mapping):
        raise NotImplementedError

    def tombstone_absent(self, store, *, repo, pr, seen_keys):
        raise NotImplementedError

    @staticmethod
    def finding(**over):
        f = {"path": "src/a.ts", "line": 10, "principle_id": "TS-009",
             "evidence": "const x: any = 1;"}
        f.update(over)
        return f

    def test_key_is_stable_when_the_finding_moves(self):
        """finding_dedup.py:24 keys on path|line|principle_id|rubric_version.
        Any edit above a finding changes its line, so it re-keys, classifies
        `new`, and re-posts. Ten pushes with fifteen findings is 150 comments.
        """
        a = self.dkey(path="src/a.ts", principle_id="TS-009",
                      evidence="const x: any = 1;", line=10)
        b = self.dkey(path="src/a.ts", principle_id="TS-009",
                      evidence="const x: any = 1;", line=400)
        self.assertEqual(a, b,
                         "the same finding re-keyed purely because an edit "
                         "above it moved its line number")

    def test_key_is_stable_across_a_rulepack_version_bump(self):
        """rubric_version in the key means bumping a pack re-keys every finding
        on every open PR at once, and the bot re-posts all of them.
        """
        a = self.dkey(path="src/a.ts", principle_id="TS-009",
                      evidence="const x: any = 1;", rulepack_version="1.0.0")
        b = self.dkey(path="src/a.ts", principle_id="TS-009",
                      evidence="const x: any = 1;", rulepack_version="2.0.0")
        self.assertEqual(a, b,
                         "a rulepack bump re-keyed the finding, which re-posts "
                         "every finding on every open PR")

    def test_key_distinguishes_different_evidence(self):
        """Content anchoring has to actually anchor on content: two different
        offending lines under the same principle in the same file are two
        findings, not one.
        """
        a = self.dkey(path="src/a.ts", principle_id="TS-009",
                      evidence="const x: any = 1;")
        b = self.dkey(path="src/a.ts", principle_id="TS-009",
                      evidence="const y: any = 2;")
        self.assertNotEqual(a, b, "two distinct findings collapsed to one key")

    def test_scope_includes_the_repository(self):
        """_mr_key at :45-46 returns f"{pr_number}" - no repo, no installation.
        PR #1 of one repo therefore collides with PR #1 of every other repo
        sharing the store.
        """
        store = self.new_store()
        f = [self.finding()]
        self.classify(store, f, repo="acme/widgets", pr=1)
        keys = {x["dedup_key"] for x in self.classify(store, f, repo="acme/widgets", pr=1)}
        self.record_posted(store, repo="acme/widgets", pr=1,
                           mapping={k: 900 for k in keys})
        out = self.classify(store, f, repo="other/project", pr=1)
        self.assertEqual(
            out[0]["dedup_verdict"], "new",
            "PR #1 of other/project inherited state from PR #1 of "
            "acme/widgets - the store is not scoped by repository",
        )

    def test_store_is_merged_not_replaced(self):
        """classify at :77 returns {**store, mr_key: seen_now}, replacing the
        PR's whole entry with only this run's findings. A finding that is
        missed for one run permanently loses its thread_id, so the next run
        posts a duplicate instead of updating in place.
        """
        store = self.new_store()
        # Distinct in both content and position, so neither keying scheme can
        # collapse them into one entry and pass this by accident.
        a = self.finding(line=10, evidence="const a: any = 1;")
        b = self.finding(line=55, evidence="const b: any = 2;")
        first = self.classify(store, [a, b], repo="acme/widgets", pr=7)
        ids = {f["dedup_key"]: 100 + i for i, f in enumerate(first)}
        self.record_posted(store, repo="acme/widgets", pr=7, mapping=ids)
        b_key = first[1]["dedup_key"]
        b_id = ids[b_key]

        # Run 2 sees only A - a flaky surface, a timeout, a truncated diff.
        second = self.classify(store, [a], repo="acme/widgets", pr=7)
        self.record_posted(store, repo="acme/widgets", pr=7,
                           mapping={second[0]["dedup_key"]: ids[second[0]["dedup_key"]]})

        third = self.classify(store, [a, b], repo="acme/widgets", pr=7)
        self.assertEqual(
            third[1].get("existing_comment_id"), b_id,
            "B's comment id was destroyed by a run that did not see B, so the "
            "next run posts a duplicate instead of updating the live comment",
        )

    def test_a_resolved_finding_that_returns_is_a_regression(self):
        """Nothing in v0.5.0 ever set state='resolved', so the
        same_finding_resolved branch at :62-63 is dead code and regression
        detection does not work at all. Tombstoning absent findings is what
        makes it live.
        """
        store = self.new_store()
        a = self.finding()
        first = self.classify(store, [a], repo="acme/widgets", pr=9)
        self.record_posted(store, repo="acme/widgets", pr=9,
                           mapping={first[0]["dedup_key"]: 555})

        # The author fixes it: the finding is absent from the next run.
        self.classify(store, [], repo="acme/widgets", pr=9)
        self.tombstone_absent(store, repo="acme/widgets", pr=9,
                              seen_keys=frozenset())

        # And then it comes back.
        back = self.classify(store, [a], repo="acme/widgets", pr=9)
        self.assertEqual(
            back[0]["dedup_verdict"], "same_finding_resolved",
            "a finding that was resolved and then regressed was reported as "
            "`new`; regression detection is dead code without tombstones",
        )
