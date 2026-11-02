#!/usr/bin/env python3
"""
Dedup store mechanics.

`write_path_contract.DedupContract` already pins the five v0.5.0 defects. This
module covers the store itself: persistence, scoping, tombstone lifecycle, and
the failure modes - because the failure modes are where a dedup store does its
real damage. A store that loses state posts duplicates; a store that invents
state posts nothing at all, silently.

Run: python3 -m unittest tests.test_dedup
Stdlib only.
"""
import datetime as dt
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.dirname(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from aireview.pipeline.dedup import (  # noqa: E402
    JsonDedupStore, dedup_key, normalize_evidence, scope_key,
)

REPO = "acme/widgets"


def finding(**over):
    f = {"path": "src/a.ts", "line": 10, "principle_id": "TS-009",
         "evidence": "const x: any = 1;"}
    f.update(over)
    return f


class TestKey(unittest.TestCase):

    def test_whitespace_is_normalised_so_reformatting_does_not_re_key(self):
        """Reindenting is the commonest way a line changes without changing
        meaning. If that re-keys, a prettier run re-posts the whole review.
        """
        a = dedup_key(path="a.ts", principle_id="P", evidence="if (x) {")
        b = dedup_key(path="a.ts", principle_id="P",
                      evidence="      if   (x)   {   ")
        self.assertEqual(a, b)

    def test_case_is_not_folded(self):
        """This is source code. `User` and `user` are different identifiers,
        and collapsing them would merge two genuinely different findings.
        """
        self.assertNotEqual(
            dedup_key(path="a.ts", principle_id="P", evidence="User"),
            dedup_key(path="a.ts", principle_id="P", evidence="user"))

    def test_the_path_is_part_of_the_identity(self):
        self.assertNotEqual(
            dedup_key(path="a.ts", principle_id="P", evidence="x"),
            dedup_key(path="b.ts", principle_id="P", evidence="x"))

    def test_field_separator_cannot_be_forged_from_a_path(self):
        """v0.5.0 joined on '|'. A path ending in a pipe could then produce
        the same canonical string as a different (path, principle) pair.
        """
        self.assertNotEqual(
            dedup_key(path="a.ts|P", principle_id="Q", evidence="x"),
            dedup_key(path="a.ts", principle_id="P|Q", evidence="x"))

    def test_detector_key_separates_two_detectors_sharing_a_principle(self):
        """FA-009 is emitted by two detectors at different severities. On the
        same line with the same evidence they would otherwise be one finding,
        and the more severe of the two would be lost.
        """
        a = dedup_key(path="a.ts", principle_id="FA-009", evidence="x",
                      detector_key="fa-009-adapters")
        b = dedup_key(path="a.ts", principle_id="FA-009", evidence="x",
                      detector_key="fa-009-deep-domain")
        self.assertNotEqual(a, b)

    def test_omitting_detector_key_is_bit_identical_to_before(self):
        """The parameter is additive. A caller that does not pass it must get
        exactly the key it got when the parameter did not exist, or adding it
        would itself re-key every finding on every open pull request.
        """
        self.assertEqual(
            dedup_key(path="a.ts", principle_id="P", evidence="x"),
            dedup_key(path="a.ts", principle_id="P", evidence="x",
                      detector_key=None))

    def test_evidence_is_truncated_consistently(self):
        long_a = "x" * 500
        long_b = "x" * 400
        self.assertEqual(len(normalize_evidence(long_a)), 200)
        self.assertEqual(dedup_key(path="a", principle_id="P", evidence=long_a),
                         dedup_key(path="a", principle_id="P", evidence=long_b))

    def test_evidence_less_findings_collapse_per_file_and_principle(self):
        """Deliberate. With nothing to tell them apart they are one
        observation about that file, not twelve comments on it.
        """
        self.assertEqual(
            dedup_key(path="a.ts", principle_id="P", evidence=""),
            dedup_key(path="a.ts", principle_id="P", evidence=None))


class TestScope(unittest.TestCase):

    def test_repo_and_pr(self):
        self.assertNotEqual(scope_key("a/b", 1), scope_key("c/d", 1))
        self.assertNotEqual(scope_key("a/b", 1), scope_key("a/b", 2))

    def test_installation_namespaces_further(self):
        self.assertNotEqual(scope_key("a/b", 1, 100), scope_key("a/b", 1, 200))
        self.assertNotEqual(scope_key("a/b", 1, 100), scope_key("a/b", 1))


class TestStore(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "nested", "store.json")

    def store(self, **kw):
        return JsonDedupStore(self.path, **kw)

    # -- the property that matters most ------------------------------------ #
    def test_classify_does_not_write_anything(self):
        """If classify persisted, a run that died between classification and
        a successful POST would leave every finding marked seen - and the
        next run would post nothing at all, silently. See the module
        docstring in dedup.py; this test is what stops that being "optimised"
        back in.
        """
        s = self.store()
        s.classify([finding()], repo=REPO, pr=1)
        self.assertFalse(os.path.exists(self.path),
                         "classify created a store file")
        again = self.store().classify([finding()], repo=REPO, pr=1)
        self.assertEqual(again[0]["dedup_verdict"], "new")

    def test_state_survives_a_new_process(self):
        s = self.store()
        key = s.classify([finding()], repo=REPO, pr=1)[0]["dedup_key"]
        s.record_posted(repo=REPO, pr=1, key_to_comment_id={key: 11})
        fresh = self.store()
        out = fresh.classify([finding()], repo=REPO, pr=1)
        self.assertEqual(out[0]["dedup_verdict"], "same_finding_same_state")
        self.assertEqual(out[0]["existing_comment_id"], 11)

    def test_the_write_is_atomic_and_leaves_no_temp_file(self):
        s = self.store()
        s.record_posted(repo=REPO, pr=1, key_to_comment_id={"k": 1})
        leftovers = [f for f in os.listdir(os.path.dirname(self.path))
                     if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])
        with open(self.path, encoding="utf-8") as fh:
            json.load(fh)  # parses

    # -- tombstone lifecycle ----------------------------------------------- #
    def test_tombstones_are_kept_not_deleted(self):
        """Deleting the entry would make a regression indistinguishable from
        a first sighting - the same bug by another route.
        """
        s = self.store()
        key = s.classify([finding()], repo=REPO, pr=1)[0]["dedup_key"]
        s.record_posted(repo=REPO, pr=1, key_to_comment_id={key: 11})
        s.tombstone_absent(repo=REPO, pr=1, seen_keys=frozenset())
        entry = s.known(repo=REPO, pr=1)[key]
        self.assertEqual(entry["state"], "resolved")
        self.assertIsNotNone(entry["resolved_at"])
        self.assertEqual(entry["comment_id"], 11)

    def test_a_still_present_finding_is_not_tombstoned(self):
        s = self.store()
        key = s.classify([finding()], repo=REPO, pr=1)[0]["dedup_key"]
        s.record_posted(repo=REPO, pr=1, key_to_comment_id={key: 11})
        s.tombstone_absent(repo=REPO, pr=1, seen_keys=frozenset({key}))
        self.assertEqual(s.known(repo=REPO, pr=1)[key]["state"], "open")

    def test_recording_a_regression_reopens_the_entry(self):
        s = self.store()
        key = s.classify([finding()], repo=REPO, pr=1)[0]["dedup_key"]
        s.record_posted(repo=REPO, pr=1, key_to_comment_id={key: 11})
        s.tombstone_absent(repo=REPO, pr=1, seen_keys=frozenset())
        self.assertEqual(
            s.classify([finding()], repo=REPO, pr=1)[0]["dedup_verdict"],
            "same_finding_resolved")
        s.record_posted(repo=REPO, pr=1, key_to_comment_id={key: 12})
        entry = s.known(repo=REPO, pr=1)[key]
        self.assertEqual(entry["state"], "open")
        self.assertIsNone(entry["resolved_at"])
        self.assertEqual(
            s.classify([finding()], repo=REPO, pr=1)[0]["dedup_verdict"],
            "same_finding_same_state")

    def test_tombstoning_an_unknown_pull_request_is_a_no_op(self):
        self.store().tombstone_absent(repo=REPO, pr=999,
                                      seen_keys=frozenset({"x"}))
        self.assertFalse(os.path.exists(self.path))

    # -- degradation -------------------------------------------------------- #
    def test_a_corrupt_store_degrades_to_everything_new(self):
        """Re-posting a review is recoverable. Refusing to run is not, and
        neither is crashing the whole pipeline on a truncated cache file.
        """
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{ this is not json")
        out = self.store().classify([finding()], repo=REPO, pr=1)
        self.assertEqual(out[0]["dedup_verdict"], "new")

    def test_a_store_from_a_future_schema_is_ignored_not_misread(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump({"schema_version": 99, "scopes": {"a/b#1": {}}}, fh)
        out = self.store().classify([finding()], repo=REPO, pr=1)
        self.assertEqual(out[0]["dedup_verdict"], "new")

    def test_an_in_memory_store_writes_nothing(self):
        s = JsonDedupStore(None)
        key = s.classify([finding()], repo=REPO, pr=1)[0]["dedup_key"]
        s.record_posted(repo=REPO, pr=1, key_to_comment_id={key: 1})
        self.assertEqual(
            s.classify([finding()], repo=REPO, pr=1)[0]["dedup_verdict"],
            "same_finding_same_state")
        self.assertFalse(os.path.exists(self.path))

    # -- housekeeping ------------------------------------------------------- #
    def test_old_scopes_are_pruned(self):
        """A merged pull request is never reviewed again; its tombstones are
        dead weight in a cache that has to be uploaded and downloaded.
        """
        s = self.store(max_age_days=30)
        s.record_posted(repo=REPO, pr=1, key_to_comment_id={"k": 1})
        with open(self.path, encoding="utf-8") as fh:
            data = json.load(fh)
        stale = (dt.datetime.now(dt.timezone.utc)
                 - dt.timedelta(days=400)).isoformat()
        data["scopes"][scope_key(REPO, 1)]["updated_at"] = stale
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        s.record_posted(repo=REPO, pr=2, key_to_comment_id={"k2": 2})
        with open(self.path, encoding="utf-8") as fh:
            after = json.load(fh)
        self.assertNotIn(scope_key(REPO, 1), after["scopes"])
        self.assertIn(scope_key(REPO, 2), after["scopes"])

    def test_installation_scoping_keeps_two_apps_apart(self):
        a = JsonDedupStore(self.path, installation_id="100")
        b = JsonDedupStore(self.path, installation_id="200")
        key = a.classify([finding()], repo=REPO, pr=1)[0]["dedup_key"]
        a.record_posted(repo=REPO, pr=1, key_to_comment_id={key: 1})
        self.assertEqual(
            b.classify([finding()], repo=REPO, pr=1)[0]["dedup_verdict"],
            "new")

    def test_recording_nothing_is_a_no_op(self):
        self.store().record_posted(repo=REPO, pr=1, key_to_comment_id={})
        self.assertFalse(os.path.exists(self.path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
