"""
Detector parity. v0.5.0 had no assertion of any kind over its detector set.

That absence is why both detector bugs survived to v0.5.0. `detectors.py`
shipped a `--selftest` that printed findings and asserted nothing, so
`FA-009b` silently becoming `FA-009` and `FA-010` firing on the one file kind
it exempts were both invisible. Worse, the resulting collision is why the
project-wide count was "17 detectors" when there are 18 - the miscount was a
symptom of the bug.

Three layers here:

  1. a frozen table of the detector set, so any change is a deliberate edit
  2. targeted regression tests for the two fixed bugs, each written so it would
     fail against the legacy behaviour
  3. behavioural parity against the legacy `SELFTEST_PR` fixture
"""
import hashlib
import json
import unittest

from ..detect import added_lines, run
from ..loader import load, load_all
from ..model import Detector
from . import support

#: (key, emits_principle_id, severity, pack, include_globs, exclude_globs,
#:  flags). The fields where the bugs lived are spelled out; `pattern` and
#: `message` are pinned by hash below so a silent regex edit still fails.
EXPECTED = [
    ("a11y-022-icon-only-button", "A11Y-022", "medium", "react-ts",
     ("**/*.tsx",), (), ()),
    ("dl-001-create-table-rls", "DL-001", "high", "supabase-rls",
     ("**/*.sql",), (), ("IGNORECASE",)),
    ("dl-008-view-security-invoker", "DL-008", "critical", "supabase-rls",
     ("**/*.sql",), (), ("IGNORECASE",)),
    ("dl-009-select-star", "DL-009", "medium", "supabase-rls",
     ("**/services/**/*.ts",), (), ()),
    ("dl-014-soft-delete-filter", "DL-014", "high", "supabase-rls",
     ("**/services/**/*.ts",), (), ()),
    ("dl-030-for-all-policy", "DL-030", "high", "supabase-rls",
     ("**/*.sql",), (), ("IGNORECASE",)),
    ("fa-009-banned-root-import", "FA-009", "medium", "medtrics-oracle",
     ("**/*.ts", "**/*.tsx"), (), ()),
    ("fa-009-deep-domain-import", "FA-009", "low", "medtrics-oracle",
     ("**/*.ts", "**/*.tsx"), (), ()),
    ("fa-010-supabase-client-outside-service", "FA-010", "high",
     "medtrics-oracle", ("**/*.ts", "**/*.tsx"), ("**/*.service.ts",), ()),
    ("fa-026-window-confirm", "FA-026", "high", "react-ts",
     ("**/*.ts", "**/*.tsx"), (), ()),
    ("i18n-001-hardcoded-jsx-string", "I18N-001", "medium", "react-ts",
     ("**/*.tsx",), (), ()),
    ("i18n-003-rtl-directional-class", "I18N-003", "high", "react-ts",
     ("**/*.tsx",), (), ()),
    ("perf-022-unstable-query-key", "PERF-022", "medium", "react-ts",
     ("**/*.ts", "**/*.tsx"), (), ()),
    ("sec-004-hardcoded-secret", "SEC-004", "high", "react-ts",
     ("**/*.ts", "**/*.tsx"), (), ()),
    ("sec-011-raw-error-message", "SEC-011", "medium", "react-ts",
     ("**/*.ts", "**/*.tsx"), (), ()),
    ("sec-014-policy-returns-true", "SEC-014", "critical", "supabase-rls",
     ("**/*.sql",), (), ("IGNORECASE",)),
    ("ts-009-any-type", "TS-009", "medium", "react-ts",
     ("**/*.ts", "**/*.tsx"), (), ()),
    ("ts-010-console-statement", "TS-010", "medium", "react-ts",
     ("**/*.ts", "**/*.tsx"), (), ()),
]

#: sha256(json([pattern, message]))[:16], keyed by detector key.
PATTERN_HASHES = {
    "a11y-022-icon-only-button": "e5813b22258d4e75",
    "dl-001-create-table-rls": "c4e45a976ed801e7",
    "dl-008-view-security-invoker": "911113a481a2a72e",
    "dl-009-select-star": "4bc07dc353b71212",
    "dl-014-soft-delete-filter": "47a71d9393397230",
    "dl-030-for-all-policy": "64e619f948e1a68c",
    "fa-009-banned-root-import": "106ae46597d770dc",
    "fa-009-deep-domain-import": "6aacbe269726df16",
    "fa-010-supabase-client-outside-service": "25ae3ca548edc346",
    "fa-026-window-confirm": "bf13806df25d531b",
    "i18n-001-hardcoded-jsx-string": "1e88ab23ed33a04b",
    "i18n-003-rtl-directional-class": "8d42030fa796fcfa",
    "perf-022-unstable-query-key": "5142979ab6fa7e50",
    "sec-004-hardcoded-secret": "72ab54f42bdd0569",
    "sec-011-raw-error-message": "45170ac3e72592e6",
    "sec-014-policy-returns-true": "673357a7b6f1e876",
    "ts-009-any-type": "f7516c2e37981f91",
    "ts-010-console-statement": "4c10ff7c85ca39ab",
}

#: Verbatim from `skills/detectors/scripts/detectors.py:108`.
SELFTEST_PR = {
    "diffs": [
        {"file_new_path": "src/components/organisms/forms/FormCard.tsx",
         "hunks": [{"line_range_new": [10, 12], "unified_text":
                    "@@ -10,0 +10,3 @@\n+<div className=\"ml-2 text-left\">x</div>\n"
                    "+const y: any = 1;\n+<button><svg/></button>"}]},
        {"file_new_path": "src/domains/forms/services/x.service.ts",
         "hunks": [{"line_range_new": [5, 6], "unified_text":
                    "@@ -5,0 +5,2 @@\n+const { data } = await supabase.from('t').select('*');\n"
                    "+console.log('debug');"}]},
        {"file_new_path": "supabase/migrations/domains/07_forms/v.sql",
         "hunks": [{"line_range_new": [1, 2], "unified_text":
                    "@@ -0,0 +1,2 @@\n+CREATE VIEW v_forms AS SELECT * FROM forms;\n"
                    "+CREATE POLICY p ON forms FOR ALL TO authenticated USING (true);"}]},
    ]
}


def _hash(detector):
    payload = json.dumps([detector.pattern, detector.message],
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]


class TestDetectorSet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rubric = load_all(support.REGISTRY)
        cls.by_key = {d.key: d for d in cls.rubric.detectors}

    def test_there_are_eighteen_detectors(self):
        """
        Eighteen, not seventeen.

        `detectors.py:58` has 18 entries. They collapsed to 17 distinct
        principle ids only because the FA-009b collision erased one, and that
        collapsed number is what got written down everywhere.
        """
        self.assertEqual(len(self.rubric.detectors), 18)

    def test_every_detector_key_is_unique(self):
        keys = [d.key for d in self.rubric.detectors]
        self.assertEqual(len(keys), len(set(keys)))

    def test_seventeen_distinct_principles_are_emitted(self):
        emitted = [d.emits_principle_id for d in self.rubric.detectors]
        self.assertEqual(len(set(emitted)), 17)
        self.assertEqual(
            sorted(i for i in set(emitted) if emitted.count(i) > 1),
            ["FA-009"],
        )

    def test_the_frozen_table_matches(self):
        actual = [
            (d.key, d.emits_principle_id, d.severity, d.pack,
             tuple(d.include_globs), tuple(d.exclude_globs), tuple(d.flags))
            for d in self.rubric.detectors
        ]
        self.assertEqual(actual, EXPECTED)

    def test_patterns_and_messages_are_unchanged(self):
        for det in self.rubric.detectors:
            with self.subTest(detector=det.key):
                self.assertEqual(_hash(det), PATTERN_HASHES[det.key])

    def test_every_pattern_compiles(self):
        import re
        for det in self.rubric.detectors:
            with self.subTest(detector=det.key):
                re.compile(det.pattern)

    def test_every_emitted_principle_exists(self):
        ids = {r.id for r in self.rubric.rules}
        for det in self.rubric.detectors:
            with self.subTest(detector=det.key):
                self.assertIn(det.emits_principle_id, ids)


class TestFa009Collision(unittest.TestCase):
    """
    Regression: two detectors, one principle, told apart by key.

    Legacy behaviour was `rid.split("b")[0] if rid.endswith("b")`, which meant
    nothing downstream could distinguish the deep-domain-import finding from
    the banned-root-import one. The test that would have caught it is simply:
    are there two, and can you tell them apart?
    """

    @classmethod
    def setUpClass(cls):
        cls.rubric = load_all(support.REGISTRY)
        cls.pair = [d for d in cls.rubric.detectors
                    if d.emits_principle_id == "FA-009"]

    def test_both_detectors_survive(self):
        self.assertEqual(len(self.pair), 2)

    def test_they_have_distinct_descriptive_keys(self):
        self.assertEqual(
            sorted(d.key for d in self.pair),
            ["fa-009-banned-root-import", "fa-009-deep-domain-import"],
        )

    def test_they_keep_their_original_distinct_severities(self):
        severities = {d.key: d.severity for d in self.pair}
        self.assertEqual(severities, {
            "fa-009-banned-root-import": "medium",
            "fa-009-deep-domain-import": "low",
        })

    def test_no_emitted_id_is_derivable_from_its_key(self):
        """
        The general form of the bug, not just the one instance.

        `FA-009b` is also unrepresentable: the schema's
        `^[A-Z0-9]+-[0-9]{3}$` rejects it, so the legacy suffix convention
        cannot come back through the data either.
        """
        for det in self.rubric.detectors:
            with self.subTest(detector=det.key):
                self.assertFalse(det.key.endswith("b"))
                self.assertNotEqual(det.key, det.emits_principle_id)

    def test_findings_carry_the_detector_key_so_dedup_can_separate_them(self):
        pr = {"diffs": [{"file_new_path": "src/x.ts", "hunks": [{
            "line_range_new": [1, 2],
            "unified_text": "@@ -0,0 +1,2 @@\n"
                            "+import { a } from '@/core/thing';\n"
                            "+import { b } from '@/domains/forms/hooks/useX';",
        }]}]}
        findings = run(self.rubric, pr)
        self.assertEqual(len(findings), 2)
        self.assertEqual({f["principle_id"] for f in findings}, {"FA-009"})
        self.assertEqual(
            {f["detector_key"] for f in findings},
            {"fa-009-banned-root-import", "fa-009-deep-domain-import"},
        )
        self.assertEqual({f["severity"] for f in findings}, {"medium", "low"})


class TestFa010Inversion(unittest.TestCase):
    """
    Regression: FA-010 must not fire on the file kind its own message permits.

    `detectors.py:68` bound it to `_is_ts` with no exclusion while its message
    reads "only *.service.ts may import it". So the detector flagged exactly
    the compliant case and said nothing about the violating one being
    acceptable elsewhere.
    """

    @classmethod
    def setUpClass(cls):
        cls.rubric = load_all(support.REGISTRY)
        cls.det = next(d for d in cls.rubric.detectors
                       if d.emits_principle_id == "FA-010")

    def _run(self, path):
        pr = {"diffs": [{"file_new_path": path, "hunks": [{
            "line_range_new": [1, 1],
            "unified_text": "@@ -0,0 +1 @@\n"
                            "+import { supabase } from '@/integrations/supabase/client';",
        }]}]}
        return [f for f in run(self.rubric, pr)
                if f["principle_id"] == "FA-010"]

    def test_it_declares_an_exclusion(self):
        self.assertEqual(tuple(self.det.exclude_globs), ("**/*.service.ts",))

    def test_it_does_not_fire_on_a_service(self):
        self.assertEqual(
            self._run("src/domains/forms/services/x.service.ts"), [],
            "FA-010 fired on *.service.ts, the one case its own message "
            "permits - this is the legacy inversion",
        )

    def test_it_still_fires_outside_a_service(self):
        self.assertEqual(
            len(self._run("src/components/organisms/forms/FormCard.tsx")), 1)
        self.assertEqual(len(self._run("src/hooks/useThing.ts")), 1)

    def test_a_non_service_file_inside_a_services_directory_still_fires(self):
        """The exclusion keys on the filename, matching the rule's wording."""
        self.assertEqual(len(self._run("src/domains/forms/services/util.ts")), 1)

    def test_the_legacy_shape_would_have_failed_this(self):
        """
        Pin the counterfactual.

        Same detector with `exclude_globs` dropped - i.e. exactly what
        `detectors.py:68` expressed - must fire on the service file. If this
        ever stops being true, the test above has stopped proving anything.
        """
        legacy = Detector(
            key=self.det.key, emits_principle_id=self.det.emits_principle_id,
            severity=self.det.severity, pattern=self.det.pattern,
            message=self.det.message, pack=self.det.pack,
            flags=self.det.flags, include_globs=self.det.include_globs,
            exclude_globs=(),
        )

        class _Stub:
            detectors = (legacy,)

        pr = {"diffs": [{"file_new_path":
                         "src/domains/forms/services/x.service.ts",
                         "hunks": [{
                             "line_range_new": [1, 1],
                             "unified_text": "@@ -0,0 +1 @@\n+import { supabase } "
                                             "from '@/integrations/supabase/client';",
                         }]}]}
        self.assertEqual(len(run(_Stub(), pr)), 1)


class TestSelftestParity(unittest.TestCase):
    """
    Behavioural parity against the legacy `SELFTEST_PR` fixture.

    v0.5.0 printed these findings and checked nothing. Pinning them means the
    glob translation of `_is_ts` / `_is_tsx` / `_is_sql` / `_is_service` is
    verified against real input rather than read and assumed correct.
    """

    @classmethod
    def setUpClass(cls):
        cls.findings = run(load_all(support.REGISTRY), SELFTEST_PR)

    def test_expected_findings(self):
        actual = sorted(
            (f["path"], f["line"], f["detector_key"], f["severity"])
            for f in self.findings
        )
        self.assertEqual(actual, [
            ("src/components/organisms/forms/FormCard.tsx", 10,
             "i18n-003-rtl-directional-class", "high"),
            ("src/components/organisms/forms/FormCard.tsx", 11,
             "ts-009-any-type", "medium"),
            ("src/components/organisms/forms/FormCard.tsx", 12,
             "a11y-022-icon-only-button", "medium"),
            ("src/domains/forms/services/x.service.ts", 5,
             "dl-009-select-star", "medium"),
            ("src/domains/forms/services/x.service.ts", 6,
             "ts-010-console-statement", "medium"),
            ("supabase/migrations/domains/07_forms/v.sql", 1,
             "dl-008-view-security-invoker", "critical"),
            ("supabase/migrations/domains/07_forms/v.sql", 2,
             "dl-030-for-all-policy", "high"),
        ])

    def test_sql_detectors_do_not_leak_onto_typescript(self):
        for f in self.findings:
            if f["path"].endswith(".ts") or f["path"].endswith(".tsx"):
                with self.subTest(finding=f["detector_key"]):
                    self.assertNotIn(f["detector_key"], {
                        "dl-001-create-table-rls",
                        "dl-008-view-security-invoker",
                        "dl-030-for-all-policy",
                        "sec-014-policy-returns-true",
                    })

    def test_tsx_only_detectors_do_not_fire_on_plain_ts(self):
        tsx_only = {"i18n-001-hardcoded-jsx-string",
                    "i18n-003-rtl-directional-class",
                    "a11y-022-icon-only-button"}
        for f in self.findings:
            if f["path"].endswith(".ts"):
                self.assertNotIn(f["detector_key"], tsx_only)

    def test_service_only_detectors_do_not_fire_outside_services(self):
        for f in self.findings:
            if "/services/" not in f["path"]:
                self.assertNotIn(
                    f["detector_key"],
                    {"dl-009-select-star", "dl-014-soft-delete-filter"})

    def test_findings_are_candidates_not_verdicts(self):
        for f in self.findings:
            self.assertEqual(f["source"], "detector")
            self.assertEqual(f["confidence"], "candidate")


class TestAddedLineWalk(unittest.TestCase):
    """Line numbering must match the writer's walk, or findings anchor wrongly.

    Originally this class pinned parity with v0.5.0. That was the right instinct
    and the wrong reference point: v0.5.0's detector walk and its writer walk
    disagreed, which is the defect, so matching one of them guarantees
    disagreeing with the other. `added_lines` now delegates to the single shared
    walker in `aireview.github.hunks` and these assert that behaviour.
    """

    def test_removed_lines_do_not_advance_the_new_counter(self):
        pr = {"diffs": [{"file_new_path": "a.ts", "hunks": [{
            "line_range_new": [10, 12],
            "unified_text": "@@ -10,3 +10,2 @@\n context\n-gone\n+added",
        }]}]}
        self.assertEqual(list(added_lines(pr)), [("a.ts", 11, "added")])


    def test_a_plus_plus_line_is_content_not_a_file_header(self):
        """`+++` inside a hunk is an added line whose source begins `++`.

        GitHub's `/pulls/{n}/files` `patch` field begins at `@@` and carries no
        `---`/`+++` file headers - the filename is a sibling field. Verified
        against the captured fixtures: every patch starts `@@` and none contains
        a `+++` line. So treating `+++` as a header, as v0.5.0 did, makes it
        impossible for any detector to fire on a line starting `++` and shifts
        the counter after any removed line starting `--`.

        Not hypothetical: a markdown file documenting a diff, or a `.patch`
        fixture, contains exactly these lines. This repository now has several.
        """
        pr = {"diffs": [{"file_new_path": "a.ts", "hunks": [{
            "line_range_new": [1, 2],
            "unified_text": "@@ -0,0 +1,2 @@\n+++ b/a.ts\n+real",
        }]}]}
        self.assertEqual(
            [(line, text) for _, line, text in added_lines(pr)],
            [(1, "++ b/a.ts"), (2, "real")],
        )

    def test_added_lines_agrees_with_the_writer(self):
        """The detector and the writer must never disagree about a line number.

        A detector number the writer's commentable set happens to accept puts a
        comment on the wrong line of code, under the bot's name, silently.
        """
        from aireview.github.hunks import iter_added_lines
        pr = {"diffs": [{"file_new_path": "a.ts", "hunks": [{
            "line_range_new": [40, 5], "line_range_old": [40, 3],
            "unified_text": "@@ -40,3 +40,5 @@\n ctx\n---legacy;\n"
                            "+++attempts;\n+  const x = 1;\n ctx",
        }]}]}
        self.assertEqual(list(added_lines(pr)), list(iter_added_lines(pr)))

    def test_old_path_is_used_when_there_is_no_new_path(self):
        pr = {"diffs": [{"file_old_path": "gone.ts", "hunks": [{
            "line_range_new": [1, 1], "unified_text": "@@ -1 +0,0 @@\n+x",
        }]}]}
        self.assertEqual([p for p, _, _ in added_lines(pr)], ["gone.ts"])


class TestDetectorsInSubsets(unittest.TestCase):
    def test_a_react_only_repo_gets_no_sql_or_oracle_detectors(self):
        rubric = load(support.REGISTRY, ["base", "react-ts"])
        self.assertEqual(len(rubric.detectors), 9)
        for det in rubric.detectors:
            self.assertNotIn("**/*.sql", det.include_globs)

    def test_detectors_for_path_filters_by_glob(self):
        rubric = load_all(support.REGISTRY)
        keys = {d.key for d in rubric.detectors_for_path("db/schema.sql")}
        self.assertEqual(keys, {
            "dl-001-create-table-rls", "dl-008-view-security-invoker",
            "dl-030-for-all-policy", "sec-014-policy-returns-true",
        })


if __name__ == "__main__":
    unittest.main()
