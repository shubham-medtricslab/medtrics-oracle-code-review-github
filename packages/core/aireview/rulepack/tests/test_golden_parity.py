"""
All five packs together must reproduce `contracts/golden-rubric.tsv` exactly.

This is the gate the migration lives or dies by. v0.5.0's equivalent was
`rubric.py parity`, which asserted `len(rules) == 374 and len(CATEGORIES) == 17`
- a check you can pass while having moved every rule to the wrong surface. Here
every one of the six columns of all 374 rows is compared.
"""
import os
import subprocess
import sys
import unittest

from ..loader import load, load_all
from ..model import COLUMNS
from . import support


def read_golden():
    rows = {}
    with open(support.GOLDEN, encoding="utf-8") as fh:
        header = tuple(fh.readline().rstrip("\n").split("\t"))
        assert header == COLUMNS, header
        for line in fh:
            line = line.rstrip("\n")
            if line:
                parts = tuple(line.split("\t"))
                rows[parts[0]] = parts
    return rows


class TestGoldenParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rubric = load_all(support.REGISTRY)
        cls.golden = read_golden()

    def test_golden_snapshot_has_374_rows(self):
        self.assertEqual(len(self.golden), 374)

    def test_no_rule_is_missing_or_added(self):
        actual = {r.id for r in self.rubric.rules}
        self.assertEqual(sorted(actual - set(self.golden)), [],
                         "rules present in packs but not in the snapshot")
        self.assertEqual(sorted(set(self.golden) - actual), [],
                         "rules present in the snapshot but not in packs")

    def test_every_column_of_every_row_matches(self):
        for row in self.rubric.materialize():
            with self.subTest(rule=row[0]):
                self.assertEqual(row, self.golden[row[0]])

    def test_no_duplicate_ids(self):
        ids = [r.id for r in self.rubric.rules]
        self.assertEqual(len(ids), len(set(ids)))

    def test_surface_distribution_matches_the_measured_legacy_split(self):
        expected = {
            "process": 105, "ux_a11y": 71, "security_privacy": 46,
            "frontend": 27, "risk": 23, "data_layer": 23, "i18n_rtl": 22,
            "typescript": 21, "edge_function": 20, "rls": 16,
        }
        actual = {s: len(self.rubric.by_surface(s))
                  for s in self.rubric.populated_surfaces()}
        self.assertEqual(actual, expected)

    def test_all_17_categories_are_declared_exactly_once(self):
        self.assertEqual(len(self.rubric.categories), 17)
        self.assertEqual(
            {c.pack for c in self.rubric.categories.values()}, {"base"},
            "categories are declared by base alone; see rulepacks/README.md",
        )

    def test_42_oracle_domain_overlays_plus_2_cross_cutting(self):
        by_kind = {"path": 0, "surface": 0}
        for overlay in self.rubric.overlays:
            if overlay.path_prefixes:
                by_kind["path"] += 1
            else:
                by_kind["surface"] += 1
        self.assertEqual(by_kind, {"path": 42, "surface": 2})

    def test_cross_cutting_overlays_can_actually_fire(self):
        """They were dead under contract v1.1; v1.2 gave them a trigger."""
        self.assertIn(
            "permissions",
            [o.id for o in self.rubric.overlays_for_surface("rls")],
        )
        self.assertIn(
            "portals",
            [o.id for o in self.rubric.overlays_for_surface("frontend")],
        )


class TestPackPartition(unittest.TestCase):
    """Invariants about where rules live, as distinct from what they resolve to."""

    @classmethod
    def setUpClass(cls):
        cls.rubric = load_all(support.REGISTRY)

    def test_pack_sizes(self):
        counts = {}
        for rule in self.rubric.rules:
            counts[rule.pack] = counts.get(rule.pack, 0) + 1
        self.assertEqual(counts, {
            "base": 93, "react-ts": 61, "supabase-rls": 51,
            "org-practice": 105, "medtrics-oracle": 64,
        })
        self.assertEqual(sum(counts.values()), 374)

    def test_supabase_rls_owns_every_rls_rule(self):
        packs = {r.pack for r in self.rubric.by_surface("rls")}
        self.assertEqual(packs, {"supabase-rls"})
        self.assertEqual(len(self.rubric.by_surface("rls")), 16)

    def test_org_practice_owns_every_process_rule(self):
        packs = {r.pack for r in self.rubric.by_surface("process")}
        self.assertEqual(packs, {"org-practice"})

    def test_org_practice_does_not_depend_on_the_oracle_pack(self):
        """
        The reason org-practice exists.

        If it required medtrics-oracle, a repo wanting process rules would be
        forced to install Oracle-specific content, and the Oracle pack would
        not be optional in any meaningful sense.
        """
        rubric = load(support.REGISTRY, ["org-practice"])
        self.assertNotIn("medtrics-oracle", rubric.pack_ids)
        self.assertEqual(len(rubric.by_surface("process")), 105)

    def test_oracle_pack_contributes_only_the_remainder(self):
        oracle = [r for r in self.rubric.rules if r.pack == "medtrics-oracle"]
        self.assertEqual(len(oracle), 64)
        self.assertEqual(
            [r.id for r in oracle if r.surface in ("rls", "process")], [])


class TestVerifyGoldenScript(unittest.TestCase):
    """The CI-facing entry point must agree with the in-process check."""

    def test_verify_golden_exits_zero(self):
        script = os.path.join(
            support.REPO_ROOT, "rulepacks", "tools", "verify_golden.py")
        proc = subprocess.run(
            [sys.executable, script, "--root", support.REGISTRY,
             "--snapshot", support.GOLDEN,
             "--breaks", os.path.join(support.CONTRACTS, "parity-breaks.tsv")],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PACK/GOLDEN OK", proc.stdout)


if __name__ == "__main__":
    unittest.main()
