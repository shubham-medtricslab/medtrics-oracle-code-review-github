"""
Partial pack sets must load, and must make their gaps obvious.

The whole point of splitting the catalog is that a repo takes only the packs
that match its stack. Two things have to hold for that to be safe:

  * a subset loads cleanly - no dangling category references, no detector
    pointing at a rule that was left behind
  * a surface with no rules is *visibly* empty, so the orchestrator refuses to
    dispatch a reviewer for it

The second matters more than it looks. An LLM handed an empty rubric does not
return "nothing to check"; it returns a fluent, confident review of nothing,
which costs a model call and reads exactly like a real one.
"""
import unittest

from ..loader import EmptySurfaceError, load
from . import support


class TestBasePlusReactTs(unittest.TestCase):
    """The canonical non-Supabase, non-Oracle repo."""

    @classmethod
    def setUpClass(cls):
        cls.rubric = load(support.REGISTRY, ["base", "react-ts"])

    def test_it_loads(self):
        self.assertEqual(sorted(self.rubric.pack_ids), ["base", "react-ts"])
        self.assertEqual(len(self.rubric.rules), 93 + 61)

    def test_it_produces_no_rls_surface(self):
        self.assertEqual(self.rubric.by_surface("rls"), ())
        self.assertIn("rls", self.rubric.empty_surfaces())

    def test_requesting_an_empty_surface_raises_rather_than_returning_nothing(self):
        with self.assertRaises(EmptySurfaceError) as ctx:
            self.rubric.require_surface("rls")
        message = str(ctx.exception)
        self.assertIn("rls", message)
        self.assertIn("refuse to dispatch", message)

    def test_the_other_supabase_and_process_surfaces_are_empty_too(self):
        self.assertEqual(
            set(self.rubric.empty_surfaces()),
            {"rls", "data_layer", "edge_function", "process"},
        )

    def test_populated_surfaces_are_exactly_the_dispatchable_ones(self):
        for surface in self.rubric.populated_surfaces():
            with self.subTest(surface=surface):
                self.assertTrue(self.rubric.require_surface(surface))

    def test_no_rls_severity_floor_is_suggested_without_the_supabase_pack(self):
        self.assertEqual(self.rubric.suggested_severity_floors, {})

    def test_every_detector_still_resolves_to_a_loaded_rule(self):
        ids = {r.id for r in self.rubric.rules}
        for det in self.rubric.detectors:
            with self.subTest(detector=det.key):
                self.assertIn(det.emits_principle_id, ids)

    def test_the_oracle_detectors_are_absent(self):
        keys = {d.key for d in self.rubric.detectors}
        self.assertNotIn("fa-010-supabase-client-outside-service", keys)
        self.assertNotIn("fa-009-banned-root-import", keys)

    def test_no_overlays_without_the_oracle_pack(self):
        self.assertEqual(self.rubric.overlays, ())


class TestOtherSubsets(unittest.TestCase):
    def test_base_alone_loads_and_leaves_six_surfaces_empty(self):
        rubric = load(support.REGISTRY, ["base"])
        self.assertEqual(len(rubric.rules), 93)
        self.assertEqual(
            set(rubric.empty_surfaces()),
            {"frontend", "typescript", "data_layer", "rls", "edge_function",
             "process"},
        )

    def test_base_plus_supabase_has_rls_but_no_frontend(self):
        rubric = load(support.REGISTRY, ["supabase-rls"])
        self.assertEqual(sorted(rubric.pack_ids), ["base", "supabase-rls"])
        self.assertEqual(len(rubric.by_surface("rls")), 16)
        self.assertIn("frontend", rubric.empty_surfaces())
        self.assertEqual(rubric.suggested_severity_floors, {"rls": "high"})

    def test_requires_are_pulled_in_transitively_and_ordered_first(self):
        rubric = load(support.REGISTRY, ["medtrics-oracle"])
        self.assertEqual(
            list(rubric.pack_ids),
            ["base", "react-ts", "supabase-rls", "medtrics-oracle"],
        )
        self.assertEqual(len(rubric.rules), 374 - 105)
        self.assertIn("process", rubric.empty_surfaces())

    def test_requesting_a_pack_twice_is_idempotent(self):
        a = load(support.REGISTRY, ["base", "react-ts"])
        b = load(support.REGISTRY, ["base", "react-ts", "base"])
        self.assertEqual(a.materialize(), b.materialize())

    def test_every_subset_resolves_at_least_one_surface(self):
        for pack in support.SHIPPED_PACKS:
            with self.subTest(pack=pack):
                rubric = load(support.REGISTRY, [pack])
                self.assertTrue(rubric.populated_surfaces())


class TestSurfaceRouting(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rubric = load(support.REGISTRY, support.SHIPPED_PACKS)

    def test_a_sql_migration_routes_to_rls_and_data_layer(self):
        surfaces = self.rubric.surfaces_for_path(
            "supabase/migrations/domains/19_groups/05_rls_policies.sql")
        self.assertIn("rls", surfaces)
        self.assertIn("data_layer", surfaces)

    def test_a_component_does_not_route_to_rls(self):
        surfaces = self.rubric.surfaces_for_path(
            "src/components/organisms/groups/GroupFormDialog.tsx")
        self.assertNotIn("rls", surfaces)
        self.assertIn("frontend", surfaces)

    def test_domain_overlay_resolution(self):
        overlays = self.rubric.overlays_for_path(
            "src/domains/curriculum/services/group-enhanced.service.ts")
        self.assertEqual([o.id for o in overlays], ["curriculum"])

    def test_migration_domain_overlay_uses_the_underscored_form(self):
        overlays = self.rubric.overlays_for_path(
            "supabase/migrations/domains/04_curriculum/02_tables.sql")
        self.assertIn("curriculum", [o.id for o in overlays])

    def test_a_path_in_no_domain_resolves_to_no_overlay(self):
        self.assertEqual(
            self.rubric.overlays_for_path("src/lib/utils.ts"), ())


if __name__ == "__main__":
    unittest.main()
