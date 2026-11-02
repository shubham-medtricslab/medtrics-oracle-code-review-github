"""
`loaded_pack_ids()` — the source of truth for `allowed_rulepack_ids`.

`validate_agent_output` rejects a finding that names a rulepack which was
never loaded, rather than relabelling it to a default. That makes this set
security-relevant in both directions:

  * over-report and a fabricated `rulepack_id` sails through
  * under-report and a perfectly legitimate finding is discarded

The second is the easier mistake. A repo that asks for `supabase-rls` also
gets `base` via `requires`; if the closure were omitted, every `base` finding
would look like a fabrication.
"""
import unittest

from ..loader import RulepackError, load
from . import support


class TestLoadedPackIds(unittest.TestCase):
    def test_it_is_a_frozenset_of_ids(self):
        ids = load(support.REGISTRY, ["base"]).loaded_pack_ids()
        self.assertIsInstance(ids, frozenset)
        self.assertEqual(ids, {"base"})

    def test_it_includes_the_requires_closure(self):
        ids = load(support.REGISTRY, ["supabase-rls"]).loaded_pack_ids()
        self.assertEqual(ids, {"base", "supabase-rls"})

    def test_it_includes_the_transitive_closure(self):
        ids = load(support.REGISTRY, ["medtrics-oracle"]).loaded_pack_ids()
        self.assertEqual(
            ids, {"base", "react-ts", "supabase-rls", "medtrics-oracle"})

    def test_it_never_reports_an_unrequested_pack(self):
        ids = load(support.REGISTRY, ["base", "react-ts"]).loaded_pack_ids()
        self.assertNotIn("medtrics-oracle", ids)
        self.assertNotIn("org-practice", ids)

    def test_every_rule_belongs_to_a_reported_pack(self):
        """The invariant that makes the set usable as a membership gate."""
        rubric = load(support.REGISTRY, support.SHIPPED_PACKS)
        ids = rubric.loaded_pack_ids()
        self.assertEqual({r.pack for r in rubric.rules} - ids, set())
        self.assertEqual({d.pack for d in rubric.detectors} - ids, set())

    def test_it_agrees_with_pack_ids(self):
        rubric = load(support.REGISTRY, ["medtrics-oracle"])
        self.assertEqual(rubric.loaded_pack_ids(), frozenset(rubric.pack_ids))


class TestFailureReporting(unittest.TestCase):
    """
    A broken pack must not erase what did load.

    "pack not requested" and "pack requested but broken" warrant different
    things said in a review body, so the error carries both the ids that
    resolved cleanly and the one that failed.
    """

    def test_a_broken_pack_still_reports_what_loaded(self):
        packs = {
            "good": support.minimal_pack(
                "good",
                categories={
                    "frontend-architecture": support.minimal_category()},
                rules=[support.minimal_rule()],
            ),
            "broken": support.minimal_pack(
                "broken", requires=["good"],
                rules=[support.minimal_rule(id="FA-002",
                                            enforcement="sort-of")],
            ),
        }
        with support.temp_registry(packs) as root:
            with self.assertRaises(RulepackError) as ctx:
                load(root, ["broken"])
        self.assertEqual(ctx.exception.failing_pack_id, "broken")
        self.assertEqual(ctx.exception.resolved_pack_ids, frozenset())

    def test_a_broken_dependency_reports_the_dependency_as_the_failure(self):
        packs = {
            "dep": support.minimal_pack(
                "dep", rules=[support.minimal_rule(enforcement="sort-of")]),
            "top": support.minimal_pack("top", requires=["dep"]),
        }
        with support.temp_registry(packs) as root:
            with self.assertRaises(RulepackError) as ctx:
                load(root, ["top"])
        self.assertEqual(ctx.exception.failing_pack_id, "dep")

    def test_a_missing_pack_names_itself(self):
        with support.temp_registry({}) as root:
            with self.assertRaises(RulepackError) as ctx:
                load(root, ["absent"])
        self.assertEqual(ctx.exception.failing_pack_id, "absent")
        self.assertEqual(ctx.exception.resolved_pack_ids, frozenset())

    def test_a_failure_after_resolution_reports_every_pack(self):
        """Duplicate ids surface only once both packs have been read."""
        packs = {
            "a": support.minimal_pack(
                "a",
                categories={
                    "frontend-architecture": support.minimal_category()},
                rules=[support.minimal_rule()],
            ),
            "b": support.minimal_pack(
                "b", requires=["a"], rules=[support.minimal_rule()]),
        }
        with support.temp_registry(packs) as root:
            with self.assertRaises(RulepackError) as ctx:
                load(root, ["b"])
        self.assertEqual(
            ctx.exception.resolved_pack_ids, frozenset({"a", "b"}))

    def test_a_cycle_reports_the_pack_it_closed_on(self):
        packs = {
            "a": support.minimal_pack("a", requires=["b"]),
            "b": support.minimal_pack("b", requires=["a"]),
        }
        with support.temp_registry(packs) as root:
            with self.assertRaises(RulepackError) as ctx:
                load(root, ["a"])
        self.assertEqual(ctx.exception.failing_pack_id, "a")

    def test_an_invalid_pack_id_reports_nothing_as_resolved(self):
        with self.assertRaises(RulepackError) as ctx:
            load(support.REGISTRY, ["../secrets"])
        self.assertEqual(ctx.exception.resolved_pack_ids, frozenset())


if __name__ == "__main__":
    unittest.main()
