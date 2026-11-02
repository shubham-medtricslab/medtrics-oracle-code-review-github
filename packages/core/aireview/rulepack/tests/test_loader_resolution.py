"""
Loader behaviour: the three layers, and everything it must refuse.

Most of these use synthetic registries rather than the shipped packs. The
shipped packs are correct, so they cannot exercise the rejection paths - and an
unexercised rejection path is indistinguishable from no rejection at all.
"""
import unittest

from ..loader import (
    DeadOverlayError,
    DependencyCycleError,
    DuplicateCategoryError,
    DuplicateDetectorKeyError,
    DuplicateRuleIdError,
    InvalidPackIdError,
    PackNotFoundError,
    RulepackError,
    UnknownCategoryError,
    UnknownPrincipleError,
    load,
    resolve_severity,
)
from ..model import Category, Rule
from . import support


def _cat(**over):
    base = dict(id="frontend-architecture", name="Frontend Architecture",
                prefix="FA", default_surface="frontend",
                default_severity="medium", default_diff_checkable="checkout",
                pack="base")
    base.update(over)
    return Category(**base)


def _rule(**over):
    base = dict(id="FA-001", category="frontend-architecture", title="t",
                enforcement="established", pack="base")
    base.update(over)
    return Rule(**base)


class TestThreeLayerResolution(unittest.TestCase):
    def test_category_default_applies_when_rule_is_silent(self):
        self.assertEqual(resolve_severity(_rule(), _cat()), "medium")

    def test_explicit_rule_severity_overrides_the_default(self):
        self.assertEqual(
            resolve_severity(_rule(severity="critical"), _cat()), "critical")

    def test_missing_enforcement_caps_at_low(self):
        self.assertEqual(
            resolve_severity(_rule(enforcement="missing"), _cat()), "low")

    def test_partial_enforcement_caps_at_low(self):
        self.assertEqual(
            resolve_severity(_rule(enforcement="partial"), _cat()), "low")

    def test_the_cap_beats_an_explicit_severity(self):
        """An advisory rule is advisory however loudly the pack declares it."""
        self.assertEqual(
            resolve_severity(
                _rule(severity="critical", enforcement="missing"), _cat()),
            "low",
        )

    def test_resolution_takes_no_floor_argument(self):
        """
        Severity floors are finding-time policy, not materialization.

        Pinned as a test because it is a tempting "fix": someone will see
        `suggested_severity_floors` in a pack, assume it belongs in resolution,
        and wire it in. DL-031 (`rls`, `medium`, established) is the row that
        would break, and `verify_golden.py` would catch it - but only if the
        signature keeps the floor out of reach in the first place.
        """
        import inspect
        params = list(inspect.signature(resolve_severity).parameters)
        self.assertEqual(params, ["rule", "category"])


class TestShippedResolution(unittest.TestCase):
    """Spot-checks against the real packs for each resolution layer."""

    @classmethod
    def setUpClass(cls):
        cls.rubric = load(support.REGISTRY, support.SHIPPED_PACKS)

    def test_dl_031_keeps_its_explicit_medium_on_the_rls_surface(self):
        rule = self.rubric.get("DL-031")
        self.assertEqual((rule.surface, rule.severity), ("rls", "medium"))

    def test_rls_floor_is_advertised_but_not_applied(self):
        self.assertEqual(
            self.rubric.suggested_severity_floors.get("rls"), "high")
        self.assertEqual(self.rubric.get("DL-031").severity, "medium")

    def test_surface_override_moves_a_rule_off_its_category_default(self):
        self.assertEqual(self.rubric.get("DL-005").surface, "security_privacy")
        self.assertEqual(self.rubric.get("SEC-006").surface, "edge_function")

    def test_advisory_rules_are_capped(self):
        for rid in ("TS-003", "SEC-005", "DOC-002", "PRIV-004", "EF-013"):
            with self.subTest(rule=rid):
                rule = self.rubric.get(rid)
                self.assertIn(rule.enforcement, ("missing", "partial"))
                self.assertEqual(rule.severity, "low")

    def test_diff_checkable_override(self):
        self.assertEqual(self.rubric.get("FA-009").diff_checkable, "yes")
        self.assertEqual(self.rubric.get("FA-025").diff_checkable, "process")

    def test_every_rule_carries_detect_guidance(self):
        missing = [r.id for r in self.rubric.rules if not r.detect]
        self.assertEqual(missing, [])


class TestRejections(unittest.TestCase):
    def test_duplicate_rule_id_across_packs(self):
        """
        The failure a count-based check cannot see.

        `len(rules) == 374` passes happily while one pack's FA-001 silently
        shadows another's. This is the check that replaces it.
        """
        packs = {
            "base": support.minimal_pack(
                "base",
                categories={"frontend-architecture": support.minimal_category()},
                rules=[support.minimal_rule()],
            ),
            "other": support.minimal_pack(
                "other", requires=["base"],
                rules=[support.minimal_rule(severity="critical")],
            ),
        }
        with support.temp_registry(packs) as root:
            with self.assertRaises(DuplicateRuleIdError) as ctx:
                load(root, ["base", "other"])
            self.assertIn("FA-001", str(ctx.exception))

    def test_duplicate_category_declaration(self):
        cat = {"frontend-architecture": support.minimal_category()}
        packs = {
            "base": support.minimal_pack("base", categories=cat),
            "other": support.minimal_pack("other", categories=cat),
        }
        with support.temp_registry(packs) as root:
            with self.assertRaises(DuplicateCategoryError):
                load(root, ["base", "other"])

    def test_requires_cycle(self):
        packs = {
            "a": support.minimal_pack("a", requires=["b"]),
            "b": support.minimal_pack("b", requires=["a"]),
        }
        with support.temp_registry(packs) as root:
            with self.assertRaises(DependencyCycleError):
                load(root, ["a"])

    def test_rule_in_an_undeclared_category(self):
        packs = {"a": support.minimal_pack("a", rules=[support.minimal_rule()])}
        with support.temp_registry(packs) as root:
            with self.assertRaises(UnknownCategoryError):
                load(root, ["a"])

    def test_rule_id_prefix_must_match_its_category(self):
        packs = {"a": support.minimal_pack(
            "a",
            categories={"frontend-architecture": support.minimal_category()},
            rules=[support.minimal_rule(id="TS-001")],
        )}
        with support.temp_registry(packs) as root:
            with self.assertRaises(RulepackError) as ctx:
                load(root, ["a"])
            self.assertIn("prefix", str(ctx.exception))

    def test_detector_emitting_an_unknown_principle(self):
        packs = {"a": support.minimal_pack(
            "a",
            categories={"frontend-architecture": support.minimal_category()},
            rules=[support.minimal_rule()],
            detectors=[{
                "key": "k", "emits_principle_id": "FA-999",
                "severity": "low", "pattern": "x", "message": "m",
            }],
        )}
        with support.temp_registry(packs) as root:
            with self.assertRaises(UnknownPrincipleError):
                load(root, ["a"])

    def test_duplicate_detector_key_across_packs(self):
        det = {"key": "k", "emits_principle_id": "FA-001",
               "severity": "low", "pattern": "x", "message": "m"}
        packs = {
            "base": support.minimal_pack(
                "base",
                categories={"frontend-architecture": support.minimal_category()},
                rules=[support.minimal_rule()],
                detectors=[det],
            ),
            "other": support.minimal_pack(
                "other", requires=["base"], detectors=[dict(det)]),
        }
        with support.temp_registry(packs) as root:
            with self.assertRaises(DuplicateDetectorKeyError):
                load(root, ["base", "other"])

    def test_two_detectors_may_emit_one_principle_at_different_severities(self):
        """
        The FA-009 shape must be allowed.

        The duplicate check belongs on rule ids, not on detector emissions.
        Two detectors finding two different problems that map to one principle
        is normal; conflating them is what the legacy `split("b")` did.
        """
        packs = {"a": support.minimal_pack(
            "a",
            categories={"frontend-architecture": support.minimal_category()},
            rules=[support.minimal_rule()],
            detectors=[
                {"key": "k1", "emits_principle_id": "FA-001",
                 "severity": "medium", "pattern": "x", "message": "m1"},
                {"key": "k2", "emits_principle_id": "FA-001",
                 "severity": "low", "pattern": "y", "message": "m2"},
            ],
        )}
        with support.temp_registry(packs) as root:
            rubric = load(root, ["a"])
        self.assertEqual(len(rubric.detectors), 2)
        self.assertEqual(
            {d.severity for d in rubric.detectors}, {"medium", "low"})

    def test_overlay_with_no_activation_is_rejected(self):
        packs = {"a": support.minimal_pack(
            "a", overlays={"ghost": {"guidance": "never fires"}})}
        with support.temp_registry(packs) as root:
            with self.assertRaises(DeadOverlayError) as ctx:
                load(root, ["a"])
            self.assertIn("ghost", str(ctx.exception))

    def test_pack_id_declared_inside_must_match_its_directory(self):
        packs = {"a": support.minimal_pack("b")}
        with support.temp_registry(packs) as root:
            with self.assertRaises(RulepackError):
                load(root, ["a"])

    def test_missing_pack(self):
        with support.temp_registry({}) as root:
            with self.assertRaises(PackNotFoundError):
                load(root, ["nope"])


class TestPackIdsAreNotPaths(unittest.TestCase):
    """
    Pack references must never be usable as a file-read primitive.

    Core's config layer already rejects anything path-shaped, which is only
    sound if the loader refuses path-shaped ids too - otherwise a pack id is
    just a path with extra steps.
    """

    def test_traversal_and_absolute_ids_are_refused(self):
        for bad in ("../secrets", "/etc/passwd", "a/b", "./a", "..",
                    "Base", "a b", "", "a\\b"):
            with self.subTest(pack_id=bad):
                with self.assertRaises(InvalidPackIdError):
                    load(support.REGISTRY, [bad])

    def test_a_required_pack_id_is_checked_too(self):
        packs = {"a": support.minimal_pack("a", requires=["../x"])}
        with support.temp_registry(packs) as root:
            with self.assertRaises(InvalidPackIdError):
                load(root, ["a"])


if __name__ == "__main__":
    unittest.main()
