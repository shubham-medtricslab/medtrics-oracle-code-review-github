"""
The two primitives everything else rests on: schema validation and globbing.

If the mini validator silently passes a malformed pack, every downstream
guarantee is void - a rulepack is read from an attacker-controlled checkout.
If the glob matcher treats `*` as crossing `/`, `exclude_globs` stops being a
precise instrument and FA-010 quietly regresses.
"""
import unittest

from .. import globs, jsonschema_mini
from ..jsonschema_mini import SchemaError, validate
from . import support


class TestContractCoverage(unittest.TestCase):
    """The validator must actually implement what the contract uses."""

    def setUp(self):
        self.schema = jsonschema_mini.load_schema(support.SCHEMA)

    def test_contract_uses_no_unsupported_keywords(self):
        unsupported = jsonschema_mini.unsupported_keywords(self.schema)
        self.assertEqual(
            unsupported, [],
            "contracts/rulepack.schema.json uses JSON Schema keywords this "
            "validator ignores, so packs would pass checks that were never "
            f"run: {unsupported}",
        )

    def test_every_shipped_pack_validates(self):
        from ..loader import read_pack
        for pack_id in support.SHIPPED_PACKS:
            with self.subTest(pack=pack_id):
                read_pack(support.REGISTRY, pack_id, self.schema)


class TestValidator(unittest.TestCase):
    def setUp(self):
        self.schema = jsonschema_mini.load_schema(support.SCHEMA)

    def _bad(self, pack, fragment):
        with self.assertRaises(SchemaError) as ctx:
            validate(pack, self.schema)
        self.assertIn(fragment, str(ctx.exception))

    def test_missing_required_property(self):
        self._bad({"id": "x", "version": "1.0.0"}, "missing required")

    def test_unexpected_top_level_property(self):
        pack = support.minimal_pack("x")
        pack["exec"] = "rm -rf /"
        self._bad(pack, "unexpected property 'exec'")

    def test_bad_pack_id_pattern(self):
        self._bad(support.minimal_pack("Not-An-Id"), "does not match")

    def test_bad_version_pattern(self):
        self._bad(support.minimal_pack("x", version="1.0"), "does not match")

    def test_rule_id_must_be_three_digits(self):
        pack = support.minimal_pack(
            "x", rules=[support.minimal_rule(id="FA-1")])
        self._bad(pack, "does not match")

    def test_enforcement_enum(self):
        pack = support.minimal_pack(
            "x", rules=[support.minimal_rule(enforcement="sort-of")])
        self._bad(pack, "not one of")

    def test_severity_enum_via_ref(self):
        pack = support.minimal_pack(
            "x", rules=[support.minimal_rule(severity="catastrophic")])
        self._bad(pack, "not one of")

    def test_surface_enum_via_ref(self):
        pack = support.minimal_pack(
            "x", rules=[support.minimal_rule(surface="backend")])
        self._bad(pack, "not one of")

    def test_detector_emitted_id_rejects_the_legacy_fa_009b_form(self):
        """
        `FA-009b` must be unrepresentable as an emitted id.

        This is the contract-level half of the fix: the schema pattern makes
        the old `rid.split("b")[0]` derivation impossible to re-express, so a
        future detector cannot quietly reintroduce the collision by naming
        itself after a principle that does not exist.
        """
        pack = support.minimal_pack("x", detectors=[{
            "key": "fa-009b",
            "emits_principle_id": "FA-009b",
            "severity": "low",
            "pattern": "x",
            "message": "m",
        }])
        self._bad(pack, "does not match")

    def test_wrong_type(self):
        pack = support.minimal_pack("x", rules={})
        self._bad(pack, "expected array")

    def test_valid_minimal_pack_passes(self):
        validate(support.minimal_pack("x"), self.schema)

    def test_ref_cycle_is_rejected(self):
        schema = {"$ref": "#/$defs/a", "$defs": {"a": {"$ref": "#/$defs/a"}}}
        with self.assertRaises(SchemaError):
            validate({}, schema)


class TestGlobs(unittest.TestCase):
    def test_doublestar_slash_matches_zero_segments(self):
        self.assertTrue(globs.match("a.ts", "**/*.ts"))
        self.assertTrue(globs.match("src/a.ts", "**/*.ts"))
        self.assertTrue(globs.match("src/x/y/a.ts", "**/*.ts"))

    def test_single_star_does_not_cross_a_slash(self):
        self.assertTrue(globs.match("src/a.ts", "src/*.ts"))
        self.assertFalse(globs.match("src/x/a.ts", "src/*.ts"))

    def test_extension_is_not_matched_loosely(self):
        self.assertFalse(globs.match("a.tsx", "**/*.ts"))
        self.assertFalse(globs.match("a.ts.bak", "**/*.ts"))

    def test_services_glob_matches_the_legacy_predicate_cases(self):
        pattern = "**/services/**/*.ts"
        self.assertTrue(
            globs.match("src/domains/forms/services/x.service.ts", pattern))
        self.assertTrue(globs.match("services/x.ts", pattern))
        self.assertFalse(globs.match("src/domains/forms/x.service.ts", pattern))

    def test_paths_are_normalised(self):
        self.assertTrue(globs.match("./src/a.ts", "**/*.ts"))
        self.assertTrue(globs.match("/src/a.ts", "src/*.ts"))

    def test_exclude_wins_over_include(self):
        self.assertFalse(globs.path_selected(
            "src/x.service.ts", ["**/*.ts"], ["**/*.service.ts"]))
        self.assertTrue(globs.path_selected(
            "src/x.ts", ["**/*.ts"], ["**/*.service.ts"]))

    def test_absent_includes_mean_every_path(self):
        self.assertTrue(globs.path_selected("anything.md", (), ()))

    def test_question_mark_does_not_cross_a_slash(self):
        self.assertTrue(globs.match("ab", "a?"))
        self.assertFalse(globs.match("a/b", "a?b"))

    def test_character_class(self):
        self.assertTrue(globs.match("a1.sql", "a[0-9].sql"))
        self.assertFalse(globs.match("ax.sql", "a[0-9].sql"))

    def test_dot_is_literal_not_a_regex_wildcard(self):
        self.assertFalse(globs.match("axts", "*.ts"))


if __name__ == "__main__":
    unittest.main()
