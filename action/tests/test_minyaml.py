#!/usr/bin/env python3
"""
Tests for the restricted YAML subset.

Two things are being checked here, and only the first is about correctness.
The second is that the parser *refuses* rather than guesses: a construct
outside the subset must raise, because silently mis-parsing a policy file is
worse than failing to parse it.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import minyaml  # noqa: E402


class ScalarTest(unittest.TestCase):
    def test_types(self):
        self.assertEqual(minyaml.parse("a: 1"), {"a": 1})
        self.assertEqual(minyaml.parse("a: 1.5"), {"a": 1.5})
        self.assertEqual(minyaml.parse("a: true"), {"a": True})
        self.assertEqual(minyaml.parse("a: False"), {"a": False})
        self.assertEqual(minyaml.parse("a: yes"), {"a": True})
        self.assertEqual(minyaml.parse("a: off"), {"a": False})
        self.assertEqual(minyaml.parse("a: null"), {"a": None})
        self.assertEqual(minyaml.parse("a: ~"), {"a": None})
        self.assertEqual(minyaml.parse("a:"), {"a": None})
        self.assertEqual(minyaml.parse("a: plain text"), {"a": "plain text"})

    def test_quoted_strings_stay_strings(self):
        self.assertEqual(minyaml.parse('a: "true"'), {"a": "true"})
        self.assertEqual(minyaml.parse("a: '42'"), {"a": "42"})

    def test_quoting_protects_special_characters(self):
        self.assertEqual(minyaml.parse('a: "x # y"'), {"a": "x # y"})
        self.assertEqual(minyaml.parse("a: 'it''s'"), {"a": "it's"})

    def test_comments(self):
        self.assertEqual(minyaml.parse("# lead\na: 1  # trailing\n"), {"a": 1})

    def test_hash_inside_a_word_is_not_a_comment(self):
        self.assertEqual(minyaml.parse("a: http://x#y"), {"a": "http://x#y"})

    def test_infinities_and_nan_are_plain_strings(self):
        self.assertEqual(minyaml.parse("a: .inf"), {"a": ".inf"})
        self.assertEqual(minyaml.parse("a: nan"), {"a": "nan"})


class StructureTest(unittest.TestCase):
    def test_block_sequence(self):
        self.assertEqual(
            minyaml.parse("rulepacks:\n  - core\n  - security\n"),
            {"rulepacks": ["core", "security"]},
        )

    def test_flow_sequence(self):
        self.assertEqual(
            minyaml.parse("rulepacks: [core, security]"),
            {"rulepacks": ["core", "security"]},
        )
        self.assertEqual(minyaml.parse("rulepacks: []"), {"rulepacks": []})

    def test_nested_mapping(self):
        self.assertEqual(
            minyaml.parse("surfaces:\n  security:\n    enabled: true\n"),
            {"surfaces": {"security": {"enabled": True}}},
        )

    def test_mapping_inside_a_sequence(self):
        self.assertEqual(
            minyaml.parse("packs:\n  - id: core\n    version: 2\n  - id: sec\n"),
            {"packs": [{"id": "core", "version": 2}, {"id": "sec"}]},
        )

    def test_realistic_config(self):
        text = (
            "# review policy\n"
            "severity_floor: high\n"
            "max_changed_files: 250\n"
            "rulepacks:\n"
            "  - core\n"
            "  - security\n"
            'exclude_globs: ["**/*.snap", "dist/**"]\n'
        )
        self.assertEqual(
            minyaml.parse(text),
            {
                "severity_floor": "high",
                "max_changed_files": 250,
                "rulepacks": ["core", "security"],
                "exclude_globs": ["**/*.snap", "dist/**"],
            },
        )

    def test_empty_document(self):
        self.assertEqual(minyaml.parse(""), {})
        self.assertEqual(minyaml.parse("# only a comment\n"), {})

    def test_crlf_is_handled(self):
        self.assertEqual(minyaml.parse("a: 1\r\nb: 2\r\n"), {"a": 1, "b": 2})

    def test_leading_document_marker_is_allowed(self):
        self.assertEqual(minyaml.parse("---\na: 1\n"), {"a": 1})


class RefusalTest(unittest.TestCase):
    """Everything outside the subset must raise, not guess."""

    def assertRefused(self, text, because):
        with self.assertRaises(minyaml.YamlError, msg=f"should refuse: {because}"):
            minyaml.parse(text)

    def test_duplicate_keys_are_an_error(self):
        # "Last one silently wins" is how an override gets smuggled past a
        # reviewer skimming the diff of a policy file.
        self.assertRefused("a: 1\na: 2\n", "duplicate key")

    def test_anchors_and_aliases_are_refused(self):
        self.assertRefused("a: &anchor 1\nb: *anchor\n", "anchor")

    def test_merge_keys_are_refused(self):
        self.assertRefused("a:\n  <<: b\n", "merge key")

    def test_tags_are_refused(self):
        self.assertRefused("a: !!python/object:os.system\n", "tag")

    def test_block_scalars_are_refused(self):
        self.assertRefused("a: |\n  text\n", "block scalar")
        self.assertRefused("a: >\n  text\n", "folded scalar")

    def test_flow_mappings_are_refused(self):
        self.assertRefused("a: {b: 1}", "flow mapping")

    def test_tab_indentation_is_refused(self):
        self.assertRefused("a:\n\tb: 1\n", "tab indentation")

    def test_multi_document_is_refused(self):
        self.assertRefused("a: 1\n---\nb: 2\n", "multi-document")

    def test_unterminated_quote_is_refused(self):
        self.assertRefused('a: "unterminated\n', "unterminated quote")

    def test_oversized_input_is_refused(self):
        # A YAML bomb must die here rather than reach core.
        self.assertRefused("a: " + ("x" * (minyaml.MAX_BYTES + 1)), "size cap")

    def test_too_many_lines_is_refused(self):
        self.assertRefused(
            "\n".join(f"k{i}: {i}" for i in range(minyaml.MAX_LINES + 1)), "line cap"
        )

    def test_overlong_line_is_refused(self):
        self.assertRefused("a: " + ("x" * (minyaml.MAX_LINE_CHARS + 1)), "line length")

    def test_bare_text_is_refused(self):
        self.assertRefused("just some prose\n", "not a mapping")

    def test_errors_carry_a_line_number(self):
        try:
            minyaml.parse("a: 1\nb: 2\nb: 3\n")
        except minyaml.YamlError as exc:
            self.assertEqual(exc.line_no, 3)
            self.assertIn("line 3", str(exc))
        else:  # pragma: no cover
            self.fail("expected YamlError")


if __name__ == "__main__":
    unittest.main()
