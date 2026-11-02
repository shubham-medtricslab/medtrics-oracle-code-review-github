#!/usr/bin/env python3
"""
Check the test fixtures against `contracts/run-record.schema.json`.

Without this, the renderer is tested against shapes someone here invented. A
fixture that drifts from the contract makes every test above it a test of the
wrong thing, and the drift is silent -- the tests keep passing.

`jsonschema` is not available (stdlib-only, and that rule exists precisely so
the job handling untrusted pull requests has nothing to install), so this
implements the slice of JSON Schema the contract actually uses: `type`,
`required`, `additionalProperties: false`, `enum`, `const`, `pattern`,
`minimum`, `properties`, `items`, and `additionalProperties` as a schema. That
is enough to catch the mistakes that matter -- a typo'd key, a severity outside
the enum, a field the contract forbids -- and `additionalProperties: false` is
the one doing most of the work.
"""
import json
import os
import re
import unittest

ROOT = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
)
SCHEMA_PATH = os.path.join(ROOT, "contracts", "run-record.schema.json")
FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def _type_ok(value, expected) -> bool:
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        py = _TYPES.get(name)
        if py is None:
            continue
        if name == "integer" and isinstance(value, bool):
            continue  # bool is an int in Python; JSON Schema disagrees
        if name in ("number", "integer") and isinstance(value, bool):
            continue
        if isinstance(value, py):
            return True
    return False


def validate(instance, schema, path="$", errors=None):
    errors = [] if errors is None else errors

    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected const {schema['const']!r}, got {instance!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: {instance!r} not in enum {schema['enum']}")
    if "type" in schema and not _type_ok(instance, schema["type"]):
        errors.append(f"{path}: expected type {schema['type']}, got {type(instance).__name__}")
        return errors
    if "pattern" in schema and isinstance(instance, str):
        if not re.search(schema["pattern"], instance):
            errors.append(f"{path}: {instance!r} does not match /{schema['pattern']}/")
    if "minimum" in schema and isinstance(instance, (int, float)):
        if instance < schema["minimum"]:
            errors.append(f"{path}: {instance} < minimum {schema['minimum']}")

    if isinstance(instance, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{path}: missing required key {key!r}")
        extra_schema = schema.get("additionalProperties")
        for key, value in instance.items():
            if key in properties:
                validate(value, properties[key], f"{path}.{key}", errors)
            elif extra_schema is False:
                errors.append(f"{path}: key {key!r} is not permitted by the contract")
            elif isinstance(extra_schema, dict):
                validate(value, extra_schema, f"{path}.{key}", errors)

    if isinstance(instance, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(instance):
            validate(item, schema["items"], f"{path}[{index}]", errors)

    return errors


class FixtureContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            cls.schema = json.load(fh)

    def _check(self, name):
        with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
            record = json.load(fh)
        errors = validate(record, self.schema, f"<{name}>")
        self.assertEqual(errors, [], "\n  " + "\n  ".join(errors))
        return record

    def test_complete_fixture_conforms(self):
        self._check("run-record.complete.json")

    def test_incomplete_fixture_conforms(self):
        self._check("run-record.incomplete.json")

    def test_no_fixture_claims_an_approve_verdict(self):
        # There is deliberately no `approve` member: a GitHub App's approval
        # counts toward required_approving_review_count.
        verdicts = self.schema["properties"]["verdict"]["enum"]
        self.assertNotIn("approve", verdicts)
        for name in ("run-record.complete.json", "run-record.incomplete.json"):
            with open(os.path.join(FIXTURES, name), encoding="utf-8") as fh:
                self.assertIn(json.load(fh)["verdict"], verdicts)

    def test_the_validator_actually_rejects_things(self):
        # A validator that cannot fail is decoration.
        record = self._check("run-record.complete.json")

        bad_enum = json.loads(json.dumps(record))
        bad_enum["findings"][0]["severity"] = "catastrophic"
        self.assertTrue(validate(bad_enum, self.schema))

        extra_key = json.loads(json.dumps(record))
        extra_key["findings"][0]["detector_key"] = "dl-009-select-star"
        self.assertTrue(
            validate(extra_key, self.schema),
            "findings are additionalProperties: false, so an unknown key must fail",
        )

        missing = json.loads(json.dumps(record))
        del missing["head_sha"]
        self.assertTrue(validate(missing, self.schema))

        bad_sha = json.loads(json.dumps(record))
        bad_sha["head_sha"] = "not-a-sha"
        self.assertTrue(validate(bad_sha, self.schema))

    def test_fixture_rule_ids_match_the_golden_rubric(self):
        # The fixtures carry real principle ids, so the renderer is exercised
        # against the severities and surfaces that will actually show up.
        golden = {}
        with open(os.path.join(ROOT, "contracts", "golden-rubric.tsv"), encoding="utf-8") as fh:
            next(fh)
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 5:
                    golden[parts[0]] = {"surface": parts[2], "severity": parts[3],
                                        "enforcement": parts[4]}

        with open(os.path.join(FIXTURES, "run-record.complete.json"), encoding="utf-8") as fh:
            record = json.load(fh)

        for finding in record["findings"]:
            pid = finding["principle_id"]
            self.assertIn(pid, golden, f"{pid} is not a real rule")
            self.assertEqual(finding["severity"], golden[pid]["severity"], pid)
            self.assertEqual(finding["surface"], golden[pid]["surface"], pid)
            self.assertEqual(finding["enforcement"], golden[pid]["enforcement"], pid)

    def test_fixture_rulepack_ids_are_real_packs(self):
        packs_dir = os.path.join(ROOT, "rulepacks")
        if not os.path.isdir(packs_dir):
            self.skipTest("rulepacks/ not present")
        known = {
            name
            for name in os.listdir(packs_dir)
            if os.path.exists(os.path.join(packs_dir, name, "rulepack.json"))
        }
        with open(os.path.join(FIXTURES, "run-record.complete.json"), encoding="utf-8") as fh:
            record = json.load(fh)
        for finding in record["findings"]:
            self.assertIn(finding["rulepack_id"], known)


if __name__ == "__main__":
    unittest.main()
