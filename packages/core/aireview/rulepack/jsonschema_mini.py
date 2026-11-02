"""
A deliberately small JSON Schema validator, enough for the rulepack contract.

`packages/core` is stdlib-only, so `jsonschema` is not available. The honest
alternative to a dependency is not "skip validation" - a rulepack is read from
a PR checkout and is therefore attacker-controlled, so it has to be checked
before anything reads fields off it.

Rather than hand-coding the rulepack's shape (which would drift from the
contract the moment the contract changes), this interprets
`contracts/rulepack.schema.json` directly. It supports exactly the keywords
that contract uses:

    type, required, properties, additionalProperties (bool or schema),
    items, enum, pattern, $ref to #/$defs/*

Anything else in a schema is ignored rather than silently treated as passing -
`unsupported_keywords()` reports what was skipped so a future contract change
that needs more cannot go unnoticed.
"""
import json
import os
import re

SUPPORTED = {
    "$schema", "$id", "title", "description", "$defs",
    "type", "required", "properties", "additionalProperties",
    "items", "enum", "pattern", "$ref",
}

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "number": (int, float),
    "integer": int,
}


class SchemaError(Exception):
    """The instance does not conform to the schema."""


def load_schema(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def default_schema_path():
    """
    Locate `contracts/rulepack.schema.json`.

    Explicit override first, then a walk up from this module. Note this is a
    *developer convenience*, not a config surface: nothing here reads a path
    out of repository configuration.
    """
    env = os.environ.get("AIREVIEW_RULEPACK_SCHEMA")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    cur = here
    while True:
        cand = os.path.join(cur, "contracts", "rulepack.schema.json")
        if os.path.exists(cand):
            return cand
        parent = os.path.dirname(cur)
        if parent == cur:
            raise SchemaError(
                "cannot locate contracts/rulepack.schema.json; set "
                "AIREVIEW_RULEPACK_SCHEMA"
            )
        cur = parent


def unsupported_keywords(schema):
    """Every keyword in `schema` this validator does not implement."""
    found = set()

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k in ("properties", "$defs"):
                    for sub in v.values():
                        walk(sub)
                    continue
                if k == "additionalProperties" and isinstance(v, dict):
                    walk(v)
                    continue
                if k == "items":
                    walk(v)
                    continue
                if k not in SUPPORTED:
                    found.add(k)
        elif isinstance(node, list):
            for sub in node:
                walk(sub)

    walk(schema)
    return sorted(found)


def _resolve(schema, root):
    seen = 0
    while isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/"):
            raise SchemaError(f"unsupported $ref {ref!r}")
        node = root
        for part in ref[2:].split("/"):
            node = node[part]
        schema = node
        seen += 1
        if seen > 32:
            raise SchemaError(f"$ref cycle at {ref!r}")
    return schema


def validate(instance, schema, root=None, path="$"):
    """Validate `instance`; raise SchemaError on the first problem."""
    root = root if root is not None else schema
    schema = _resolve(schema, root)

    t = schema.get("type")
    if t is not None:
        expected = _TYPES[t]
        if t == "number" and isinstance(instance, bool):
            raise SchemaError(f"{path}: expected number, got boolean")
        if t == "integer" and isinstance(instance, bool):
            raise SchemaError(f"{path}: expected integer, got boolean")
        if not isinstance(instance, expected):
            got = type(instance).__name__
            raise SchemaError(f"{path}: expected {t}, got {got}")

    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaError(
            f"{path}: {instance!r} not one of {schema['enum']}"
        )

    if "pattern" in schema and isinstance(instance, str):
        if not re.search(schema["pattern"], instance):
            raise SchemaError(
                f"{path}: {instance!r} does not match {schema['pattern']!r}"
            )

    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                raise SchemaError(f"{path}: missing required property {key!r}")
        props = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in props:
                validate(value, props[key], root, f"{path}.{key}")
            elif extra is False:
                raise SchemaError(f"{path}: unexpected property {key!r}")
            elif isinstance(extra, dict):
                validate(value, extra, root, f"{path}.{key}")

    if isinstance(instance, list) and "items" in schema:
        for i, item in enumerate(instance):
            validate(item, schema["items"], root, f"{path}[{i}]")
