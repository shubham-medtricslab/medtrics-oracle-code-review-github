"""
Shared helpers: locating the repo, and building throwaway registries.

Several loader behaviours - duplicate ids across packs, requires cycles, a
category declared twice - cannot be provoked using the five shipped packs,
because the shipped packs are correct. `temp_registry` builds a minimal
registry on disk so those paths get exercised rather than assumed.
"""
import json
import os
import tempfile

REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "..", "..", "..", "..", "..")
)
REGISTRY = os.path.join(REPO_ROOT, "rulepacks")
CONTRACTS = os.path.join(REPO_ROOT, "contracts")
GOLDEN = os.path.join(CONTRACTS, "golden-rubric.tsv")
SCHEMA = os.path.join(CONTRACTS, "rulepack.schema.json")
LEGACY = os.path.abspath(
    os.path.join(REPO_ROOT, "..", "medtrics-oracle-code-review")
)

SHIPPED_PACKS = ("base", "react-ts", "supabase-rls", "org-practice",
                 "medtrics-oracle")


def minimal_category(**over):
    cat = {
        "name": "Frontend Architecture",
        "prefix": "FA",
        "default_surface": "frontend",
        "default_severity": "medium",
        "default_diff_checkable": "checkout",
    }
    cat.update(over)
    return cat


def minimal_rule(**over):
    rule = {
        "id": "FA-001",
        "category": "frontend-architecture",
        "title": "A rule",
        "enforcement": "established",
    }
    rule.update(over)
    return rule


def minimal_pack(pack_id, **over):
    pack = {"id": pack_id, "version": "1.0.0", "rules": []}
    pack.update(over)
    return pack


class temp_registry:
    """Context manager writing `{pack_id: pack_dict}` to a temp registry."""

    def __init__(self, packs):
        self.packs = packs
        self._tmp = None

    def __enter__(self):
        self._tmp = tempfile.TemporaryDirectory()
        for pack_id, pack in self.packs.items():
            d = os.path.join(self._tmp.name, pack_id)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "rulepack.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(pack, fh)
        return self._tmp.name

    def __exit__(self, *exc):
        self._tmp.cleanup()
        return False
