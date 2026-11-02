"""
Declarative rulepacks: the 374-rule catalog as data, plus the loader.

v0.5.0 hardcoded the catalog in `skills/principle-rubric/scripts/catalog_data.py`
and its detectors in `skills/detectors/scripts/detectors.py`, which tied the
rubric to one company's stack. Here the rules are JSON conforming to
`contracts/rulepack.schema.json` and live in a registry of packs:

    base            stack-neutral rules; declares the shared category table
    react-ts        React / TypeScript / browser frontend
    supabase-rls    Supabase, SQL, RLS - owns all 16 `rls`-surface rules
    org-practice    the 105 `process`-surface rules, independent of Oracle
    medtrics-oracle Oracle specifics plus the 42 domain overlays

The three resolution layers - category defaults, per-rule overrides and the
missing/partial enforcement cap - stay here in core. Packs only contribute data
into them, and every rule id lives in one global namespace.

Typical use:

    from aireview.rulepack import load
    rubric = load("rulepacks", ["base", "react-ts"])
    for surface in rubric.populated_surfaces():
        dispatch(surface, rubric.by_surface(surface))
"""
from .detect import run as run_detectors
from .loader import (
    DependencyCycleError,
    DuplicateCategoryError,
    DuplicateDetectorKeyError,
    DuplicateRuleIdError,
    EmptySurfaceError,
    InvalidPackIdError,
    PackNotFoundError,
    Rubric,
    RulepackError,
    UnknownCategoryError,
    UnknownPrincipleError,
    discover,
    load,
    load_all,
    read_pack,
    resolve_severity,
)
from .model import (
    DIFF_CHECKABLE,
    SEVERITIES,
    SURFACES,
    Category,
    Detector,
    Overlay,
    Pack,
    ResolvedRule,
    Rule,
)

__all__ = [
    "Category", "Detector", "Overlay", "Pack", "ResolvedRule", "Rule",
    "Rubric", "SEVERITIES", "SURFACES", "DIFF_CHECKABLE",
    "RulepackError", "PackNotFoundError", "InvalidPackIdError",
    "DuplicateRuleIdError", "DuplicateCategoryError",
    "DuplicateDetectorKeyError", "UnknownCategoryError",
    "UnknownPrincipleError", "DependencyCycleError", "EmptySurfaceError",
    "discover", "load", "load_all", "read_pack", "resolve_severity",
    "run_detectors",
]
