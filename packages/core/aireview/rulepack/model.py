"""
Immutable value types for rulepacks and the rubric they resolve to.

Everything here is frozen on purpose. The resolved rubric is handed to the
reviewer dispatch and to prompt construction; if a caller could mutate a rule's
severity after resolution, the three-layer resolution would stop being the
single place severity is decided, which is exactly the property the golden
snapshot exists to protect.
"""
from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Kept in sync with contracts/rulepack.schema.json `$defs.surface`; the loader
# asserts the two agree rather than trusting this copy.
SURFACES = (
    "frontend", "typescript", "data_layer", "rls", "edge_function",
    "security_privacy", "ux_a11y", "i18n_rtl", "risk", "process",
)

DIFF_CHECKABLE = ("yes", "checkout", "repo", "process")

#: Column order of contracts/golden-rubric.tsv. Duplicated from
#: tools/golden_snapshot.py on purpose: the snapshot tool reads the *legacy*
#: module, this reads the packs, and the parity check is only meaningful if
#: both agree on the shape of a row.
COLUMNS = ("id", "category", "surface", "severity", "enforcement",
           "diff_checkable")

#: Enforcement levels that cap severity at `low`. MISSING/PARTIAL rules
#: describe practice the codebase has not adopted, so they are advisory and
#: must never drive a blocking verdict on their own.
ADVISORY_ENFORCEMENT = ("missing", "partial")


def max_severity(a, b):
    return a if SEVERITY_RANK[a] >= SEVERITY_RANK[b] else b


@dataclass(frozen=True)
class Category:
    id: str
    name: str
    prefix: str
    default_surface: str
    default_severity: str
    default_diff_checkable: str
    pack: str


@dataclass(frozen=True)
class Rule:
    """A rule as declared by a pack, before resolution."""
    id: str
    category: str
    title: str
    enforcement: str
    pack: str
    severity: str = None
    surface: str = None
    diff_checkable: str = None
    detect: str = None


@dataclass(frozen=True)
class ResolvedRule:
    """A rule after category default -> override -> floor -> enforcement cap."""
    id: str
    category: str
    category_name: str
    title: str
    enforcement: str
    severity: str
    surface: str
    diff_checkable: str
    detect: str
    pack: str

    def as_row(self):
        """The golden-snapshot column order."""
        return (self.id, self.category, self.surface, self.severity,
                self.enforcement, self.diff_checkable)


@dataclass(frozen=True)
class Detector:
    key: str
    emits_principle_id: str
    severity: str
    pattern: str
    message: str
    pack: str
    flags: tuple = ()
    include_globs: tuple = ()
    exclude_globs: tuple = ()


@dataclass(frozen=True)
class Overlay:
    id: str
    guidance: str
    pack: str
    path_prefixes: tuple = ()
    activate_on_surfaces: tuple = ()


@dataclass(frozen=True)
class Pack:
    id: str
    version: str
    description: str
    path: str
    requires: tuple = ()
    categories: tuple = ()
    rules: tuple = ()
    detectors: tuple = ()
    overlays: tuple = ()
    surface_path_globs: dict = field(default_factory=dict)
    #: Advisory only. Seeds org config; never read during materialization.
    suggested_severity_floors: dict = field(default_factory=dict)
