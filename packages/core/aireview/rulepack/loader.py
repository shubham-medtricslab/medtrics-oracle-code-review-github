"""
Load rulepacks by ID and resolve them into a single rubric.

Why this is not just `json.load`:

* **Packs are addressed by ID, never by path.** Config is attacker-controlled,
  so a pack reference that could carry `../` or an absolute path would be a
  file-read primitive. `load()` takes a registry root supplied by core and a
  list of IDs matching `^[a-z0-9][a-z0-9-]*$`; anything else is refused before
  it touches the filesystem.

* **Duplicate principle IDs across packs are a hard error.** v0.5.0's parity
  check was `len(rules) == 374`, which cannot see two packs both defining
  FA-009 - one silently wins and the other's severity vanishes. Counting is not
  checking.

* **Resolution happens in exactly one place**, and it is exactly three layers:
  category default -> explicit per-rule severity -> enforcement cap. Surface
  severity floors are deliberately *not* among them; see `resolve_severity`.

* **An empty surface is a first-class result, not an empty list.** Dispatching
  a reviewer with no rules spends a model call to produce a confident-looking
  review of nothing. `empty_surfaces()` and `require_surface()` make the
  orchestrator say no instead.
"""
import json
import os
import re

from . import jsonschema_mini
from .model import (
    ADVISORY_ENFORCEMENT,
    SURFACES,
    Category,
    Detector,
    Overlay,
    Pack,
    ResolvedRule,
    Rule,
    max_severity,
)

PACK_FILENAME = "rulepack.json"
PACK_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class RulepackError(Exception):
    """
    Base class for every rulepack load/resolution failure.

    Carries `resolved_pack_ids` - the packs that loaded cleanly before the
    failure - and `failing_pack_id`. Callers need both to distinguish "that
    pack was never requested" from "that pack was requested and is broken",
    which warrant very different things said in a review body.
    """

    def __init__(self, *args, resolved_pack_ids=(), failing_pack_id=None):
        super().__init__(*args)
        self.resolved_pack_ids = frozenset(resolved_pack_ids)
        self.failing_pack_id = failing_pack_id


class PackNotFoundError(RulepackError):
    pass


class InvalidPackIdError(RulepackError):
    pass


class DuplicateRuleIdError(RulepackError):
    pass


class DuplicateCategoryError(RulepackError):
    pass


class UnknownCategoryError(RulepackError):
    pass


class UnknownPrincipleError(RulepackError):
    pass


class DuplicateDetectorKeyError(RulepackError):
    pass


class DependencyCycleError(RulepackError):
    pass


class EmptySurfaceError(RulepackError):
    """A reviewer surface was requested but resolved to zero rules."""


class DeadOverlayError(RulepackError):
    """An overlay declares no way to be activated, so it can never fire."""


def _as_tuple(value):
    return tuple(value) if value else ()


def discover(root):
    """Return {pack_id: pack_dir} for every pack directory under `root`."""
    found = {}
    if not os.path.isdir(root):
        raise PackNotFoundError(f"rulepack registry root not found: {root}")
    for name in sorted(os.listdir(root)):
        pack_dir = os.path.join(root, name)
        if not os.path.isdir(pack_dir):
            continue
        if not os.path.exists(os.path.join(pack_dir, PACK_FILENAME)):
            continue
        found[name] = pack_dir
    return found


def _check_pack_id(pack_id):
    if not isinstance(pack_id, str) or not PACK_ID_RE.match(pack_id):
        raise InvalidPackIdError(
            f"pack id {pack_id!r} is not a bare identifier matching "
            f"{PACK_ID_RE.pattern}; packs are resolved by id, never by path"
        )


def read_pack(root, pack_id, schema=None):
    """Read and schema-validate one pack. Does not resolve `requires`."""
    _check_pack_id(pack_id)
    pack_dir = os.path.join(root, pack_id)
    path = os.path.join(pack_dir, PACK_FILENAME)
    if not os.path.exists(path):
        raise PackNotFoundError(f"no pack {pack_id!r} in registry {root}")

    with open(path, encoding="utf-8") as fh:
        try:
            raw = json.load(fh)
        except ValueError as exc:
            raise RulepackError(f"{path}: invalid JSON: {exc}") from exc

    if schema is None:
        schema = jsonschema_mini.load_schema(
            jsonschema_mini.default_schema_path()
        )
    try:
        jsonschema_mini.validate(raw, schema)
    except jsonschema_mini.SchemaError as exc:
        raise RulepackError(f"{path}: {exc}") from exc

    if raw["id"] != pack_id:
        raise RulepackError(
            f"{path}: declares id {raw['id']!r} but lives in directory "
            f"{pack_id!r}; the registry resolves by directory name"
        )

    categories = tuple(
        Category(
            id=cid,
            name=c["name"],
            prefix=c["prefix"],
            default_surface=c["default_surface"],
            default_severity=c["default_severity"],
            default_diff_checkable=c["default_diff_checkable"],
            pack=pack_id,
        )
        for cid, c in sorted(raw.get("categories", {}).items())
    )
    rules = tuple(
        Rule(
            id=r["id"],
            category=r["category"],
            title=r["title"],
            enforcement=r["enforcement"],
            severity=r.get("severity"),
            surface=r.get("surface"),
            diff_checkable=r.get("diff_checkable"),
            detect=r.get("detect"),
            pack=pack_id,
        )
        for r in raw.get("rules", [])
    )
    detectors = tuple(
        Detector(
            key=d["key"],
            emits_principle_id=d["emits_principle_id"],
            severity=d["severity"],
            pattern=d["pattern"],
            message=d["message"],
            flags=_as_tuple(d.get("flags")),
            include_globs=_as_tuple(d.get("include_globs")),
            exclude_globs=_as_tuple(d.get("exclude_globs")),
            pack=pack_id,
        )
        for d in raw.get("detectors", [])
    )
    overlays = tuple(
        Overlay(
            id=oid,
            guidance=o.get("guidance", ""),
            path_prefixes=_as_tuple(o.get("path_prefixes")),
            activate_on_surfaces=_as_tuple(o.get("activate_on_surfaces")),
            pack=pack_id,
        )
        for oid, o in sorted(raw.get("overlays", {}).items())
    )
    for overlay in overlays:
        if not overlay.path_prefixes and not overlay.activate_on_surfaces:
            raise DeadOverlayError(
                f"{path}: overlay {overlay.id!r} declares neither "
                f"path_prefixes nor activate_on_surfaces, so nothing can ever "
                f"activate it; dead guidance should fail loudly rather than "
                f"sit there looking configured"
            )
        for surface in overlay.activate_on_surfaces:
            if surface not in SURFACES:
                raise RulepackError(
                    f"{path}: overlay {overlay.id!r} activates on unknown "
                    f"surface {surface!r}"
                )

    return Pack(
        id=pack_id,
        version=raw["version"],
        description=raw.get("description", ""),
        path=path,
        requires=_as_tuple(raw.get("requires")),
        categories=categories,
        rules=rules,
        detectors=detectors,
        overlays=overlays,
        surface_path_globs=dict(raw.get("surface_path_globs", {})),
        suggested_severity_floors=dict(
            raw.get("suggested_severity_floors", {})
        ),
    )


def _resolve_order(root, pack_ids, schema, resolved):
    """
    Depth-first topological order over `requires`, dependencies first.

    Cycles are rejected rather than broken arbitrarily: a cycle means two packs
    each claim to build on the other, and silently picking an order would make
    the resolved rubric depend on dict iteration order.

    `resolved` is a caller-owned set that accumulates the ids read cleanly, so
    it survives an exception thrown part-way through.
    """
    packs = {}
    order = []
    visiting = []

    def visit(pid):
        if pid in packs:
            return
        if pid in visiting:
            cycle = " -> ".join(visiting[visiting.index(pid):] + [pid])
            raise DependencyCycleError(
                f"rulepack requires cycle: {cycle}",
                resolved_pack_ids=resolved, failing_pack_id=pid,
            )
        visiting.append(pid)
        try:
            pack = read_pack(root, pid, schema)
        except RulepackError as exc:
            exc.resolved_pack_ids = frozenset(resolved)
            exc.failing_pack_id = exc.failing_pack_id or pid
            raise
        for dep in pack.requires:
            _check_pack_id(dep)
            visit(dep)
        visiting.pop()
        packs[pid] = pack
        resolved.add(pid)
        order.append(pack)

    for pid in pack_ids:
        _check_pack_id(pid)
        visit(pid)
    return order


def resolve_severity(rule, category):
    """
    The three resolution layers, in order.

      1. the category default
      2. the rule's own `severity`, when it declares one
      3. the enforcement cap: missing/partial force `low`

    **Surface severity floors are deliberately absent.** They are a
    finding-time policy, not a materialization one. v0.5.0 kept the `rls` floor
    in config (`principles.surface_overrides.*.severity_floor`) and in the
    rls-reviewer prompt; `rubric.py build_rules()` contains no floor at all.

    The golden snapshot settles it: DL-031 is surface `rls` at severity
    `medium`. No materialization-time floor of `high`, under any ordering,
    produces that row. Applying one here would also make static pack content
    depend on a per-repo config value, which is backwards - a repo setting
    `severity_floor: critical` must not require editing a pack.

    The enforcement cap is last, as in v0.5.0. A rule describing practice the
    codebase has not adopted is advisory no matter how loudly its category
    shouts.
    """
    severity = category.default_severity
    if rule.severity:
        severity = rule.severity
    if rule.enforcement in ADVISORY_ENFORCEMENT:
        severity = "low"
    return severity


class Rubric:
    """The merged, resolved result of loading one or more packs."""

    def __init__(self, packs, rules, categories, detectors, overlays,
                 surface_path_globs, suggested_severity_floors):
        self.packs = tuple(packs)
        self.rules = tuple(rules)
        self.categories = dict(categories)
        self.detectors = tuple(detectors)
        self.overlays = tuple(overlays)
        self.surface_path_globs = surface_path_globs
        #: Advisory. Exposed so org config can be seeded from the packs, and
        #: for no other reason - nothing in materialization reads this.
        self.suggested_severity_floors = dict(suggested_severity_floors)
        self._by_surface = {s: [] for s in SURFACES}
        self._by_id = {}
        for rule in self.rules:
            self._by_surface[rule.surface].append(rule)
            self._by_id[rule.id] = rule

    @property
    def pack_ids(self):
        """Resolved pack ids in dependency order (dependencies first)."""
        return tuple(p.id for p in self.packs)

    def loaded_pack_ids(self):
        """
        The set of pack ids actually resolved, including `requires` closure.

        This is the source of truth for `validate_agent_output`'s
        `allowed_rulepack_ids`: a finding claiming a pack that was never
        loaded is a fabrication and must be rejected, not relabelled. The
        closure matters - a repo asking for `supabase-rls` also gets `base`,
        and a legitimate `base` finding must not be thrown away.
        """
        return frozenset(p.id for p in self.packs)

    def by_surface(self, surface):
        """Resolved rules for `surface`, sorted by id. May be empty."""
        if surface not in self._by_surface:
            raise RulepackError(f"unknown reviewer surface {surface!r}")
        return tuple(self._by_surface[surface])

    def get(self, rule_id):
        try:
            return self._by_id[rule_id]
        except KeyError:
            raise UnknownPrincipleError(rule_id) from None

    def populated_surfaces(self):
        return tuple(s for s in SURFACES if self._by_surface[s])

    def empty_surfaces(self):
        """
        Surfaces with zero resolved rules.

        The orchestrator must refuse to dispatch a reviewer for any of these.
        A reviewer handed an empty rubric still produces fluent output; it just
        has nothing behind it.
        """
        return tuple(s for s in SURFACES if not self._by_surface[s])

    def require_surface(self, surface):
        """Return the rules for `surface`, or raise if it is empty."""
        rules = self.by_surface(surface)
        if not rules:
            raise EmptySurfaceError(
                f"surface {surface!r} resolves to 0 rules under packs "
                f"{list(self.pack_ids)}; refuse to dispatch a reviewer for it"
            )
        return rules

    def surfaces_for_path(self, path):
        """Which reviewer surfaces a changed path activates."""
        from . import globs as _globs
        hit = []
        for surface in SURFACES:
            patterns = self.surface_path_globs.get(surface)
            if patterns and _globs.match_any(path, patterns):
                hit.append(surface)
        return tuple(hit)

    def overlays_for_path(self, path):
        """Domain overlays whose path prefixes match, longest prefix first."""
        from . import globs as _globs
        norm = _globs.normalize(path)
        matches = []
        for overlay in self.overlays:
            best = 0
            for prefix in overlay.path_prefixes:
                if "*" in prefix or "?" in prefix:
                    if _globs.match_any(norm, [prefix.rstrip("/") + "/**"]):
                        best = max(best, len(prefix))
                elif norm.startswith(_globs.normalize(prefix)):
                    best = max(best, len(prefix))
            if best:
                matches.append((best, overlay))
        matches.sort(key=lambda m: (-m[0], m[1].id))
        return tuple(o for _, o in matches)

    def overlays_for_surface(self, surface):
        """Cross-cutting overlays that activate on a reviewer surface."""
        return tuple(o for o in self.overlays
                     if surface in o.activate_on_surfaces)

    def detectors_for_path(self, path):
        from . import globs as _globs
        return tuple(
            d for d in self.detectors
            if _globs.path_selected(path, d.include_globs, d.exclude_globs)
        )

    def materialize(self):
        """Golden-snapshot rows, sorted. Mirrors tools/golden_snapshot.py."""
        return sorted(r.as_row() for r in self.rules)


def load(root, pack_ids, schema=None):
    """
    Load `pack_ids` (plus their `requires` closure) from the registry at `root`.

    `root` comes from core, not from repository config. `pack_ids` are bare
    identifiers.

    On failure the raised `RulepackError` carries `resolved_pack_ids` and
    `failing_pack_id`, so a caller can still tell which packs are legitimate
    rather than having to treat every id as unknown.
    """
    read_ok = set()
    try:
        return _load(root, pack_ids, schema, read_ok)
    except RulepackError as exc:
        if not exc.resolved_pack_ids:
            exc.resolved_pack_ids = frozenset(read_ok)
        raise


def _load(root, pack_ids, schema, read_ok):
    if schema is None:
        schema = jsonschema_mini.load_schema(
            jsonschema_mini.default_schema_path()
        )
    _assert_surfaces_match_schema(schema)

    packs = _resolve_order(root, list(pack_ids), schema, read_ok)

    categories = {}
    for pack in packs:
        for cat in pack.categories:
            if cat.id in categories:
                raise DuplicateCategoryError(
                    f"category {cat.id!r} declared by both "
                    f"{categories[cat.id].pack!r} and {pack.id!r}; a category "
                    f"may be declared by exactly one pack"
                )
            categories[cat.id] = cat

    # Advisory only: collected so org config can be seeded from the packs.
    # Deliberately not passed to `resolve_severity` - see its docstring.
    floors = {}
    for pack in packs:
        for surface, severity in pack.suggested_severity_floors.items():
            if surface not in SURFACES:
                raise RulepackError(
                    f"{pack.id}: suggested severity floor for unknown surface "
                    f"{surface!r}"
                )
            floors[surface] = (
                max_severity(floors[surface], severity)
                if surface in floors else severity
            )

    surface_globs = {}
    for pack in packs:
        for surface, patterns in pack.surface_path_globs.items():
            if surface not in SURFACES:
                raise RulepackError(
                    f"{pack.id}: path globs for unknown surface {surface!r}"
                )
            bucket = surface_globs.setdefault(surface, [])
            for pattern in patterns:
                if pattern not in bucket:
                    bucket.append(pattern)

    seen_rules = {}
    resolved = []
    for pack in packs:
        for rule in pack.rules:
            if rule.id in seen_rules:
                raise DuplicateRuleIdError(
                    f"principle id {rule.id!r} defined by both "
                    f"{seen_rules[rule.id]!r} and {pack.id!r}; rule ids are a "
                    f"single global namespace across all packs"
                )
            seen_rules[rule.id] = pack.id

            category = categories.get(rule.category)
            if category is None:
                raise UnknownCategoryError(
                    f"{pack.id}: rule {rule.id} names category "
                    f"{rule.category!r}, which no loaded pack declares"
                )
            if rule.id.rsplit("-", 1)[0] != category.prefix:
                raise RulepackError(
                    f"{pack.id}: rule {rule.id} does not carry the prefix "
                    f"{category.prefix!r} of its category {category.id!r}"
                )

            surface = rule.surface or category.default_surface
            severity = resolve_severity(rule, category)
            resolved.append(ResolvedRule(
                id=rule.id,
                category=rule.category,
                category_name=category.name,
                title=rule.title,
                enforcement=rule.enforcement,
                severity=severity,
                surface=surface,
                diff_checkable=(
                    rule.diff_checkable or category.default_diff_checkable
                ),
                detect=rule.detect or "",
                pack=pack.id,
            ))

    seen_keys = {}
    detectors = []
    for pack in packs:
        for det in pack.detectors:
            if det.key in seen_keys:
                raise DuplicateDetectorKeyError(
                    f"detector key {det.key!r} defined by both "
                    f"{seen_keys[det.key]!r} and {pack.id!r}"
                )
            seen_keys[det.key] = pack.id
            # Two detectors legitimately emitting one principle id at different
            # severities is normal - that is the FA-009 case, and the reason
            # emits_principle_id is explicit rather than derived from the key.
            # Only the *rule* namespace is checked for duplicates.
            if det.emits_principle_id not in seen_rules:
                raise UnknownPrincipleError(
                    f"{pack.id}: detector {det.key!r} emits "
                    f"{det.emits_principle_id!r}, which no loaded pack defines"
                )
            detectors.append(det)

    overlays = []
    seen_overlays = {}
    for pack in packs:
        for overlay in pack.overlays:
            if overlay.id in seen_overlays:
                raise RulepackError(
                    f"overlay {overlay.id!r} declared by both "
                    f"{seen_overlays[overlay.id]!r} and {pack.id!r}"
                )
            seen_overlays[overlay.id] = pack.id
            overlays.append(overlay)

    resolved.sort(key=lambda r: r.id)
    detectors.sort(key=lambda d: d.key)
    return Rubric(packs, resolved, categories, detectors, overlays,
                  surface_globs, floors)


def load_all(root, schema=None):
    """Load every pack in the registry. Used by the golden-parity check."""
    return load(root, sorted(discover(root)), schema=schema)


def _assert_surfaces_match_schema(schema):
    """
    Fail loudly if `model.SURFACES` has drifted from the frozen contract.

    A surface the loader does not know about would silently never be dispatched
    and would never show up in `empty_surfaces()` either, so it has to be caught
    at load time rather than discovered by a reviewer that never runs.
    """
    declared = tuple(schema["$defs"]["surface"]["enum"])
    if set(declared) != set(SURFACES):
        raise RulepackError(
            f"surface list drift: contract declares {sorted(declared)}, "
            f"loader knows {sorted(SURFACES)}"
        )
