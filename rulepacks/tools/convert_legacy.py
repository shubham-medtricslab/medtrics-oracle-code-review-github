#!/usr/bin/env python3
"""
One-time migration: v0.5.0 hardcoded catalog -> five declarative rulepacks.

This script exists so the 374-rule / 18-detector partition is *auditable* rather
than a 374-line hand edit nobody can review. It is deliberately kept in the repo
after the migration: re-running it must be a no-op, which is itself a regression
test on the packs. `rulepacks/tools/verify_golden.py` then proves the packs
reproduce `contracts/golden-rubric.tsv` row for row.

Two legacy bugs are fixed here, and only these two:

  1. FA-009b. detectors.py:104 derived the emitted principle id from the
     detector key (`rid.split("b")[0] if rid.endswith("b")`). Two detectors
     therefore landed on one principle id with two different severities and no
     way to tell them apart downstream. Here each detector carries an explicit
     `emits_principle_id` and a distinct `key`. Both legitimately emit FA-009 -
     the catalog has exactly one rule for banned import paths - but they are now
     distinguishable, which is the whole point of the schema field.

  2. FA-010. detectors.py:68 bound "Supabase client imported outside a service"
     to `_is_ts` with no exclusion, so it fired on `*.service.ts` - the one file
     kind the rule explicitly permits. Expressed here with `exclude_globs`.

Everything else is transcribed mechanically. Regex patterns and flags are read
off the compiled objects in the legacy module rather than retyped, so there is
no transcription risk.

    convert_legacy.py --legacy ../medtrics-oracle-code-review --out rulepacks
    convert_legacy.py --legacy ... --out rulepacks --check   # no-op assertion
"""
import argparse
import json
import os
import re
import sys

PACK_IDS = ["base", "react-ts", "supabase-rls", "org-practice", "medtrics-oracle"]

PACK_META = {
    "base": {
        "version": "1.0.0",
        "description": (
            "Stack-neutral review rules. Applies to any codebase. Declares the "
            "shared category table that every other pack contributes rules into."
        ),
        "requires": [],
    },
    "react-ts": {
        "version": "1.0.0",
        "description": "React, TypeScript and browser-frontend rules.",
        "requires": ["base"],
    },
    "supabase-rls": {
        "version": "1.0.0",
        "description": (
            "Supabase, SQL, Postgres RLS and edge-function rules. Owns all 16 "
            "rules on the `rls` reviewer surface."
        ),
        "requires": ["base"],
    },
    "org-practice": {
        "version": "1.0.0",
        "description": (
            "Engineering-process rules: testing, documentation, git, devops and "
            "AI-agent management. Separate from medtrics-oracle so a repo can "
            "adopt process rules without taking on Oracle-specific content."
        ),
        "requires": ["base"],
    },
    "medtrics-oracle": {
        "version": "1.0.0",
        "description": (
            "Medtrics Oracle specifics: the repo's domain system, portal model, "
            "import bans, HIPAA/FERPA rules and the 42 domain overlays."
        ),
        "requires": ["base", "react-ts", "supabase-rls"],
    },
}

# Every category is declared exactly once, by `base`. Packs contribute rules
# into those categories; the category-default layer itself is shared, which is
# what lets `supabase-rls` carry a `typescript-standards` rule without taking a
# dependency on `react-ts`.
CATEGORY_DECLARING_PACK = "base"

# Default pack for each category. Per-rule exceptions follow.
CATEGORY_DEFAULT_PACK = {
    "frontend-architecture": "react-ts",
    "typescript-standards": "react-ts",
    "supabase-data-layer": "supabase-rls",
    "authentication-security": "base",
    "edge-functions-apis": "supabase-rls",
    "ux-accessibility": "base",
    "performance": "base",
    "testing-quality-gates": "org-practice",
    "documentation-standards": "org-practice",
    "git-collaboration": "org-practice",
    "devops-infrastructure": "org-practice",
    "ai-agent-management": "org-practice",
    "incident-monitoring": "base",
    "accessibility-wcag": "base",
    "mobile-best-practices": "base",
    "gdpr-data-privacy": "base",
    "internationalization": "base",
}

# Per-rule pack assignment, overriding the category default. Grouped by the
# reason the rule leaves its category's default pack.
RULE_PACK = {}


def _assign(pack, ids):
    for rid in ids:
        if rid in RULE_PACK:
            raise SystemExit(f"internal: {rid} assigned twice")
        RULE_PACK[rid] = pack


# -- Oracle-specific frontend architecture: domain system, portals, @/ import
#    bans, DashboardLayout, the Oracle build order and recovery playbook.
_assign("medtrics-oracle", [
    "FA-006", "FA-007", "FA-008", "FA-009", "FA-010", "FA-012", "FA-013",
    "FA-014", "FA-015", "FA-016", "FA-018", "FA-019", "FA-021", "FA-022",
    "FA-023", "FA-024", "FA-025",
])
# -- TypeScript rules that are really about generated DB types.
_assign("supabase-rls", ["TS-007", "TS-008", "TS-011", "TS-012"])
# -- TS-001 is a meta-rule about this catalog's own E/P/M convention.
_assign("medtrics-oracle", ["TS-001"])
# -- Data-layer rules that are Oracle tooling/process, not Supabase practice.
_assign("medtrics-oracle", [
    "DL-011", "DL-019", "DL-020", "DL-022", "DL-023", "DL-024", "DL-025",
    "DL-026", "DL-027", "DL-033",
])
# -- Security rules that are Postgres/Supabase mechanics (incl. all 7 rls ones).
_assign("supabase-rls", [
    "SEC-001", "SEC-002", "SEC-006", "SEC-013", "SEC-014", "SEC-015",
    "SEC-018", "SEC-019", "SEC-020",
])
# -- Security rules that are Oracle escalation process or sector-specific.
_assign("medtrics-oracle", [
    "SEC-008", "SEC-009", "SEC-010", "SEC-012", "SEC-021", "SEC-023",
    "SEC-024", "SEC-025", "SEC-026",
])
# -- Edge-function rules that encode Oracle's own helpers and decision process.
_assign("medtrics-oracle", ["EF-006", "EF-007", "EF-008", "EF-015", "EF-019"])
# -- UX rules that are Oracle brand voice / microcopy.
_assign("medtrics-oracle", ["UX-008", "UX-020", "UX-021", "UX-022", "UX-023"])
# -- UX rules that presuppose React Query / shadcn tokens.
_assign("react-ts", ["UX-003", "UX-016", "UX-018", "UX-019"])
# -- Performance rules that name React or React Query primitives.
_assign("react-ts", [
    "PERF-001", "PERF-003", "PERF-004", "PERF-006", "PERF-007", "PERF-008",
    "PERF-009", "PERF-010", "PERF-012", "PERF-013", "PERF-015", "PERF-016",
    "PERF-022", "PERF-023",
])
# -- Incident rules tied to HIPAA auditing or Oracle's escalation protocol.
_assign("medtrics-oracle", [
    "IM-006", "IM-009", "IM-010", "IM-011", "IM-012", "IM-015",
])
_assign("supabase-rls", ["IM-013"])
# -- A11y rules that presuppose shadcn Dialog/Sheet or i18n keys.
_assign("react-ts", ["A11Y-010", "A11Y-023"])
# -- A11y rules specific to the clinical setting / Oracle audit criteria.
_assign("medtrics-oracle", ["A11Y-011", "A11Y-012"])
# -- Mobile rules that presuppose React Native readiness lint or React dialogs.
_assign("react-ts", ["MOB-012", "MOB-013", "MOB-016", "MOB-018", "MOB-022"])
# -- Mobile rules naming Oracle shared types / conventions.
_assign("medtrics-oracle", ["MOB-014", "MOB-015"])
# -- Privacy rules that are HIPAA/PHI specific.
_assign("medtrics-oracle", ["PRIV-009", "PRIV-010", "PRIV-011"])
# -- i18n rules that name react-i18next, Tailwind RTL classes or React context.
_assign("react-ts", [
    "I18N-002", "I18N-003", "I18N-011", "I18N-012", "I18N-013", "I18N-016",
    "I18N-018", "I18N-020", "I18N-021", "I18N-022",
])
# -- i18n rules that are Oracle validator tooling.
_assign("medtrics-oracle", ["I18N-009", "I18N-010", "I18N-017", "I18N-019"])


SURFACE_PATH_GLOBS = {
    "base": {
        "security_privacy": ["**/*"],
        "risk": ["**/*"],
    },
    "react-ts": {
        "frontend": ["**/*.tsx", "**/*.jsx", "**/*.css", "**/*.scss"],
        "typescript": ["**/*.ts", "**/*.tsx"],
        "ux_a11y": ["**/*.tsx", "**/*.jsx", "**/*.css", "**/*.scss"],
        "i18n_rtl": [
            "**/*.ts", "**/*.tsx", "**/*.jsx",
            "**/locales/**/*.json", "**/i18n/**",
        ],
    },
    "supabase-rls": {
        "data_layer": ["**/*.sql", "**/services/**/*.ts", "supabase/**"],
        "rls": ["**/*.sql", "supabase/migrations/**"],
        "edge_function": ["supabase/functions/**", "**/functions/**/*.ts"],
    },
    "org-practice": {
        "process": [
            "**/*.md", ".github/**", "**/*.test.ts", "**/*.test.tsx",
            "**/*.spec.ts", "**/tests/**", "**/e2e/**", "**/package.json",
            "**/Makefile", "**/Dockerfile", "**/docker-compose*.yml",
        ],
    },
    "medtrics-oracle": {},
}

# Only `supabase-rls` introduces the `rls` surface, so the floor belongs there.
# A floor raises the *category default* for rules on that surface; an explicit
# per-rule `severity` is a reviewed exception and still wins (DL-031 is exactly
# that case, and is `medium` in the golden snapshot).
SEVERITY_FLOORS = {
    "supabase-rls": {"rls": "high"},
}

# detectors.py path predicates, translated. `_is_service` was
# `"/services/" in p and p.endswith(".ts")`.
PREDICATE_GLOBS = {
    "_is_ts": ["**/*.ts", "**/*.tsx"],
    "_is_tsx": ["**/*.tsx"],
    "_is_sql": ["**/*.sql"],
    "_is_service": ["**/services/**/*.ts"],
}

# Legacy detector tuple index -> (pack, key, emits_principle_id, exclude_globs).
# Keyed by the legacy first element so the mapping is readable next to the
# source. FA-009b is the collision; FA-010 is the inversion.
DETECTOR_PLAN = {
    "I18N-003": ("react-ts", "i18n-003-rtl-directional-class", "I18N-003", None),
    "TS-009": ("react-ts", "ts-009-any-type", "TS-009", None),
    "TS-010": ("react-ts", "ts-010-console-statement", "TS-010", None),
    "FA-026": ("react-ts", "fa-026-window-confirm", "FA-026", None),
    "FA-010": (
        "medtrics-oracle",
        "fa-010-supabase-client-outside-service",
        "FA-010",
        ["**/*.service.ts"],
    ),
    "FA-009": ("medtrics-oracle", "fa-009-banned-root-import", "FA-009", None),
    "FA-009b": ("medtrics-oracle", "fa-009-deep-domain-import", "FA-009", None),
    "DL-009": ("supabase-rls", "dl-009-select-star", "DL-009", None),
    "DL-008": ("supabase-rls", "dl-008-view-security-invoker", "DL-008", None),
    "DL-030": ("supabase-rls", "dl-030-for-all-policy", "DL-030", None),
    "DL-001": ("supabase-rls", "dl-001-create-table-rls", "DL-001", None),
    "SEC-014": ("supabase-rls", "sec-014-policy-returns-true", "SEC-014", None),
    "SEC-004": ("react-ts", "sec-004-hardcoded-secret", "SEC-004", None),
    "SEC-011": ("react-ts", "sec-011-raw-error-message", "SEC-011", None),
    "I18N-001": ("react-ts", "i18n-001-hardcoded-jsx-string", "I18N-001", None),
    "PERF-022": ("react-ts", "perf-022-unstable-query-key", "PERF-022", None),
    "A11Y-022": ("react-ts", "a11y-022-icon-only-button", "A11Y-022", None),
    "DL-014": ("supabase-rls", "dl-014-soft-delete-filter", "DL-014", None),
}

FLAG_NAMES = [("IGNORECASE", re.IGNORECASE), ("MULTILINE", re.MULTILINE),
              ("DOTALL", re.DOTALL)]

CROSS_CUTTING_OVERLAYS = {
    "permissions": (
        "Authorization overlay. Apply to any change touching RLS policies, "
        "permission checks or security-definer functions. Activated by the "
        "`rls` and `security_privacy` surfaces rather than by path."
    ),
    "portals": (
        "Portal behaviour overlay: organization / institution / admin / "
        "personal differences. Apply when a change alters behaviour that "
        "varies by portal."
    ),
}


def load_legacy(legacy_root):
    rubric_scripts = os.path.join(legacy_root, "skills", "principle-rubric", "scripts")
    detector_scripts = os.path.join(legacy_root, "skills", "detectors", "scripts")
    for d in (rubric_scripts, detector_scripts):
        if not os.path.isdir(d):
            sys.exit(f"ERROR: missing legacy directory {d}")
    sys.path.insert(0, rubric_scripts)
    sys.path.insert(0, detector_scripts)
    import catalog_data  # noqa: E402
    import detectors  # noqa: E402
    import rubric  # noqa: E402
    return catalog_data, detectors, rubric


def detect_text(rid, title, pack):
    if pack == "medtrics-oracle":
        return (f'Apply catalog rule {rid} ("{title}") to the changed hunks; '
                f"confirm against the repository's own `.agents/references/` "
                f"where a repo-native check exists.")
    return (f'Apply catalog rule {rid} ("{title}") to the changed hunks; cite '
            f"file and line for every finding.")


def build_rules(catalog_data):
    """Return {pack_id: [rule dict]} in catalog order."""
    out = {p: [] for p in PACK_IDS}
    enforcement_map = {"E": "established", "P": "partial", "M": "missing"}
    for cat_id, (_name, prefix, _surf, _sev, _diff) in catalog_data.CATEGORIES.items():
        for seq, title, enf in catalog_data.RULES[cat_id]:
            rid = f"{prefix}-{seq:03d}"
            pack = RULE_PACK.get(rid, CATEGORY_DEFAULT_PACK[cat_id])
            ov = catalog_data.OVERRIDES.get(rid, {})
            rule = {
                "id": rid,
                "category": cat_id,
                "title": title,
                "enforcement": enforcement_map[enf],
            }
            # OVERRIDES collapse into optional per-rule fields. The schema has
            # no separate override table: core applies category default ->
            # these fields -> enforcement cap.
            if "severity" in ov:
                rule["severity"] = ov["severity"]
            if "surface" in ov:
                rule["surface"] = ov["surface"]
            if "diff" in ov:
                rule["diff_checkable"] = ov["diff"]
            rule["detect"] = detect_text(rid, title, pack)
            out[pack].append(rule)
    return out


def build_detectors(detectors_mod):
    out = {p: [] for p in PACK_IDS}
    seen_keys = set()
    for legacy_id, severity, predicate, rx, message in detectors_mod.RULES:
        if legacy_id not in DETECTOR_PLAN:
            sys.exit(f"ERROR: unplanned legacy detector {legacy_id!r}")
        pack, key, emits, exclude = DETECTOR_PLAN[legacy_id]
        if key in seen_keys:
            sys.exit(f"ERROR: duplicate detector key {key!r}")
        seen_keys.add(key)
        globs = PREDICATE_GLOBS.get(predicate.__name__)
        if globs is None:
            sys.exit(f"ERROR: no glob translation for predicate "
                     f"{predicate.__name__!r} (detector {legacy_id})")
        flags = [name for name, bit in FLAG_NAMES if rx.flags & bit]
        det = {
            "key": key,
            "emits_principle_id": emits,
            "severity": severity,
            "pattern": rx.pattern,
            "message": message,
        }
        if flags:
            det["flags"] = flags
        det["include_globs"] = list(globs)
        if exclude:
            det["exclude_globs"] = list(exclude)
        out[pack].append(det)
    missing = set(DETECTOR_PLAN) - {d for d in DETECTOR_PLAN}
    if missing:  # pragma: no cover - defensive
        sys.exit(f"ERROR: planned detectors never seen: {sorted(missing)}")
    return out


def build_overlays(rubric_mod):
    overlays = {}
    for d in rubric_mod.ORACLE_DOMAINS:
        underscored = d.replace("-", "_")
        overlays[d] = {
            "path_prefixes": [
                f"src/domains/{d}/",
                f"src/components/organisms/{d}/",
                f"supabase/migrations/domains/*_{underscored}/",
            ],
            "guidance": (
                f"Oracle domain overlay for `{d}`. Load this domain's "
                f"conventions alongside the surface rubric when files under "
                f"these prefixes change."
            ),
        }
    for name, guidance in CROSS_CUTTING_OVERLAYS.items():
        overlays[name] = {"guidance": guidance}
    return overlays


def build_categories(catalog_data):
    cats = {}
    for cat_id, (name, prefix, surf, sev, diff) in catalog_data.CATEGORIES.items():
        cats[cat_id] = {
            "name": name,
            "prefix": prefix,
            "default_surface": surf,
            "default_severity": sev,
            "default_diff_checkable": diff,
        }
    return cats


def build_packs(catalog_data, detectors_mod, rubric_mod):
    rules = build_rules(catalog_data)
    dets = build_detectors(detectors_mod)
    overlays = build_overlays(rubric_mod)
    categories = build_categories(catalog_data)

    packs = {}
    for pid in PACK_IDS:
        meta = PACK_META[pid]
        pack = {"id": pid, "version": meta["version"],
                "description": meta["description"]}
        if meta["requires"]:
            pack["requires"] = list(meta["requires"])
        if pid == CATEGORY_DECLARING_PACK:
            pack["categories"] = categories
        pack["rules"] = rules[pid]
        if dets[pid]:
            pack["detectors"] = dets[pid]
        if SURFACE_PATH_GLOBS.get(pid):
            pack["surface_path_globs"] = SURFACE_PATH_GLOBS[pid]
        if SEVERITY_FLOORS.get(pid):
            pack["severity_floors"] = SEVERITY_FLOORS[pid]
        if pid == "medtrics-oracle":
            pack["overlays"] = overlays
        packs[pid] = pack
    return packs


def render(pack):
    return json.dumps(pack, indent=2, ensure_ascii=False) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(prog="convert_legacy.py")
    p.add_argument("--legacy", required=True,
                   help="path to the medtrics-oracle-code-review checkout")
    p.add_argument("--out", default="rulepacks",
                   help="rulepack registry root to write into")
    p.add_argument("--check", action="store_true",
                   help="do not write; fail if output differs from on-disk packs")
    args = p.parse_args(argv)

    catalog_data, detectors_mod, rubric_mod = load_legacy(args.legacy)
    packs = build_packs(catalog_data, detectors_mod, rubric_mod)

    total_rules = sum(len(pk["rules"]) for pk in packs.values())
    if total_rules != 374:
        sys.exit(f"ERROR: partitioned {total_rules} rules, expected 374")
    total_dets = sum(len(pk.get("detectors", [])) for pk in packs.values())
    if total_dets != len(detectors_mod.RULES):
        sys.exit(f"ERROR: partitioned {total_dets} detectors, expected "
                 f"{len(detectors_mod.RULES)}")

    drift = []
    for pid, pack in packs.items():
        path = os.path.join(args.out, pid, "rulepack.json")
        text = render(pack)
        if args.check:
            if not os.path.exists(path):
                drift.append(f"{path}: missing")
                continue
            with open(path, encoding="utf-8") as fh:
                if fh.read() != text:
                    drift.append(f"{path}: differs from converter output")
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"WROTE {path} ({len(pack['rules'])} rules, "
              f"{len(pack.get('detectors', []))} detectors)")

    if args.check:
        if drift:
            print("CONVERTER DRIFT")
            for d in drift:
                print("  " + d)
            return 1
        print(f"CONVERTER CLEAN ({total_rules} rules, {total_dets} detectors)")
        return 0

    print(f"TOTAL {total_rules} rules, {total_dets} detectors across "
          f"{len(packs)} packs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
