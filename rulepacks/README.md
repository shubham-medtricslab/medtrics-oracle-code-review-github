# Rulepacks

The 374-rule review catalog as data, conforming to
`contracts/rulepack.schema.json`. v0.5.0 hardcoded it in
`skills/principle-rubric/scripts/catalog_data.py`, which welded the rubric to
one company's stack. A repo now takes only the packs that match what it is.

## The five packs

| Pack | Rules | Detectors | Requires | What it is |
|---|---|---|---|---|
| `base` | 93 | 0 | — | Stack-neutral rules. Declares all 17 categories. |
| `react-ts` | 61 | 9 | `base` | React, TypeScript, browser frontend. |
| `supabase-rls` | 51 | 6 | `base` | Supabase, SQL, Postgres RLS, edge functions. Owns all 16 `rls`-surface rules. |
| `org-practice` | 105 | 0 | `base` | The 105 `process`-surface rules: testing, docs, git, devops, AI-agent management. |
| `medtrics-oracle` | 64 | 3 | `base`, `react-ts`, `supabase-rls` | Oracle specifics plus the 42 domain overlays. |

Two properties are load-bearing and are asserted by tests, not just described
here:

- **`org-practice` does not depend on `medtrics-oracle`.** That is the entire
  reason it exists. Without it, a repo that wanted process rules would be
  forced to install Oracle-specific content, and the Oracle pack would not be
  optional in any meaningful sense.
- **`base` + `react-ts` cannot produce an `rls` surface.** Every `rls` rule
  lives in `supabase-rls`. A repo with no database has no RLS reviewer, and
  the loader says so explicitly rather than dispatching one with an empty
  rubric.

### Why `base` declares every category

The schema permits a category to be declared by exactly one pack. Putting all
17 in `base` makes the dependency graph a star rather than a mesh, and buys
something concrete: `supabase-rls` can carry TS-007/008/011/012 — the rules
about never hand-editing generated database types — without `supabase-rls`
having to depend on `react-ts`. A Python-plus-Supabase repo should not drag in
a React pack to get them.

No category is homogeneous by stack, so most categories fragment across packs.
`frontend-architecture`, for instance, splits 10/17 between `react-ts` and
`medtrics-oracle`: `shadcn/ui as the base` is portable, `domain.json
Validation` is not.

## Resolution

Materializing a rule is exactly three layers, applied by `packages/core`:

1. the category default (`default_surface`, `default_severity`,
   `default_diff_checkable`)
2. the rule's own `severity` / `surface` / `diff_checkable`, when it declares
   one
3. the **enforcement cap** — `missing` and `partial` rules force severity to
   `low`, whatever the layers above said

Packs contribute data into these layers. They never carry the layering itself,
and they never carry filesystem paths: a pack is resolved by ID against a
registry root supplied by core, because anything path-shaped coming out of
repository config is a file-read primitive.

### Severity floors are deliberately **not** part of materialization

`suggested_severity_floors` exists in the schema and `supabase-rls` sets
`rls: high`, but **nothing in rule materialization reads it.** It is advisory —
it seeds org config, and that is all.

This looks like an oversight and will be tempting to "fix". It is not. Floors
are a **finding-time** policy. In v0.5.0 the `rls` floor lived in config
(`principles.surface_overrides.*.severity_floor`) and in the reviewer prompt
(`rls-reviewer.md:46`, "Floor every finding at **high**"); `rubric.py
build_rules()` contains no floor at all.

The golden snapshot settles the argument:

```
DL-031	supabase-data-layer	rls	medium	established	checkout
```

Surface `rls`, severity `medium`. No materialization-time floor of `high`
produces that row under any ordering. Applying one would also make static pack
content depend on a per-repo config value — a repo setting
`severity_floor: critical` must not require editing a pack.

`resolve_severity(rule, category)` takes no floor argument, and a test asserts
its signature for exactly this reason.

## The two bugs fixed in the migration

**`FA-009b`.** `detectors.py:104` derived the emitted principle id from the
detector key — `rid.split("b")[0] if rid.endswith("b")` — collapsing two
detectors onto one id. `emits_principle_id` is now explicit and never derived.
Both FA-009 detectors still emit `FA-009`, correctly: the catalog has one rule
covering banned import paths. What changed is that they have distinct keys
(`fa-009-banned-root-import`, `fa-009-deep-domain-import`) and keep their
distinct severities, so downstream can tell them apart.

The collision also explains a number that had propagated everywhere: this
catalog has **18** detectors, not 17. Seventeen was the count of *distinct
emitted ids* after the collision erased one.

**`FA-010`.** `detectors.py:68` bound "Supabase client imported outside a
service" to `_is_ts` with no exclusion, so it fired on `*.service.ts` — the one
file kind its own message permits. Now expressed with
`exclude_globs: ["**/*.service.ts"]`.

Neither fix changes a rule attribute, so neither appears in
`contracts/parity-breaks.tsv`; both are covered by the detector parity test,
which v0.5.0 had no equivalent of.

## Overlays

`medtrics-oracle` carries 44 overlays: the 42 Oracle domains, resolved by path
prefix, plus `permissions` and `portals`, which are cross-cutting and resolve
by surface via `activate_on_surfaces`. An overlay with neither activation
mechanism is a load error — dead guidance should fail loudly rather than sit
there looking configured.

## Checks

```bash
# the packs reproduce contracts/golden-rubric.tsv, all six columns, all 374 rows
python3 rulepacks/tools/verify_golden.py

# re-running the migration must be a no-op
python3 rulepacks/tools/convert_legacy.py \
    --legacy ../medtrics-oracle-code-review --out rulepacks --check

# loader + pack tests
python3 -m unittest discover -s packages/core/aireview/rulepack/tests -t packages/core

# inspect
PYTHONPATH=packages/core python3 -m aireview.rulepack validate --root rulepacks
PYTHONPATH=packages/core python3 -m aireview.rulepack surfaces --root rulepacks --packs base,react-ts
```

## Editing a pack

Rules were partitioned by `rulepacks/tools/convert_legacy.py`, which is kept in
the repo so the split is auditable and re-runnable rather than being a 374-line
hand edit nobody can review. If you move a rule between packs, change it there
and regenerate; `--check` mode will otherwise flag the drift.

Changing a rule's *attributes* is a different matter. `verify_golden.py` will
reject it, correctly — `contracts/golden-rubric.tsv` and
`contracts/parity-breaks.tsv` are lead-owned, and a deliberate change needs a
row in the latter.
