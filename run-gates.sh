#!/usr/bin/env bash
# Every gate, one command. This is what runs before integration and in CI.
#
# Deliberately not `unittest discover` over everything: the suites have
# different shapes (plain scripts vs unittest packages) and forcing one harness
# on all of them would be churn for no benefit. A gate that is awkward to run is
# a gate that stops being run.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

LEGACY="${LEGACY:-../medtrics-oracle-code-review}"
failed=0
run() {
  local name="$1"; shift
  printf '\n== %s ==\n' "$name"
  if "$@"; then
    return 0
  fi
  printf 'FAILED: %s\n' "$name"
  failed=$((failed + 1))
}

# --- static gates -----------------------------------------------------------
run "stdlib-only lint (packages/core)" \
  python3 tools/stdlib_lint.py packages/core

run "contracts parse" python3 - <<'PY'
import ast, json, sys
json.load(open("contracts/rulepack.schema.json"))
json.load(open("contracts/run-record.schema.json"))
ast.parse(open("contracts/write_api.py").read())
print("contracts OK")
PY

# --- rubric parity ----------------------------------------------------------
if [ -d "$LEGACY" ]; then
  run "golden snapshot vs legacy" \
    python3 tools/golden_snapshot.py verify --legacy "$LEGACY"
else
  printf '\n== golden snapshot vs legacy ==\nSKIPPED (no legacy at %s)\n' "$LEGACY"
fi

if [ -f rulepacks/tools/verify_golden.py ]; then
  run "golden snapshot vs packs" python3 rulepacks/tools/verify_golden.py
fi

if [ -f rulepacks/tools/convert_legacy.py ] && [ -d "$LEGACY" ]; then
  run "converter is a no-op" \
    python3 rulepacks/tools/convert_legacy.py --legacy "$LEGACY" --out rulepacks --check
fi

# --- test suites ------------------------------------------------------------
for t in packages/core/tests/test_*.py; do
  [ -e "$t" ] || continue
  run "$(basename "$t")" python3 "$t"
done

for suite in packages/core/aireview/*/tests; do
  [ -d "$suite" ] || continue
  run "unittest $suite" \
    python3 -m unittest discover -s "$suite" -t packages/core -q
done

# action/tests has no __init__.py, so it is its own top-level dir rather than
# a package under the repo root. Discovery from the root fails with
# "Start directory is not importable" if -t is wrong.
if [ -d action/tests ]; then
  run "unittest action/tests" \
    python3 -m unittest discover -s action/tests -t action/tests -q
fi

# --- CLI smoke --------------------------------------------------------------
run "cli --help" env PYTHONPATH=packages/core python3 -m aireview --help

printf '\n============================================================\n'
if [ "$failed" -eq 0 ]; then
  echo "ALL GATES PASSED"
else
  echo "FAILED GATES: $failed"
fi
exit "$failed"
