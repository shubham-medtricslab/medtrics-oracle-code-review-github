#!/usr/bin/env python3
"""
Enforce that packages/core imports nothing outside the stdlib.

The v0.5.0 plugin's stdlib-only property is a real asset: the Actions runner
needs no pip install step, so there is no dependency-resolution failure mode and
no supply-chain surface in the component that handles untrusted diffs. It erodes
silently unless something checks, so this runs in CI.

    stdlib_lint.py packages/core
"""
import ast
import os
import sys

ALLOWED_LOCAL_ROOTS = {"aireview"}


def top_level_imports(path):
    with open(path, encoding="utf-8") as fh:
        try:
            tree = ast.parse(fh.read(), filename=path)
        except SyntaxError as e:
            print(f"SYNTAX ERROR {path}: {e}")
            return None
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                mods.add(a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue  # relative import, local by definition
            if node.module:
                mods.add(node.module.split(".")[0])
    return mods


def main(argv=None):
    argv = argv or sys.argv[1:]
    root = argv[0] if argv else "packages/core"
    stdlib = set(sys.stdlib_module_names)

    violations = []
    checked = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {"__pycache__", ".git"}]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            p = os.path.join(dirpath, fn)
            mods = top_level_imports(p)
            if mods is None:
                violations.append((p, "<syntax error>"))
                continue
            checked += 1
            for m in sorted(mods):
                if m in stdlib or m in ALLOWED_LOCAL_ROOTS:
                    continue
                violations.append((p, m))

    if violations:
        print(f"STDLIB LINT FAILED ({len(violations)} violations in {root})")
        for p, m in violations:
            print(f"  {p}: non-stdlib import {m!r}")
        return 1
    print(f"STDLIB LINT OK ({checked} files in {root})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
