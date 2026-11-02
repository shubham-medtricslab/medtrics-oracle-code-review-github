#!/usr/bin/env python3
"""
Golden snapshot of the v0.5.0 materialized rubric.

`rubric.py parity` asserted only `len(rules)==374 and len(CATEGORIES)==17`. You
can move every rule to a different surface, drop the RLS high floor, and re-sever
the whole catalog while still passing it. It is a count, not a guard.

This emits the fully materialized tuple for all 374 rules - after category
defaults, after OVERRIDES, after the missing/partial severity cap - so the
rulepack split can be diffed row by row.

    golden_snapshot.py emit   --legacy <path> --out contracts/golden-rubric.tsv
    golden_snapshot.py verify --legacy <path> --snapshot contracts/golden-rubric.tsv

Deliberate parity breaks live in contracts/parity-breaks.tsv and are the ONLY
differences `verify` tolerates.
"""
import argparse
import os
import sys

COLUMNS = ["id", "category", "surface", "severity", "enforcement", "diff_checkable"]


def load_legacy(legacy_root):
    """Import the v0.5.0 rubric module and return its materialized rules."""
    scripts = os.path.join(legacy_root, "skills", "principle-rubric", "scripts")
    if not os.path.isdir(scripts):
        sys.exit(f"ERROR: no rubric scripts at {scripts}")
    sys.path.insert(0, scripts)
    import rubric  # noqa: E402
    return rubric.all_rules()


def to_rows(rules):
    rows = []
    for r in rules:
        rows.append(tuple(str(r[c]) for c in COLUMNS))
    return sorted(rows)


def read_breaks(path):
    """Accepted deliberate differences: id<TAB>column<TAB>old<TAB>new<TAB>reason."""
    accepted = {}
    if not path or not os.path.exists(path):
        return accepted
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 4:
                continue
            rid, col, old, new = parts[0], parts[1], parts[2], parts[3]
            accepted[(rid, col)] = (old, new)
    return accepted


def emit(rules, out):
    rows = to_rows(rules)
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\t".join(COLUMNS) + "\n")
        for row in rows:
            fh.write("\t".join(row) + "\n")
    return len(rows)


def read_snapshot(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        if header != COLUMNS:
            sys.exit(f"ERROR: snapshot header {header} != {COLUMNS}")
        for line in fh:
            line = line.rstrip("\n")
            if line:
                rows.append(tuple(line.split("\t")))
    return rows


def verify(current_rules, snapshot_path, breaks_path):
    expected = {r[0]: r for r in read_snapshot(snapshot_path)}
    actual = {r[0]: r for r in to_rows(current_rules)}
    accepted = read_breaks(breaks_path)

    problems = []
    for rid in sorted(set(expected) - set(actual)):
        problems.append(f"MISSING  {rid} present in snapshot, absent now")
    for rid in sorted(set(actual) - set(expected)):
        problems.append(f"ADDED    {rid} present now, absent from snapshot")

    for rid in sorted(set(expected) & set(actual)):
        for i, col in enumerate(COLUMNS):
            if expected[rid][i] == actual[rid][i]:
                continue
            key = (rid, col)
            if key in accepted and accepted[key] == (expected[rid][i], actual[rid][i]):
                continue
            problems.append(
                f"CHANGED  {rid}.{col}: {expected[rid][i]!r} -> {actual[rid][i]!r}"
            )

    # Duplicate IDs across packs are invisible to a count check.
    ids = [r[0] for r in to_rows(current_rules)]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        problems.append(f"DUPLICATE ids across packs: {dupes}")

    return problems


def main(argv=None):
    p = argparse.ArgumentParser(prog="golden_snapshot.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("emit")
    e.add_argument("--legacy", required=True)
    e.add_argument("--out", default="contracts/golden-rubric.tsv")
    v = sub.add_parser("verify")
    v.add_argument("--legacy", required=True)
    v.add_argument("--snapshot", default="contracts/golden-rubric.tsv")
    v.add_argument("--breaks", default="contracts/parity-breaks.tsv")
    args = p.parse_args(argv)

    rules = load_legacy(args.legacy)

    if args.cmd == "emit":
        n = emit(rules, args.out)
        print(f"WROTE {args.out} ({n} rules)")
        return 0

    problems = verify(rules, args.snapshot, args.breaks)
    if problems:
        print(f"GOLDEN SNAPSHOT MISMATCH ({len(problems)} problems)")
        for pr in problems[:50]:
            print("  " + pr)
        return 1
    print("GOLDEN SNAPSHOT OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
