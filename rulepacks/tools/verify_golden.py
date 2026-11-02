#!/usr/bin/env python3
"""
Prove the rulepacks reproduce `contracts/golden-rubric.tsv` row for row.

`tools/golden_snapshot.py verify` imports the *legacy* v0.5.0 rubric module, so
it can only tell you the legacy module still agrees with the snapshot it was
generated from. That is a tautology once the migration is done. This is the
check that actually matters: it materializes all 374 rules from the packs -
through the real loader, with the real three-layer resolution - and diffs the
result against the same frozen snapshot.

A count would not do. v0.5.0's `rubric.py parity` asserted
`len(rules) == 374 and len(CATEGORIES) == 17`; you could move every rule to a
different surface, drop the `rls` floor, and uncap the advisory rules while
still passing it. This compares all six columns of all 374 rows.

Deliberate deviations are read from `contracts/parity-breaks.tsv`, which is
lead-owned and currently empty of rows - neither detector fix changes a rule
attribute, so neither belongs there.

    verify_golden.py
    verify_golden.py --root rulepacks --snapshot contracts/golden-rubric.tsv

Exit codes: 0 parity holds, 1 mismatch, 2 the packs would not load.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "packages", "core",
))

from aireview.rulepack import RulepackError, load, load_all  # noqa: E402
from aireview.rulepack.model import COLUMNS  # noqa: E402


def read_snapshot(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        header = fh.readline().rstrip("\n").split("\t")
        if tuple(header) != COLUMNS:
            sys.exit(f"ERROR: snapshot header {header} != {list(COLUMNS)}")
        for line in fh:
            line = line.rstrip("\n")
            if line:
                rows.append(tuple(line.split("\t")))
    return rows


def read_breaks(path):
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
            accepted[(parts[0], parts[1])] = (parts[2], parts[3])
    return accepted


def compare(rows, snapshot_path, breaks_path):
    expected = {r[0]: r for r in read_snapshot(snapshot_path)}
    actual = {r[0]: r for r in rows}
    accepted = read_breaks(breaks_path)

    problems = []
    for rid in sorted(set(expected) - set(actual)):
        problems.append(f"MISSING  {rid} in snapshot, absent from packs")
    for rid in sorted(set(actual) - set(expected)):
        problems.append(f"ADDED    {rid} in packs, absent from snapshot")
    for rid in sorted(set(expected) & set(actual)):
        for i, col in enumerate(COLUMNS):
            if expected[rid][i] == actual[rid][i]:
                continue
            if accepted.get((rid, col)) == (expected[rid][i], actual[rid][i]):
                continue
            problems.append(
                f"CHANGED  {rid}.{col}: {expected[rid][i]!r} -> "
                f"{actual[rid][i]!r}"
            )

    ids = [r[0] for r in rows]
    if len(ids) != len(set(ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        problems.append(f"DUPLICATE ids across packs: {dupes}")
    return problems


def main(argv=None):
    p = argparse.ArgumentParser(prog="verify_golden.py")
    p.add_argument("--root", default="rulepacks")
    p.add_argument("--packs", default="all",
                   help="comma-separated pack ids, or 'all'")
    p.add_argument("--snapshot", default="contracts/golden-rubric.tsv")
    p.add_argument("--breaks", default="contracts/parity-breaks.tsv")
    args = p.parse_args(argv)

    try:
        if args.packs == "all":
            rubric = load_all(args.root)
        else:
            rubric = load(args.root,
                          [x.strip() for x in args.packs.split(",") if x.strip()])
    except RulepackError as exc:
        print(f"RULEPACK ERROR: {exc}", file=sys.stderr)
        return 2

    problems = compare(rubric.materialize(), args.snapshot, args.breaks)
    if problems:
        print(f"PACK/GOLDEN MISMATCH ({len(problems)} problems)")
        for pr in problems[:50]:
            print("  " + pr)
        return 1
    print(f"PACK/GOLDEN OK ({len(rubric.rules)} rules from "
          f"{list(rubric.pack_ids)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
