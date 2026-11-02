#!/usr/bin/env python3
"""
Inspect the rulepack registry from the command line.

Mirrors what v0.5.0's `rubric.py` offered, minus the parts that were only
counts. `materialize` is the one that matters: it prints the fully resolved
rubric in the golden-snapshot column order, which is what
`rulepacks/tools/verify_golden.py` diffs against `contracts/golden-rubric.tsv`.

    python3 -m aireview.rulepack validate     --root rulepacks
    python3 -m aireview.rulepack surfaces     --root rulepacks --packs base,react-ts
    python3 -m aireview.rulepack list         --root rulepacks --surface rls
    python3 -m aireview.rulepack get FA-002   --root rulepacks
    python3 -m aireview.rulepack detectors    --root rulepacks
    python3 -m aireview.rulepack materialize  --root rulepacks --out -

Exit codes: 0 ok, 1 validation or lookup failure.
"""
import argparse
import dataclasses
import json
import sys

from .loader import RulepackError, discover, load
from .model import COLUMNS


def _rubric(args):
    root = args.root
    if args.packs in (None, "", "all"):
        pack_ids = sorted(discover(root))
    else:
        pack_ids = [p.strip() for p in args.packs.split(",") if p.strip()]
    return load(root, pack_ids)


def _add_common(parser):
    parser.add_argument("--root", default="rulepacks",
                        help="rulepack registry root")
    parser.add_argument("--packs", default="all",
                        help="comma-separated pack ids, or 'all'")


def cmd_validate(args):
    rubric = _rubric(args)
    empty = rubric.empty_surfaces()
    print(json.dumps({
        "packs": list(rubric.pack_ids),
        "rules": len(rubric.rules),
        "categories": len(rubric.categories),
        "detectors": len(rubric.detectors),
        "distinct_emitted_principles": len(
            {d.emits_principle_id for d in rubric.detectors}
        ),
        "overlays": len(rubric.overlays),
        "severity_floors": rubric.severity_floors,
        "populated_surfaces": list(rubric.populated_surfaces()),
        "empty_surfaces": list(empty),
        "ok": True,
    }, indent=2))
    return 0


def cmd_surfaces(args):
    rubric = _rubric(args)
    for surface in rubric.populated_surfaces():
        rules = rubric.by_surface(surface)
        print(f"{surface:17} {len(rules):4}")
    for surface in rubric.empty_surfaces():
        print(f"{surface:17}    0  EMPTY - do not dispatch a reviewer")
    return 0


def cmd_list(args):
    rubric = _rubric(args)
    rules = (rubric.by_surface(args.surface) if args.surface
             else rubric.rules)
    for r in rules:
        print(f"{r.id:10} [{r.severity:8}] {r.enforcement:11} "
              f"{r.surface:16} {r.pack:16} {r.title}")
    return 0


def cmd_get(args):
    rubric = _rubric(args)
    print(json.dumps(dataclasses.asdict(rubric.get(args.id)), indent=2))
    return 0


def cmd_detectors(args):
    rubric = _rubric(args)
    print(json.dumps([dataclasses.asdict(d) for d in rubric.detectors],
                     indent=2))
    return 0


def cmd_materialize(args):
    rubric = _rubric(args)
    lines = ["\t".join(COLUMNS)]
    lines += ["\t".join(row) for row in rubric.materialize()]
    text = "\n".join(lines) + "\n"
    if args.out == "-":
        sys.stdout.write(text)
    else:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"WROTE {args.out} ({len(rubric.rules)} rules)")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="aireview.rulepack")
    sub = p.add_subparsers(dest="cmd", required=True)

    for name, fn in (("validate", cmd_validate), ("surfaces", cmd_surfaces),
                     ("detectors", cmd_detectors)):
        sp = sub.add_parser(name)
        _add_common(sp)
        sp.set_defaults(fn=fn)

    sp = sub.add_parser("list")
    _add_common(sp)
    sp.add_argument("--surface")
    sp.set_defaults(fn=cmd_list)

    sp = sub.add_parser("get")
    _add_common(sp)
    sp.add_argument("id")
    sp.set_defaults(fn=cmd_get)

    sp = sub.add_parser("materialize")
    _add_common(sp)
    sp.add_argument("--out", default="-")
    sp.set_defaults(fn=cmd_materialize)

    args = p.parse_args(argv)
    try:
        return args.fn(args)
    except RulepackError as exc:
        print(f"RULEPACK ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
