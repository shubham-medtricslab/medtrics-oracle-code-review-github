"""
Run declarative rulepack detectors over the added lines of a diff.

This is the interpreter for the `detectors` section of a rulepack. v0.5.0 had
the equivalent logic welded to Python predicates in
`skills/detectors/scripts/detectors.py`, which is how both of its bugs got in:
a path rule you can only express as a Python function is a path rule nobody
reviews, and an emitted id computed as `rid.split("b")[0]` is an id nobody
notices is wrong.

Behaviour kept identical to v0.5.0 on purpose:

* only ADDED lines are considered; removed lines do not advance the new-file
  line counter, context lines do
* a finding is a candidate, not a verdict - the reviewer agent confirms or
  rejects it

Two behavioural changes. `exclude_globs` is honoured, which is what makes
FA-010 stop firing on `*.service.ts`. And line numbering now comes from the
shared walker in `aireview.github.hunks` rather than a second local copy.

That second point is not tidying. This module originally carried v0.5.0's walk
verbatim, so after the writer's walk was fixed the two disagreed - and a
disagreement here is worse than the original bug. A detector line number that
the writer's `commentable_lines` happens to accept produces a comment posted on
the wrong line of code, under the bot's name, with nothing raised. v0.5.0 was
partly protected by the writer rejecting bad positions; a correct writer waves
them straight through. Fixing one of two disagreeing walks is less safe than
fixing neither.

Concretely, the old walk excluded any added line whose source began `++`
(`startswith("+") and not startswith("+++")`), so no detector could ever fire
on one, and a removed line beginning `--` fell through to the context branch
and advanced the new-file counter, shifting everything after it.
"""
import re

from ..github.hunks import iter_added_lines

_FLAGS = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
}

_COMPILED = {}


def compile_detector(detector):
    """Compile a detector's pattern, caching on (pattern, flags)."""
    key = (detector.pattern, detector.flags)
    rx = _COMPILED.get(key)
    if rx is None:
        flags = 0
        for name in detector.flags:
            flags |= _FLAGS[name]
        rx = re.compile(detector.pattern, flags)
        _COMPILED[key] = rx
    return rx


def added_lines(prfetch):
    """Yield (path, new_line_no, text) for every added line in the diff.

    Delegates to the single shared walker. Kept as a named function because it
    is the detector stage's vocabulary, but it must never grow its own walk
    again - see the module docstring.
    """
    return iter_added_lines(prfetch)


def finding(detector, path, line, text):
    return {
        "principle_id": detector.emits_principle_id,
        "detector_key": detector.key,
        "severity": detector.severity,
        "path": path,
        "line": line,
        "evidence": text.strip()[:200],
        "message": detector.message,
        "source": "detector",
        "confidence": "candidate",
    }


def run(rubric, prfetch):
    """Run every detector in `rubric` over `prfetch`; return candidates."""
    from . import globs

    findings = []
    selectable = {}
    for path, line, text in added_lines(prfetch):
        applicable = selectable.get(path)
        if applicable is None:
            applicable = [
                d for d in rubric.detectors
                if globs.path_selected(path, d.include_globs, d.exclude_globs)
            ]
            selectable[path] = applicable
        for detector in applicable:
            if compile_detector(detector).search(text):
                findings.append(finding(detector, path, line, text))
    return findings
