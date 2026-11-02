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

The one behavioural change is that `exclude_globs` is honoured, which is what
makes FA-010 stop firing on `*.service.ts`.
"""
import re

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
    """Yield (path, new_line_no, text) for every added line in the diff."""
    for diff in prfetch.get("diffs", []):
        path = diff.get("file_new_path") or diff.get("file_old_path")
        for hunk in diff.get("hunks", []):
            new_no = (hunk.get("line_range_new") or [0, 0])[0]
            for raw in (hunk.get("unified_text") or "").split("\n"):
                if raw.startswith("@@"):
                    continue
                if raw.startswith("+") and not raw.startswith("+++"):
                    yield path, new_no, raw[1:]
                    new_no += 1
                elif raw.startswith("-") and not raw.startswith("---"):
                    continue
                else:
                    new_no += 1


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
