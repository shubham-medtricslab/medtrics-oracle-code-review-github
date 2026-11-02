#!/usr/bin/env python3
"""
The unified hunk walker - one implementation of diff line numbering.

v0.5.0 walked the same `unified_text` twice, differently. `detectors.py:29-35`
decided what an added line was and what line number it had;
`github_write.py:44-51` decided which line numbers GitHub would accept a comment
on. They disagreed, which is the worst possible shape for this bug: the detector
reports a finding at line N, the writer's commentable set was built with a
different walk, and the comment lands on the wrong line or is silently demoted
to the summary. Neither walk was right, and nothing compared them.

The three rules that matter, all of which v0.5.0 got wrong:

  1. GitHub's `patch` field contains NO file headers. It begins at the first
     `@@`. So a line beginning `+++` is not a header - it is an added line whose
     SOURCE begins `++`, which in TypeScript is a pre-increment and in C-family
     code generally is unremarkable. `github_write.py:45` skipped it without
     advancing the counter, so everything after it in the hunk was off by one
     and the hunk's last line fell out of the commentable set.

     The same applies to `---` on the removed side: a removed line whose source
     begins `--` (a SQL comment, a YAML list of negatives, a decrement) was
     skipped, desyncing old-side numbering.

  2. `.split("\\n")` on text ending in a newline yields a trailing `""`. It is
     not a diff line. v0.5.0 counted it as a context line.

  3. `\\ No newline at end of file` is diff metadata, not content. v0.5.0
     counted it as a context line too.

Together 2 and 3 put positions past the end of the hunk into the commentable
set, where `line_in_diff` approved them and GitHub rejected the whole review -
because `POST /pulls/{n}/reviews` is atomic.

Stdlib only.
"""
from typing import Iterator, Optional

__all__ = [
    "DiffLine", "walk_hunk", "walk_file_hunks", "commentable_lines",
    "iter_added_lines", "line_in_diff", "hunks_for_path",
]

# A hunk header. Safe as a bare prefix test because every CONTENT line in a
# unified diff carries a ' ', '+' or '-' marker, so content can never begin
# '@@' at column zero.
_HUNK_HEADER_PREFIX = "@@"

# '\ No newline at end of file'. Same reasoning: a content line always carries
# a marker, so a leading backslash at column zero is always this metadata.
_NO_NEWLINE_PREFIX = "\\"

DiffLine = dict  # see contracts/write_api.py: {path, new_line, old_line, kind, text}


def _hunk_lines(unified_text: str):
    """Split hunk text into real diff lines.

    Drops exactly one trailing empty token - the artifact of a terminating
    newline - and nothing else. An empty token in the MIDDLE of a hunk is a
    real context line: git writes an unmodified blank line as a single space,
    but several producers strip trailing whitespace in transit and it arrives
    as "". Treating those as context keeps numbering correct; treating the
    final one as content is bug 3.
    """
    lines = unified_text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def walk_hunk(unified_text: str, new_start: int, old_start: int,
              *, path: str = "") -> Iterator[DiffLine]:
    """Walk one hunk, yielding every line with correct new/old numbering.

    `unified_text` is one hunk: the `@@` header followed by its body, exactly
    as `github_retrieval.parse_patch` slices GitHub's `patch`. It contains no
    file headers, so none are skipped - see the module docstring.

    Removed lines advance `old_line` only, added lines advance `new_line` only,
    context lines advance both.
    """
    new_line = new_start
    old_line = old_start
    for raw in _hunk_lines(unified_text):
        if raw.startswith(_HUNK_HEADER_PREFIX):
            continue                      # structure, not content
        if raw.startswith(_NO_NEWLINE_PREFIX):
            continue                      # '\ No newline at end of file'
        if raw.startswith("+"):
            # NOT special-cased on '+++'. See rule 1.
            yield {"path": path, "new_line": new_line, "old_line": None,
                   "kind": "added", "text": raw[1:]}
            new_line += 1
        elif raw.startswith("-"):
            # NOT special-cased on '---'. See rule 1.
            yield {"path": path, "new_line": None, "old_line": old_line,
                   "kind": "removed", "text": raw[1:]}
            old_line += 1
        else:
            # Context. A leading space is the marker and is stripped; a bare
            # "" is a blank context line that lost its marker in transit.
            yield {"path": path, "new_line": new_line, "old_line": old_line,
                   "kind": "context", "text": raw[1:] if raw.startswith(" ") else raw}
            new_line += 1
            old_line += 1


def hunks_for_path(prfetch: dict, path: str):
    """Yield the hunk dicts belonging to `path`.

    Matches on `file_new_path` first: a rename reports the old path too, and a
    comment is positioned against the new file.
    """
    for d in prfetch.get("diffs", []) or []:
        p = d.get("file_new_path") or d.get("file_old_path")
        if p != path:
            continue
        for h in d.get("hunks", []) or []:
            yield h


def walk_file_hunks(prfetch: dict, path: str) -> Iterator[DiffLine]:
    """Every DiffLine for `path`, across all its hunks, in order."""
    for h in hunks_for_path(prfetch, path):
        new_range = h.get("line_range_new") or [0, 0]
        old_range = h.get("line_range_old") or [0, 0]
        yield from walk_hunk(h.get("unified_text", "") or "",
                             new_range[0], old_range[0], path=path)


def commentable_lines(prfetch: dict, path: str) -> set:
    """New-file line numbers GitHub will accept an inline comment on.

    Added and context lines only. Built from `walk_hunk`, so the writer and the
    detectors can no longer disagree.

    The result is additionally clamped to each hunk's declared new-side range.
    Correct walking already guarantees that, so the clamp only bites on a
    malformed `patch` - but the failure mode it guards is a 422 that destroys
    the entire review, so it is worth the four lines.
    """
    out = set()
    for h in hunks_for_path(prfetch, path):
        new_range = h.get("line_range_new") or [0, 0]
        old_range = h.get("line_range_old") or [0, 0]
        lo, hi = new_range[0], new_range[-1]
        for dl in walk_hunk(h.get("unified_text", "") or "",
                            new_range[0], old_range[0], path=path):
            n = dl["new_line"]
            if n is None or dl["kind"] == "removed":
                continue
            if lo <= n <= hi:
                out.add(n)
    return out


def line_in_diff(prfetch: dict, path: str, line) -> bool:
    """True when an inline comment on (path, line) is positionable."""
    if not path or not isinstance(line, int) or isinstance(line, bool):
        return False
    return line in commentable_lines(prfetch, path)


def iter_added_lines(prfetch: dict, path: Optional[str] = None):
    """Yield (path, new_line, text) for every ADDED line in the diff.

    The detector-facing view, deliberately built from the same walker rather
    than from a second hand-rolled loop. `detectors.py:20-35` is the function
    this replaces; keeping both would just recreate the divergence.
    """
    for d in prfetch.get("diffs", []) or []:
        p = d.get("file_new_path") or d.get("file_old_path")
        if path is not None and p != path:
            continue
        for h in d.get("hunks", []) or []:
            new_range = h.get("line_range_new") or [0, 0]
            old_range = h.get("line_range_old") or [0, 0]
            for dl in walk_hunk(h.get("unified_text", "") or "",
                                new_range[0], old_range[0], path=p):
                if dl["kind"] == "added":
                    yield p, dl["new_line"], dl["text"]
