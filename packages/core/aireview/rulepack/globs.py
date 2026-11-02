"""
Path glob matching for rulepack `include_globs` / `exclude_globs`.

`fnmatch` is not usable here: its `*` happily crosses `/`, so `**/*.service.ts`
and `*.service.ts` would mean the same thing and `src/a/*.ts` would match
`src/a/b/c.ts`. Getting that wrong matters directly - `exclude_globs` is the
mechanism that stops FA-010 firing on the one file kind its own rule permits,
so an over-broad `*` would silently re-introduce the bug it was added to fix.

Semantics, chosen to match what people expect from .gitignore / ripgrep:

  `**/`  zero or more leading path segments, so `**/*.ts` matches `a.ts`
         as well as `src/a.ts`
  `**`   anything, including `/`
  `*`    anything except `/`
  `?`    one character except `/`
  `[..]` character class, `!` or `^` negates

Paths are normalised to forward slashes with no leading `./` or `/` before
matching, so a diff path and a glob can never miss each other on punctuation.
"""
import re

_CACHE = {}


def normalize(path):
    """Normalise a repo-relative path for matching."""
    if not path:
        return ""
    p = path.replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def translate(pattern):
    """Translate a glob into an anchored regex string."""
    i, n = 0, len(pattern)
    out = []
    while i < n:
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 3] == "**/":
                out.append("(?:[^/]+/)*")
                i += 3
                continue
            if pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
            continue
        if c == "?":
            out.append("[^/]")
            i += 1
            continue
        if c == "[":
            j = i + 1
            if j < n and pattern[j] in "!^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                out.append(re.escape("["))
                i += 1
                continue
            inner = pattern[i + 1:j]
            if inner.startswith("!"):
                inner = "^" + inner[1:]
            out.append("[" + inner + "]")
            i = j + 1
            continue
        out.append(re.escape(c))
        i += 1
    return "".join(out) + r"\Z"


def compile_glob(pattern):
    rx = _CACHE.get(pattern)
    if rx is None:
        rx = re.compile(translate(pattern))
        _CACHE[pattern] = rx
    return rx


def match(path, pattern):
    return compile_glob(pattern).match(normalize(path)) is not None


def match_any(path, patterns):
    """True if `path` matches at least one pattern. Empty list -> False."""
    norm = normalize(path)
    for p in patterns or ():
        if compile_glob(p).match(norm):
            return True
    return False


def path_selected(path, include_globs, exclude_globs):
    """
    Apply the rulepack include/exclude contract.

    An absent or empty `include_globs` means "every path", matching the
    schema's "Path must match at least one" being vacuous when there are none.
    `exclude_globs` always wins.
    """
    if include_globs and not match_any(path, include_globs):
        return False
    if exclude_globs and match_any(path, exclude_globs):
        return False
    return True
