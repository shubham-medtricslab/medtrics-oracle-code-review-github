#!/usr/bin/env python3
"""
A deliberately small, strict YAML-subset parser.

Why this exists at all: `packages/core` is stdlib-only (enforced by
`tools/stdlib_lint.py`), and the Python standard library has no YAML parser.
The review config that repos actually write is `.github/ai-review.yml`, so
*something* has to turn YAML into JSON before core ever sees it. Doing that
translation here, in the Actions layer, also puts it on the right side of the
trust boundary: the action is the component that decides *which ref* the config
is read from and which keys a repo is allowed to set. Core just receives an
already-resolved JSON document.

The alternative -- `pip install pyyaml` on the runner -- was rejected. It adds a
dependency-resolution failure mode and a supply-chain surface to the one job
that handles untrusted pull requests, in exchange for parsing a config file
whose grammar is a dozen lines of flat keys.

Supported subset, and nothing else:

    key: scalar                 mappings with scalar values
    key:                        nested block mapping / block sequence
      nested: value
    key:                        block sequence of scalars
      - one
      - two
    key: [one, two]             flow sequence of scalars
    - key: value                mapping inside a sequence item
    # comment                   full-line and trailing comments
    scalars                     'single' / "double" quoted, bare, int, float,
                                true/false/yes/no/on/off, null/~/empty

Deliberately rejected, with an error rather than a guess:

    &anchors, *aliases, !!tags, << merge keys, multi-document streams,
    block scalars (| and >), flow mappings ({a: b}), tab indentation,
    duplicate keys.

Duplicate keys are an error on purpose. In a file whose whole job is to express
policy, "the last one silently wins" is a way to smuggle an override past a
reviewer skimming the diff.

Resource limits are hard-coded (see MAX_*). The config is read from the base
ref, so it is maintainer-controlled rather than PR-author-controlled, but
"trusted" is not the same as "well-formed" and this parser must not be a way to
hang the runner.
"""
from __future__ import annotations

MAX_BYTES = 256 * 1024
MAX_LINES = 2_000
MAX_DEPTH = 8
MAX_LINE_CHARS = 8_192

_TRUE = {"true", "yes", "on"}
_FALSE = {"false", "no", "off"}
_NULL = {"", "null", "~"}

_REJECTED_PREFIXES = (
    ("&", "YAML anchors are not supported"),
    ("*", "YAML aliases are not supported"),
    ("!", "YAML tags are not supported"),
    ("{", "flow mappings are not supported; use a block mapping"),
    ("|", "block scalars are not supported"),
    (">", "block scalars are not supported"),
)


class YamlError(ValueError):
    """Raised for anything outside the supported subset. Never a silent guess."""

    def __init__(self, message: str, line_no: int | None = None):
        self.line_no = line_no
        if line_no is not None:
            message = f"line {line_no}: {message}"
        super().__init__(message)


# --------------------------------------------------------------------------- #
# Lexing
# --------------------------------------------------------------------------- #
def _strip_comment(raw: str) -> str:
    """Remove a trailing `#` comment, respecting quotes.

    A `#` only starts a comment at the start of the (stripped) line or when
    preceded by whitespace. `url: http://x#y` is therefore not a comment.
    """
    out: list[str] = []
    quote: str | None = None
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        if quote is not None:
            if quote == '"' and ch == "\\" and i + 1 < n:
                out.append(ch)
                out.append(raw[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            out.append(ch)
        elif ch in ("'", '"'):
            quote = ch
            out.append(ch)
        elif ch == "#" and (i == 0 or raw[i - 1] in " \t"):
            break
        else:
            out.append(ch)
        i += 1
    if quote is not None:
        raise YamlError("unterminated quoted string")
    return "".join(out).rstrip()


def _lex(text: str) -> list[tuple[int, str, int]]:
    """-> [(indent, content, line_no)], blanks and comment-only lines removed."""
    lines: list[tuple[int, str, int]] = []
    for line_no, raw in enumerate(text.split("\n"), start=1):
        if len(raw) > MAX_LINE_CHARS:
            raise YamlError(f"line exceeds {MAX_LINE_CHARS} characters", line_no)
        if "\t" in raw[: len(raw) - len(raw.lstrip(" \t"))]:
            raise YamlError("tab indentation is not supported; use spaces", line_no)
        stripped = raw.strip()
        if stripped in ("---", "..."):
            # A single leading document marker is harmless; anything else means
            # a multi-document stream, which this parser will not guess at.
            if any(c for _, c, _ in lines):
                raise YamlError("multi-document YAML is not supported", line_no)
            continue
        try:
            content = _strip_comment(raw)
        except YamlError as exc:
            raise YamlError(str(exc), line_no) from None
        if not content.strip():
            continue
        indent = len(content) - len(content.lstrip(" "))
        lines.append((indent, content.strip(), line_no))
    return lines


# --------------------------------------------------------------------------- #
# Scalars
# --------------------------------------------------------------------------- #
def _unescape_double(body: str, line_no: int) -> str:
    out: list[str] = []
    i = 0
    simple = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/", "0": "\0"}
    while i < len(body):
        ch = body[i]
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        if i + 1 >= len(body):
            raise YamlError("trailing backslash in double-quoted string", line_no)
        nxt = body[i + 1]
        if nxt in simple:
            out.append(simple[nxt])
            i += 2
        elif nxt == "u" and i + 5 < len(body) + 1:
            hexpart = body[i + 2 : i + 6]
            if len(hexpart) != 4 or any(c not in "0123456789abcdefABCDEF" for c in hexpart):
                raise YamlError("malformed \\u escape", line_no)
            out.append(chr(int(hexpart, 16)))
            i += 6
        else:
            raise YamlError(f"unsupported escape '\\{nxt}'", line_no)
    return "".join(out)


def parse_scalar(token: str, line_no: int = 0):
    """Parse one scalar. Quoted strings stay strings; bare tokens are typed."""
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ("'", '"'):
        body = token[1:-1]
        if token[0] == "'":
            return body.replace("''", "'")
        return _unescape_double(body, line_no)

    for prefix, why in _REJECTED_PREFIXES:
        if token.startswith(prefix):
            raise YamlError(why, line_no)

    low = token.lower()
    if low in _NULL:
        return None
    if low in _TRUE:
        return True
    if low in _FALSE:
        return False
    try:
        return int(token, 10)
    except ValueError:
        pass
    try:
        # Reject inf/nan spellings; they are never meaningful in this config.
        if low in ("inf", "-inf", "+inf", "nan", ".inf", "-.inf", ".nan"):
            raise ValueError
        return float(token)
    except ValueError:
        pass
    return token


def _split_key(content: str, line_no: int) -> tuple[str, str] | None:
    """Split `key: rest` at the first quote-aware `:` followed by space or EOL."""
    quote: str | None = None
    i = 0
    n = len(content)
    while i < n:
        ch = content[i]
        if quote is not None:
            if quote == '"' and ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == ":" and (i + 1 == n or content[i + 1] in " \t"):
            key_tok = content[:i].strip()
            if not key_tok:
                raise YamlError("empty mapping key", line_no)
            key = parse_scalar(key_tok, line_no)
            if not isinstance(key, str):
                key = str(key).lower() if isinstance(key, bool) else str(key)
            if key.startswith("<<"):
                raise YamlError("merge keys are not supported", line_no)
            return key, content[i + 1 :].strip()
        i += 1
    return None


def _parse_flow_sequence(token: str, line_no: int) -> list:
    inner = token[1:-1].strip()
    if not inner:
        return []
    items: list = []
    buf: list[str] = []
    quote: str | None = None
    for ch in inner:
        if quote is not None:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == ",":
            items.append(parse_scalar("".join(buf), line_no))
            buf = []
        elif ch in "[]{}":
            raise YamlError("nested flow collections are not supported", line_no)
        else:
            buf.append(ch)
    if quote is not None:
        raise YamlError("unterminated quoted string in flow sequence", line_no)
    items.append(parse_scalar("".join(buf), line_no))
    return items


def _parse_value_token(token: str, line_no: int):
    token = token.strip()
    if token.startswith("[") and token.endswith("]"):
        return _parse_flow_sequence(token, line_no)
    if token.startswith("[") or token.endswith("]"):
        raise YamlError("malformed flow sequence", line_no)
    return parse_scalar(token, line_no)


# --------------------------------------------------------------------------- #
# Block parsing
# --------------------------------------------------------------------------- #
def _parse_block(lines, idx: int, indent: int, depth: int):
    if depth > MAX_DEPTH:
        raise YamlError(f"nesting deeper than {MAX_DEPTH} levels", lines[idx][2])
    if lines[idx][1].startswith("- ") or lines[idx][1] == "-":
        return _parse_sequence(lines, idx, indent, depth)
    return _parse_mapping(lines, idx, indent, depth)


def _parse_mapping(lines, idx: int, indent: int, depth: int):
    result: dict = {}
    while idx < len(lines):
        cur_indent, content, line_no = lines[idx]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise YamlError("unexpected indentation", line_no)
        if content.startswith("- ") or content == "-":
            raise YamlError("sequence item where a mapping key was expected", line_no)
        split = _split_key(content, line_no)
        if split is None:
            raise YamlError(f"expected 'key: value', got {content!r}", line_no)
        key, rest = split
        if key in result:
            raise YamlError(f"duplicate key {key!r}", line_no)
        if rest:
            result[key] = _parse_value_token(rest, line_no)
            idx += 1
            continue
        # Empty value: either a nested block or an explicit null.
        if idx + 1 < len(lines) and lines[idx + 1][0] > cur_indent:
            value, idx = _parse_block(lines, idx + 1, lines[idx + 1][0], depth + 1)
            result[key] = value
        else:
            result[key] = None
            idx += 1
    return result, idx


def _parse_sequence(lines, idx: int, indent: int, depth: int):
    result: list = []
    while idx < len(lines):
        cur_indent, content, line_no = lines[idx]
        if cur_indent < indent:
            break
        if cur_indent > indent:
            raise YamlError("unexpected indentation", line_no)
        if not (content.startswith("- ") or content == "-"):
            break
        item = content[1:].strip()
        if not item:
            if idx + 1 < len(lines) and lines[idx + 1][0] > cur_indent:
                value, idx = _parse_block(lines, idx + 1, lines[idx + 1][0], depth + 1)
                result.append(value)
            else:
                result.append(None)
                idx += 1
            continue
        split = _split_key(item, line_no)
        if split is not None:
            # `- key: value` -- a mapping whose first key shares this line. Its
            # continuation keys are indented past the dash.
            inner_indent = cur_indent + 2
            synthetic = [(inner_indent, item, line_no)]
            j = idx + 1
            while j < len(lines) and lines[j][0] >= inner_indent:
                synthetic.append(lines[j])
                j += 1
            value, consumed = _parse_mapping(synthetic, 0, inner_indent, depth + 1)
            if consumed != len(synthetic):
                raise YamlError("unexpected content in sequence item", lines[idx][2])
            result.append(value)
            idx = j
            continue
        result.append(_parse_value_token(item, line_no))
        idx += 1
    return result, idx


def parse(text: str):
    """Parse a document in the supported subset. Returns dict / list / scalar."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise YamlError(f"config exceeds {MAX_BYTES} bytes")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = _lex(text)
    if len(lines) > MAX_LINES:
        raise YamlError(f"config exceeds {MAX_LINES} significant lines")
    if not lines:
        return {}
    base_indent = lines[0][0]
    if base_indent != 0:
        raise YamlError("document must start at column 0", lines[0][2])
    value, idx = _parse_block(lines, 0, 0, 1)
    if idx != len(lines):
        raise YamlError("trailing content could not be parsed", lines[idx][2])
    return value


if __name__ == "__main__":  # pragma: no cover - debugging aid
    import json
    import sys

    with open(sys.argv[1], encoding="utf-8") as fh:
        print(json.dumps(parse(fh.read()), indent=2, sort_keys=True))
