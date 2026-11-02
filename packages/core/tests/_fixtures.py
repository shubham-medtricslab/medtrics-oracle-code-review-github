"""
Realistic GitHub `patch` payloads for the write-path tests.

These are real unified-diff strings of the shape GitHub returns from
`GET /repos/{repo}/pulls/{n}/files`. Two properties matter and are easy to lose
if you hand-build hunk dicts instead:

  - GitHub's `patch` contains NO `diff --git` / `index` / `+++` / `---` file
    headers. It starts at the first `@@`. So any line beginning `+++` in that
    text is an ordinary added line whose source happens to start with `++`.
  - The last hunk often ends with `\\ No newline at end of file`, and the
    string itself may end with a newline, which `.split("\\n")` turns into a
    trailing empty token.

Both are the substance of bugs 2 and 3.
"""
import re

_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_patch(patch):
    """Split a GitHub `patch` into hunk dicts.

    Mirrors `github_retrieval.parse_patch` in v0.5.0 so the fixtures exercise
    the same hunk shape the real pipeline produces. Test-only.
    """
    if not patch:
        return []
    hunks, cur = [], None
    for line in patch.split("\n"):
        m = _HUNK_HEADER.match(line)
        if m:
            if cur:
                hunks.append(cur)
            old_start, old_count = int(m.group(1)), int(m.group(2) or 1)
            new_start, new_count = int(m.group(3)), int(m.group(4) or 1)
            cur = {
                "line_range_old": [old_start, old_start + max(old_count - 1, 0)],
                "line_range_new": [new_start, new_start + max(new_count - 1, 0)],
                "unified_text": line,
            }
        elif cur is not None:
            cur["unified_text"] += "\n" + line
    if cur:
        hunks.append(cur)
    return hunks


def prfetch(*files, head="a" * 40, base="b" * 40, repo="acme/widgets", pr=42):
    """Build a PRFetch from (path, patch) pairs."""
    return {
        "repo": repo,
        "pr_number": pr,
        "shas": {"base": base, "head": head},
        "diffs": [
            {
                "file_old_path": path,
                "file_new_path": path,
                "change_kind": "modified",
                "is_binary": False,
                "hunks": parse_patch(patch),
            }
            for path, patch in files
        ],
    }


HEAD_SHA = "a" * 40
OTHER_SHA = "c" * 40

# --------------------------------------------------------------------------- #
# BUG 2: an added line whose SOURCE begins '++'. Nothing exotic - a C-style
# pre-increment, which is ordinary in TS. v0.5.0's writer skips it WITHOUT
# advancing, so every line after it in the hunk is off by one and the last line
# of the hunk falls out of the commentable set entirely.
# --------------------------------------------------------------------------- #
PLUSPLUS_PATH = "src/domains/forms/services/retry.service.ts"
PLUSPLUS_PATCH = """\
@@ -40,3 +40,6 @@ export async function withRetry(fn: () => Promise<void>) {
   const a = 1;
+++attempts;
+  const b = 2;
+  const c = 3;
   const d = 4;
   return a;"""
# new lines 40..45:
#   40 context '  const a = 1;'
#   41 added   '++attempts;'
#   42 added   '  const b = 2;'
#   43 added   '  const c = 3;'
#   44 context '  const d = 4;'
#   45 context '  return a;'
PLUSPLUS_COMMENTABLE = {40, 41, 42, 43, 44, 45}
PLUSPLUS_ADDED = {41: "++attempts;", 42: "  const b = 2;", 43: "  const c = 3;"}

# The mirror image: an added line whose source begins '---'. A markdown
# horizontal rule or a YAML document separator does this constantly.
MINUSMINUS_PATH = "docs/runbook.md"
MINUSMINUS_PATCH = """\
@@ -1,2 +1,5 @@
 # Runbook
+---
+## Rollback
+Call the on-call.
 Done."""
MINUSMINUS_COMMENTABLE = {1, 2, 3, 4, 5}

# --------------------------------------------------------------------------- #
# BUG 3: phantom trailing lines. The '\\ No newline at end of file' marker and
# the trailing empty token from .split("\\n") both enter the commentable set in
# v0.5.0 and both advance the counter, so line_in_diff() approves positions past
# the end of the hunk that GitHub then rejects.
# --------------------------------------------------------------------------- #
NONEWLINE_PATH = "src/config/flags.ts"
NONEWLINE_PATCH = (
    "@@ -1,2 +1,3 @@\n"
    " export const FLAGS = {\n"
    "+  betaDashboard: true,\n"
    " };\n"
    "\\ No newline at end of file\n"
)
NONEWLINE_COMMENTABLE = {1, 2, 3}

# --------------------------------------------------------------------------- #
# A well-behaved multi-hunk patch with removals, for the "nothing regressed"
# baseline and for old/new numbering.
# --------------------------------------------------------------------------- #
ORDINARY_PATH = "src/domains/groups/services/groups.service.ts"
ORDINARY_PATCH = """\
@@ -10,5 +10,7 @@ export class GroupsService {
   constructor(private db: Db) {}
 
-  async list(): Promise<Group[]> {
-    return this.db.select('*');
+  async list(): Promise<Group[]> {
+    return this.db.select('id, name');
+  }
+
   }
@@ -80,2 +81,3 @@ export class GroupsService {
   async remove(id: string) {
+    return this.db.delete(id).is('deleted_at', null);
   }"""

# Pure deletion: the new-side count is zero, so there is nothing commentable.
DELETION_PATH = "src/legacy/old.ts"
DELETION_PATCH = """\
@@ -5,3 +4,0 @@ const x = 1;
-const gone1 = 1;
-const gone2 = 2;
-const gone3 = 3;"""


def plusplus_pr():
    return prfetch((PLUSPLUS_PATH, PLUSPLUS_PATCH))


def nonewline_pr():
    return prfetch((NONEWLINE_PATH, NONEWLINE_PATCH))


def ordinary_pr():
    return prfetch((ORDINARY_PATH, ORDINARY_PATCH))


def mixed_pr():
    return prfetch(
        (PLUSPLUS_PATH, PLUSPLUS_PATCH),
        (NONEWLINE_PATH, NONEWLINE_PATCH),
        (ORDINARY_PATH, ORDINARY_PATCH),
        (DELETION_PATH, DELETION_PATCH),
        (MINUSMINUS_PATH, MINUSMINUS_PATCH),
    )
