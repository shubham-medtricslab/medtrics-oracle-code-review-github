# ai-code-review

Repo-agnostic AI code review, distributed as a **reusable GitHub Actions workflow**.
Derived from `medtrics-oracle-code-review` v0.5.0, de-coupled from the Oracle stack
and hardened for unattended execution against untrusted pull requests.

## Design spine

**The parent drives; the LLM is a leaf.** `packages/core` runs the deterministic
stages (config → fetch → checkout → segment → detect → dedup → validate → report
→ post) and spawns one `claude` process per reviewer surface. The agent never
drives control flow, never holds a GitHub token, and its output is treated as
data the parent validates — never as instructions.

**The workspace is hostile to the parent, not just to the agent.** Everything read
from the checkout is attacker-controlled: `.env`, `.git/config`, `.claude/`,
`.mcp.json`, and the review config itself.

**The merge gate is the check-run conclusion, not a review.** Reviews are posted
as `COMMENT` only. There is no `APPROVE` path, by design — a GitHub App's approval
counts toward `required_approving_review_count`, so the bot must never be able to
satisfy a human-review requirement.

## Verified runtime facts

Established by spike against Claude Code **v2.1.175**, not assumed:

- The sub-agent tool is named **`Agent`**, not `Task`. (v0.5.0's
  `review-orchestrator` says "Task tool"; that name is stale.)
- There are **18 detectors**, not 17. `detectors.py:58` has 18 entries that
  collapse to 17 distinct emitted IDs *because of* the `FA-009b` collision at
  `detectors.py:104`. The familiar "17" was a symptom of the bug, and v0.5.0 had
  no detector parity assertion of any kind to catch it.
- `--tools "Read,Grep,Glob"` **genuinely restricts** the tool set — a dispatch
  attempt returns BLOCKED with no permission denial. This is the hardening
  primitive.
- `--restricted` and `--permission-prompts` **do not exist** in this version. Use
  `--tools` plus `--permission-mode dontAsk`.
- `--bare` requires `ANTHROPIC_API_KEY`; it does not read subscription login or
  the keychain, and fails `Not logged in` without one.
- A result can carry `is_error: true` while `subtype: "success"`. Callers must
  check `is_error`, never the exit code alone.

## Frozen contracts

Under `contracts/`. **Children consume these; only the lead changes them.**

| Contract | What it fixes |
|---|---|
| `run-record.schema.json` | The single artifact the pipeline emits. No `approve` verdict. Truncation and partial dimensions are first-class. |
| `rulepack.schema.json` | Declarative rules + detectors. `emits_principle_id` is explicit (fixes the `FA-009b` collision); `exclude_globs` exists (fixes inverted `FA-010`). |
| `write_api.py` | One shared hunk walker, the output validator, content-anchored dedup, atomic-422 degradation. |
| `golden-rubric.tsv` | All 374 rules fully materialized. Replaces `rubric.py parity`, which asserted only counts. |
| `parity-breaks.tsv` | The only tolerated deviations from the golden snapshot. |

## Ownership while the batch runs

`packages/core/` and `contracts/` belong to the **lead**. Children consume them
and must not edit them. If a contract is wrong, say so — do not work around it.

| Area | Owner |
|---|---|
| `rulepacks/` | `rulepack-migration` |
| `packages/core/aireview/github/`, dedup | `write-path-hardening` |
| `action/`, `.github/workflows/` | `actions-packaging` |

## Checks

```bash
python3 tools/stdlib_lint.py packages/core
python3 tools/golden_snapshot.py verify --legacy ../medtrics-oracle-code-review
```
