#!/usr/bin/env python3
"""
Create, complete and reap the check run that gates merges.

The single invariant this file exists to uphold:

    NO CODE PATH MAY LEAVE A CHECK RUN `in_progress`.

A required check stuck pending blocks merging on every open pull request. That
is a far worse outage than a missing review, and it is the failure mode that
happens by accident -- a cancelled job, a killed runner, an API 500 on the final
PATCH. So `complete` is written defensively, in four descending tiers:

    1. PATCH the rich payload (summary, text, annotations).
    2. On 422, PATCH again with output omitted. Oversized or malformed output
       is the likeliest cause of a rejected update, and the conclusion matters
       more than the prose.
    3. If there is no check-run id -- because creation itself failed -- POST a
       new run that is already `completed`. A late check beats a missing gate.
    4. Exit non-zero and say exactly what is stuck, so the scheduled reaper
       (see action/examples/reaper-workflow.yml) can finish the job.

`reap` is the other half of that guarantee: it finds `in_progress` runs for a
SHA and completes them. It is used by the `closed` trigger, so a pull request
merged or abandoned mid-review leaves nothing dangling, and by the optional
scheduled sweeper for runs whose runner died outright.

Subcommands
-----------
  create    POST an in_progress run; emit its id to $GITHUB_OUTPUT
  complete  render from a run record and PATCH the run to completed
  reap      complete any in_progress runs with this name on this SHA

Exit codes: 0 ok, 1 nothing to do, 2 the check could not be completed.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import gh  # noqa: E402
import render_summary  # noqa: E402

MAX_ANNOTATIONS_PER_REQUEST = render_summary.MAX_ANNOTATIONS_PER_REQUEST


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _token() -> str:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        print("check_run: GITHUB_TOKEN is not set", file=sys.stderr)
        raise SystemExit(2)
    return token


def _emit_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"{name}={value}\n")


# --------------------------------------------------------------------------- #
# create
# --------------------------------------------------------------------------- #
def cmd_create(args) -> int:
    owner, name = gh.split_repo(args.repo)
    payload = {
        "name": args.name,
        "head_sha": args.sha,
        "status": "in_progress",
        "started_at": _now(),
        "output": {
            "title": "Review queued",
            "summary": (
                "The AI reviewer has started. This check reports `neutral` unless the "
                "repository has opted into blocking mode, and it always completes - a "
                "check left pending would block merges, which is worse than no review."
            ),
        },
    }
    if args.details_url:
        payload["details_url"] = args.details_url

    try:
        body = gh.request(
            "POST", f"/repos/{owner}/{name}/check-runs", token=_token(), payload=payload
        )
    except gh.GitHubError as exc:
        # Creation failing is survivable: `complete` falls back to POSTing an
        # already-completed run. Do not fail the job over it.
        print(f"check_run: could not create check run ({exc}); {exc.body[:500]}", file=sys.stderr)
        _emit_output("check_run_id", "")
        return 1

    check_id = str(body.get("id", ""))
    print(f"check_run: created {check_id} for {args.sha[:7]}")
    _emit_output("check_run_id", check_id)
    return 0


# --------------------------------------------------------------------------- #
# complete
# --------------------------------------------------------------------------- #
def _patch_complete(owner, repo_name, check_id, token, conclusion, output=None) -> None:
    payload = {
        "status": "completed",
        "conclusion": conclusion,
        "completed_at": _now(),
    }
    if output is not None:
        payload["output"] = output
    gh.request(
        "PATCH",
        f"/repos/{owner}/{repo_name}/check-runs/{check_id}",
        token=token,
        payload=payload,
    )


def _post_completed(owner, repo_name, token, name, sha, conclusion, output, details_url) -> int:
    payload = {
        "name": name,
        "head_sha": sha,
        "status": "completed",
        "conclusion": conclusion,
        "completed_at": _now(),
        "output": output,
    }
    if details_url:
        payload["details_url"] = details_url
    body = gh.request(
        "POST", f"/repos/{owner}/{repo_name}/check-runs", token=token, payload=payload
    )
    return int(body.get("id", 0))


def _push_extra_annotations(owner, repo_name, check_id, token, title, summary, annotations):
    """Annotations cap at 50 per request, so the rest go in follow-up PATCHes.

    Best effort by definition: the check is already completed at this point, so
    a failure here costs detail, not the merge gate.
    """
    for start in range(MAX_ANNOTATIONS_PER_REQUEST, len(annotations), MAX_ANNOTATIONS_PER_REQUEST):
        batch = annotations[start : start + MAX_ANNOTATIONS_PER_REQUEST]
        try:
            gh.request(
                "PATCH",
                f"/repos/{owner}/{repo_name}/check-runs/{check_id}",
                token=token,
                payload={
                    "output": {"title": title, "summary": summary, "annotations": batch}
                },
                attempts=2,
            )
        except gh.GitHubError as exc:
            print(f"check_run: extra annotations batch failed ({exc})", file=sys.stderr)
            return


def cmd_complete(args) -> int:
    owner, repo_name = gh.split_repo(args.repo)
    token = _token()

    record = _load_json(args.run_record)
    notes = _load_json(args.notes)
    outcome = args.outcome
    if outcome == "ok" and not isinstance(record, dict):
        print(
            "check_run: outcome 'ok' but no readable run record; reporting as unavailable",
            file=sys.stderr,
        )
        outcome = "agent_failed"

    rendered = render_summary.render(
        outcome,
        record,
        notes,
        {
            "blocking": _bool(args.blocking),
            "dry_run": _bool(args.dry_run),
            "run_url": args.run_url,
            "failure_detail": args.failure_detail,
        },
    )
    conclusion = rendered["conclusion"]
    annotations = rendered["annotations"]
    output = {
        "title": rendered["title"],
        "summary": rendered["summary"],
    }
    if rendered["text"]:
        output["text"] = rendered["text"]
    if annotations:
        output["annotations"] = annotations[:MAX_ANNOTATIONS_PER_REQUEST]

    _emit_output("conclusion", conclusion)
    _emit_output("verdict", rendered.get("verdict") or "")

    check_id = (args.check_run_id or "").strip()

    # Tier 1: the rich payload.
    if check_id:
        try:
            _patch_complete(owner, repo_name, check_id, token, conclusion, output)
            print(f"check_run: completed {check_id} as {conclusion}")
            if len(annotations) > MAX_ANNOTATIONS_PER_REQUEST:
                _push_extra_annotations(
                    owner, repo_name, check_id, token,
                    rendered["title"], rendered["summary"], annotations,
                )
            return 0
        except gh.GitHubError as exc:
            print(
                f"check_run: rich completion rejected ({exc}); {exc.body[:500]}",
                file=sys.stderr,
            )

        # Tier 2: conclusion only. The gate matters more than the prose.
        try:
            _patch_complete(owner, repo_name, check_id, token, conclusion, None)
            print(f"check_run: completed {check_id} as {conclusion} (output dropped)")
            return 0
        except gh.GitHubError as exc:
            print(f"check_run: bare completion also failed ({exc})", file=sys.stderr)

    # Tier 3: no usable id, or both PATCHes failed. Post a run that is already
    # completed so the gate exists at all.
    if args.name and args.sha:
        try:
            new_id = _post_completed(
                owner, repo_name, token, args.name, args.sha, conclusion, output, args.run_url
            )
            print(f"check_run: posted completed run {new_id} as {conclusion} (fallback)")
            return 0
        except gh.GitHubError as exc:
            print(f"check_run: fallback completed-run POST failed ({exc})", file=sys.stderr)

    # Tier 4: loud failure. Name exactly what is stuck.
    print(
        "check_run: COULD NOT COMPLETE THE CHECK RUN. "
        f"repo={args.repo} sha={args.sha} id={check_id or '-'} "
        f"intended_conclusion={conclusion}. "
        "If a check run is stuck in_progress, run the reaper workflow.",
        file=sys.stderr,
    )
    return 2


# --------------------------------------------------------------------------- #
# reap
# --------------------------------------------------------------------------- #
def cmd_reap(args) -> int:
    owner, repo_name = gh.split_repo(args.repo)
    token = _token()
    try:
        body = gh.request(
            "GET",
            f"/repos/{owner}/{repo_name}/commits/{args.sha}/check-runs"
            f"?check_name={args.name}&per_page=100",
            token=token,
        )
    except gh.GitHubError as exc:
        print(f"check_run: could not list check runs ({exc})", file=sys.stderr)
        return 2

    stale = [
        run
        for run in body.get("check_runs", [])
        if run.get("status") in ("queued", "in_progress")
    ]
    if not stale:
        print(f"check_run: nothing to reap for {args.sha[:7]}")
        return 1

    failures = 0
    for run in stale:
        output = {
            "title": args.title,
            "summary": args.summary,
        }
        try:
            _patch_complete(owner, repo_name, run["id"], token, args.conclusion, output)
            print(f"check_run: reaped {run['id']} as {args.conclusion}")
        except gh.GitHubError as exc:
            failures += 1
            print(f"check_run: could not reap {run['id']} ({exc})", file=sys.stderr)
    return 2 if failures else 0


# --------------------------------------------------------------------------- #
def _bool(value) -> bool:
    return str(value).strip().lower() in ("true", "1", "yes", "on")


def _load_json(path):
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"check_run: could not read {path}: {exc}", file=sys.stderr)
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check-run lifecycle for the AI reviewer.")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create", help="create an in_progress check run")
    create.add_argument("--repo", required=True)
    create.add_argument("--sha", required=True)
    create.add_argument("--name", required=True)
    create.add_argument("--details-url", default="")
    create.set_defaults(func=cmd_create)

    complete = sub.add_parser("complete", help="complete the check run from a run record")
    complete.add_argument("--repo", required=True)
    complete.add_argument("--check-run-id", default="")
    complete.add_argument("--name", default="", help="for the fallback completed-run POST")
    complete.add_argument("--sha", default="", help="for the fallback completed-run POST")
    complete.add_argument("--outcome", required=True, choices=list(render_summary.OUTCOMES))
    complete.add_argument("--run-record", default="")
    complete.add_argument("--notes", default="")
    complete.add_argument("--blocking", default="false")
    complete.add_argument("--dry-run", default="true")
    complete.add_argument("--run-url", default="")
    complete.add_argument("--failure-detail", default="")
    complete.set_defaults(func=cmd_complete)

    reap = sub.add_parser("reap", help="complete any in_progress runs for a SHA")
    reap.add_argument("--repo", required=True)
    reap.add_argument("--sha", required=True)
    reap.add_argument("--name", required=True)
    reap.add_argument("--conclusion", default="neutral", choices=["neutral", "skipped"])
    reap.add_argument("--title", default="Review did not complete")
    reap.add_argument(
        "--summary",
        default=(
            "This review run ended without completing its check. The check was closed "
            "as `neutral` so it cannot block merging."
        ),
    )
    reap.set_defaults(func=cmd_reap)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
