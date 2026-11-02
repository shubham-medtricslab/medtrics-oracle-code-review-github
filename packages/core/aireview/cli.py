#!/usr/bin/env python3
"""
`aireview` - three-phase CLI.

The split into `fetch` / `review` / `post` is a security boundary, not
ergonomics. It makes "the agent never holds a GitHub token" a property of the
process tree rather than a convention:

    fetch   GITHUB_TOKEN        no agent
    review  ANTHROPIC_API_KEY   agent runs here, no GitHub credential exists
    post    GITHUB_TOKEN        no agent

A prompt-injection payload that fully controls the agent still cannot reach a
GitHub credential, because there is none in that process. It also means the
installation token is minted immediately before `post` rather than being held
for the whole run, which matters because installation tokens expire after an
hour and a slow review would otherwise post with a dead token.

Exit codes:
    0  success
    1  policy refusal (disabled, kill switch, over caps) - NOT an error;
       the caller should conclude the check run `neutral`
    2  genuine failure

Stdlib only.
"""
import argparse
import json
import os
import sys

from . import auth
from .config import ConfigError, load_layered

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_FAILED = 2


def _load_json(path):
    if path == "-":
        return json.load(sys.stdin)
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path, payload):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)
    return path


def _resolve_config(path):
    """Read the action-supplied config envelope and resolve it through core.

    The envelope carries `repo_layer_source` because core treats it as
    load-bearing: a `pr-head` layer is parsed for reporting but never applied.
    Enforcement lives here rather than in the action so there is exactly one
    tested implementation of the trust split.
    """
    if not path:
        return load_layered()
    envelope = _load_json(path)
    if not isinstance(envelope, dict):
        raise ConfigError("config envelope must be a JSON object")
    source = envelope.get("repo_layer_source", "pr-head")
    if source not in ("base-ref", "pr-head"):
        raise ConfigError(f"repo_layer_source must be base-ref or pr-head, got {source!r}")
    return load_layered(
        org_layer=envelope.get("org_layer"),
        repo_layer=envelope.get("repo_layer"),
        repo_layer_source=source,
        strict=False,   # one malformed repo file must not take the reviewer offline
    )


# --------------------------------------------------------------------------- #
# fetch
# --------------------------------------------------------------------------- #
def cmd_fetch(args):
    """Retrieve the PR and write prfetch.json + allowed_paths.json.

    `allowed_paths.json` is the exact set of files GitHub reports as changed. It
    is the allowlist the output validator checks every finding's `path` against,
    so it must come from the API and never from agent output.
    """
    from .github.retrieval import fetch_pr  # owned by write-path-hardening

    provider = auth.EnvToken("GITHUB_TOKEN")
    _, endpoint = auth.resolve(token_provider=provider,
                               api_base_url=args.api_url)

    prfetch = fetch_pr(repo=args.repo, number=args.pr,
                       token_provider=provider, endpoint=endpoint)

    os.makedirs(args.out, exist_ok=True)
    _write_json(os.path.join(args.out, "prfetch.json"), prfetch)
    allowed = sorted({
        d.get("file_new_path") or d.get("file_old_path")
        for d in prfetch.get("diffs", [])
        if (d.get("file_new_path") or d.get("file_old_path"))
    })
    _write_json(os.path.join(args.out, "allowed_paths.json"), allowed)

    trunc = prfetch.get("completeness", {}).get("diff_truncated")
    print(f"WROTE {args.out}/prfetch.json ({len(allowed)} files"
          f"{', TRUNCATED' if trunc else ''})")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# review
# --------------------------------------------------------------------------- #
def cmd_review(args):
    """Run the reviewer surfaces and emit the run record.

    No GitHub credential is read in this phase, by design.
    """
    from .pipeline.orchestrator import run_review

    cfg = _resolve_config(args.config)
    if not cfg.get("enabled"):
        print("REFUSED: reviewer disabled by org policy", file=sys.stderr)
        for n in cfg.notices:
            print(f"  note: {n}", file=sys.stderr)
        return EXIT_REFUSED

    prfetch = _load_json(args.prfetch)
    allowed = set(_load_json(args.allowed_paths)) if args.allowed_paths else None

    n_files = len(prfetch.get("diffs", []))
    if n_files > cfg["max_changed_files"]:
        print(f"REFUSED: {n_files} changed files exceeds "
              f"max_changed_files={cfg['max_changed_files']}", file=sys.stderr)
        return EXIT_REFUSED

    record = run_review(prfetch=prfetch, config=cfg, allowed_paths=allowed,
                        workspace=args.workspace)
    _write_json(args.out, record)
    print(f"WROTE {args.out} "
          f"(verdict={record['verdict']} status={record['status']} "
          f"findings={len(record['findings'])})")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# post
# --------------------------------------------------------------------------- #
def cmd_post(args):
    """Post the review. The only phase that writes to GitHub.

    Imports of the write layer are deliberately deferred past the `--dry-run`
    branch so a dry run exercises the full policy path with no GitHub module and
    no credential involved at all.
    """
    record = _load_json(args.run_record)

    if record.get("review_event", "COMMENT") != "COMMENT":
        print(f"REFUSED: review_event must be COMMENT, got "
              f"{record.get('review_event')!r}", file=sys.stderr)
        return EXIT_FAILED
    if record.get("verdict") == "approve":
        # Defence in depth: the schema has no such value, so reaching here means
        # something upstream was tampered with or regressed.
        print("REFUSED: 'approve' is not a permitted verdict", file=sys.stderr)
        return EXIT_FAILED

    if args.dry_run:
        print(json.dumps({
            "dry_run": True,
            "verdict": record["verdict"],
            "check_conclusion": record["check_conclusion"],
            "findings": len(record["findings"]),
            "positioned": sum(1 for f in record["findings"] if f.get("positionable")),
        }, indent=2))
        return EXIT_OK

    from .github.retrieval import make_client
    from .github.write import post_review

    provider = auth.EnvToken("GITHUB_TOKEN")
    _, endpoint = auth.resolve(token_provider=provider, api_base_url=args.api_url)
    client = make_client(token_provider=provider, endpoint=endpoint)

    outcome = post_review(
        client,
        repo=record["repo"],
        pr=record["pr_number"],
        head_sha=record["head_sha"],
        findings=record["findings"],
        summary_body=record.get("summary_markdown", ""),
        dry_run=False,
    )
    print(json.dumps(outcome, indent=2))
    if not outcome.get("posted"):
        # Most likely the head moved between review and post. Not a failure -
        # the caller should requeue against the new SHA.
        return EXIT_REFUSED
    return EXIT_OK


def build_parser():
    p = argparse.ArgumentParser(prog="aireview")
    p.add_argument("--api-url", default=None,
                   help="GitHub API base URL. Injected only; never read from a checkout.")
    sub = p.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="retrieve the PR (GITHUB_TOKEN)")
    f.add_argument("--repo", required=True)
    f.add_argument("--pr", type=int, required=True)
    f.add_argument("--out", required=True)
    f.set_defaults(fn=cmd_fetch)

    r = sub.add_parser("review", help="run reviewers (ANTHROPIC_API_KEY, no GitHub token)")
    r.add_argument("--prfetch", required=True)
    r.add_argument("--allowed-paths")
    r.add_argument("--config")
    r.add_argument("--workspace")
    r.add_argument("--out", default="run-record.json")
    r.set_defaults(fn=cmd_review)

    o = sub.add_parser("post", help="post the review (GITHUB_TOKEN, no agent)")
    o.add_argument("--run-record", required=True)
    o.add_argument("--dry-run", action="store_true")
    o.set_defaults(fn=cmd_post)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except ConfigError as e:
        print(f"CONFIG ERROR: {e}", file=sys.stderr)
        return EXIT_FAILED
    except auth.AuthError as e:
        print(f"AUTH ERROR: {e}", file=sys.stderr)
        return EXIT_FAILED
    except ImportError as e:
        print(f"NOT IMPLEMENTED YET: {e}", file=sys.stderr)
        return EXIT_FAILED
    except OSError as e:
        print(f"IO ERROR: {e}", file=sys.stderr)
        return EXIT_FAILED


if __name__ == "__main__":
    raise SystemExit(main())
