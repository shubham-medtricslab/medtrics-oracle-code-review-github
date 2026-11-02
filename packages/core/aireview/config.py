#!/usr/bin/env python3
"""
Layered config with a hard trust split.

This is a rewrite, not a port. v0.5.0's `config.py` cannot be reused here:

  - `validate()` hard-required `optimus.product_slug` (config.py:229), so a
    non-Oracle repo could not produce a valid config at all. That directly
    contradicts connectors being optional.
  - `_deep_default_merge` (config.py:272-280) documented itself as "override
    wins on leaves" and passed unknown keys straight through with `out[k] = v`.
    In a hosted context the untrusted layer is the repo file, so "override wins"
    means a pull request rewrites the policy that governs it.
  - Several keys carried filesystem paths (`modules_dir`, `index_path`,
    `feature_map_path`, `channels.audit_log_path`). The first three are an
    arbitrary-read primitive; `audit_log_path` flows into `audit.py:38`, which
    does `makedirs` + append, making it an arbitrary-WRITE primitive.

The model here instead:

  1. ORG keys are authoritative and a repo file may never set them. Attempting
     to is a hard error, not a silent drop, so misconfiguration is visible.
  2. REPO keys are a closed allowlist with per-key validators.
  3. Unknown keys are rejected outright rather than merged.
  4. No key may carry a filesystem path. Rulepacks resolve by ID against a
     registry that core owns.

The repo file is additionally read from the BASE ref, never the PR head - see
`load_layered(repo_layer_source=...)`. That is enforced by the caller, and this
module records which source was used so the review body can say so.

Stdlib only.
"""
import json
import re

SCHEMA_VERSION = "2.0"
SEVERITIES = ("info", "low", "medium", "high", "critical")

# Keys only the org may set. A repo file naming any of these is rejected.
# These are exactly the knobs that decide whether a review can be weakened.
ORG_ONLY_KEYS = frozenset({
    "dry_run",
    "enabled",
    "blocking_mode",
    "kill_switch",
    "rulepacks",
    "model_tier",
    "max_budget_usd",
    "allowed_repos",
})

# Keys a repo may set, each with a validator. Anything absent here is rejected.
REPO_ALLOWED_KEYS = frozenset({
    "severity_floor",
    "post_threshold_severity",
    "max_changed_files",
    "reviewer_timeout_seconds",
    "skip_paths",
    "surface_overrides",
    "connectors",
})

_PATHLIKE = re.compile(r"(^|/)\.\.(/|$)|^[/~]|^[A-Za-z]:[\\/]")


class ConfigError(Exception):
    """Raised for any invalid or untrusted configuration."""


def _reject_pathlike(key, value):
    """No config value may be a filesystem path.

    v0.5.0 accepted `modules.modules_dir`, `impact_scan.feature_map_path` and
    `channels.audit_log_path` as paths. Since the repo file is attacker
    controlled, that is arbitrary read and arbitrary write. Rulepacks and
    artifacts resolve by ID, never by path.
    """
    if isinstance(value, str) and _PATHLIKE.search(value):
        raise ConfigError(
            f"{key!r} looks like a filesystem path ({value!r}); "
            "config may not carry paths - reference resources by id"
        )
    if isinstance(value, dict):
        for k, v in value.items():
            _reject_pathlike(f"{key}.{k}", v)
    if isinstance(value, list):
        for i, v in enumerate(value):
            _reject_pathlike(f"{key}[{i}]", v)


def org_defaults():
    """Safe-by-default org policy. Everything that can surprise someone is off."""
    return {
        "$schema_version": SCHEMA_VERSION,
        "enabled": True,
        "dry_run": True,            # post nothing until explicitly turned on
        "blocking_mode": False,     # check-run concludes neutral
        "kill_switch": False,
        "rulepacks": ["base"],
        "model_tier": "sonnet",     # Opus is ~2.5x the cost for marginal gain
        "max_budget_usd": 5.0,
        "allowed_repos": [],        # empty means "any repo this action runs in"
        "severity_floor": "low",
        "post_threshold_severity": "low",
        "max_changed_files": 400,
        "reviewer_timeout_seconds": 420,   # 90s fired on most real runs
        "skip_paths": [],
        "surface_overrides": {},
        "connectors": {},
    }


def _validate_severity(key, value):
    if value not in SEVERITIES:
        raise ConfigError(f"{key} must be one of {SEVERITIES}, got {value!r}")


def _validate_repo_layer(layer):
    if not isinstance(layer, dict):
        raise ConfigError("repo config must be a mapping")

    for key, value in layer.items():
        if key.startswith("$"):
            continue
        if key in ORG_ONLY_KEYS:
            raise ConfigError(
                f"{key!r} is org-controlled and cannot be set by a repository. "
                "This key decides whether a review can be weakened."
            )
        if key not in REPO_ALLOWED_KEYS:
            raise ConfigError(f"unknown config key {key!r}")
        _reject_pathlike(key, value)

    if "severity_floor" in layer:
        _validate_severity("severity_floor", layer["severity_floor"])
    if "post_threshold_severity" in layer:
        _validate_severity("post_threshold_severity", layer["post_threshold_severity"])

    for key in ("max_changed_files", "reviewer_timeout_seconds"):
        if key in layer:
            v = layer[key]
            if not isinstance(v, int) or isinstance(v, bool) or not (1 <= v <= 100_000):
                raise ConfigError(f"{key} must be a positive int <= 100000, got {v!r}")

    if "skip_paths" in layer:
        v = layer["skip_paths"]
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            raise ConfigError("skip_paths must be a list of glob strings")

    if "surface_overrides" in layer:
        v = layer["surface_overrides"]
        if not isinstance(v, dict):
            raise ConfigError("surface_overrides must be a mapping")
        for surface, ov in v.items():
            if not isinstance(ov, dict):
                raise ConfigError(f"surface_overrides.{surface} must be a mapping")
            unknown = set(ov) - {"severity_floor", "enabled"}
            if unknown:
                raise ConfigError(f"surface_overrides.{surface}: unknown {sorted(unknown)}")
            if "severity_floor" in ov:
                _validate_severity(f"surface_overrides.{surface}.severity_floor",
                                   ov["severity_floor"])
            if "enabled" in ov and not isinstance(ov["enabled"], bool):
                raise ConfigError(f"surface_overrides.{surface}.enabled must be bool")

    if "connectors" in layer:
        v = layer["connectors"]
        if not isinstance(v, dict):
            raise ConfigError("connectors must be a mapping")
        for name, cfg in v.items():
            if not isinstance(cfg, dict):
                raise ConfigError(f"connectors.{name} must be a mapping")
            if "enabled" in cfg and not isinstance(cfg["enabled"], bool):
                raise ConfigError(f"connectors.{name}.enabled must be bool")

    return True


class ResolvedConfig(dict):
    """Resolved config plus provenance.

    `repo_layer_source` is surfaced in the posted review so a PR author can see
    that their in-PR config edit was not the one applied.
    """

    def __init__(self, data, *, repo_layer_source, repo_layer_applied, notices):
        super().__init__(data)
        self.repo_layer_source = repo_layer_source
        self.repo_layer_applied = repo_layer_applied
        self.notices = notices


def load_layered(org_layer=None, repo_layer=None, *,
                 repo_layer_source="base-ref", strict=True):
    """Resolve org policy over an optional repo layer.

    `repo_layer_source` must be `base-ref`. A `pr-head` layer is never applied -
    it is parsed only so the caller can tell the author it was ignored. This is
    the fix for a PR disabling its own security reviewer.

    `strict=False` downgrades an invalid repo layer to a notice and falls back to
    org policy, so one bad YAML file does not take the reviewer offline.
    """
    resolved = org_defaults()
    notices = []

    if org_layer:
        if not isinstance(org_layer, dict):
            raise ConfigError("org config must be a mapping")
        for key, value in org_layer.items():
            if key.startswith("$"):
                continue
            if key not in ORG_ONLY_KEYS and key not in REPO_ALLOWED_KEYS:
                raise ConfigError(f"unknown org config key {key!r}")
            _reject_pathlike(key, value)
            resolved[key] = value

    applied = False
    if repo_layer is not None:
        if repo_layer_source != "base-ref":
            notices.append(
                f"Repository config from {repo_layer_source!r} was ignored; "
                "configuration is read from the base branch so a pull request "
                "cannot alter the policy that reviews it."
            )
        else:
            try:
                _validate_repo_layer(repo_layer)
            except ConfigError as e:
                if strict:
                    raise
                notices.append(f"Repository config ignored: {e}")
            else:
                for key, value in repo_layer.items():
                    if key.startswith("$"):
                        continue
                    resolved[key] = value
                applied = True

    if resolved.get("kill_switch"):
        resolved["enabled"] = False
        notices.append("Org kill switch is engaged; no review will be posted.")

    return ResolvedConfig(
        resolved,
        repo_layer_source=repo_layer_source,
        repo_layer_applied=applied,
        notices=notices,
    )


def main(argv=None):
    import argparse
    import sys

    p = argparse.ArgumentParser(prog="aireview-config")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("defaults")
    v = sub.add_parser("validate-repo-layer")
    v.add_argument("--input", default="-")
    args = p.parse_args(argv)

    if args.cmd == "defaults":
        print(json.dumps(org_defaults(), indent=2))
        return 0

    raw = sys.stdin.read() if args.input == "-" else open(args.input).read()
    try:
        _validate_repo_layer(json.loads(raw))
    except ConfigError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"ERROR: invalid JSON: {e}", file=sys.stderr)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
