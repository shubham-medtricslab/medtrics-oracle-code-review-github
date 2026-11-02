#!/usr/bin/env python3
"""
Config trust-split tests.

These are adversarial: the repo layer is attacker-controlled, because a pull
request can edit `.github/ai-review.yml` in the same PR the reviewer is judging.
Every test here corresponds to a concrete attack that worked against v0.5.0's
`_deep_default_merge` (config.py:272-280), which let the override layer win.

Stdlib only. Run: python3 packages/core/tests/test_config.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from aireview.config import (  # noqa: E402
    ConfigError, load_layered, org_defaults, ORG_ONLY_KEYS, REPO_ALLOWED_KEYS,
)

_passed = 0
_failed = []


def check(name, fn):
    global _passed
    try:
        fn()
    except AssertionError as e:
        _failed.append(f"{name}: {e}")
    except Exception as e:  # noqa: BLE001
        _failed.append(f"{name}: unexpected {type(e).__name__}: {e}")
    else:
        _passed += 1


def expect_rejected(repo_layer, because):
    try:
        load_layered(repo_layer=repo_layer)
    except ConfigError:
        return
    raise AssertionError(f"should have been rejected ({because})")


# --------------------------------------------------------------------------- #
# Defaults are safe
# --------------------------------------------------------------------------- #
def test_defaults_are_safe():
    d = org_defaults()
    assert d["dry_run"] is True, "dry_run must default on"
    assert d["blocking_mode"] is False, "blocking must default off"
    assert d["model_tier"] == "sonnet", "default tier should be the cheap one"
    assert d["reviewer_timeout_seconds"] >= 300, (
        "90s fired on most real runs and silently marked dimensions partial"
    )


def test_org_and_repo_keys_are_disjoint():
    overlap = ORG_ONLY_KEYS & REPO_ALLOWED_KEYS
    assert not overlap, f"a key cannot be both org-only and repo-settable: {overlap}"


# --------------------------------------------------------------------------- #
# A PR must not be able to weaken the review that judges it
# --------------------------------------------------------------------------- #
def test_repo_cannot_enable_dry_run():
    expect_rejected({"dry_run": True}, "silences all posting")


def test_repo_cannot_disable_the_reviewer():
    expect_rejected({"enabled": False}, "turns the reviewer off entirely")


def test_repo_cannot_flip_the_kill_switch():
    expect_rejected({"kill_switch": True}, "org-level control")


def test_repo_cannot_drop_rulepacks():
    expect_rejected({"rulepacks": []}, "removing supabase-rls removes RLS review")


def test_repo_cannot_raise_its_own_budget():
    expect_rejected({"max_budget_usd": 10_000}, "cost control is org policy")


def test_repo_cannot_disable_blocking():
    expect_rejected({"blocking_mode": False}, "merge gate is org policy")


def test_unknown_keys_are_rejected_not_merged():
    # v0.5.0 did `out[k] = v` for any unseen key, so attacker keys passed through.
    expect_rejected({"totally_made_up": 1}, "unknown keys must not be merged")


# --------------------------------------------------------------------------- #
# No filesystem paths anywhere - these were read and write primitives
# --------------------------------------------------------------------------- #
def test_absolute_path_rejected():
    expect_rejected({"skip_paths": ["/etc/passwd"]}, "arbitrary read")


def test_traversal_rejected():
    expect_rejected({"skip_paths": ["../../.ssh/id_rsa"]}, "traversal")


def test_home_path_rejected():
    expect_rejected({"skip_paths": ["~/.aws/credentials"]}, "home expansion")


def test_nested_path_rejected():
    expect_rejected(
        {"connectors": {"audit": {"log_path": "/tmp/evil.ndjson"}}},
        "audit_log_path flowed into makedirs+append in v0.5.0: arbitrary write",
    )


# --------------------------------------------------------------------------- #
# Provenance: head config is parsed but never applied
# --------------------------------------------------------------------------- #
def test_pr_head_layer_is_never_applied():
    hostile = {"post_threshold_severity": "critical"}
    cfg = load_layered(repo_layer=hostile, repo_layer_source="pr-head")
    assert cfg.repo_layer_applied is False, "a pr-head layer must never be applied"
    assert cfg["post_threshold_severity"] == "low", "org default must survive"
    assert cfg.notices, "the author must be told their edit was ignored"


def test_base_ref_layer_is_applied():
    cfg = load_layered(repo_layer={"post_threshold_severity": "high"},
                       repo_layer_source="base-ref")
    assert cfg.repo_layer_applied is True
    assert cfg["post_threshold_severity"] == "high"


def test_valid_repo_keys_round_trip():
    cfg = load_layered(repo_layer={
        "severity_floor": "medium",
        "max_changed_files": 50,
        "surface_overrides": {"rls": {"severity_floor": "critical"}},
    })
    assert cfg["severity_floor"] == "medium"
    assert cfg["max_changed_files"] == 50
    assert cfg["surface_overrides"]["rls"]["severity_floor"] == "critical"


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #
def test_bad_repo_layer_does_not_take_reviewer_offline():
    cfg = load_layered(repo_layer={"nonsense": True}, strict=False)
    assert cfg["enabled"] is True, "one bad YAML file must not disable reviews"
    assert cfg.repo_layer_applied is False
    assert cfg.notices


def test_kill_switch_disables():
    cfg = load_layered(org_layer={"kill_switch": True})
    assert cfg["enabled"] is False
    assert cfg.notices


def test_invalid_severity_rejected():
    expect_rejected({"severity_floor": "catastrophic"}, "not a severity")


def test_bool_is_not_an_int_for_counts():
    expect_rejected({"max_changed_files": True}, "bool must not pass as int")


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            check(_name, _fn)
    for f in _failed:
        print("FAIL " + f)
    print(f"{_passed} passed, {len(_failed)} failed")
    raise SystemExit(1 if _failed else 0)
