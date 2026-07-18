#!/usr/bin/env python3
"""capability-screen-language-coverage.py - language-aware phase-2 screen check.

ENFORCEMENT-HOLE FIX (axelar-sc 2026-07-12): make audit-deep runs 77 wired
phase-2 (audit-deep) capability screens. Each screen writes a
`*_hypotheses.jsonl` artifact when it runs. On axelar-sc only 8/77 screens
actually executed (the EVM/Solidity screen pass never ran on that
tick-driven workspace) yet the runbook's step-2 done-verification still
reported the step as met, because step-2 only checked for a single
aggregate manifest file (audit_deep_manifest.json / solidity-deep-audit
manifest.json), not for whether the language-applicable SCREEN PASS itself
emitted anything. Same enforcement-hole family as the corpus-driven-hunt /
step-4c gap (soft driver sub-stage counted as "ran" without checking output).

This module answers, generically for ANY workspace: "for every in-scope
language, did AT LEAST ONE capability-screen for that language emit its
hypotheses artifact?" It is fail-closed: a required language bucket with
ZERO matching hypotheses files is a FAIL.

Design (reuse, no re-implementation of the screen registry):
  - tools/capability-inventory-build.py already carries the single source of
    truth mapping "tools/<screen>.py" -> {"outputs": [...]} in
    CURATED_FULL_WIRING. We import that dict (module load by path, the file
    is hyphenated) rather than re-deriving or hard-coding the 77 screens.
  - A CURATED_FULL_WIRING entry is a "capability screen" (as opposed to some
    other wired artifact producer) iff at least one of its outputs ends with
    "hypotheses.jsonl" - that is the canonical phase-2 screen output shape
    used across this repo (grep any *_hypotheses.jsonl in an audited ws).
  - Each screen is bucketed into a language by its TOOL FILENAME prefix,
    mirroring the classification the verify-backfill-77-capabilities pass
    used: go-*/consensus-* = Go; rust-*/transmute*/raii-drop*/
    panic-during-drop* = Rust; js-oscript-* = JS; zk-* = ZK; anything else =
    language-agnostic/Solidity ("agnostic").
  - A bucket is REQUIRED for a workspace only if the workspace's detected
    language set (tools/readme-conformance-check.py::_detect_languages)
    intersects that bucket's trigger languages. `_detect_languages` has no
    JS/Oscript or ZK marker today, so those buckets are never auto-required
    by this check (they simply never block a workspace that has no such
    marker) - this keeps the check generic and unable to spuriously block a
    Solidity-only or Go-only workspace for an inapplicable bucket.

CLI (for manual inspection):
    python3 tools/capability-screen-language-coverage.py <workspace> [--json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent

# Bucket -> workspace-detected-language keys (from _detect_languages) that
# REQUIRE that bucket to have emitted >=1 hypotheses artifact. Buckets not
# reachable via any detected-language key (js, zk today) are never required.
_BUCKET_TRIGGER_LANGUAGES: dict[str, set[str]] = {
    "go": {"go"},
    "rust": {"rust"},
    "js": {"js", "oscript"},
    "zk": {"zk"},
    "agnostic": {"solidity", "evm"},
}

_ALL_BUCKETS = tuple(_BUCKET_TRIGGER_LANGUAGES.keys())


def _load_capability_inventory_module():
    path = _TOOLS_DIR / "capability-inventory-build.py"
    spec = importlib.util.spec_from_file_location("_cslc_cap_inventory", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_cslc_cap_inventory"] = mod
    spec.loader.exec_module(mod)
    return mod


def _bucket_for_tool_path(tool_path: str) -> str:
    """Classify a `tools/<name>.py` entry into a language bucket by filename."""
    base = os.path.basename(tool_path)
    if base.startswith("go-") or base.startswith("consensus-"):
        return "go"
    if (
        base.startswith("rust-")
        or "transmute" in base
        or "raii-drop" in base
        or "panic-during-drop" in base
    ):
        return "rust"
    if base.startswith("js-oscript-"):
        return "js"
    if base.startswith("zk-"):
        return "zk"
    return "agnostic"


def screen_registry(wiring: dict[str, dict] | None = None) -> dict[str, list[str]]:
    """{bucket: [hypotheses output filenames]} derived from CURATED_FULL_WIRING.

    Only entries with >=1 output ending in 'hypotheses.jsonl' are counted as
    capability SCREENS (other CURATED_FULL_WIRING entries produce non-screen
    artifacts like census/accounting jsons and are out of scope for this
    check).
    """
    if wiring is None:
        mod = _load_capability_inventory_module()
        wiring = getattr(mod, "CURATED_FULL_WIRING", {})
    registry: dict[str, list[str]] = {b: [] for b in _ALL_BUCKETS}
    for tool_path, meta in wiring.items():
        outputs = meta.get("outputs", []) if isinstance(meta, dict) else []
        hyp_outputs = [o for o in outputs if str(o).endswith("hypotheses.jsonl")]
        if not hyp_outputs:
            continue
        bucket = _bucket_for_tool_path(tool_path)
        registry[bucket].extend(hyp_outputs)
    return registry


def required_buckets(languages: set[str]) -> set[str]:
    """Which screen-language buckets are required for a workspace's detected
    languages. Fail-closed by construction: only buckets whose trigger set
    intersects `languages` are required; everything else is not applicable
    and never blocks the workspace."""
    langs = {str(l).lower() for l in (languages or set())}
    return {
        bucket
        for bucket, triggers in _BUCKET_TRIGGER_LANGUAGES.items()
        if langs.intersection(triggers)
    }


def _candidate_dirs(ws: Path) -> list[Path]:
    # Hypotheses artifacts have been observed both at <ws>/.auditooor/ and
    # occasionally at the workspace root; check both, same tolerance pattern
    # readme-conformance-check.py already uses elsewhere (file_nonempty_any).
    return [ws / ".auditooor", ws]


def evaluate(
    ws: Path,
    languages: set[str],
    wiring: dict[str, dict] | None = None,
) -> dict[str, Any]:
    """Return {"ok": bool, "failures": [...], "required": [...], "found": {...}}."""
    registry = screen_registry(wiring)
    req = required_buckets(languages)
    dirs = _candidate_dirs(ws)

    found: dict[str, list[str]] = {}
    failures: list[str] = []
    for bucket in sorted(req):
        names = registry.get(bucket, [])
        present = []
        for name in names:
            for d in dirs:
                if (d / name).is_file():
                    present.append(name)
                    break
        found[bucket] = present
        if not present:
            failures.append(
                f"capability_screen_language_coverage FAIL: bucket '{bucket}' "
                f"(required by in-scope language) emitted ZERO of its "
                f"{len(names)} screen hypotheses artifact(s) under "
                f"{ws / '.auditooor'}; the phase-2 screen pass for this "
                f"language did not run on this workspace"
            )

    return {
        "ok": len(failures) == 0,
        "failures": failures,
        "required_buckets": sorted(req),
        "found": found,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("workspace")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    ws = Path(os.path.expanduser(args.workspace)).resolve()

    # Best-effort language detection reuse (avoid re-implementing _detect_languages)
    conf_path = _TOOLS_DIR / "readme-conformance-check.py"
    spec = importlib.util.spec_from_file_location("_cslc_conformance", conf_path)
    conf_mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["_cslc_conformance"] = conf_mod
    spec.loader.exec_module(conf_mod)  # type: ignore[union-attr]
    languages = conf_mod._detect_languages(ws)

    res = evaluate(ws, languages)
    res["workspace"] = str(ws)
    res["detected_languages"] = sorted(languages)

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"capability-screen-language-coverage  workspace: {ws}")
        print(f"  detected languages: {sorted(languages)}")
        print(f"  required buckets  : {res['required_buckets']}")
        for bucket, names in res["found"].items():
            print(f"    {bucket}: {len(names)} artifact(s) present")
        if res["ok"]:
            print("  PASS")
        else:
            print("  FAIL")
            for f in res["failures"]:
                print(f"    {f}")

    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
