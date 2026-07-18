#!/usr/bin/env python3
# <!-- r36-rebuttal: lane-PR10-PRODUCTION-PIPELINE registered in .auditooor/agent_pathspec.json -->
"""production-pipeline-check.py - PR10 FINAL gate orchestrator.

What this is
------------
``audit-completeness-check.py`` (L37) is the signal AUTHORITY: it knows every
pipeline stage and whether each one produced enough evidence under L37 policy.
This tool is the FINAL-gate ORCHESTRATOR layered on top of it. It:

  1. runs EVERY required pipeline stage's completeness signal (by delegating to
     ``audit-completeness-check.evaluate``),
  2. writes a deterministic per-stage MANIFEST to
     ``<ws>/.auditooor/production_pipeline_manifest.json`` recording, per stage,
     the ordered position, the pass/fail status, the artifacts found, and the
     reason,
  3. FAIL-CLOSES (rc=1) on any missing hard-required signal - not merely rc=0
     from a sub-tool. Advisory proof-conversion gaps remain advisory and may
     pass without an artifact unless ``ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1``
     is set.

The FINAL gate ORDERING (load-bearing)
--------------------------------------
The ordering is inherited verbatim from L37's ``_SIGNAL_ORDER`` so the operator
sees ONE canonical pipeline order across both tools. It is:

  1.  tier6-mining        (structural prerequisite)
  2.  hunt-complete       (structural prerequisite - delegates to L35/L36)
  3.  live-engines        (language-correct engines ran)
  4.  engine-harness      (engines ran REAL harnesses, not rc=0 zero-output)
  5.  audit-preflight     (per-function packs)
  6.  exploit-queue       (queue built)
  7.  chain-synth         (chain synthesis)
  8.  exploit-conversion  (conversion loop)
  9.  prove-top-leads     (proof/judgment artifact)
  10. originality         (vs the advisory set)
  11. advisory-corpus     (published == corpus parity)
  12. learning            (7-artifact agent learning)
  13. mined-landed        (sidecar == corpus parity)
  14. cross-ws-seed       (seed back into corpus)
  15. brain-prime         (ADD-D intake artifact)            <- FAIL-CLOSE
  16. hacker-questions    (ADD-D per-fn hacker-question)     <- FAIL-CLOSE
  17. fork-divergence     (PR8 ADD-C, fork targets only)
  18. novel-vector        (PR9/PR10 novel-vector stage)
  19. adversarial-panel   (PR8 ADD-B, gates FINAL_LEADS)
  20. evm-0day-proof      (PR5a, Medium+ EVM candidates; advisory by default)
  21. coverage-map        (swept-surface denominator coverage)
  22. rubric-coverage     (rubric impact-class coverage)
  23. hunt-trust          (hunt run trust meta-signal)

Stages 15-20 are the PR10 wiring contract. ADD-D (brain-prime + per-fn
hacker-question) is a HARD fail-close - production-pipeline-check refuses to
certify a workspace without both. Autonomous proof conversion remains advisory
by default for ``exploit-conversion``, ``prove-top-leads``, and
``evm-0day-proof``; set ``ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1`` to make those
signals hard-required.

STRICT mode
-----------
``--strict`` / ``STRICT=1`` threads through to L37's engine-harness PROOF gate:
the engines are only credited when PR4's proof gate confirms every counted
harness is a REAL target-call harness (not a tautological stub). A production
audit MUST run under STRICT.

Verdict vocabulary
------------------
- ``pass-production-pipeline-complete``  every hard-required stage passed.
- ``fail-production-pipeline-incomplete`` >=1 hard-required stage is missing its
                                          artifact (the first failing stage's
                                          L37 verdict is surfaced as ``blocker``).
- ``error``                               unreadable workspace / internal error.

Exit code
---------
- 0 on ``pass-production-pipeline-complete``.
- 1 on ``fail-production-pipeline-incomplete``.
- 2 on ``error``.

Override
--------
Per-signal L37 rebuttals (``<ws>/.auditooor/audit_completeness_rebuttal.txt``)
are honored verbatim - a rebutted L37 signal is treated as ``ok-rebuttal`` here
too. There is no separate production-pipeline rebuttal surface; the L37 one is
the single source of truth.

RELATED TOOLS (tool-duplication preflight, per global memory)
-------------------------------------------------------------
- ``audit-completeness-check.py`` (L37) - the signal authority. This tool
  DELEGATES to its ``evaluate`` and does NOT re-implement any signal. The gap
  this tool fills: L37 prints a verdict; PR10 additionally WRITES a per-stage
  manifest and is the ``make production-pipeline-check`` FINAL-gate entrypoint
  that fail-closes on missing hard-required evidence with STRICT threaded
  through. Advisory proof-conversion stages may pass without artifacts unless
  autonomous proof conversion is explicitly enforced.
- ``hunt-completeness-check.py`` (L35/L36) - the HUNT half; reached transitively
  via L37's hunt-complete signal.
- ``loop-finalization-check.py`` - per-slice closeout manifest gate; orthogonal.

CLI
---
    python3 tools/production-pipeline-check.py <workspace> [--json] [--strict] \
        [--manifest-out <path>]

Usage
-----
    make production-pipeline-check WS=~/audits/<project> STRICT=1
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import sys
from pathlib import Path

SCHEMA = "auditooor.pr10_production_pipeline.v1"
GATE = "PR10-PRODUCTION-PIPELINE"
P0_DEEP_FRESHNESS_SCHEMA = "auditooor.pr10_p0_deep_engine_freshness.v1"

# The stages that fail L37 without a rebuttal fail-close the FINAL gate. ADD-D
# remains hard-required. Autonomous proof-conversion stages are advisory unless
# ENFORCE_AUTONOMOUS_PROOF_CONVERSION=1 is set.
_DEFAULT_MANIFEST_REL = (".auditooor", "production_pipeline_manifest.json")
_AUDIT_DEEP_LANGS = {"go", "rust", "move", "cairo"}


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_l37_module():
    """Load tools/audit-completeness-check.py (the signal authority)."""
    tool_path = Path(__file__).resolve().with_name("audit-completeness-check.py")
    spec = importlib.util.spec_from_file_location("_l37_audit_completeness", tool_path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_l37_audit_completeness"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def _signal_order(mod) -> list[str]:
    """Return the canonical stage ordering from L37's _SIGNAL_ORDER."""
    order = getattr(mod, "_SIGNAL_ORDER", None)
    if not order:
        return []
    return [s for s, _ in order]


def _deep_freshness_relevant(signal: str, detail: dict) -> bool:
    """Return true when live-engines depends on audit-deep freshness."""
    if signal != "live-engines":
        return False
    languages = detail.get("languages", {})
    if isinstance(languages, dict) and any(lang in _AUDIT_DEEP_LANGS for lang in languages):
        return True
    if detail.get("audit_deep") is True or detail.get("audit_deep_skip") is True:
        return True
    missing = detail.get("missing_for_language", [])
    if isinstance(missing, list):
        return any("audit_deep" in str(item) or "audit-deep" in str(item) for item in missing)
    return False


def _source_manifest_summary(row: dict) -> dict:
    """Keep the P0 report compact while preserving freshness evidence."""
    keep = (
        "kind",
        "path",
        "exists",
        "schema",
        "expected_schema",
        "schema_matches",
        "workspace_matches",
        "timestamp_field",
        "timestamp_utc",
        "mtime_utc",
        "run_id",
        "run_id_matches_current",
        "run_id_mismatch",
        "run_id_missing",
        "fresh_by_timestamp",
        "fresh_by_mtime",
        "fresh_by_run_id",
        "execution_ok",
        "execution_reason",
        "fresh",
        "error",
    )
    return {key: row.get(key) for key in keep if key in row}


def _p0_deep_engine_freshness(signal: str, detail: dict) -> dict | None:
    """Normalize audit-deep-manifest freshness output for PR10 reports."""
    if not _deep_freshness_relevant(signal, detail):
        return None
    freshness = detail.get("audit_deep_freshness")
    if not isinstance(freshness, dict):
        return None

    verdict = str(freshness.get("verdict") or "")
    if verdict == "pass-fresh-deep-manifest":
        status = "hard-required-pass"
        completion_mode = "fresh-manifest"
        completion_claimed = True
    elif verdict == "pass-explicit-deep-skip":
        status = "typed-deep-skip"
        completion_mode = "typed-skip"
        completion_claimed = False
    elif verdict in {"fail-stale-deep-manifest", "fail-conflicting-deep-manifest"}:
        status = "stale-deep-manifest"
        completion_mode = None
        completion_claimed = False
    elif verdict == "fail-no-deep-manifest":
        status = "missing-deep-manifest"
        completion_mode = None
        completion_claimed = False
    elif verdict.startswith("fail-no-current-run") or verdict.startswith("fail-current-run"):
        status = "missing-deep-manifest"
        completion_mode = None
        completion_claimed = False
    else:
        status = "deep-freshness-failed" if not freshness.get("ok") else "hard-required-pass"
        completion_mode = None
        completion_claimed = bool(freshness.get("ok"))

    source_manifests = freshness.get("source_manifests", [])
    if not isinstance(source_manifests, list):
        source_manifests = []
    return {
        "schema": P0_DEEP_FRESHNESS_SCHEMA,
        "status": status,
        "verdict": verdict,
        "ok": bool(freshness.get("ok")),
        "reason": freshness.get("reason"),
        "completion_mode": completion_mode,
        # False for typed skip, stale, and missing cases so the report does not
        # imply a deep engine completed when only a policy skip or failure exists.
        "completion_claimed": completion_claimed,
        "audit_run_manifest": freshness.get("audit_run_manifest"),
        "run_start_utc": freshness.get("run_start_utc"),
        "run_start_line": freshness.get("run_start_line"),
        "run_id": freshness.get("run_id"),
        "fresh_manifest_paths": freshness.get("fresh_manifest_paths", []),
        "blocking_manifest_paths": freshness.get("blocking_manifest_paths", []),
        "skip": freshness.get("skip"),
        "source_manifests": [
            _source_manifest_summary(row)
            for row in source_manifests
            if isinstance(row, dict)
        ],
    }


def _stage_status_class(
    *,
    ok: bool,
    policy: str,
    deep_freshness: dict | None,
) -> str:
    """Classify the stage for human and JSON status reports."""
    if deep_freshness is not None:
        return str(deep_freshness.get("status") or "deep-freshness-failed")
    if policy == "advisory" and ok:
        return "advisory-accounted"
    if ok:
        return "hard-required-pass"
    return "hard-required-fail"


def evaluate(ws: Path, strict: bool = False) -> dict:
    """Run every pipeline stage via L37 and assemble the FINAL-gate verdict."""
    if strict:
        os.environ["AUDITOOOR_L37_ENGINE_PROOF_STRICT"] = "1"

    mod = _load_l37_module()
    if mod is None or not hasattr(mod, "evaluate"):
        return {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "error",
            "reason": "unable to load audit-completeness-check (L37) signal authority",
            "strict": strict, "stages": [], "blocker": None,
        }

    try:
        l37 = mod.evaluate(ws)
    except Exception as exc:  # pragma: no cover (defensive)
        return {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "error", "reason": f"L37 evaluate raised: {exc}",
            "strict": strict, "stages": [], "blocker": None,
        }

    order = _signal_order(mod)
    by_signal = {s["signal"]: s for s in l37.get("signals", [])}

    # Build the per-stage manifest in canonical order. Each stage records its
    # ordered position, status, artifacts, and reason. A stage with ok=False is
    # a hard failure after L37 rebuttal and advisory handling.
    stages: list[dict] = []
    failing: list[dict] = []
    for idx, signal in enumerate(order, start=1):
        s = by_signal.get(signal)
        if s is None:
            # A declared stage produced no signal entry: treat as a hard fail
            # so a future stage added to _SIGNAL_ORDER cannot be silently skipped.
            stage = {
                "order": idx, "stage": signal, "ok": False,
                "verdict": "fail-stage-not-evaluated",
                "reason": "stage declared in ordering but not evaluated by L37",
                "artifacts": [], "artifact_present": False,
            }
            stages.append(stage)
            failing.append(stage)
            continue
        ok = bool(s.get("ok"))
        artifacts = s.get("artifacts", [])
        detail = s.get("detail", {}) if isinstance(s.get("detail"), dict) else {}
        advisory_proof_conversion = bool(
            ok
            and detail.get("advisory_autonomous_proof_conversion") is True
            and detail.get("enforce_autonomous_proof_conversion") is not True
        )
        advisory_without_artifact = advisory_proof_conversion and not artifacts
        artifact_requirement = "artifact-backed"
        if advisory_proof_conversion and artifacts:
            artifact_requirement = "advisory-artifact-present"
        elif not artifacts:
            if advisory_without_artifact:
                artifact_requirement = "advisory-without-artifact"
            elif s.get("verdict") == "ok-rebuttal":
                artifact_requirement = "explicit-l37-rebuttal"
            elif ok:
                artifact_requirement = "not-required-for-this-workspace"
            else:
                artifact_requirement = "missing-required-artifact-or-signal"
        policy = "advisory" if advisory_proof_conversion else "hard-required"
        p0_deep_freshness = _p0_deep_engine_freshness(signal, detail)
        stage = {
            "order": idx,
            "stage": signal,
            "ok": ok,
            "verdict": (
                "advisory-without-artifact"
                if advisory_without_artifact
                else "advisory-artifact-present"
                if advisory_proof_conversion and artifacts
                else s.get("verdict")
            ),
            "reason": s.get("reason"),
            "artifacts": artifacts,
            "policy": policy,
            "hard_required": not advisory_proof_conversion,
            # The manifest distinguishes artifact-backed pass from explicit
            # rebuttal, N/A, and advisory-without-artifact pass. Do not treat
            # advisory proof conversion as a completed real artifact.
            "artifact_present": bool(artifacts),
            "advisory_without_artifact": advisory_without_artifact,
            "artifact_requirement": artifact_requirement,
            "status_class": _stage_status_class(
                ok=ok,
                policy=policy,
                deep_freshness=p0_deep_freshness,
            ),
            "l37_detail": detail,
        }
        if p0_deep_freshness is not None:
            stage["p0_deep_engine_freshness"] = p0_deep_freshness
        stages.append(stage)
        if not ok:
            failing.append(stage)

    if failing:
        verdict = "fail-production-pipeline-incomplete"
        blocker = failing[0]
        reason = (
            f"{len(failing)} required pipeline stage(s) missing hard-required evidence; "
            f"first blocker: stage #{blocker['order']} '{blocker['stage']}' "
            f"({blocker['verdict']})"
        )
    else:
        verdict = "pass-production-pipeline-complete"
        blocker = None
        hard_required_count = sum(1 for s in stages if s.get("hard_required"))
        reason = (
            f"all {hard_required_count} hard-required pipeline checks are satisfied "
            "under L37 policy; artifact-backed, explicit rebuttal, N/A, and "
            "advisory proof-conversion stages are distinguished in the manifest"
        )

    return {
        "schema": SCHEMA,
        "gate": GATE,
        "workspace": str(ws),
        "generated_at": _utc_now(),
        "strict": strict,
        "verdict": verdict,
        "reason": reason,
        "blocker": blocker,
        "n_stages": len(stages),
        "n_failing": len(failing),
        "stages": stages,
        # Carry the underlying L37 verdict for cross-reference/audit trail.
        "l37_verdict": l37.get("verdict"),
        "l37_failures": l37.get("failures", []),
        "l37_rebutted": l37.get("rebutted", []),
    }


def write_manifest(result: dict, manifest_path: Path) -> None:
    """Write the per-stage manifest deterministically."""
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(result, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def _print_human(result: dict) -> None:
    print(f"[{GATE}] verdict={result['verdict']} strict={result.get('strict')}")
    print(f"[{GATE}] workspace={result['workspace']}")
    for s in result.get("stages", []):
        mark = "ADVISORY" if s.get("policy") == "advisory" else ("PASS" if s["ok"] else "FAIL")
        rb = " (rebuttal)" if s.get("verdict") == "ok-rebuttal" else ""
        status = s.get("status_class") or "unknown"
        print(f"  #{s['order']:>2} [{mark}] {s['stage']}{rb} [{status}]: {s['reason']}")
        deep = s.get("p0_deep_engine_freshness")
        if isinstance(deep, dict):
            print(
                "       P0 deep-engine: "
                f"{deep.get('status')} ({deep.get('verdict')}), "
                f"completion_claimed={deep.get('completion_claimed')}"
            )
    if result.get("blocker"):
        b = result["blocker"]
        print(f"[{GATE}] BLOCKER: stage #{b['order']} '{b['stage']}' -> {b['verdict']}")
    print(f"[{GATE}] reason: {result['reason']}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="production-pipeline-check.py",
        description="PR10 FINAL gate: run every pipeline stage, write a per-stage "
                    "manifest, fail-close on any missing hard-required evidence.",
    )
    p.add_argument("workspace", help="Path to the audit workspace.")
    p.add_argument("--json", action="store_true", help="Emit JSON verdict payload.")
    p.add_argument(
        "--strict", action="store_true",
        help="Strict mode: thread STRICT into L37's engine-harness PROOF gate.",
    )
    p.add_argument(
        "--manifest-out", default=None,
        help="Override the manifest output path "
             "(default <ws>/.auditooor/production_pipeline_manifest.json).",
    )
    p.add_argument(
        "--no-manifest", action="store_true",
        help="Do not write the per-stage manifest (verdict only).",
    )
    args = p.parse_args(argv)

    strict = args.strict or os.environ.get("STRICT", "").strip() in ("1", "true", "yes")

    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not ws.exists() or not ws.is_dir():
        payload = {
            "schema": SCHEMA, "gate": GATE, "workspace": str(ws),
            "verdict": "error",
            "reason": "workspace path does not exist or is not a directory",
            "strict": strict, "stages": [], "blocker": None,
        }
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(f"[{GATE}] verdict=error reason={payload['reason']}")
        return 2

    result = evaluate(ws, strict=strict)

    if result["verdict"] != "error" and not args.no_manifest:
        manifest_path = (
            Path(os.path.expanduser(args.manifest_out)).resolve()
            if args.manifest_out else ws.joinpath(*_DEFAULT_MANIFEST_REL)
        )
        try:
            write_manifest(result, manifest_path)
        except OSError as exc:
            result["manifest_path"] = str(manifest_path)
            result["manifest_write_error"] = str(exc)
            result["verdict"] = "error"
            result["reason"] = f"failed to write production pipeline manifest: {exc}"
        else:
            result["manifest_path"] = str(manifest_path)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_human(result)
        if result.get("manifest_path"):
            print(f"[{GATE}] manifest: {result['manifest_path']}")

    if result["verdict"] == "pass-production-pipeline-complete":
        return 0
    if result["verdict"] == "error":
        return 2
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
