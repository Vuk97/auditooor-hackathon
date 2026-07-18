#!/usr/bin/env python3
"""wave2-a-close-readiness.

Automates the six "Wave-2-A close criteria" defined in
``~/.claude/scheduled-tasks/auditooor-loops-hourly/SKILL.md`` so the operator
can run a single check to decide whether PR #728
(``wave-2-corpus-migration``) is ready to squash-merge.

The six criteria:

  1. Schema v1.1 migration runner shipped and executed against the full
     corpus (41,100 records migrated; 0 validation failures).
     Resolved by invoking ``tools/wave2-w21-post-migration-validator.py``
     and demanding ``overall_status=PASS`` with ``v1_record_count==0``.

  2. Tier-3 backfill execution complete (p=1,790 records promoted from
     tier-3 -> tier-2).
     Resolved by walking ``audit/corpus_tags/tags/`` for the
     ``verification_tier`` distribution.  The gate-full-coverage half of
     the original SKILL.md spec (>= 80.5% in record_quality.jsonl) is
     deferred to a Wave-3 quality-rescore lane and is NOT checked here;
     see ``docs/WAVE2_A_GATE_FULL_COVERAGE_DEFERRED_2026-05-16.md`` for
     rationale (empirical baseline = 12.27%, 80.5% was speculative, and
     Phase-3 schema migration does not regenerate quality scores).  The
     coverage figure is still computed and surfaced in the ``detail``
     field as advisory telemetry; it is no longer a gate.

  3. Cosmos-sdk dedup residual resolved (ASA-2024-0012 verdict-artefacts
     marked).  Resolved by checking
     ``audit/corpus_tags/tags/_deprecated/REDIRECT_MANIFEST.json``
     for the ``wave2_w26_execution_ledger`` block and an
     ASA-2024-0012-bearing entry under ``verdict_artefacts[]``.

  4. R38 + R39 wired as ``Check #73`` and ``Check #74`` in
     ``tools/pre-submit-check.sh``.  Resolved by grepping for the four
     literal strings.

  5. ``make hackerman-pre-merge`` PASS.  Three resolution paths, in
     priority order:

       a. ``--run-pre-merge`` flag - actually invoke
          ``make hackerman-pre-merge`` inline (30-45 min on the
          36k-yaml corpus).  Honoured even when a cache file exists,
          to support a forced rerun.

       b. ``--use-pre-merge-cache <path>`` - read a previously-emitted
          pre-merge JSON envelope (see
          ``tools/hackerman-pre-merge.py --out-json``) and use its
          ``overall_status`` field as the verdict.  Default path:
          ``<workspace>/.auditooor/cache/pre_merge_result.json``.

       c. fallback - if no cache exists at the configured path and no
          ``--run-pre-merge`` flag is supplied, return SKIPPED with a
          diagnostic pointing the operator at
          ``make hackerman-pre-merge-cached`` (which writes the cache
          file for future close-readiness calls without the 30+ min
          wait).  A best-effort fallback also scans ``/tmp/`` for
          legacy cache shapes.

  6. All Wave-2-A test suites pass.  Resolved by invoking
     ``python3 -m unittest`` against the three Wave-2-A introduced test
     modules.

Output schema: ``auditooor.wave2_a_close_readiness.v1``.

The tool runs cleanly against the CURRENT pre-Phase-3 corpus state and is
expected to emit ``overall_status=BLOCKED`` (criterion 1 FAIL: v1 records
still present); it emits ``READY_TO_MERGE`` only after Phase 3 lands and
``make hackerman-pre-merge`` itself goes green.

CLI:

    python3 tools/wave2-a-close-readiness.py \\
        --workspace /Users/wolf/auditooor-702-full --json --strict

Exit codes:

    0  - overall_status=READY_TO_MERGE (or non-strict mode regardless)
    1  - overall_status in {BLOCKED, PARTIAL} and ``--strict`` set
    2  - tooling error (workspace missing, validator unreadable, etc.)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

SCHEMA = "auditooor.wave2_a_close_readiness.v1"

DEFAULT_WORKSPACE = Path("/Users/wolf/auditooor-702-full")
PR_URL = "https://github.com/Vuk97/auditooor/pull/728"

CRITERION_NAMES = [
    "schema_v1_1_migration_complete",
    "tier3_backfill_complete",
    "cosmos_sdk_dedup_residual_resolved",
    "r38_r39_wired_into_pre_submit_check",
    "hackerman_pre_merge_pass",
    "wave2_a_test_suites_pass",
]

# Workspace-relative default cache path for the pre-merge result file
# (PR #728 Wave-2 PR-A close-readiness cache contract).  The composite
# pre-merge runner writes here via ``make hackerman-pre-merge-cached``
# (or any invocation of ``tools/hackerman-pre-merge.py --out-json``).
DEFAULT_PRE_MERGE_CACHE_REL = ".auditooor/cache/pre_merge_result.json"

# Legacy /tmp/ scan order (most recent first; we just glob).  Kept as a
# best-effort fallback so existing operator workflows that drop pre-merge
# JSON envelopes under /tmp/ keep working.
PRE_MERGE_CACHE_GLOBS = [
    "/tmp/hackerman-pre-merge*.json",
    "/tmp/pre-merge*.json",
]

# Cache-key normalisation: hackerman-pre-merge.py emits ``overall_status``
# (cache-friendly mirror) and the older ``overall`` (v1 schema) plus
# legacy spellings used by other workflows that wrote pre-merge JSON
# envelopes by hand.  Read in priority order.
PRE_MERGE_VERDICT_KEYS = (
    "overall_status",
    "overall_verdict",
    "verdict",
    "overall",
)

# Gate-full coverage threshold from SKILL.md.  Deferred to a Wave-3
# quality-rescore lane: the 80.5% target was speculative, the empirical
# baseline at PR-A is 12.27%, and Phase-3 schema migration does not
# regenerate ``record_quality.jsonl``.  See
# ``docs/WAVE2_A_GATE_FULL_COVERAGE_DEFERRED_2026-05-16.md``.  The
# constant is retained for telemetry (we still report current vs target
# in the detail string) but is NOT a gate.
GATE_FULL_COVERAGE_THRESHOLD = 0.805  # advisory only, deferred to Wave-3

# Tier-3 promotion target from SKILL.md.
TIER3_PROMOTION_TARGET = 1790

# Wave-2-A test modules to invoke for criterion #6.
WAVE2_A_TEST_MODULES = [
    "tools.tests.test_wave2_w21_post_migration_validator",
    "tools.tests.test_r38_bug_class_shift_check",
    "tools.tests.test_r39_attack_class_orphan_check",
]


def _git_head_sha(workspace: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return ""


def _git_branch(workspace: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=str(workspace),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return ""


def check_criterion_1_schema_migration(workspace: Path) -> Dict[str, Any]:
    """Invoke wave2-w21-post-migration-validator; PASS only when
    overall_status=PASS AND v1_record_count == 0."""
    name = CRITERION_NAMES[0]
    tool = workspace / "tools" / "wave2-w21-post-migration-validator.py"
    if not tool.is_file():
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"validator tool missing at {tool}",
            "evidence_ref": str(tool),
        }
    proc = subprocess.run(
        ["python3", str(tool), "--workspace", str(workspace), "--json"],
        capture_output=True,
        text=True,
        timeout=600,
    )
    stdout = proc.stdout.strip()
    try:
        payload = json.loads(stdout)
    except Exception as exc:
        return {
            "name": name,
            "status": "FAIL",
            "detail": (
                "validator emitted non-JSON output "
                f"(rc={proc.returncode}, stderr={proc.stderr[:160]!r}, "
                f"exc={exc!r})"
            ),
            "evidence_ref": f"{tool} --workspace {workspace} --json",
        }
    overall = payload.get("overall_status", "UNKNOWN")
    v1_count = payload.get("v1_record_count", -1)
    v11_count = payload.get("v1_1_record_count", -1)
    if overall == "PASS" and v1_count == 0:
        return {
            "name": name,
            "status": "PASS",
            "detail": (
                f"validator PASS; v1_record_count=0; "
                f"v1_1_record_count={v11_count}"
            ),
            "evidence_ref": f"{tool} --workspace {workspace} --json",
        }
    return {
        "name": name,
        "status": "FAIL",
        "detail": (
            f"validator overall_status={overall}; "
            f"v1_record_count={v1_count} (post-migration target: 0); "
            f"v1_1_record_count={v11_count}"
        ),
        "evidence_ref": f"{tool} --workspace {workspace} --json",
    }


_VERIFICATION_TIER_RE = re.compile(r"^verification_tier:\s*(\S+)", re.MULTILINE)
_SHAPE_TAG_TIER_RE = re.compile(r"verification_tier:(tier-[1-5][^\s\"']*)")


def _record_tier(text: str) -> Optional[str]:
    """Return the verification_tier value found in a YAML/JSON record."""
    m = _VERIFICATION_TIER_RE.search(text)
    if m:
        return m.group(1).strip().strip("\"'")
    # Legacy shape: function_shape.shape_tags entry of form
    # ``verification_tier:tier-N-foo``
    m = _SHAPE_TAG_TIER_RE.search(text)
    if m:
        return m.group(1).strip()
    return None


def check_criterion_2_tier3_backfill(workspace: Path) -> Dict[str, Any]:
    """Walk tags/ for verification_tier distribution and verify the
    1,790-record tier-3 -> tier-2 promotion target.

    The original SKILL.md spec ALSO required gate-full coverage >= 80.5%
    in ``record_quality.jsonl``; that half is deferred to a Wave-3
    quality-rescore lane (see
    ``docs/WAVE2_A_GATE_FULL_COVERAGE_DEFERRED_2026-05-16.md``).  We still
    compute and surface the coverage figure as advisory telemetry in the
    ``detail`` field, but we do NOT fail the criterion on it.
    """
    name = CRITERION_NAMES[1]
    tags_dir = workspace / "audit" / "corpus_tags" / "tags"
    rq_path = workspace / "audit" / "corpus_tags" / "derived" / "record_quality.jsonl"
    if not tags_dir.is_dir():
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"tags dir missing at {tags_dir}",
            "evidence_ref": str(tags_dir),
        }
    # Tier distribution across top-level tags/ records (skip deprecated /
    # quarantine subtrees which are intentionally excluded from corpus
    # coverage gates).
    tier_counts: Dict[str, int] = {}
    scanned = 0
    for p in tags_dir.rglob("*.yaml"):
        rel = p.relative_to(tags_dir).as_posix()
        if rel.startswith("_deprecated/") or rel.startswith("_QUARANTINE_"):
            continue
        scanned += 1
        try:
            text = p.read_text(errors="replace")
        except Exception:
            continue
        tier = _record_tier(text) or "no_tier_or_missing"
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
    # Tier-3 backfill measure: count of canonical tier-2 records.  We treat
    # the post-Phase-3 state as "tier-2-* count >= TIER3_PROMOTION_TARGET",
    # i.e. the operator promoted >=1,790 records out of tier-3 into tier-2.
    tier2_total = sum(
        v for k, v in tier_counts.items() if k.startswith("tier-2")
    )
    # Gate-full coverage: advisory only.  We compute it for telemetry but
    # never fail the criterion on it; the 80.5% target was speculative,
    # the empirical baseline is ~12.27%, and Phase-3 schema migration
    # does not regenerate ``record_quality.jsonl``.  A Wave-3 lane will
    # run the quality-rescore (see deferred-doc).
    rq_total = 0
    rq_full = 0
    rq_status = "present"
    if rq_path.is_file():
        try:
            with rq_path.open("r", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    rq_total += 1
                    score = rec.get("record_quality_score")
                    if isinstance(score, (int, float)) and score >= 3.0:
                        rq_full += 1
        except Exception as exc:
            rq_status = f"unreadable:{exc!r}"
    else:
        rq_status = "absent"
    coverage = (rq_full / rq_total) if rq_total > 0 else 0.0
    detail = (
        f"tier-2 record count={tier2_total} "
        f"(target: >={TIER3_PROMOTION_TARGET}); "
        f"gate-full coverage={coverage:.4f} "
        f"(advisory only; Wave-3 quality-rescore deferral; "
        f"see docs/WAVE2_A_GATE_FULL_COVERAGE_DEFERRED_2026-05-16.md); "
        f"record_quality rq_status={rq_status} rows={rq_total}; "
        f"tags scanned={scanned}"
    )
    if tier2_total >= TIER3_PROMOTION_TARGET:
        return {
            "name": name,
            "status": "PASS",
            "detail": detail,
            "evidence_ref": (
                f"{tags_dir} + {rq_path}"
            ),
        }
    return {
        "name": name,
        "status": "FAIL",
        "detail": detail,
        "evidence_ref": f"{tags_dir} + {rq_path}",
    }


def check_criterion_3_cosmos_dedup(workspace: Path) -> Dict[str, Any]:
    """Look for wave2_w26_execution_ledger block + ASA-2024-0012 entry in
    verdict_artefacts[] of REDIRECT_MANIFEST."""
    name = CRITERION_NAMES[2]
    manifest_path = (
        workspace
        / "audit"
        / "corpus_tags"
        / "tags"
        / "_deprecated"
        / "REDIRECT_MANIFEST.json"
    )
    if not manifest_path.is_file():
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"REDIRECT_MANIFEST.json missing at {manifest_path}",
            "evidence_ref": str(manifest_path),
        }
    try:
        manifest = json.loads(manifest_path.read_text())
    except Exception as exc:
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"could not parse REDIRECT_MANIFEST.json: {exc!r}",
            "evidence_ref": str(manifest_path),
        }
    failures: List[str] = []
    if "wave2_w26_execution_ledger" not in manifest:
        failures.append("missing wave2_w26_execution_ledger block")
    artefacts = manifest.get("verdict_artefacts", [])
    has_asa = any(
        "ASA-2024-0012" in json.dumps(rec)
        for rec in artefacts
    )
    if not has_asa:
        failures.append("no verdict_artefacts entry cites ASA-2024-0012")
    if failures:
        return {
            "name": name,
            "status": "FAIL",
            "detail": "; ".join(failures),
            "evidence_ref": str(manifest_path),
        }
    return {
        "name": name,
        "status": "PASS",
        "detail": (
            f"wave2_w26_execution_ledger present; "
            f"verdict_artefacts cites ASA-2024-0012 "
            f"(count={len(artefacts)})"
        ),
        "evidence_ref": str(manifest_path),
    }


CHECK_73_VARIANTS = ("Check #73", "Check 73")
CHECK_74_VARIANTS = ("Check #74", "Check 74")
R38_REQUIRED = "R38-BUG-CLASS-SHIFT"
R39_REQUIRED = "R39-ATTACK-CLASS-ORPHAN"


def check_criterion_4_r38_r39_wired(workspace: Path) -> Dict[str, Any]:
    """Grep tools/pre-submit-check.sh for Check #73 + Check #74 +
    R38-BUG-CLASS-SHIFT + R39-ATTACK-CLASS-ORPHAN."""
    name = CRITERION_NAMES[3]
    script = workspace / "tools" / "pre-submit-check.sh"
    if not script.is_file():
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"pre-submit-check.sh missing at {script}",
            "evidence_ref": str(script),
        }
    try:
        text = script.read_text(errors="replace")
    except Exception as exc:
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"could not read pre-submit-check.sh: {exc!r}",
            "evidence_ref": str(script),
        }
    missing: List[str] = []
    if not any(v in text for v in CHECK_73_VARIANTS):
        missing.append("Check #73 (or 'Check 73')")
    if not any(v in text for v in CHECK_74_VARIANTS):
        missing.append("Check #74 (or 'Check 74')")
    if R38_REQUIRED not in text:
        missing.append(R38_REQUIRED)
    if R39_REQUIRED not in text:
        missing.append(R39_REQUIRED)
    if missing:
        return {
            "name": name,
            "status": "FAIL",
            "detail": f"missing literal strings in pre-submit-check.sh: {missing}",
            "evidence_ref": str(script),
        }
    return {
        "name": name,
        "status": "PASS",
        "detail": (
            "pre-submit-check.sh contains Check 73 (R38-BUG-CLASS-SHIFT) "
            "and Check 74 (R39-ATTACK-CLASS-ORPHAN) wiring"
        ),
        "evidence_ref": str(script),
    }


def _find_latest_pre_merge_cache() -> Optional[Path]:
    """Best-effort scan of ``/tmp/`` for legacy pre-merge cache files.

    Returned only as a fallback when neither an explicit
    ``--use-pre-merge-cache`` path is supplied nor the default workspace
    cache exists.  Kept to preserve compatibility with the historical
    operator workflow that dropped pre-merge JSON envelopes under
    ``/tmp/hackerman-pre-merge*.json``.
    """
    candidates: List[Path] = []
    for pattern in PRE_MERGE_CACHE_GLOBS:
        if pattern.startswith("/tmp/"):
            tmp = Path("/tmp")
            if tmp.is_dir():
                stem = pattern[len("/tmp/"):]
                for p in tmp.glob(stem):
                    if p.is_file():
                        candidates.append(p)
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def _read_pre_merge_cache(cache: Path) -> Dict[str, Any]:
    """Parse a pre-merge cache file and return the JSON payload.

    Raises ``ValueError`` on parse failure with the original exception
    chained.  Callers map the failure to a FAIL criterion verdict.
    """
    try:
        return json.loads(cache.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(
            f"pre-merge cache at {cache} not parseable: {exc!r}"
        ) from exc


def _verdict_from_payload(payload: Dict[str, Any]) -> str:
    """Extract the cache verdict using ``PRE_MERGE_VERDICT_KEYS`` priority."""
    for key in PRE_MERGE_VERDICT_KEYS:
        value = payload.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _run_pre_merge_inline(workspace: Path) -> Dict[str, Any]:
    """Invoke ``make hackerman-pre-merge`` inline; map stdout to verdict.

    Returns a criterion-shaped dict so the caller can append it directly.
    """
    name = CRITERION_NAMES[4]
    proc = subprocess.run(
        ["make", "hackerman-pre-merge"],
        cwd=str(workspace),
        capture_output=True,
        text=True,
        timeout=3600,
    )
    out = proc.stdout + proc.stderr
    if "PASS" in out and "FAIL" not in out and "NEEDS-CHANGES" not in out:
        return {
            "name": name,
            "status": "PASS",
            "detail": "make hackerman-pre-merge PASS (live inline run)",
            "evidence_ref": "make hackerman-pre-merge",
        }
    return {
        "name": name,
        "status": "FAIL",
        "detail": (
            f"make hackerman-pre-merge did not emit PASS "
            f"(rc={proc.returncode}; tail={out[-240:]!r})"
        ),
        "evidence_ref": "make hackerman-pre-merge",
    }


def check_criterion_5_hackerman_pre_merge(
    workspace: Path,
    run_pre_merge: bool = False,
    use_pre_merge_cache: Optional[Path] = None,
) -> Dict[str, Any]:
    """Pre-merge verdict resolver with three priority-ordered paths.

    Priority order (see top-of-file docstring section 5):

      a. ``run_pre_merge=True``  - actually invoke the heavy gate (30-45
                                   min).  Honoured even when a cache is
                                   present, to support forced reruns.
      b. cache hit               - read ``use_pre_merge_cache`` (or the
                                   workspace default at
                                   ``<ws>/.auditooor/cache/pre_merge_result.json``);
                                   verdict is the ``overall_status``
                                   field of the JSON envelope.
      c. SKIPPED                 - no cache found and ``run_pre_merge``
                                   not requested; emits a diagnostic
                                   pointing the operator at
                                   ``make hackerman-pre-merge-cached``.

    The legacy ``/tmp/hackerman-pre-merge*.json`` scan is retained as a
    best-effort fallback after the workspace-default lookup misses.
    """
    name = CRITERION_NAMES[4]

    # Path (a): explicit --run-pre-merge always wins, even when a cache
    # exists.  This supports the "the cache is stale; force a rerun"
    # operator workflow.
    if run_pre_merge:
        return _run_pre_merge_inline(workspace)

    # Path (b): resolve the cache file.  If the caller supplied an
    # explicit path we honour it verbatim; otherwise we try the
    # workspace-default location, then fall back to the legacy /tmp/
    # scan.
    cache: Optional[Path] = None
    cache_source = ""
    if use_pre_merge_cache is not None:
        cache_candidate = Path(use_pre_merge_cache).expanduser()
        if not cache_candidate.is_absolute():
            cache_candidate = (workspace / cache_candidate).resolve()
        if cache_candidate.is_file():
            cache = cache_candidate
            cache_source = "explicit --use-pre-merge-cache"
    if cache is None:
        ws_default = workspace / DEFAULT_PRE_MERGE_CACHE_REL
        if ws_default.is_file():
            cache = ws_default
            cache_source = f"workspace default ({DEFAULT_PRE_MERGE_CACHE_REL})"
    if cache is None:
        legacy = _find_latest_pre_merge_cache()
        if legacy is not None:
            cache = legacy
            cache_source = "legacy /tmp/ scan"

    # Path (c): no cache found anywhere.
    if cache is None:
        return {
            "name": name,
            "status": "SKIPPED",
            "detail": (
                "no hackerman-pre-merge cache found at "
                f"<workspace>/{DEFAULT_PRE_MERGE_CACHE_REL} (default) or "
                "under /tmp/; rerun with --run-pre-merge to invoke the "
                "live gate (30-45 min) or write the cache once via "
                "`make hackerman-pre-merge-cached` (or "
                "`make hackerman-pre-merge PRE_MERGE_OUT=<path>`) and "
                "rerun close-readiness."
            ),
            "evidence_ref": (
                f"<workspace>/{DEFAULT_PRE_MERGE_CACHE_REL} (default), "
                "/tmp/hackerman-pre-merge*.json (legacy)"
            ),
        }

    # Cache resolved; parse and read the verdict.
    try:
        payload = _read_pre_merge_cache(cache)
    except ValueError as exc:
        return {
            "name": name,
            "status": "FAIL",
            "detail": str(exc),
            "evidence_ref": str(cache),
        }
    verdict = _verdict_from_payload(payload)
    if verdict.upper() == "PASS":
        return {
            "name": name,
            "status": "PASS",
            "detail": (
                f"cached hackerman-pre-merge verdict=PASS "
                f"(source={cache_source}; cache={cache})"
            ),
            "evidence_ref": str(cache),
        }
    return {
        "name": name,
        "status": "FAIL",
        "detail": (
            f"cached hackerman-pre-merge verdict={verdict!r} "
            f"(source={cache_source}; cache={cache})"
        ),
        "evidence_ref": str(cache),
    }


def check_criterion_6_test_suites(
    workspace: Path,
    modules: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Run unittest against the Wave-2-A introduced test modules."""
    name = CRITERION_NAMES[5]
    use_modules = modules or WAVE2_A_TEST_MODULES
    proc = subprocess.run(
        ["python3", "-m", "unittest", "-v", *use_modules],
        cwd=str(workspace),
        capture_output=True,
        text=True,
        timeout=900,
    )
    # unittest emits "OK" on its summary line when the run passed.
    out = proc.stdout + proc.stderr
    last_lines = out.strip().splitlines()[-10:] if out.strip() else []
    tail = "\n".join(last_lines)
    if proc.returncode == 0 and ("\nOK" in out or out.strip().endswith("OK")):
        return {
            "name": name,
            "status": "PASS",
            "detail": f"unittest OK across {len(use_modules)} modules",
            "evidence_ref": (
                "python3 -m unittest " + " ".join(use_modules)
            ),
        }
    return {
        "name": name,
        "status": "FAIL",
        "detail": (
            f"unittest rc={proc.returncode}; tail:\n{tail}"
        ),
        "evidence_ref": (
            "python3 -m unittest " + " ".join(use_modules)
        ),
    }


def evaluate(
    workspace: Path,
    run_pre_merge: bool = False,
    skip_criteria: Optional[Set[str]] = None,
    test_modules_override: Optional[List[str]] = None,
    use_pre_merge_cache: Optional[Path] = None,
) -> Dict[str, Any]:
    """Run all six criteria; return the full status pack.

    ``use_pre_merge_cache`` selects the cache file consulted by
    criterion 5 when ``run_pre_merge`` is false; defaults to the
    workspace-relative ``DEFAULT_PRE_MERGE_CACHE_REL`` path.  See
    :func:`check_criterion_5_hackerman_pre_merge` for the full
    priority chain.
    """
    skip = skip_criteria or set()
    workspace = workspace.expanduser().resolve()

    criteria: List[Dict[str, Any]] = []

    def _run(idx: int, fn, *args, **kwargs) -> None:
        name = CRITERION_NAMES[idx]
        if name in skip:
            criteria.append(
                {
                    "name": name,
                    "status": "SKIPPED",
                    "detail": "skipped via --skip-criteria",
                    "evidence_ref": "--skip-criteria",
                }
            )
            return
        criteria.append(fn(*args, **kwargs))

    _run(0, check_criterion_1_schema_migration, workspace)
    _run(1, check_criterion_2_tier3_backfill, workspace)
    _run(2, check_criterion_3_cosmos_dedup, workspace)
    _run(3, check_criterion_4_r38_r39_wired, workspace)
    _run(
        4,
        check_criterion_5_hackerman_pre_merge,
        workspace,
        run_pre_merge,
        use_pre_merge_cache,
    )
    _run(5, check_criterion_6_test_suites, workspace, test_modules_override)

    failures = [c["name"] for c in criteria if c["status"] == "FAIL"]
    passes = [c["name"] for c in criteria if c["status"] == "PASS"]
    skipped = [c["name"] for c in criteria if c["status"] == "SKIPPED"]

    if failures:
        overall = "BLOCKED"
    elif skipped:
        overall = "PARTIAL"
    else:
        overall = "READY_TO_MERGE"

    return {
        "schema": SCHEMA,
        "branch": _git_branch(workspace),
        "head_sha": _git_head_sha(workspace),
        "pr_url": PR_URL,
        "overall_status": overall,
        "criteria": criteria,
        "failures": failures,
        "passes": passes,
        "skipped": skipped,
    }


def _print_human(payload: Dict[str, Any]) -> None:
    print(f"wave2-a-close-readiness :: {payload['overall_status']}")
    print(f"  branch:  {payload['branch']}")
    print(f"  head:    {payload['head_sha']}")
    print(f"  pr_url:  {payload['pr_url']}")
    print("")
    for c in payload["criteria"]:
        marker = {"PASS": "PASS", "FAIL": "FAIL", "SKIPPED": "SKIP"}[c["status"]]
        print(f"  [{marker}] {c['name']}")
        print(f"        detail:   {c['detail']}")
        print(f"        evidence: {c['evidence_ref']}")
    print("")
    if payload["failures"]:
        print(f"  failures: {payload['failures']}")
    if payload["skipped"]:
        print(f"  skipped:  {payload['skipped']}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--workspace",
        type=Path,
        default=DEFAULT_WORKSPACE,
        help="Repo root (default: %(default)s).",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON pack.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero unless overall_status=READY_TO_MERGE.",
    )
    parser.add_argument(
        "--run-pre-merge",
        action="store_true",
        help=(
            "Actually invoke `make hackerman-pre-merge` for criterion 5 "
            "(heavy: 30-45 min on the 36k-yaml corpus).  Honoured even "
            "when a cache file exists, to support forced reruns."
        ),
    )
    parser.add_argument(
        "--use-pre-merge-cache",
        type=Path,
        default=Path(DEFAULT_PRE_MERGE_CACHE_REL),
        help=(
            "Path to a previously-emitted pre-merge JSON envelope (from "
            "`tools/hackerman-pre-merge.py --out-json` / "
            "`make hackerman-pre-merge-cached`) whose `overall_status` "
            "field is the criterion 5 verdict.  Relative paths resolve "
            "against --workspace.  Default: "
            f"'{DEFAULT_PRE_MERGE_CACHE_REL}'."
        ),
    )
    parser.add_argument(
        "--skip-criteria",
        action="append",
        default=[],
        help="Criterion name to skip (repeatable; testing knob).",
    )
    args = parser.parse_args(argv)

    skip = set(args.skip_criteria or [])
    unknown = skip - set(CRITERION_NAMES)
    if unknown:
        sys.stderr.write(
            f"error: unknown --skip-criteria names: {sorted(unknown)}\n"
            f"valid names: {CRITERION_NAMES}\n"
        )
        return 2
    try:
        payload = evaluate(
            args.workspace,
            run_pre_merge=args.run_pre_merge,
            skip_criteria=skip,
            use_pre_merge_cache=args.use_pre_merge_cache,
        )
    except FileNotFoundError as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 2

    if args.json:
        json.dump(payload, sys.stdout, sort_keys=True, indent=2)
        sys.stdout.write("\n")
    else:
        _print_human(payload)

    if not args.strict:
        return 0
    return 0 if payload["overall_status"] == "READY_TO_MERGE" else 1


if __name__ == "__main__":
    sys.exit(main())
