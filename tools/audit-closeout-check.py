#!/usr/bin/env python3
"""audit-closeout-check.py — close-out gate: did the audit actually run?

Background
----------
Codex P0 #1 follow-up from PR #253 review. The agent harness can claim "audit
done" by writing a few markdown files without ever running ``make audit`` or
the canonical 30-stage chain — see V5 Gap-23 (Monetrix audit emitted
``HYPOTHESIS_PROMPT.md`` but never produced ``HYPOTHESES.md``; downstream
stages got nothing). Gap-24 is a similar shape (workspace-citation discipline
not enforced post-audit).

This tool is a deterministic, stdlib-only, offline-safe gate that reads the
artifacts a real run leaves behind, flags missing evidence, and exits non-zero
on hard close-out failures. It is **diagnostic** — it never re-runs the audit,
never calls a live LLM provider by default, and never touches the network.

The mental model is "post-flight check" rather than "preflight": run it after
``make audit`` (and optionally after ``make audit-deep``) and before opening a
submission PR.

Output discipline
-----------------
- Table of ``[PASS] / [WARN] / [FAIL]`` rows.
- WARN rows are explicit and impossible-to-miss; they are not silently folded
  into PASS.
- Exit non-zero only on FAIL; WARN keeps exit 0 unless ``--require-deep`` is
  passed (which promotes the deep-profile WARN to FAIL).
- ``--json`` emits an aggregate JSON document; ``--write-manifest`` writes
  ``<workspace>/.audit_logs/audit_closeout_manifest.json`` for downstream
  bookkeeping.

Checks
------
1. ``canonical-audit``      evidence that ``make audit`` / ``engage.py
                            --stage all`` actually produced its primary
                            artifacts (``engage_report.md``,
                            ``INTAKE_BASELINE.json``, ``SCAN_REPORT.md``,
                            ``swarm/mining_priorities.json``,
                            ``swarm/mining_briefs/*.md``,
                            ``submissions/packaged/``).
2. ``audit-deep-all``       parses ``<ws>/.audit_logs/audit_deep_all_manifest
                            .json`` (the PR #246 bounded handoff packet) and
                            confirms the four child profiles
                            (``default``, ``math``, ``econ``, ``crypto``)
                            were attempted with explicit status. ``crypto``
                            being inapplicable is fine if explicitly recorded
                            (``status`` ∈ ``{success, skipped_*, failed}``).
                            If typed ``deep_candidates/*.json`` exist, also
                            expects the PR #356 promotion report
                            (``typed_candidate_promotions.json``) so candidate
                            piles become a sorted work queue.
3. ``pattern-mining``       evidence of pattern mining over the workspace
                            (``cross_ws_patterns.md``, ``pattern_migration_
                            alert.md``, ``SOLODIT_SEARCH_PLAN.md``,
                            ``PATTERN_HITS.md``). Absence requires an
                            explicit skip marker
                            (``<ws>/.audit_logs/pattern_mining_skip.md``).
4. ``hypotheses``           V5 Gap-23 gate: if ``HYPOTHESIS_PROMPT.md``
                            exists but ``HYPOTHESES.md`` does not, the
                            hypothesis-generation stage silently failed.
                            FAIL.
5. ``agent-synthesize``     ``swarm/brief_candidates.json`` /
                            ``swarm/agent_verdicts.json`` /
                            ``agent_outputs/*``. PASS on synthesis JSON,
                            WARN on outputs without synthesis, FAIL on
                            neither (the close-out lane never ran).
6. ``pre-submit``           if reportable submission drafts exist,
                            check for production-path evidence under
                            ``submissions/packaged/`` and an
                            ``llm_review/`` sibling. High/Critical drafts
                            without production-path evidence are FAIL.
7. ``poc-execution``        if source-mining produced ``poc_task_briefs/*.md``,
                            require matching execution manifests under
                            ``poc_execution/**/execution_manifest.json``.
                            Missing manifests WARN so generated briefs do not
                            become a dormant queue. Also warns when normalized
                            ``deep_counterexample.v1`` records exist without
                            any PoC execution manifest, so audit-deep traces
                            do not become a second dormant queue. Also checks
                            P1 fixture extraction queues so #311 source/archive
                            rows do not become terminal-only TODOs.
8. ``detector-environment`` parses
                            ``<ws>/detector_environment_manifest.json`` from
                            ``workspace-scan-orchestrator.py`` so Slither/solc
                            versions and skipped-compilation counters stay
                            visible during close-out. Missing or nonzero
                            skipped/compile counters WARN, not FAIL.
9. ``go-dlt-audit-enforcement`` parses
                            ``<ws>/.audit_logs/go_dlt_audit_enforcement.json``
                            when Go/DLT audit-deep wrote one, and mirrors its
                            PASS/WARN/FAIL signal. Missing manifests WARN only
                            for workspaces with non-vendor Go files; non-Go
                            workspaces pass as not applicable.
10. ``llm-budget``          invokes ``tools/llm-budget-guard.py status`` and
                            embeds the rolling-window status. Also probes
                            for a future ``tools/llm-preflight-auth.py``;
                            absence emits a TODO WARN, not a FAIL.
11. ``p0-followups``        parses ``<ws>/.audit_logs/p0_followups.json`` or
                            ``docs/V5_P0_FOLLOWUPS.md``. If the V5 capability
                            gaps doc lists P0 items but no follow-up
                            tracking artifact exists, WARN.
12. ``yaml-wave17-consistency`` V5-P0-17 / foot-gun #14: each YAML under
                            ``reference/patterns.dsl/`` (excluding ``_held/``)
                            must have a paired ``detectors/wave17/<under>.py``
                            and, if a fixture exists, a paired
                            ``run_test``/``run_clean_test`` row in
                            ``detectors/test_fixtures/run_tests.sh``. Orphan
                            wave17 .py files (no YAML) are also flagged.
                            ``--require-strict-wiring`` promotes WARN to FAIL.
13. ``counterexample-execution``  P0-1 burn-down: walks
                            ``<ws>/deep_counterexamples/*.deep_counterexample
                            .v1.json`` (the symbolic/fuzz traces emitted by
                            ``audit-deep`` lanes) and, for each record, looks
                            for a corresponding
                            ``poc_execution/**/execution_manifest.json``.
                            Counterexamples without an execution manifest are
                            "advisory until replayed" and surface as a WARN row
                            with explicit ``executed=N/total=M`` counts.
                            ``--require-replay-executed`` (or
                            ``REQUIRE_REPLAY_EXECUTED=1``) promotes this WARN
                            to a hard FAIL so a stale queue cannot silently
                            slip past pre-submit close-out.
14. ``final-paste-hygiene`` Existing operator/final paste files under
                            ``submissions/paste-ready/``,
                            ``submissions/cantina_paste/``,
                            ``submissions/operator_paste/``,
                            ``submissions/final_paste/``, or packaged
                            ``*_ready.md`` outputs must not contain HTML
                            comments, local absolute paths, manual-fill
                            placeholders, or path-only PoC sections.

Discipline
----------
- Stdlib only.
- Deterministic — checks read files; no clock-dependent gates.
- Offline-safe by default; no live provider calls.
- No GitHub network access.
- Workspace-rooted; the repo root is auto-detected from this script's path.

Usage
-----
::

    python3 tools/audit-closeout-check.py --workspace <ws>
    python3 tools/audit-closeout-check.py --workspace <ws> --require-deep
    python3 tools/audit-closeout-check.py --workspace <ws> --json
    python3 tools/audit-closeout-check.py --workspace <ws> --write-manifest

The Makefile target ``make audit-closeout WS=<ws>`` is the front door.

Exit codes
----------
0  no FAIL rows (WARN/PASS only)
1  at least one FAIL row
2  argument / I/O error
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping


# Local import for the ``evidence_class`` schema (item #14). The closeout
# check refuses to count generated hypotheses or unverified scaffolds as
# proof, and surfaces a WARN row when artifacts are missing the field.
def _load_evidence_class_module():
    spec = importlib.util.spec_from_file_location(
        "_evidence_class", Path(__file__).resolve().parent / "evidence_class.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_EVIDENCE_CLASS = _load_evidence_class_module()


def _load_bound_source_validator():
    spec = importlib.util.spec_from_file_location(
        "_execution_manifest_proof",
        Path(__file__).resolve().parent / "execution_manifest_proof.py",
    )
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception:  # pragma: no cover - compatibility fallback
        return None
    return getattr(module, "bound_source_validation", None)


_BOUND_SOURCE_VALIDATION = _load_bound_source_validator()
bound_source_validation = _BOUND_SOURCE_VALIDATION


def _validate_bound_sources(manifest: dict, ws: Path) -> dict:
    """Return source freshness state while preserving invalid diagnostics."""
    supplied = "bound_sources" in manifest and manifest.get("bound_sources") not in (None, [])
    if not supplied:
        return {"supplied": "bound_sources" in manifest, "valid": True, "errors": []}
    if bound_source_validation is None:
        return {
            "supplied": True,
            "valid": False,
            "errors": ["bound_source_validation_unavailable"],
        }
    try:
        result = bound_source_validation(manifest, ws)
    except Exception as exc:  # pragma: no cover - validator boundary
        return {"supplied": True, "valid": False, "errors": [f"bound_source_validation_error:{exc}"]}
    if not isinstance(result, dict):
        return {"supplied": True, "valid": False, "errors": ["bound_source_validation_invalid_result"]}
    return {
        **result,
        "supplied": True,
        "valid": bool(result.get("valid")),
        "errors": list(result.get("errors") or []),
    }


# PR #535 PR 1: shared Program Impact Mapping helper. Used by the
# `program-impact-mapping` closeout row to roll up per-draft mapping
# status counts (mapped / missing_mapping / tier_mismatch /
# proof_artifact_missing / advisory_no_rubric).
def _load_impact_mapping_module():
    spec = importlib.util.spec_from_file_location(
        "_impact_mapping_closeout",
        Path(__file__).resolve().parent / "lib" / "program_impact_mapping.py",
    )
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    sys.modules["_impact_mapping_closeout"] = module
    try:
        spec.loader.exec_module(module)
    except Exception:  # pragma: no cover - fail-open
        return None
    return module


_IMPACT_MAPPING = _load_impact_mapping_module()


REPO_ROOT = Path(__file__).resolve().parents[1]
UNEXECUTED_QUEUE_COUNT_REVIEW_THRESHOLD = 5
DEEP_ENGINE_CLEAN_TRUTH_LABELS = {"counterexample", "no_findings"}
DEEP_ENGINE_NON_CLEAN_TRUTH_LABELS = {
    "setup_failure",
    "tooling_failure",
    "no_targets",
    "zero_execution",
    "parser_failure",
}
DEEP_ENGINE_NON_CLEAN_STATUSES = {
    "tooling_failure_origin",
    "skipped_tooling_failure",
    "error",
}

# P2-4: age-based stale queue thresholds. Configurable via environment so
# operators can tighten the gate per workspace without editing code.
#   AUDITOOOR_QUEUE_WARN_DAYS  — items older than this WARN  (default 7)
#   AUDITOOOR_QUEUE_FAIL_DAYS  — items older than this FAIL  (default 30)
#   REQUIRE_NO_STALE_QUEUES=1  — promote any WARN-aged queue item to FAIL
# Negative / non-numeric values fall back to defaults rather than disabling
# the gate, so a typo cannot silently turn the check off.
DEFAULT_QUEUE_WARN_DAYS = 7
DEFAULT_QUEUE_FAIL_DAYS = 30


# Load tools/scan_skip_remediation.py via importlib so the closeout gate
# can render the same hint set the orchestrator wrote into the manifest.
def _load_skip_remediation():
    spec = importlib.util.spec_from_file_location(
        "_scan_skip_remediation_closeout",
        REPO_ROOT / "tools" / "scan_skip_remediation.py",
    )
    if spec is None or spec.loader is None:  # pragma: no cover (defensive)
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_scan_skip_remediation_closeout"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:  # pragma: no cover (defensive)
        return None
    return mod


_SKIP_REM = _load_skip_remediation()


def _load_hacker_question_obligations_module():
    spec = importlib.util.spec_from_file_location(
        "_hacker_question_obligations_closeout",
        REPO_ROOT / "tools" / "hacker-question-obligations.py",
    )
    if spec is None or spec.loader is None:  # pragma: no cover (defensive)
        return None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_hacker_question_obligations_closeout"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:  # pragma: no cover - fail-open to WARN row
        return None
    return mod


_HACKER_QUESTION_OBLIGATIONS = _load_hacker_question_obligations_module()


# ---- check-result plumbing -------------------------------------------------

PASS = "PASS"
WARN = "WARN"
FAIL = "FAIL"


def _env_int_days(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value < 0:
        return default
    return value


def _queue_age_thresholds() -> tuple[int, int]:
    """Resolve (warn_days, fail_days) from env, with safe fallbacks.

    The ordering invariant ``fail_days >= warn_days`` is enforced so a typo
    like ``WARN=30 FAIL=7`` cannot create a dead band where WARN never fires.
    """
    warn_days = _env_int_days("AUDITOOOR_QUEUE_WARN_DAYS", DEFAULT_QUEUE_WARN_DAYS)
    fail_days = _env_int_days("AUDITOOOR_QUEUE_FAIL_DAYS", DEFAULT_QUEUE_FAIL_DAYS)
    if fail_days < warn_days:
        fail_days = warn_days
    return warn_days, fail_days


def _require_no_stale_queues() -> bool:
    return os.environ.get("REQUIRE_NO_STALE_QUEUES", "").strip() in {"1", "true", "yes"}


def _age_status(age_days: float, warn_days: int, fail_days: int) -> str:
    """PASS / WARN / FAIL for one queue item of the given age.

    ``REQUIRE_NO_STALE_QUEUES`` promotes WARN to FAIL so CI can hard-gate
    even before items cross the 30-day fail threshold.
    """
    if age_days >= fail_days:
        return FAIL
    if age_days >= warn_days:
        return FAIL if _require_no_stale_queues() else WARN
    return PASS


def _age_days_from_mtime(mtime: float, *, now: float | None = None) -> float:
    if mtime <= 0:
        return 0.0
    ref = time.time() if now is None else now
    delta = ref - mtime
    if delta < 0:
        return 0.0
    return delta / 86400.0


def _aggregate_status(statuses: Iterable[str]) -> str:
    """Pick the worst status from a sequence: FAIL > WARN > PASS."""
    seen = set(statuses)
    if FAIL in seen:
        return FAIL
    if WARN in seen:
        return WARN
    return PASS


@dataclass
class CheckResult:
    check: str
    status: str  # PASS | WARN | FAIL
    reason: str = ""
    artifacts: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "check": self.check,
            "status": self.status,
            "reason": self.reason,
            "artifacts": [str(p) for p in self.artifacts],
            "detail": self.detail,
        }


# ---- helpers --------------------------------------------------------------


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


def _glob(root: Path, pattern: str) -> list[Path]:
    try:
        return sorted(root.glob(pattern))
    except OSError:
        return []


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _read_json(path: Path) -> object | None:
    """Read a JSON file. Returns the decoded value, or ``None`` on I/O / parse
    error. Callers MUST ``isinstance``-check the return value before using
    ``.get(...)`` etc. — a manifest file containing the literal JSON ``42``
    or ``"string"`` is valid JSON but the wrong shape, and we treat that as
    "unrecognised" rather than crash with ``AttributeError`` (Kimi review)."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _format_count_map(value: object) -> str:
    if not isinstance(value, dict):
        return ""
    pairs = [
        f"{key}={val}"
        for key, val in sorted(value.items())
        if isinstance(key, str) and isinstance(val, int) and val > 0
    ]
    return ", ".join(pairs)


def _safe_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _dir_has_real_file(p: Path, *, suffixes: tuple[str, ...] = ()) -> bool:
    """Return True iff ``p`` is a directory containing at least one
    non-dotfile FILE (``is_file()`` true). Optionally restricted by
    ``suffixes`` (e.g. ``(".md",)`` for mining briefs).

    The earlier shape ``any(c for c in p.iterdir() if not c.name.startswith
    ("."))`` accepted a bare subdirectory or a broken symlink as evidence
    (Kimi review Bug 1). This helper insists on a real file.
    """
    norm_suffixes = tuple(
        s.lower() if s.startswith(".") else "." + s.lower() for s in suffixes
    )
    try:
        for c in p.iterdir():
            if c.name.startswith("."):
                continue
            try:
                if not c.is_file():
                    continue
            except OSError:
                continue
            if norm_suffixes and not any(
                c.name.lower().endswith(s) for s in norm_suffixes
            ):
                continue
            return True
        return False
    except OSError:
        return False


_GO_DLT_VENDOR_DIRS = {
    ".git",
    ".auditooor",
    ".audit_logs",
    "build",
    "cache",
    "node_modules",
    "out",
    "target",
    "vendor",
}


def _workspace_has_non_vendor_go_files(ws: Path) -> bool:
    """Return true if the workspace has at least one non-vendor Go source.

    Mirrors the audit-deep Go/DLT applicability check closely enough for
    closeout without shelling out to ``find``.
    """
    try:
        for path in ws.rglob("*.go"):
            try:
                rel_parts = path.relative_to(ws).parts
            except ValueError:
                rel_parts = path.parts
            if any(part in _GO_DLT_VENDOR_DIRS for part in rel_parts[:-1]):
                continue
            if path.is_file():
                return True
    except OSError:
        return False
    return False


# ---- check 1: canonical-audit ---------------------------------------------

# Primary artifacts a healthy `make audit` run leaves behind. Each entry is
# (relative-path, kind) — ``file`` is a single file, ``dir-glob`` is a
# directory we glob for any non-dotfile child.
_CANONICAL_PRIMARY = [
    # (relative-path, kind, suffixes-for-dir-globs)
    ("engage_report.md", "file", ()),
    ("INTAKE_BASELINE.json", "file", ()),
    ("SCAN_REPORT.md", "file", ()),
    ("swarm/mining_priorities.json", "file", ()),
    # mining_briefs is a directory of .md files; require at least one real
    # non-dotfile .md file (Kimi review Bug 1: a stray subdirectory should
    # not satisfy the artifact gate).
    ("swarm/mining_briefs", "dir-glob", (".md",)),
    # submissions/packaged is a directory of bundle subdirectories; require
    # at least one non-dotfile entry that is a directory (the canonical
    # bundle layout).
    ("submissions/packaged", "dir-glob-bundles", ()),
]


def _dir_has_real_subdir(p: Path) -> bool:
    """Return True iff ``p`` is a directory with at least one non-dotfile
    SUBDIRECTORY child (``submissions/packaged/<slug>/``). A real
    ``submission-packager.py`` run lays one subdirectory per bundle; an
    empty marker directory like ``packaged/.gitkeep`` should NOT pass.
    """
    try:
        for c in p.iterdir():
            if c.name.startswith("."):
                continue
            try:
                if c.is_dir():
                    return True
            except OSError:
                continue
        return False
    except OSError:
        return False


def check_canonical_audit(ws: Path) -> CheckResult:
    """Look for primary artifacts of a real ``make audit`` run.

    PASS if at least 3 of the primary artifact rows are present (a real run
    produces all 6, but a partial-but-real run is still better than none).
    WARN if 1-2 are present (inferred but thin). FAIL on zero.
    """
    found: list[str] = []
    missing: list[str] = []
    for rel, kind, suffixes in _CANONICAL_PRIMARY:
        p = ws / rel
        if kind == "file":
            ok = _exists(p) and p.is_file() and p.stat().st_size > 0
        elif kind == "dir-glob":
            ok = (
                _exists(p)
                and p.is_dir()
                and _dir_has_real_file(p, suffixes=suffixes)
            )
        elif kind == "dir-glob-bundles":
            ok = _exists(p) and p.is_dir() and _dir_has_real_subdir(p)
        else:  # pragma: no cover (defensive, structural enum)
            ok = False
        (found if ok else missing).append(rel)

    detail = {"found": found, "missing": missing}
    artifacts = [str(ws / rel) for rel in found]

    if len(found) >= 3:
        return CheckResult(
            check="canonical-audit",
            status=PASS,
            reason=f"{len(found)}/{len(_CANONICAL_PRIMARY)} primary artifacts present",
            artifacts=artifacts,
            detail=detail,
        )
    if len(found) >= 1:
        return CheckResult(
            check="canonical-audit",
            status=WARN,
            reason=(
                f"only {len(found)}/{len(_CANONICAL_PRIMARY)} primary artifacts; "
                "infer partial run, missing: " + ", ".join(missing)
            ),
            artifacts=artifacts,
            detail=detail,
        )
    return CheckResult(
        check="canonical-audit",
        status=FAIL,
        reason=(
            "no primary `make audit` artifacts; the canonical 30-stage chain "
            "does not appear to have run on this workspace"
        ),
        artifacts=[],
        detail=detail,
    )


# ---- check 2: audit-deep-all ----------------------------------------------

_EXPECTED_DEEP_PROFILES = ("default", "math", "econ", "crypto")
_DEEP_OK_STATUSES = {"success", "skipped_budget", "failed"}


def check_audit_deep_all(ws: Path, require_deep: bool) -> CheckResult:
    """Parse `<ws>/.audit_logs/audit_deep_all_manifest.json` (PR #246).

    PASS when the four child profiles each carry an explicit status.
    WARN (or FAIL when ``--require-deep``) when the manifest is missing.
    FAIL when a child profile is missing without explanation, or when an
    unrecognised status is recorded.
    """
    manifest_path = ws / ".audit_logs" / "audit_deep_all_manifest.json"
    if not _exists(manifest_path):
        status = FAIL if require_deep else WARN
        return CheckResult(
            check="audit-deep-all",
            status=status,
            reason=(
                "audit_deep_all_manifest.json not found; "
                "`make audit-deep WS=... DEEP_PROFILE=all` was not run"
                + (" (--require-deep)" if require_deep else "")
            ),
            artifacts=[],
            detail={"path": str(manifest_path)},
        )

    payload = _read_json(manifest_path)
    if payload is None:
        return CheckResult(
            check="audit-deep-all",
            status=FAIL,
            reason="audit_deep_all_manifest.json present but unreadable / not JSON",
            artifacts=[str(manifest_path)],
            detail={"path": str(manifest_path)},
        )
    # Defensive shape check (Kimi review Bug 5): a manifest containing
    # the literal JSON `42` / `"string"` / `[]` / `null` decodes to a
    # non-dict value and would crash `payload.get(...)` with AttributeError.
    if not isinstance(payload, dict):
        return CheckResult(
            check="audit-deep-all",
            status=FAIL,
            reason=(
                "audit_deep_all_manifest.json has unexpected JSON shape "
                f"({type(payload).__name__}); expected an object with a "
                "`profiles` array (auditooor.audit_deep_all.v1)"
            ),
            artifacts=[str(manifest_path)],
            detail={"path": str(manifest_path), "shape": type(payload).__name__},
        )
    raw_profiles = payload.get("profiles", [])
    if not isinstance(raw_profiles, list):
        return CheckResult(
            check="audit-deep-all",
            status=FAIL,
            reason=(
                "audit_deep_all_manifest.json `profiles` is not a list "
                f"(got {type(raw_profiles).__name__})"
            ),
            artifacts=[str(manifest_path)],
            detail={"path": str(manifest_path)},
        )
    profiles = {}
    for row in raw_profiles:
        if not isinstance(row, dict):
            continue
        key = row.get("profile")
        if isinstance(key, str):
            profiles[key] = row
    rows = []
    missing = []
    bad_status = []
    for name in _EXPECTED_DEEP_PROFILES:
        row = profiles.get(name)
        if row is None:
            missing.append(name)
            continue
        st = (row.get("status") or "").strip()
        # Allow any "skipped_*" status (skipped_budget is the canonical one,
        # skipped_inapplicable / skipped_no_artifact are forward-compatible).
        ok = st in _DEEP_OK_STATUSES or st.startswith("skipped_") or st == "success"
        if not ok:
            bad_status.append(f"{name}={st or '<empty>'}")
        rows.append({"profile": name, "status": st, "exit_code": row.get("exit_code")})

    detail = {
        "manifest": str(manifest_path),
        "expected_profiles": list(_EXPECTED_DEEP_PROFILES),
        "rows": rows,
        "missing_profiles": missing,
        "unrecognised_statuses": bad_status,
    }
    deep_candidates = _glob(ws, "deep_candidates/**/*.json")
    promo_path_raw = payload.get("typed_candidate_promotion")
    promo_path = Path(promo_path_raw) if isinstance(promo_path_raw, str) else (
        ws / ".audit_logs" / "typed_candidate_promotions.json"
    )
    if not promo_path.is_absolute():
        promo_path = ws / promo_path
    promotion_payload = _read_json(promo_path) if _exists(promo_path) else None
    detail["deep_candidate_count"] = len(deep_candidates)
    detail["typed_candidate_promotion"] = str(promo_path)
    if isinstance(promotion_payload, dict):
        detail["promotion_decision_counts"] = promotion_payload.get("decision_counts", {})
        detail["promotion_candidate_count"] = promotion_payload.get("candidate_count")
        detail["promotion_blocker_counts"] = promotion_payload.get("blocker_counts", {})
        work_items = promotion_payload.get("work_items", [])
        detail["promotion_work_item_count"] = len(work_items) if isinstance(work_items, list) else 0

    if missing:
        return CheckResult(
            check="audit-deep-all",
            status=FAIL,
            reason=(
                "audit_deep_all_manifest.json is missing child profile(s) "
                "with no explicit status: " + ", ".join(missing)
            ),
            artifacts=[str(manifest_path)],
            detail=detail,
        )
    if bad_status:
        return CheckResult(
            check="audit-deep-all",
            status=FAIL,
            reason=(
                "audit_deep_all_manifest.json has unrecognised status(es): "
                + ", ".join(bad_status)
                + " (expected one of: success, failed, skipped_*)"
            ),
            artifacts=[str(manifest_path)],
            detail=detail,
        )
    if deep_candidates and not _exists(promo_path):
        return CheckResult(
            check="audit-deep-all",
            status=WARN,
            reason=(
                "typed deep_candidates exist but typed_candidate_promotions.json "
                "is missing; rerun `DEEP_PROFILE=all make audit-deep` on current "
                "main so candidates are sorted into rejected/needs_poc/poc_ready"
            ),
            artifacts=[str(manifest_path)],
            detail=detail,
        )
    if deep_candidates and promotion_payload is None:
        return CheckResult(
            check="audit-deep-all",
            status=WARN,
            reason="typed_candidate_promotions.json exists but is unreadable / not JSON",
            artifacts=[str(manifest_path), str(promo_path)],
            detail=detail,
        )
    blocker_summary = ""
    if isinstance(promotion_payload, dict):
        formatted = _format_count_map(promotion_payload.get("blocker_counts", {}))
        if formatted:
            blocker_summary = f"; blockers: {formatted}"

    return CheckResult(
        check="audit-deep-all",
        status=PASS,
        reason=(
            "all 4 child profiles have explicit status in deep-all manifest"
            + (
                "; typed candidate promotion report present"
                if deep_candidates
                else ""
            )
            + blocker_summary
        ),
        artifacts=[str(manifest_path)] + ([str(promo_path)] if _exists(promo_path) else []),
        detail=detail,
    )


# ---- check 3: pattern-mining ----------------------------------------------

_PATTERN_MINING_ARTIFACTS = (
    "cross_ws_patterns.md",
    "pattern_migration_alert.md",
    "SOLODIT_SEARCH_PLAN.md",
    "PATTERN_HITS.md",
)
_PATTERN_MINING_SKIP_MARKER = ".audit_logs/pattern_mining_skip.md"


def check_pattern_mining(ws: Path) -> CheckResult:
    """Pattern-mining evidence (cross-ws, migration, solodit, hits)."""
    found = [a for a in _PATTERN_MINING_ARTIFACTS if _exists(ws / a)]
    if found:
        return CheckResult(
            check="pattern-mining",
            status=PASS,
            reason=f"{len(found)} pattern-mining artifact(s) present",
            artifacts=[str(ws / a) for a in found],
            detail={"found": list(found), "expected": list(_PATTERN_MINING_ARTIFACTS)},
        )

    skip_marker = ws / _PATTERN_MINING_SKIP_MARKER
    if _exists(skip_marker):
        text = _read_text(skip_marker).strip()
        # Empty / whitespace-only marker is NOT an explicit skip — Kimi
        # review Bug 2: `touch` on the marker would otherwise silently
        # downgrade FAIL to WARN.
        if not text:
            return CheckResult(
                check="pattern-mining",
                status=FAIL,
                reason=(
                    "pattern-mining skip marker exists but is empty / "
                    "whitespace-only; an explicit skip requires a written "
                    "reason. Either run pattern-mining or write the reason "
                    f"into {_PATTERN_MINING_SKIP_MARKER}."
                ),
                artifacts=[str(skip_marker)],
                detail={"skip_marker": str(skip_marker), "marker_empty": True},
            )
        reason_summary = text.splitlines()[0]
        return CheckResult(
            check="pattern-mining",
            status=WARN,
            reason=(
                "no pattern-mining artifacts; explicit skip marker present at "
                f"{_PATTERN_MINING_SKIP_MARKER}: {reason_summary[:120]}"
            ),
            artifacts=[str(skip_marker)],
            detail={"skip_marker": str(skip_marker), "marker_first_line": reason_summary},
        )

    return CheckResult(
        check="pattern-mining",
        status=FAIL,
        reason=(
            "no pattern-mining artifacts and no explicit skip marker. "
            "Either run `engage.py --stage cross-ws-patterns,pattern-migration,"
            "scan` or write `<ws>/.audit_logs/pattern_mining_skip.md` with a "
            "reason."
        ),
        artifacts=[],
        detail={
            "expected": list(_PATTERN_MINING_ARTIFACTS),
            "skip_marker": str(skip_marker),
        },
    )


# ---- check 4: hypotheses (V5 Gap-23) --------------------------------------


def check_hypotheses(ws: Path) -> CheckResult:
    """V5 Gap-23: HYPOTHESIS_PROMPT.md without HYPOTHESES.md is a silent
    failure of stage 16 (engage.py hypothesis generation). FAIL.
    """
    prompt = ws / "HYPOTHESIS_PROMPT.md"
    final = ws / "HYPOTHESES.md"
    has_prompt = _exists(prompt)
    has_final = _exists(final)

    if has_prompt and not has_final:
        return CheckResult(
            check="hypotheses",
            status=FAIL,
            reason=(
                "V5 Gap-23: HYPOTHESIS_PROMPT.md exists but HYPOTHESES.md is "
                "missing. Stage 16 silently emitted the prompt without "
                "producing the final hypotheses file. Re-run hypothesis "
                "generation or document the skip."
            ),
            artifacts=[str(prompt)],
            detail={"prompt": str(prompt), "final": str(final)},
        )
    if has_prompt and has_final:
        return CheckResult(
            check="hypotheses",
            status=PASS,
            reason="HYPOTHESIS_PROMPT.md and HYPOTHESES.md both present",
            artifacts=[str(prompt), str(final)],
            detail={"prompt": str(prompt), "final": str(final)},
        )
    if has_final and not has_prompt:
        # Operator wrote HYPOTHESES.md by hand without running the prompt
        # stage; that is fine but worth noting.
        return CheckResult(
            check="hypotheses",
            status=WARN,
            reason=(
                "HYPOTHESES.md present without HYPOTHESIS_PROMPT.md; "
                "manual authorship is fine but the prompt-emit stage did not run"
            ),
            artifacts=[str(final)],
            detail={"prompt": str(prompt), "final": str(final)},
        )
    # Neither file — stage simply did not run. WARN, not FAIL: a workspace
    # may legitimately not be at the hypothesis stage yet (e.g. in a partial
    # run gated by --require-deep). Gap-23 is the asymmetric case.
    return CheckResult(
        check="hypotheses",
        status=WARN,
        reason="neither HYPOTHESIS_PROMPT.md nor HYPOTHESES.md present",
        artifacts=[],
        detail={"prompt": str(prompt), "final": str(final)},
    )


# ---- check 5: agent-synthesize --------------------------------------------


def _synth_json_is_substantive(path: Path) -> bool:
    """A synthesis JSON file is substantive if it parses AND its top-level
    container is non-empty (Minimax review Gap 4: an agent could fabricate
    completion by writing ``[]`` or ``{}`` to either file).
    """
    if not _exists(path):
        return False
    payload = _read_json(path)
    if isinstance(payload, list):
        return len(payload) > 0
    if isinstance(payload, dict):
        return len(payload) > 0
    return False


def check_agent_synthesize(ws: Path) -> CheckResult:
    """``swarm/brief_candidates.json`` / ``agent_verdicts.json`` /
    ``agent_outputs/*``. PASS on substantive synthesis JSON, WARN on
    outputs without synthesis (or only empty synthesis JSON), FAIL on
    neither.
    """
    brief = ws / "swarm" / "brief_candidates.json"
    verdicts = ws / "swarm" / "agent_verdicts.json"
    out_dir = ws / "agent_outputs"
    out_files = _glob(out_dir, "*") if _exists(out_dir) else []
    out_count = sum(1 for p in out_files if p.is_file())

    # PASS only when at least one synthesis JSON is substantive (non-empty).
    has_synth = _synth_json_is_substantive(brief) or _synth_json_is_substantive(verdicts)
    if has_synth:
        artifacts = []
        if _exists(brief):
            artifacts.append(str(brief))
        if _exists(verdicts):
            artifacts.append(str(verdicts))
        return CheckResult(
            check="agent-synthesize",
            status=PASS,
            reason=(
                "synthesis JSON present"
                f" (brief_candidates.json={'yes' if _exists(brief) else 'no'}, "
                f"agent_verdicts.json={'yes' if _exists(verdicts) else 'no'})"
            ),
            artifacts=artifacts,
            detail={
                "brief": str(brief),
                "verdicts": str(verdicts),
                "agent_outputs_count": out_count,
            },
        )
    if out_count > 0:
        return CheckResult(
            check="agent-synthesize",
            status=WARN,
            reason=(
                f"{out_count} agent_outputs/* file(s) present but no synthesis "
                "JSON. Run `engage.py --stage agent-synthesize`."
            ),
            artifacts=[str(out_dir)],
            detail={
                "brief": str(brief),
                "verdicts": str(verdicts),
                "agent_outputs_count": out_count,
            },
        )
    return CheckResult(
        check="agent-synthesize",
        status=FAIL,
        reason=(
            "no agent outputs and no synthesis JSON; the close-out lane never "
            "ran. Expected at least swarm/brief_candidates.json or "
            "swarm/agent_verdicts.json."
        ),
        artifacts=[],
        detail={
            "brief": str(brief),
            "verdicts": str(verdicts),
            "agent_outputs_count": 0,
        },
    )


# ---- check: MCP context evidence ------------------------------------------

_MCP_CONTEXT_NEEDLES = {
    "resume": ("vault_resume_context", "auditooor.vault_context_pack.v1:resume:"),
    "exploit": ("vault_exploit_context", "auditooor.vault_exploit_context.v1:exploit:"),
    "harness": ("vault_harness_context", "auditooor.vault_harness_context.v1:harness:"),
    "knowledge_gap": (
        "vault_knowledge_gap_context",
        "auditooor.vault_knowledge_gap_context.v1:knowledge_gap:",
    ),
}
_HIGH_MED_CRIT_RE = re.compile(
    r"\b(?:severity|impact|risk)\s*[:=]\s*(?:critical|high|medium)\b",
    re.IGNORECASE,
)


def _workspace_has_hm_memory_promotion(ws: Path) -> bool:
    for draft in _discover_pre_submit_drafts(ws):
        if _HIGH_MED_CRIT_RE.search(_strip_frontmatter(_read_text(draft))):
            return True
    for dirname in ("final_cantina_paste", "final_paste", "poc_notes"):
        root = ws / dirname
        if not root.is_dir():
            continue
        for path in _glob(root, "*.md") + _glob(root, "**/*.md"):
            text = _strip_frontmatter(_read_text(path))
            if _HIGH_MED_CRIT_RE.search(text) and not re.search(
                r"\b(?:killed|duplicate|oos|out of scope|false positive|no hm)\b",
                text[:1600],
                re.IGNORECASE,
            ):
                return True
    return False


# Existing final/operator paste artifacts can be hand-edited or produced by
# tools other than submission-factory, so closeout owns an output-layer hygiene
# sweep that is independent of any generator's internal refusal rules.
_FINAL_PASTE_GLOBS = (
    "paste-ready/*.md",
    "paste_ready/*.md",
    "cantina_paste/*.md",
    "final_cantina_paste/*.md",
    "operator_paste/*.md",
    "final_paste/*.md",
    "submissions/paste-ready/*.md",
    "submissions/paste_ready/*.md",
    "submissions/cantina_paste/*.md",
    "submissions/final_cantina_paste/*.md",
    "submissions/operator_paste/*.md",
    "submissions/final_paste/*.md",
    "submissions/packaged/**/*_ready.md",
)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
# Whitelist of HTML-comment markers that are LEGITIMATE in paste-ready drafts.
# These are sanctioned by individual R-rules / L-rules (see ~/.claude/CLAUDE.md
# "Hard do not list") as the ONLY accepted form of in-draft rebuttal /
# coordination marker. Treating them as `html_comment` hygiene violations
# produces structural false-fails on otherwise-clean paste-ready drafts.
#
# Categories:
#   1. Rule-rebuttal markers: <!-- r22-rebuttal: ... -->, <!-- l29-rebuttal: ... -->
#      (R20..R58 and L29..L34 all use the HTML-comment form).
#   2. Named-rebuttal markers used by specific gate tooling:
#      reachability, config-downstream, opposed-trace, operator-action,
#      auditooor-tracker, oos-dupe, novel-vector, dupe, rebuttal (bare).
#   3. AUDITOOOR_* coordination markers: AUDITOOOR_TRACKER_MANAGED_START / _END,
#      AUDITOOOR_PR_MANAGED_*, and similar bracketed managed-block markers.
#   4. Bounded reason payload (<=200 chars) per the codified-rules contract;
#      empty or oversized payloads on rule-rebuttal markers are NOT whitelisted
#      so the original rule-side gate (which also enforces the 200-char cap)
#      still surfaces the violation. The hygiene check defers to the rule-side
#      gate for payload sanity.
_PASTE_HYGIENE_ALLOWED_COMMENT_RE = re.compile(
    r"<!--\s*(?:"
    # 1. Rule-rebuttal markers (r10..r99, l10..l99). The payload must contain
    # at least one non-whitespace character after the colon; the rule-side
    # gate (e.g. tools/<rule>-check.py) separately enforces the 200-char
    # bounded-payload contract and ignores oversized payloads. Payload may
    # contain `<` (Rust generics like `Fees::<T>`) - `>` cannot appear
    # inside an HTML comment body until `-->`, so a non-greedy `.+?` under
    # re.DOTALL anchored by `\s*-->` is safe.
    r"[rl]\d{1,3}-rebuttal\s*:\s*\S.*?|"
    # r36-rebuttal: lane polish-optimism-hygiene registered in .auditooor/agent_pathspec.json; add gap30 sanctioned-marker parity to paste-hygiene whitelist
    # 2. Named-rebuttal markers (reachability, config-downstream, opposed-trace,
    # operator-action, auditooor-tracker, oos-dupe, novel-vector, dupe,
    # workspace-artifact, gap<NN> (sanctioned gate markers e.g. gap30), rebuttal).
    # Bounded similarly to (1).
    r"(?:reachability|config-downstream|opposed-trace|operator-action|"
    r"auditooor-tracker|oos-dupe|novel-vector|dupe|workspace-artifact|"
    # severity-calibration / oos-natural-activity: these two markers are
    # REQUIRED by their rule-side gates (severity-calibration-check.py and
    # per-finding-oos-check.py resp.) to green a legitimate calibration /
    # natural-activity rebuttal. Without them here the hygiene gate (#43)
    # and the rule gates that DEMAND the marker were mutually exclusive -
    # any finding that earned either rebuttal could never pass both. The
    # rule-side gate still validates the payload; whitelisting only the
    # marker NAME here resolves the deadlock without greening anything.
    r"severity-calibration|oos-natural-activity|"
    # r-escalate-first / r-escalate-measure (escalate-first-required-check.py)
    # and severity-calibration-gate (severity-calibration-gate.py) are REQUIRED
    # by their rule-side gates to green a legitimate escalate-first-deferral /
    # measured-escalation / calibration-gate rebuttal. Co-firing is CONFIRMED
    # (escalate-first-required-check wired at pre-submit, severity-calibration-gate
    # promoted through high-plus-submission-gate into #76). Without them here the
    # hygiene gate (#43) and those rule gates were mutually exclusive. The
    # rule-side gate still validates the payload; whitelisting only the marker
    # NAME here resolves the deadlock without greening anything.
    r"r-escalate-first|r-escalate-measure|severity-calibration-gate|"
    # r82-restart-executed (impact-recovery-falsification-check.py): dedicated rebuttal
    # that a permanent claim's permanence is NOT restart-based, so the executed
    # close-and-reopen restart-survival PoC requirement does not apply.
    r"r82-restart-executed|"
    # escalation-workflow (escalation-workflow-planner.py / ESCALATION-WORKFLOW-REQUIRED
    # check #141): dedicated rebuttal asserting the finding is at its max reachable tier
    # so the multi-lane escalation workflow need not be run. Check #141 REQUIRES this
    # marker to green a max-tier finding; without it here the hygiene gate (#43) and
    # #141 were mutually exclusive (same deadlock as r-escalate-first above). The
    # rule-side gate still validates the payload; whitelisting only the marker NAME
    # here resolves the deadlock without greening anything.
    r"escalation-workflow|"
    r"gap\d{1,3}|rebuttal)-rebuttal\s*:\s*\S.*?|"
    # 3. AUDITOOOR_* coordination markers (e.g. AUDITOOOR_TRACKER_MANAGED_START,
    # AUDITOOOR_TRACKER_MANAGED_END, AUDITOOOR_PR_MANAGED_START / _END).
    r"AUDITOOOR[_A-Z0-9]+"
    r")\s*-->",
    re.DOTALL,
)
_LOCAL_ABSOLUTE_PATH_RE = re.compile(
    r"(?<![\w])(?:"
    r"/Users/[^\s)`'\"<>]+|"
    r"/home/[^\s)`'\"<>]+|"
    r"/private/(?:tmp|var)/[^\s)`'\"<>]+|"
    r"/var/folders/[^\s)`'\"<>]+|"
    r"/tmp/[^\s)`'\"<>]+|"
    r"[A-Za-z]:\\[^\s)`'\"<>]+"
    r")"
)
_MANUAL_FILL_PLACEHOLDER_RE = re.compile(
    r"(?:"
    r"<TODO_OPERATOR\b|TODO_OPERATOR\b|"
    r"manual[- ]fill(?: required)?|"
    r"not available\s+[-—]\s+manual fill required|"
    r"<(?:fill|insert|replace)[^>]*>|"
    r"\[(?:TODO|TBD|fill(?: me| in)?|insert|replace)[^\]]*\]|"
    r"\b(?:TODO|TBD)\s*:"
    r")",
    re.IGNORECASE,
)
# wave-2 #5: internal labels that cantina-paste-scrub (L27) strips before filing. If any
# survive into a final_cantina_paste file, the paste was filed WITHOUT scrubbing - the
# hygiene gate flags it so the operator runs tools/cantina-paste-scrub.py first.
_FINAL_PASTE_INTERNAL_LABEL_RE = re.compile(
    r"(?:"
    r"RG-KILL-\d+|"
    r"\bRG-N\d+-S\d+\b|"
    r"submissions/(?:staging|held|internal_sidecars)/|"
    r"agent_outputs/|"
    r"\bWorker-[A-Z]+\b"
    r")"
)
_POC_HEADING_RE = re.compile(
    r"^(#{2,6})\s+(.+?)\s*$",
    re.MULTILINE,
)
_POC_PATH_RE = re.compile(
    r"(?:"
    r"(?:\.{0,2}/)?(?:[\w.-]+/)+[\w.-]+\.(?:t\.sol|sol|rs|go|py|js|ts|tsx|move|md|json|txt|log)|"
    r"[\w.-]+\.(?:t\.sol|sol|rs|go|py|js|ts|tsx|move)"
    r")"
)
_POC_COMMAND_OR_RESULT_RE = re.compile(
    r"\b(?:forge\s+test|cargo\s+test|npm\s+test|yarn\s+test|pnpm\s+test|"
    r"pytest|go\s+test|Suite result:\s*ok|PASS|passed|Result:\s*proved|"
    r"test result:\s*ok|function\s+test|contract\s+\w+)\b",
    re.IGNORECASE,
)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


def _iter_final_paste_files(ws: Path) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    for pattern in _FINAL_PASTE_GLOBS:
        for path in _glob(ws, pattern):
            if not path.is_file() or path.name == "INDEX.md":
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            files.append(path)
    return sorted(files)


def _normalise_poc_heading(raw: str) -> str:
    name = re.sub(r"[*_`]+", "", raw.lower())
    name = re.sub(r"[^a-z0-9 /-]+", " ", name)
    return re.sub(r"\s+", " ", name).strip()


def _iter_poc_sections(text: str) -> Iterable[tuple[int, str, str]]:
    headings = list(_POC_HEADING_RE.finditer(text))
    for idx, match in enumerate(headings):
        title = _normalise_poc_heading(match.group(2))
        if not (
            "poc" in title
            or "proof of concept" in title
            or "test proof" in title
            or title == "proof"
        ):
            continue
        level = len(match.group(1))
        end = len(text)
        for next_match in headings[idx + 1:]:
            if len(next_match.group(1)) <= level:
                end = next_match.start()
                break
        yield (
            _line_number(text, match.start()),
            match.group(0).rstrip(),
            text[match.end():end],
        )


def _is_path_only_poc_body(body: str) -> bool:
    if not _POC_PATH_RE.search(body):
        return False
    if _POC_COMMAND_OR_RESULT_RE.search(body):
        return False
    lines = [
        ln.strip()
        for ln in body.splitlines()
        if ln.strip() and not ln.strip().startswith("```")
    ]
    if not lines or len(lines) > 4:
        return False
    for line in lines:
        cleaned = line.strip(" -*_`")
        cleaned = re.sub(
            r"^(?:(?:poc|proof(?: of concept)?)(?:\s+file)?|path|file|attachment|see)\s*[:\-]\s*",
            "",
            cleaned,
            flags=re.IGNORECASE,
        ).strip(" `.")
        if not cleaned:
            continue
        if not _POC_PATH_RE.fullmatch(cleaned):
            return False
    return True


def _code_block_line_set(text: str) -> set[int]:
    """Return 1-based line numbers covered by fenced or indented code blocks.

    Fenced blocks: lines between matching ``` (or ~~~) fences, inclusive.
    Indented blocks: contiguous runs of >=4-space-prefixed (or tab-prefixed)
    lines preceded by a blank line, mirroring CommonMark's indented-code rule.
    Markdown citations of source code commonly contain `// TODO:` and similar
    tokens that look like operator placeholders but are real code being quoted;
    treating them as paste-hygiene violations produces false positives.
    """
    lines = text.split("\n")
    in_fence = False
    fence_marker = ""
    code_lines: set[int] = set()
    for idx, line in enumerate(lines, start=1):
        stripped = line.lstrip()
        if not in_fence and (stripped.startswith("```") or stripped.startswith("~~~")):
            in_fence = True
            fence_marker = stripped[:3]
            code_lines.add(idx)
            continue
        if in_fence:
            code_lines.add(idx)
            if stripped.startswith(fence_marker):
                in_fence = False
                fence_marker = ""
            continue
        # indented code block: line starts with 4+ spaces or a tab and the
        # previous non-empty content line is blank (or this is start-of-file).
        if line.startswith("    ") or line.startswith("\t"):
            prev_nonempty = ""
            for back in range(idx - 2, -1, -1):
                if lines[back].strip():
                    prev_nonempty = lines[back]
                    break
                prev_nonempty = ""
            if not prev_nonempty or prev_nonempty.startswith("    ") or prev_nonempty.startswith("\t"):
                code_lines.add(idx)
    return code_lines


def _final_paste_hygiene_violations(path: Path) -> list[dict]:
    text = _read_text(path)
    code_line_set = _code_block_line_set(text)
    violations: list[dict] = []
    # `manual_fill_placeholder` matches inside fenced/indented code blocks are
    # almost always quoted source code (e.g. `// TODO:` from upstream Go/Sol
    # files), not stray operator placeholders. Skip them for that label only.
    skip_in_code = {"manual_fill_placeholder"}
    for label, pattern in (
        ("html_comment", _HTML_COMMENT_RE),
        ("local_absolute_path", _LOCAL_ABSOLUTE_PATH_RE),
        ("manual_fill_placeholder", _MANUAL_FILL_PLACEHOLDER_RE),
    ):
        for match in pattern.finditer(text):
            line_no = _line_number(text, match.start())
            if label in skip_in_code and line_no in code_line_set:
                continue
            # Whitelist legitimate rule-rebuttal / coordination markers per
            # the codified-rules contract (Gap 18). The hygiene check should
            # only flag stray operator-leaked HTML comments (e.g. inline
            # `<!-- TODO: fix this -->`), not sanctioned rebuttal markers.
            if label == "html_comment" and _PASTE_HYGIENE_ALLOWED_COMMENT_RE.fullmatch(
                match.group(0)
            ):
                continue
            excerpt = re.sub(r"\s+", " ", match.group(0)).strip()
            violations.append(
                {
                    "file": str(path),
                    "line": line_no,
                    "kind": label,
                    "excerpt": excerpt[:160],
                }
            )
    for line, heading, body in _iter_poc_sections(text):
        if _is_path_only_poc_body(body):
            violations.append(
                {
                    "file": str(path),
                    "line": line,
                    "kind": "path_only_poc",
                    "excerpt": heading,
                }
            )
    # wave-2 #5: an un-scrubbed internal label in a final paste -> run cantina-paste-scrub.
    for match in _FINAL_PASTE_INTERNAL_LABEL_RE.finditer(text):
        violations.append(
            {
                "file": str(path),
                "line": _line_number(text, match.start()),
                "kind": "internal_label_unscrubbed",
                "excerpt": match.group(0)[:160],
                "fix": "run tools/cantina-paste-scrub.py before filing",
            }
        )
    return violations


def check_final_paste_hygiene(ws: Path) -> CheckResult:
    files = _iter_final_paste_files(ws)
    violations: list[dict] = []
    for path in files:
        violations.extend(_final_paste_hygiene_violations(path))

    counts: dict[str, int] = {}
    for row in violations:
        kind = str(row.get("kind") or "unknown")
        counts[kind] = counts.get(kind, 0) + 1
    detail = {
        "patterns": list(_FINAL_PASTE_GLOBS),
        "file_count": len(files),
        "files": [str(p) for p in files],
        "violation_counts": dict(sorted(counts.items())),
        "violations": violations,
    }
    if violations:
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        return CheckResult(
            check="final-paste-hygiene",
            status=FAIL,
            reason=(
                f"{len(violations)} unsafe final/operator paste hygiene issue(s) "
                f"across {len(files)} file(s): {summary}"
            ),
            artifacts=sorted({str(row["file"]) for row in violations}),
            detail=detail,
        )
    if not files:
        return CheckResult(
            check="final-paste-hygiene",
            status=PASS,
            reason="no final/operator paste artifacts found",
            artifacts=[],
            detail=detail,
        )
    return CheckResult(
        check="final-paste-hygiene",
        status=PASS,
        reason=f"{len(files)} final/operator paste artifact(s) passed hygiene checks",
        artifacts=[str(p) for p in files],
        detail=detail,
    )


def _memory_context_receipt_summary(
    ws: Path, *, require_proof: bool = False
) -> tuple[int, dict[str, Any]]:
    cmd = [
        sys.executable,
        str(REPO_ROOT / "tools" / "memory-context-load.py"),
        "--workspace",
        str(ws),
        "--check",
        "--json",
    ]
    if require_proof:
        cmd.append("--require-proof")
    proc = subprocess.run(cmd, cwd=REPO_ROOT, text=True, capture_output=True, check=False)
    text = proc.stdout.strip()
    try:
        payload = json.loads(text) if text else {}
    except json.JSONDecodeError:
        payload = {
            "status": "invalid_tool_output",
            "stdout": proc.stdout[-2000:],
            "stderr": proc.stderr[-2000:],
        }
    if proc.stderr.strip():
        payload.setdefault("stderr", proc.stderr.strip()[-2000:])
    return proc.returncode, payload


def _memory_context_reload_command(ws: Path, summary: dict[str, Any]) -> str:
    cmd = str(summary.get("next_command") or "").strip()
    if cmd:
        return cmd
    return (
        f"python3 tools/memory-context-load.py --workspace {ws} "
        "--from-requirements --write-receipt"
    )


def _memory_context_issue_summary(summary: dict[str, Any]) -> str:
    issues: list[str] = []
    missing = len(summary.get("missing_contexts", []) or [])
    stale = len(summary.get("stale_contexts", []) or [])
    invalid_rows = [
        row
        for row in (summary.get("invalid_contexts", []) or [])
        if isinstance(row, dict)
    ]
    invalid = len(invalid_rows)
    if missing:
        issues.append("required contexts missing from receipt")
    if stale:
        issues.append("receipt predates closeout-relevant candidate/PoC artifacts")
    if invalid:
        issues.append("receipt or pack validation failed")
        invalid_reasons = [
            str(reason).strip()
            for reason in (row.get("reason") for row in invalid_rows[:3])
            if isinstance(reason, str) and reason.strip()
        ]
        if invalid_reasons:
            issues.append(", ".join(invalid_reasons))
    return "; ".join(issues)


def check_mcp_context(ws: Path) -> CheckResult:
    """Require memory context receipt evidence, with legacy-id fallback.

    Vault MCP context is memory/continuity evidence, not exploit proof. The
    receipt row prevents an MCP-first workflow from being silently bypassed
    while audit/deep artifacts remain green. Narrative ids are preserved only
    as migration warnings because they cannot prove pack hash/freshness.
    """
    requirements_path = ws / ".auditooor" / "memory_requirements.json"
    receipt_path = ws / ".auditooor" / "memory_context_receipt.json"
    strict_required = (
        os.environ.get("REQUIRE_MEMORY_CONTEXT") == "1"
        or os.environ.get("STRICT_MEMORY_CONTEXT") == "1"
        or _workspace_has_hm_memory_promotion(ws)
    )
    if requirements_path.is_file() or receipt_path.is_file():
        rc, summary = _memory_context_receipt_summary(
            ws,
            require_proof=strict_required and receipt_path.is_file(),
        )
        status_text = str(summary.get("status", "unknown"))
        artifacts = [str(path) for path in (requirements_path, receipt_path) if path.is_file()]
        reason_counts = (
            f"required={summary.get('required_count', '?')} "
            f"loaded={summary.get('loaded_count', '?')} "
            f"missing={len(summary.get('missing_contexts', []) or [])} "
            f"stale={len(summary.get('stale_contexts', []) or [])}"
        )
        reload_cmd = _memory_context_reload_command(ws, summary)
        issue_summary = _memory_context_issue_summary(summary)
        issue_suffix = f"; {issue_summary}" if issue_summary else ""
        detail = {
            "receipt_mode": "strict_receipt",
            "tool_rc": rc,
            "strict_required": strict_required,
            "summary": summary,
            "advisory_boundary": (
                "MCP context is memory/continuity evidence only; it is not PoC, "
                "OOS, severity, or exploit proof."
            ),
        }
        if rc == 0:
            return CheckResult(
                check="mcp-context",
                status=PASS,
                reason=f"memory context receipt valid ({reason_counts})",
                artifacts=artifacts,
                detail=detail,
            )
        if rc == 1 or strict_required:
            return CheckResult(
                check="mcp-context",
                status=FAIL,
                reason=(
                    "strict memory-context closeout blocker: "
                    f"memory context receipt {status_text} ({reason_counts}{issue_suffix}); "
                    f"rerun `{reload_cmd}`"
                ),
                artifacts=artifacts,
                detail=detail,
            )
        return CheckResult(
            check="mcp-context",
            status=WARN,
            reason=(
                f"memory context receipt {status_text} ({reason_counts}{issue_suffix}); "
                f"rerun `{reload_cmd}`"
            ),
            artifacts=artifacts,
            detail=detail,
        )

    candidate_paths = [
        ws / "AUDIT.md",
        ws / "FINDINGS.md",
        ws / "SESSION_LOG.md",
        ws / ".audit_logs" / "audit_closeout_manifest.json",
    ]
    agent_dir = ws / "agent_outputs"
    if agent_dir.is_dir():
        candidate_paths.extend(sorted(agent_dir.glob("*.md"))[:50])

    found: dict[str, list[str]] = {key: [] for key in _MCP_CONTEXT_NEEDLES}
    scanned: list[str] = []
    for path in candidate_paths:
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scanned.append(str(path))
        for key, needles in _MCP_CONTEXT_NEEDLES.items():
            if any(needle in text for needle in needles):
                found[key].append(str(path))

    missing = [key for key, paths in found.items() if not paths]
    detail = {
        "required_contexts": sorted(_MCP_CONTEXT_NEEDLES),
        "found": {key: paths for key, paths in found.items() if paths},
        "missing": missing,
        "scanned": scanned,
        "advisory_boundary": (
            "MCP context is memory/continuity evidence only; it is not PoC, "
            "OOS, severity, or exploit proof."
        ),
    }
    artifacts = sorted({paths[0] for paths in found.values() if paths})
    if not missing:
        return CheckResult(
            check="mcp-context",
            status=FAIL if strict_required else WARN,
            reason=(
                "legacy MCP context ids recorded but no requirements/receipt pack files; "
                "run `python3 tools/memory-auto-link.py --workspace <ws> --write` and "
                "`python3 tools/memory-context-load.py --workspace <ws> --from-requirements --write-receipt`"
            ),
            artifacts=artifacts,
            detail=detail,
        )
    return CheckResult(
        check="mcp-context",
        status=WARN,
        reason=(
            "missing recorded MCP context: "
            + ", ".join(missing)
            + "; run vault_resume_context, vault_exploit_context, "
            "vault_harness_context, and vault_knowledge_gap_context before closeout"
        ),
        artifacts=artifacts,
        detail=detail,
    )


# ---- check (CISS-002): vault-mcp self-test regression --------------------
#
# `vault-mcp-server.py --self-test` is the regression invariant that gates
# the four MCP recall packs (resume / exploit / harness / knowledge-gap).
# Run it as a subprocess and emit a closeout row. Soft by default (PASS or
# WARN) so we do not block pre-existing audits, but escalate to FAIL when
# the operator opts in via `MCP_SELF_TEST_REQUIRED=1`. Mirrors the spirit
# of `make harness-failure-memory-validate` as a CI-style invariant.


def check_vault_mcp_self_test(ws: Path) -> CheckResult:
    """Run `tools/vault-mcp-server.py --self-test` and a follow-up
    `vault_resume_context` call against the workspace, asserting both
    exit 0 AND the resume call returns a non-empty `context_pack_id`.

    Soft by default: PASS on success, WARN on failure. Escalates to FAIL
    only when `MCP_SELF_TEST_REQUIRED=1` is set in the environment, so we
    do not retroactively break workspaces whose vault entrypoints are
    incomplete (the server already falls back to the active vault on its
    own and prints a banner; we tolerate that lead-in line).
    """
    server = REPO_ROOT / "tools" / "vault-mcp-server.py"
    strict = os.environ.get("MCP_SELF_TEST_REQUIRED") == "1"
    fail_status = FAIL if strict else WARN
    artifacts = [str(server)]

    if not server.is_file():
        return CheckResult(
            check="vault-mcp-self-test",
            status=fail_status,
            reason=(
                "tools/vault-mcp-server.py not found; cannot run "
                "vault-mcp self-test regression invariant (CISS-002)"
            ),
            artifacts=[],
            detail={"server_path": str(server), "strict": strict},
        )

    try:
        st_proc = subprocess.run(
            [sys.executable, str(server), "--self-test"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CheckResult(
            check="vault-mcp-self-test",
            status=fail_status,
            reason=f"vault-mcp self-test failed to launch: {exc!r}",
            artifacts=artifacts,
            detail={"strict": strict, "phase": "self-test", "error": repr(exc)},
        )
    if st_proc.returncode != 0:
        return CheckResult(
            check="vault-mcp-self-test",
            status=fail_status,
            reason=(
                f"vault-mcp self-test exited rc={st_proc.returncode}; "
                "rerun `python3 tools/vault-mcp-server.py --self-test` to repro (CISS-002)"
            ),
            artifacts=artifacts,
            detail={
                "strict": strict,
                "phase": "self-test",
                "rc": st_proc.returncode,
                "stdout": st_proc.stdout[-2000:],
                "stderr": st_proc.stderr[-2000:],
            },
        )

    args_payload = json.dumps({"workspace_path": str(ws), "limit": 2})
    try:
        rc_proc = subprocess.run(
            [
                sys.executable,
                str(server),
                "--call",
                "vault_resume_context",
                "--args",
                args_payload,
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CheckResult(
            check="vault-mcp-self-test",
            status=fail_status,
            reason=f"vault_resume_context launch failed: {exc!r}",
            artifacts=artifacts,
            detail={"strict": strict, "phase": "resume-context", "error": repr(exc)},
        )
    if rc_proc.returncode != 0:
        return CheckResult(
            check="vault-mcp-self-test",
            status=fail_status,
            reason=(
                f"vault_resume_context exited rc={rc_proc.returncode} "
                "(self-test passed but live recall path broken; CISS-002)"
            ),
            artifacts=artifacts,
            detail={
                "strict": strict,
                "phase": "resume-context",
                "rc": rc_proc.returncode,
                "stdout": rc_proc.stdout[-2000:],
                "stderr": rc_proc.stderr[-2000:],
            },
        )

    body_lines = [
        line
        for line in rc_proc.stdout.splitlines()
        if not line.startswith("[vault-mcp-server]")
    ]
    body = "\n".join(body_lines).strip()
    payload: dict[str, object] | None = None
    if body:
        try:
            decoded = json.loads(body)
            if isinstance(decoded, dict):
                payload = decoded
        except json.JSONDecodeError:
            payload = None
    if payload is None:
        return CheckResult(
            check="vault-mcp-self-test",
            status=fail_status,
            reason=(
                "vault_resume_context returned non-JSON or non-object payload "
                "after banner strip (CISS-002)"
            ),
            artifacts=artifacts,
            detail={
                "strict": strict,
                "phase": "resume-context",
                "stdout_tail": rc_proc.stdout[-2000:],
            },
        )
    pack_id = payload.get("context_pack_id")
    if not (isinstance(pack_id, str) and pack_id.strip()):
        return CheckResult(
            check="vault-mcp-self-test",
            status=fail_status,
            reason=(
                "vault_resume_context payload missing context_pack_id; "
                "self-test passed but live recall is empty (CISS-002)"
            ),
            artifacts=artifacts,
            detail={
                "strict": strict,
                "phase": "resume-context",
                "payload_keys": sorted(payload.keys()),
            },
        )
    pack_hash = payload.get("context_pack_hash")
    return CheckResult(
        check="vault-mcp-self-test",
        status=PASS,
        reason=(
            "vault-mcp self-test rc=0 and vault_resume_context returned "
            f"context_pack_id={pack_id}"
        ),
        artifacts=artifacts,
        detail={
            "strict": strict,
            "context_pack_id": pack_id,
            "context_pack_hash": pack_hash if isinstance(pack_hash, str) else None,
        },
    )


# ---- check 6: pre-submit --------------------------------------------------

# Severity tokens we treat as High/Critical for the production-path gate.
_HIGH_CRIT_RE = re.compile(
    r"^\s*[-*]?\s*\*?\*?"
    r"(?:severity(?:\s+claim(?:ed)?)?|impact|risk)"
    r"\*?\*?\s*[:=]\s*(?:`)?(?:\*\*)?\s*"
    r"(?P<sev>high|critical)\b",
    re.IGNORECASE | re.MULTILINE,
)
_NOT_SUBMIT_READY_RE = re.compile(r"\bNOT_SUBMIT_READY\b", re.IGNORECASE)
_EXECUTION_BLOCKED_RE = re.compile(r"\bEXECUTION_BLOCKED\b", re.IGNORECASE)
_PENDING_RUNTIME_POC_RE = re.compile(
    r"\b(?:pending\s+runnable\s+poc|must\s+execute\s+the\s+poc|"
    r"poc\s+(?:not\s+)?(?:run|executed|verified))\b",
    re.IGNORECASE,
)
_LISTED_IMPACT_FALSE_RE = re.compile(
    r"\blisted_impact_proven\s*=\s*false\b",
    re.IGNORECASE,
)


_FRONTMATTER_RE = re.compile(r"\A---\s*\n.*?\n---\s*\n", re.DOTALL)


def _strip_frontmatter(text: str) -> str:
    """Strip a leading YAML frontmatter block ``---\\n...\\n---\\n``, if any.

    Kimi review Bug 3: a draft with frontmatter ``severity: high`` should not
    override the body severity. We strip the frontmatter before scanning.
    """
    return _FRONTMATTER_RE.sub("", text, count=1)


def _has_real_production_path_section(text: str) -> bool:
    """Return True iff ``text`` contains a real ``## Production Path``
    markdown header (start-of-line, not inside a fenced code block, not
    inside an HTML comment).

    Kimi review Bug 4 / Minimax Gap 7: the previous shape ``"## Production
    Path" in text`` accepted the substring inside fenced code blocks, HTML
    comments, or quoted text as evidence. We reproduce a tighter check
    that mirrors the spirit of the mechanical pre-submit gate.
    """
    # Strip HTML comments (non-greedy, including newlines).
    sans_comments = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    # Strip fenced code blocks (``` ... ```).
    sans_code = re.sub(r"```.*?```", "", sans_comments, flags=re.DOTALL)
    # Look for a heading at start-of-line (after optional indentation).
    for line in sans_code.splitlines():
        if re.match(r"^\s*##+\s+production path\b", line, re.IGNORECASE):
            return True
    return False


def _severity_from_draft(text: str) -> str | None:
    """Extract the first severity-ish token from a draft markdown body.

    Returns one of ``"high"``, ``"critical"`` (lower-cased), or ``None``.
    The regex is intentionally conservative — we only flag drafts that
    explicitly call themselves High/Critical. Ambiguous drafts get a WARN
    in the aggregate, not a FAIL. Kimi review Bug 3: strip YAML
    frontmatter before scanning so a frontmatter-only severity does not
    override the body.
    """
    body = _strip_frontmatter(text)
    m = _HIGH_CRIT_RE.search(body)
    if m:
        return m.group("sev").lower()
    return None


def _draft_readiness_blockers(text: str) -> list[str]:
    """Return explicit "do not submit yet" markers from a draft body."""
    body = _strip_frontmatter(text)
    blockers: list[str] = []
    if _NOT_SUBMIT_READY_RE.search(body):
        blockers.append("NOT_SUBMIT_READY")
    if _EXECUTION_BLOCKED_RE.search(body):
        blockers.append("EXECUTION_BLOCKED")
    if _PENDING_RUNTIME_POC_RE.search(body):
        blockers.append("pending_runtime_poc")
    if _LISTED_IMPACT_FALSE_RE.search(body):
        blockers.append("listed_impact_proven=false")
    return blockers


def _normalize_skip_counts(value: object) -> dict[str, int]:
    keys = ("skipped_tools", "compile_failure_markers", "modules_failed", "total")
    if not isinstance(value, dict):
        return {key: 0 for key in keys}
    out: dict[str, int] = {}
    for key in keys:
        raw = value.get(key, 0)
        out[key] = raw if isinstance(raw, int) else 0
    return out


def _tool_status_counts(value: object) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    buckets: dict[str, int] = {}
    for status in value.values():
        text = str(status or "")
        bucket = text.split(" ", 1)[0] if text else "UNKNOWN"
        buckets[bucket] = buckets.get(bucket, 0) + 1
    return dict(sorted(buckets.items()))


def _empty_skip_remediation() -> dict:
    return {
        "schema_version": "auditooor.scan_skip_remediation.v1",
        "row_count": 0,
        "top_n": 0,
        "by_error_class": {},
        "by_tool": {},
        "rows": [],
    }


def _normalize_skip_remediation(value: object) -> dict:
    """Coerce a manifest's ``skipped_modules`` entry into the canonical
    shape, even if the manifest is from before this PR landed (in which
    case the field is absent and we synthesise an empty summary)."""
    if not isinstance(value, dict):
        return _empty_skip_remediation()
    out = _empty_skip_remediation()
    schema = value.get("schema_version")
    if isinstance(schema, str) and schema:
        out["schema_version"] = schema
    row_count = value.get("row_count", 0)
    out["row_count"] = row_count if isinstance(row_count, int) else 0
    top_n = value.get("top_n", 0)
    out["top_n"] = top_n if isinstance(top_n, int) else 0
    by_class = value.get("by_error_class")
    if isinstance(by_class, dict):
        out["by_error_class"] = {
            str(k): int(v) for k, v in by_class.items() if isinstance(v, int)
        }
    by_tool = value.get("by_tool")
    if isinstance(by_tool, dict):
        out["by_tool"] = {
            str(k): int(v) for k, v in by_tool.items() if isinstance(v, int)
        }
    rows = value.get("rows")
    if isinstance(rows, list):
        clean: list[dict] = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            clean.append({
                "tool": str(r.get("tool", "")),
                "module": str(r.get("module", "")),
                "error_class": str(r.get("error_class", "")),
                "error_excerpt": str(r.get("error_excerpt", "")),
                "hint": str(r.get("hint", "")),
                "log_path": str(r.get("log_path", "")),
            })
        out["rows"] = clean
    return out


def _format_skip_remediation_warning(summary: dict) -> str:
    """One-line summary suitable for pre-submit / detector-environment
    WARN reasons. Returns "" when there are no rows."""
    rows = summary.get("row_count", 0) or 0
    if not rows:
        return ""
    by_class = summary.get("by_error_class") or {}
    if by_class:
        breakdown = ", ".join(f"{k}={v}" for k, v in sorted(by_class.items()))
        return f"skipped-module remediation rows: total={rows} ({breakdown})"
    return f"skipped-module remediation rows: total={rows}"


def _detector_environment_summary(ws: Path) -> dict:
    manifest = ws / "detector_environment_manifest.json"
    machine_summary = {
        "schema_version": "auditooor.detector_environment_closeout_summary.v1",
        "manifest": str(manifest),
        "manifest_present": _exists(manifest),
        "manifest_valid": False,
        "skip_fail_counts": _normalize_skip_counts({}),
        "skip_fail_total": 0,
        "has_skip_failures": False,
        "tool_status_counts": {},
        "skip_remediation": _empty_skip_remediation(),
        "warning": "",
    }
    summary = {
        "manifest": str(manifest),
        "present": machine_summary["manifest_present"],
        "schema_version": "",
        "skipped_compilation_counts": {},
        "skipped_compilation_total": 0,
        "skip_remediation": _empty_skip_remediation(),
        "visible_for_pre_submit": False,
        "warning": "",
        "machine_summary": machine_summary,
    }
    if not summary["present"]:
        summary["warning"] = (
            "detector_environment_manifest.json missing; scan skip/solc coverage "
            "is not visible in pre-submit closeout"
        )
        machine_summary["warning"] = summary["warning"]
        return summary

    payload = _read_json(manifest)
    if not isinstance(payload, dict):
        summary["warning"] = "detector_environment_manifest.json unreadable / not a JSON object"
        machine_summary["warning"] = summary["warning"]
        return summary
    schema = payload.get("schema_version", "")
    summary["schema_version"] = schema
    if schema != "auditooor.detector_environment.v1":
        summary["warning"] = (
            "detector_environment_manifest.json has unexpected schema "
            f"{schema!r}"
        )
        machine_summary["warning"] = summary["warning"]
        return summary

    counts = _normalize_skip_counts(payload.get("skipped_compilation_counts", {}))
    total = counts["total"]
    summary["skipped_compilation_counts"] = counts
    summary["skipped_compilation_total"] = total
    summary["visible_for_pre_submit"] = True
    skip_rem = _normalize_skip_remediation(payload.get("skipped_modules"))
    summary["skip_remediation"] = skip_rem
    machine_summary.update(
        {
            "manifest_valid": True,
            "skip_fail_counts": counts,
            "skip_fail_total": total,
            "has_skip_failures": total > 0,
            "tool_status_counts": _tool_status_counts(payload.get("tool_status", {})),
            "skip_remediation": skip_rem,
        }
    )
    warnings: list[str] = []
    if total > 0:
        formatted = _format_count_map(counts)
        warnings.append(
            "detector environment manifest reports skipped/failed detector "
            f"coverage: {formatted or f'total={total}'}"
        )
    rem_warning = _format_skip_remediation_warning(skip_rem)
    if rem_warning:
        warnings.append(rem_warning)
    if warnings:
        joined = "; ".join(warnings)
        summary["warning"] = joined
        machine_summary["warning"] = joined
    return summary


def _discover_pre_submit_drafts(ws: Path) -> list[Path]:
    if _IMPACT_MAPPING is not None and hasattr(_IMPACT_MAPPING, "discover_workspace_drafts"):
        return [
            p for p in _IMPACT_MAPPING.discover_workspace_drafts(ws)
            if p.name.upper() not in {"README.MD", "INDEX.MD"}
            and not p.name.endswith((".block.md", ".notes.md"))
        ]
    staging = ws / "submissions" / "staging"
    return _glob(staging, "*.md") if _exists(staging) else []


def check_pre_submit(ws: Path) -> CheckResult:
    """If reportable submission drafts exist, look for production-path
    evidence under ``submissions/packaged/`` and an ``llm_review/`` sibling.
    High/Critical drafts without production-path evidence are FAIL.
    """
    staging = ws / "submissions" / "staging"
    packaged = ws / "submissions" / "packaged"
    llm_review = ws / "submissions" / "llm_review"

    drafts = _discover_pre_submit_drafts(ws)
    if not drafts:
        return CheckResult(
            check="pre-submit",
            status=PASS,
            reason="no reportable submission drafts found; pre-submit gate not applicable",
            artifacts=[],
            detail={
                "staging": str(staging),
                "draft_dirs": list(getattr(_IMPACT_MAPPING, "DEFAULT_WORKSPACE_DRAFT_DIRS", ("staging",))),
                "draft_count": 0,
            },
        )

    # Map each draft to (severity, has_packaged_bundle, has_llm_review_row).
    rows = []
    high_crit_missing_pp: list[str] = []
    high_crit_blocked: list[str] = []
    for draft in drafts:
        text = _read_text(draft)
        sev = _severity_from_draft(text)
        readiness_blockers = _draft_readiness_blockers(text)
        # Match a packaged bundle by stem; the canonical packager uses the
        # draft slug as the directory name.
        stem = draft.stem
        bundle_dir = packaged / stem
        has_bundle = _exists(bundle_dir) and bundle_dir.is_dir() and any(
            c for c in bundle_dir.iterdir() if not c.name.startswith(".")
        )
        # Production-path evidence: either a `manifest.json` with a non-empty
        # `production_path` field, or a `## Production Path` section in the
        # draft itself. The mechanical Check #27 in `pre-submit-check.sh` is
        # the source of truth; we reproduce its test surface here.
        has_pp = False
        if has_bundle:
            manifest = bundle_dir / "manifest.json"
            mfp = _read_json(manifest) if _exists(manifest) else None
            if isinstance(mfp, dict):
                pp = mfp.get("production_path")
                if pp:
                    has_pp = True
        if not has_pp:
            # Real `## Production Path` markdown header, not just the
            # substring (Kimi Bug 4 / Minimax Gap 7).
            has_pp = _has_real_production_path_section(text)

        # llm_review/ presence is advisory in the close-out check.
        has_review = (
            _exists(llm_review)
            and any(_glob(llm_review, f"{stem}*"))
        )
        rows.append(
            {
                "draft": str(draft),
                "severity": sev,
                "has_packaged_bundle": has_bundle,
                "has_production_path": has_pp,
                "has_llm_review": has_review,
                "readiness_blockers": readiness_blockers,
                "not_submit_ready": "NOT_SUBMIT_READY" in readiness_blockers,
                "execution_blocked": "EXECUTION_BLOCKED" in readiness_blockers,
            }
        )
        if sev in {"high", "critical"} and readiness_blockers:
            high_crit_blocked.append(str(draft))
        if sev in {"high", "critical"} and not has_pp:
            high_crit_missing_pp.append(str(draft))

    detector_env_summary = _detector_environment_summary(ws)
    detail = {
        "staging": str(staging),
        "draft_dirs": list(getattr(_IMPACT_MAPPING, "DEFAULT_WORKSPACE_DRAFT_DIRS", ("staging",))),
        "packaged": str(packaged),
        "llm_review": str(llm_review),
        "drafts": rows,
        "detector_environment": detector_env_summary,
    }

    if high_crit_blocked:
        return CheckResult(
            check="pre-submit",
            status=FAIL,
            reason=(
                f"{len(high_crit_blocked)} High/Critical draft(s) explicitly "
                "marked NOT_SUBMIT_READY / EXECUTION_BLOCKED / pending PoC. "
                "Run and record the PoC, clear the readiness blockers, then "
                "rerun closeout before treating the draft as paste-ready."
            ),
            artifacts=high_crit_blocked,
            detail=detail,
        )

    if high_crit_missing_pp:
        return CheckResult(
            check="pre-submit",
            status=FAIL,
            reason=(
                f"{len(high_crit_missing_pp)} High/Critical draft(s) without "
                "production-path evidence (mechanical pre-submit Check #27 "
                "would block these). Run `make audit` close-out lane "
                "(quality-score, auto-fix, package, pre-submit) and add the "
                "`## Production Path` section."
            ),
            artifacts=high_crit_missing_pp,
            detail=detail,
        )

    # No High/Critical missing PP, but drafts exist. WARN if no packaged
    # bundles at all; PASS if at least one bundle.
    bundles = sum(1 for r in rows if r["has_packaged_bundle"])
    if bundles == 0:
        return CheckResult(
            check="pre-submit",
            status=WARN,
            reason=(
                f"{len(drafts)} draft(s) discovered, but no packaged bundles; "
                "run `engage.py --stage package`."
            ),
            artifacts=[str(staging)],
            detail=detail,
        )
    if detector_env_summary.get("warning"):
        artifacts = [str(staging), str(packaged)]
        manifest_path = str(detector_env_summary.get("manifest") or "")
        if manifest_path and detector_env_summary.get("present"):
            artifacts.append(manifest_path)
        return CheckResult(
            check="pre-submit",
            status=WARN,
            reason=(
                f"{len(drafts)} draft(s) discovered, {bundles} packaged, but "
                + str(detector_env_summary["warning"])
            ),
            artifacts=artifacts,
            detail=detail,
        )
    return CheckResult(
        check="pre-submit",
        status=PASS,
        reason=f"{len(drafts)} draft(s) discovered, {bundles} packaged",
        artifacts=[str(staging), str(packaged)],
        detail=detail,
    )


# ---- check 7: poc-execution ----------------------------------------------


def _queue_item_summary(
    kind: str,
    path: Path,
    *,
    owner: str = "",
    now: float | None = None,
) -> dict:
    """Build one queue-item summary row.

    Adds age-based status (P2-4) using the file mtime. ``now`` is overridable
    so unit tests can pin time deterministically.
    """
    warn_days, fail_days = _queue_age_thresholds()
    mtime = _safe_mtime(path)
    age_days = _age_days_from_mtime(mtime, now=now)
    status = _age_status(age_days, warn_days, fail_days)
    return {
        "kind": kind,
        "path": str(path),
        "owner": owner,
        "mtime": mtime,
        "age_days": round(age_days, 3),
        "status": status,
    }


def _oldest_queue_item(items: list[dict]) -> dict | None:
    if not items:
        return None
    return min(items, key=lambda row: (row.get("mtime", 0.0), row.get("path", "")))


def _queue_owner_counts(items: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        owner = str(item.get("owner") or "unassigned")
        counts[owner] = counts.get(owner, 0) + 1
    return dict(sorted(counts.items()))


def _per_queue_summaries(items: list[dict]) -> list[dict]:
    """Group queue items by ``kind`` and emit a per-queue summary block.

    Each block reports: queue (kind), count, oldest_age_days, oldest_id (path),
    owner of the oldest item, and aggregated status (PASS/WARN/FAIL — worst of
    the queue's items). Sorted by kind for deterministic output.
    """
    grouped: dict[str, list[dict]] = {}
    for item in items:
        kind = str(item.get("kind") or "queue")
        grouped.setdefault(kind, []).append(item)
    blocks: list[dict] = []
    for kind in sorted(grouped):
        rows = grouped[kind]
        oldest = _oldest_queue_item(rows)
        statuses = [str(r.get("status") or PASS) for r in rows]
        blocks.append(
            {
                "queue": kind,
                "count": len(rows),
                "oldest_age_days": (
                    float(oldest.get("age_days", 0.0)) if oldest else 0.0
                ),
                "oldest_id": str(oldest.get("path", "")) if oldest else "",
                "owner": str(oldest.get("owner", "unassigned")) if oldest else "unassigned",
                "status": _aggregate_status(statuses),
            }
        )
    return blocks


def _format_per_queue_summaries(blocks: list[dict]) -> str:
    """Render the per-queue summary as a compact ``; ``-joined string for the
    closeout WARN/FAIL row reason."""
    if not blocks:
        return ""
    parts = []
    for b in blocks:
        parts.append(
            f"{b['queue']}=[count={b['count']}, "
            f"oldest_age_days={b['oldest_age_days']:.1f}, "
            f"owner={b['owner']}, status={b['status']}]"
        )
    return "; per-queue: " + " | ".join(parts)


def _per_queue_age_status(blocks: list[dict]) -> str:
    """Worst status across all per-queue blocks (used to promote the
    poc-execution row when REQUIRE_NO_STALE_QUEUES is set or any queue
    crosses the FAIL threshold)."""
    return _aggregate_status(str(b.get("status") or PASS) for b in blocks)


def _deep_counterexample_queue_owners(ws: Path) -> dict[str, str]:
    data = _read_json(ws / "deep_counterexamples" / "execution_queue.json")
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        return {}
    owners: dict[str, str] = {}
    for item in data["items"]:
        if not isinstance(item, dict):
            continue
        record_path = item.get("record_path")
        assigned_model = item.get("assigned_model")
        if isinstance(record_path, str) and isinstance(assigned_model, str) and assigned_model:
            owners[record_path] = assigned_model
    return owners


def _deep_engine_truth_manifest_summary(ws: Path) -> dict[str, object]:
    """Summarize recon-log-bridge truth labels for closeout.

    The bridge already emits ``truth_label`` / ``truth_reason`` / execution
    booleans. Closeout should preserve those labels rather than flattening a
    deep-engine setup/tooling/no-target/zero-execution/parser run into a clean
    no-findings-style pass.
    """
    manifest_paths = _glob(ws, "deep_counterexamples/**/recon_log_bridge_manifest.json")
    exact_path = ws / "deep_counterexamples" / "recon_log_bridge_manifest.json"
    if exact_path.exists() and exact_path not in manifest_paths:
        manifest_paths.insert(0, exact_path)
    if not manifest_paths:
        return {
            "manifest_present": False,
            "manifest_count": 0,
            "manifest_paths": [],
            "truth_label_counts": {},
            "rows": [],
            "non_clean_labels": [],
            "status": "missing",
        }

    rows: list[dict[str, object]] = []
    truth_label_counts: Counter[str] = Counter()
    non_clean_labels: list[str] = []
    for path in manifest_paths:
        data = _read_json(path)
        if not isinstance(data, dict):
            truth_label_counts["unreadable"] += 1
            rows.append(
                {
                    "path": str(path),
                    "status": "unreadable",
                    "truth_label": "",
                    "truth_reason": "manifest unreadable",
                    "engine_executed": None,
                    "targets_discovered": None,
                    "parser_status": "",
                    "classification": "non_clean",
                }
            )
            non_clean_labels.append("unreadable")
            continue

        truth_label = str(data.get("truth_label") or "").strip()
        truth_reason = str(data.get("truth_reason") or "").strip()
        engine_executed = data.get("engine_executed")
        targets_discovered = data.get("targets_discovered")
        parser_status = str(data.get("parser_status") or "").strip()
        status = str(data.get("status") or "").strip()
        clean_no_findings = (
            truth_label == "no_findings"
            and engine_executed is True
            and targets_discovered is True
        )
        clean_counterexample = (
            truth_label == "counterexample"
            and engine_executed is True
            and targets_discovered is True
        )
        classification = "clean" if (clean_no_findings or clean_counterexample) else "non_clean"
        if truth_label:
            truth_label_counts[truth_label] += 1
        else:
            truth_label_counts["missing"] += 1
        if classification == "non_clean":
            non_clean_labels.append(truth_label or status or "missing")
        rows.append(
            {
                "path": str(path),
                "status": status,
                "truth_label": truth_label,
                "truth_reason": truth_reason,
                "engine_executed": engine_executed,
                "targets_discovered": targets_discovered,
                "parser_status": parser_status,
                "classification": classification,
            }
        )

    return {
        "manifest_present": True,
        "manifest_count": len(manifest_paths),
        "manifest_paths": [str(path) for path in manifest_paths],
        "truth_label_counts": dict(sorted(truth_label_counts.items())),
        "rows": rows,
        "non_clean_labels": non_clean_labels,
        "status": "warn" if non_clean_labels else "pass",
    }


def _queue_threshold_reason_suffix(count: int, owner_counts: dict[str, int]) -> str:
    if count < UNEXECUTED_QUEUE_COUNT_REVIEW_THRESHOLD:
        return ""
    owners = ", ".join(f"{owner}={total}" for owner, total in owner_counts.items())
    return (
        "; stale queue threshold exceeded: "
        f"total_unexecuted={count} >= {UNEXECUTED_QUEUE_COUNT_REVIEW_THRESHOLD}"
        + (f"; owners: {owners}" if owners else "")
    )


def _oldest_queue_reason_suffix(
    oldest: dict | None,
    count: int,
    owner_counts: dict[str, int] | None = None,
    *,
    per_queue: list[dict] | None = None,
) -> str:
    if not oldest:
        return ""
    owner = oldest.get("owner") or "unassigned"
    age_days = oldest.get("age_days")
    age_str = (
        f", age_days={float(age_days):.1f}"
        if isinstance(age_days, (int, float))
        else ""
    )
    threshold = _queue_threshold_reason_suffix(count, owner_counts or {})
    per_queue_str = _format_per_queue_summaries(per_queue or [])
    return (
        f"; oldest unexecuted queue item: {oldest.get('kind', 'queue')} "
        f"{oldest.get('path', '<unknown>')} owner={owner}{age_str} "
        f"(total_unexecuted={count})"
        f"{threshold}"
        f"{per_queue_str}"
    )


def check_poc_scaffold_ambiguity(ws: Path) -> CheckResult:
    """Warn when ``poc-scaffold.py`` resolved candidate ambiguity via
    ``--candidate-index``.

    Item #16 / P1-5 burn-down: when ``--plan-json`` matches more than one
    candidate, the scaffold fails closed unless the operator passes
    ``--candidate-index <n>``. Every disambiguating pick appends a row to
    ``.auditooor/poc_scaffold_ambiguity_resolutions.jsonl`` so closeout (and
    any auditor reviewing the run) can sanity-check that the operator chose
    the intended hypothesis. Empty / missing log is PASS — this row only
    speaks up when a non-empty log shows pending review.
    """
    log, rows = _read_poc_scaffold_ambiguity_log(ws)
    detail = {
        "log_path": str(log),
        "log_present": log.exists(),
        "entry_count": len(rows),
        "entries": rows[:20],
    }
    if not rows:
        return CheckResult(
            check="poc-scaffold-ambiguity",
            status=PASS,
            reason=(
                "no PoC scaffold ambiguity-resolution log entries"
                if log.exists()
                else "poc-scaffold ambiguity log not present (no scaffolds disambiguated)"
            ),
            artifacts=[str(log)] if log.exists() else [],
            detail=detail,
        )
    return CheckResult(
        check="poc-scaffold-ambiguity",
        status=WARN,
        reason=(
            f"{len(rows)} poc-scaffold scaffold(s) emitted with "
            "ambiguity-resolved candidate selection; review "
            f"{log} and confirm the chosen hypothesis matches the intended "
            "exploit path before treating the scaffold as proof work"
        ),
        artifacts=[str(log)],
        detail=detail,
    )


def check_claim_precondition(ws: Path) -> CheckResult:
    """Surface the claim-precondition manifest from any draft run that wrote
    one with ``tools/claim-precondition-check.py --workspace ...``.

    Wave 2 (Issue #345 follow-up): explicit ``<!-- claim-precondition: ... -->``
    directives can hard-fail at pre-submit when observed live state contradicts
    the bug claim. The checker also writes a structured JSON manifest at
    ``<workspace>/.auditooor/claim_precondition_results.json`` so closeout can
    re-surface contradictions or unresolved checks without re-running cast.

    Empty / missing manifest is PASS (no draft has declared claim-preconditions
    yet, or the draft was checked outside the workspace). When the manifest is
    present, this check warns/fails based on ``overall_status``:

      * ``match`` -> PASS
      * ``no-directives`` -> PASS (advisory: directives recommended for live claims)
      * ``cannot-run`` -> WARN
      * ``contradicts`` -> FAIL (mirrors pre-submit check #28 verdict)
    """
    manifest = ws / ".auditooor" / "claim_precondition_results.json"
    if not manifest.exists():
        return CheckResult(
            check="claim-precondition",
            status=PASS,
            reason="claim-precondition manifest not present (no live-claim draft scanned)",
            artifacts=[],
            detail={"manifest_path": str(manifest), "manifest_present": False},
        )
    payload = _read_json(manifest)
    if not isinstance(payload, dict):
        return CheckResult(
            check="claim-precondition",
            status=WARN,
            reason="claim_precondition_results.json present but unreadable / not a JSON object",
            artifacts=[str(manifest)],
            detail={"manifest_path": str(manifest)},
        )
    overall = str(payload.get("overall_status") or "").strip()
    entries = payload.get("entries") or []
    contradictions = [
        e for e in entries if isinstance(e, dict) and e.get("status") == "contradicts"
    ]
    cannot_run = [
        e for e in entries if isinstance(e, dict) and e.get("status") == "cannot-run"
    ]
    detail = {
        "manifest_path": str(manifest),
        "overall_status": overall,
        "entry_count": len(entries),
        "contradictions": contradictions[:5],
        "cannot_run": cannot_run[:5],
    }
    if overall == "contradicts" or contradictions:
        return CheckResult(
            check="claim-precondition",
            status=FAIL,
            reason=(
                f"{len(contradictions)} claim-precondition directive(s) contradicted "
                "by observed live state — fix the draft, cite correct live proof, "
                "or pass --skip-live-verify only for deliberate source-only review"
            ),
            artifacts=[str(manifest)],
            detail=detail,
        )
    if overall == "cannot-run" or cannot_run:
        return CheckResult(
            check="claim-precondition",
            status=WARN,
            reason=(
                f"{len(cannot_run)} claim-precondition directive(s) could not be "
                "verified (missing RPC URL / cast / observed value); review the "
                "manifest and re-run with the appropriate AUDITOOOR_LIVE_RPC_<NETWORK> set"
            ),
            artifacts=[str(manifest)],
            detail=detail,
        )
    return CheckResult(
        check="claim-precondition",
        status=PASS,
        reason=(
            f"all {len(entries)} claim-precondition directive(s) match observed live state"
            if entries
            else "draft had no claim-precondition directives"
        ),
        artifacts=[str(manifest)],
        detail=detail,
    )


def _read_poc_scaffold_ambiguity_log(ws: Path) -> tuple[Path, list[dict]]:
    """Return the (path, rows) for ``.auditooor/poc_scaffold_ambiguity_resolutions.jsonl``.

    Each row records one ``poc-scaffold.py --candidate-index`` disambiguating
    pick (item #16 / P1-5 burn-down). Closeout treats any non-empty log as a
    soft warning: the operator should sanity-check the chosen hypothesis
    before promoting the scaffold to a real PoC. Bad / unreadable lines are
    skipped silently — the goal is visibility, not blocking.
    """
    log = ws / ".auditooor" / "poc_scaffold_ambiguity_resolutions.jsonl"
    rows: list[dict] = []
    if not log.exists():
        return log, rows
    try:
        for line in log.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except ValueError:
                continue
            if isinstance(payload, dict):
                rows.append(payload)
    except OSError:
        return log, []
    return log, rows


def check_poc_execution(ws: Path) -> CheckResult:
    """Generated PoC dispatch briefs should become execution manifests.

    The source-mining lane now emits ``poc_task_briefs/*.md``. This closeout
    row keeps those briefs from turning into another dormant queue by warning
    until the operator records execution under ``poc_execution/**``. The same
    applies to normalized deep counterexamples: a ``deep_counterexample.v1`` is
    useful queue evidence, not proof, until a replay is wired and execution is
    recorded. P1 fixture extraction queues follow the same rule: a generated
    queue is inventory until ``p1-extraction-run`` writes its execution
    manifest/report.

    PoC scaffolds emitted with an ambiguity-resolved candidate selection are
    flagged separately by ``check_poc_scaffold_ambiguity``; this row stays
    focused on execution-record completeness.
    """
    briefs = _glob(ws, "source_mining/**/poc_task_briefs/*.md")
    manifests = _glob(ws, "poc_execution/**/execution_manifest.json")
    p1_queue = ws / ".audit_logs" / "p1_fixture_extraction" / "extraction_queue.json"
    p1_manifest = ws / ".audit_logs" / "p1_fixture_extraction" / "execution_manifest.json"
    p1_report = ws / ".audit_logs" / "p1_fixture_extraction" / "execution_report.md"
    p1_queue_rows = _read_json(p1_queue) if p1_queue.exists() else None
    p1_queue_count = len(p1_queue_rows) if isinstance(p1_queue_rows, list) else 0
    p1_manifest_data = _read_json(p1_manifest) if p1_manifest.exists() else None
    p1_result_counts = (
        p1_manifest_data.get("result_counts", {})
        if isinstance(p1_manifest_data, dict)
        else {}
    )
    p1_selected_count = (
        int(p1_manifest_data.get("selected_count", 0))
        if isinstance(p1_manifest_data, dict)
        and isinstance(p1_manifest_data.get("selected_count", 0), int)
        else 0
    )
    deep_records = [
        path
        for path in _glob(ws, "deep_counterexamples/*.deep_counterexample.v1.json")
        if path.name != "collection_manifest.json"
    ]
    deep_engine_truth = _deep_engine_truth_manifest_summary(ws)
    deep_rows = []
    for path in deep_records:
        data = _read_json(path)
        if isinstance(data, dict):
            deep_rows.append({
                "path": str(path),
                "engine": data.get("engine", ""),
                "target_function": data.get("target_function", ""),
                "promotes_to_poc_work": bool(data.get("promotes_to_poc_work")),
                "generated_forge_test_path": data.get("generated_forge_test_path", ""),
                "replay_impossible_reason": data.get("replay_impossible_reason", ""),
            })
        else:
            deep_rows.append({
                "path": str(path),
                "engine": "",
                "target_function": "",
                "promotes_to_poc_work": False,
                "generated_forge_test_path": "",
                "replay_impossible_reason": "unreadable",
            })
    manifest_rows = []
    for path in manifests:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                brief_path = data.get("brief_path", "")
                brief_path_exists = (
                    Path(brief_path).is_file()
                    if isinstance(brief_path, str) and brief_path
                    else False
                )
                commands_attempted = data.get("commands_attempted")
                if isinstance(commands_attempted, list):
                    command_count = len(commands_attempted)
                elif isinstance(commands_attempted, int):
                    command_count = commands_attempted
                elif isinstance(commands_attempted, str) and commands_attempted.strip():
                    command_count = 1
                else:
                    command_count = 0
                manifest_rows.append({
                    "path": str(path),
                    "candidate_id": data.get("candidate_id", ""),
                    "brief_path": brief_path,
                    "brief_path_exists": brief_path_exists,
                    "final_result": data.get("final_result", ""),
                    "impact_assertion": data.get("impact_assertion", ""),
                    "command_count": command_count,
                    "has_foundry_version_inventory": isinstance(
                        data.get("foundry_version_inventory"), dict
                    ),
                    "foundry_planned_target": (
                        (data.get("foundry_version_inventory") or {})
                        .get("planned_target", {})
                        .get("foundry_version", "")
                        if isinstance(data.get("foundry_version_inventory"), dict)
                        else ""
                    ),
                })
                manifest_rows[-1]["bound_source_validation"] = _validate_bound_sources(data, ws)
        except (OSError, ValueError):
            manifest_rows.append({
                "path": str(path),
                "candidate_id": "",
                "brief_path": "",
                "brief_path_exists": False,
                "final_result": "unreadable",
                "impact_assertion": "",
                "command_count": 0,
                "has_foundry_version_inventory": False,
                "foundry_planned_target": "",
                "bound_source_validation": {
                    "supplied": False, "valid": False,
                    "errors": ["manifest_unreadable"],
                },
            })
    invalid_bound_source_rows = [
        row for row in manifest_rows
        if not row.get("bound_source_validation", {}).get("valid", True)
    ]
    manifests = [
        path for path, row in zip(manifests, manifest_rows)
        if row.get("bound_source_validation", {}).get("valid", True)
    ]
    missing_manifest_briefs = [
        row for row in manifest_rows
        if row.get("brief_path") and not row.get("brief_path_exists")
    ]
    invalid_proved = [
        row for row in manifest_rows
        if row.get("final_result") == "proved" and row.get("impact_assertion") != "exploit_impact"
    ]
    unresolved = [
        row for row in manifest_rows
        if row.get("final_result") in {"", "needs_human", "unreadable"}
    ]
    missing_foundry_inventory = [
        row for row in manifest_rows
        if not row.get("has_foundry_version_inventory")
    ]
    deep_queue_owners = _deep_counterexample_queue_owners(ws)
    queue_items = (
        [_queue_item_summary("poc_task_brief", path, owner="poc-execution") for path in briefs]
        + [
            _queue_item_summary(
                "deep_counterexample",
                path,
                owner=deep_queue_owners.get(str(path), "deep-counterexample-replay"),
            )
            for path in deep_records
        ]
    )
    if p1_queue_count and not p1_manifest.exists():
        queue_items.append(_queue_item_summary(
            "p1_extraction_queue",
            p1_queue,
            owner="p1-fixture-extraction",
        ))
    oldest_queue_item = _oldest_queue_item(queue_items)
    queue_owner_counts = _queue_owner_counts(queue_items)
    # Item #14: surface per-evidence-class counts inside this row's detail
    # so callers (and the dedicated ``evidence-class`` check) can refuse to
    # treat scaffolds or hypotheses as proof. We deliberately count only
    # poc-execution-adjacent artifacts here; the dedicated check covers the
    # broader set (briefs, survivors, queues).
    deep_record_records = []
    for path in deep_records:
        data = _read_json(path)
        deep_record_records.append(data if isinstance(data, dict) else {})
    manifest_records = []
    for path in _glob(ws, "poc_execution/**/execution_manifest.json"):
        data = _read_json(path)
        if isinstance(data, dict):
            data = dict(data)
            validation = _validate_bound_sources(data, ws)
            if not validation.get("valid", True):
                data.pop("evidence_class", None)
                data["_bound_source_validation"] = validation
            manifest_records.append(data)
        else:
            manifest_records.append({})
    poc_evidence_class_counts = _EVIDENCE_CLASS.merge_counts(
        _EVIDENCE_CLASS.count_records(deep_record_records),
        _EVIDENCE_CLASS.count_records(manifest_records),
    )
    per_queue_blocks = _per_queue_summaries(queue_items)
    warn_days, fail_days = _queue_age_thresholds()
    age_status = _per_queue_age_status(per_queue_blocks)
    detail = {
        "brief_count": len(briefs),
        "deep_counterexample_count": len(deep_records),
        "execution_manifest_count": len(manifests),
        "p1_extraction_queue_count": p1_queue_count,
        "p1_extraction_manifest_present": p1_manifest.exists(),
        "p1_extraction_report_present": p1_report.exists(),
        "p1_extraction_selected_count": p1_selected_count,
        "p1_extraction_result_counts": p1_result_counts,
        "briefs": [str(p) for p in briefs],
        "deep_counterexamples": [str(p) for p in deep_records],
        "deep_counterexample_rows": deep_rows,
        "deep_engine_truth": deep_engine_truth,
        "execution_manifests": [str(p) for p in manifests],
        "manifest_rows": manifest_rows,
        "invalid_bound_source_count": len(invalid_bound_source_rows),
        "invalid_bound_source_rows": invalid_bound_source_rows,
        "unexecuted_queue_item_count": len(queue_items),
        "oldest_unexecuted_queue_item": oldest_queue_item,
        "unexecuted_queue_owner_counts": queue_owner_counts,
        "unexecuted_queue_count_review_threshold": UNEXECUTED_QUEUE_COUNT_REVIEW_THRESHOLD,
        "unexecuted_queue_count_threshold_exceeded": (
            len(queue_items) >= UNEXECUTED_QUEUE_COUNT_REVIEW_THRESHOLD
        ),
        "evidence_class_counts": poc_evidence_class_counts,
        "verified_evidence_count": _EVIDENCE_CLASS.verified_total(
            poc_evidence_class_counts
        ),
        "hypothesis_evidence_count": _EVIDENCE_CLASS.hypothesis_total(
            poc_evidence_class_counts
        ),
        "queue_age_warn_days": warn_days,
        "queue_age_fail_days": fail_days,
        "queue_age_require_no_stale": _require_no_stale_queues(),
        "per_queue_summaries": per_queue_blocks,
        "queue_age_status": age_status,
        "missing_foundry_inventory_count": len(missing_foundry_inventory),
    }
    deep_truth_suffix = ""
    if deep_engine_truth.get("manifest_present"):
        labels = deep_engine_truth.get("truth_label_counts") or {}
        label_bits = ", ".join(
            f"{label}={count}"
            for label, count in labels.items()
            if isinstance(label, str)
        )
        rows = deep_engine_truth.get("rows") or []
        row_bits = []
        for row in rows[:3]:
            if not isinstance(row, dict):
                continue
            truth_label = str(row.get("truth_label") or row.get("status") or "missing")
            classification = str(row.get("classification") or "non_clean")
            truth_reason = str(row.get("truth_reason") or "").strip()
            pieces = [truth_label, classification]
            if truth_reason:
                pieces.append(truth_reason)
            row_bits.append("; ".join(pieces))
        suffix_bits = []
        if label_bits:
            suffix_bits.append(f"labels={label_bits}")
        if row_bits:
            suffix_bits.append("rows=" + " | ".join(row_bits))
        deep_truth_suffix = "; deep-engine truth: " + " ; ".join(suffix_bits) if suffix_bits else "; deep-engine truth present"

    if (
        deep_engine_truth.get("status") == "warn"
        and not briefs
        and not deep_records
        and not (p1_queue_count and not p1_manifest.exists())
    ):
        return CheckResult(
            check="poc-execution",
            status=WARN,
            reason=(
                "deep-engine truth labels are non-clean; "
                "preserve parser/setup/no-target/zero-execution state instead of collapsing to no_findings"
                + deep_truth_suffix
            ),
            artifacts=[str(p) for p in deep_engine_truth.get("manifest_paths", [])[:20]],
            detail=detail,
        )
    if p1_queue_count and not p1_manifest.exists():
        # P2-4: a queue stalled past the FAIL threshold (or stalled past WARN
        # under REQUIRE_NO_STALE_QUEUES) promotes WARN to FAIL.
        promoted = FAIL if age_status == FAIL else WARN
        return CheckResult(
            check="poc-execution",
            status=promoted,
            reason=(
                f"{p1_queue_count} P1 fixture extraction queue row(s) but no "
                ".audit_logs/p1_fixture_extraction/execution_manifest.json; "
                "run make p1-extraction-run or close the queue before treating "
                "P1 fixture extraction as complete"
                + _oldest_queue_reason_suffix(
                    oldest_queue_item,
                    len(queue_items),
                    queue_owner_counts,
                    per_queue=per_queue_blocks,
                )
                + deep_truth_suffix
            ),
            artifacts=[str(p1_queue)],
            detail=detail,
        )
    if p1_queue_count and not p1_report.exists():
        return CheckResult(
            check="poc-execution",
            status=WARN,
            reason=(
                "P1 fixture extraction manifest exists but execution_report.md "
                "is missing; regenerate with current make p1-extraction-run so "
                "reviewers have operator-readable evidence"
                + deep_truth_suffix
            ),
            artifacts=[str(p1_manifest)],
            detail=detail,
        )
    p1_bad_results = {
        key: val
        for key, val in p1_result_counts.items()
        if key in {"failed", "invalid_queue_row"} and isinstance(val, int) and val > 0
    }
    if p1_bad_results:
        return CheckResult(
            check="poc-execution",
            status=WARN,
            reason=(
                "P1 fixture extraction has failed/invalid queue rows: "
                + _format_count_map(p1_bad_results)
                + deep_truth_suffix
            ),
            artifacts=[str(p1_manifest), str(p1_report)],
            detail=detail,
        )
    if missing_manifest_briefs:
        return CheckResult(
            check="poc-execution",
            status=WARN,
            reason=(
                f"{len(missing_manifest_briefs)} execution manifest(s) reference "
                "missing brief_path; rerun poc-execution-record or restore the "
                "source brief before proof-complete closeout"
                + deep_truth_suffix
            ),
            artifacts=[str(row["path"]) for row in missing_manifest_briefs[:20]],
            detail=detail,
        )
    if not briefs and not deep_records:
        if deep_engine_truth.get("status") == "warn":
            return CheckResult(
                check="poc-execution",
                status=WARN,
                reason=(
                    "deep-engine truth labels are non-clean; "
                    "preserve parser/setup/no-target/zero-execution state instead of collapsing to no_findings"
                    + deep_truth_suffix
                ),
                artifacts=[str(p) for p in deep_engine_truth.get("manifest_paths", [])[:20]],
                detail=detail,
            )
        return CheckResult(
            check="poc-execution",
            status=PASS,
            reason=(
                "no generated poc_task_briefs or deep_counterexample.v1 records found; "
                + (
                    f"{p1_queue_count} P1 extraction queue row(s) have execution evidence"
                    if p1_queue_count
                    else "execution tracking not applicable"
                )
                + deep_truth_suffix
            ),
            artifacts=[str(p1_manifest)] if p1_manifest.exists() else [],
            detail=detail,
        )
    if not manifests:
        queue_bits = []
        if briefs:
            queue_bits.append(f"{len(briefs)} generated PoC dispatch brief(s)")
        if deep_records:
            queue_bits.append(f"{len(deep_records)} deep counterexample record(s)")
        promoted = FAIL if age_status == FAIL else WARN
        return CheckResult(
            check="poc-execution",
            status=promoted,
            reason=(
                f"{' and '.join(queue_bits)} but no "
                "poc_execution/**/execution_manifest.json; execute or close "
                "the queued proof work before treating the campaign as proof-complete"
                + _oldest_queue_reason_suffix(
                    oldest_queue_item,
                    len(queue_items),
                    queue_owner_counts,
                    per_queue=per_queue_blocks,
                )
                + deep_truth_suffix
            ),
            artifacts=[str(p) for p in (briefs + deep_records)[:20]],
            detail=detail,
        )
    queue_count = len(briefs) + len(deep_records)
    if len(manifests) < queue_count:
        promoted = FAIL if age_status == FAIL else WARN
        return CheckResult(
            check="poc-execution",
            status=promoted,
            reason=(
                f"{queue_count} queued proof item(s) but only {len(manifests)} "
                "execution manifest(s); unresolved proof work remains"
                + _oldest_queue_reason_suffix(
                    oldest_queue_item,
                    len(queue_items),
                    queue_owner_counts,
                    per_queue=per_queue_blocks,
                )
                + deep_truth_suffix
            ),
            artifacts=[str(p) for p in manifests[:20]],
            detail=detail,
        )
    if invalid_proved:
        return CheckResult(
            check="poc-execution",
            status=FAIL,
            reason=(
                "execution manifest marks proved without impact_assertion=exploit_impact"
                + deep_truth_suffix
            ),
            artifacts=[str(p) for p in manifests[:20]],
            detail=detail,
        )
    if unresolved:
        return CheckResult(
            check="poc-execution",
            status=WARN,
            reason=(
                f"{len(unresolved)} execution manifest(s) are still needs_human/unreadable; "
                "finish proved/disproved/blocked adjudication before proof-complete closeout"
                + deep_truth_suffix
            ),
            artifacts=[str(p) for p in manifests[:20]],
            detail=detail,
        )
    if missing_foundry_inventory:
        return CheckResult(
            check="poc-execution",
            status=WARN,
            reason=(
                f"{len(missing_foundry_inventory)} execution manifest(s) lack "
                "foundry_version_inventory; rerun poc-execution-record with current "
                "tooling before comparing v1.7.1 evidence"
                + deep_truth_suffix
            ),
            artifacts=[str(p) for p in manifests[:20]],
            detail=detail,
        )
    return CheckResult(
        check="poc-execution",
        status=WARN if deep_engine_truth.get("status") == "warn" else PASS,
        reason=(
            f"{len(briefs)} PoC dispatch brief(s), {len(manifests)} execution manifest(s), "
            f"{p1_queue_count} P1 extraction queue row(s)"
            + deep_truth_suffix
        ),
        artifacts=[str(p) for p in manifests[:20]] + ([str(p1_manifest)] if p1_manifest.exists() else []),
        detail=detail,
    )


# ---- check 8: detector-environment ----------------------------------------


def _skip_remediation_strict_mode() -> tuple[bool, int]:
    """Read ``REQUIRE_NO_SCAN_SKIPS`` / ``REQUIRE_NO_SCAN_SKIPS_THRESHOLD``
    from the environment and return ``(strict, threshold)``.

    Strict mode promotes >threshold skip rows from WARN to FAIL.
    Threshold defaults to 0 when strict mode is on, so any skip row fails.
    """
    require = os.environ.get("REQUIRE_NO_SCAN_SKIPS", "").strip() in {
        "1", "true", "TRUE", "yes", "YES",
    }
    raw = os.environ.get("REQUIRE_NO_SCAN_SKIPS_THRESHOLD", "").strip()
    try:
        threshold = int(raw) if raw else 0
    except ValueError:
        threshold = 0
    return require, threshold


def _skip_remediation_example_lines(rows: list[dict], *, max_examples: int = 3) -> list[str]:
    """Format up to ``max_examples`` skip-row examples as bullet strings.

    Used in the human reason field so the operator sees:
    `slither skipped X.sol because of Y; suggested fix: Z`.
    """
    out: list[str] = []
    for row in rows[:max_examples]:
        tool = row.get("tool") or "<tool>"
        module = row.get("module") or "<module>"
        cls = row.get("error_class") or "<class>"
        hint = row.get("hint") or "(no hint)"
        out.append(f"{tool} skipped {module} ({cls}); suggested fix: {hint}")
    return out


def check_detector_environment(ws: Path) -> CheckResult:
    """Surface detector-runner environment manifests in closeout.

    ``workspace-scan-orchestrator.py`` writes this manifest beside
    ``scan_report.md``. It records Python/slither/solc versions, per-tool
    statuses, conservative skipped-compilation counters, AND (PR P2-3 /
    handover #17) the top-N exact ``(tool, module, error class, hint)``
    rows pulled from per-tool logs by ``scan_skip_remediation``.

    Closeout keeps the row advisory by default. ``REQUIRE_NO_SCAN_SKIPS=1``
    promotes more-than-threshold skip-remediation rows from WARN to FAIL
    so CI can fail-closed on stale solc/remapping coverage.
    """
    summary = _detector_environment_summary(ws)
    manifest = Path(str(summary["manifest"]))
    if not summary["present"]:
        return CheckResult(
            check="detector-environment",
            status=WARN,
            reason=(
                "detector_environment_manifest.json missing; rerun "
                "`python3 tools/workspace-scan-orchestrator.py --workspace <ws>` "
                "so Slither/solc versions and skipped-compilation counts are "
                "visible during close-out"
            ),
            artifacts=[],
            detail={
                "manifest": str(manifest),
                "machine_summary": summary["machine_summary"],
            },
        )

    payload = _read_json(manifest)
    if not isinstance(payload, dict):
        return CheckResult(
            check="detector-environment",
            status=WARN,
            reason="detector_environment_manifest.json present but unreadable / not a JSON object",
            artifacts=[str(manifest)],
            detail={
                "manifest": str(manifest),
                "machine_summary": summary["machine_summary"],
            },
        )
    schema = payload.get("schema_version")
    if schema != "auditooor.detector_environment.v1":
        return CheckResult(
            check="detector-environment",
            status=WARN,
            reason=(
                "detector_environment_manifest.json has unexpected schema "
                f"{schema!r}; expected auditooor.detector_environment.v1"
            ),
            artifacts=[str(manifest)],
            detail={
                "manifest": str(manifest),
                "schema_version": schema,
                "machine_summary": summary["machine_summary"],
            },
        )

    counts = summary["machine_summary"]["skip_fail_counts"]
    total = summary["machine_summary"]["skip_fail_total"]
    skip_rem = summary["machine_summary"].get("skip_remediation") or _empty_skip_remediation()
    rem_rows = list(skip_rem.get("rows") or [])
    rem_count = int(skip_rem.get("row_count", 0) or 0)
    examples = _skip_remediation_example_lines(rem_rows)

    require_no_skips, strict_threshold = _skip_remediation_strict_mode()
    strict_fail = require_no_skips and rem_count > strict_threshold

    detail = {
        "manifest": str(manifest),
        "versions": payload.get("versions", {}),
        "tool_status": payload.get("tool_status", {}),
        "skipped_compilation_counts": counts,
        "skip_remediation": skip_rem,
        "skip_remediation_examples": examples,
        "require_no_scan_skips": require_no_skips,
        "require_no_scan_skips_threshold": strict_threshold,
        "machine_summary": summary["machine_summary"],
    }

    has_count_signal = isinstance(total, int) and total > 0
    has_remediation_rows = rem_count > 0

    if not has_count_signal and not has_remediation_rows:
        return CheckResult(
            check="detector-environment",
            status=PASS,
            reason="detector environment manifest present; no skipped/failed compilation counters",
            artifacts=[str(manifest)],
            detail=detail,
        )

    parts: list[str] = []
    if has_count_signal:
        formatted = _format_count_map(counts)
        parts.append(
            "detector environment manifest reports skipped/failed "
            f"detector coverage: {formatted or f'total={total}'}"
        )
    if has_remediation_rows:
        rem_summary = _format_skip_remediation_warning(skip_rem)
        if rem_summary:
            parts.append(rem_summary)
        if examples:
            parts.append("examples: " + " | ".join(examples))
    reason = "; ".join(parts)
    if strict_fail:
        reason = (
            "REQUIRE_NO_SCAN_SKIPS=1: " + reason
            + f" (threshold={strict_threshold}, rows={rem_count})"
        )
        return CheckResult(
            check="detector-environment",
            status=FAIL,
            reason=reason,
            artifacts=[str(manifest)],
            detail=detail,
        )
    return CheckResult(
        check="detector-environment",
        status=WARN,
        reason=reason,
        artifacts=[str(manifest)],
        detail=detail,
    )


# ---- check 8b: Go/DLT audit-deep enforcement manifest ---------------------

_GO_DLT_ENFORCEMENT_SCHEMA = "auditooor.go_dlt_audit_enforcement.v1"
_GO_DLT_ENFORCEMENT_REL = ".audit_logs/go_dlt_audit_enforcement.json"


def check_go_dlt_audit_enforcement(ws: Path) -> CheckResult:
    """Surface audit-deep's Go/DLT canonical-audit enforcement receipt.

    ``audit-deep.sh`` writes this only for workspaces with non-vendor Go
    files. Missing manifests are therefore not a global warning: non-Go
    workspaces pass as not applicable, while Go workspaces get an advisory
    WARN telling the operator to rerun the paired audit/audit-deep lane.
    """
    manifest = ws / _GO_DLT_ENFORCEMENT_REL
    has_go_files = _workspace_has_non_vendor_go_files(ws)
    if not _exists(manifest):
        status = WARN if has_go_files else PASS
        reason = (
            "go_dlt_audit_enforcement.json missing for workspace with non-vendor "
            "Go files; run `make audit WS=<workspace>` followed by "
            "`make audit-deep WS=<workspace>`"
            if has_go_files
            else "go_dlt_audit_enforcement.json not present; no non-vendor Go files detected"
        )
        return CheckResult(
            check="go-dlt-audit-enforcement",
            status=status,
            reason=reason,
            artifacts=[],
            detail={
                "manifest": str(manifest),
                "manifest_present": False,
                "go_files_detected": has_go_files,
                "machine_summary": {
                    "schema": _GO_DLT_ENFORCEMENT_SCHEMA,
                    "status": status,
                    "manifest_present": False,
                    "go_files_detected": has_go_files,
                },
            },
        )

    payload = _read_json(manifest)
    if not isinstance(payload, dict):
        return CheckResult(
            check="go-dlt-audit-enforcement",
            status=FAIL,
            reason="go_dlt_audit_enforcement.json present but unreadable / wrong shape",
            artifacts=[str(manifest)],
            detail={
                "manifest": str(manifest),
                "manifest_present": True,
                "go_files_detected": has_go_files,
            },
        )

    schema = payload.get("schema")
    if schema != _GO_DLT_ENFORCEMENT_SCHEMA:
        return CheckResult(
            check="go-dlt-audit-enforcement",
            status=FAIL,
            reason=(
                "go_dlt_audit_enforcement.json has unexpected schema "
                f"{schema!r}; expected {_GO_DLT_ENFORCEMENT_SCHEMA}"
            ),
            artifacts=[str(manifest)],
            detail={
                "manifest": str(manifest),
                "manifest_present": True,
                "go_files_detected": has_go_files,
                "schema": schema,
            },
        )

    raw_status = str(payload.get("status") or "").strip().lower()
    status_map = {"pass": PASS, "warn": WARN, "warning": WARN, "fail": FAIL}
    status = status_map.get(raw_status)
    audit_completion = payload.get("audit_completion")
    if not isinstance(audit_completion, dict):
        audit_completion = {}

    if status is None:
        return CheckResult(
            check="go-dlt-audit-enforcement",
            status=FAIL,
            reason=(
                "go_dlt_audit_enforcement.json has unrecognised status "
                f"{payload.get('status')!r} (expected pass|warn|fail)"
            ),
            artifacts=[str(manifest)],
            detail={
                "manifest": str(manifest),
                "manifest_present": True,
                "go_files_detected": has_go_files,
                "status_field": payload.get("status"),
            },
        )

    marker_exists = bool(audit_completion.get("exists"))
    marker_fresh = bool(audit_completion.get("fresh_for_workspace"))
    if status == PASS and (not marker_exists or not marker_fresh):
        status = WARN

    required_commands = payload.get("required_commands")
    if not isinstance(required_commands, list):
        required_commands = []
    reason = str(payload.get("reason") or "").strip()
    if status == PASS:
        reason = reason or "Go/DLT audit-deep enforcement passed"
        if marker_fresh:
            reason += "; audit completion marker is fresh for this workspace"
    elif status == WARN:
        reason = reason or "Go/DLT audit-deep enforcement warning"
        if not marker_exists:
            reason += "; audit completion marker is missing"
        elif not marker_fresh:
            reason += "; audit completion marker exists but is not fresh for this workspace"
    else:
        reason = reason or "Go/DLT audit-deep enforcement failed"

    machine_summary = {
        "schema": _GO_DLT_ENFORCEMENT_SCHEMA,
        "status": status,
        "manifest_present": True,
        "go_files_detected": has_go_files,
        "manifest_status": raw_status,
        "audit_completion_exists": marker_exists,
        "audit_completion_fresh_for_workspace": marker_fresh,
        "required_commands": [str(cmd) for cmd in required_commands],
    }
    detail = {
        "manifest": str(manifest),
        "manifest_present": True,
        "go_files_detected": has_go_files,
        "schema": schema,
        "manifest_status": raw_status,
        "audit_completion": audit_completion,
        "required_commands": machine_summary["required_commands"],
        "audit_deep_report": payload.get("audit_deep_report"),
        "machine_summary": machine_summary,
    }
    return CheckResult(
        check="go-dlt-audit-enforcement",
        status=status,
        reason=reason,
        artifacts=[str(manifest)],
        detail=detail,
    )


# ---- check 8b-bis: scan-go coverage --------------------------------------

# Worker B added the `scan-go` stage to ``tools/engage.py``; Workers G/K
# added 9 Go-detector patterns under ``detectors/go.*``. The runner
# (`tools/go-detector-runner.py`) writes two artifacts under
# ``<ws>/.auditooor/``: ``go_findings.json`` (canonical) plus a
# byte-for-byte ``SCAN_GO_SUMMARY.json`` alias. This check mirrors the
# rust-coverage philosophy of ``check_go_dlt_audit_enforcement`` for the
# scan-go stage:
#   - PASS  : workspace has non-vendor Go files AND both artifacts exist
#             AND validate to the expected ``schema_version: 1`` shape;
#             OR no Go files are present (NA → PASS).
#   - WARN  : Go files present but artifacts missing / malformed (operator
#             needs to rerun ``make scan-go WS=<ws>``).
#   - FAIL  : artifacts present but unreadable / wrong shape entirely.

_SCAN_GO_FINDINGS_REL = ".auditooor/go_findings.json"
_SCAN_GO_SUMMARY_REL = ".auditooor/SCAN_GO_SUMMARY.json"
_SCAN_GO_EXPECTED_SCHEMA_VERSION = 1


def _scan_go_payload_shape_ok(payload: object) -> tuple[bool, str]:
    """Light shape gate for ``go_findings.json`` /
    ``SCAN_GO_SUMMARY.json``. Required keys (per
    ``tools/go-detector-runner.py``):
      schema_version (int == 1), scanner (str), scanner_version (str),
      go_files_scanned (int), patterns (dict), totals (dict).
    Returns ``(ok, reason)``."""
    if not isinstance(payload, dict):
        return (False, "payload is not a JSON object")
    sv = payload.get("schema_version")
    if sv != _SCAN_GO_EXPECTED_SCHEMA_VERSION:
        return (False, f"schema_version={sv!r} (expected {_SCAN_GO_EXPECTED_SCHEMA_VERSION})")
    if not isinstance(payload.get("scanner"), str):
        return (False, "missing/non-string 'scanner'")
    if not isinstance(payload.get("scanner_version"), str):
        return (False, "missing/non-string 'scanner_version'")
    if not isinstance(payload.get("go_files_scanned"), int):
        return (False, "missing/non-int 'go_files_scanned'")
    if not isinstance(payload.get("patterns"), dict):
        return (False, "missing/non-dict 'patterns'")
    if not isinstance(payload.get("totals"), dict):
        return (False, "missing/non-dict 'totals'")
    return (True, "")


def check_scan_go(ws: Path) -> CheckResult:
    """Closeout coverage for the ``scan-go`` engage stage.

    Parallel to ``check_go_dlt_audit_enforcement`` but for the
    Go-pattern-scanner artifacts that ``tools/go-detector-runner.py`` emits.
    """
    findings = ws / _SCAN_GO_FINDINGS_REL
    summary = ws / _SCAN_GO_SUMMARY_REL
    has_go_files = _workspace_has_non_vendor_go_files(ws)
    findings_present = _exists(findings)
    summary_present = _exists(summary)

    # SKIP path: no Go files in the workspace -> stage is N/A, return PASS.
    if not has_go_files and not findings_present and not summary_present:
        return CheckResult(
            check="scan-go-coverage",
            status=PASS,
            reason="scan-go not applicable: no non-vendor Go files in workspace",
            artifacts=[],
            detail={
                "findings": str(findings),
                "summary": str(summary),
                "findings_present": False,
                "summary_present": False,
                "go_files_detected": False,
                "machine_summary": {
                    "schema_version": _SCAN_GO_EXPECTED_SCHEMA_VERSION,
                    "status": PASS,
                    "applicable": False,
                    "findings_present": False,
                    "summary_present": False,
                    "go_files_detected": False,
                },
            },
        )

    # WARN path: Go files present but at least one artifact missing.
    if not findings_present or not summary_present:
        missing = []
        if not findings_present:
            missing.append(_SCAN_GO_FINDINGS_REL)
        if not summary_present:
            missing.append(_SCAN_GO_SUMMARY_REL)
        return CheckResult(
            check="scan-go-coverage",
            status=WARN,
            reason=(
                f"scan-go artifact(s) missing for workspace with non-vendor "
                f"Go files: {', '.join(missing)}; rerun "
                f"`make scan-go WS=<workspace>`"
            ),
            artifacts=[str(p) for p in (findings, summary) if _exists(p)],
            detail={
                "findings": str(findings),
                "summary": str(summary),
                "findings_present": findings_present,
                "summary_present": summary_present,
                "go_files_detected": has_go_files,
                "missing_artifacts": missing,
                "machine_summary": {
                    "schema_version": _SCAN_GO_EXPECTED_SCHEMA_VERSION,
                    "status": WARN,
                    "applicable": True,
                    "findings_present": findings_present,
                    "summary_present": summary_present,
                    "go_files_detected": has_go_files,
                    "missing_artifacts": missing,
                },
            },
        )

    # Shape-validate both artifacts.
    findings_payload = _read_json(findings)
    summary_payload = _read_json(summary)
    f_ok, f_reason = _scan_go_payload_shape_ok(findings_payload)
    s_ok, s_reason = _scan_go_payload_shape_ok(summary_payload)
    if not f_ok or not s_ok:
        bad = []
        if not f_ok:
            bad.append(f"go_findings.json: {f_reason}")
        if not s_ok:
            bad.append(f"SCAN_GO_SUMMARY.json: {s_reason}")
        return CheckResult(
            check="scan-go-coverage",
            status=FAIL,
            reason="scan-go artifacts present but malformed: " + "; ".join(bad),
            artifacts=[str(findings), str(summary)],
            detail={
                "findings": str(findings),
                "summary": str(summary),
                "findings_present": True,
                "summary_present": True,
                "go_files_detected": has_go_files,
                "shape_errors": bad,
                "machine_summary": {
                    "schema_version": _SCAN_GO_EXPECTED_SCHEMA_VERSION,
                    "status": FAIL,
                    "applicable": True,
                    "findings_present": True,
                    "summary_present": True,
                    "go_files_detected": has_go_files,
                    "shape_errors": bad,
                },
            },
        )

    # PASS path.
    assert isinstance(findings_payload, dict)  # for the type checker
    totals = findings_payload.get("totals") or {}
    files_with_hits = totals.get("files") if isinstance(totals, dict) else None
    hits = totals.get("hits") if isinstance(totals, dict) else None
    pattern_count = len(findings_payload.get("patterns") or {})
    go_files_scanned = findings_payload.get("go_files_scanned")

    reason = (
        f"scan-go OK: {pattern_count} pattern(s) over "
        f"{go_files_scanned} Go file(s); totals files={files_with_hits} "
        f"hits={hits}"
    )
    return CheckResult(
        check="scan-go-coverage",
        status=PASS,
        reason=reason,
        artifacts=[str(findings), str(summary)],
        detail={
            "findings": str(findings),
            "summary": str(summary),
            "findings_present": True,
            "summary_present": True,
            "go_files_detected": has_go_files,
            "go_files_scanned": go_files_scanned,
            "pattern_count": pattern_count,
            "hits_total": hits,
            "files_with_hits": files_with_hits,
            "machine_summary": {
                "schema_version": _SCAN_GO_EXPECTED_SCHEMA_VERSION,
                "status": PASS,
                "applicable": True,
                "findings_present": True,
                "summary_present": True,
                "go_files_detected": has_go_files,
                "go_files_scanned": go_files_scanned,
                "pattern_count": pattern_count,
                "hits_total": hits,
                "files_with_hits": files_with_hits,
            },
        },
    )


# ---- check 8c: fp-calibration manifest ------------------------------------

# P1-4 burn-down: every Tier-S/A pattern claim should be backed by a recent
# clean-codebase calibration row. Default behaviour is advisory (WARN); set
# REQUIRE_FP_CALIBRATION=1 in the environment to promote missing/stale rows
# to FAIL.

_FP_CALIBRATION_MANIFEST_REL = "reference/fp_calibration_manifest.json"
_FP_CALIBRATION_TIER_REGISTRY_REL = "detectors/_tier_registry.yaml"


def _fp_calibration_strict() -> bool:
    raw = os.environ.get("REQUIRE_FP_CALIBRATION", "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def check_fp_calibration_manifest(
    repo_root: Path = REPO_ROOT,
    *,
    require_strict: bool | None = None,
    max_age_days: int = 90,
    now: object | None = None,
) -> CheckResult:
    """Surface the FP-calibration manifest during close-out.

    PASS  — manifest present and every Tier-S/A pattern has a row newer
            than ``max_age_days``.
    WARN  — manifest missing/stale/missing-row (default, advisory). The
            row is promoted to FAIL when ``require_strict`` is True (env
            var ``REQUIRE_FP_CALIBRATION=1`` or function override).
    FAIL  — strict mode + missing/stale rows, or schema validation errors
            on a present manifest (those are always FAIL — a malformed
            machine-readable artifact is worse than a missing one).
    """
    strict = (
        require_strict if require_strict is not None
        else _fp_calibration_strict()
    )
    manifest_path = repo_root / _FP_CALIBRATION_MANIFEST_REL
    registry_path = repo_root / _FP_CALIBRATION_TIER_REGISTRY_REL

    # Lazy import: the manifest tool is stdlib-only and lives next door.
    tool_path = repo_root / "tools" / "fp-calibration-manifest.py"
    if not _exists(tool_path):
        # Should be unreachable in this repo; defensive WARN so a future
        # rename doesn't accidentally break close-out.
        return CheckResult(
            check="fp-calibration",
            status=WARN,
            reason=(
                "tools/fp-calibration-manifest.py not present; cannot "
                "evaluate Tier-S/A FP calibration freshness"
            ),
            artifacts=[],
            detail={
                "manifest": str(manifest_path),
                "registry": str(registry_path),
                "strict": strict,
            },
        )

    import importlib.util as _ilu  # stdlib

    spec = _ilu.spec_from_file_location("fp_calibration_manifest", tool_path)
    if spec is None or spec.loader is None:
        return CheckResult(
            check="fp-calibration",
            status=WARN,
            reason="could not load tools/fp-calibration-manifest.py for import",
            artifacts=[],
            detail={"manifest": str(manifest_path)},
        )
    mod = _ilu.module_from_spec(spec)
    sys.modules.setdefault("fp_calibration_manifest", mod)
    spec.loader.exec_module(mod)

    manifest = mod.load_manifest(manifest_path)
    schema_errors = mod.validate_manifest(manifest)
    if schema_errors:
        return CheckResult(
            check="fp-calibration",
            status=FAIL,
            reason=(
                "fp_calibration_manifest.json failed schema validation: "
                + "; ".join(schema_errors[:5])
                + ("; ..." if len(schema_errors) > 5 else "")
            ),
            artifacts=[str(manifest_path)],
            detail={
                "manifest": str(manifest_path),
                "errors": schema_errors,
                "strict": strict,
            },
        )

    registry = mod.parse_tier_registry(registry_path)
    report = mod.required_for_tier_sa(
        manifest, registry, max_age_days=max_age_days, now=now
    )

    detail = {
        "manifest": str(manifest_path),
        "registry": str(registry_path),
        "tier_sa_count": len(report["tier_sa_patterns"]),
        "fresh_count": len(report["fresh"]),
        "stale_count": len(report["stale"]),
        "missing_count": len(report["missing"]),
        "max_age_days": report["max_age_days"],
        "strict": strict,
        "missing": report["missing"],
        "stale": report["stale"],
    }

    if report["ok"]:
        return CheckResult(
            check="fp-calibration",
            status=PASS,
            reason=(
                f"fp_calibration_manifest covers all "
                f"{len(report['tier_sa_patterns'])} Tier-S/A pattern(s) "
                f"with rows newer than {report['max_age_days']}d"
            ),
            artifacts=[str(manifest_path)],
            detail=detail,
        )

    status = FAIL if strict else WARN
    bits: list[str] = []
    if report["missing"]:
        bits.append(
            f"missing rows: {len(report['missing'])} "
            f"({', '.join(report['missing'][:3])}"
            + (", ..." if len(report["missing"]) > 3 else "")
            + ")"
        )
    if report["stale"]:
        bits.append(
            f"stale rows (> {report['max_age_days']}d): {len(report['stale'])}"
        )
    reason = "Tier-S/A FP calibration incomplete: " + "; ".join(bits)
    if strict:
        reason += " (REQUIRE_FP_CALIBRATION=1 -> FAIL)"
    return CheckResult(
        check="fp-calibration",
        status=status,
        reason=reason,
        artifacts=[str(manifest_path)],
        detail=detail,
    )


# ---- check 9: llm-budget --------------------------------------------------


def check_llm_budget() -> CheckResult:
    """Invoke ``tools/llm-budget-guard.py status`` and embed output.

    Also probes for a future ``tools/llm-preflight-auth.py``; absence is a
    TODO WARN, not a FAIL. No live provider calls.
    """
    guard = REPO_ROOT / "tools" / "llm-budget-guard.py"
    auth = REPO_ROOT / "tools" / "llm-preflight-auth.py"

    if not _exists(guard):
        return CheckResult(
            check="llm-budget",
            status=WARN,
            reason="tools/llm-budget-guard.py not present in repo",
            artifacts=[],
            detail={"guard": str(guard), "auth": str(auth)},
        )
    try:
        proc = subprocess.run(
            [sys.executable, str(guard), "status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        return CheckResult(
            check="llm-budget",
            status=WARN,
            reason="`llm-budget-guard.py status` timed out after 10s",
            artifacts=[str(guard)],
            detail={"guard": str(guard)},
        )
    except OSError as exc:
        return CheckResult(
            check="llm-budget",
            status=WARN,
            reason=f"could not invoke llm-budget-guard.py: {exc}",
            artifacts=[str(guard)],
            detail={"guard": str(guard)},
        )

    status_lines = proc.stdout.strip().splitlines()
    status_summary = "; ".join(status_lines[:6]) or "(no output)"
    auth_present = _exists(auth)

    if proc.returncode != 0:
        return CheckResult(
            check="llm-budget",
            status=WARN,
            reason=(
                f"llm-budget-guard returned rc={proc.returncode}: "
                + (proc.stderr.strip()[:160] or "(no stderr)")
            ),
            artifacts=[str(guard)],
            detail={
                "guard": str(guard),
                "auth_present": auth_present,
                "status_lines": status_lines,
                "stderr": proc.stderr.strip(),
            },
        )

    if not auth_present:
        return CheckResult(
            check="llm-budget",
            status=WARN,
            reason=(
                "llm-budget-guard status OK; "
                "TODO: tools/llm-preflight-auth.py not present (V5 follow-up). "
                f"status: {status_summary}"
            ),
            artifacts=[str(guard)],
            detail={
                "guard": str(guard),
                "auth_present": False,
                "status_lines": status_lines,
            },
        )
    return CheckResult(
        check="llm-budget",
        status=PASS,
        reason=f"llm-budget-guard status OK; preflight-auth present. {status_summary}",
        artifacts=[str(guard), str(auth)],
        detail={
            "guard": str(guard),
            "auth_present": True,
            "status_lines": status_lines,
        },
    )


# ---- check 10: p0-followups -----------------------------------------------

# Heuristic regex that finds explicit P0 markers in V5_CAPABILITY_GAPS_*.md.
# Either ``Priority: P0`` or ``**Priority**: P0`` shape.
_P0_RE = re.compile(r"\*?\*?Priority\*?\*?\s*[:=]\s*P0\b", re.IGNORECASE)


def check_p0_followups(ws: Path) -> CheckResult:
    """Look for explicit P0 follow-up tracking.

    Sources of P0 enumeration (in priority order):
      1. ``<ws>/.audit_logs/p0_followups.json`` — workspace-local manifest.
      2. ``<repo>/docs/V5_P0_FOLLOWUPS.md`` — repo-level manifest.

    If neither exists but the V5 capability-gaps doc lists P0 items, WARN.
    """
    ws_followups = ws / ".audit_logs" / "p0_followups.json"
    repo_followups = REPO_ROOT / "docs" / "V5_P0_FOLLOWUPS.md"
    gaps_doc = REPO_ROOT / "docs" / "V5_CAPABILITY_GAPS_2026-04-26.md"

    if _exists(ws_followups):
        payload = _read_json(ws_followups)
        n = len(payload.get("items", [])) if isinstance(payload, dict) else 0
        return CheckResult(
            check="p0-followups",
            status=PASS,
            reason=f"workspace p0_followups.json present ({n} item(s))",
            artifacts=[str(ws_followups)],
            detail={"source": str(ws_followups), "items": n},
        )
    if _exists(repo_followups):
        return CheckResult(
            check="p0-followups",
            status=PASS,
            reason="repo-level docs/V5_P0_FOLLOWUPS.md present",
            artifacts=[str(repo_followups)],
            detail={"source": str(repo_followups)},
        )

    # Neither tracking artifact exists; check whether the capability-gaps
    # doc lists any P0 items at all. If yes, WARN.
    if _exists(gaps_doc):
        text = _read_text(gaps_doc)
        p0_count = len(_P0_RE.findall(text))
        if p0_count:
            return CheckResult(
                check="p0-followups",
                status=WARN,
                reason=(
                    f"{p0_count} P0 item(s) in V5_CAPABILITY_GAPS doc but no "
                    "tracking artifact (workspace `.audit_logs/p0_followups.json` "
                    "or repo `docs/V5_P0_FOLLOWUPS.md`)."
                ),
                artifacts=[str(gaps_doc)],
                detail={
                    "gaps_doc": str(gaps_doc),
                    "p0_count": p0_count,
                    "ws_followups": str(ws_followups),
                    "repo_followups": str(repo_followups),
                },
            )
        return CheckResult(
            check="p0-followups",
            status=PASS,
            reason="V5 capability-gaps doc lists no P0 items",
            artifacts=[str(gaps_doc)],
            detail={"gaps_doc": str(gaps_doc), "p0_count": 0},
        )
    return CheckResult(
        check="p0-followups",
        status=WARN,
        reason=(
            "no V5 capability-gaps doc; cannot reason about P0 follow-up "
            "completeness"
        ),
        artifacts=[],
        detail={
            "gaps_doc": str(gaps_doc),
            "ws_followups": str(ws_followups),
            "repo_followups": str(repo_followups),
        },
    )


# ---- check 11: yaml-wave17-consistency (V5-P0-17 / foot-gun #14) ----------

# Each YAML pattern under reference/patterns.dsl/ is the source of truth;
# downstream artifacts are:
#   - detectors/wave17/<underscored>.py     -- compiled detector
#   - detectors/test_fixtures/run_tests.sh  -- regression rows referencing
#                                              the kebab-case pattern name
#                                              and the underscored fixtures
#
# Foot-gun #14 (rename-without-mate): a YAML gets renamed/added but its
# .py mate or run_tests.sh row is left stale. The pattern silently no-ops
# in production. This check enumerates the YAMLs and flags the mismatches.
#
# Edge cases handled (Kimi-pre-review):
#   - YAMLs under reference/patterns.dsl/_held/ are quarantined drafts;
#     they are explicitly excluded.
#   - run_tests.sh references can use either kebab- or underscore-cased
#     detector names; we normalise both sides before matching.
#   - Manually-compiled wave17/*.py with no YAML source-of-truth surface
#     as a separate "orphan" subset.
#   - The check is fixture-scoped: missing run_test rows are only flagged
#     for YAML patterns that ALSO have a `<name>_vulnerable.sol` fixture
#     on disk. Static-only patterns (no fixture) ship without a regression
#     row by design and we do not flag them.


def _pattern_to_under(name: str) -> str:
    return name.replace("-", "_")


def _strip_yaml_scalar_comment(value: str) -> str:
    """Best-effort top-level scalar cleanup for the tiny YAML subset used here.

    The closeout checker is intentionally stdlib-only. Pattern YAMLs are
    compiler-owned, so we only need to read simple top-level ``pattern:`` and
    ``status:`` values. Inline comments are common in status fields, e.g.
    ``status: documentation-only  # skip compiler``.
    """
    value = value.strip()
    if "#" in value:
        value = value.split("#", 1)[0].strip()
    return value.strip("\"'")


def _top_level_yaml_scalar(text: str, key: str) -> str:
    m = re.search(rf"^{re.escape(key)}:\s*(.*?)\s*$", text, re.MULTILINE)
    if not m:
        return ""
    return _strip_yaml_scalar_comment(m.group(1))


def _yaml_pattern_records(repo_root: Path) -> dict[str, dict[str, str]]:
    root = repo_root / "reference" / "patterns.dsl"
    if not _exists(root):
        return {}
    out: dict[str, dict[str, str]] = {}
    try:
        for p in root.iterdir():
            if not p.is_file():
                continue
            if p.suffix.lower() != ".yaml":
                continue
            if p.name.startswith("_") or p.name.startswith("."):
                continue
            text = _read_text(p)
            # The compiler emits detectors from the DSL's `pattern:` value, not
            # the YAML filename. Several migrated files intentionally kept their
            # historical filename while the canonical pattern id differs.
            pattern_id = _top_level_yaml_scalar(text, "pattern") or p.stem
            out[_pattern_to_under(pattern_id)] = {
                "file_stem": p.stem,
                "pattern": pattern_id,
                "status": _top_level_yaml_scalar(text, "status").lower(),
            }
    except OSError:
        return {}
    return out


def _yaml_pattern_names(repo_root: Path) -> set[str]:
    """Return compiler-canonical pattern names, preserving old helper API."""
    return set(_yaml_pattern_records(repo_root))


def _wave17_pattern_names(repo_root: Path) -> set[str]:
    root = repo_root / "detectors" / "wave17"
    if not _exists(root):
        return set()
    out: set[str] = set()
    try:
        for p in root.iterdir():
            if not p.is_file() or p.suffix != ".py":
                continue
            if p.name.startswith("_") or p.name.startswith("."):
                continue
            out.add(p.stem)
    except OSError:
        return set()
    return out


_RUN_TEST_RE = re.compile(
    r'^\s*run(?:_clean)?_test\s+"([A-Za-z0-9_\-]+)"',
    re.MULTILINE,
)


def _run_tests_pattern_names(repo_root: Path) -> tuple[set[str], set[str]]:
    """Return ``(vuln_names, clean_names)`` of underscore-normalised pattern
    names referenced by ``run_test``/``run_clean_test`` rows in
    ``detectors/test_fixtures/run_tests.sh``.
    """
    path = repo_root / "detectors" / "test_fixtures" / "run_tests.sh"
    if not _exists(path):
        return set(), set()
    text = _read_text(path)
    vuln: set[str] = set()
    clean: set[str] = set()
    for line in text.splitlines():
        m = _RUN_TEST_RE.match(line)
        if not m:
            continue
        name = _pattern_to_under(m.group(1))
        if "run_clean_test" in line:
            clean.add(name)
        else:
            vuln.add(name)
    return vuln, clean


def _fixture_pattern_names(repo_root: Path, *, suffix: str) -> set[str]:
    root = repo_root / "detectors" / "test_fixtures"
    if not _exists(root):
        return set()
    out: set[str] = set()
    try:
        for p in root.iterdir():
            if not p.is_file() or p.suffix != ".sol":
                continue
            stem = p.stem
            if stem.endswith(suffix):
                out.add(stem[: -len(suffix)])
    except OSError:
        return set()
    return out


def check_yaml_wave17_consistency(
    repo_root: Path,
    *,
    require_strict_wiring: bool,
) -> CheckResult:
    """V5-P0-17 / foot-gun #14: cross-check YAML <-> wave17 .py <->
    run_tests.sh. See module docstring for full edge-case list.
    """
    yaml_records = _yaml_pattern_records(repo_root)
    if not yaml_records:
        return CheckResult(
            check="yaml-wave17-consistency",
            status=WARN,
            reason=(
                "no YAML patterns under reference/patterns.dsl/; "
                "consistency check is non-applicable"
            ),
            artifacts=[],
            detail={"repo_root": str(repo_root)},
        )

    # Worker-U Loop 5 path A: also exclude YAMLs whose top-level ``status:``
    # field literally equals one of the gated tokens below. These are
    # source-of-truth YAMLs that are intentionally NOT compilable to a
    # ``detectors/wave17/<name>.py`` mate yet (either upstream content
    # is gated, or the mate must be hand-written). Filter is exact-match
    # on the top-level ``status:`` scalar (already lower-cased by
    # ``_yaml_pattern_records``); never substring against random fields.
    _DOC_ONLY_STATUSES = frozenset({
        "documentation-only",
        "not-submit-ready",
        "handwritten-detector",
        "blocked_semantic_detector",
    })
    documentation_only = {
        name for name, rec in yaml_records.items()
        if rec.get("status") in _DOC_ONLY_STATUSES
    }
    yaml_under = set(yaml_records) - documentation_only
    wave17 = _wave17_pattern_names(repo_root)
    vuln_rows, clean_rows = _run_tests_pattern_names(repo_root)
    fx_vuln = _fixture_pattern_names(repo_root, suffix="_vulnerable")
    fx_clean = _fixture_pattern_names(repo_root, suffix="_clean")

    missing_py = sorted(yaml_under - wave17)
    expected_vuln_rows = yaml_under & fx_vuln
    expected_clean_rows = yaml_under & fx_clean
    missing_vuln_row = sorted(expected_vuln_rows - vuln_rows)
    missing_clean_row = sorted(expected_clean_rows - clean_rows)
    orphan_py = sorted(wave17 - yaml_under)

    def _cap(xs: list[str], n: int = 16) -> list[str]:
        return xs[:n] + (["..."] if len(xs) > n else [])

    detail = {
        "repo_root": str(repo_root),
        "yaml_count": len(yaml_under),
        "documentation_only_yaml_count": len(documentation_only),
        "wave17_count": len(wave17),
        "fixture_vuln_count": len(fx_vuln),
        "fixture_clean_count": len(fx_clean),
        "run_test_vuln_rows": len(vuln_rows),
        "run_test_clean_rows": len(clean_rows),
        "missing_py": _cap(missing_py),
        "missing_vuln_row": _cap(missing_vuln_row),
        "missing_clean_row": _cap(missing_clean_row),
        "orphan_py": _cap(orphan_py),
        "missing_py_total": len(missing_py),
        "missing_vuln_row_total": len(missing_vuln_row),
        "missing_clean_row_total": len(missing_clean_row),
        "orphan_py_total": len(orphan_py),
        "require_strict_wiring": require_strict_wiring,
    }

    has_hard = bool(missing_py) or bool(missing_vuln_row)
    has_soft = bool(missing_clean_row) or bool(orphan_py)

    if not has_hard and not has_soft:
        return CheckResult(
            check="yaml-wave17-consistency",
            status=PASS,
            reason=(
                f"{len(yaml_under)} YAML patterns aligned with "
                f"{len(wave17)} wave17 detectors and run_tests rows"
            ),
            artifacts=[],
            detail=detail,
        )

    parts: list[str] = []
    if missing_py:
        parts.append(f"{len(missing_py)} YAML(s) without wave17 .py")
    if missing_vuln_row:
        parts.append(f"{len(missing_vuln_row)} YAML(s) without run_test row")
    if missing_clean_row:
        parts.append(
            f"{len(missing_clean_row)} YAML(s) without run_clean_test row"
        )
    if orphan_py:
        parts.append(f"{len(orphan_py)} wave17 .py orphan(s) (no YAML)")
    reason = "; ".join(parts)

    if has_hard and require_strict_wiring:
        return CheckResult(
            check="yaml-wave17-consistency",
            status=FAIL,
            reason=(
                "V5-P0-17 (foot-gun #14): " + reason
                + " (--require-strict-wiring promotes to FAIL)"
            ),
            artifacts=[],
            detail=detail,
        )
    if has_hard:
        return CheckResult(
            check="yaml-wave17-consistency",
            status=WARN,
            reason=(
                "V5-P0-17 (foot-gun #14): " + reason
                + " (pass --require-strict-wiring to make this a hard FAIL)"
            ),
            artifacts=[],
            detail=detail,
        )
    return CheckResult(
        check="yaml-wave17-consistency",
        status=WARN,
        reason="V5-P0-17 (advisory): " + reason,
        artifacts=[],
        detail=detail,
    )


# ---- check 12: evidence-class (item #14) ----------------------------------

# Closeout never treats anything below ``executed_with_manifest`` as proof.
# Legacy artifacts (no ``evidence_class`` field) WARN — they are not silently
# bucketed as ``generated_hypothesis`` because that is a real value.
_EVIDENCE_CLASS_ARTIFACTS = (
    ("brief_candidates", "swarm/brief_candidates.json"),
    ("source_mining_survivors", "source_mining/**/survivors.json"),
    (
        "deep_counterexample_records",
        "deep_counterexamples/*.deep_counterexample.v1.json",
    ),
    ("deep_counterexample_queue", "deep_counterexamples/execution_queue.json"),
    ("poc_execution_manifests", "poc_execution/**/execution_manifest.json"),
    ("impact_miss_benchmark", ".auditooor/impact_miss_offset_benchmark.json"),
    ("impact_miss_predictions", ".auditooor/impact_miss_offset_predictions.json"),
    ("impact_miss_harness_blockers", ".auditooor/impact_miss_harness_blocker_queue.json"),
    ("impact_miss_harness_execution", ".auditooor/impact_miss_harness_blocker_execution.json"),
    ("impact_proof_requirements", ".auditooor/impact_proof_requirement_manifests.json"),
    ("scanner_autonomy_plan", ".auditooor/scanner_autonomy_plan.json"),
    ("scanner_autonomy_execution", ".auditooor/scanner_autonomy_execution.json"),
    ("callgraph_terminal_conversion", ".auditooor/callgraph_terminal_conversion_*.json"),
    ("callgraph_fixture_smoke_evidence", ".auditooor/callgraph_fixture_smoke_evidence_*.json"),
    ("semantic_detector_argument_resolver", ".auditooor/semantic_detector_argument_resolver.json"),
    ("source_proof_impact_bridge", ".auditooor/source_proof_impact_bridge.json"),
    ("semantic_live_depth_blockers", ".auditooor/semantic_live_depth_blockers.json"),
    ("semantic_live_depth_queue", ".auditooor/semantic_live_depth_queue.json"),
    ("live_topology_proof_requirements", ".auditooor/live_topology_proof_requirements.json"),
    ("execution_proof_task_queue", ".auditooor/execution_proof_task_queue.json"),
    ("execution_proof_command_manifest", ".auditooor/execution_proof_command_manifest.json"),
    ("execution_proof_outcomes", ".auditooor/execution_proof_outcomes/*.json"),
    ("live_provider_result_triage", ".audit_logs/pr560_worker_*/live_provider_result_triage.json"),
    ("provider_local_verification_queue", ".audit_logs/pr560_worker_*/local_provider_verification_queue.json"),
    ("provider_result_local_verification", ".audit_logs/pr560_worker_*/provider_result_local_verification.json"),
    ("provider_local_verification_closure", ".audit_logs/pr560_worker_*/provider_local_verification_closure.json"),
)

_EVIDENCE_ROW_CONTAINER_KEYS = (
    "candidates",
    "items",
    "rows",
    "tasks",
    "predictions",
    "requirements",
    "outcomes",
    "results",
    "fixture_needed_tasks",
    "local_grep_tasks",
    "source_review_tasks",
    "killed_rows",
)


def _iter_records_for_artifact(ws: Path, glob_or_path: str) -> list[dict]:
    """Yield record dicts from each matching artifact.

    Each artifact may be:
      - a JSON list of records (e.g. ``survivors.json``)
      - a JSON object containing a ``candidates`` or ``items`` list
        (e.g. ``brief_candidates.json``, ``execution_queue.json``)
      - a single JSON object with its own ``evidence_class`` field
        (e.g. one ``deep_counterexample.v1.json`` or one
        ``execution_manifest.json``)
    Any other shape contributes a synthetic record with no evidence_class so
    the legacy WARN counter still trips.
    """
    rows: list[dict] = []
    for path in _glob(ws, glob_or_path):
        if path.name == "collection_manifest.json":
            continue
        if not path.is_file():
            continue
        data = _read_json(path)
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    rows.append({**item, "_artifact_path": str(path)})
                else:
                    rows.append({"_artifact_path": str(path)})
            continue
        if isinstance(data, dict):
            container = None
            for key in _EVIDENCE_ROW_CONTAINER_KEYS:
                child = data.get(key)
                if isinstance(child, list):
                    container = child
                    break
            if container is not None:
                for item in container:
                    if isinstance(item, dict):
                        rows.append({**item, "_artifact_path": str(path)})
                    else:
                        rows.append({"_artifact_path": str(path)})
                continue
            # Single-object artifact with its own evidence_class field
            # (deep_counterexample.v1, execution_manifest.v1, etc.).
            row = {**data, "_artifact_path": str(path)}
            if glob_or_path == "poc_execution/**/execution_manifest.json":
                validation = _validate_bound_sources(data, ws)
                row["_bound_source_validation"] = validation
                if not validation.get("valid", True):
                    # Keep the row and its diagnostics, but prevent a stale
                    # source binding from being counted as verified evidence.
                    row.pop("evidence_class", None)
            rows.append(row)
            continue
        # Unreadable / wrong shape — count a single legacy row so the WARN
        # surfaces.
        rows.append({"_artifact_path": str(path)})
    return rows


def _truthy_record_bool(value: object) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _false_record_bool(value: object) -> bool:
    return value is False or (isinstance(value, str) and value.strip().lower() == "false")


def _row_has_exact_proof_state(row: dict) -> bool:
    exact_keys = (
        "selected_impact",
        "exact_impact",
        "exact_impact_row",
        "impact_assertion",
        "listed_impact_proven",
        "source_proof",
        "source_proofs",
        "source_hits",
        "source_paths",
        "final_verdict",
        "oos_status",
        "oos_verdict",
        "scope_status",
        "submission_posture",
    )
    return any(row.get(key) not in (None, "", [], {}) for key in exact_keys)


def _evidence_policy_violations(label: str, records: list[dict]) -> list[dict]:
    violations: list[dict] = []
    for idx, row in enumerate(records):
        evidence_class = row.get("evidence_class")
        verified = _EVIDENCE_CLASS.is_verified(evidence_class)
        row_id = (
            row.get("requirement_id")
            or row.get("task_id")
            or row.get("queue_id")
            or row.get("candidate_id")
            or row.get("benchmark_id")
            or row.get("id")
            or idx
        )
        base = {
            "artifact": label,
            "path": str(row.get("_artifact_path") or label),
            "row_id": str(row_id),
        }
        if not verified and _truthy_record_bool(row.get("submit_ready")):
            violations.append({**base, "reason": "unverified_row_submit_ready_true"})
        if not verified and _truthy_record_bool(row.get("promotion_allowed")):
            violations.append({**base, "reason": "unverified_row_promotion_allowed_true"})
        if (
            not verified
            and row.get("submit_ready") is not None
            and not _truthy_record_bool(row.get("submit_ready"))
            and not _false_record_bool(row.get("submit_ready"))
        ):
            violations.append({**base, "reason": "unverified_row_submit_ready_not_false"})
        if verified and not _row_has_exact_proof_state(row):
            violations.append(
                {**base, "reason": "verified_row_missing_exact_impact_source_or_scope_state"}
            )
    return violations


def check_evidence_class(ws: Path) -> CheckResult:
    """KNOWN_LIMITATIONS item #14: every closeout artifact must declare
    ``evidence_class``. Legacy artifacts WARN; verified totals only count
    rows at ``executed_with_manifest`` or above.
    """
    per_artifact: dict[str, dict[str, int]] = {}
    legacy_rows: list[str] = []
    policy_violations: list[dict] = []
    aggregate = _EVIDENCE_CLASS.empty_counts()
    for label, glob_or_path in _EVIDENCE_CLASS_ARTIFACTS:
        records = _iter_records_for_artifact(ws, glob_or_path)
        counts = _EVIDENCE_CLASS.count_records(records)
        per_artifact[label] = counts
        aggregate = _EVIDENCE_CLASS.merge_counts(aggregate, counts)
        policy_violations.extend(_evidence_policy_violations(label, records))
        if counts.get(_EVIDENCE_CLASS.MISSING, 0):
            for rec in records:
                if not _EVIDENCE_CLASS.is_known(rec.get("evidence_class")):
                    artifact = rec.get("_artifact_path") or label
                    legacy_rows.append(f"{label}:{artifact}")

    total_rows = sum(aggregate.values())
    legacy_count = aggregate.get(_EVIDENCE_CLASS.MISSING, 0)
    verified = _EVIDENCE_CLASS.verified_total(aggregate)
    hypotheses = _EVIDENCE_CLASS.hypothesis_total(aggregate)

    detail = {
        "schema_version": _EVIDENCE_CLASS.SCHEMA_VERSION,
        "evidence_classes": list(_EVIDENCE_CLASS.EVIDENCE_CLASSES),
        "verified_classes": sorted(_EVIDENCE_CLASS.VERIFIED_CLASSES),
        "per_artifact_counts": per_artifact,
        "aggregate_counts": aggregate,
        "total_rows": total_rows,
        "legacy_count": legacy_count,
        "legacy_rows_sample": sorted(set(legacy_rows))[:8],
        "policy_violation_count": len(policy_violations),
        "policy_violations_sample": policy_violations[:8],
        "verified_count": verified,
        "hypothesis_count": hypotheses,
    }

    if total_rows == 0:
        return CheckResult(
            check="evidence-class",
            status=PASS,
            reason=(
                "no closeout artifacts present; evidence_class accounting is "
                "non-applicable"
            ),
            artifacts=[],
            detail=detail,
        )
    if legacy_count > 0:
        return CheckResult(
            check="evidence-class",
            status=WARN,
            reason=(
                f"{legacy_count} closeout row(s) missing evidence_class; "
                "treat as legacy and rerun the upstream tool to backfill the "
                "field. Verified={verified}, hypotheses={hypotheses}.".format(
                    verified=verified, hypotheses=hypotheses
                )
            ),
            artifacts=[],
            detail=detail,
        )
    if policy_violations:
        return CheckResult(
            check="evidence-class",
            status=WARN,
            reason=(
                f"{len(policy_violations)} evidence policy violation(s); "
                "unverified rows must not be submit-ready/promotable and verified "
                "rows must carry exact impact/source/scope state. "
                f"Verified={verified}, hypotheses={hypotheses}."
            ),
            artifacts=[],
            detail=detail,
        )
    return CheckResult(
        check="evidence-class",
        status=PASS,
        reason=(
            f"{verified} verified row(s), {hypotheses} hypothesis row(s); "
            "no missing evidence_class"
        ),
        artifacts=[],
        detail=detail,
    )


# ---- check 12: counterexample-execution (P0-1 burn-down) -----------------
#
# Background: deep-counterexample-queue.py turns audit-deep symbolic/fuzz
# traces into queue rows, but a queue row is *not* proof. Until a replay is
# wired and an execution manifest under poc_execution/**/ is recorded, the
# trace is "advisory until replayed". The legacy poc-execution check folds
# deep records into a generic queue summary; this dedicated row gives the
# operator an explicit executed-vs-unreplayed count and a strict-mode escape
# hatch (REQUIRE_REPLAY_EXECUTED=1) that promotes WARN to FAIL when a campaign
# must not ship with stale counterexample queue items.

REPLAY_NOT_EXECUTED_STATUS = "replay-not-executed"
REQUIRE_REPLAY_EXECUTED_ENV = "REQUIRE_REPLAY_EXECUTED"


def _counterexample_slug(value: str) -> str:
    """Mirror the slug rule used by deep-counterexample-queue.py.

    Stdlib-only normalization so this check stays offline-safe and we do not
    import the queue module (its filename has hyphens, which makes import
    fragile in test contexts).
    """
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9_.-]+", "-", value)
    return value.strip("-") or "counterexample"


def _record_id_for(path: Path) -> str:
    suffix = ".deep_counterexample.v1.json"
    return path.name[: -len(suffix)] if path.name.endswith(suffix) else path.stem


def _execution_manifest_index(ws: Path) -> list[dict]:
    """Read every poc_execution/**/execution_manifest.json into a list of
    dicts, attaching the file path. Mirrors deep-counterexample-queue.py.
    """
    out: list[dict] = []
    for path in _glob(ws, "poc_execution/**/execution_manifest.json"):
        data = _read_json(path)
        if isinstance(data, dict):
            row = dict(data)
            row["_path"] = str(path)
            row["_bound_source_validation"] = _validate_bound_sources(row, ws)
            out.append(row)
    return out


def _counterexample_execution_match(
    record_id: str,
    record: dict,
    manifests: list[dict],
) -> dict | None:
    """Return the first execution manifest that plausibly belongs to
    ``record_id`` / ``record``. Mirrors execution_match() in
    deep-counterexample-queue.py so closeout and the queue tool agree.
    """
    target_slug = _counterexample_slug(str(record.get("target_function") or ""))
    forge_path = str(record.get("generated_forge_test_path") or "")
    forge_stem = _counterexample_slug(Path(forge_path).stem) if forge_path else ""
    candidates = {record_id, target_slug, forge_stem}
    candidates.discard("")
    for manifest in manifests:
        if not manifest.get("_bound_source_validation", {}).get("valid", True):
            continue
        candidate_id = _counterexample_slug(str(manifest.get("candidate_id") or ""))
        brief = _counterexample_slug(str(manifest.get("brief_path") or ""))
        if candidate_id in candidates:
            return manifest
        if any(c and c in brief for c in candidates):
            return manifest
    return None


def check_counterexample_execution(
    ws: Path,
    *,
    require_replay_executed: bool,
) -> CheckResult:
    """P0-1 burn-down: every deep_counterexample.v1 record needs a paired
    execution manifest before it can be treated as proof. Without one the
    record is queue evidence, not a verified replay.

    Status semantics:
      - empty queue                  -> PASS (no symbolic traces collected)
      - all records executed         -> PASS
      - some records unreplayed      -> WARN (or FAIL when strict)
      - records exist + no manifests -> WARN (or FAIL when strict)
    """
    records = [
        path
        for path in _glob(ws, "deep_counterexamples/*.deep_counterexample.v1.json")
        if path.name != "collection_manifest.json"
    ]
    if not records:
        return CheckResult(
            check="counterexample-execution",
            status=PASS,
            reason=(
                "no deep_counterexample.v1 records present; symbolic/fuzz "
                "replay queue is empty"
            ),
            artifacts=[],
            detail={
                "record_count": 0,
                "executed_count": 0,
                "unreplayed_count": 0,
                "unreplayed_records": [],
                "executed_records": [],
                "require_replay_executed": bool(require_replay_executed),
                "strict_env_var": REQUIRE_REPLAY_EXECUTED_ENV,
                "status_value": "queue-empty",
            },
        )

    manifests = _execution_manifest_index(ws)
    executed_rows: list[dict] = []
    unreplayed_rows: list[dict] = []
    for path in records:
        rec = _read_json(path)
        record_id = _record_id_for(path)
        if not isinstance(rec, dict):
            unreplayed_rows.append({
                "record_id": record_id,
                "record_path": str(path),
                "engine": "",
                "target_function": "",
                "reason": "unreadable_or_malformed",
            })
            continue
        match = _counterexample_execution_match(record_id, rec, manifests)
        if match is not None:
            executed_rows.append({
                "record_id": record_id,
                "record_path": str(path),
                "engine": rec.get("engine", ""),
                "target_function": rec.get("target_function", ""),
                "execution_manifest": match.get("_path", ""),
                "final_result": match.get("final_result", ""),
                "impact_assertion": match.get("impact_assertion", ""),
            })
        else:
            unreplayed_rows.append({
                "record_id": record_id,
                "record_path": str(path),
                "engine": rec.get("engine", ""),
                "target_function": rec.get("target_function", ""),
                "reason": "no_execution_manifest",
            })

    total = len(records)
    n_executed = len(executed_rows)
    n_unreplayed = len(unreplayed_rows)
    detail = {
        "record_count": total,
        "executed_count": n_executed,
        "unreplayed_count": n_unreplayed,
        "execution_manifest_count": len(manifests),
        "invalid_bound_source_count": sum(
            not row.get("_bound_source_validation", {}).get("valid", True)
            for row in manifests
        ),
        "invalid_bound_source_rows": [
            {
                "path": row.get("_path", ""),
                "errors": row.get("_bound_source_validation", {}).get("errors", []),
            }
            for row in manifests
            if not row.get("_bound_source_validation", {}).get("valid", True)
        ],
        "executed_records": executed_rows,
        "unreplayed_records": unreplayed_rows,
        "require_replay_executed": bool(require_replay_executed),
        "strict_env_var": REQUIRE_REPLAY_EXECUTED_ENV,
        "status_value": (
            "all-replayed" if n_unreplayed == 0 else REPLAY_NOT_EXECUTED_STATUS
        ),
    }

    if n_unreplayed == 0:
        return CheckResult(
            check="counterexample-execution",
            status=PASS,
            reason=(
                f"{n_executed}/{total} deep counterexample(s) have execution "
                "manifests; replay coverage complete"
            ),
            artifacts=[row["execution_manifest"] for row in executed_rows[:20]],
            detail=detail,
        )

    sample_paths = [row["record_path"] for row in unreplayed_rows[:5]]
    base_reason = (
        f"P0-1: {n_unreplayed}/{total} deep counterexample(s) advisory "
        "until replayed (no poc_execution/**/execution_manifest.json); "
        f"executed={n_executed}, unreplayed={n_unreplayed}; status="
        f"{REPLAY_NOT_EXECUTED_STATUS}"
    )
    if require_replay_executed:
        return CheckResult(
            check="counterexample-execution",
            status=FAIL,
            reason=(
                base_reason
                + f" (--require-replay-executed / {REQUIRE_REPLAY_EXECUTED_ENV}=1)"
            ),
            artifacts=sample_paths,
            detail=detail,
        )
    return CheckResult(
        check="counterexample-execution",
        status=WARN,
        reason=(
            base_reason
            + " (pass --require-replay-executed or set "
            + f"{REQUIRE_REPLAY_EXECUTED_ENV}=1 to make this a hard FAIL)"
        ),
        artifacts=sample_paths,
        detail=detail,
    )


# ---- check 12b: replay-execution-distinction (PR #526 gap 5) -------------
#
# This check is paired with ``check_counterexample_execution`` (P0-1) but
# answers a different question: it surfaces an explicit "observed" vs
# "executed" distinction so closeout reports cannot accidentally treat a
# raw counterexample as if it had been replayed in Foundry. The legacy
# counterexample-execution row reports a bulk unreplayed_count; this row
# adds:
#
#   1. a per-record status of "observed" or "executed",
#   2. an optional cutoff timestamp (CLI ``--replay-after`` or env
#      ``REQUIRE_REPLAY_AFTER``) so legacy backlog stays advisory while
#      *new* counterexamples must be replayed,
#   3. the same strict-mode hatch used elsewhere
#      (``--require-replay-executed`` / ``REQUIRE_REPLAY_EXECUTED=1``)
#      which promotes WARN to FAIL once the cutoff is honoured.
#
# Cutoff parsing: accepts unix-seconds integers OR ISO-8601 strings.
# Records older than the cutoff are tagged "legacy" and never push the
# row to FAIL even in strict mode.

REQUIRE_REPLAY_AFTER_ENV = "REQUIRE_REPLAY_AFTER"


def _parse_replay_cutoff(raw: str | None) -> tuple[int | None, str | None]:
    """Return ``(unix_seconds_or_None, error_or_None)``.

    Empty / ``None`` -> ``(None, None)`` (no cutoff). Bad input keeps the
    cutoff disabled but surfaces the parse error in the check detail so
    operators see why their value did not apply.
    """
    if raw is None:
        return None, None
    raw = raw.strip()
    if not raw:
        return None, None
    if raw.isdigit():
        try:
            return int(raw), None
        except ValueError as exc:  # pragma: no cover - isdigit guarantees this
            return None, f"int parse error: {exc}"
    # Tolerate ISO-8601, optionally with a trailing Z.
    candidate = raw.replace("Z", "+00:00")
    try:
        from datetime import datetime
        dt = datetime.fromisoformat(candidate)
        return int(dt.timestamp()), None
    except ValueError as exc:
        return None, f"could not parse {raw!r} as int seconds or ISO-8601: {exc}"


def _record_observation_unix(path: Path, record: dict) -> int:
    """Best-effort timestamp for a deep counterexample.

    Prefers the in-record ``generated_at_unix`` (written by the bridge)
    or ``observed_at_unix``, then ``recorded_at_unix``, then the file's
    mtime. Returning ``0`` is reserved for "we genuinely could not
    determine a timestamp" so cutoff comparisons fall through.
    """
    for key in ("generated_at_unix", "observed_at_unix", "recorded_at_unix"):
        value = record.get(key)
        if isinstance(value, (int, float)) and value > 0:
            return int(value)
    try:
        return int(path.stat().st_mtime)
    except OSError:
        return 0


def check_replay_execution_distinction(
    ws: Path,
    *,
    require_replay_executed: bool,
    replay_cutoff_unix: int | None,
    replay_cutoff_parse_error: str | None = None,
) -> CheckResult:
    """Surface an explicit ``observed`` vs ``executed`` count for every
    deep_counterexample.v1 record under the workspace.

    Status semantics:
      - no records present                             -> PASS
      - all records executed                           -> PASS
      - records exist, no post-cutoff observed-only    -> PASS (legacy backlog)
      - some post-cutoff observed-only, default        -> WARN
      - some post-cutoff observed-only, strict-mode    -> FAIL
    """
    records = [
        path
        for path in _glob(ws, "deep_counterexamples/*.deep_counterexample.v1.json")
        if path.name != "collection_manifest.json"
    ]

    if not records:
        return CheckResult(
            check="replay-execution-distinction",
            status=PASS,
            reason=(
                "no deep_counterexample.v1 records present; "
                "nothing to distinguish"
            ),
            artifacts=[],
            detail={
                "record_count": 0,
                "observed_count": 0,
                "executed_count": 0,
                "post_cutoff_observed_count": 0,
                "legacy_observed_count": 0,
                "replay_cutoff_unix": replay_cutoff_unix,
                "replay_cutoff_env_var": REQUIRE_REPLAY_AFTER_ENV,
                "replay_cutoff_parse_error": replay_cutoff_parse_error,
                "require_replay_executed": bool(require_replay_executed),
                "strict_env_var": REQUIRE_REPLAY_EXECUTED_ENV,
                "status_value": "queue-empty",
            },
        )

    manifests = _execution_manifest_index(ws)
    observed_rows: list[dict] = []
    executed_rows: list[dict] = []
    for path in records:
        rec = _read_json(path)
        record_id = _record_id_for(path)
        if not isinstance(rec, dict):
            observed_rows.append({
                "record_id": record_id,
                "record_path": str(path),
                "engine": "",
                "target_function": "",
                "observed_at_unix": _record_observation_unix(path, {}),
                "is_legacy": False,
                "reason": "unreadable_or_malformed",
                "status": "observed",
            })
            continue
        ts = _record_observation_unix(path, rec)
        is_legacy = (
            replay_cutoff_unix is not None
            and ts > 0
            and ts < replay_cutoff_unix
        )
        match = _counterexample_execution_match(record_id, rec, manifests)
        if match is not None:
            executed_rows.append({
                "record_id": record_id,
                "record_path": str(path),
                "engine": rec.get("engine", ""),
                "target_function": rec.get("target_function", ""),
                "observed_at_unix": ts,
                "is_legacy": is_legacy,
                "execution_manifest": match.get("_path", ""),
                "final_result": match.get("final_result", ""),
                "impact_assertion": match.get("impact_assertion", ""),
                "status": "executed",
            })
        else:
            observed_rows.append({
                "record_id": record_id,
                "record_path": str(path),
                "engine": rec.get("engine", ""),
                "target_function": rec.get("target_function", ""),
                "observed_at_unix": ts,
                "is_legacy": is_legacy,
                "reason": "no_execution_manifest",
                "status": "observed",
            })

    total = len(records)
    n_observed = len(observed_rows)
    n_executed = len(executed_rows)
    legacy_observed = [row for row in observed_rows if row.get("is_legacy")]
    post_cutoff_observed = [row for row in observed_rows if not row.get("is_legacy")]

    detail = {
        "record_count": total,
        "observed_count": n_observed,
        "executed_count": n_executed,
        "legacy_observed_count": len(legacy_observed),
        "post_cutoff_observed_count": len(post_cutoff_observed),
        "execution_manifest_count": len(manifests),
        "invalid_bound_source_count": sum(
            not row.get("_bound_source_validation", {}).get("valid", True)
            for row in manifests
        ),
        "invalid_bound_source_rows": [
            {
                "path": row.get("_path", ""),
                "errors": row.get("_bound_source_validation", {}).get("errors", []),
            }
            for row in manifests
            if not row.get("_bound_source_validation", {}).get("valid", True)
        ],
        "replay_cutoff_unix": replay_cutoff_unix,
        "replay_cutoff_env_var": REQUIRE_REPLAY_AFTER_ENV,
        "replay_cutoff_parse_error": replay_cutoff_parse_error,
        "require_replay_executed": bool(require_replay_executed),
        "strict_env_var": REQUIRE_REPLAY_EXECUTED_ENV,
        "executed_records": executed_rows,
        "observed_records": observed_rows,
    }

    if n_observed == 0:
        detail["status_value"] = "all-executed"
        return CheckResult(
            check="replay-execution-distinction",
            status=PASS,
            reason=(
                f"observed=0 executed={n_executed} of {total} record(s); "
                "every counterexample has a paired execution manifest"
            ),
            artifacts=[row["execution_manifest"] for row in executed_rows[:20]],
            detail=detail,
        )

    if not post_cutoff_observed:
        # All observed records predate the cutoff -> legacy backlog only.
        detail["status_value"] = "legacy-only"
        cutoff_note = (
            f" (cutoff={replay_cutoff_unix})" if replay_cutoff_unix is not None else ""
        )
        return CheckResult(
            check="replay-execution-distinction",
            status=PASS,
            reason=(
                f"observed={n_observed} executed={n_executed} of {total} "
                f"record(s); all observed-only entries predate cutoff{cutoff_note}"
            ),
            artifacts=[row["record_path"] for row in legacy_observed[:5]],
            detail=detail,
        )

    sample_paths = [row["record_path"] for row in post_cutoff_observed[:5]]
    base_reason = (
        f"PR #526 gap 5: observed={n_observed} executed={n_executed} "
        f"(post_cutoff_observed={len(post_cutoff_observed)}, "
        f"legacy_observed={len(legacy_observed)}); each post-cutoff "
        "observed-only record needs poc_execution/**/execution_manifest.json"
    )
    if require_replay_executed:
        detail["status_value"] = "replay-not-executed"
        return CheckResult(
            check="replay-execution-distinction",
            status=FAIL,
            reason=(
                base_reason
                + f" (--require-replay-executed / {REQUIRE_REPLAY_EXECUTED_ENV}=1)"
            ),
            artifacts=sample_paths,
            detail=detail,
        )
    detail["status_value"] = "replay-not-executed"
    return CheckResult(
        check="replay-execution-distinction",
        status=WARN,
        reason=(
            base_reason
            + " (pass --require-replay-executed or set "
            + f"{REQUIRE_REPLAY_EXECUTED_ENV}=1 to make this a hard FAIL; "
            + f"set --replay-after / {REQUIRE_REPLAY_AFTER_ENV} to skip legacy backlog)"
        ),
        artifacts=sample_paths,
        detail=detail,
    )


# ---- check 12: fixture-duplicates (item #11 burn-down) --------------------

# Closeout reads the manifest emitted by tools/fixture-duplicate-detector.py.
# The detector is advisory-only (always exits 0) so the closeout check is the
# place where WARN/FAIL actually escalates. We DO NOT shell out to the
# detector here — closeout is a "what evidence exists?" gate, not a producer.
def check_fixture_duplicates(ws: Path) -> CheckResult:
    """Surface tools/fixture-duplicate-detector.py's manifest.

    Manifest schema: ``auditooor.fixture_duplicate.v1`` written to either
    ``<ws>/.auditooor/fixture_duplicate_manifest.json`` (workspace mode,
    invoked from `make audit`) or ``<repo>/.auditooor/fixture_duplicate_
    manifest.json`` (repo-level mode, invoked from `make fixture-dupe`).
    Closeout falls back to the repo-level manifest so a workspace audit run
    can still cite duplicate counts even if the operator only ran the
    detector at repo level.

    PASS / WARN / FAIL mirror the manifest's ``status`` field; a missing
    manifest is WARN (not FAIL) because the detector is advisory and may
    legitimately not have been run yet for a given workspace.
    """
    candidates = [
        ws / ".auditooor" / "fixture_duplicate_manifest.json",
        REPO_ROOT / ".auditooor" / "fixture_duplicate_manifest.json",
    ]
    manifest_path: Path | None = None
    for cand in candidates:
        if _exists(cand):
            manifest_path = cand
            break

    if manifest_path is None:
        return CheckResult(
            check="fixture-duplicates",
            status=WARN,
            reason=(
                "fixture_duplicate_manifest.json not found under "
                "<ws>/.auditooor/ or <repo>/.auditooor/; "
                "run `make fixture-dupe` to populate (item #11 burn-down)"
            ),
            artifacts=[str(c) for c in candidates],
            detail={"candidates": [str(c) for c in candidates]},
        )

    payload = _read_json(manifest_path)
    if not isinstance(payload, dict):
        return CheckResult(
            check="fixture-duplicates",
            status=FAIL,
            reason=(
                "fixture_duplicate_manifest.json present but unreadable / "
                "wrong shape (expected JSON object)"
            ),
            artifacts=[str(manifest_path)],
            detail={"manifest": str(manifest_path)},
        )

    raw_status = payload.get("status")
    status = raw_status if raw_status in (PASS, WARN, FAIL) else None
    duplicate_pairs = payload.get("duplicate_pairs")
    duplicate_groups = payload.get("duplicate_groups")
    total_fixtures = payload.get("total_fixtures")
    threshold_warn = payload.get("threshold_warn")
    threshold_fail = payload.get("threshold_fail")

    if status is None:
        return CheckResult(
            check="fixture-duplicates",
            status=FAIL,
            reason=(
                "fixture_duplicate_manifest.json has unrecognised status "
                f"{raw_status!r} (expected PASS|WARN|FAIL)"
            ),
            artifacts=[str(manifest_path)],
            detail={
                "manifest": str(manifest_path),
                "status_field": raw_status,
            },
        )

    detail = {
        "manifest": str(manifest_path),
        "total_fixtures": total_fixtures,
        "duplicate_pairs": duplicate_pairs,
        "duplicate_groups": duplicate_groups,
        "threshold_warn": threshold_warn,
        "threshold_fail": threshold_fail,
        "machine_summary": {
            "status": status,
            "duplicate_pairs": duplicate_pairs,
            "duplicate_groups": duplicate_groups,
            "total_fixtures": total_fixtures,
            "threshold_warn": threshold_warn,
            "threshold_fail": threshold_fail,
        },
    }

    if status == PASS:
        reason = (
            f"item #11: {duplicate_pairs} duplicate pair(s) / "
            f"{duplicate_groups} group(s) over {total_fixtures} fixture(s) "
            f"[warn>={threshold_warn}, fail>={threshold_fail}]"
        )
    elif status == WARN:
        reason = (
            f"item #11 WARN: {duplicate_pairs} duplicate pair(s) >= "
            f"warn threshold {threshold_warn} (fail at {threshold_fail}) "
            f"over {total_fixtures} fixture(s); see "
            "docs/FIXTURE_DUPLICATE_REPORT.md"
        )
    else:  # FAIL
        reason = (
            f"item #11 FAIL: {duplicate_pairs} duplicate pair(s) >= "
            f"fail threshold {threshold_fail} over {total_fixtures} "
            "fixture(s); fixtures need wholesale refactor before close-out"
        )

    return CheckResult(
        check="fixture-duplicates",
        status=status,
        reason=reason,
        artifacts=[str(manifest_path)],
        detail=detail,
    )


# ---- check N: invariant-ledger (PR #511 Slice 2) --------------------------
#
# The invariant ledger is the workspace bridge between scope/spec
# understanding and runnable harnesses. By default we WARN when the
# ledger is missing (this is NOT a silent zero — the closeout row is
# still emitted with WARN status and an explicit reason). Two env-var
# escalations:
#
#   REQUIRE_INVARIANT_LEDGER=1
#     Promote a missing ledger from WARN to FAIL.
#
#   REQUIRE_HIGH_IMPACT_INVARIANTS=1
#     Promote High/Critical rows lacking harness/replay/blocker from
#     WARN to FAIL.
#
# The check NEVER silently no-ops: even when both ledger files are
# absent it returns a CheckResult with `status=WARN` (or FAIL under
# strict mode) and a reason that names the missing path.

REQUIRE_INVARIANT_LEDGER_ENV = "REQUIRE_INVARIANT_LEDGER"
REQUIRE_HIGH_IMPACT_INVARIANTS_ENV = "REQUIRE_HIGH_IMPACT_INVARIANTS"


def _invariant_ledger_strict(env_name: str) -> bool:
    return os.environ.get(env_name, "").strip().lower() in {"1", "true", "yes", "on"}


def check_invariant_ledger(ws: Path) -> CheckResult:
    """Closeout row for the PR #511 Slice 2 invariant ledger.

    Default: WARN when the ledger is missing. Strict modes:
    REQUIRE_INVARIANT_LEDGER=1 -> FAIL on missing.
    REQUIRE_HIGH_IMPACT_INVARIANTS=1 -> FAIL on High/Critical rows that
    have no harness/replay/blocker.
    """
    require_ledger = _invariant_ledger_strict(REQUIRE_INVARIANT_LEDGER_ENV)
    require_high_impact = _invariant_ledger_strict(REQUIRE_HIGH_IMPACT_INVARIANTS_ENV)

    md_p = ws / "INVARIANT_LEDGER.md"
    json_p = ws / ".auditooor" / "invariant_ledger.json"
    manifest_p = ws / ".audit_logs" / "invariant_ledger_manifest.json"

    if not _exists(json_p):
        status = FAIL if require_ledger else WARN
        return CheckResult(
            check="invariant-ledger",
            status=status,
            reason=(
                "invariant_ledger.json not found; run "
                "`make invariant-ledger WS=<ws>` to scaffold "
                "(PR #511 Slice 2). "
                "Set REQUIRE_INVARIANT_LEDGER=1 to promote this WARN to FAIL."
                if not require_ledger
                else "invariant_ledger.json not found "
                "(REQUIRE_INVARIANT_LEDGER=1)."
            ),
            artifacts=[],
            detail={
                "json_path": str(json_p),
                "md_path": str(md_p),
                "manifest_path": str(manifest_p),
                "require_invariant_ledger": require_ledger,
                "require_high_impact_invariants": require_high_impact,
            },
        )

    payload = _read_json(manifest_p)
    if payload is None or not isinstance(payload, dict):
        # Ledger present but no closeout manifest. Try to compute a
        # cheap summary from the JSON store directly so the closeout
        # row still carries content.
        store = _read_json(json_p)
        rows = []
        if isinstance(store, dict):
            rows = store.get("rows", []) or []
        elif isinstance(store, list):
            rows = store
        status_counts: dict[str, int] = {}
        high_impact_total = 0
        high_impact_ok = 0
        for r in rows:
            if not isinstance(r, dict):
                continue
            st = r.get("status", "unknown")
            status_counts[st] = status_counts.get(st, 0) + 1
            sev = r.get("severity")
            if sev in ("High", "Critical"):
                high_impact_total += 1
                if st in (
                    "scaffolded", "executed_clean", "counterexample",
                    "killed", "blocked",
                ):
                    high_impact_ok += 1
        return CheckResult(
            check="invariant-ledger",
            status=WARN,
            reason=(
                f"ledger present ({len(rows)} row(s)) but "
                "invariant_ledger_manifest.json is missing/unreadable; "
                "run `python3 tools/invariant-ledger.py --workspace <ws> "
                "--emit-closeout` to persist a manifest"
            ),
            artifacts=[str(json_p)],
            detail={
                "row_count": len(rows),
                "status_counts": status_counts,
                "high_impact_total": high_impact_total,
                "high_impact_ok": high_impact_ok,
                "manifest_path": str(manifest_p),
                "require_invariant_ledger": require_ledger,
                "require_high_impact_invariants": require_high_impact,
            },
        )

    # Manifest present.
    row_count = int(payload.get("row_count", 0) or 0)
    status_counts = payload.get("status_counts") or {}
    high_impact_total = int(payload.get("high_impact_total", 0) or 0)
    high_impact_ok = int(payload.get("high_impact_ok", 0) or 0)
    high_impact_missing = high_impact_total - high_impact_ok
    issues = payload.get("issues") or []

    artifacts = [str(manifest_p), str(json_p)]
    detail = {
        "row_count": row_count,
        "status_counts": status_counts,
        "high_impact_total": high_impact_total,
        "high_impact_ok": high_impact_ok,
        "high_impact_missing": high_impact_missing,
        "issue_count": len(issues),
        "manifest_path": str(manifest_p),
        "require_invariant_ledger": require_ledger,
        "require_high_impact_invariants": require_high_impact,
    }

    if high_impact_missing > 0:
        status = FAIL if require_high_impact else WARN
        reason = (
            f"{high_impact_missing}/{high_impact_total} High/Critical row(s) "
            "lack harness/replay/blocker"
            + (" (REQUIRE_HIGH_IMPACT_INVARIANTS=1)" if require_high_impact
               else "; set REQUIRE_HIGH_IMPACT_INVARIANTS=1 to promote to FAIL")
        )
        return CheckResult(
            check="invariant-ledger",
            status=status,
            reason=reason,
            artifacts=artifacts,
            detail=detail,
        )

    if row_count == 0:
        return CheckResult(
            check="invariant-ledger",
            status=WARN,
            reason=(
                "ledger initialised but contains 0 rows; "
                "run `make invariant-ledger-check WS=<ws>` after "
                "seeding rows from scope"
            ),
            artifacts=artifacts,
            detail=detail,
        )

    return CheckResult(
        check="invariant-ledger",
        status=PASS,
        reason=(
            f"{row_count} row(s); high-impact "
            f"{high_impact_ok}/{high_impact_total} backed by harness"
        ),
        artifacts=artifacts,
        detail=detail,
    )


# PR #535 PR 1: program-impact-mapping promotion contract.
# `REQUIRE_PROGRAM_IMPACT_MAPPING=1` escalates the closeout row to FAIL
# whenever any non-clean status (missing_mapping / tier_mismatch /
# proof_artifact_missing) appears. Default policy is advisory WARN so
# existing workflows are unbroken.
REQUIRE_PROGRAM_IMPACT_MAPPING_ENV = "REQUIRE_PROGRAM_IMPACT_MAPPING"
REQUIRE_PR560_ARTIFACTS_ENV = "REQUIRE_PR560_ARTIFACTS"
ENFORCE_AUTONOMOUS_PROOF_CONVERSION_ENV = "ENFORCE_AUTONOMOUS_PROOF_CONVERSION"


def _require_program_impact_mapping() -> bool:
    return os.environ.get(REQUIRE_PROGRAM_IMPACT_MAPPING_ENV, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _truthy_env(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _enforce_autonomous_proof_conversion() -> bool:
    return os.environ.get(ENFORCE_AUTONOMOUS_PROOF_CONVERSION_ENV, "").strip() == "1"


def check_program_impact_mapping(ws: Path) -> CheckResult:
    """Closeout row for the Program Impact Mapping promotion contract.

    Counts emitted per workspace draft sweep:
      - ``mapped``                 — draft has a complete, rubric-grounded mapping
      - ``missing_mapping``        — Critical/High/paste-ready draft has no block
      - ``tier_mismatch``          — selected_impact lives in a different rubric tier
      - ``proof_artifact_missing`` — proof_artifact path does not resolve to a file
      - ``advisory_no_rubric``     — workspace has no SEVERITY*.md / RUBRIC_COVERAGE.md
      - ``not_required``           — Medium/Low draft without paste-ready marker

    Status policy:
      - All non-clean counts == 0  → PASS
      - Any non-clean count > 0    → WARN (default), or FAIL when
        ``REQUIRE_PROGRAM_IMPACT_MAPPING=1`` is set in the environment.
    """
    require_strict = _require_program_impact_mapping()

    if _IMPACT_MAPPING is None:
        return CheckResult(
            check="program-impact-mapping",
            status=WARN,
            reason=(
                "program_impact_mapping helper not loadable; "
                "tools/lib/program_impact_mapping.py missing or broken"
            ),
            artifacts=[],
            detail={"require_strict": require_strict},
        )

    rollup = _IMPACT_MAPPING.closeout_counts(ws)
    counts = rollup.get("counts", {})
    summaries = rollup.get("draft_summaries", [])

    mapped = int(counts.get("mapped", 0))
    missing = int(counts.get("missing_mapping", 0))
    tier = int(counts.get("tier_mismatch", 0))
    proof = int(counts.get("proof_artifact_missing", 0))
    advisory = int(counts.get("advisory_no_rubric", 0))
    not_required = int(counts.get("not_required", 0))
    total = int(counts.get("total", 0))

    bad = missing + tier + proof
    detail = {
        "mapped": mapped,
        "missing_mapping": missing,
        "tier_mismatch": tier,
        "proof_artifact_missing": proof,
        "advisory_no_rubric": advisory,
        "not_required": not_required,
        "total": total,
        "require_strict": require_strict,
        "strict_env_var": REQUIRE_PROGRAM_IMPACT_MAPPING_ENV,
        "draft_summaries": [
            {
                "draft": s.get("draft"),
                "status": s.get("status"),
                "severity_claim": s.get("severity_claim"),
                "selected_impact": s.get("selected_impact"),
                "errors": s.get("errors", []),
            }
            for s in summaries
        ],
    }

    if total == 0:
        return CheckResult(
            check="program-impact-mapping",
            status=PASS,
            reason=(
                "no drafts under submissions/{staging,ready,paste-ready,"
                "drafts,candidates}"
            ),
            artifacts=[],
            detail=detail,
        )

    if bad == 0:
        # PR #541 follow-up F7 fix: ``advisory_no_rubric`` was previously
        # bucketed silently into PASS. Operators reading only the
        # PASS/WARN/FAIL signal would miss the rubric-missing condition.
        # We now emit WARN whenever any draft fell into the advisory
        # bucket so the rubric-missing case is loud enough to spot in CI.
        if advisory > 0:
            return CheckResult(
                check="program-impact-mapping",
                status=WARN,
                reason=(
                    f"{advisory} draft(s) skipped rubric grounding because "
                    f"the workspace has no SEVERITY*.md / RUBRIC_COVERAGE.md "
                    f"({mapped} mapped, {not_required} not-required, "
                    f"{advisory} advisory_no_rubric across {total} draft(s)) "
                    f"-- add a rubric to enforce Critical/High grounding"
                ),
                artifacts=[],
                detail=detail,
            )
        return CheckResult(
            check="program-impact-mapping",
            status=PASS,
            reason=(
                f"{mapped} mapped / {not_required} not-required across "
                f"{total} draft(s)"
            ),
            artifacts=[],
            detail=detail,
        )

    status = FAIL if require_strict else WARN
    reason = (
        f"{bad} draft(s) with mapping issues "
        f"(missing_mapping={missing}, tier_mismatch={tier}, "
        f"proof_artifact_missing={proof}); "
    )
    if require_strict:
        reason += f"{REQUIRE_PROGRAM_IMPACT_MAPPING_ENV}=1 escalates to FAIL"
    else:
        reason += (
            f"set {REQUIRE_PROGRAM_IMPACT_MAPPING_ENV}=1 to escalate this WARN to FAIL"
        )
    return CheckResult(
        check="program-impact-mapping",
        status=status,
        reason=reason,
        artifacts=[],
        detail=detail,
    )


# PR #560 closeout integration: summarize the artifact family that records
# exact-impact contracts, harness/source-proof routing, corpus
# detectorization, and known-limitations burn-down. Default policy is
# advisory so ordinary closeout stays non-destructive; STRICT=1 or
# REQUIRE_PR560_ARTIFACTS=1 promotes unresolved/missing rows to FAIL.
PR560_ARTIFACT_SPECS = {
    "agent_output_inventory": {
        "paths": [".auditooor/agent_output_inventory.json"],
        "row_keys": ["rows"],
        "ok_statuses": {
            "verified_local",
            "killed_duplicate_or_oos",
            "routed_to_impact_analysis",
            "routed_to_source_proof",
            "routed_to_harness_task",
            "detectorized",
            "archived_no_claims",
            "ok",
        },
        "terminal_ok_statuses": set(),
        "unresolved_statuses": {
            "needs_local_verification",
            "needs_archive_review",
            "not_verified",
        },
    },
    "impact_contracts": {
        "paths": [".auditooor/impact_contracts.json"],
        "row_keys": ["contracts", "rows"],
        "ok_statuses": {
            "in_scope_direct_submit",
            "ok",
            "empty_no_candidates",
            "covered_by_candidate",
        },
        "terminal_ok_statuses": set(),
    },
    "harness_tasks": {
        "paths": [".auditooor/harness_tasks.json"],
        "row_keys": ["rows", "tasks"],
        "ok_statuses": {"ready_to_execute", "ok", "empty_no_harness_tasks"},
        "terminal_ok_statuses": set(),
    },
    "impact_analysis_queue": {
        "paths": [".auditooor/impact_analysis_queue.json"],
        "row_keys": ["rows"],
        "ok_statuses": {"empty_no_blocked_agent_recall_rows"},
        "terminal_ok_statuses": set(),
        "unresolved_statuses": {
            "exact_impact_candidate",
            "oos_duplicate_kill",
            "source_proof_precondition",
            "harness_precondition",
        },
    },
    "source_proof_tasks": {
        "paths": [".auditooor/source_proof_tasks.json"],
        "row_keys": ["rows", "tasks"],
        "ok_statuses": {"terminal_evidence_present", "empty_no_source_proof_tasks"},
        "terminal_ok_statuses": set(),
        "unresolved_statuses": {
            "ready_for_source_review",
            "blocked_missing_impact_contract",
            "blocked_missing_citations",
            "blocked_oos_not_checked",
        },
    },
    "source_proofs": {
        "paths": [".auditooor/source_proofs.json"],
        "glob": "source_proofs/**/source_proof.json",
        "row_keys": ["rows", "proofs"],
        "ok_statuses": {"proved_source_only", "killed", "ok"},
        "terminal_ok_statuses": set(),
    },
    "corpus_detectorization_inventory": {
        "paths": [".auditooor/corpus_detectorization_inventory.json"],
        "row_keys": ["rows"],
        "ok_statuses": {"detectorized", "killed", "ok"},
        "terminal_ok_statuses": set(),
    },
    "known_limitations_burndown": {
        "paths": [".auditooor/known_limitations_burndown.json"],
        "row_keys": ["rows"],
        "ok_statuses": {"already_satisfied_with_citation", "ok"},
        "terminal_ok_statuses": set(),
    },
    "invariant_acceptance_queue": {
        "paths": [".auditooor/invariant_acceptance_queue.json"],
        "row_keys": ["rows"],
        "ok_statuses": {
            "advisory_accepted",
            "advisory_merged",
            "advisory_killed",
            "advisory_harness_required",
            "advisory_review_dispositions_complete",
            "advisory_all_generated_invariants_accepted",
            "advisory_empty_invariant_acceptance_queue",
            "advisory_missing_generated_invariants",
        },
        "terminal_ok_statuses": set(),
        "unresolved_statuses": {
            "advisory_accept",
            "advisory_merge_duplicate",
            "advisory_needs_harness",
            "advisory_review_incomplete",
            "advisory_invariant_acceptance_queue_open",
        },
    },
    "pr560_next_actions": {
        "paths": [".auditooor/pr560_next_actions.json"],
        "row_keys": ["rows"],
        "ok_statuses": {"advisory_no_next_actions"},
        "terminal_ok_statuses": set(),
        "unresolved_statuses": {
            "advisory_accept",
            "advisory_accepted",
            "advisory_merge_duplicate",
            "advisory_merged",
            "advisory_needs_harness",
            "advisory_review_incomplete",
            "advisory_invariant_acceptance_queue_open",
            "advisory_next_actions_open",
            "harness_impact_work",
        },
    },
}


def _require_pr560_artifacts() -> bool:
    return _truthy_env("STRICT") or _truthy_env(REQUIRE_PR560_ARTIFACTS_ENV)


def _first_existing(paths: list[Path]) -> Path | None:
    for path in paths:
        if path.is_file():
            return path
    return None


def _rows_from_payload(payload: object, row_keys: list[str]) -> list[dict]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []
    rows: list[dict] = []
    for key in row_keys:
        value = payload.get(key)
        if isinstance(value, list):
            rows.extend(row for row in value if isinstance(row, dict))
    return rows


def _row_identifier(row: dict) -> str:
    for key in (
        "verification_task_id",
        "next_action_id",
        "limitation_id",
        "source_proof_task_id",
        "queue_id",
        "harness_task_id",
        "impact_contract_id",
        "candidate_id",
        "row_id",
        "source_id",
        "stable_source_path",
        "id",
        "title",
    ):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "UNKNOWN"


def _row_state(row: dict) -> str:
    for key in (
        "local_verification_status",
        "terminal_state",
        "strict_status",
        "status",
        "verdict",
        "final_verdict",
        "posture",
        "submission_posture",
        "candidate_status",
        "proof_status",
        "action_type",
    ):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _row_terminal_route(row: dict) -> str:
    value = row.get("terminal_route")
    return value.strip() if isinstance(value, str) else ""


def _source_proof_candidate_slug(value: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value.strip()).strip("-")
    return safe or "candidate"


def _source_proof_terminal_evidence(ws: Path, row: dict) -> tuple[bool, str, str]:
    candidate = str(row.get("candidate_id") or "").strip()
    if not candidate:
        return False, "", ""
    path = ws / "source_proofs" / _source_proof_candidate_slug(candidate) / "source_proof.json"
    payload = _read_json(path)
    if not isinstance(payload, dict):
        return False, str(path), ""
    if str(payload.get("candidate_id") or "") != candidate:
        return False, str(path), ""
    verdict = str(payload.get("final_verdict") or "").strip()
    if verdict not in {"proved_source_only", "killed", "blocked_missing_impact_contract"}:
        return False, str(path), verdict
    return True, str(path), verdict


def _strict_missing_fields(row: dict) -> list[str]:
    value = row.get("strict_missing_fields")
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return []


def _invariant_acceptance_missing_fields(row: dict) -> list[str]:
    state = _row_state(row).lower()
    action = str(row.get("suggested_ledger_action") or row.get("suggested_action") or "").strip()
    required: list[str] = []
    if state == "advisory_accepted" or action == "accept":
        required.extend(["exact_source_scope_text", "ledger_update_artifact", "next_command"])
    elif state == "advisory_merged" or action == "merge_duplicate":
        required.extend(["exact_source_scope_text", "accepted_row_id", "merge_evidence_artifact", "next_command"])
    elif state == "advisory_killed" or action == "kill_oos":
        required.extend(["exact_source_scope_text", "oos_precondition", "kill_evidence_artifact", "next_command"])
    elif state == "advisory_harness_required":
        required.extend(["exact_source_scope_text", "harness_target", "next_command"])
    missing = [field for field in required if not str(row.get(field) or "").strip()]
    missing.extend(str(item) for item in row.get("missing_review_evidence") or [] if str(item).strip())
    return sorted(set(_strict_missing_fields(row) + missing))


def _is_pr560_unresolved(
    row: dict,
    *,
    ok_statuses: set[str],
    terminal_ok_statuses: set[str],
    unresolved_statuses: set[str] | None = None,
    missing_fields: list[str] | None = None,
) -> bool:
    missing = missing_fields if missing_fields is not None else _strict_missing_fields(row)
    if missing:
        return True

    unresolved_tokens = (
        "blocked",
        "missing",
        "unresolved",
        "not_submit_ready",
        "harness_task",
        "inventory_only",
        "deferred",
        "queued",
        "needs_",
        "scaffolded_unverified",
    )
    strict_state = str(row.get("strict_status") or "").strip().lower()
    if strict_state and any(token in strict_state for token in unresolved_tokens):
        return True

    state = _row_state(row)
    state_l = state.lower()
    route_l = _row_terminal_route(row).lower()
    configured_unresolved = {s.lower() for s in (unresolved_statuses or set())}

    if state_l in {s.lower() for s in ok_statuses}:
        return False
    if route_l in {s.lower() for s in terminal_ok_statuses}:
        return False
    if state_l in configured_unresolved:
        return True

    if not state_l:
        return False

    return any(token in state_l for token in unresolved_tokens)


def _summarize_pr560_artifact(ws: Path, name: str, spec: dict) -> dict:
    candidate_paths = [ws / rel for rel in spec.get("paths", [])]
    glob_pattern = spec.get("glob")
    glob_paths = _glob(ws, glob_pattern) if isinstance(glob_pattern, str) else []
    path = _first_existing(candidate_paths) or (glob_paths[0] if glob_paths else None)
    row_keys = list(spec.get("row_keys", []))
    ok_statuses = set(spec.get("ok_statuses", set()))
    terminal_ok_statuses = set(spec.get("terminal_ok_statuses", set()))
    unresolved_statuses = set(spec.get("unresolved_statuses", set()))

    if path is None:
        return {
            "present": False,
            "paths_checked": (
                [str(p) for p in candidate_paths] + [str(ws / glob_pattern)]
                if isinstance(glob_pattern, str)
                else [str(p) for p in candidate_paths]
            ),
            "row_count": 0,
            "unresolved_count": 0,
            "unresolved_rows": [],
            "status": "missing",
        }

    payload = _read_json(path)
    if payload is None:
        return {
            "present": True,
            "path": str(path),
            "row_count": 0,
            "unresolved_count": 1,
            "unresolved_rows": [
                {
                    "id": path.name,
                    "state": "unreadable_or_invalid_json",
                    "path": str(path),
                }
            ],
            "status": "unreadable_or_invalid_json",
        }

    rows = _rows_from_payload(payload, row_keys)
    if name == "source_proofs" and glob_paths:
        rows = []
        for proof_path in glob_paths:
            proof_payload = _read_json(proof_path)
            if isinstance(proof_payload, dict):
                row = dict(proof_payload)
                row["_source_file"] = str(proof_path)
                rows.append(row)

    unresolved = []
    resolved_by_external_evidence = []
    for row in rows:
        missing_fields = (
            _invariant_acceptance_missing_fields(row)
            if name == "invariant_acceptance_queue"
            else _strict_missing_fields(row)
        )
        if not _is_pr560_unresolved(
            row,
            ok_statuses=ok_statuses,
            terminal_ok_statuses=terminal_ok_statuses,
            unresolved_statuses=unresolved_statuses,
            missing_fields=missing_fields,
        ):
            continue
        unresolved.append(
            {
                "id": _row_identifier(row),
                "state": _row_state(row) or _row_terminal_route(row) or "unknown",
                "path": str(row.get("_source_file") or path),
                "next_command": str(row.get("next_command") or row.get("owner_command") or ""),
                "stop_condition": str(row.get("stop_condition") or ""),
                "missing_fields": missing_fields,
            }
        )

    return {
        "present": True,
        "path": str(path),
        "row_count": len(rows),
        "unresolved_count": len(unresolved),
        "unresolved_rows": unresolved[:10],
        "resolved_by_external_evidence": resolved_by_external_evidence[:10],
        "resolved_by_external_evidence_count": len(resolved_by_external_evidence),
        "status": (
            "unresolved_rows"
            if unresolved
            else ("empty" if not rows else "ok")
        ),
    }


def check_pr560_artifact_closure(
    ws: Path,
    *,
    require_strict: bool | None = None,
) -> CheckResult:
    strict = _require_pr560_artifacts() if require_strict is None else require_strict
    summaries = {
        name: _summarize_pr560_artifact(ws, name, spec)
        for name, spec in PR560_ARTIFACT_SPECS.items()
    }
    missing = [name for name, summary in summaries.items() if not summary["present"]]
    unresolved = {
        name: summary["unresolved_count"]
        for name, summary in summaries.items()
        if int(summary.get("unresolved_count", 0)) > 0
    }
    artifact_paths = [
        str(summary.get("path"))
        for summary in summaries.values()
        if isinstance(summary.get("path"), str)
    ]
    total_unresolved = sum(unresolved.values())
    next_command_examples = []
    for artifact_name, summary in summaries.items():
        for row in summary.get("unresolved_rows", []):
            if not isinstance(row, dict):
                continue
            command = str(row.get("next_command") or "").strip()
            if not command:
                continue
            next_command_examples.append(
                {
                    "artifact": artifact_name,
                    "id": row.get("id") or "UNKNOWN",
                    "state": row.get("state") or "unknown",
                    "next_command": command,
                }
            )
    detail = {
        "require_strict": strict,
        "strict_env_vars": ["STRICT", REQUIRE_PR560_ARTIFACTS_ENV],
        "artifacts": summaries,
        "missing_artifacts": missing,
        "unresolved_counts": unresolved,
        "total_unresolved": total_unresolved,
        "next_command_examples": next_command_examples[:8],
    }

    if not missing and total_unresolved == 0:
        return CheckResult(
            check="pr560-artifact-closure",
            status=PASS,
            reason="PR560 closeout artifacts present with no unresolved blocked rows",
            artifacts=artifact_paths,
            detail=detail,
        )

    status = FAIL if strict else WARN
    parts = []
    if missing:
        parts.append("missing " + ", ".join(missing))
    if unresolved:
        parts.append(
            "unresolved "
            + ", ".join(f"{name}={count}" for name, count in sorted(unresolved.items()))
        )
    reason = "; ".join(parts) or "PR560 artifacts unresolved"
    if strict:
        reason += " (STRICT closeout enabled)"
    else:
        reason += (
            f"; advisory only (set STRICT=1 or {REQUIRE_PR560_ARTIFACTS_ENV}=1 "
            "to fail closeout)"
        )
    return CheckResult(
        check="pr560-artifact-closure",
        status=status,
        reason=reason,
        artifacts=artifact_paths,
        detail=detail,
    )


# ---- check: outcome-scoreboard (T1-P0-4) ----------------------------------


# v0 freshness window: WARN if the scoreboard is staler than this; never FAIL.
_OUTCOME_SCOREBOARD_FRESH_DAYS = 7


def check_outcome_scoreboard(ws: Path) -> CheckResult:
    """T1-P0-4 v0: scoreboard freshness gate.

    Reads ``reports/outcome_scoreboard.json`` (repo-level, not per-workspace
    — the ledger is shared across engagements). PASS if present and fresh
    (mtime within ``_OUTCOME_SCOREBOARD_FRESH_DAYS``), WARN if missing or
    stale, never FAIL. The lane is a v0 visibility gate, not a hard close-out
    blocker — outcomes can lag behind code by weeks while triagers respond.
    """
    sb_path = REPO_ROOT / "reports" / "outcome_scoreboard.json"
    if not _exists(sb_path):
        return CheckResult(
            check="outcome-scoreboard",
            status=WARN,
            reason=(
                "reports/outcome_scoreboard.json missing; "
                "run `make outcome-scoreboard` to refresh (T1-P0-4 v0)"
            ),
            artifacts=[],
            detail={"path": str(sb_path)},
        )
    try:
        mtime = sb_path.stat().st_mtime
    except OSError as exc:
        return CheckResult(
            check="outcome-scoreboard",
            status=WARN,
            reason=f"could not stat reports/outcome_scoreboard.json: {exc}",
            artifacts=[str(sb_path)],
            detail={"path": str(sb_path)},
        )
    age_days = (time.time() - mtime) / 86400.0
    try:
        payload = json.loads(sb_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return CheckResult(
            check="outcome-scoreboard",
            status=WARN,
            reason=(
                f"reports/outcome_scoreboard.json parse error: {exc}; "
                "regenerate via `make outcome-scoreboard`"
            ),
            artifacts=[str(sb_path)],
            detail={"path": str(sb_path), "age_days": age_days},
        )
    schema = payload.get("schema") if isinstance(payload, dict) else None
    if schema != "auditooor.outcome_scoreboard.v1":
        return CheckResult(
            check="outcome-scoreboard",
            status=WARN,
            reason=(
                f"reports/outcome_scoreboard.json schema mismatch: {schema!r} "
                "(expected auditooor.outcome_scoreboard.v1)"
            ),
            artifacts=[str(sb_path)],
            detail={"path": str(sb_path), "schema": schema},
        )
    rows = payload.get("ledger_row_count", 0)
    if age_days > _OUTCOME_SCOREBOARD_FRESH_DAYS:
        return CheckResult(
            check="outcome-scoreboard",
            status=WARN,
            reason=(
                f"reports/outcome_scoreboard.json is {age_days:.1f}d old "
                f"(> {_OUTCOME_SCOREBOARD_FRESH_DAYS}d); "
                f"rerun `make outcome-scoreboard` (rows={rows})"
            ),
            artifacts=[str(sb_path)],
            detail={
                "path": str(sb_path),
                "age_days": age_days,
                "rows": rows,
            },
        )
    return CheckResult(
        check="outcome-scoreboard",
        status=PASS,
        reason=(
            f"outcome scoreboard fresh ({age_days:.1f}d old); "
            f"rows={rows}, engagements={len(payload.get('engagements', []))}, "
            f"detectors={len(payload.get('detectors', []))}"
        ),
        artifacts=[str(sb_path)],
        detail={
            "path": str(sb_path),
            "age_days": age_days,
            "rows": rows,
            "by_outcome": payload.get("summary", {}).get("by_outcome", {}),
        },
        )


def check_hacker_question_obligations(ws: Path) -> CheckResult:
    """High/Critical drafts must not leave matching hacker questions open."""
    drafts = _discover_pre_submit_drafts(ws)
    if not drafts:
        return CheckResult(
            check="hacker-question-obligations",
            status=PASS,
            reason="no reportable submission drafts found; obligation gate not applicable",
            artifacts=[],
            detail={"draft_count": 0},
        )
    if _HACKER_QUESTION_OBLIGATIONS is None:
        return CheckResult(
            check="hacker-question-obligations",
            status=WARN,
            reason="hacker-question-obligations helper unavailable; cannot enforce open-obligation gate",
            artifacts=[],
            detail={"draft_count": len(drafts)},
        )

    rows: list[dict] = []
    blocking: list[dict] = []
    high_plus_count = 0
    for draft in drafts:
        text = _read_text(draft)
        sev = _severity_from_draft(text)
        row = {"draft": str(draft), "severity": sev, "blocking_count": 0}
        if sev in {"high", "critical"}:
            high_plus_count += 1
            result = _HACKER_QUESTION_OBLIGATIONS.gate_draft_obligations(ws, draft)
            row["gate_status"] = result.get("status")
            blockers = result.get("blocking_obligations") or []
            row["blocking_count"] = len(blockers)
            for blocker in blockers:
                blocking.append({"draft": str(draft), **blocker})
        rows.append(row)

    detail = {
        "draft_count": len(drafts),
        "high_plus_draft_count": high_plus_count,
        "blocking_count": len(blocking),
        "drafts": rows,
        "blocking_obligations": blocking[:10],
    }
    if blocking:
        return CheckResult(
            check="hacker-question-obligations",
            status=FAIL,
            reason=(
                f"{len(blocking)} open hacker-question obligation(s) still "
                "match High/Critical draft(s); answer, kill, or promote them "
                "before closeout"
            ),
            artifacts=[row["draft"] for row in blocking],
            detail=detail,
        )
    return CheckResult(
        check="hacker-question-obligations",
        status=PASS,
        reason="no matching open hacker-question obligations for High/Critical drafts",
        artifacts=[],
        detail=detail,
    )


# ---- H1/H2/H3/K6: strict audit-closeout checks --------------------------
#
# H1 - STRICT=1 fails when High/Critical drafts/candidates exist but the
#      required Hackerman receipts are missing (brain_prime_receipt,
#      novel_vectors.summary.json, exploit_conversion_loop_manifest, top-N
#      queue closure).
# H2 - Advisory warnings become BLOCKERS for High/Critical candidate
#      promotion (bridge failures, exploit-queue failures stay advisory for
#      low/no-draft workspaces; become FAIL in STRICT mode when H/C drafts
#      exist).
# H3 - Enforce the full audit/deep path.  The closeout artifact must prove
#      each required stage ran OR carry a typed NO_<STAGE>_REASON skip.
# K6 - Learning-gate result is surfaced as a closeout row so finalization
#      manifests can include learning_ledger_path, learning_gate_status,
#      and unclassified_artifact_count.


_BRAIN_PRIME_RECEIPT_CANDIDATES = (
    ".auditooor/brain_prime_receipt.json",
    "brain_prime_receipt.json",
)
_NOVEL_VECTORS_CANDIDATES = (
    ".auditooor/novel_vectors.summary.json",
    "novel_vectors.summary.json",
)
_EXPLOIT_CONV_LOOP_CANDIDATES = (
    ".auditooor/exploit_conversion_loop_manifest.json",
    "exploit_conversion_loop_manifest.json",
)
_PROVE_TOP_LEADS_REQUIRED_GROUPS = {
    "source_mine": ".auditooor/prove_top_leads_source_mine.json",
    "source_mined_impact_contracts": (
        ".auditooor/prove_top_leads_source_mined_impact_contracts.json"
    ),
    "prefiling_stress": ".auditooor/prove_top_leads_prefiling_stress_test.json",
    "candidate_judgment": ".auditooor/prove_top_leads_candidate_judgment_packet.json",
    "outcome_lesson_gate": ".auditooor/prove_top_leads_outcome_lesson_gate.json",
}
_PROVE_TOP_LEADS_NO_LEADS_SCHEMA = "auditooor.prove_top_leads_no_leads.v1"
_PROVE_TOP_LEADS_NO_LEADS_CANDIDATES = (
    ".auditooor/prove_top_leads_no_leads.json",
    "reports/prove_top_leads_no_leads.json",
)
_PROVE_TOP_LEADS_QUEUE_RELS = (
    # Parity with audit-completeness-check.py PROVE_TOP_LEADS_QUEUE_RELS: the
    # no-leads manifest is produced against the exploit queue + its source-mined
    # sibling, NOT proof_obligation_queue.json. Reading a different rel set here
    # made a real emitted manifest pass audit-complete yet fail audit-closeout.
    ".auditooor/exploit_queue.json",
    ".auditooor/exploit_queue.source_mined.json",
    ".auditooor/exploit_queue.zero_day_admitted.json",
)
_AUDIT_COMPLETENESS_TOOL = Path(__file__).with_name("audit-completeness-check.py")
_AUDIT_COMPLETENESS_MOD = None
_TYPED_ENVELOPE_TOOL = Path(__file__).with_name("zero-day-proof-envelope-verify.py")
_TYPED_ENVELOPE_MOD = None
_EVM_0DAY_PROOF_CANDIDATES = (
    ".auditooor/evm_0day_proof*.json",
    ".auditooor/evm-0day-proof*.json",
    "reports/evm_0day_proof*.json",
    "reports/evm-0day-proof*.json",
    "*evm_0day_proof*.json",
)
_EXPLOIT_QUEUE_CANDIDATES = (
    ".auditooor/exploit_queue.json",
    "exploit_queue.json",
)
_AUDIT_HACKER_BRIDGE_CANDIDATES = (
    ".auditooor/audit_hacker_logic_bridge.json",
    "audit_hacker_logic_bridge.json",
)
_MEDIUM_PLUS_RE = re.compile(r"\b(medium|high|critical)\b", re.IGNORECASE)
_EVM_SOURCE_EXTENSIONS = {".sol", ".vy"}
_EVM_0DAY_PROOF_PASS_STATES = {
    "proof_backed",
}
_EVM_0DAY_PROOF_FAIL_STATES = {
    "error",
    "fail",
    "failed",
    "blocked",
    "blocked_with_obligation",
    "candidate_not_submit_ready",
    "not_submit_ready",
    "scaffold_only_not_run",
    "scaffolded",
    "not_run",
    "no_run",
    "compile_blocked_with_obligation",
}

# Full ordered pipeline stages for H3.
_H3_STAGES = (
    # (stage_name, skip_env_key, artifact_rel_paths, is_required_for_high_crit)
    ("session-start",          "NO_SESSION_START_REASON",        [],                                   False),
    ("make-audit",             "NO_MAKE_AUDIT_REASON",           ["engage_report.md"],                 True),
    ("brain-prime",            "NO_BRAIN_PRIME_REASON",          list(_BRAIN_PRIME_RECEIPT_CANDIDATES), True),
    ("audit-deep",             "NO_AUDIT_DEEP_REASON",           [".audit_logs/audit_deep_all_manifest.json"], True),
    ("exploit-conversion-loop","NO_EXPLOIT_CONVERSION_REASON",   list(_EXPLOIT_CONV_LOOP_CANDIDATES),   True),
    ("prove-top-leads",        "NO_PROVE_TOP_LEADS_REASON",      [],                                   True),
    ("evm-0day-proof",         "NO_EVM_0DAY_PROOF_REASON",       [],                                   True),
    ("hacker-brief",           "NO_HACKER_BRIEF_REASON",         [".auditooor/worker_packets"],         False),
    # pre-submit has no emitted artifact; its gate is enforced by check_full_audit_path
    # via the pre-submit-check.sh run, but we cannot detect it purely from filesystem
    # artifacts here.  Keep required_for_hc=False so stages without an emitted artifact
    # do not hard-fail H3 (a typed NO_PRE_SUBMIT_REASON still silences the advisory).
    ("pre-submit",             "NO_PRE_SUBMIT_REASON",           [],                                   False),
    ("paste-ready",            "NO_PASTE_READY_REASON",          [],                                   False),
    ("finalization",           "NO_FINALIZATION_REASON",         [],                                   False),
)


def _ws_has_high_crit_drafts_or_candidates(ws: Path) -> bool:
    """Return True if the workspace has any High/Critical draft or candidate."""
    drafts = _discover_pre_submit_drafts(ws)
    for draft in drafts:
        text = _read_text(draft)
        if _severity_from_draft(text) in {"high", "critical"}:
            return True
    exploit_queue = _first_existing([ws / rel for rel in _EXPLOIT_QUEUE_CANDIDATES])
    if exploit_queue is not None:
        payload = _read_json(exploit_queue)
        if isinstance(payload, list):
            for row in payload:
                if not isinstance(row, dict):
                    continue
                sev = str(row.get("severity") or row.get("severity_tier") or "").lower()
                if sev in {"high", "critical"}:
                    return True
        elif isinstance(payload, dict):
            for key in ("rows", "items", "queue"):
                items = payload.get(key)
                if not isinstance(items, list):
                    continue
                for row in items:
                    if not isinstance(row, dict):
                        continue
                    sev = str(row.get("severity") or row.get("severity_tier") or "").lower()
                    if sev in {"high", "critical"}:
                        return True
    return False


def _skip_reason_for_stage(ws: Path, skip_key: str) -> str:
    """Return the typed skip reason for a stage, or empty string if not skipped.

    The typed reason lives in <ws>/.auditooor/stage_skips.json as a
    ``{skip_key: reason_text}`` map, or in any .auditooor/*.skip.md file whose
    stem matches the skip_key.
    """
    skip_json = ws / ".auditooor" / "stage_skips.json"
    if skip_json.is_file():
        payload = _read_json(skip_json)
        if isinstance(payload, dict):
            reason = payload.get(skip_key, "")
            if isinstance(reason, str) and reason.strip():
                return reason.strip()
    skip_md = ws / ".auditooor" / f"{skip_key}.md"
    if skip_md.is_file():
        text = _read_text(skip_md).strip()
        if text:
            return text.splitlines()[0]
    return ""


def _stage_artifact_present(ws: Path, rel_paths: list[str]) -> bool:
    """Return True if any of the artifact paths exists and is non-empty."""
    for rel in rel_paths:
        p = ws / rel
        try:
            if p.is_dir():
                return _dir_has_real_file(p)
            if p.is_file() and p.stat().st_size > 0:
                return True
        except OSError:
            continue
    return False


def _status_token(value: object) -> str:
    return str(value or "").strip().lower().replace(" ", "_").replace("-", "_")


def _glob_relative(ws: Path, patterns: Iterable[str]) -> list[Path]:
    """Return unique workspace-rooted glob matches for relative patterns."""
    seen: set[str] = set()
    matches: list[Path] = []
    for pattern in patterns:
        for path in _glob(ws, pattern):
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            matches.append(path)
    return matches


def _queue_row_count(payload: object) -> int:
    if isinstance(payload, list):
        return len(payload)
    if not isinstance(payload, dict):
        return 0
    for key in ("queue", "items", "candidates", "rows", "leads"):
        rows = payload.get(key)
        if isinstance(rows, list):
            return len(rows)
    return 0


def _prove_top_leads_current_queue_counts(ws: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rel in _PROVE_TOP_LEADS_QUEUE_RELS:
        path = ws / rel
        counts[rel] = _queue_row_count(_read_json(path)) if path.is_file() else 0
    return counts


def _load_audit_completeness_tool():
    """Load the single no-leads authority instead of copying closeout policy."""
    global _AUDIT_COMPLETENESS_MOD
    if _AUDIT_COMPLETENESS_MOD is not None:
        return _AUDIT_COMPLETENESS_MOD
    spec = importlib.util.spec_from_file_location(
        "audit_closeout_no_leads_completeness", _AUDIT_COMPLETENESS_TOOL,
    )
    if spec is None or spec.loader is None:
        raise ValueError("audit_completeness_no_leads_validator_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _AUDIT_COMPLETENESS_MOD = module
    return module


def _valid_prove_top_leads_no_leads_manifest(ws: Path, path: Path) -> bool:
    """Use the canonical completeness validator for closeout eligibility.

    Closeout may discover a manifest under an additional reports/ path, but it
    must never reinterpret its queue, freshness, or typed terminal semantics.
    """
    try:
        return bool(
            _load_audit_completeness_tool()._valid_prove_top_leads_no_leads_manifest(ws, path)
        )
    except Exception:
        return False


def _prefiling_confirms_all_terminal(ws: Path) -> bool:
    """UN-FAKEABLE corroboration for a non-empty-queue no-leads manifest: the
    prefiling-stress producer found 0 NON-TERMINAL top leads in a real window (top_n>0,
    rows_assessed==0) while >=1 queue row was skipped as already-terminal. That is
    the producer's own evidence that every eligible top lead is adjudicated - a
    processed queue with nothing left to prove, not an empty/unrun one. Mirrors
    audit-completeness-check.py:_prefiling_confirms_all_terminal for validator
    parity."""
    try:
        return bool(_load_audit_completeness_tool()._prefiling_confirms_all_terminal(ws))
    except Exception:
        return False


def _prove_top_leads_group_payload_valid(group: str, path: Path) -> bool:
    payload = _read_json(path)
    if not isinstance(payload, dict):
        return False
    if group == "source_mine":
        if payload.get("schema") != "auditooor.exploit_queue_source_miner.v1":
            return False
        return any(
            isinstance(payload.get(key), int)
            for key in ("selected_rows", "source_found", "blocked")
        ) or isinstance(payload.get("artifacts"), list)
    if group == "source_mined_impact_contracts":
        rows = payload.get("contracts")
        return isinstance(rows, list) and any(isinstance(row, dict) for row in rows)
    if group == "prefiling_stress":
        rows = payload.get("results")
        return isinstance(rows, list) and any(isinstance(row, dict) for row in rows)
    if group == "candidate_judgment":
        if payload.get("advisory_only") is True or payload.get("candidate_not_submit_ready") is True:
            return False
        rows = payload.get("packets")
        return isinstance(rows, list) and any(isinstance(row, dict) for row in rows)
    if group == "outcome_lesson_gate":
        if payload.get("schema") != "auditooor.outcome_lesson_gate.v1":
            return False
        status = str(payload.get("status") or payload.get("verdict") or "").strip().lower()
        return status in {"pass", "ok", "completed", "complete", "no-blockers"}
    return False


def _prove_top_leads_artifact_state(ws: Path) -> dict:
    groups: dict[str, list[str]] = {}
    invalid_groups: list[str] = []
    for group, rel in _PROVE_TOP_LEADS_REQUIRED_GROUPS.items():
        path = ws / rel
        if path.is_file() and path.stat().st_size > 0 and _prove_top_leads_group_payload_valid(group, path):
            groups[group] = [str(path)]
        else:
            groups[group] = []
            if path.is_file() and path.stat().st_size > 0:
                invalid_groups.append(group)
    missing = [group for group, paths in groups.items() if not paths]
    no_leads_candidates = _glob_relative(ws, _PROVE_TOP_LEADS_NO_LEADS_CANDIDATES)
    valid_no_leads = [
        str(path)
        for path in no_leads_candidates
        if _valid_prove_top_leads_no_leads_manifest(ws, path)
    ]
    artifacts: list[str] = []
    if not missing:
        for paths in groups.values():
            artifacts.extend(paths)
    elif valid_no_leads:
        artifacts.extend(valid_no_leads[:1])
    weak_candidates = [
        str(path)
        for path in _glob_relative(
            ws,
            (".auditooor/prove_top_leads_*", "reports/prove_top_leads_*"),
        )
    ]
    complete = bool(artifacts)
    return {
        "complete": complete,
        "artifact_groups": groups,
        "missing_required_groups": missing,
        "invalid_required_groups": invalid_groups,
        "no_leads_manifest": valid_no_leads[0] if valid_no_leads else None,
        "current_queue_rows": _prove_top_leads_current_queue_counts(ws),
        "weak_candidates": weak_candidates,
        "artifacts": artifacts,
        "reason": (
            "prove-top-leads full artifact set or structured no-leads manifest present"
            if complete
            else "missing prove-top-leads full artifact set and structured no-leads manifest"
        ),
    }


def _has_evm_source(ws: Path) -> bool:
    skip_dirs = {
        ".git",
        ".auditooor",
        ".audit_logs",
        "node_modules",
        "lib",
        "cache",
        "out",
        "reports",
    }
    try:
        for root, dirs, files in os.walk(ws):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
            if any(Path(name).suffix.lower() in _EVM_SOURCE_EXTENSIONS for name in files):
                return True
    except OSError:
        return False
    return False


def _has_medium_plus_evm_candidate(ws: Path) -> bool:
    queue = _first_existing([ws / rel for rel in _EXPLOIT_QUEUE_CANDIDATES])
    payload = _read_json(queue) if queue is not None else None
    rows: list[object] = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for key in ("queue", "items", "candidates", "rows", "leads"):
            value = payload.get(key)
            if isinstance(value, list):
                rows = value
                break
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ("severity", "tier", "impact_tier", "proposed_severity", "likely_severity"):
            value = row.get(key)
            if isinstance(value, str) and _MEDIUM_PLUS_RE.search(value):
                return True
    return False


def _needs_evm_0day_proof(ws: Path) -> bool:
    return _has_evm_source(ws) and _has_medium_plus_evm_candidate(ws)


def _load_typed_envelope_tool():
    global _TYPED_ENVELOPE_MOD
    if _TYPED_ENVELOPE_MOD is not None:
        return _TYPED_ENVELOPE_MOD
    spec = importlib.util.spec_from_file_location("audit_closeout_typed_envelope", _TYPED_ENVELOPE_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("typed_proof_envelope_tool_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _TYPED_ENVELOPE_MOD = module
    return module


def _typed_evm_proof_binding(ws: Path, payload: Mapping[str, object]) -> tuple[bool, str]:
    """Verify typed EVM proof context only when the artifact declares it."""
    candidate = payload.get("candidate")
    typed = candidate.get("zero_day_proof_envelope") if isinstance(candidate, Mapping) else None
    if typed is None:
        return True, "legacy_evm_proof_artifact"
    if not isinstance(typed, Mapping):
        return False, "typed_evm_proof_context_malformed"
    envelope_path = ws / ".auditooor" / "zero_day_proof_envelope.json"
    queue_path = ws / ".auditooor" / "exploit_queue.zero_day_admitted.json"
    if not envelope_path.is_file() or not queue_path.is_file():
        return False, "typed_evm_proof_envelope_missing"
    try:
        _load_typed_envelope_tool().verify(ws, envelope_path, queue_path)
        envelope = _read_json(envelope_path)
    except Exception:
        return False, "typed_evm_proof_envelope_invalid"
    entries = envelope.get("entries") if isinstance(envelope, Mapping) else None
    if not isinstance(entries, list):
        return False, "typed_evm_proof_envelope_invalid"
    envelope_id = typed.get("envelope_id")
    parent_ids = typed.get("parent_ids")
    lead_id = candidate.get("lead_id") if isinstance(candidate, Mapping) else None
    for entry in entries:
        if isinstance(entry, Mapping) and entry.get("envelope_id") == envelope_id and entry.get("parent_ids") == parent_ids and entry.get("lead_id") == lead_id:
            return True, "typed_evm_proof_envelope_verified"
    return False, "typed_evm_proof_envelope_binding_mismatch"


def _evm_0day_proof_artifact_state(ws: Path) -> dict:
    needed = _needs_evm_0day_proof(ws)
    candidates = _glob_relative(ws, _EVM_0DAY_PROOF_CANDIDATES)
    artifact = candidates[0] if candidates else None
    detail = {
        "needed": needed,
        "artifact": str(artifact) if artifact else None,
        "proof_valid": False,
        "proof_states": [],
    }
    if not needed:
        detail["reason"] = "EVM proof pipeline not applicable"
        return detail
    if artifact is None:
        detail["reason"] = "missing EVM 0-day proof artifact"
        return detail
    payload = _read_json(artifact)
    if not isinstance(payload, dict):
        detail["reason"] = "EVM 0-day proof artifact is malformed JSON"
        return detail
    binding_ok, binding_reason = _typed_evm_proof_binding(ws, payload)
    detail["typed_binding"] = binding_reason
    if not binding_ok:
        detail["reason"] = binding_reason
        return detail
    states = {
        _status_token(payload.get("verdict")),
        _status_token(payload.get("status")),
        _status_token(payload.get("result")),
        _status_token(payload.get("final_result")),
        _status_token(payload.get("proof_status")),
        _status_token(payload.get("conversion_verdict")),
    }
    states.discard("")
    detail["proof_states"] = sorted(states)
    if states & _EVM_0DAY_PROOF_PASS_STATES:
        detail["proof_valid"] = True
        detail["reason"] = "EVM 0-day proof artifact is proof-backed"
    elif states & _EVM_0DAY_PROOF_FAIL_STATES:
        detail["reason"] = "EVM 0-day proof artifact is not proof-backed"
    else:
        detail["reason"] = "EVM 0-day proof artifact has no recognized proof-backed verdict"
    return detail


def _artifact_state_for_h3_stage(ws: Path, stage_name: str, rel_paths: list[str]) -> tuple[bool | None, dict]:
    if stage_name == "prove-top-leads":
        state = _prove_top_leads_artifact_state(ws)
        return bool(state["complete"]), state
    if stage_name == "evm-0day-proof":
        state = _evm_0day_proof_artifact_state(ws)
        if not state["needed"]:
            return None, state
        return bool(state["proof_valid"]), state
    return (_stage_artifact_present(ws, rel_paths) if rel_paths else None), {}


def check_strict_hackerman_receipts(ws: Path, *, strict: bool) -> CheckResult:
    """H1 - verify brain-prime, novel-vectors, conversion-loop, queue-closure
    artifacts exist for workspaces with High/Critical drafts or candidates.

    In non-strict mode this is always advisory (WARN-only).
    In STRICT mode it becomes FAIL when H/C drafts exist but the required
    Hackerman receipts are absent.
    """
    has_hc = _ws_has_high_crit_drafts_or_candidates(ws)
    enforce_conversion = _enforce_autonomous_proof_conversion()

    receipt_checks = [
        ("brain-prime-receipt",     list(_BRAIN_PRIME_RECEIPT_CANDIDATES)),
        ("novel-vectors-summary",   list(_NOVEL_VECTORS_CANDIDATES)),
        ("exploit-conversion-loop", list(_EXPLOIT_CONV_LOOP_CANDIDATES)),
    ]
    missing: list[str] = []
    found: list[str] = []
    for label, candidates in receipt_checks:
        p = _first_existing([ws / rel for rel in candidates])
        if p is not None:
            found.append(label)
        else:
            missing.append(label)

    prove_state = _prove_top_leads_artifact_state(ws)
    if prove_state["complete"]:
        found.append("prove-top-leads")
    else:
        missing.append("prove-top-leads")

    evm_state = _evm_0day_proof_artifact_state(ws)
    if evm_state["needed"]:
        if evm_state["proof_valid"]:
            found.append("evm-0day-proof")
        else:
            missing.append("evm-0day-proof")

    missing_hard = [
        label
        for label in missing
        if label not in {
            "exploit-conversion-loop",
            "prove-top-leads",
            "evm-0day-proof",
        } or enforce_conversion
    ]
    missing_advisory = [
        label
        for label in missing
        if label in {
            "exploit-conversion-loop",
            "prove-top-leads",
            "evm-0day-proof",
        } and not enforce_conversion
    ]

    detail = {
        "has_high_crit_drafts_or_candidates": has_hc,
        "strict": strict,
        "enforce_autonomous_proof_conversion": enforce_conversion,
        "found": found,
        "missing": missing,
        "missing_hard": missing_hard,
        "missing_advisory": missing_advisory,
        "prove_top_leads": prove_state,
        "evm_0day_proof": evm_state,
    }

    if not missing:
        return CheckResult(
            check="strict-hackerman-receipts",
            status=PASS,
            reason="brain-prime, novel-vectors, and conversion-loop artifacts present",
            artifacts=[],
            detail=detail,
        )

    summary = f"missing: {', '.join(missing)}"
    if missing_hard and strict and has_hc:
        return CheckResult(
            check="strict-hackerman-receipts",
            status=FAIL,
            reason=(
                f"STRICT=1 + High/Critical candidates: missing hard receipts: "
                f"{', '.join(missing_hard)}. "
                "Run `make brain-prime`, `make audit-deep-novel-vectors`, "
                "and enforced proof-conversion stages before closeout."
            ),
            artifacts=[],
            detail=detail,
        )
    return CheckResult(
        check="strict-hackerman-receipts",
        status=WARN,
        reason=f"Hackerman receipts {summary} (advisory; use STRICT=1 with H/C drafts to gate)",
        artifacts=[],
        detail=detail,
    )


def check_strict_advisory_blockers(ws: Path, *, strict: bool) -> CheckResult:
    """H2 - promote advisory bridge/queue failures to BLOCKERS when STRICT=1
    and High/Critical drafts exist.

    Checks:
    - audit-hacker-logic-bridge result (bridge failure = advisory normally,
      FAIL in STRICT+H/C)
    - exploit-conversion-loop hard_failure_count (advisory normally, FAIL in
      STRICT+H/C when count > 0)
    """
    has_hc = _ws_has_high_crit_drafts_or_candidates(ws)
    enforce_conversion = _enforce_autonomous_proof_conversion()

    advisory_issues: list[str] = []
    strict_blocker_issues: list[str] = []
    detail: dict = {
        "strict": strict,
        "has_high_crit": has_hc,
        "enforce_autonomous_proof_conversion": enforce_conversion,
    }

    # Bridge failure check.
    bridge_path = _first_existing([ws / rel for rel in _AUDIT_HACKER_BRIDGE_CANDIDATES])
    if bridge_path is not None:
        bridge_payload = _read_json(bridge_path)
        if isinstance(bridge_payload, dict):
            bridge_status = str(bridge_payload.get("status") or "").lower()
            if bridge_status in {"fail", "failed", "error"}:
                issue = f"audit-hacker-logic-bridge status={bridge_status}"
                advisory_issues.append(issue)
                strict_blocker_issues.append(issue)
            detail["bridge_status"] = bridge_status
        detail["bridge_path"] = str(bridge_path)
    else:
        detail["bridge_path"] = None

    # Exploit-conversion-loop hard failures.
    loop_path = _first_existing([ws / rel for rel in _EXPLOIT_CONV_LOOP_CANDIDATES])
    if loop_path is not None:
        loop_payload = _read_json(loop_path)
        if isinstance(loop_payload, dict):
            hard_fail_count = loop_payload.get("hard_failure_count")
            if isinstance(hard_fail_count, int) and hard_fail_count > 0:
                issue = f"exploit-conversion-loop hard_failure_count={hard_fail_count}"
                advisory_issues.append(issue)
                if enforce_conversion:
                    strict_blocker_issues.append(issue)
            detail["hard_failure_count"] = hard_fail_count
        detail["loop_path"] = str(loop_path)
    else:
        detail["loop_path"] = None

    prove_state = _prove_top_leads_artifact_state(ws)
    detail["prove_top_leads"] = prove_state
    if enforce_conversion and not prove_state["complete"] and prove_state["weak_candidates"]:
        issue = "prove-top-leads incomplete artifact set"
        advisory_issues.append(issue)
        strict_blocker_issues.append(issue)

    evm_state = _evm_0day_proof_artifact_state(ws)
    detail["evm_0day_proof"] = evm_state
    if evm_state["needed"] and evm_state["artifact"] and not evm_state["proof_valid"]:
        issue = f"evm-0day-proof {evm_state['reason']}"
        advisory_issues.append(issue)
        if enforce_conversion:
            strict_blocker_issues.append(issue)

    if not advisory_issues:
        return CheckResult(
            check="strict-advisory-blockers",
            status=PASS,
            reason="no bridge/queue advisory failures detected",
            artifacts=[],
            detail=detail,
        )

    summary = "; ".join(advisory_issues)
    if strict and has_hc and strict_blocker_issues:
        return CheckResult(
            check="strict-advisory-blockers",
            status=FAIL,
            reason=(
                f"STRICT=1 + High/Critical candidates: hard advisory blockers: "
                f"{'; '.join(strict_blocker_issues)}"
            ),
            artifacts=[],
            detail={
                **detail,
                "issues": advisory_issues,
                "strict_blocker_issues": strict_blocker_issues,
            },
        )
    return CheckResult(
        check="strict-advisory-blockers",
        status=WARN,
        reason=f"advisory bridge/queue issues (use STRICT=1 to gate on H/C): {summary}",
        artifacts=[],
        detail={
            **detail,
            "issues": advisory_issues,
            "strict_blocker_issues": strict_blocker_issues,
        },
    )


def check_full_audit_path(ws: Path, *, strict: bool) -> CheckResult:
    """H3 - verify the full audit pipeline ran or carries typed NO_<STAGE>_REASON
    skips.  In STRICT mode, required stages without skip reasons FAIL.
    """
    has_hc = _ws_has_high_crit_drafts_or_candidates(ws)
    enforce_conversion = _enforce_autonomous_proof_conversion()

    stage_rows: list[dict] = []
    missing_required: list[str] = []

    for (
        stage_name,
        skip_key,
        artifact_rels,
        required_for_hc,
    ) in _H3_STAGES:
        effective_required_for_hc = required_for_hc
        if stage_name in {"exploit-conversion-loop", "prove-top-leads"} and not enforce_conversion:
            effective_required_for_hc = False
        if stage_name == "evm-0day-proof":
            effective_required_for_hc = (
                required_for_hc
                and enforce_conversion
                and _needs_evm_0day_proof(ws)
            )
        artifact_present, artifact_detail = _artifact_state_for_h3_stage(
            ws,
            stage_name,
            artifact_rels,
        )
        skip_reason = _skip_reason_for_stage(ws, skip_key)

        if artifact_present:
            status_label = "ran"
        elif skip_reason:
            status_label = "skipped"
        else:
            status_label = "missing"

        row = {
            "stage": stage_name,
            "status": status_label,
            "artifact_checked": bool(artifact_rels),
            "skip_key": skip_key,
            "skip_reason": skip_reason or None,
            "base_required_for_high_critical": required_for_hc,
            "required_for_high_critical": effective_required_for_hc,
            "artifact_detail": artifact_detail,
        }
        stage_rows.append(row)

        if status_label == "missing" and effective_required_for_hc and has_hc:
            missing_required.append(stage_name)

    detail = {
        "strict": strict,
        "has_high_crit": has_hc,
        "enforce_autonomous_proof_conversion": enforce_conversion,
        "stages": stage_rows,
        "missing_required_stages": missing_required,
    }

    ran_count = sum(1 for r in stage_rows if r["status"] == "ran")
    skipped_count = sum(1 for r in stage_rows if r["status"] == "skipped")
    missing_count = sum(1 for r in stage_rows if r["status"] == "missing")
    # Optional-missing: stages that are missing but NOT in missing_required.
    optional_missing = [
        r["stage"] for r in stage_rows
        if r["status"] == "missing" and r["stage"] not in missing_required
    ]

    # Hard-FAIL path: STRICT + H/C + required stages missing.
    if missing_required and strict and has_hc:
        # Handled by the unconditional return at the bottom of the function.
        pass
    else:
        # No hard-fail.  PASS when all *required* stages are satisfied;
        # advisory WARN when optional stages are missing.
        # (In non-H/C or non-strict mode, missing_required is always empty here.)
        if not missing_required:
            if not optional_missing:
                status_val = PASS
                reason = (
                    f"all {len(_H3_STAGES)} pipeline stages have artifacts or "
                    f"typed skips (ran={ran_count}, skipped={skipped_count})"
                )
            else:
                # Required stages all satisfied; optional gaps are advisory.
                status_val = PASS
                reason = (
                    f"all required pipeline stages satisfied "
                    f"(ran={ran_count}, skipped={skipped_count}); "
                    f"{len(optional_missing)} optional stage(s) missing: "
                    f"{', '.join(optional_missing)}"
                )
        else:
            # missing_required is non-empty but strict+has_hc is False - advisory WARN.
            status_val = WARN
            reason = (
                f"{len(missing_required)} required + {len(optional_missing)} optional "
                f"pipeline stage(s) missing artifacts/skips: "
                f"{', '.join(missing_required + optional_missing)} "
                f"(advisory; STRICT=1 + H/C drafts promotes required stages to FAIL)"
            )
        return CheckResult(
            check="full-audit-path",
            status=status_val,
            reason=reason,
            artifacts=[],
            detail=detail,
        )

    return CheckResult(
        check="full-audit-path",
        status=FAIL,
        reason=(
            f"STRICT=1 + High/Critical candidates: "
            f"{len(missing_required)} required pipeline stage(s) missing "
            f"artifacts and no typed skip: "
            + ", ".join(missing_required)
            + ". Add `NO_<STAGE>_REASON` entries to "
            f"`<ws>/.auditooor/stage_skips.json` or run the missing stages."
        ),
        artifacts=[],
        detail=detail,
    )


def check_learning_gate(ws: Path, *, strict: bool) -> CheckResult:
    """K6 - run agent-learning-gate and surface the result as a closeout row.

    This wraps the existing `agent-learning-gate.py` tool so the closeout
    manifest always includes learning_ledger_path, learning_gate_status, and
    unclassified_artifact_count fields.
    """
    gate_tool = REPO_ROOT / "tools" / "agent-learning-gate.py"
    if not gate_tool.is_file():
        return CheckResult(
            check="learning-gate",
            status=WARN,
            reason="agent-learning-gate.py not found; K6 learning gate skipped",
            artifacts=[],
            detail={"gate_tool": str(gate_tool)},
        )

    cmd = [
        sys.executable,
        str(gate_tool),
        "--workspace",
        str(ws),
        "--json",
    ]
    if strict:
        cmd.append("--strict")

    try:
        proc = subprocess.run(
            cmd,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CheckResult(
            check="learning-gate",
            status=WARN,
            reason=f"agent-learning-gate failed to launch: {exc!r}",
            artifacts=[str(gate_tool)],
            detail={"error": repr(exc)},
        )

    body = proc.stdout.strip()
    payload: dict = {}
    try:
        decoded = json.loads(body) if body else {}
        if isinstance(decoded, dict):
            payload = decoded
    except (json.JSONDecodeError, ValueError):
        payload = {}

    gate_status = payload.get("status", "unknown")
    unclassified = payload.get("unclassified_agent_artifact_count", 0)
    ledger_paths = payload.get("learning_ledger_paths") or []
    ledger_path = ledger_paths[0] if ledger_paths else None
    artifact_count = payload.get("artifact_count", 0)

    detail = {
        "gate_tool": str(gate_tool),
        "strict": strict,
        "learning_gate_status": gate_status,
        "learning_ledger_path": ledger_path,
        "unclassified_artifact_count": unclassified,
        "artifact_count": artifact_count,
        "rc": proc.returncode,
        "blockers": payload.get("blockers", [])[:5],
        "warnings": payload.get("warnings", [])[:5],
    }

    if proc.returncode == 0 or gate_status in {"pass", "warn"}:
        status_val = PASS if gate_status == "pass" else WARN
        reason = (
            f"agent-learning-gate: {gate_status} "
            f"(artifacts={artifact_count}, unclassified={unclassified}, "
            f"ledger={'present' if ledger_path else 'absent'})"
        )
        return CheckResult(
            check="learning-gate",
            status=status_val,
            reason=reason,
            artifacts=[str(gate_tool)],
            detail=detail,
        )

    return CheckResult(
        check="learning-gate",
        status=FAIL,
        reason=(
            f"agent-learning-gate FAIL (rc={proc.returncode}): "
            f"unclassified_artifact_count={unclassified}; "
            f"run `make agent-artifact-mine WS=<ws>` then "
            f"`make agent-learning-compiler WS=<ws>` to classify"
        ),
        artifacts=[str(gate_tool)],
        detail=detail,
    )


# ---- driver ---------------------------------------------------------------


def run_all(
    ws: Path,
    *,
    require_deep: bool,
    require_strict_wiring: bool = False,
    require_replay_executed: bool = False,
    require_pr560_artifacts: bool | None = None,
    replay_cutoff_unix: int | None = None,
    replay_cutoff_parse_error: str | None = None,
    strict: bool = False,
) -> list[CheckResult]:
    return [
        check_canonical_audit(ws),
        check_audit_deep_all(ws, require_deep=require_deep),
        check_pattern_mining(ws),
        check_hypotheses(ws),
        check_agent_synthesize(ws),
        check_mcp_context(ws),
        check_vault_mcp_self_test(ws),
        check_pre_submit(ws),
        check_hacker_question_obligations(ws),
        check_final_paste_hygiene(ws),
        check_poc_execution(ws),
        check_poc_scaffold_ambiguity(ws),
        check_claim_precondition(ws),
        check_detector_environment(ws),
        check_go_dlt_audit_enforcement(ws),
        check_scan_go(ws),
        check_fp_calibration_manifest(REPO_ROOT),
        check_llm_budget(),
        check_p0_followups(ws),
        check_yaml_wave17_consistency(
            REPO_ROOT, require_strict_wiring=require_strict_wiring
        ),
        check_evidence_class(ws),
        check_counterexample_execution(
            ws, require_replay_executed=require_replay_executed
        ),
        check_replay_execution_distinction(
            ws,
            require_replay_executed=require_replay_executed,
            replay_cutoff_unix=replay_cutoff_unix,
            replay_cutoff_parse_error=replay_cutoff_parse_error,
        ),
        check_fixture_duplicates(ws),
        check_invariant_ledger(ws),
        check_program_impact_mapping(ws),
        check_pr560_artifact_closure(
            ws, require_strict=require_pr560_artifacts
        ),
        check_outcome_scoreboard(ws),
        # H1/H2/H3/K6 strict closeout checks.
        check_strict_hackerman_receipts(ws, strict=strict),
        check_strict_advisory_blockers(ws, strict=strict),
        check_full_audit_path(ws, strict=strict),
        check_learning_gate(ws, strict=strict),
    ]


def _format_human(results: Iterable[CheckResult]) -> str:
    results = list(results)
    width = max((len(r.check) for r in results), default=20)
    lines: list[str] = []
    lines.append(f"{'STATUS':<6}  {'CHECK':<{width}}  REASON")
    lines.append(f"{'-' * 6}  {'-' * width}  {'-' * 60}")
    marker = {PASS: "[PASS]", WARN: "[WARN]", FAIL: "[FAIL]"}
    indent = " " * (6 + 2 + width + 2)
    for r in results:
        m = marker[r.status]
        # Wrap reasons longer than 80 chars onto continuation lines that
        # still align under the REASON column.
        reason = r.reason or ""
        lines.append(f"{m:<6}  {r.check:<{width}}  {reason}")
        # P2-3: indent example skip-row hints under the detector-env row
        # so the operator sees the exact failures, not just the summary.
        if r.check == "detector-environment":
            examples = r.detail.get("skip_remediation_examples") or []
            for example in examples:
                lines.append(f"{indent}  - {example}")
        if r.check == "pr560-artifact-closure":
            examples = r.detail.get("next_command_examples") or []
            for example in examples:
                if not isinstance(example, dict):
                    continue
                artifact = example.get("artifact") or "artifact"
                row_id = example.get("id") or "UNKNOWN"
                state = example.get("state") or "unknown"
                command = example.get("next_command") or ""
                if command:
                    lines.append(
                        f"{indent}  - {artifact}:{row_id} [{state}] -> {command}"
                    )
    n_pass = sum(1 for r in results if r.status == PASS)
    n_warn = sum(1 for r in results if r.status == WARN)
    n_fail = sum(1 for r in results if r.status == FAIL)
    lines.append("")
    if n_fail:
        verdict = f"FAIL ({n_fail} hard close-out failure(s))"
    elif n_warn:
        verdict = f"PASS WITH WARNINGS ({n_warn} warning(s))"
    else:
        verdict = "PASS"
    lines.append(f"summary: {n_pass} pass, {n_warn} warn, {n_fail} fail -> {verdict}")
    return "\n".join(lines)


def _detector_environment_manifest_summary(results: Iterable[CheckResult]) -> dict | None:
    for result in results:
        if result.check != "detector-environment":
            continue
        machine_summary = result.detail.get("machine_summary")
        if isinstance(machine_summary, dict):
            # Bolt the human-friendly remediation examples onto the
            # machine summary so downstream automation sees the same
            # rows the operator gets in the human report (P2-3).
            examples = result.detail.get("skip_remediation_examples") or []
            if isinstance(examples, list):
                machine_summary = dict(machine_summary)
                machine_summary["skip_remediation_examples"] = list(examples)
            return machine_summary
    return None


def _fixture_duplicate_manifest_summary(results: Iterable[CheckResult]) -> dict | None:
    """Pull the fixture-duplicate machine_summary block from check results.

    Mirrors ``_detector_environment_manifest_summary`` so the aggregate
    closeout manifest carries an item-#11 summary that downstream tooling
    (track-submissions, dashboards) can read without parsing every check
    row.
    """
    for result in results:
        if result.check != "fixture-duplicates":
            continue
        machine_summary = result.detail.get("machine_summary")
        if isinstance(machine_summary, dict):
            return machine_summary
    return None


def _go_dlt_audit_enforcement_summary(results: Iterable[CheckResult]) -> dict | None:
    for result in results:
        if result.check != "go-dlt-audit-enforcement":
            continue
        machine_summary = result.detail.get("machine_summary")
        if isinstance(machine_summary, dict):
            return machine_summary
    return None


def _learning_gate_manifest_summary(results: list[CheckResult]) -> dict | None:
    """Extract K6 learning-gate fields for the finalization manifest."""
    for result in results:
        if result.check != "learning-gate":
            continue
        d = result.detail
        return {
            "learning_ledger_path": d.get("learning_ledger_path"),
            "learning_gate_status": d.get("learning_gate_status"),
            "unclassified_artifact_count": d.get("unclassified_artifact_count", 0),
            "artifact_count": d.get("artifact_count", 0),
        }
    return None


def _closeout_manifest_payload(
    ws: Path,
    results: list[CheckResult],
    *,
    require_deep: bool,
    require_strict_wiring: bool = False,
    require_replay_executed: bool = False,
    require_pr560_artifacts: bool = False,
    replay_cutoff_unix: int | None = None,
    strict: bool = False,
) -> dict:
    summary = {
        "pass": sum(1 for r in results if r.status == PASS),
        "warn": sum(1 for r in results if r.status == WARN),
        "fail": sum(1 for r in results if r.status == FAIL),
    }
    detector_environment = _detector_environment_manifest_summary(results)
    if detector_environment is not None:
        summary["detector_environment"] = detector_environment
    fixture_duplicate = _fixture_duplicate_manifest_summary(results)
    if fixture_duplicate is not None:
        summary["fixture_duplicate"] = fixture_duplicate
    go_dlt_audit_enforcement = _go_dlt_audit_enforcement_summary(results)
    if go_dlt_audit_enforcement is not None:
        summary["go_dlt_audit_enforcement"] = go_dlt_audit_enforcement
    # K6: include learning-gate fields so finalization manifests surface them.
    learning_gate = _learning_gate_manifest_summary(results)
    if learning_gate is not None:
        summary["learning_gate"] = learning_gate
    payload = {
        "schema": "auditooor.audit_closeout.v1",
        "workspace": str(ws),
        "require_deep": bool(require_deep),
        "require_strict_wiring": bool(require_strict_wiring),
        "require_replay_executed": bool(require_replay_executed),
        "require_pr560_artifacts": bool(require_pr560_artifacts),
        "replay_cutoff_unix": replay_cutoff_unix,
        "strict": bool(strict),
        "checks": [r.to_dict() for r in results],
        "summary": summary,
    }
    return payload


def _write_manifest(
    ws: Path,
    results: list[CheckResult],
    *,
    require_deep: bool,
    require_strict_wiring: bool = False,
    require_replay_executed: bool = False,
    require_pr560_artifacts: bool = False,
    replay_cutoff_unix: int | None = None,
    strict: bool = False,
) -> Path:
    out_dir = ws / ".audit_logs"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "audit_closeout_manifest.json"
    payload = _closeout_manifest_payload(
        ws,
        results,
        require_deep=require_deep,
        require_strict_wiring=require_strict_wiring,
        require_replay_executed=require_replay_executed,
        require_pr560_artifacts=require_pr560_artifacts,
        replay_cutoff_unix=replay_cutoff_unix,
        strict=strict,
    )
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "Close-out gate: verify a real `make audit` run before opening a "
            "submission PR."
        ),
    )
    p.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="Audit workspace root (the `WS=...` argument to `make audit`).",
    )
    p.add_argument(
        "--require-deep",
        action="store_true",
        help=(
            "Promote a missing audit_deep_all_manifest.json to FAIL "
            "(default: WARN)."
        ),
    )
    p.add_argument(
        "--require-strict-wiring",
        action="store_true",
        help=(
            "Promote yaml-wave17-consistency hard mismatches "
            "(missing wave17 .py / missing run_test row) from WARN to "
            "FAIL. Used in repo-level CI to block silent rename drift "
            "(V5-P0-17, foot-gun #14). Also implied by --strict / STRICT=1."
        ),
    )
    p.add_argument(
        "--require-replay-executed",
        action="store_true",
        help=(
            "Promote counterexample-execution WARN to FAIL when any "
            "deep_counterexample.v1 record lacks an execution manifest "
            "(P0-1 burn-down). Equivalent env: REQUIRE_REPLAY_EXECUTED=1."
        ),
    )
    p.add_argument(
        "--require-pr560-artifacts",
        action="store_true",
        help=(
            "Promote the PR560 artifact closeout row from WARN to FAIL when "
            "impact_contracts, harness_tasks, impact_analysis_queue, "
            "source_proof_tasks, source_proofs, corpus_detectorization_inventory, "
            "or known_limitations_burndown "
            f"are missing/unresolved. Equivalent env: {REQUIRE_PR560_ARTIFACTS_ENV}=1 "
            "or STRICT=1."
        ),
    )
    p.add_argument(
        "--replay-after",
        "--cutoff",
        dest="replay_after",
        default=None,
        help=(
            "Cutoff timestamp (unix seconds or ISO-8601) for "
            "replay-execution-distinction. Records older than the cutoff "
            "are treated as legacy backlog and never push the row to "
            "FAIL. Equivalent env: REQUIRE_REPLAY_AFTER=<value>."
        ),
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON aggregate instead of the human-readable table.",
    )
    p.add_argument(
        "--write-manifest",
        action="store_true",
        help=(
            "Write <workspace>/.audit_logs/audit_closeout_manifest.json "
            "alongside the human / JSON output."
        ),
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help=(
            "H1/H2/H3/K6 strict mode: promotes advisory Hackerman-receipt, "
            "bridge/queue-failure, and full-audit-path WARN rows to FAIL when "
            "High/Critical drafts or candidates are present. Equivalent to "
            "STRICT=1 env var. Also enables strict mode for agent-learning-gate."
        ),
    )
    args = p.parse_args(argv)

    # Direct CLI users may pass `~/audits/<project>` — argparse leaves the
    # tilde literal so we expand it here (Kimi review Bug 8). The Makefile
    # front door already expands tilde via `_WS_RESOLVED`.
    ws = args.workspace.expanduser()
    if not ws.exists():
        print(
            f"[audit-closeout-check] error: workspace not found: {ws}",
            file=sys.stderr,
        )
        return 2
    if not ws.is_dir():
        print(
            f"[audit-closeout-check] error: workspace is not a directory: {ws}",
            file=sys.stderr,
        )
        return 2

    # REQUIRE_REPLAY_EXECUTED=1 is the env-var equivalent of the CLI flag
    # (P0-1 burn-down). The flag wins if set; otherwise honour the env.
    env_strict_replay = os.environ.get(REQUIRE_REPLAY_EXECUTED_ENV, "").strip().lower()
    require_replay_executed = bool(args.require_replay_executed) or env_strict_replay in {
        "1",
        "true",
        "yes",
        "on",
    }

    # PR #526 gap 5: --replay-after / REQUIRE_REPLAY_AFTER. CLI wins.
    replay_cutoff_raw = args.replay_after
    if replay_cutoff_raw is None:
        replay_cutoff_raw = os.environ.get(REQUIRE_REPLAY_AFTER_ENV)
    replay_cutoff_unix, replay_cutoff_parse_error = _parse_replay_cutoff(replay_cutoff_raw)
    if replay_cutoff_parse_error:
        print(
            f"[audit-closeout-check] warning: ignoring --replay-after / "
            f"{REQUIRE_REPLAY_AFTER_ENV}: {replay_cutoff_parse_error}",
            file=sys.stderr,
        )

    require_pr560_artifacts = bool(args.require_pr560_artifacts) or _require_pr560_artifacts()

    # H1/H2/H3/K6 strict mode: --strict flag or STRICT=1 env.
    strict = bool(args.strict) or _truthy_env("STRICT")

    require_strict_wiring = bool(args.require_strict_wiring) or strict

    results = run_all(
        ws,
        require_deep=args.require_deep,
        require_strict_wiring=require_strict_wiring,
        require_replay_executed=require_replay_executed,
        require_pr560_artifacts=require_pr560_artifacts,
        replay_cutoff_unix=replay_cutoff_unix,
        replay_cutoff_parse_error=replay_cutoff_parse_error,
        strict=strict,
    )

    if args.write_manifest:
        try:
            manifest_path = _write_manifest(
                ws,
                results,
                require_deep=args.require_deep,
                require_strict_wiring=require_strict_wiring,
                require_replay_executed=require_replay_executed,
                require_pr560_artifacts=require_pr560_artifacts,
                replay_cutoff_unix=replay_cutoff_unix,
                strict=strict,
            )
        except OSError as exc:
            print(
                f"[audit-closeout-check] could not write manifest: {exc}",
                file=sys.stderr,
            )
            return 2
        # Make the manifest path discoverable in both output modes.
        if args.json:
            payload = _closeout_manifest_payload(
                ws,
                results,
                require_deep=args.require_deep,
                require_strict_wiring=require_strict_wiring,
                require_replay_executed=require_replay_executed,
                require_pr560_artifacts=require_pr560_artifacts,
                replay_cutoff_unix=replay_cutoff_unix,
                strict=strict,
            )
            payload["manifest"] = str(manifest_path)
            print(json.dumps(payload, indent=2))
        else:
            print(_format_human(results))
            print(f"\nmanifest: {manifest_path}")
    else:
        if args.json:
            payload = {
                "workspace": str(ws),
                "require_deep": args.require_deep,
                "require_pr560_artifacts": require_pr560_artifacts,
                "strict": strict,
                "checks": [r.to_dict() for r in results],
            }
            print(json.dumps(payload, indent=2))
        else:
            print(_format_human(results))

    return 1 if any(r.status == FAIL for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
