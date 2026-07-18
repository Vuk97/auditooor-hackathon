#!/usr/bin/env python3
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[]
"""G15.1 hunt-coverage gate - enumerate all in-scope source units or log skips.

# G15: this tool emits no corpus record.

A hunt that drills 18/121 concrete contracts (and skips ALL libraries, the
Low/Medium goldmine) is presumed incomplete. This gate computes per-workspace
coverage by reusing the workspace-coverage-heatmap source-unit report:

  - build_coverage_report(ws_path) -> total source units, covered units,
                                      uncovered units, true denominator

An optional skip-log (``<ws>/.auditooor/hunt_coverage_skips.txt``, one
source unit or basename + reason per line) subtracts intentionally-skipped
units before scoring, so a hunt can honestly declare "I skipped these N units
because <reason>" without failing the gate.

When invoked with an audit-run-full run id, the CLI also writes
``<ws>/.auditooor/g15_hunt_coverage_gate_last_result.json`` so status tooling
can surface the exact G15 blocker for that run.

Verdicts:
  pass-coverage-met               - covered/total >= min OR all uncovered
                                    units are skip-logged AND the strict
                                    per-function gate (function-coverage-
                                    completeness.py) agrees (no hollow/untouched)
  fail-strict-function-coverage-disagrees - G15 token-coverage is met but
                                    function-coverage-completeness reports
                                    hollow or untouched functions; token
                                    references alone do not satisfy per-function
                                    attack coverage
  fail-coverage-below-threshold   - unlogged uncovered units remain below
                                    threshold (lists them; flags libraries)
  fail-zero-coverage-denominator   - no source units found; bootstrap or
                                    mirror the target source before claiming
                                    audit-run-full completion
  fail-stale-coverage-denominator  - cached coverage report denominator is stale
  fail-denominator-missing-in-scope-units - live in-scope units are missing
                                    from the reported denominator
  fail-source-unit-only-denominator - function-level source was only counted at
                                    file/source-unit granularity
  fail-skip-without-reason          - a skip-log line names a unit but no reason
  fail-detector-only-not-queued     - detector-hit units were not queued
  fail-queued-not-scanned           - queued units have no scan artifact
  ok-rebuttal                     - bounded g15-rebuttal accepted
  error                           - input / IO error

Exit codes:
  0 - pass / ok-rebuttal (warn-grade fail also exits 0 unless --strict)
  1 - fail-closed verdicts, or fail-coverage-below-threshold AND --strict
  2 - error

Coverage threshold remains WARN-only by default; strict-denominator and queue
integrity failures hard-fail closed.

Anchor: Aztec cold-run drilled 18/121 concrete contracts (~15%), skipped ALL
libraries; this gate would fire fail-coverage-below-threshold listing the
103 uncovered contracts with zero skip-log entries.

Override marker: visible bounded line ``g15-rebuttal: <reason>`` (<=200
chars) OR HTML-comment form ``<!-- g15-rebuttal: <reason> -->``.

Schema: ``auditooor.g15_hunt_coverage_gate.v1``.
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent

SCHEMA_VERSION = "auditooor.g15_hunt_coverage_gate.v1"
GATE = "G15-HUNT-COVERAGE-GATE"
TOOL_REL_PATH = "tools/hunt-coverage-gate.py"

DEFAULT_MIN_COVERAGE = 0.80
DEFAULT_SKIP_LOG_REL = ".auditooor/hunt_coverage_skips.txt"
DEFAULT_LAST_RESULT_REL = ".auditooor/g15_hunt_coverage_gate_last_result.json"
UNHUNTED_SURFACE_SOURCE = "unhunted-surface"

# Per-function sweep manifests that may carry a documented wall-clock budget
# truncation (truncated_by_total_budget). When a sweep stopped early on a budget,
# the units it queued-but-did-not-scan are an INTENTIONAL skip, not a queue bug.
_BUDGET_TRUNCATION_MANIFESTS = (
    ".audit_logs/solidity_per_function_halmos_manifest.json",
    ".auditooor/pre_flight_packs/manifest.json",
)


def _run_budget_truncation(ws_path: Path) -> dict[str, Any] | None:
    """Return a summary of any documented per-function sweep budget truncation in
    this workspace, or None. Used to treat budget-skipped units as skip-logged so
    a bounded sweep does not hard-fail the strict coverage gate."""
    import json as _json
    truncated: list[dict[str, Any]] = []
    for rel in _BUDGET_TRUNCATION_MANIFESTS:
        p = ws_path / rel
        try:
            data = _json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # the flag lives at top level (halmos manifest) or under function_coverage
        # (preflight manifest)
        flag = data.get("truncated_by_total_budget")
        skipped = data.get("skipped_invocation_count")
        cov = data.get("function_coverage")
        if flag is None and isinstance(cov, dict):
            flag = cov.get("truncated_by_total_budget")
            skipped = cov.get("budget_skipped")
        if flag:
            truncated.append(
                {
                    "manifest": rel,
                    "skipped": skipped,
                    "total_budget_seconds": data.get("total_budget_seconds")
                    or (cov.get("total_budget_seconds") if isinstance(cov, dict) else None),
                }
            )
    return {"truncated_sweeps": truncated} if truncated else None
QUEUE_SCANNED_EXEMPT_SOURCES: set[str] = set()
SEED_TOOL_PATH = AUDITOOOR_ROOT / "tools" / "coverage-to-hunt-seed.py"

# Library-ish basenames carry the Low/Medium goldmine; flag them when
# uncovered.
_LIBRARY_HINT_RE = re.compile(
    r"(lib|library|libraries|utils?|helpers?|math|safe)", re.IGNORECASE
)
_FUNCTION_DENOMINATOR_EXTENSIONS = {".sol", ".nr", ".oscript", ".aa"}
REQUIRED_COVERAGE_REPORT_FRESHNESS_FIELDS = (
    "source_freshness",
    "numerator_freshness",
)
_JSON_TOKEN_KEYS = (
    "file", "file_path", "file_path_hint", "path", "source_file", "contract",
    "contract_name", "unit", "target_file", "affected_file",
)
_JSON_FN_KEYS = ("function", "function_name", "fn", "method", "affected_function")
_DETECTOR_TOKEN_FILENAMES = (
    "engage_report.json",
    "coverage_tokens.json",
    "mimo_coverage.json",
    "detector_hits.json",
    "detector_coverage.json",
)
_DETECTOR_TOKEN_GLOBS = ("*detector*.json", "*engage*.json")
_QUEUE_TOKEN_GLOBS = ("exploit_queue.json", "exploit_queue.*.json")
_SCANNED_REVIEW_TOKEN_GLOBS = (
    "*review*.json",
    "*_REVIEW.json",
)
_SCANNED_REVIEW_DIRS = (
    ".auditooor/hunt_findings_sidecars",
    "hunt_findings_sidecars",
    ".auditooor/source_artifacts",
    "source_artifacts",
)
_SOURCE_PATH_HINT_RE = re.compile(
    r"([A-Za-z0-9_./\\-]+\.(?:sol|vy|nr|rs|go|move|cairo|ts|tsx|js|jsx|py|oscript|aa))"
    r"(?::[0-9]+(?:-[0-9]+)?)?"
)
_FUNCTION_DECL_RE = re.compile(
    r"\b(function|constructor)\s*([A-Za-z_][A-Za-z0-9_]*)?\s*\(",
    re.IGNORECASE,
)
_RUN_ID_FIELD_NAMES = (
    "run_id",
    "audit_run_id",
    "audit_run_full_run_id",
    "source_mining_run_id",
)
_RUN_ID_IN_TEXT_RE = re.compile(
    r"(?:^|[\s,;\[\(])(?:run_id|audit_run_id|audit-run-id)\s*[:=]\s*([A-Za-z0-9_.:-]+)"
)

REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*g15[-_ ]rebuttal\s*:\s*(.*?)\s*-->",
    re.IGNORECASE | re.DOTALL,
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?g15[-_ ]rebuttal\s*:\s*(.+?)\s*$",
)
MAX_REBUTTAL_LEN = 200


def _load_heatmap():
    """Import workspace-coverage-heatmap.py by file path (hyphenated name)."""
    path = AUDITOOOR_ROOT / "tools" / "workspace-coverage-heatmap.py"
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_wch", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        return None


_HDP_PROVENANCE_MOD: Any | None = None


def _load_provenance_module():
    """Import tools/hunt-dispatch-provenance-check.py by file path (E4 classifier).

    Reuses that module's ``classify_sidecar_provenance`` +
    ``_ws_dispatch_receipt_tokens`` + ``_sidecar_provenance_strict_enabled`` so
    this gate NEVER rebuilds the synthetic-lead classifier or the token==0 /
    haiku-zero-token trap logic. Cached; returns None on any absence/error so the
    demotion degrades to a no-op (byte-identical to today) rather than crashing
    the coverage gate.
    """
    global _HDP_PROVENANCE_MOD
    if _HDP_PROVENANCE_MOD is not None:
        return _HDP_PROVENANCE_MOD
    path = AUDITOOOR_ROOT / "tools" / "hunt-dispatch-provenance-check.py"
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_hdp_prov_for_cov", path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _HDP_PROVENANCE_MOD = mod
        return mod
    except Exception:
        return None


def _provenance_strict_enabled_for_coverage() -> bool:
    """True iff the E4 per-sidecar provenance gate is ENFORCED (default-ON under
    L37). Reuses the provenance module's own predicate verbatim - the SAME
    ``_sidecar_provenance_strict_enabled()`` semantics already flipped default-ON:
    enforced under AUDITOOOR_L37_STRICT, opt-out via
    AUDITOOOR_SIDECAR_PROVENANCE_STRICT in {0,false,no}. When the predicate cannot
    be loaded, returns False so the demotion is a no-op (byte-parity preserved)."""
    mod = _load_provenance_module()
    if mod is None or not hasattr(mod, "_sidecar_provenance_strict_enabled"):
        return False
    try:
        return bool(mod._sidecar_provenance_strict_enabled())
    except Exception:
        return False


def _synthetic_only_scanned_tokens(
    ws_path: Path, current_run_id: str = ""
) -> tuple[set[str], dict[str, Any]]:
    """Tokens contributed EXCLUSIVELY by E4-flagged synthetic-lead sidecars.

    THE LOAD-BEARING DEMOTION (NUVA 2026-07-03): a hunt_findings_sidecar whose
    ONLY provenance is inline-authoring (duration_s<=0 & started==ended) or a
    self-declared tier-3-synthetic tier - and which has NO spawn_worker dispatch
    receipt - is classified ``synthetic-lead`` by the E4 gate
    (hunt-dispatch-provenance-check.classify_sidecar_provenance). It CLAIMS a
    per-fn hunt but was never really dispatched, so it must NOT satisfy the
    coverage obligation under enforcement. This returns the token set that would
    be credited to coverage SOLELY from such synthetic sidecars, so the caller can
    subtract it and the unit re-enters the residual worker queue.

    NEVER-FALSE-FLAG: a token ALSO emitted by ANY authentic sidecar (real
    duration>0 or a dispatch-receipt link, per the E4 classifier's own
    ``authentic`` verdict) is kept out of the returned set - a unit covered by
    BOTH a synthetic AND a genuine sidecar stays covered. The returned set is
    strictly ``synthetic_tokens - genuine_tokens``.

    ADVISORY-OFF PARITY: when the E4 gate is NOT enforced the caller does not even
    call this (see the gate in ``check``); but this function ALSO returns an empty
    set if the classifier is unavailable, so it can never demote outside strict.
    """
    trace: dict[str, Any] = {
        "enforced": True,
        "synthetic_lead_sidecars": [],
        "synthetic_only_tokens": [],
    }
    mod = _load_provenance_module()
    if mod is None or not hasattr(mod, "classify_sidecar_provenance"):
        trace["enforced"] = False
        trace["reason"] = "E4 classifier unavailable"
        return set(), trace
    try:
        receipt_tokens = mod._ws_dispatch_receipt_tokens(ws_path)
    except Exception:
        receipt_tokens = set()
    # Bounded forward mtime windows of RECEIPT-CONFIRMED hunt dispatch lanes: a
    # sidecar written inside such a window is a genuine dispatched sibling (same
    # batch as the receipt-carrying sidecar that confirmed the window) even with
    # duration_s==0 - the provenance JOIN that stops E4 demoting a real dispatched
    # hunt's coverage. Absent on the module (older checkout) -> [] -> no-op.
    try:
        dispatch_windows = mod._ws_confirmed_dispatch_windows(ws_path)
    except Exception:
        dispatch_windows = []

    synthetic_tokens: set[str] = set()
    genuine_tokens: set[str] = set()
    synthetic_paths: list[str] = []
    for sidecars in (
        ws_path / ".auditooor" / "hunt_findings_sidecars",
        ws_path / "hunt_findings_sidecars",
    ):
        if not sidecars.is_dir():
            continue
        for path in sorted(sidecars.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                data = None
            if not isinstance(data, dict):
                continue
            if current_run_id and not _record_matches_run_id(data, current_run_id):
                continue
            record = _review_token_source_record(path, current_run_id)
            sc_tokens = set(record["tokens"]) if record else set()
            if not sc_tokens:
                continue
            try:
                cls = mod.classify_sidecar_provenance(
                    path, data, receipt_tokens, dispatch_windows)
            except TypeError:
                # older classifier signature (no dispatch_windows param) -> fall back
                cls = mod.classify_sidecar_provenance(path, data, receipt_tokens)
            except Exception:
                cls = {"status": "authentic"}
            if str(cls.get("status")) == "synthetic-lead":
                synthetic_tokens |= sc_tokens
                synthetic_paths.append(str(path))
            else:
                # authentic OR not-coverage-claiming -> its tokens are GENUINE
                # coverage evidence and protect any shared token from demotion.
                genuine_tokens |= sc_tokens

    synthetic_only = synthetic_tokens - genuine_tokens
    trace["synthetic_lead_sidecars"] = sorted(synthetic_paths)
    trace["synthetic_lead_sidecar_count"] = len(synthetic_paths)
    trace["synthetic_only_tokens"] = sorted(synthetic_only)
    trace["synthetic_only_token_count"] = len(synthetic_only)
    return synthetic_only, trace


# ---------------------------------------------------------------------------
# needs-llm-depth-only coverage demotion (NUVA 2026-07-11)
# ---------------------------------------------------------------------------
# auto-coverage-closer writes a per-unit ``coverage_unit_verdict`` (schema
# auditooor.coverage_unit_verdict.v1) of EXACTLY two honest values:
#   * ``mechanical-hunt-no-finding`` - the bounded arsenal ran CLEAN (no question /
#     detector hit / harness / invariant). This is genuine mechanical coverage
#     credit (self-labelled ``coverage_credit=mechanical-source-cited``).
#   * ``needs-llm-depth``           - the arsenal emitted >=1 adversarial hypothesis
#     but proved NO impact mechanically; the closer EXPLICITLY defers the unit to
#     an LLM-depth lane ("requires LLM-depth lane"). This is a hunt OBLIGATION, not
#     a satisfied coverage - crediting it lets the residual drain to empty and
#     make audit-complete STRICT pass WITHOUT the deferred LLM hunt ever running.
# This is the EXACT E4 synthetic-lead problem one layer up: a coverage token whose
# only provenance is a self-declared-incomplete artifact. Mirror the E4 demotion:
# compute the needs-llm-depth-ONLY token set (tokens covered SOLELY by a
# needs-llm-depth verdict, NOT also by a mechanical-hunt-no-finding verdict NOR an
# E4-authentic dispatched hunt sidecar) and subtract it from coverage under strict.
_NEEDS_LLM_DEPTH_VERDICT = "needs-llm-depth"
_MECHANICAL_NO_FINDING_VERDICT = "mechanical-hunt-no-finding"
_COVERAGE_UNIT_VERDICT_SCHEMA = "auditooor.coverage_unit_verdict.v1"


def _needs_llm_depth_strict_enabled_for_coverage() -> bool:
    """True iff the needs-llm-depth-only coverage demotion is ENFORCED (fail-closed).

    Enforcement mirrors the E4 opt-out idiom so non-strict flows stay byte-identical:
      * HARD-ON  when the dedicated env ``AUDITOOOR_NEEDS_LLM_DEPTH_STRICT`` is truthy
        ({1,true,yes,on});
      * HARD-OFF (advisory WARN) when that env is explicitly falsy
        ({0,false,no,off,""});
      * otherwise RIDES the existing L37 / hunt-coverage provenance-strict signal
        (``_provenance_strict_enabled_for_coverage`` - default-ON under
        AUDITOOOR_L37_STRICT) so the normal STRICT audit-run-full pipeline enforces
        it while a parked / non-strict caller demotes nothing.
    """
    raw = os.environ.get("AUDITOOOR_NEEDS_LLM_DEPTH_STRICT")
    if raw is not None:
        v = raw.strip().lower()
        if v in {"1", "true", "yes", "on"}:
            return True
        if v in {"0", "false", "no", "off", ""}:
            return False
    return _provenance_strict_enabled_for_coverage()


def _authentic_hunt_sidecar_tokens(
    ws_path: Path, current_run_id: str = ""
) -> set[str]:
    """Union of review tokens from ``hunt_findings_sidecars`` the E4 provenance
    classifier does NOT flag ``synthetic-lead`` (i.e. authentic: real duration>0 OR
    a dispatch-receipt link, per ``classify_sidecar_provenance``).

    These are GENUINELY-hunted tokens and PROTECT a shared coverage token from the
    needs-llm-depth demotion (never-false-demote). Run-id-AGNOSTIC on purpose: the
    protection must be MAXIMALLY inclusive so a token genuinely hunted in ANY lane
    can never be demoted. Returns an empty set when the classifier is unavailable so
    the demotion degrades safely (mechanical-no-finding verdicts still protect).
    """
    mod = _load_provenance_module()
    tokens: set[str] = set()
    if mod is None or not hasattr(mod, "classify_sidecar_provenance"):
        return tokens
    try:
        receipt_tokens = mod._ws_dispatch_receipt_tokens(ws_path)
    except Exception:
        receipt_tokens = set()
    try:
        dispatch_windows = mod._ws_confirmed_dispatch_windows(ws_path)
    except Exception:
        dispatch_windows = []
    for sidecars in (
        ws_path / ".auditooor" / "hunt_findings_sidecars",
        ws_path / "hunt_findings_sidecars",
    ):
        if not sidecars.is_dir():
            continue
        for path in sorted(sidecars.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                data = None
            if not isinstance(data, dict):
                continue
            record = _review_token_source_record(path, "")
            sc_tokens = set(record["tokens"]) if record else set()
            if not sc_tokens:
                continue
            try:
                cls = mod.classify_sidecar_provenance(
                    path, data, receipt_tokens, dispatch_windows)
            except TypeError:
                cls = mod.classify_sidecar_provenance(path, data, receipt_tokens)
            except Exception:
                cls = {"status": "authentic"}
            if str(cls.get("status")) != "synthetic-lead":
                tokens |= sc_tokens
    return tokens


def _needs_llm_depth_only_scanned_tokens(
    ws_path: Path, current_run_id: str = ""
) -> tuple[set[str], dict[str, Any]]:
    """Tokens whose ONLY coverage provenance is a ``needs-llm-depth`` per-unit
    ``coverage_unit_verdict`` (see the module note above).

    Reads ``<ws>/.auditooor/coverage_unit_verdicts/*.json``. Verdict files are
    persistent per-unit artifacts that legitimately carry ``run_id=null``, so - like
    residual-scope-per-fn's existence check - they are read RUN-ID-AGNOSTIC (a
    needs-llm-depth obligation does not evaporate because a later run has a new id).

    NEVER-FALSE-DEMOTE (mirrors the E4 ``genuine_tokens`` carve-out): a token ALSO
    emitted by (a) a ``mechanical-hunt-no-finding`` verdict for its unit, or (b) an
    E4-authentic dispatched hunt_findings_sidecar, is kept OUT of the returned set.
    The result is strictly
    ``needs_llm_depth_tokens - (mechanical_no_finding_tokens | authentic_hunt_tokens)``.
    """
    trace: dict[str, Any] = {
        "enforced": True,
        "needs_llm_depth_units": [],
        "needs_llm_depth_only_tokens": [],
        "needs_llm_depth_only_units": [],
    }
    vdir = ws_path / ".auditooor" / "coverage_unit_verdicts"
    if not vdir.is_dir():
        trace["enforced"] = False
        trace["reason"] = "no coverage_unit_verdicts dir"
        return set(), trace

    needs_tokens: set[str] = set()
    mechanical_tokens: set[str] = set()
    token_to_units: dict[str, set[str]] = {}
    needs_units: list[str] = []
    for path in sorted(vdir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        if str(data.get("schema") or "") != _COVERAGE_UNIT_VERDICT_SCHEMA:
            continue
        verdict = str(data.get("verdict") or "").strip()
        unit_id = str(data.get("unit_id") or "").strip()
        source_path = str(data.get("source_path") or "").strip()
        if not unit_id:
            continue
        toks: set[str] = set()
        _add_review_unit_token(toks, unit_id, source_path or None)
        if not toks:
            continue
        if verdict == _NEEDS_LLM_DEPTH_VERDICT:
            needs_tokens |= toks
            needs_units.append(unit_id)
            for t in toks:
                token_to_units.setdefault(t, set()).add(unit_id)
        elif verdict == _MECHANICAL_NO_FINDING_VERDICT:
            mechanical_tokens |= toks

    trace["needs_llm_depth_units"] = sorted(set(needs_units))
    trace["needs_llm_depth_unit_count"] = len(set(needs_units))
    if not needs_tokens:
        trace["needs_llm_depth_only_token_count"] = 0
        return set(), trace

    authentic_hunt_tokens = _authentic_hunt_sidecar_tokens(ws_path, current_run_id)
    genuine = mechanical_tokens | authentic_hunt_tokens
    needs_only = needs_tokens - genuine

    demoted_units: set[str] = set()
    for t in needs_only:
        demoted_units |= token_to_units.get(t, set())

    trace["mechanical_no_finding_protected_token_count"] = len(
        needs_tokens & mechanical_tokens
    )
    trace["authentic_hunt_protected_token_count"] = len(
        needs_tokens & authentic_hunt_tokens
    )
    trace["needs_llm_depth_only_tokens"] = sorted(needs_only)
    trace["needs_llm_depth_only_token_count"] = len(needs_only)
    trace["needs_llm_depth_only_units"] = sorted(demoted_units)
    trace["needs_llm_depth_only_unit_count"] = len(demoted_units)
    return needs_only, trace


def needs_llm_depth_only_units(ws_path: Path, current_run_id: str = "") -> set[str]:
    """Public helper: the set of ``unit_id`` strings whose ONLY coverage provenance
    is a needs-llm-depth verdict AND which are demoted under strict.

    Returns an EMPTY set unless the strict demotion is enforced
    (``_needs_llm_depth_strict_enabled_for_coverage``), so a non-strict caller
    (e.g. residual-scope-per-fn under advisory mode) is byte-identical to today.
    Consumed by residual-scope-per-fn.py to re-open the residual for these units.
    """
    if not _needs_llm_depth_strict_enabled_for_coverage():
        return set()
    _toks, trace = _needs_llm_depth_only_scanned_tokens(ws_path, current_run_id)
    return set(trace.get("needs_llm_depth_only_units") or [])


def _load_strict_fn_coverage_module():
    """Load tools/function-coverage-completeness.py if on disk; else None.

    Mirrors the loader in audit-completeness-check.py. Graceful: returns None
    when the tool is absent so G15 degrades to warn-only rather than hard-fail
    on tooling-absence.
    """
    path = AUDITOOOR_ROOT / "tools" / "function-coverage-completeness.py"
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_fcc_g15", path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_fcc_g15"] = mod
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        return None


def _call_strict_fn_coverage_gate(
    mod: Any, ws_path: Path
) -> dict[str, Any] | None:
    """Invoke function-coverage-completeness and return its payload or None.

    Probes entry-points in the order the sibling audit-completeness-check does:
    check_function_coverage -> check -> evaluate.  Returns None on error or
    non-dict result; the caller treats None as 'tooling unavailable'.
    """
    for name in ("check_function_coverage", "check", "evaluate"):
        fn = getattr(mod, name, None)
        if not callable(fn):
            continue
        try:
            result = fn(ws_path)
        except TypeError:
            try:
                result = fn(str(ws_path))
            except Exception:
                return None
        except Exception:
            return None
        if isinstance(result, dict):
            return result
        return None
    return None


def _fcc_real_attack_keys(payload: dict[str, Any] | None) -> set[tuple[str, str]]:
    """Extract (basename_lower, function) keys for every function-coverage record
    classified real-attack with genuine evidence.

    A real-attack classification means function-coverage-completeness recorded a
    terminal per-function attack verdict (finding-attack / mutation-killed /
    finding-clean-trivial / finding-fp-defended evidence) for the unit - i.e. it
    WAS hunted. The hunt-coverage-gate's narrow scan-artifact reader can miss
    these (facade entrypoints like SSVNetwork.sol delegating to a hunted module,
    or clean-trivial getters), producing a serving-join false-red. Crediting only
    real-attack (never hollow/untouched) keeps the exemption never-false-pass.
    """
    keys: set[tuple[str, str]] = set()
    if not isinstance(payload, dict):
        return keys
    for rec in payload.get("functions", []) or []:
        if not isinstance(rec, dict):
            continue
        cls = str(
            rec.get("classification")
            or rec.get("verdict")
            or rec.get("class")
            or ""
        ).lower()
        if cls not in ("real-attack", "real_attack"):
            continue
        fn = rec.get("function") or rec.get("name")
        fileref = rec.get("file") or rec.get("source_ref") or ""
        if not fn or not fileref:
            continue
        ev = rec.get("evidence")
        if isinstance(ev, (list, tuple)) and len(ev) == 0:
            continue  # never-false-pass: a real-attack record must carry evidence
        base = str(fileref).rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
        keys.add((base, str(fn)))
    return keys


def _load_fcc_real_attack_keys(ws_path: Path) -> set[tuple[str, str]]:
    """Load function-coverage-completeness and return its real-attack unit keys.

    Degrades to an empty set (no exemption) on any tooling absence/error so the
    gate never false-passes from a missing or broken fcc backend.
    """
    mod = _load_strict_fn_coverage_module()
    if mod is None:
        return set()
    try:
        payload = _call_strict_fn_coverage_gate(mod, ws_path)
    except Exception:
        return set()
    return _fcc_real_attack_keys(payload)


def _unit_in_fcc_real_attack(unit: str, keys: set[tuple[str, str]]) -> bool:
    """True if a ``file::fn`` unit matches a real-attack (basename, fn) key."""
    if "::" not in unit or not keys:
        return False
    file_part, _, fn_part = unit.partition("::")
    if not fn_part:
        return False
    base = file_part.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    return (base, fn_part) in keys


def _load_fcc_go_entrypoint_keys(ws_path: Path) -> tuple[bool, set[str], set[str]]:
    """Load function-coverage-completeness' Go entry-point surface.

    Returns ``(applied, ep_base_keys, ep_rel_keys)`` where ``applied`` is True ONLY
    when fcc's ``go_entry_surface.applied`` is True (fcc CONFIDENTLY narrowed the
    Cosmos/Go-L1 denominator to true external entry points and excluded the internal
    helpers). ``ep_base_keys`` are ``<basename-lower>::<fn>`` and ``ep_rel_keys`` are
    ``<relpath>::<fn>`` for the enumerated entry-point functions.

    WHY (axelar-dlt 2026-07-12 serving-join): fcc's function-coverage gate excludes
    internal Go helpers from the coverage obligation (a Go ``export`` is a linkage
    property, the Solidity-``internal`` analog; helpers are reached transitively
    through an entry point that carries the obligation). But hunt-coverage-gate's
    ``queued_units_strict`` is drawn from the exploit_queue on the every-exported
    source-unit basis, so it demanded hunting exported-yet-non-entrypoint keeper
    helpers (baseKeeper.CreateChain, ABIInflationGuard.walk) that fcc already treats
    as covered - a permanent ``fail-queued-not-scanned`` false-red the ecdsa-narrowed
    fcc denominator disagreed with (axelar-core: 559 queued -> 445 helpers + 114 real
    entry-point residual). Aligning the hunt obligation with fcc's authoritative
    entry-point surface removes exactly the helpers fcc excludes; the entry points
    (msg-server/ABCI/ante/IBC/genesis) stay obligated.

    Degrades to ``(False, set(), set())`` on any tooling absence/parse error -
    fail-CLOSED on the exemption (no artifact => no exemption => every queued unit
    stays obligated), so the gate never false-passes from a missing/broken fcc file.
    """
    fcc_path = ws_path / ".auditooor" / "function_coverage_completeness.json"
    if not fcc_path.is_file():
        return (False, set(), set())
    try:
        payload = json.loads(fcc_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return (False, set(), set())
    if not isinstance(payload, dict):
        return (False, set(), set())
    ges = payload.get("go_entry_surface")
    if not isinstance(ges, dict) or not ges.get("applied"):
        return (False, set(), set())
    ep_base: set[str] = set()
    ep_rel: set[str] = set()
    for fn in payload.get("functions") or []:
        if not isinstance(fn, dict):
            continue
        name = str(fn.get("name") or "").strip()
        rel = str(fn.get("file") or "").strip()
        if not name or not rel:
            continue
        base = rel.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        ep_base.add(f"{base.lower()}::{name}")
        ep_rel.add(f"{rel}::{name}")
    return (True, ep_base, ep_rel)


def _unit_is_go_nonentrypoint_helper(
    unit: str, ep_base: set[str], ep_rel: set[str]
) -> bool:
    """True iff ``unit`` is a GO ``file::fn`` unit NOT in fcc's enumerated entry-point
    surface - an internal helper fcc excluded from the coverage obligation. Restricted
    to ``.go`` units: fcc's go_entry_surface narrowing is Go-specific, so a Rust/tofn
    helper (k256_serde.rs) absent from the set keeps its own obligation (never exempted
    here). Both the basename::fn and the relpath::fn spelling must be absent from the
    entry-point set for the unit to be treated as a non-entrypoint helper."""
    if "::" not in unit:
        return False
    file_part, _, fn_part = unit.partition("::")
    if not fn_part:
        return False
    if not file_part.lower().endswith(".go"):
        return False
    base = file_part.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    base_key = f"{base.lower()}::{fn_part}"
    return base_key not in ep_base and unit not in ep_rel


# Verdicts from function-coverage-completeness that indicate a genuine
# per-function attack deficit (mirrors _is_function_coverage_fail in
# audit-completeness-check.py).  Absence/tooling verdicts are NOT failures.
_FCC_NON_FAIL_VERDICTS: frozenset[str] = frozenset({
    "error",
    "no-inputs",
    "pass-no-inputs",
    "no-source",
    "pass-no-source",
    "unavailable",
    "ok-rebuttal",
})


def _emit(payload: dict[str, Any], as_json: bool) -> None:
    payload.setdefault("schema", SCHEMA_VERSION)
    payload.setdefault("gate", GATE)
    payload.setdefault("tool", TOOL_REL_PATH)
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        v = payload.get("verdict", "?")
        r = payload.get("reason", "")
        print(f"[{GATE}] verdict={v} reason={r}")


def _resolve_workspace_path(workspace: str) -> str | None:
    direct = Path(workspace).expanduser()
    if direct.exists():
        return str(direct.resolve())
    heatmap = _load_heatmap()
    if heatmap is None:
        return None
    try:
        resolved = heatmap.workspace_to_path(workspace)
    except Exception:
        return None
    if isinstance(resolved, Path):
        return str(resolved.expanduser().resolve())
    return None


def _persist_cli_result(
    payload: dict[str, Any],
    *,
    workspace: str,
    run_id: str = "",
    strict: bool = False,
    min_coverage: float = DEFAULT_MIN_COVERAGE,
) -> dict[str, object]:
    workspace_path = payload.get("workspace_path") or _resolve_workspace_path(workspace)
    if not isinstance(workspace_path, str) or not workspace_path.strip():
        return {"written": False, "reason": "missing_workspace_path"}
    out = Path(workspace_path).expanduser() / DEFAULT_LAST_RESULT_REL
    adhoc_run = False
    if not str(run_id or "").strip():
        # An ad-hoc CLI run (no audit-run-full run id) must NEVER clobber a real
        # run's sidecar - that run-scoped result is what status tooling trusts.
        # But when NO sidecar exists yet, audit-honesty-check reports the
        # workspace HOLLOW with "coverage gate absent ... run make
        # hunt-coverage-gate WS=<ws>" - and that bare remediation command (no
        # RUN_ID) must be able to create the file, else the documented fix can
        # never satisfy the gate. Write-if-absent: synthesize an explicit
        # ad-hoc run id and write ONLY when no real-run sidecar exists; a stale
        # ad-hoc sidecar IS refreshed (re-running the gate must update the
        # measurement) but a real audit-run-full sidecar is preserved untouched.
        # Generic: every workspace whose audit-run-full has not yet stamped a
        # G15 sidecar gets a truthful measurement instead of a false "gate
        # absent".
        if out.exists():
            try:
                prev = json.loads(out.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                prev = {}
            if not prev.get("adhoc_run"):
                return {"written": False, "reason": "missing_run_id"}
        run_id = "cli-adhoc"
        adhoc_run = True
    record = dict(payload)
    record.setdefault("schema", SCHEMA_VERSION)
    record.setdefault("gate", GATE)
    record.setdefault("tool", TOOL_REL_PATH)
    record["generated_at_utc"] = (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    record["run_id"] = run_id
    record["adhoc_run"] = adhoc_run
    record["strict"] = bool(strict)
    record["min_coverage"] = min_coverage
    record["workspace_path"] = str(out.parent.parent)
    record["result_path"] = str(out)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        # This helper is diagnostic. The gate verdict remains authoritative
        # even if the sidecar cannot be written.
        return {"written": False, "path": str(out), "error": str(exc)}
    return {"written": True, "path": str(out)}


def _extract_rebuttal(text: str) -> str | None:
    if not text:
        return None
    m = REBUTTAL_HTML_RE.search(text)
    if not m:
        m = REBUTTAL_LINE_RE.search(text)
    if not m:
        return None
    reason = (m.group(1) or "").strip()
    if not reason or len(reason) > MAX_REBUTTAL_LEN:
        return None
    return reason


def _run_id_from_text(text: str) -> str:
    match = _RUN_ID_IN_TEXT_RE.search(text or "")
    return match.group(1).strip() if match else ""


def _record_run_id(data: Any) -> str:
    if not isinstance(data, dict):
        return ""
    for key in _RUN_ID_FIELD_NAMES:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    meta = data.get("metadata")
    if isinstance(meta, dict):
        for key in _RUN_ID_FIELD_NAMES:
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


def _record_matches_run_id(data: Any, current_run_id: str) -> bool:
    current = str(current_run_id or "").strip()
    if not current:
        return True
    return _record_run_id(data) == current


def _read_skip_log(
    path: Path,
    current_run_id: str = "",
) -> tuple[dict[str, str], list[dict[str, Any]], list[dict[str, Any]]]:
    """Return skip-logged unit tokens and reasons.

    Lines are '<unit-or-basename> [reason]'; blank lines and '#' comments are
    ignored. A basename token such as 'Vault.sol' skips every uncovered unit in
    that file, while 'Vault.sol::withdraw' skips only that source unit.
    """
    reasons: dict[str, str] = {}
    missing_reason: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, OSError):
        return reasons, missing_reason, entries
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        token = parts[0].strip()
        reason = parts[1].strip() if len(parts) > 1 else ""
        reason_run_id = _run_id_from_text(reason)
        run_id_matches_current = (
            not current_run_id or (reason_run_id == current_run_id)
        )
        entry = {
            "line": lineno,
            "token": token,
            "reason": reason,
            "run_id": reason_run_id or None,
            "run_id_matches_current": run_id_matches_current,
        }
        entries.append(entry)
        if not reason:
            missing_reason.append(entry)
            continue
        if current_run_id and not run_id_matches_current:
            continue
        reasons[token] = reason
    return reasons, missing_reason, entries


def _unit_file_key(unit: str) -> str:
    return unit.split("::", 1)[0]


def _unit_basename(unit: str) -> str:
    return Path(_unit_file_key(unit).replace("\\", "/")).name


def _inscope_manifest_basenames(ws_path: Path) -> set[str]:
    """File-basenames of the authoritative in-scope units from
    .auditooor/inscope_units.jsonl (whose emitter honors the SCOPE.md ENUMERATED
    allowlist). Used to prune dir-granularity heatmap over-enumeration (OOS siblings
    of enumerated in-scope files). Empty set -> no manifest -> caller no-ops (preserves
    legacy behavior on a workspace without the manifest)."""
    mf = ws_path / ".auditooor" / "inscope_units.jsonl"
    out: set[str] = set()
    if not mf.is_file():
        return out
    try:
        for ln in mf.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                rec = json.loads(ln)
            except (ValueError, TypeError):
                continue
            f = str(rec.get("file") or "")
            if f:
                out.add(Path(f.replace("\\", "/")).name)
    except OSError:
        return set()
    return out


def _unit_skip_logged(unit: str, skips: set[str]) -> bool:
    return unit in skips or _unit_file_key(unit) in skips or _unit_basename(unit) in skips


def _skip_reason_for_unit(unit: str, skip_reasons: dict[str, str]) -> str | None:
    for key in (unit, _unit_file_key(unit), _unit_basename(unit)):
        if key in skip_reasons:
            return skip_reasons[key]
    return None


def _function_denominator_expected(report: dict[str, Any]) -> bool:
    """Return true when the workspace has source whose denominator should be functions."""
    enum = report.get("enumeration") if isinstance(report, dict) else {}
    languages = enum.get("languages") if isinstance(enum, dict) else {}
    if not isinstance(languages, dict):
        return False
    return any(str(ext) in _FUNCTION_DENOMINATOR_EXTENSIONS for ext in languages)


def _coverage_report_denominator_mismatches(
    cached: dict[str, Any], current: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    mismatches: dict[str, dict[str, Any]] = {}
    source_keys = (
        "source_files_count",
        "source_files_sha256",
        "source_units_count",
        "source_units_sha256",
        "function_denominator_status",
        "full_in_scope_function_denominator",
        "denominator_sha256",
    )
    cached_freshness = cached.get("source_freshness")
    current_freshness = current.get("source_freshness")
    if not isinstance(cached_freshness, dict) or not isinstance(current_freshness, dict):
        mismatches["source_freshness"] = {
            "stored": type(cached_freshness).__name__,
            "recomputed": type(current_freshness).__name__,
        }
        return mismatches
    for key in source_keys:
        if cached_freshness.get(key) != current_freshness.get(key):
            mismatches[f"source_freshness.{key}"] = {
                "stored": cached_freshness.get(key),
                "recomputed": current_freshness.get(key),
            }
    for key in (
        "total_units",
        "function_denominator_status",
        "full_in_scope_function_denominator",
    ):
        if cached.get(key) != current.get(key):
            mismatches[f"coverage_report.{key}"] = {
                "stored": cached.get(key),
                "recomputed": current.get(key),
            }
    return mismatches


def _source_freshness_mismatches(
    cached_freshness: dict[str, Any],
    current_freshness: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    mismatches: dict[str, dict[str, Any]] = {}
    source_keys = (
        "source_files_count",
        "source_files_sha256",
        "source_units_count",
        "source_units_sha256",
        "function_denominator_status",
        "full_in_scope_function_denominator",
        "denominator_sha256",
    )
    for key in source_keys:
        if cached_freshness.get(key) != current_freshness.get(key):
            mismatches[f"source_freshness.{key}"] = {
                "stored": cached_freshness.get(key),
                "recomputed": current_freshness.get(key),
            }
    return mismatches


def _build_current_source_freshness(
    heatmap: Any,
    ws_path: Path,
) -> dict[str, Any] | None:
    build_source_freshness = getattr(heatmap, "build_source_freshness", None)
    if not callable(build_source_freshness):
        return None
    try:
        scope = None
        resolve_scope = getattr(heatmap, "resolve_scope", None)
        if callable(resolve_scope):
            scope = resolve_scope(ws_path)
        enumerate_units = getattr(heatmap, "enumerate_units", None)
        units = None
        enum_detail = None
        if callable(enumerate_units):
            if scope is None:
                units, enum_detail = enumerate_units(ws_path)
            else:
                units, enum_detail = enumerate_units(ws_path, scope=scope)
        denominator_honesty = None
        honesty_builder = getattr(heatmap, "build_function_denominator_honesty", None)
        if callable(honesty_builder) and isinstance(enum_detail, dict):
            denominator_honesty = honesty_builder(enum_detail)
        kwargs: dict[str, Any] = {}
        if scope is not None:
            kwargs["scope"] = scope
        if units is not None:
            kwargs["units"] = units
        if denominator_honesty is not None:
            kwargs["denominator_honesty"] = denominator_honesty
        return build_source_freshness(ws_path, **kwargs)
    except Exception:
        return None


def _coverage_report_has_current_freshness_shape(report: dict[str, Any]) -> bool:
    return all(
        isinstance(report.get(field), dict)
        for field in REQUIRED_COVERAGE_REPORT_FRESHNESS_FIELDS
    )


def _write_current_coverage_report(report: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def _coverage_skip_trace(report: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(report, dict):
        return {
            "skipped_coverage_count": 0,
            "skipped_coverage_reasons": {},
            "skipped_coverage": [],
            "skipped_coverage_truncated": False,
            "skipped_coverage_omitted": 0,
        }
    return {
        "skipped_coverage_count": int(report.get("skipped_coverage_count") or 0),
        "skipped_coverage_reasons": dict(report.get("skipped_coverage_reasons") or {}),
        "skipped_coverage": list(report.get("skipped_coverage") or []),
        "skipped_coverage_truncated": bool(report.get("skipped_coverage_truncated")),
        "skipped_coverage_omitted": int(report.get("skipped_coverage_omitted") or 0),
    }


def _reported_denominator_units(report: dict[str, Any]) -> set[str]:
    for key in ("denominator_units", "source_units", "all_units", "units"):
        raw = report.get(key)
        if isinstance(raw, list):
            return {str(item) for item in raw if str(item)}
    return set()


_GO_ENTRY_MOD: Any | None = None
_GO_ENTRY_MOD_LOADED = False


def _load_go_entrypoint_surface():
    """Import tools/go_entrypoint_surface.py by file path. Cached; returns None
    on any absence/error (fail-open: caller must treat None as "cannot
    classify / cannot narrow", never as "narrow anyway")."""
    global _GO_ENTRY_MOD, _GO_ENTRY_MOD_LOADED
    if _GO_ENTRY_MOD_LOADED:
        return _GO_ENTRY_MOD
    _GO_ENTRY_MOD_LOADED = True
    path = AUDITOOOR_ROOT / "tools" / "go_entrypoint_surface.py"
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_go_entry_for_gate", path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _GO_ENTRY_MOD = mod
    except Exception:
        _GO_ENTRY_MOD = None
    return _GO_ENTRY_MOD


# ---------------------------------------------------------------------------
# JS/Oscript value-moving classifier (single source of truth in
# value-moving-functions.py). Used to exempt genuinely non-value-moving JS units
# (infra/config/CLI/pure-util) from the coverage DENOMINATOR - the JS/Oscript
# analog of the bodyless-interface exemption. Fail-open: a None module or an
# unclassifiable unit is NEVER exempted (kept as value-moving attack surface).
# ---------------------------------------------------------------------------
_VMF_MOD: Any | None = None
_VMF_MOD_LOADED = False


def _load_value_moving_mod():
    """Import tools/value-moving-functions.py by file path (hyphenated name).
    Cached; returns None on any absence/error (fail-open)."""
    global _VMF_MOD, _VMF_MOD_LOADED
    if _VMF_MOD_LOADED:
        return _VMF_MOD
    _VMF_MOD_LOADED = True
    path = AUDITOOOR_ROOT / "tools" / "value-moving-functions.py"
    if not path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_vmf_for_gate", path)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        _VMF_MOD = mod
    except Exception:
        _VMF_MOD = None
    return _VMF_MOD


def _js_nonvaluemoving_denom_enabled() -> bool:
    """Advisory-first gate for the JS/Oscript non-value-moving denominator
    exemption. Default ON; disabled only by a literal 0/false/no. This exemption
    ONLY narrows JavaScript units (Oscript is fail-open value-moving, every other
    language is untouched), so it can never hide non-JS attack surface."""
    return os.environ.get(
        "AUDITOOOR_JS_NONVALUEMOVING_DENOM_EXEMPT", "1"
    ).strip().lower() not in ("0", "false", "no")


def _unit_is_nonvaluemoving_js(ws_path: Path, unit: str) -> bool:
    """True iff ``unit`` is a JavaScript coverage unit that the JS/Oscript
    value-moving classifier (value-moving-functions.py) positively classifies as
    non-value-moving (config / test-CLI / pure-util / pure-infra) AFTER a source
    value-signal veto. Fail-open on every uncertainty:
      * classifier module unavailable -> False (keep).
      * a value/ledger/asset signal in the module SOURCE -> False (keep).
      * anything not positively categorized -> False (keep).
    Only ever returns True for JavaScript (never Solidity/Go/Rust/Oscript), so it
    can never narrow a non-JS denominator."""
    file_part = unit.split("::", 1)[0]
    if not file_part.lower().endswith(".js"):
        return False
    mod = _load_value_moving_mod()
    if mod is None or not hasattr(mod, "js_oscript_unit_value_moving_verdict"):
        return False
    # Resolve the module source so the value-signal veto (anti-rubber-stamp) can
    # run. An unresolved source falls back to the name-based verdict (still
    # fail-open: only positively-categorized infra names are exempt).
    text = _resolve_unit_source(ws_path, file_part)
    try:
        verdict, _reason = mod.js_oscript_unit_value_moving_verdict(file_part, text or None)
    except Exception:
        return False
    return verdict == "non-value-moving"


def _reported_narrowing_applied(report: dict[str, Any]) -> bool:
    """True iff the coverage_report's OWN denominator was actually narrowed by
    Lane D's ``go_cosmos_scope_narrowing`` pass (``enumeration.
    go_cosmos_scope_narrowing.applied is True``). Any other shape (absent
    block, ``applied`` false/missing, non-dict) => False - this is the
    fail-open gate condition #1: the live side is only ever narrowed
    SYMMETRICALLY with an already-narrowed reported side, never ahead of it."""
    enum = report.get("enumeration") if isinstance(report, dict) else None
    if not isinstance(enum, dict):
        return False
    block = enum.get("go_cosmos_scope_narrowing")
    return isinstance(block, dict) and bool(block.get("applied"))


def _apply_live_go_cosmos_narrowing_if_consistent(
    heatmap: Any,
    ws_path: Path,
    report: dict[str, Any],
    units: set[str],
    enum_detail: dict[str, Any],
) -> tuple[set[str], dict[str, Any]]:
    """Narrow the GATE's own live in-scope enumeration with the IDENTICAL
    predicate ``workspace-coverage-heatmap.py``'s ``build_coverage_report``
    already applied to the reported side (Lane
    CAP-HUNT-GATE-NARROWING-CONSISTENT) - both call sites reuse
    ``go_entrypoint_surface.apply_go_cosmos_coverage_scope_narrowing`` (via the
    heatmap module's thin wrapper), so they can never drift apart.

    GUARDED / fail-open (constraint #1 from the lane brief): narrowing is
    applied ONLY when BOTH:
      (a) the coverage_report was ITSELF narrowed
          (``_reported_narrowing_applied(report)`` is True), AND
      (b) the workspace is independently confirmed Cosmos-Go by the SAME
          ``go_entrypoint_surface.is_cosmos_go_workspace`` detector Lane D
          uses (never a new heuristic).
    If either is false, ``units`` is returned UNCHANGED (un-narrowed compare,
    byte-identical to pre-existing behavior) - this is critical for
    STRATA/NUVA and any non-Cosmos-Go workspace. Any exception fails open the
    same way (returns ``units`` unchanged).
    """
    detail: dict[str, Any] = {"applied": False, "reason": "not-evaluated"}
    try:
        if not _reported_narrowing_applied(report):
            detail["reason"] = "reported-side-not-narrowed"
            return units, detail
        go_entry = _load_go_entrypoint_surface()
        if go_entry is None:
            detail["reason"] = "go_entrypoint_surface-unavailable"
            return units, detail
        if not go_entry.is_cosmos_go_workspace(ws_path):
            detail["reason"] = "not-a-cosmos-go-workspace"
            return units, detail
        apply_fn = getattr(heatmap, "apply_go_cosmos_coverage_scope_narrowing", None)
        if not callable(apply_fn):
            detail["reason"] = "heatmap-narrowing-fn-unavailable"
            return units, detail
        narrowed_units, narrow_detail = apply_fn(ws_path, sorted(units))
        if not isinstance(narrow_detail, dict) or not narrow_detail.get("applied"):
            detail["reason"] = (
                (narrow_detail or {}).get("reason", "not-applied")
                if isinstance(narrow_detail, dict)
                else "not-applied"
            )
            return units, detail
        detail = dict(narrow_detail)
        detail["applied"] = True
        return set(narrowed_units), detail
    except Exception as exc:  # pragma: no cover - defensive fail-open
        detail = {"applied": False, "reason": f"error:{exc}"}
        return units, detail


def _live_denominator(
    heatmap: Any,
    ws_path: Path,
    report: dict[str, Any],
) -> tuple[set[str] | None, dict[str, Any], list[dict[str, Any]]]:
    units: set[str] | None = None
    enum_detail: dict[str, Any] = {}
    source_files: list[dict[str, Any]] = []
    try:
        scope = None
        resolve_scope = getattr(heatmap, "resolve_scope", None)
        if callable(resolve_scope):
            scope = resolve_scope(ws_path)
        enumerate_units = getattr(heatmap, "enumerate_units", None)
        if callable(enumerate_units):
            if scope is None:
                raw_units, raw_detail = enumerate_units(ws_path)
            else:
                raw_units, raw_detail = enumerate_units(ws_path, scope=scope)
            units = {str(unit) for unit in raw_units}
            if isinstance(raw_detail, dict):
                enum_detail = raw_detail
            # Scope-bleed guard (strata 2026-06-30): heatmap.enumerate_units resolves
            # scope at DIR granularity, so a SCOPE.md that enumerates SPECIFIC files in
            # an in-scope dir (e.g. only AprPairProvider.sol + ChainlinkAprProviderLib.sol
            # under tranches/oracles/providers/) still admits the dir's OOS siblings
            # (Aave*Provider.sol). The canonical .auditooor/inscope_units.jsonl manifest
            # already honors the enumerated allowlist (its emitter was taught), so it is
            # the authoritative in-scope set. Intersect the denominator by file-basename
            # when the manifest is present + non-empty: this only REMOVES OOS units
            # (never-false-pass - it cannot credit an unhunted in-scope unit), turning a
            # phantom-inflated "372 queued not scanned" into the true in-scope count.
            _inscope = _inscope_manifest_basenames(ws_path)
            if _inscope:
                kept = {u for u in units if _unit_basename(u) in _inscope}
                dropped = len(units) - len(kept)
                if dropped:
                    enum_detail = dict(enum_detail or {})
                    enum_detail["oos_units_pruned_via_inscope_manifest"] = dropped
                    units = kept
            # Lane CAP-HUNT-GATE-NARROWING-CONSISTENT: when the coverage_report's
            # OWN denominator was narrowed by Lane D's go_cosmos_scope_narrowing
            # pass (Cosmos-Go workspaces only), apply the IDENTICAL narrowing
            # predicate to this live enumeration BEFORE the caller compares the
            # two totals - otherwise a narrowed reported_total is false-flagged
            # against an un-narrowed live_total (fail-denominator-missing-in-
            # scope-units false-fail). Fully guarded/fail-open; see
            # ``_apply_live_go_cosmos_narrowing_if_consistent`` docstring.
            units, go_narrow_detail = _apply_live_go_cosmos_narrowing_if_consistent(
                heatmap, ws_path, report, units, enum_detail
            )
            if go_narrow_detail.get("applied"):
                enum_detail = dict(enum_detail or {})
                enum_detail["go_cosmos_scope_narrowing_live"] = go_narrow_detail
        source_file_records = getattr(heatmap, "_source_file_records", None)
        if callable(source_file_records) and scope is not None:
            records = source_file_records(ws_path, scope)
            if isinstance(records, list):
                source_files = [
                    record for record in records if isinstance(record, dict)
                ]
    except Exception:
        units = None
        enum_detail = {}
        source_files = []
    if units is None:
        reported = _reported_denominator_units(report)
        if reported:
            units = reported
    return units, enum_detail, source_files


def _denominator_payload(
    report: dict[str, Any],
    live_units: set[str] | None,
    source_files: list[dict[str, Any]],
) -> dict[str, Any]:
    units = sorted(live_units) if live_units is not None else []
    return {
        "coverage_basis": report.get("coverage_basis") or "source-unit",
        "total_units": len(units) if live_units is not None else int(report.get("total_units") or 0),
        "units": units,
        "source_files_count": len(source_files) if source_files else (
            report.get("source_freshness", {}) or {}
        ).get("source_files_count"),
        "source_files": [
            str(record.get("path") or "")
            for record in source_files
            if record.get("path")
        ],
        "scope_mode": report.get("scope_mode"),
        "scope_globs": report.get("scope_globs") or [],
        "scope_exclude_globs": report.get("scope_exclude_globs") or [],
        "function_denominator_status": report.get("function_denominator_status"),
        "full_in_scope_function_denominator": report.get(
            "full_in_scope_function_denominator"
        ),
        "function_level_extensions": report.get("function_level_extensions") or [],
        "source_unit_extensions": report.get("source_unit_extensions") or [],
        "partial_function_extensions": report.get("partial_function_extensions") or [],
    }


def _normalize_source_ref(raw: str) -> str | None:
    value = str(raw or "").strip().replace("\\", "/")
    if not value or value.upper() in {"NA", "N/A", "NULL"}:
        return None
    value = re.sub(r"(?::[0-9]+(?:-[0-9]+)?)$", "", value)
    while value.startswith("./"):
        value = value[2:]
    value = value.strip("/")
    return value or None


def _source_path_hint(raw: str) -> str | None:
    value = str(raw or "").strip().replace("\\", "/")
    if not value:
        return None
    match = _SOURCE_PATH_HINT_RE.search(value)
    if match:
        return _normalize_source_ref(match.group(1))
    return _normalize_source_ref(value)


def _add_source_tokens(tokens: set[str], raw_ref: str, fn_name: str | None = None) -> None:
    token = _normalize_source_ref(raw_ref)
    if not token:
        return
    base = Path(token).name
    for file_token in {token, base}:
        tokens.add(file_token)
        if fn_name:
            tokens.add(f"{file_token}::{fn_name}")


def _queue_row_tokens(row: dict[str, Any]) -> set[str]:
    tokens: set[str] = set()
    file_refs: list[str] = []
    for key in _JSON_TOKEN_KEYS:
        value = row.get(key)
        if not isinstance(value, str):
            continue
        ref = _normalize_source_ref(value)
        if not ref:
            continue
        file_refs.append(ref)
        _add_source_tokens(tokens, ref)
    for key in _JSON_FN_KEYS:
        value = row.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        fn_name = value.strip().split("(", 1)[0].strip()
        if not fn_name:
            continue
        for ref in file_refs:
            _add_source_tokens(tokens, ref, fn_name)
    return tokens


def _load_seed_tool():
    if not SEED_TOOL_PATH.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_coverage_seed_for_gate", SEED_TOOL_PATH)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        return None


def _run_seed_self_heal(ws_path: Path, run_id: str = "") -> dict[str, Any] | None:
    seed_mod = _load_seed_tool()
    if seed_mod is None or not hasattr(seed_mod, "run"):
        return None
    try:
        result = seed_mod.run(
            ws_path,
            rebuild=True,
            dry_run=False,
            queue_path_override=None,
            run_id=run_id,
        )
        if isinstance(result, dict):
            return result
    except Exception:
        return None
    return None


def _add_review_unit_token(
    tokens: set[str],
    raw_name: Any,
    raw_ref: Any = None,
) -> None:
    name = str(raw_name or "").strip()
    if not name:
        return
    fn_name = ""
    file_hint = name
    if "::" in name:
        file_hint, fn_name = name.split("::", 1)
        fn_name = fn_name.split("(", 1)[0].strip()
        if not fn_name:
            return
    if not file_hint.strip():
        return
    source_refs: list[str] = []
    name_ref = _source_path_hint(file_hint)
    raw_ref_hint = _source_path_hint(str(raw_ref or ""))
    if name_ref and (
        "/" in file_hint
        or "\\" in file_hint
        or "::" in file_hint
        or _SOURCE_PATH_HINT_RE.search(file_hint)
    ):
        source_refs.append(name_ref)
    if raw_ref_hint and raw_ref_hint not in source_refs:
        source_refs.append(raw_ref_hint)
    if not source_refs and name_ref:
        source_refs.append(name_ref)
    if not source_refs:
        return
    for source_ref in source_refs:
        if fn_name:
            _add_source_tokens(tokens, source_ref, fn_name)
        else:
            _add_source_tokens(tokens, source_ref)


def _augment_workspace_relative_tokens(tokens: set[str], ws_path: Path) -> None:
    """Add the workspace-RELATIVE variant of any scanned token that lies under
    the workspace root.

    A per-function hunt sidecar's ``function_anchor.file`` is frequently an
    ABSOLUTE path - agents ``Read`` the real source and cite its absolute path
    (``/Users/.../<ws>/src/x.rs``). ``_normalize_source_ref`` only strips the
    leading ``/``, yielding ``Users/.../<ws>/src/x.rs``, which never matches the
    workspace-RELATIVE denominator unit ``src/x.rs`` (and the bare basename can be
    ambiguous when two dirs share a filename, so basename-collapse cannot rescue
    it). Without this, absolute-path anchors score queued-not-scanned even though
    the unit was genuinely hunted - a serving-join false-red surfaced on
    near-intents 2026-06-26 where 80 genuine wave-A hunt sidecars credited 0
    units. Emitting the relative variant makes an absolute-path anchor credit the
    SAME unit a relative-path anchor would. Additive only (never removes a token),
    so it cannot false-clear a unit that was not actually anchored.
    """
    prefixes: set[str] = set()
    for candidate in (ws_path, ):
        for variant in (str(candidate), ):
            norm = variant.replace("\\", "/").strip("/")
            if norm:
                prefixes.add(norm + "/")
    try:
        resolved = str(ws_path.resolve()).replace("\\", "/").strip("/")
        if resolved:
            prefixes.add(resolved + "/")
    except Exception:
        pass
    if not prefixes:
        return
    add: set[str] = set()
    for tok in tokens:
        file_part, sep, fn_part = tok.partition("::")
        for prefix in prefixes:
            if file_part.startswith(prefix):
                rel = file_part[len(prefix):]
                if not rel:
                    break
                base = Path(rel).name
                add.add(rel)
                add.add(base)
                if sep and fn_part:
                    add.add(f"{rel}::{fn_part}")
                    add.add(f"{base}::{fn_part}")
                break
    tokens.update(add)


def _harvest_json_tokens_fallback(path: Path, tokens: set[str]) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            file_ref = None
            for key in _JSON_TOKEN_KEYS:
                value = obj.get(key)
                if isinstance(value, str):
                    ref = _normalize_source_ref(value)
                    if ref:
                        _add_source_tokens(tokens, ref)
                        file_ref = ref
            for key in _JSON_FN_KEYS:
                value = obj.get(key)
                if isinstance(value, str) and value.strip() and file_ref:
                    fn = value.strip().split("(", 1)[0].strip()
                    if fn:
                        _add_source_tokens(tokens, file_ref, fn)
            for value in obj.values():
                walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)

    walk(data)


def _harvest_json_tokens(heatmap: Any, path: Path, tokens: set[str]) -> None:
    harvester = getattr(heatmap, "_harvest_json_tokens", None)
    if callable(harvester):
        before = set(tokens)
        try:
            harvester(path, tokens)
            if tokens != before:
                return
        except Exception:
            tokens.clear()
            tokens.update(before)
    _harvest_json_tokens_fallback(path, tokens)


def _token_source_record(heatmap: Any, path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    tokens: set[str] = set()
    _harvest_json_tokens(heatmap, path, tokens)
    if not tokens:
        return None
    return {"path": str(path), "tokens": sorted(tokens)}


def _function_name_from_snippet(snippet: Any) -> str | None:
    text = str(snippet or "")
    if not text.strip():
        return None
    match = _FUNCTION_DECL_RE.search(text)
    if not match:
        return None
    kind = match.group(1).lower()
    if kind == "constructor":
        return "constructor"
    name = (match.group(2) or "").strip()
    return name or None


def _clean_function_name(raw: Any) -> str | None:
    name = str(raw or "").strip()
    if not name:
        return None
    lowered = name.lower()
    if lowered in {"?", "na", "n/a", "none", "null", "unknown"}:
        return None
    return name.split("(", 1)[0].split(".", 1)[-1].strip() or None


def _detector_precise_tokens_from_obj(obj: Any, tokens: set[str]) -> None:
    if isinstance(obj, dict):
        file_ref = None
        for key in (
            "file_path",
            "target_file",
            "source_file",
            "source_ref",
            "file",
            "path",
        ):
            value = obj.get(key)
            if isinstance(value, str):
                file_ref = _source_path_hint(value)
                if file_ref:
                    break

        fn_name = None
        for key in ("function", "function_name", "fn", "method", "affected_function"):
            value = obj.get(key)
            if isinstance(value, str):
                fn_name = _clean_function_name(value)
                if fn_name:
                    break
        if not fn_name:
            for key in ("snippet", "code_excerpt", "source_excerpt"):
                fn_name = _function_name_from_snippet(obj.get(key))
                if fn_name:
                    break

        if file_ref and fn_name:
            _add_source_tokens(tokens, file_ref, fn_name)

        for value in obj.values():
            _detector_precise_tokens_from_obj(value, tokens)
    elif isinstance(obj, list):
        for value in obj:
            _detector_precise_tokens_from_obj(value, tokens)


def _detector_token_source_record(heatmap: Any, path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    generic_record = _token_source_record(heatmap, path)
    generic_tokens = set(generic_record["tokens"]) if generic_record else set()
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        data = None

    precise_tokens: set[str] = set()
    _detector_precise_tokens_from_obj(data, precise_tokens)
    if not precise_tokens:
        return generic_record

    precise_files = {token.split("::", 1)[0] for token in precise_tokens if "::" in token}
    precise_basenames = {Path(token).name for token in precise_files}
    filtered_generic = {
        token for token in generic_tokens
        if "::" in token
        or (
            token not in precise_files
            and Path(token).name not in precise_basenames
        )
    }
    tokens = precise_tokens | filtered_generic
    return {"path": str(path), "tokens": sorted(tokens)}


def _review_token_source_record(path: Path, current_run_id: str = "") -> dict[str, Any] | None:
    """Extract exact reviewed source units from local review artifacts.

    These files are source-review evidence, not raw detector output. Only exact
    unit fields count here. Generic citation paths intentionally do not blanket
    cover every function in a cited file.
    """
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if not _record_matches_run_id(data, current_run_id):
        return None

    tokens: set[str] = set()

    target = data.get("target")
    if isinstance(target, dict):
        _add_review_unit_token(
            tokens,
            target.get("name") or target.get("unit") or target.get("source_unit"),
            target.get("source_ref") or target.get("path") or target.get("file"),
        )

    for key in ("reviewed_units", "scanned_units", "covered_units"):
        raw_units = data.get(key)
        if not isinstance(raw_units, list):
            continue
        for raw_unit in raw_units:
            if isinstance(raw_unit, str):
                _add_review_unit_token(tokens, raw_unit)
            elif isinstance(raw_unit, dict):
                _add_review_unit_token(
                    tokens,
                    raw_unit.get("name") or raw_unit.get("unit") or raw_unit.get("source_unit"),
                    raw_unit.get("source_ref") or raw_unit.get("path") or raw_unit.get("file"),
                )

    for citation in data.get("source_citations") or []:
        if isinstance(citation, str):
            _add_review_unit_token(tokens, citation)
            continue
        if not isinstance(citation, dict):
            continue
        _add_review_unit_token(
            tokens,
            citation.get("name") or citation.get("unit") or citation.get("source_unit"),
            citation.get("source_ref") or citation.get("path") or citation.get("file"),
        )

    # r36-rebuttal: lane L37-G15-FUNCTION-ANCHOR-FIX registered in .auditooor/agent_pathspec.json
    # spawn-worker / per-function hunt sidecar schema: an adjudicated
    # ``function_anchor`` {file, function} IS the per-function source-review
    # evidence for that unit (the same schema function-coverage + rubric-coverage
    # consume). Without this branch a detector-flagged unit that WAS genuinely
    # hunted (source-cited FP-defended) is scored detector-only / queued-not-
    # scanned, a false-red. The adjudication signal (top-level OR nested-dict
    # ``result``.applies_to_target / verdict) gates it so a raw un-adjudicated
    # seed does not count. The downstream unit/basename match still gates which
    # unit it covers.
    anchor = data.get("function_anchor")
    if isinstance(anchor, str):
        try:
            anchor = json.loads(anchor)
        except (ValueError, TypeError):
            anchor = None
    if isinstance(anchor, dict):
        afile = str(anchor.get("file") or "").strip()
        afn = str(anchor.get("function") or anchor.get("fn") or "").strip()
        res = data.get("result")
        sig_keys = ("verdict", "disposition", "applies_to_target", "kill_verdict")
        signal = any(str(data.get(k) or "").strip() for k in sig_keys)
        # r36-rebuttal: lane L37-G15-FUNCTION-ANCHOR-FIX registered
        # ``result`` carries the adjudication in EITHER a dict (spawn-worker
        # Sonnet schema) OR a nested JSON string (MIMO/haiku per-fn schema).
        if isinstance(res, dict):
            signal = signal or any(str(res.get(k) or "").strip() for k in sig_keys)
        elif isinstance(res, str) and res.strip():
            try:
                res_obj = json.loads(res)
            except (ValueError, TypeError):
                res_obj = None
            if isinstance(res_obj, dict):
                signal = signal or any(str(res_obj.get(k) or "").strip() for k in sig_keys)
        # r36-rebuttal: lane L37-G15-FUNCTION-ANCHOR-FIX registered
        # Reject the MIMO/haiku placeholder anchor (file='?', fn='?') - it carries
        # no real per-function location and would emit junk '?::?' tokens.
        if afile and afn and afile != "?" and afn != "?" and signal:
            _add_review_unit_token(tokens, f"{afile}::{afn}", afile)

    # Natural hunt-sidecar schema: per-function hunt agents commonly write the
    # anchor at TOP LEVEL ({file, function, line, verdict, ...}) rather than nested
    # under ``function_anchor``. Credit that too - it is the SAME per-function
    # source-review evidence (function-level precise, not file-blanket), gated on
    # an adjudication signal so a raw un-judged row does not count. Without this
    # branch the hunt fan-out's sidecars score queued-not-scanned: a serving-join
    # false-red surfaced on near-intents 2026-06-26, where 265 genuine hunt
    # sidecars ({task_id, file, function, verdict, ...}) credited ~0 units.
    if not tokens:
        tfile = str(
            data.get("file") or data.get("source_ref") or data.get("path") or ""
        ).strip()
        tfn = str(data.get("function") or data.get("fn") or "").strip()
        tfn = tfn.split("(", 1)[0].strip()
        sig_keys = ("verdict", "disposition", "applies_to_target", "kill_verdict")
        top_signal = any(str(data.get(k) or "").strip() for k in sig_keys)
        if tfile and tfn and tfile != "?" and tfn != "?" and top_signal:
            _add_review_unit_token(tokens, f"{tfile}::{tfn}", tfile)

    # Filename-encoded unit fallback: some per-fn disposition agents write a
    # sidecar whose ONLY unit identity is the double-encoded ``result`` string's
    # file_line PLUS the canonical filename slug ``hunt__<file>__<fn>__...`` - with
    # NO ``function_anchor`` and NO top-level file/fn. The batch generator's
    # _sidecar_slug (haiku-fanout-dispatcher) guarantees the slug layout
    # hunt__<file-basename>__<fn>[__<hash>][__L<line>][__I-<impact>], so the unit is
    # recoverable from the filename, gated on an adjudication signal from ``result``
    # (dict OR nested JSON string). Without this branch a genuinely-hunted unit
    # scores queued-not-scanned purely because the agent omitted function_anchor
    # (NUVA residual-80 2026-07-03: 40 real NO dispositions credited 0 units).
    if not tokens:
        res = data.get("result")
        sig_keys = ("verdict", "disposition", "applies_to_target", "kill_verdict")
        fsignal = any(str(data.get(k) or "").strip() for k in sig_keys)
        if isinstance(res, dict):
            fsignal = fsignal or any(str(res.get(k) or "").strip() for k in sig_keys)
        elif isinstance(res, str) and res.strip():
            try:
                _ro = json.loads(res)
            except (ValueError, TypeError):
                _ro = None
            if isinstance(_ro, dict):
                fsignal = fsignal or any(str(_ro.get(k) or "").strip() for k in sig_keys)
        stem = os.path.basename(str(path))
        if fsignal and stem.startswith("hunt__") and stem.endswith(".json"):
            core = stem[len("hunt__"):-len(".json")]
            segs = core.split("__")
            if len(segs) >= 2 and segs[0] and segs[1] and segs[0] != "?" and segs[1] != "?":
                _add_review_unit_token(tokens, f"{segs[0]}::{segs[1]}", segs[0])

    if not tokens:
        return None
    return {"path": str(path), "tokens": sorted(tokens)}


def _collect_detector_tokens(heatmap: Any, ws_path: Path) -> tuple[set[str], list[dict[str, Any]]]:
    audit_dir = ws_path / ".auditooor"
    tokens: set[str] = set()
    records: list[dict[str, Any]] = []
    seen: set[Path] = set()
    if not audit_dir.is_dir():
        return tokens, records
    candidates: list[Path] = [audit_dir / name for name in _DETECTOR_TOKEN_FILENAMES]
    for glob_pat in _DETECTOR_TOKEN_GLOBS:
        candidates.extend(audit_dir.glob(glob_pat))
    for path in sorted(candidates):
        if path in seen or path.name == "coverage_report.json":
            continue
        seen.add(path)
        record = _detector_token_source_record(heatmap, path)
        if record:
            tokens.update(record["tokens"])
            records.append(record)
    return tokens, records


def _collect_queue_tokens(
    heatmap: Any,
    ws_path: Path,
) -> tuple[set[str], set[str], list[dict[str, Any]], list[dict[str, Any]]]:
    audit_dir = ws_path / ".auditooor"
    tokens: set[str] = set()
    strict_tokens: set[str] = set()
    records: list[dict[str, Any]] = []
    exempt_records: list[dict[str, Any]] = []
    seen: set[Path] = set()
    if not audit_dir.is_dir():
        return tokens, strict_tokens, records, exempt_records
    candidates: list[Path] = []
    for glob_pat in _QUEUE_TOKEN_GLOBS:
        candidates.extend(audit_dir.glob(glob_pat))
    for path in sorted(candidates):
        if path in seen:
            continue
        seen.add(path)
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            payload = None
        queue_rows = []
        if isinstance(payload, dict):
            queue = payload.get("queue")
            entries = payload.get("entries")
            if isinstance(queue, list):
                queue_rows.extend([row for row in queue if isinstance(row, dict)])
            if isinstance(entries, list):
                queue_rows.extend([row for row in entries if isinstance(row, dict)])
        if not queue_rows:
            record = _token_source_record(heatmap, path)
            if record:
                tokens.update(record["tokens"])
                strict_tokens.update(record["tokens"])
                records.append(record)
            continue
        file_tokens: set[str] = set()
        file_exempt_tokens: set[str] = set()
        for row in queue_rows:
            row_tokens = _queue_row_tokens(row)
            if not row_tokens:
                continue
            file_tokens.update(row_tokens)
            source = str(row.get("source") or row.get("learning_route") or "").strip().lower()
            if source in QUEUE_SCANNED_EXEMPT_SOURCES:
                file_exempt_tokens.update(row_tokens)
                continue
            strict_tokens.update(row_tokens)
        if file_tokens:
            tokens.update(file_tokens)
            records.append({"path": str(path), "tokens": sorted(file_tokens)})
        if file_exempt_tokens:
            exempt_records.append({"path": str(path), "tokens": sorted(file_exempt_tokens)})
    return tokens, strict_tokens, records, exempt_records


def _collect_scanned_tokens(
    heatmap: Any,
    ws_path: Path,
    current_run_id: str = "",
) -> tuple[set[str], list[dict[str, Any]]]:
    tokens: set[str] = set()
    records: list[dict[str, Any]] = []

    mega_harvester = getattr(heatmap, "_harvest_mega_mimo_anchor_tokens", None)
    if not current_run_id and callable(mega_harvester):
        before = set(tokens)
        try:
            mega_harvester(ws_path.name, tokens, workspace_path=ws_path)
        except Exception:
            tokens = before
        if tokens != before:
            records.append({
                "path": "audit/corpus_tags/derived/mega-or-mimo",
                "tokens": sorted(tokens - before),
            })

    # Workspace-local per-fn hunt sidecar dirs. The two hunt_findings_sidecars dirs
    # are the canonical ones; the mimo_harness_<ws>_workflow / mega_<ws> dirs catch
    # workflow-drill-sidecar-emit.py output when a hunt agent passed --out-base <ws>
    # (its default is DERIVED_ROOT, but agents commonly override to the workspace), so
    # a REAL, correctly function-anchored NEGATIVE hunt lands there. _review_token_
    # source_record credits a genuine ``applies_to_target: "no"`` verdict via its
    # function_anchor - unlike the mega/mimo HEATMAP harvester, which treats "no" as a
    # hallucination signal and skips it, so those clean NEGATIVE entry-point hunts
    # scored queued-not-scanned (axelar-dlt 2026-07-12: 24 axelar-core verdicts credited
    # 0 until read here). Additive + safe: _review_token_source_record only emits a token
    # for a real function_anchor + adjudication signal, and the unit/basename match still
    # gates which residual unit it covers.
    _sidecar_dirs: list[Path] = [
        ws_path / ".auditooor" / "hunt_findings_sidecars",
        ws_path / "hunt_findings_sidecars",
    ]
    for _mimo_glob in ("mimo_harness_*", "mega_*", "mega-*"):
        _sidecar_dirs.extend(
            d for d in sorted(ws_path.glob(_mimo_glob)) if d.is_dir()
        )
    for sidecars in _sidecar_dirs:
        if not sidecars.is_dir():
            continue
        for path in sorted(sidecars.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                data = None
            if current_run_id and not _record_matches_run_id(data, current_run_id):
                continue
            before = set(tokens)
            review_record = _review_token_source_record(path, current_run_id)
            if review_record:
                tokens.update(review_record["tokens"])
            if not current_run_id:
                _harvest_json_tokens(heatmap, path, tokens)
            if tokens != before:
                records.append({"path": str(path), "tokens": sorted(tokens - before)})

    # Source-artifact review evidence can be nested; only explicit reviewed
    # unit schema counts as scanned here. Queue rows alone do not.
    for rel_dir in _SCANNED_REVIEW_DIRS:
        root = ws_path / rel_dir
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.json")):
            review_record = _review_token_source_record(path, current_run_id)
            if not review_record:
                continue
            before = set(tokens)
            tokens.update(review_record["tokens"])
            if tokens != before:
                records.append({"path": str(path), "tokens": sorted(tokens - before)})

    audit_dir = ws_path / ".auditooor"
    if audit_dir.is_dir():
        seen_reviews: set[Path] = set()
        for glob_pat in _SCANNED_REVIEW_TOKEN_GLOBS:
            for path in sorted(audit_dir.glob(glob_pat)):
                if path in seen_reviews:
                    continue
                seen_reviews.add(path)
                record = _review_token_source_record(path, current_run_id)
                if record:
                    tokens.update(record["tokens"])
                    records.append(record)

    if current_run_id:
        _augment_workspace_relative_tokens(tokens, ws_path)
        return tokens, records

    for fn_name in ("_harvest_submission_draft_tokens", "_harvest_agent_artifact_tokens"):
        harvester = getattr(heatmap, fn_name, None)
        if not callable(harvester):
            continue
        before = set(tokens)
        try:
            harvester(ws_path, tokens)
        except Exception:
            tokens = before
            continue
        if tokens != before:
            records.append({"path": fn_name, "tokens": sorted(tokens - before)})

    _augment_workspace_relative_tokens(tokens, ws_path)
    return tokens, records


_NONPUBLIC_FILE_CACHE: dict[str, str] = {}


# Directory markers that disqualify a source match from unit resolution: vendored /
# build / VCS trees, plus TEST trees and TEST CRATES. The latter matters because a
# bare basename (e.g. ``conversions.rs``) can resolve to both a production module and
# a same-named file inside an end-to-end / integration test crate; counting the test
# copy makes the basename look ambiguous and blocks an otherwise-sound exemption
# (near-intents 2026-06-26: near-mpc-crypto-types/conversions.rs is a no-fn module but
# e2e-tests/src/conversions.rs has 4 test fns). Test crates are not in scope, so they
# must not participate in production-source resolution.
_SRC_RESOLVE_SKIP = (
    "/node_modules/", "/.cargo/", "/vendor/", "/build/", "/target/", "/.git/",
    "/tests/", "/test/", "/e2e-tests/", "/e2e/", "/integration-tests/",
    "/integration_tests/", "/it-tests/", "/testing/", "/mock/", "/mocks/",
)


def _resolve_unit_source(ws_path: Path, file_part: str) -> str:
    """Read the source text for a unit's file part (a relpath or bare basename),
    excluding vendored/build/test trees. Cached. '' if not resolvable."""
    key = f"{ws_path}|{file_part}"
    if key in _NONPUBLIC_FILE_CACHE:
        return _NONPUBLIC_FILE_CACHE[key]
    text = ""
    cand = ws_path / file_part
    if not cand.is_file() and "/" not in file_part and "\\" not in file_part:
        skip = _SRC_RESOLVE_SKIP
        for m in (ws_path / "src").rglob(file_part) if (ws_path / "src").is_dir() else []:
            sp = str(m).replace("\\", "/")
            if m.is_file() and not any(s in sp for s in skip):
                cand = m
                break
    if cand.is_file():
        try:
            text = cand.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
    _NONPUBLIC_FILE_CACHE[key] = text
    return text


def _unit_is_nonpublic_internal(ws_path: Path, unit: str) -> bool:
    """True iff the unit's function declaration is source-confirmed NON-public - a
    Solidity `internal`/`private` helper or a Rust non-`pub` fn. Such functions are
    NOT independent unprivileged entrypoints; they are reachable only via their public
    callers, which carry the coverage obligation. Conservative: returns False unless a
    declaration is found AND positively non-public (Cairo/other => never exempt)."""
    if "::" not in unit:
        return False
    file_part, fn = unit.split("::", 1)
    fn = fn.split("(", 1)[0].strip()
    if not fn:
        return False
    text = _resolve_unit_source(ws_path, file_part)
    if not text:
        return False
    base = file_part.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    if base.endswith(".sol"):
        # Solidity decls span multiple lines: `function f(\n  ...\n) internal pure {`.
        # Find the decl start, take the span up to the body-open `{` or `;`, and read
        # the visibility keyword from the WHOLE span (not just the first line).
        m = re.search(rf"\bfunction\s+{re.escape(fn)}\b", text)
        if not m:
            return False
        tail = text[m.start():]
        brace = tail.find("{")
        semi = tail.find(";")
        end = min(x for x in (brace, semi, 4000) if x >= 0)
        span = tail[:end]
        if re.search(r"\b(external|public)\b", span):
            return False
        if re.search(r"\b(internal|private)\b", span):
            return True
        return False
    if base.endswith(".rs"):
        for line in text.splitlines():
            ls = line.strip()
            if re.search(rf"\bfn\s+{re.escape(fn)}\b", ls):
                # pub fn / pub(super) = public surface; bare fn / pub(crate) = internal
                if re.match(r"^pub\s+fn\b", ls) or re.match(r"^pub\s*\(\s*super", ls) \
                        or re.match(r"^pub\s+(unsafe\s+|async\s+)*fn\b", ls):
                    return False
                if "pub(crate)" in ls or "pub (crate)" in ls \
                        or re.match(r"^(unsafe\s+|async\s+)*fn\b", ls):
                    return True
                if ls.startswith("pub"):
                    return False
                return True
    return False


def _unit_is_solidity_interface_decl(ws_path: Path, unit: str) -> bool:
    """True iff the unit is a Solidity function that is a BODYLESS DECLARATION - an
    ``interface`` method or an unimplemented ``abstract`` signature (``function f(...)
    external returns (bool);`` terminated by ``;`` with no ``{ ... }`` body). Such a
    declaration has NO implementation logic in this file to hunt - it is an ABI/linkage
    artifact (the Solidity analog of a forward declaration). For a Cosmos-EVM L1 the
    ``precompiles/<mod>/<Mod>.sol`` files are pure ``interface`` mirrors of the Go
    precompile (e.g. precompiles/bank/Bank.sol = ``interface IBank`` with 0 bodies); the
    real coverage obligation lives on the Go precompile implementation, which carries its
    own queue unit and is hunted. Counting the bodyless mirror decls as queued-not-scanned
    is a PERMANENT false-red (there is nothing to scan). SEI 2026-07-05: 830 such
    ``Bank.sol::send`` interface-mirror decls lingered forever.

    NEVER-FALSE-PASS: exemption is per-function and positive - the function's declaration
    span must reach a ``;`` BEFORE any ``{`` (proving no body). A function with an
    implementation body (``{`` before ``;``) is NEVER exempt; a ``.sol`` contract/library
    with real logic keeps every implemented function's obligation. Only genuinely bodyless
    Solidity declarations are removed."""
    if "::" not in unit:
        return False
    file_part, fn = unit.split("::", 1)
    fn = fn.split("(", 1)[0].strip()
    if not fn:
        return False
    base = file_part.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    if not base.endswith(".sol"):
        return False
    text = _resolve_unit_source(ws_path, file_part)
    if not text:
        return False
    m = re.search(rf"\bfunction\s+{re.escape(fn)}\b", text)
    if not m:
        return False
    tail = text[m.start():]
    brace = tail.find("{")
    semi = tail.find(";")
    if semi < 0:
        return False  # no terminator found -> cannot positively confirm bodyless
    # Bodyless iff a ``;`` closes the signature before any ``{`` body opener.
    return brace < 0 or semi < brace


_LEGACY_VER_RX = re.compile(r"/legacy/v[0-9]+/")


def _extract_fn_body(text: str, fn: str) -> str | None:
    """Return the brace-balanced body of Go/Rust/Sol function ``fn`` in ``text`` (the
    ``{ ... }`` span, inclusive), or None if the function or a balanced body is not
    found. Handles a Go method receiver (``func (r *T) fn(...) ... {``). Used to compare
    a legacy version-snapshot's function against its canonical sibling."""
    m = re.search(r"\bfunc\s+(\([^)]*\)\s*)?" + re.escape(fn) + r"\b", text)
    if not m:
        m = re.search(r"\bfunction\s+" + re.escape(fn) + r"\b", text)
    if not m:
        m = re.search(r"\bfn\s+" + re.escape(fn) + r"\b", text)
    if not m:
        return None
    i = text.find("{", m.start())
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i : j + 1]
    return None


def _unit_is_byte_identical_legacy_copy(
    ws_path: Path, unit: str, scanned_units: set[str]
) -> bool:
    """True iff ``unit`` is a ``.../legacy/v<NNN>/FILE::fn`` version-snapshot whose
    function body is BYTE-IDENTICAL to its canonical (non-legacy) sibling ``.../FILE::fn``
    AND that canonical unit has been SCANNED. A Cosmos-EVM L1 (SEI) ships each precompile
    as ~10 height-gated legacy copies (precompiles/gov/legacy/v6xx/gov.go) for historical
    replay; the agents confirmed most are byte-identical to the live file. A byte-identical
    copy has NO independent bug surface once the canonical is hunted, so counting it as
    queued-not-scanned is dead-weight duplication (SEI: 752 legacy units, ~86% identical).

    NEVER-FALSE-PASS: exemption requires BOTH (a) the canonical unit id is in scanned_units
    (the canonical was actually hunted) AND (b) the function bodies are byte-identical. A
    legacy copy that DIFFERS from canonical (a real historical fix-delta, where version-
    specific bugs live) is NEVER exempt; if the canonical is unscanned or either body is
    unresolvable, NOT exempt. This mirrors the fork-delta-unmodified prune but for intra-
    repo version snapshots."""
    if "::" not in unit or not _LEGACY_VER_RX.search(unit):
        return False
    canonical = _LEGACY_VER_RX.sub("/", unit)
    if canonical == unit or canonical not in scanned_units:
        return False
    file_part, fn = unit.split("::", 1)
    fn = fn.split("(", 1)[0].strip()
    canon_file = _LEGACY_VER_RX.sub("/", file_part)
    if not fn:
        return False
    lf = ws_path / file_part
    cf = ws_path / canon_file
    if not (lf.is_file() and cf.is_file()):
        return False
    try:
        lbody = _extract_fn_body(lf.read_text(encoding="utf-8", errors="replace"), fn)
        cbody = _extract_fn_body(cf.read_text(encoding="utf-8", errors="replace"), fn)
    except OSError:
        return False
    return lbody is not None and lbody == cbody


_FN_DECL_RX = {
    ".rs": re.compile(r"\bfn\s+[A-Za-z_]"),
    ".sol": re.compile(r"\bfunction\s+[A-Za-z_]"),
    ".cairo": re.compile(r"\bfn\s+[A-Za-z_]"),
    ".go": re.compile(r"\bfunc\s+[A-Za-z_(]"),
}


def _resolve_unit_source_files(ws_path: Path, file_part: str) -> list[Path]:
    """Return the non-vendored/build/test source file(s) a unit's file_part resolves
    to. A path-bearing file_part resolves to at most one exact file; a bare basename
    can resolve to MANY (e.g. dozens of ``lib.rs``). Callers that need soundness on an
    ambiguous basename must check ``len(...) == 1`` before trusting a per-file verdict."""
    skip = _SRC_RESOLVE_SKIP
    cand = ws_path / file_part
    if cand.is_file():
        return [cand]
    if "/" in file_part or "\\" in file_part:
        return []
    src = ws_path / "src"
    if not src.is_dir():
        return []
    out: list[Path] = []
    for m in src.rglob(file_part):
        sp = str(m).replace("\\", "/")
        if m.is_file() and not any(s in sp for s in skip):
            out.append(m)
    return out


def _unit_is_no_function_file(ws_path: Path, unit: str) -> bool:
    """True iff a FILE-ONLY queue unit (no ``::``) resolves UNAMBIGUOUSLY to a single
    source file that declares NO function at all - a pure data/const/type module (Rust
    ``pub const`` tables, event/DTO ``struct`` definitions, ``pub use`` re-exports,
    trait-less type aliases). Such a file has no per-function hunt surface; its
    definitions are exercised transitively by the functions that consume them, which
    carry the real coverage obligation. The exploit_queue over-includes these coarse
    file-level tokens (near-intents 2026-06-26: method_names.rs = 73 ``pub const``,
    block_events.rs = 24 event structs, 0 fn each).

    SOUNDNESS: an ambiguous bare basename (e.g. ``lib.rs`` matching dozens of files)
    is NEVER exempted here - resolving it to an arbitrary first match could check the
    wrong file and a sibling match may well have functions. Ambiguous basenames fall
    through to the function-granularity exemption (scanned-token based) or stay queued.
    Only a unit that resolves to EXACTLY ONE file with zero function declarations is
    exempt."""
    if "::" in unit:
        return False
    file_part = unit.strip()
    if not file_part:
        return False
    base = file_part.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
    rx = None
    for ext, pat in _FN_DECL_RX.items():
        if base.endswith(ext):
            rx = pat
            break
    if rx is None:
        return False
    files = _resolve_unit_source_files(ws_path, file_part)
    if len(files) != 1:
        return False  # unresolvable or ambiguous basename -> not safe to exempt here
    try:
        text = files[0].read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if not text:
        return False
    return not rx.search(text)


def _file_only_unit_hunted_at_fn(unit: str, scanned_tokens: set[str]) -> bool:
    """True iff a FILE-ONLY queue unit (no ``::``) was already hunted at FUNCTION
    granularity - i.e. some scanned token ``<X>::<fn>`` shares the unit's file
    identity. A coarse file-level queue token ("look at this file") is satisfied once
    the file's functions were reviewed per-function; per-function COMPLETENESS is
    separately enforced by function-coverage, so this only clears the redundant
    coarse token. Match is relpath-exact for path units and basename-level for bare
    basenames (the coarse token is itself basename-granular, so basename matching is
    consistent with its own precision). near-intents 2026-06-26: foreign-chain
    bitcoin.rs/polygon.rs/etc. were hunted at fn-level (serialize/from) yet their
    coarse file tokens lingered in queued_not_scanned."""
    if "::" in unit:
        return False
    u = unit.strip()
    if not u:
        return False
    u_base = u.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    is_bare = ("/" not in u and "\\" not in u)
    for tok in scanned_tokens:
        if "::" not in tok:
            continue
        file_part = tok.split("::", 1)[0]
        if is_bare:
            if file_part.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] == u_base:
                return True
        else:
            if file_part == u or file_part.rsplit("/", 1)[-1] == u_base and u.endswith(file_part):
                return True
    return False


def _local_bases_with_fn_precise_tokens(tokens: set[str]) -> set[str]:
    return {token.split("::", 1)[0] for token in tokens if "::" in token}


def _local_unique_file_keys_by_basename(units: set[str]) -> dict[str, str]:
    by_base: dict[str, set[str]] = {}
    for unit in units:
        by_base.setdefault(_unit_basename(unit), set()).add(_unit_file_key(unit))
    return {
        base: next(iter(keys))
        for base, keys in by_base.items()
        if len(keys) == 1
    }


def _local_unit_is_covered(
    unit: str,
    tokens: set[str],
    fn_precise_bases: set[str],
    unique_file_keys: dict[str, str],
) -> bool:
    if unit in tokens:
        return True
    file_key = _unit_file_key(unit)
    basename = _unit_basename(unit)
    if "::" in unit:
        _base, _sep, fn = unit.partition("::")
        return unique_file_keys.get(basename) == file_key and f"{basename}::{fn}" in tokens
    return file_key in tokens or (
        unique_file_keys.get(basename) == file_key and basename in tokens
    )


def _units_for_tokens(
    heatmap: Any,
    units: set[str],
    tokens: set[str],
    enum_detail: dict[str, Any],
) -> set[str]:
    if not units or not tokens:
        return set()
    bases_with_fn = getattr(heatmap, "_bases_with_fn_precise_tokens", None)
    unique_by_base = getattr(heatmap, "_unique_file_keys_by_basename", None)
    unit_is_covered = getattr(heatmap, "_unit_is_covered", None)
    if callable(bases_with_fn):
        fn_precise = bases_with_fn(tokens)
    else:
        fn_precise = _local_bases_with_fn_precise_tokens(tokens)
    if callable(unique_by_base):
        unique_file_keys = unique_by_base(
            sorted(units),
            set(enum_detail.get("ambiguous_source_basenames") or []),
        )
    else:
        unique_file_keys = _local_unique_file_keys_by_basename(units)
    out: set[str] = set()
    for unit in units:
        matched = _local_unit_is_covered(unit, tokens, fn_precise, unique_file_keys)
        if not matched and callable(unit_is_covered):
            try:
                matched = unit_is_covered(unit, tokens, fn_precise, unique_file_keys)
            except Exception:
                matched = _local_unit_is_covered(unit, tokens, fn_precise, unique_file_keys)
        if matched:
            out.add(unit)
    return out


def _units_referenced_by_tokens(
    heatmap: Any,
    units: set[str],
    tokens: set[str],
    enum_detail: dict[str, Any],
) -> set[str]:
    """Map detector / queue tokens to denominator units.

    Unlike scanned coverage, detector and queue references are obligations. A
    file-level detector or queue row for a function-denominator file obligates
    every in-scope function in that file, so those units must later be queued or
    scanned precisely.
    """
    out = _units_for_tokens(heatmap, units, tokens, enum_detail)
    fn_precise_files = {token.split("::", 1)[0] for token in tokens if "::" in token}
    fn_precise_basenames = {Path(token).name for token in fn_precise_files}
    file_tokens = {
        token for token in tokens
        if "::" not in token
        and token not in fn_precise_files
        and Path(token).name not in fn_precise_basenames
    }
    if not file_tokens:
        return out
    unique_by_base = getattr(heatmap, "_unique_file_keys_by_basename", None)
    if callable(unique_by_base):
        unique_file_keys = unique_by_base(
            sorted(units),
            set(enum_detail.get("ambiguous_source_basenames") or []),
        )
    else:
        unique_file_keys = _local_unique_file_keys_by_basename(units)
    for unit in units:
        basename = _unit_basename(unit)
        if _unit_file_key(unit) in file_tokens or (
            basename in file_tokens
            and unique_file_keys.get(basename) == _unit_file_key(unit)
        ):
            out.add(unit)
    return out


def check(
    workspace_name: str,
    *,
    min_coverage: float = DEFAULT_MIN_COVERAGE,
    skip_log_path: Path | None = None,
    rebuttal_text: str = "",
    auto_seed_heal: bool = False,
    run_id: str = "",
) -> dict[str, Any]:
    current_run_id = str(run_id or "").strip()
    rebuttal = _extract_rebuttal(rebuttal_text)
    if rebuttal:
        return {
            "verdict": "ok-rebuttal",
            "reason": f"g15-rebuttal accepted: {rebuttal}",
            "exit": 0,
            "workspace": workspace_name,
        }

    heatmap = _load_heatmap()
    if heatmap is None:
        return {
            "verdict": "error",
            "reason": "workspace-coverage-heatmap.py unavailable; cannot enumerate",
            "exit": 2,
        }

    ws_path = heatmap.workspace_to_path(workspace_name)
    report = heatmap.build_coverage_report(ws_path, list_cap=-1)
    coverage_report_path = ws_path / ".auditooor" / "coverage_report.json"
    coverage_report_generated_by_gate = False
    skip_trace = _coverage_skip_trace(report)

    if coverage_report_path.is_file():
        try:
            cached_report = json.loads(coverage_report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return {
                "verdict": "fail-stale-coverage-denominator",
                "reason": f"cached coverage report cannot be read: {exc}",
                "exit": 1,
                "workspace": workspace_name,
                "workspace_path": str(ws_path),
                "coverage_report_path": str(coverage_report_path),
                "coverage_report_exists": True,
                **skip_trace,
            }
        if not isinstance(cached_report, dict):
            return {
                "verdict": "fail-stale-coverage-denominator",
                "reason": "cached coverage report is not a JSON object",
                "exit": 1,
                "workspace": workspace_name,
                "workspace_path": str(ws_path),
                "coverage_report_path": str(coverage_report_path),
                "coverage_report_exists": True,
                **skip_trace,
            }
        if not _coverage_report_has_current_freshness_shape(cached_report):
            if not _coverage_report_has_current_freshness_shape(report):
                return {
                    "verdict": "fail-stale-coverage-denominator",
                    "reason": (
                        "cached coverage report is legacy-shaped and "
                        "recomputed report lacks current freshness fields"
                    ),
                    "exit": 1,
                    "workspace": workspace_name,
                    "workspace_path": str(ws_path),
                    "coverage_basis": "source-unit",
                    "coverage_report_path": str(coverage_report_path),
                    "coverage_report_exists": True,
                    "coverage_report_generated_by_gate": False,
                    **skip_trace,
                }
            try:
                _write_current_coverage_report(report, coverage_report_path)
                coverage_report_generated_by_gate = True
            except OSError as exc:
                return {
                    "verdict": "fail-stale-coverage-denominator",
                    "reason": (
                        "cached coverage report is legacy-shaped but current "
                        f"report could not be written: {exc}"
                    ),
                    "exit": 1,
                    "workspace": workspace_name,
                    "workspace_path": str(ws_path),
                    "coverage_basis": "source-unit",
                    "coverage_report_path": str(coverage_report_path),
                    "coverage_report_exists": True,
                    "coverage_report_generated_by_gate": False,
                    **skip_trace,
                }
        else:
            mismatches = _coverage_report_denominator_mismatches(cached_report, report)
            if mismatches:
                return {
                    "verdict": "fail-stale-coverage-denominator",
                    "reason": "cached coverage report denominator is out of sync with source",
                    "exit": 1,
                    "workspace": workspace_name,
                    "workspace_path": str(ws_path),
                    "coverage_basis": "source-unit",
                    "coverage_report_path": str(coverage_report_path),
                    "coverage_report_exists": True,
                    "coverage_report_generated_by_gate": False,
                    "mismatches": mismatches,
                    **skip_trace,
                }

    live_units, enum_detail, source_files = _live_denominator(heatmap, ws_path, report)
    denominator = _denominator_payload(report, live_units, source_files)
    units = set(report.get("uncovered_units") or [])
    total = int(report.get("total_units") or 0)
    covered_count = int(report.get("covered") or 0)
    uncovered_count = int(report.get("uncovered") or 0)

    if live_units is not None:
        reported_units = _reported_denominator_units(report)
        # Scope-bleed guard (strata 2026-06-30): coverage_report.json is whole-repo
        # (750 units incl OOS Aave*Provider/Midas/Euler), but live_units is now the
        # authoritative in-scope set (135) after the inscope-manifest prune above.
        # Comparing the raw 750 against 135 false-fails on a SUPERSET report. Restrict
        # the reported denominator to in-scope by the same manifest so the match is
        # in-scope-vs-in-scope; a genuine in-scope unit MISSING from the report still
        # surfaces (live - reported_inscope), the never-false-pass property. (The deeper
        # root - coverage_report.json itself being whole-repo - is a producer concern;
        # this consumer-side prune is the safe authoritative fix.)
        _inscope = _inscope_manifest_basenames(ws_path)
        eff_total = total
        if _inscope and reported_units:
            reported_units = {u for u in reported_units if _unit_basename(u) in _inscope}
            eff_total = len(reported_units)
        missing_denominator_units = (
            sorted(live_units - reported_units) if reported_units else []
        )
        extra_reported_units = (
            sorted(reported_units - live_units) if reported_units else []
        )
        if eff_total != len(live_units) or missing_denominator_units or extra_reported_units:
            return {
                "verdict": "fail-denominator-missing-in-scope-units",
                "reason": (
                    "coverage report denominator does not match live in-scope "
                    f"enumeration: reported_total={total}, live_total={len(live_units)}"
                ),
                "exit": 1,
                "workspace": workspace_name,
                "workspace_path": str(ws_path),
                "coverage_basis": "source-unit",
                "reported_total_units": total,
                "live_total_units": len(live_units),
                "missing_denominator_units": missing_denominator_units,
                "extra_reported_units": extra_reported_units,
                "denominator": denominator,
                "denominator_units": denominator["units"],
                "coverage_report_path": str(coverage_report_path),
                "coverage_report_exists": coverage_report_path.is_file(),
                "coverage_report_generated_by_gate": coverage_report_generated_by_gate,
                **skip_trace,
            }

    if total <= 0:
        return {
            "verdict": "fail-zero-coverage-denominator",
            "reason": (
                f"no source units found under {ws_path}; refusing zero denominator "
                "for audit-run-full. Bootstrap or mirror the target source first."
            ),
            "exit": 1,
            "workspace": workspace_name,
            "workspace_path": str(ws_path),
            "coverage_basis": "source-unit",
            "total_contracts": 0,
            "total_units": 0,
            "denominator": denominator,
            "denominator_units": denominator["units"],
            "coverage_report_path": str(coverage_report_path),
            "coverage_report_exists": coverage_report_path.is_file(),
            "coverage_report_generated_by_gate": coverage_report_generated_by_gate,
            **skip_trace,
            "remediation": (
                "This workspace has no enumerable source units. Run the "
                "source/bootstrap path for the target repo, then rerun "
                "audit-run-full after source files are present."
            ),
        }

    denominator_status = str(report.get("function_denominator_status") or "")
    if (
        _function_denominator_expected(report)
        and denominator_status == "source-unit-only"
    ):
        return {
            "verdict": "fail-source-unit-only-denominator",
            "reason": (
                "function-level source is present but coverage denominator is "
                "source-unit-only"
            ),
            "exit": 1,
            "workspace": workspace_name,
            "workspace_path": str(ws_path),
            "coverage_basis": "source-unit",
            "function_denominator_status": denominator_status,
            "full_in_scope_function_denominator": bool(
                report.get("full_in_scope_function_denominator")
            ),
            "function_level_extensions": report.get("function_level_extensions") or [],
            "source_unit_extensions": report.get("source_unit_extensions") or [],
            "total_contracts": total,
            "total_units": total,
            "denominator": denominator,
            "denominator_units": denominator["units"],
            "coverage_report_path": str(coverage_report_path),
            "coverage_report_exists": coverage_report_path.is_file(),
            "coverage_report_generated_by_gate": coverage_report_generated_by_gate,
            **skip_trace,
        }

    # Subtract skip-logged source units. A basename entry skips every source
    # unit in that file for backwards compatibility with old skip logs.
    skip_log_path = skip_log_path or (ws_path / DEFAULT_SKIP_LOG_REL)
    skip_reasons, skip_missing_reason, skip_entries = _read_skip_log(
        skip_log_path,
        current_run_id=current_run_id,
    )
    skips = set(skip_reasons)
    if skip_missing_reason:
        return {
            "verdict": "fail-skip-without-reason",
            "reason": f"{len(skip_missing_reason)} skip-log entries have no reason",
            "exit": 1,
            "workspace": workspace_name,
            "workspace_path": str(ws_path),
            "coverage_basis": "source-unit",
            "total_contracts": total,
            "total_units": total,
            "denominator": denominator,
            "denominator_units": denominator["units"],
            "skip_log_path": str(skip_log_path),
            "skip_log_entries": skip_entries,
            "skip_log_missing_reasons": skip_missing_reason,
            "coverage_report_path": str(coverage_report_path),
            "coverage_report_exists": coverage_report_path.is_file(),
            "coverage_report_generated_by_gate": coverage_report_generated_by_gate,
            **skip_trace,
        }
    skip_logged_uncovered = {u for u in units if _unit_skip_logged(u, skips)}
    unlogged_uncovered = units - skip_logged_uncovered
    skip_logged_reasons = {
        unit: _skip_reason_for_unit(unit, skip_reasons)
        for unit in sorted(skip_logged_uncovered)
    }

    coverage_pct = covered_count / total if total else 1.0

    self_heal: dict[str, Any] = {
        "attempted": False,
        "applied": False,
        "result": {},
    }
    # E4 synthetic-lead demotion (NUVA 2026-07-03): when the per-sidecar
    # provenance gate is ENFORCED (default-ON under L37), a unit whose ONLY
    # covering hunt sidecar is an inline-authored / self-declared-synthetic
    # tier-3 lead with no dispatch receipt is provenance-UNVERIFIED and must NOT
    # be credited as scanned - it re-enters the residual worker queue so a GENUINE
    # hunt is dispatched. Reuses the E4 classifier verbatim (no rebuild). Computed
    # ONCE here (both the pre-heal probe and the final measurement subtract it).
    # NEVER-FALSE-FLAG: a token also emitted by a genuine sidecar is protected.
    # BYTE-PARITY OFF: skipped entirely when the E4 gate is not enforced, so a
    # parked / non-strict caller sees the exact same residual as today.
    _prov_enforced = _provenance_strict_enabled_for_coverage()
    synthetic_only_tokens: set[str] = set()
    synthetic_demotion_trace: dict[str, Any] = {"enforced": _prov_enforced}
    if _prov_enforced:
        synthetic_only_tokens, synthetic_demotion_trace = (
            _synthetic_only_scanned_tokens(ws_path, current_run_id=current_run_id)
        )

    # needs-llm-depth-only demotion (NUVA 2026-07-11): mirrors the E4 block above.
    # A coverage token whose ONLY provenance is a ``needs-llm-depth``
    # coverage_unit_verdict is an UNRESOLVED hunt obligation - it must NOT satisfy
    # coverage, so subtract it from the scanned-token set (both the pre-heal probe
    # and the final measurement) EXACTLY like synthetic_only_tokens. HARD under
    # strict, no-op (byte-parity) otherwise; a token also emitted by a genuine hunt
    # sidecar / mechanical-hunt-no-finding verdict is protected (never-false-demote).
    _needs_llm_enforced = _needs_llm_depth_strict_enabled_for_coverage()
    needs_llm_depth_only_tokens: set[str] = set()
    needs_llm_depth_demotion_trace: dict[str, Any] = {"enforced": _needs_llm_enforced}
    if _needs_llm_enforced:
        needs_llm_depth_only_tokens, needs_llm_depth_demotion_trace = (
            _needs_llm_depth_only_scanned_tokens(
                ws_path, current_run_id=current_run_id)
        )

    denominator_units = live_units or _reported_denominator_units(report)
    preheal_scanned_tokens, _preheal_scanned_sources = _collect_scanned_tokens(
        heatmap, ws_path, current_run_id=current_run_id
    )
    if synthetic_only_tokens:
        preheal_scanned_tokens = preheal_scanned_tokens - synthetic_only_tokens
    if needs_llm_depth_only_tokens:
        preheal_scanned_tokens = preheal_scanned_tokens - needs_llm_depth_only_tokens
    preheal_scanned_units = _units_for_tokens(
        heatmap, denominator_units, preheal_scanned_tokens, enum_detail
    )
    preheal_scanned_uncovered = unlogged_uncovered & preheal_scanned_units
    preheal_effective_covered_count = min(
        total,
        covered_count + len(preheal_scanned_uncovered),
    )
    preheal_effective_coverage_pct = (
        preheal_effective_covered_count / total if total else 1.0
    )

    if auto_seed_heal and preheal_effective_coverage_pct < min_coverage:
        self_heal["attempted"] = True
        heal_result = _run_seed_self_heal(ws_path, run_id=current_run_id)
        if isinstance(heal_result, dict):
            self_heal["result"] = heal_result
            if int(heal_result.get("seed_rows_total") or 0) > 0:
                report = heatmap.build_coverage_report(ws_path, list_cap=-1)
                skip_trace = _coverage_skip_trace(report)
                units = set(report.get("uncovered_units") or [])
                total = int(report.get("total_units") or 0)
                covered_count = int(report.get("covered") or 0)
                uncovered_count = int(report.get("uncovered") or 0)
                coverage_pct = covered_count / total if total else 1.0
                skip_logged_uncovered = {u for u in units if _unit_skip_logged(u, skips)}
                unlogged_uncovered = units - skip_logged_uncovered
                skip_logged_reasons = {
                    unit: _skip_reason_for_unit(unit, skip_reasons)
                    for unit in sorted(skip_logged_uncovered)
                }
                self_heal["applied"] = True

    libraries_uncovered = sorted(
        c for c in unlogged_uncovered if _LIBRARY_HINT_RE.search(c)
    )

    denominator_units = live_units or _reported_denominator_units(report)
    detector_tokens, detector_sources = _collect_detector_tokens(heatmap, ws_path)
    queue_tokens, queue_strict_tokens, queue_sources, queue_exempt_sources = _collect_queue_tokens(
        heatmap, ws_path,
    )
    scanned_tokens, scanned_sources = _collect_scanned_tokens(
        heatmap,
        ws_path,
        current_run_id=current_run_id,
    )
    # E4 synthetic-lead demotion (see above): drop coverage tokens that ONLY a
    # provenance-unverified synthetic sidecar contributed, so those units are NOT
    # marked scanned and RE-ENTER queued_not_scanned (the residual worker queue
    # that residual-scope-per-fn.py reads). No-op unless the E4 gate is enforced.
    if synthetic_only_tokens:
        scanned_tokens = scanned_tokens - synthetic_only_tokens
    # needs-llm-depth-only demotion (see above): drop coverage tokens that ONLY a
    # needs-llm-depth verdict contributed, so those units are NOT marked scanned and
    # RE-ENTER the residual worker queue. No-op unless strict-enforced.
    if needs_llm_depth_only_tokens:
        scanned_tokens = scanned_tokens - needs_llm_depth_only_tokens
    detector_units = _units_referenced_by_tokens(
        heatmap, denominator_units, detector_tokens, enum_detail
    )
    queue_units = _units_referenced_by_tokens(
        heatmap, denominator_units, queue_tokens, enum_detail
    )
    queue_units_strict = _units_referenced_by_tokens(
        heatmap, denominator_units, queue_strict_tokens, enum_detail
    )
    scanned_units = _units_for_tokens(
        heatmap, denominator_units, scanned_tokens, enum_detail
    )
    skip_logged_units = {
        unit for unit in denominator_units
        if _unit_skip_logged(unit, skips)
    }
    # Budget-truncation tolerance (G9-honest): when this run's per-function sweeps
    # stopped early on a DOCUMENTED wall-clock budget (truncated_by_total_budget),
    # the queued-but-not-scanned units are the intentionally-skipped tail, not a
    # queue-integrity bug. Treat them as skip-logged (reason: budget-truncated) so
    # the strict coverage gate records the partial honestly and the run completes.
    # A real integrity drop (queued-not-scanned with NO budget truncation) still
    # hard-fails because budget_skipped_units stays empty.
    budget_truncation = _run_budget_truncation(ws_path)
    budget_skipped_units: set[str] = set()
    if budget_truncation:
        budget_skipped_units = queue_units_strict - scanned_units - skip_logged_units
        skip_logged_units = skip_logged_units | budget_skipped_units
    review_scanned_uncovered = unlogged_uncovered & scanned_units
    effective_unlogged_uncovered = (
        unlogged_uncovered - review_scanned_uncovered - budget_skipped_units
    )
    # Bodyless Solidity interface/abstract declarations that were NEVER queued land in
    # unlogged_uncovered (not queued_not_scanned), so the queued-not-scanned interface
    # exemption above never reaches them - they permanently drag the coverage FRACTION
    # down (Strata 2026-07-07: 97/100 unlogged-uncovered were IAccounting/IAprPairFeed/
    # ICooldown interface method decls, pinning the gate at 78.72% forever). An interface
    # method has NO body to hunt; counting it in the coverage denominator is the same
    # permanent false-red the SEI queued-not-scanned exemption fixed, just on the fraction
    # side. Positively bodyless-only via _unit_is_solidity_interface_decl (an implemented
    # function has `{` before `;` and is NEVER exempt) -> never-false-pass; the denominator
    # only sheds ABI/linkage artifacts, never a real implementation obligation.
    denom_interface_exempt = {
        u for u in effective_unlogged_uncovered
        if _unit_is_solidity_interface_decl(ws_path, u)
    }
    if denom_interface_exempt:
        effective_unlogged_uncovered = effective_unlogged_uncovered - denom_interface_exempt
        total = max(0, total - len(denom_interface_exempt))
    # JS/Oscript non-value-moving denominator exemption (Obyte 2026-07-09): a
    # JS/Oscript workspace enumerates FILE-level units, and the coverage
    # denominator counted genuinely non-value-moving infra (ocore bots.js/
    # breadcrumbs.js/profiler.js/event_bus.js), pure string/int helpers
    # (int2str/errorToString/opRender), and config/CLI tooling (.eslintrc.js,
    # truffle-config.js, find-nonce.js, deploy-*.js) - inflating the denominator
    # exactly like the Solidity bodyless-interface case (Obyte: 391 total, pinned
    # at ~56%). The value-moving-functions.py JS/Oscript classifier (single
    # source of truth) exempts ONLY units it positively classifies non-value-
    # moving AFTER a source value-signal veto; a payment/balance/output/mint/burn
    # /consensus module is NEVER exempted (never hides attack surface). Only
    # JavaScript is narrowed; Oscript is fail-open value-moving and every other
    # language is byte-identical. Advisory-first (env-gated, default ON). Mirrors
    # the interface-exempt path: shed from the fraction denominator, not deleted.
    nonvaluemoving_js_exempt: set[str] = set()
    if _js_nonvaluemoving_denom_enabled():
        nonvaluemoving_js_exempt = {
            u for u in effective_unlogged_uncovered
            if _unit_is_nonvaluemoving_js(ws_path, u)
        }
        if nonvaluemoving_js_exempt:
            effective_unlogged_uncovered = (
                effective_unlogged_uncovered - nonvaluemoving_js_exempt
            )
            total = max(0, total - len(nonvaluemoving_js_exempt))
    effective_covered_count = min(total, covered_count + len(review_scanned_uncovered))
    effective_coverage_pct = effective_covered_count / total if total else 1.0
    effective_uncovered_count = max(0, total - effective_covered_count)
    effective_libraries_uncovered = sorted(
        c for c in effective_unlogged_uncovered if _LIBRARY_HINT_RE.search(c)
    )
    detector_only_not_queued = (
        detector_units - queue_units - scanned_units - skip_logged_units
    )
    queued_not_scanned = queue_units_strict - scanned_units - skip_logged_units
    # Non-entrypoint exemption: queue_units_strict (from exploit_queue) can include
    # internal/private helper functions - e.g. a Solidity `library`'s `internal pure`
    # encoders (Borsh.sol::encodeAddress) - that are NOT independent unprivileged
    # entrypoints. They are reachable only through their public callers, which carry
    # the real coverage obligation and are hunted (their hunt examines the internal
    # logic invoked). Source-confirmed non-public functions are therefore covered
    # transitively; counting them as queued-not-scanned is a permanent false-red
    # (near-intents 2026-06-26). Conservative: only exempt declarations positively
    # confirmed internal/private in source (Cairo/unknown are never exempted).
    non_entrypoint_exempt = {
        u for u in queued_not_scanned if _unit_is_nonpublic_internal(ws_path, u)
    }
    if non_entrypoint_exempt:
        queued_not_scanned = queued_not_scanned - non_entrypoint_exempt
    # Solidity interface/abstract bodyless-declaration exemption (SEI 2026-07-05): a
    # Cosmos-EVM L1 ships ``precompiles/<mod>/<Mod>.sol`` ABI mirrors that are pure
    # ``interface`` declarations (0 function bodies) of the Go precompile. The Go impl
    # carries the real hunt obligation; the bodyless mirror decls have nothing to scan
    # and lingered as a permanent false-red (830 ``Bank.sol::send`` etc.). Only positively
    # bodyless Solidity declarations are exempt (implemented functions stay obligated).
    sol_interface_exempt = {
        u for u in queued_not_scanned if _unit_is_solidity_interface_decl(ws_path, u)
    }
    if sol_interface_exempt:
        queued_not_scanned = queued_not_scanned - sol_interface_exempt
    # Byte-identical legacy version-snapshot exemption (SEI 2026-07-05): a Cosmos-EVM L1
    # ships ~10 height-gated legacy copies of each precompile (precompiles/gov/legacy/
    # v6xx/gov.go) for historical replay. A legacy copy whose function body is byte-
    # identical to its SCANNED canonical sibling has no independent bug surface - counting
    # it as queued-not-scanned is dead-weight duplication (SEI: 752 legacy units, ~86%
    # identical). Only exempt when the canonical is scanned AND the bodies match exactly;
    # a differing legacy copy (real version-delta) stays queued.
    legacy_identical_exempt = {
        u for u in queued_not_scanned
        if _unit_is_byte_identical_legacy_copy(ws_path, u, scanned_units)
    }
    if legacy_identical_exempt:
        queued_not_scanned = queued_not_scanned - legacy_identical_exempt
    # File-only queue over-inclusion exemption: the exploit_queue can carry coarse
    # FILE-LEVEL tokens (a bare ``adapters.rs`` / ``lib.rs`` with no ``::fn``) that are
    # NOT per-function hunt obligations. Two source-confirmed sub-classes are exempt:
    #   (a) no-function modules - pure data/const/type files (no per-fn surface; their
    #       definitions are exercised transitively by the functions that consume them);
    #   (b) files already hunted at function granularity - some ``<file>::<fn>`` token
    #       is in scanned_units, so the coarse "look at this file" token is redundant
    #       (per-function COMPLETENESS stays enforced separately by function-coverage).
    # near-intents 2026-06-26: 56 no-fn data modules + foreign-chain files hunted at
    # fn-level lingered as a permanent false-red. Conservative: only file-only units;
    # never touches a ``file::fn`` unit (those keep their own obligation).
    file_only_nofn_exempt = {
        u for u in queued_not_scanned
        if "::" not in u and _unit_is_no_function_file(ws_path, u)
    }
    if file_only_nofn_exempt:
        queued_not_scanned = queued_not_scanned - file_only_nofn_exempt
    file_only_hunted_exempt = {
        u for u in queued_not_scanned
        if "::" not in u and _file_only_unit_hunted_at_fn(u, scanned_tokens)
    }
    if file_only_hunted_exempt:
        queued_not_scanned = queued_not_scanned - file_only_hunted_exempt
    # Serving-join exemption (SSV 2026-06-26): function-coverage-completeness can
    # classify a queued unit as real-attack (evidence: finding-attack / mutation-
    # killed / finding-clean-trivial / finding-fp-defended) while this gate's
    # narrow scan-artifact reader misses it - e.g. SSVNetwork.sol/SSVNetworkViews
    # facade entrypoints that delegate to a hunted module, or clean-trivial
    # getters. A real-attack verdict IS a completed per-function hunt, so the unit
    # IS covered; the two coverage gates were disagreeing (function-coverage
    # 217/217 fully-covered vs hunt-coverage 112 queued-not-scanned). Only
    # real-attack is credited (hollow/untouched stay flagged) -> never-false-pass.
    # Loaded lazily, only when units would otherwise fail, so the pass path takes
    # no perf hit.
    fcc_real_attack_exempt: set[str] = set()
    if queued_not_scanned:
        _fcc_ra_keys = _load_fcc_real_attack_keys(ws_path)
        fcc_real_attack_exempt = {
            u for u in queued_not_scanned
            if _unit_in_fcc_real_attack(u, _fcc_ra_keys)
        }
        if fcc_real_attack_exempt:
            queued_not_scanned = queued_not_scanned - fcc_real_attack_exempt
    # Go entry-point exemption (axelar-dlt 2026-07-12 serving-join): on a Cosmos/Go-L1
    # workspace where fcc CONFIDENTLY narrowed the coverage denominator to true external
    # entry points (go_entry_surface.applied=True, internal helpers excluded), align the
    # STRICT queued-not-scanned obligation with that same authoritative surface. A
    # queued ``<file>.go::<fn>`` unit that is NOT one of fcc's enumerated entry points is
    # an internal helper reached transitively through an entry point that carries the
    # obligation - counting it as queued-not-scanned is a permanent false-red (axelar-
    # core: 445 exported-yet-non-entrypoint keeper helpers). The entry points themselves
    # (msg-server/ABCI/ante/IBC/genesis) STAY obligated - never a false-pass. Restricted
    # to .go units (Rust/tofn helpers keep their own obligation). Fail-CLOSED: no fcc
    # artifact / go_entry_surface not applied => empty exemption => every unit obligated.
    go_entrypoint_exempt: set[str] = set()
    if queued_not_scanned:
        _go_applied, _go_ep_base, _go_ep_rel = _load_fcc_go_entrypoint_keys(ws_path)
        if _go_applied:
            go_entrypoint_exempt = {
                u for u in queued_not_scanned
                if _unit_is_go_nonentrypoint_helper(u, _go_ep_base, _go_ep_rel)
            }
            if go_entrypoint_exempt:
                queued_not_scanned = queued_not_scanned - go_entrypoint_exempt
    strict_trace = {
        "go_entrypoint_exempt_units": sorted(go_entrypoint_exempt),
        "go_entrypoint_exempt_count": len(go_entrypoint_exempt),
        "non_entrypoint_exempt_units": sorted(non_entrypoint_exempt),
        "non_entrypoint_exempt_count": len(non_entrypoint_exempt),
        "sol_interface_exempt_units": sorted(sol_interface_exempt),
        "sol_interface_exempt_count": len(sol_interface_exempt),
        "denom_interface_exempt_units": sorted(denom_interface_exempt),
        "denom_interface_exempt_count": len(denom_interface_exempt),
        "nonvaluemoving_js_exempt_units": sorted(nonvaluemoving_js_exempt),
        "nonvaluemoving_js_exempt_count": len(nonvaluemoving_js_exempt),
        "legacy_identical_exempt_units": sorted(legacy_identical_exempt),
        "legacy_identical_exempt_count": len(legacy_identical_exempt),
        "file_only_nofn_exempt_units": sorted(file_only_nofn_exempt),
        "file_only_nofn_exempt_count": len(file_only_nofn_exempt),
        "file_only_hunted_exempt_units": sorted(file_only_hunted_exempt),
        "file_only_hunted_exempt_count": len(file_only_hunted_exempt),
        "fcc_real_attack_exempt_units": sorted(fcc_real_attack_exempt),
        "fcc_real_attack_exempt_count": len(fcc_real_attack_exempt),
        "synthetic_provenance_demotion": synthetic_demotion_trace,
        "needs_llm_depth_demotion": needs_llm_depth_demotion_trace,
        "auto_seed_heal": self_heal,
        "detector_units": sorted(detector_units),
        "queued_units": sorted(queue_units),
        "queued_units_strict": sorted(queue_units_strict),
        "scanned_units": sorted(scanned_units),
        "review_scanned_uncovered_units": sorted(review_scanned_uncovered),
        "review_scanned_uncovered_count": len(review_scanned_uncovered),
        "skip_logged_units": sorted(skip_logged_units),
        "budget_truncation": budget_truncation,
        "budget_skipped_units": sorted(budget_skipped_units),
        "detector_token_sources": detector_sources,
        "queue_token_sources": queue_sources,
        "queue_exempt_token_sources": queue_exempt_sources,
        "scanned_token_sources": scanned_sources,
        "current_run_id": current_run_id or None,
    }

    if detector_only_not_queued:
        return {
            "verdict": "fail-detector-only-not-queued",
            "reason": (
                f"{len(detector_only_not_queued)} detector-hit units are not "
                "queued and have no scan artifact"
            ),
            "exit": 1,
            "workspace": workspace_name,
            "workspace_path": str(ws_path),
            "coverage_basis": "source-unit",
            "total_contracts": total,
            "total_units": total,
            "covered": covered_count,
            "coverage_pct": round(coverage_pct, 4),
            "coverage_fraction": round(coverage_pct, 6),
            "denominator": denominator,
            "denominator_units": denominator["units"],
            "detector_only_not_queued": sorted(detector_only_not_queued),
            **strict_trace,
            "skip_log_path": str(skip_log_path),
            "skip_log_entries": skip_entries,
            "skip_logged_reasons": skip_logged_reasons,
            "coverage_report_path": str(coverage_report_path),
            "coverage_report_exists": coverage_report_path.is_file(),
            "coverage_report_generated_by_gate": coverage_report_generated_by_gate,
            **skip_trace,
        }

    if queued_not_scanned:
        return {
            "verdict": "fail-queued-not-scanned",
            "reason": f"{len(queued_not_scanned)} queued units have no scan artifact",
            "exit": 1,
            "workspace": workspace_name,
            "workspace_path": str(ws_path),
            "coverage_basis": "source-unit",
            "total_contracts": total,
            "total_units": total,
            "covered": covered_count,
            "coverage_pct": round(coverage_pct, 4),
            "coverage_fraction": round(coverage_pct, 6),
            "denominator": denominator,
            "denominator_units": denominator["units"],
            "queued_not_scanned": sorted(queued_not_scanned),
            **strict_trace,
            "skip_log_path": str(skip_log_path),
            "skip_log_entries": skip_entries,
            "skip_logged_reasons": skip_logged_reasons,
            "coverage_report_path": str(coverage_report_path),
            "coverage_report_exists": coverage_report_path.is_file(),
            "coverage_report_generated_by_gate": coverage_report_generated_by_gate,
            **skip_trace,
        }

    meets_threshold = effective_coverage_pct >= min_coverage
    all_remaining_logged = not effective_unlogged_uncovered

    if meets_threshold or all_remaining_logged:
        # Guard: token-coverage-met does NOT imply per-function attack coverage.
        # G15 measures source-unit token references (any detector hit / queue
        # entry / scan sidecar that cites a file::function).  A function can be
        # 100% "G15-covered" while the strict per-function gate
        # (function-coverage-completeness.py) reports hundreds of functions as
        # hollow or untouched - because hollow/untouched means no REAL attack
        # verdict was recorded for that function, only a heuristic token
        # reference.  If we returned pass-coverage-met here and the strict gate
        # disagrees we would produce a false-green (the monero symptom: G15
        # "100% of 136 units covered" while hundreds of functions are untouched).
        #
        # Fix: invoke function-coverage-completeness (if available) and block
        # pass-coverage-met when it reports a fail- verdict.  Tooling-absence
        # or error degrades gracefully to warn-only (does NOT block), mirroring
        # the pattern in audit-completeness-check.py signal (s).
        _fcc_mod = _load_strict_fn_coverage_module()
        _fcc_payload: dict[str, Any] | None = None
        _fcc_verdict: str | None = None
        _fcc_warn: str | None = None
        if _fcc_mod is not None:
            try:
                _fcc_payload = _call_strict_fn_coverage_gate(_fcc_mod, ws_path)
            except Exception as _exc:
                _fcc_warn = f"function-coverage-completeness raised: {_exc}"
            if _fcc_payload is not None:
                _fcc_verdict = str(_fcc_payload.get("verdict") or "")
        else:
            _fcc_warn = "function-coverage-completeness.py not found; strict per-function check skipped"

        _fcc_is_fail = (
            _fcc_verdict is not None
            and _fcc_verdict.lower() not in _FCC_NON_FAIL_VERDICTS
            and _fcc_verdict.lower().startswith("fail-")
        )

        if _fcc_is_fail:
            # Strict per-function gate disagrees: G15 token-coverage is met but
            # function-coverage-completeness reports hollow/untouched functions.
            # Return a clear fail so callers cannot interpret G15 as "covered".
            _fcc_counts = (_fcc_payload or {}).get("counts", {})
            _fcc_hollow = int(_fcc_counts.get("hollow") or 0)
            _fcc_untouched = int(_fcc_counts.get("untouched") or 0)
            _fcc_total = int(_fcc_counts.get("total") or 0)
            return {
                "verdict": "fail-strict-function-coverage-disagrees",
                "reason": (
                    f"G15 token-coverage is met ({effective_coverage_pct:.2%} "
                    f"{effective_covered_count}/{total}) but the strict per-function "
                    f"gate reports {_fcc_hollow} hollow + {_fcc_untouched} untouched "
                    f"of {_fcc_total} in-scope functions with no real attack verdict "
                    f"(function-coverage verdict: {_fcc_verdict}). "
                    "Token references alone do not satisfy per-function attack coverage. "
                    "Drive a real per-function attack verdict for each hollow/untouched "
                    "function, or add a g15-rebuttal marker with operator approval."
                ),
                "exit": 1,
                "workspace": workspace_name,
                "workspace_path": str(ws_path),
                "coverage_basis": "source-unit",
                "total_contracts": total,
                "total_units": total,
                "covered": effective_covered_count,
                "raw_covered": covered_count,
                "coverage_pct": round(effective_coverage_pct, 4),
                "coverage_fraction": round(effective_coverage_pct, 6),
                "raw_coverage_fraction": round(coverage_pct, 6),
                "uncovered_count": effective_uncovered_count,
                "raw_uncovered_count": uncovered_count,
                "skip_logged_count": len(skip_logged_uncovered),
                "skip_logged_reasons": skip_logged_reasons,
                "min_coverage": min_coverage,
                "strict_function_coverage_verdict": _fcc_verdict,
                "strict_function_coverage_hollow": _fcc_hollow,
                "strict_function_coverage_untouched": _fcc_untouched,
                "strict_function_coverage_total": _fcc_total,
                "strict_function_coverage_detail": _fcc_payload,
                "denominator": denominator,
                "denominator_units": denominator["units"],
                **strict_trace,
                "skip_log_path": str(skip_log_path),
                "skip_log_entries": skip_entries,
                "coverage_report_path": str(coverage_report_path),
                "coverage_report_exists": coverage_report_path.is_file(),
                "coverage_report_generated_by_gate": coverage_report_generated_by_gate,
                **skip_trace,
            }

        # Build the strict-function-coverage annotation to attach to the pass.
        _strict_fn_coverage_info: dict[str, Any] = {
            "verdict": _fcc_verdict,
            "warn": _fcc_warn,
        }
        if _fcc_payload:
            _fcc_counts = _fcc_payload.get("counts", {})
            _strict_fn_coverage_info.update({
                "hollow": int(_fcc_counts.get("hollow") or 0),
                "untouched": int(_fcc_counts.get("untouched") or 0),
                "total": int(_fcc_counts.get("total") or 0),
            })

        return {
            "verdict": "pass-coverage-met",
            "reason": (
                f"coverage {effective_coverage_pct:.2%} "
                f"({effective_covered_count}/{total}); "
                f"{effective_uncovered_count} uncovered, "
                f"{len(skip_logged_uncovered)} skip-logged, "
                f"{len(effective_unlogged_uncovered)} unlogged-uncovered"
                + (" (all remaining uncovered are skip-logged)"
                   if all_remaining_logged and not meets_threshold else "")
            ),
            "exit": 0,
            "workspace": workspace_name,
            "workspace_path": str(ws_path),
            "coverage_basis": "source-unit",
            "total_contracts": total,
            "total_units": total,
            "covered": effective_covered_count,
            "raw_covered": covered_count,
            "coverage_pct": round(effective_coverage_pct, 4),
            "coverage_fraction": round(effective_coverage_pct, 6),
            "raw_coverage_fraction": round(coverage_pct, 6),
            "uncovered_count": effective_uncovered_count,
            "raw_uncovered_count": uncovered_count,
            "skip_logged_count": len(skip_logged_uncovered),
            "skip_logged_reasons": skip_logged_reasons,
            "min_coverage": min_coverage,
            "strict_function_coverage": _strict_fn_coverage_info,
            "denominator": denominator,
            "denominator_units": denominator["units"],
            **strict_trace,
            "skip_log_path": str(skip_log_path),
            "skip_log_entries": skip_entries,
            "coverage_report_path": str(coverage_report_path),
            "coverage_report_exists": coverage_report_path.is_file(),
            "coverage_report_generated_by_gate": coverage_report_generated_by_gate,
            **skip_trace,
        }

    return {
        "verdict": "fail-coverage-below-threshold",
        "reason": (
            f"coverage {effective_coverage_pct:.2%} "
            f"({effective_covered_count}/{total}) below "
            f"min {min_coverage:.0%}; {len(effective_unlogged_uncovered)} "
            f"unlogged uncovered units ({len(effective_libraries_uncovered)} libraries)"
        ),
        "exit": 1,
        "workspace": workspace_name,
        "workspace_path": str(ws_path),
        "coverage_basis": "source-unit",
        "total_contracts": total,
        "total_units": total,
        "covered": effective_covered_count,
        "raw_covered": covered_count,
        "coverage_pct": round(effective_coverage_pct, 4),
        "coverage_fraction": round(effective_coverage_pct, 6),
        "raw_coverage_fraction": round(coverage_pct, 6),
        "uncovered_count": effective_uncovered_count,
        "raw_uncovered_count": uncovered_count,
        "skip_logged_count": len(skip_logged_uncovered),
        "skip_logged_reasons": skip_logged_reasons,
        "min_coverage": min_coverage,
        "unlogged_uncovered": sorted(effective_unlogged_uncovered)[:100],
        "libraries_uncovered": effective_libraries_uncovered[:50],
        "skip_log_path": str(skip_log_path),
        "skip_log_entries": skip_entries,
        "denominator": denominator,
        "denominator_units": denominator["units"],
        **strict_trace,
        "coverage_report_path": str(coverage_report_path),
        "coverage_report_exists": coverage_report_path.is_file(),
        "coverage_report_generated_by_gate": coverage_report_generated_by_gate,
        **skip_trace,
        "remediation": (
            "Drill the uncovered source units (especially libraries), OR log "
            "intentional skips one-per-line in "
            f"{skip_log_path}, OR add `<!-- g15-rebuttal: <reason> -->`."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "G15.1 hunt-coverage gate. Computes per-workspace source-unit "
            "coverage and fails when unlogged uncovered units remain below "
            "threshold."
        ),
    )
    p.add_argument("--workspace", required=True, help="Workspace name (e.g. hyperbridge) or path.")
    p.add_argument(
        "--min-coverage-pct",
        type=float,
        default=DEFAULT_MIN_COVERAGE,
        help=f"Minimum covered/total fraction (default {DEFAULT_MIN_COVERAGE}).",
    )
    p.add_argument(
        "--skip-log",
        default=None,
        help=(
            "Path to a skip-log (default <ws>/.auditooor/hunt_coverage_skips.txt); "
            "one contract basename + reason per line."
        ),
    )
    p.add_argument(
        "--prompt-file",
        default=None,
        help="Optional brief / prompt file scanned for a g15-rebuttal marker.",
    )
    p.add_argument(
        "--run-id",
        default=os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID", ""),
        help="Optional audit-run-full run id to embed in the last-result sidecar.",
    )
    p.add_argument(
        "--no-auto-seed-heal",
        action="store_true",
        help=(
            "Disable strict-mode auto-heal that re-seeds uncovered units into "
            "exploit_queue before final G15 evaluation."
        ),
    )
    p.add_argument("--strict", action="store_true", help="Hard-fail (exit 1) on below-threshold.")
    p.add_argument("--json", action="store_true", help="Emit JSON verdict payload.")
    p.add_argument(
        "--sidecar-provenance", action="store_true",
        help="ADVISORY-ONLY (E4): also run the per-sidecar provenance-authenticity "
             "scan (hunt-dispatch-provenance-check.py --sidecars) and attach its "
             "result under result['sidecar_provenance']. Purely additive: it NEVER "
             "changes this gate's verdict or exit code. Synthetic-lead sidecars are "
             "reported so they can be re-hunted before crediting per-fn coverage.",
    )
    args = p.parse_args(argv)

    rebuttal_text = ""
    if args.prompt_file:
        try:
            rebuttal_text = Path(args.prompt_file).expanduser().read_text(
                encoding="utf-8", errors="replace"
            )
        except (FileNotFoundError, OSError):
            rebuttal_text = ""

    skip_log = Path(args.skip_log).expanduser() if args.skip_log else None

    result = check(
        args.workspace,
        min_coverage=args.min_coverage_pct,
        skip_log_path=skip_log,
        rebuttal_text=rebuttal_text,
        auto_seed_heal=(bool(args.strict) and not bool(args.no_auto_seed_heal)),
        run_id=str(args.run_id or ""),
    )

    # E4 advisory-only: attach a per-sidecar provenance-authenticity report. This
    # never mutates the coverage verdict/exit; it surfaces synthetic (never-really-
    # hunted) sidecars that would otherwise green per-fn coverage. Best-effort: any
    # import/scan failure is swallowed so the coverage gate is unaffected.
    if getattr(args, "sidecar_provenance", False):
        try:
            import importlib.util as _ilu
            _prov_path = Path(__file__).resolve().parent / "hunt-dispatch-provenance-check.py"
            _spec = _ilu.spec_from_file_location("_hdp_sidecar_prov", str(_prov_path))
            _mod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
            _ws = _resolve_workspace_path(args.workspace) or args.workspace
            result["sidecar_provenance"] = _mod.scan_workspace_sidecars(Path(_ws))
        except Exception as _e:  # pragma: no cover - defensive; must not fail the gate
            result["sidecar_provenance"] = {"verdict": "error-provenance-scan",
                                            "error": str(_e)}

    persist_info = _persist_cli_result(
        result,
        workspace=args.workspace,
        run_id=str(args.run_id or ""),
        strict=bool(args.strict),
        min_coverage=float(args.min_coverage_pct),
    )
    result["last_result_sidecar"] = persist_info
    fail_exit = int(result.pop("exit", 0))
    _emit(result, args.json)

    # Default WARN-only only applies to threshold misses; integrity failures
    # hard-fail closed because they corrupt the denominator or queue state.
    if result.get("verdict") == "fail-coverage-below-threshold" and not args.strict:
        return 0
    if str(result.get("verdict") or "").startswith("fail-"):
        return fail_exit
    if result.get("verdict") == "error":
        return 2
    return fail_exit if args.strict else 0


if __name__ == "__main__":
    sys.exit(main())
