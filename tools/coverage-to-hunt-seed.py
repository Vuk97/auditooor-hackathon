#!/usr/bin/env python3
"""coverage-to-hunt-seed.py - close the measure->act loop on the swept-surface
coverage gate by feeding UNCOVERED units back into the hunt seed.

WHAT IT DOES (the unique gap):
  The swept-surface coverage report (auditooor.workspace_coverage_report.v1 at
  ``<ws>/.auditooor/coverage_report.json``, produced by
  tools/workspace-coverage-heatmap.py) MEASURES which in-scope units have NOT
  been hunted (e.g. dydx 1189/1199 UNCOVERED). This tool turns that
  measurement into ACTION: it UPSERTs one ``unhunted-surface`` seed row per
  uncovered unit into the canonical hunt queue
  (``<ws>/.auditooor/exploit_queue.json``, schema auditooor.exploit_queue.v1)
  so the NEXT hunt pass actually targets those units and the covered number
  climbs.

HONESTY IS NON-NEGOTIABLE (R76 discipline):
  A seed row means "this unit has NOT been hunted - go look here", NOT "there
  is a bug here". The rows are TARGETS, not hypotheses-with-claims and not
  findings. Each ``unhunted-surface`` row therefore carries:
    - NO ``attack_class`` / bug-class field,
    - NO ``likely_severity`` / severity field,
    - NO claim / suspicion / impact assertion.
  It carries only: workspace, unit id (``<file>::<fn>`` or ``<file>``), source
  path, a neutral reason, and the queue bookkeeping fields (lead_id, source,
  proof_status=open, contract, function). The downstream find machinery
  (corpus-driven-hunt, MIMO fanout, etc.) evaluates the targets and is the
  only place a bug class / severity is ever attached. This keeps the queue
  honest and avoids poisoning it with fabricated suspicion.

NO-SILENT-TRUNCATION DISCIPLINE:
  The coverage report's inlined ``uncovered_units`` list may be capped
  (``uncovered_units_truncated == true``). This tool refuses to silently seed
  only the first N: when truncation is detected it REGENERATES the report with
  ``--uncovered-list-cap -1`` (no cap) via the heatmap CLI so the FULL
  uncovered set is seeded. The seed set always equals the true ``uncovered``
  count from the report.

LOOP-CLOSURE (why the number climbs):
  collect_coverage_tokens() in workspace-coverage-heatmap.py harvests the
  ``contract`` / ``function`` fields of every exploit_queue row as coverage
  tokens, and _unit_is_covered() marks a unit COVERED once a matching
  ``<base>::<fn>`` token exists. Writing an unhunted-surface row with
  ``contract=<base>`` + ``function=<fn>`` therefore flips that unit to COVERED
  on the next report build. The seeding step IS the act half of measure->act.
  (A seed row is "this unit is now on the hunt queue" credit - coarse but
  honest "it has been queued for a look", which is exactly what the coverage
  gate measures.)

P1 HONESTY ADDITION:
  Detector-only rows and stale queue rows are obligations, not coverage. When
  such a row is the only thing referencing an in-scope unit, this tool emits a
  concrete hunt seed for that file/function instead of letting the unit stay
  falsely green. Skip-logged or report-skipped in-scope units are also emitted
  with their skip reason so a skipped function still turns into an actionable
  queue row.

RELATED TOOLS (read these first - this tool fills a distinct gap):
  - tools/workspace-coverage-heatmap.py: PRODUCES the coverage report this
    tool consumes (the MEASURE half). This tool is the ACT half; it does not
    re-implement enumeration/classification - it reads the report and, on
    truncation, calls the heatmap CLI to regenerate with no cap.
  - tools/corpus-driven-hunt.py: emits ``corpus-hunt-fuel`` /
    ``corpus-hunt-hacker-q`` rows into the SAME exploit_queue.json from the
    invariant/detector corpus (hypotheses WITH a cited INV-* + attack_class).
    This tool is the orthogonal source: ``unhunted-surface`` rows are pure
    coverage-gap TARGETS with NO attack_class/severity/claim. Both sources
    coexist in the queue; this tool never clobbers corpus-hunt rows.
  - tools/preflight-to-exploit-queue.py: emits per-function preflight fuel
    rows (carries an attack_class from attack_class_evidence). This tool emits
    claim-free coverage targets; the dedup namespaces (``source`` field) keep
    the three fuel sources separate.
  - tools/exploit-queue.py: the downstream queue classifier/ranker that reads
    exploit_queue rows. This tool only WRITES claim-free open rows; the
    classifier assigns proof_status downstream.

Deterministic, stdlib-only. Advisory: it does not prove exploitability and
emits TARGETS only.

Schema (--json verdict): auditooor.coverage_to_hunt_seed.v1

USAGE:
  # seed the canonical exploit_queue.json from the coverage report
  python3 tools/coverage-to-hunt-seed.py --workspace-path ~/audits/dydx

  # rebuild the coverage report first (recommended - keeps measurement fresh)
  python3 tools/coverage-to-hunt-seed.py --workspace-path ~/audits/dydx \
      --rebuild-report

  # dry-run: compute the seed rows but do not write the queue
  python3 tools/coverage-to-hunt-seed.py --workspace-path ~/audits/dydx \
      --dry-run --json
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.coverage_to_hunt_seed.v1"
COVERAGE_REPORT_REL = os.path.join(".auditooor", "coverage_report.json")
EXPLOIT_QUEUE_REL = os.path.join(".auditooor", "exploit_queue.json")
EXPLOIT_QUEUE_SCHEMA = "auditooor.exploit_queue.v1"
SEED_SNAPSHOT_REL = os.path.join(".auditooor", "hunt_coverage_seed_snapshot.json")
SEED_SNAPSHOT_SCHEMA = "auditooor.coverage_to_hunt_seed_snapshot.v1"

# The dedup namespace for coverage-gap target rows. Distinct from
# corpus-hunt-fuel / corpus-hunt-hacker-q / preflight fuel so the three never
# collide and this tool only ever refreshes its OWN rows.
UNHUNTED_SURFACE_SOURCE = "unhunted-surface"

# Neutral, claim-free reason. Deliberately carries NO bug class, NO severity,
# NO suspicion - it states only that the unit has not been hunted.
NEUTRAL_REASON = "unhunted-surface: no hypothesis references this unit"
DEFAULT_SKIP_LOG_REL = os.path.join(".auditooor", "hunt_coverage_skips.txt")

UNCOVERED_SKIP_REASON = "coverage-uncovered"
SKIP_LOG_REASON = "coverage-skip-log"
REPORT_SKIP_REASON = "coverage-report-skipped"
DETECTOR_ONLY_REASON = "coverage-invalid-detector-only-row"
STALE_ROW_REASON = "coverage-invalid-stale-row"
REQUIRED_COVERAGE_REPORT_FRESHNESS_FIELDS = (
    "source_freshness",
    "numerator_freshness",
)

# Fields that a coverage TARGET row MUST NOT carry (honest-target invariant).
# Enforced at row-build time and asserted by the regression test.
FORBIDDEN_CLAIM_FIELDS = (
    "attack_class", "likely_severity", "severity", "bug_class",
    "impact", "claim", "suspicion", "vulnerability_class", "finding_class",
)

HEATMAP_TOOL = Path(__file__).resolve().parent / "workspace-coverage-heatmap.py"

TOKEN_KEYS = (
    "file", "file_path", "file_path_hint", "path", "source_file", "contract",
    "contract_name", "unit", "unit_id", "target_file", "affected_file",
)
FN_KEYS = ("function", "function_name", "fn", "method", "affected_function")

DETECTOR_ONLY_SOURCE_MARKERS = (
    "detector-only", "detector_only", "detector-hit", "detector_hits",
    "detector", "engage-report", "engage_report", "coverage-token",
    "coverage_tokens", "source-mined", "source_mined",
)
STALE_STATUS_MARKERS = (
    "stale", "outdated", "expired", "desynced", "stale-source",
    "source-stale", "stale-denominator",
)
STATUS_KEYS = (
    "status", "proof_status", "quality_gate_status", "coverage_status",
    "freshness", "source_freshness_status", "source_status",
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", dir=str(path.parent), suffix=".tmp", delete=False
    ) as tf:
        json.dump(data, tf, indent=2)
        tmp = tf.name
    os.replace(tmp, str(path))


def _write_seed_snapshot(
    workspace_path: Path | None,
    queue_path: Path,
    report: dict,
    seeded_targets: list[dict],
    seeded_units: list[str],
    invalid_counts: dict[str, int],
    run_id: str = "",
) -> tuple[bool, str]:
    if workspace_path is None:
        return False, ""
    out = workspace_path / SEED_SNAPSHOT_REL
    payload = {
        "schema": SEED_SNAPSHOT_SCHEMA,
        "generated_at_utc": _utc_now(),
        "run_id": run_id or None,
        "workspace": str(workspace_path),
        "queue_path": str(queue_path),
        "source_freshness": report.get("source_freshness"),
        "numerator_freshness": report.get("numerator_freshness"),
        "uncovered": int(report.get("uncovered", 0)),
        "seed_rows_total": len(seeded_targets),
        "invalid_coverage_rows_reseeded": invalid_counts,
        "seeded_units": seeded_units,
        "seeded_targets": seeded_targets,
    }
    _atomic_write_json(out, payload)
    return True, str(out)


def _empty_exploit_queue(workspace_name: str) -> dict:
    return {
        "schema": EXPLOIT_QUEUE_SCHEMA,
        "generated_at_utc": _utc_now(),
        "workspace": workspace_name,
        "top_n": 0,
        "total_candidates": 0,
        "context_pack_hash": "",
        "context_pack_id": "",
        "benchmark": {},
        "source_artifacts_consumed": [],
        "queue": [],
    }


def _load_exploit_queue(queue_path: Path, workspace_name: str) -> dict:
    if not queue_path.exists():
        return _empty_exploit_queue(workspace_name)
    try:
        data = json.loads(queue_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return _empty_exploit_queue(workspace_name)
    if not isinstance(data, dict) or not isinstance(data.get("queue"), list):
        return _empty_exploit_queue(workspace_name)
    return data


def _load_heatmap_module() -> Any | None:
    """Import workspace-coverage-heatmap.py by path."""
    if not HEATMAP_TOOL.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "_coverage_heatmap_for_seed", HEATMAP_TOOL,
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:
        return None


def _unit_parts(unit: str) -> tuple[str, str]:
    """Split a coverage unit key into (file key, function).

    Function-granularity units are ``<file>::<fn>``; file-granularity units
    are bare ``<file>`` (function == "")."""
    if "::" in unit:
        base, _, fn = unit.partition("::")
        return base, fn
    return unit, ""


def _unit_file_key(unit: str) -> str:
    return _unit_parts(unit)[0]


def _unit_basename(unit: str) -> str:
    return Path(_unit_file_key(unit).replace("\\", "/")).name


def _unit_matches_token(unit: str, token: str) -> bool:
    token = (token or "").strip()
    if not token:
        return False
    unit_file, unit_fn = _unit_parts(unit)
    token_file, token_fn = _unit_parts(token)
    if token_fn:
        return (
            bool(unit_fn)
            and token_fn == unit_fn
            and Path(token_file.replace("\\", "/")).name == Path(unit_file).name
        )
    return token_file in {unit_file, Path(unit_file).name}


def _unit_source_path(
    source_root: str, file_key: str, workspace_path: Path | None = None,
) -> str:
    """Best-effort concrete source path for a unit's file key.

    Coverage reports may store basename units (``Vault.sol``) or path-qualified
    units (``src/a/Vault.sol``). Prefer an existing workspace-relative or
    source-root-relative file; fall back to a basename walk; finally return the
    original file key. Never raises.
    """
    file_key = (file_key or "").replace("\\", "/").strip()
    if not file_key:
        return file_key
    raw = Path(file_key).expanduser()
    if raw.is_absolute() and raw.is_file():
        return str(raw)
    if workspace_path is not None:
        cand = workspace_path / file_key
        if cand.is_file():
            return str(cand)
    if source_root and os.path.isdir(source_root):
        cand = Path(source_root) / file_key
        if cand.is_file():
            return str(cand)
    if "/" in file_key:
        return file_key
    if not source_root or not os.path.isdir(source_root):
        return file_key
    for dirpath, dirnames, filenames in os.walk(source_root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")]
        if file_key in filenames:
            return os.path.join(dirpath, file_key)
    return file_key


def build_seed_row(
    workspace_name: str,
    unit: str,
    source_path: str,
    skip_reason: str = UNCOVERED_SKIP_REASON,
    run_id: str = "",
) -> dict:
    """Build ONE honest-target unhunted-surface queue row.

    The row is claim-free: no attack_class, no severity, no bug class, no
    suspicion. It carries only the target identity + queue bookkeeping so the
    downstream find machinery can pick it up. The lead_id is namespaced and
    deterministic so reruns dedup idempotently.
    """
    contract, function = _unit_parts(unit)
    slug = unit.replace("/", "-").replace("\\", "-").replace(".", "-").replace("::", "--")
    unit_hash = hashlib.sha256(unit.encode("utf-8", errors="replace")).hexdigest()[:10]
    lead_id = "F-UNHUNTED-" + slug[:80] + "-" + unit_hash
    row = {
        "lead_id": lead_id,
        "title": "unhunted-surface target: " + unit,
        # proof bookkeeping (open obligation, no evidence yet)
        "proof_status": "open",
        "quality_gate_status": "open",
        # the TARGET identity (what collect_coverage_tokens harvests)
        "workspace": workspace_name,
        "unit_id": unit,
        "contract": contract,
        "file": contract,
        "function": function,
        "source_path": source_path,
        "reason": NEUTRAL_REASON,
        "skip_reason": skip_reason or UNCOVERED_SKIP_REASON,
        # provenance
        "source": UNHUNTED_SURFACE_SOURCE,
        "source_refs": [],
        "broken_invariant_ids": [],
    }
    if run_id:
        row["run_id"] = run_id
    # Honest-target invariant: assert no claim field leaked in.
    for f in FORBIDDEN_CLAIM_FIELDS:
        if f in row:
            raise AssertionError(
                "honest-target invariant violated: claim field %r in seed row" % f
            )
    return row


def _normalise_source_ref(raw: str) -> str | None:
    value = str(raw or "").strip().replace("\\", "/")
    if not value or value.upper() in {"NA", "N/A", "NULL", "NONE"}:
        return None
    value = value.strip().strip("`").strip()
    value = value.split("#", 1)[0]
    value = re.sub(r"(?::[0-9]+(?:-[0-9]+)?)$", "", value)
    value = value.strip("/")
    while value.startswith("./"):
        value = value[2:]
    value = value or None
    return value


def _add_tokens(tokens: set[str], raw_ref: str, fn_name: str | None = None) -> None:
    ref = _normalise_source_ref(raw_ref)
    if not ref:
        return
    if "::" in ref and fn_name is None:
        ref, _, fn_name = ref.partition("::")
    ref = _normalise_source_ref(ref)
    if not ref:
        return
    base = Path(ref).name
    for file_token in {ref, base}:
        tokens.add(file_token)
        if fn_name:
            tokens.add("%s::%s" % (file_token, fn_name))


def _tokens_from_row(row: dict) -> set[str]:
    tokens: set[str] = set()
    file_refs: list[str] = []
    for key in TOKEN_KEYS:
        value = row.get(key)
        if isinstance(value, str):
            ref = _normalise_source_ref(value)
            if ref:
                file_refs.append(ref)
                _add_tokens(tokens, ref)
    for key in FN_KEYS:
        value = row.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        fn_name = value.strip().split("(", 1)[0].strip()
        if not fn_name:
            continue
        for ref in file_refs:
            _add_tokens(tokens, ref, fn_name)
    return tokens


REVIEW_UNIT_KEYS = ("reviewed_units", "scanned_units", "covered_units")
SCANNED_REVIEW_DIRS = (
    "hunt_findings_sidecars",
    ".auditooor/hunt_findings_sidecars",
    "source_artifacts",
    ".auditooor/source_artifacts",
)


def _add_review_unit_tokens(tokens: set[str], raw_unit: Any, raw_ref: Any = None) -> None:
    unit = str(raw_unit or "").strip()
    if "::" not in unit:
        return
    file_hint, fn_name = unit.split("::", 1)
    fn_name = fn_name.split("(", 1)[0].strip()
    if not file_hint.strip() or not fn_name:
        return
    ref = _normalise_source_ref(str(raw_ref or "")) or _normalise_source_ref(file_hint)
    if not ref:
        return
    _add_tokens(tokens, ref, fn_name)


def _review_tokens_from_json(path: Path) -> set[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return set()
    if not isinstance(data, dict):
        return set()
    tokens: set[str] = set()
    target = data.get("target")
    if isinstance(target, dict):
        _add_review_unit_tokens(
            tokens,
            target.get("name") or target.get("unit") or target.get("source_unit"),
            target.get("source_ref") or target.get("path") or target.get("file"),
        )
    for key in REVIEW_UNIT_KEYS:
        raw_units = data.get(key)
        if not isinstance(raw_units, list):
            continue
        for raw_unit in raw_units:
            if isinstance(raw_unit, str):
                _add_review_unit_tokens(tokens, raw_unit)
            elif isinstance(raw_unit, dict):
                _add_review_unit_tokens(
                    tokens,
                    raw_unit.get("name") or raw_unit.get("unit") or raw_unit.get("source_unit"),
                    raw_unit.get("source_ref") or raw_unit.get("path") or raw_unit.get("file"),
                )
    citations = data.get("source_citations")
    if isinstance(citations, list):
        for citation in citations:
            if isinstance(citation, str):
                _add_review_unit_tokens(tokens, citation)
            elif isinstance(citation, dict):
                _add_review_unit_tokens(
                    tokens,
                    citation.get("name") or citation.get("unit") or citation.get("source_unit"),
                    citation.get("source_ref") or citation.get("path") or citation.get("file"),
                )
    return tokens


def _status_is_stale(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    text = str(value).strip().lower()
    if not text:
        return False
    return any(marker in text for marker in STALE_STATUS_MARKERS)


def _invalid_coverage_row_reason(row: dict) -> str | None:
    if not isinstance(row, dict):
        return None
    if row.get("source") == UNHUNTED_SURFACE_SOURCE:
        return None
    source = str(row.get("source") or row.get("source_kind") or "").strip().lower()
    coverage_kind = str(row.get("coverage_kind") or "").strip().lower()
    if bool(row.get("detector_only")) or coverage_kind == "detector-only":
        return DETECTOR_ONLY_REASON
    if source and any(marker in source for marker in DETECTOR_ONLY_SOURCE_MARKERS):
        return DETECTOR_ONLY_REASON
    for key in STATUS_KEYS:
        if _status_is_stale(row.get(key)):
            return STALE_ROW_REASON
    return None


def _load_queue_rows(queue_path: Path) -> list[dict]:
    try:
        data = json.loads(queue_path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return []
    raw_rows = data.get("queue") if isinstance(data, dict) else data
    if not isinstance(raw_rows, list):
        return []
    return [row for row in raw_rows if isinstance(row, dict)]


def _dict_set_add_all(target: dict[str, set[str]], key: str, values: set[str]) -> None:
    if key not in target:
        target[key] = set()
    target[key].update(values)


def _collect_queue_token_sets(queue_path: Path) -> tuple[set[str], dict[str, set[str]]]:
    valid_tokens: set[str] = set()
    invalid_by_reason: dict[str, set[str]] = {}
    for row in _load_queue_rows(queue_path):
        row_tokens = _tokens_from_row(row)
        if not row_tokens:
            continue
        reason = _invalid_coverage_row_reason(row)
        if reason:
            _dict_set_add_all(invalid_by_reason, reason, row_tokens)
        else:
            valid_tokens.update(row_tokens)
    return valid_tokens, invalid_by_reason


def _dedup_key(row: dict) -> str:
    """Dedup key for queue rows.

    unhunted-surface rows dedup by (source, lead_id) so the same unit never
    duplicates across reruns and never collides with corpus-hunt / preflight
    rows (which dedup on their own namespaces / on contract.function)."""
    src = row.get("source", "")
    if src == UNHUNTED_SURFACE_SOURCE:
        return src + "::" + row.get("lead_id", "")
    # mirror the canonical dedup used by sibling tools for foreign rows
    c, fn = row.get("contract", ""), row.get("function", "")
    if c and fn:
        return c + "." + fn
    return row.get("lead_id", row.get("title", ""))


def _regenerate_full_report(ws_path: Path) -> dict:
    """Regenerate the coverage report with NO uncovered-list cap so the full
    uncovered set is available. Calls the heatmap CLI (the MEASURE tool) rather
    than re-implementing enumeration."""
    cmd = [
        sys.executable, str(HEATMAP_TOOL),
        "--coverage-report",
        "--workspace-path", str(ws_path),
        "--uncovered-list-cap", "-1",
    ]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    report_path = ws_path / COVERAGE_REPORT_REL
    return json.loads(report_path.read_text(encoding="utf-8"))


def _coverage_report_has_current_freshness_shape(report: dict) -> bool:
    return all(
        isinstance(report.get(field), dict)
        for field in REQUIRED_COVERAGE_REPORT_FRESHNESS_FIELDS
    )


def load_coverage_report(ws_path: Path, rebuild: bool) -> dict:
    """Load the coverage report, regenerating at full cap when needed.

    - rebuild=True: always regenerate fresh at no-cap.
    - else: read the existing report; if it is truncated (or missing), call the
      heatmap CLI to produce the FULL uncovered set. NEVER silently seeds a
      truncated subset.
    """
    report_path = ws_path / COVERAGE_REPORT_REL
    if rebuild or not report_path.exists():
        return _regenerate_full_report(ws_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("uncovered_units_truncated"):
        return _regenerate_full_report(ws_path)
    if not _coverage_report_has_current_freshness_shape(report):
        return _regenerate_full_report(ws_path)
    return report


def _report_workspace_path(report: dict, fallback: Path | None = None) -> Path | None:
    raw = report.get("workspace")
    if isinstance(raw, str) and raw.strip():
        p = Path(raw.strip()).expanduser()
        if p.is_absolute() or "/" in raw or "\\" in raw:
            return p.resolve(strict=False)
    return fallback


def _inscope_file_bases(ws_path: Path) -> set[str]:
    """Basenames of the in-scope files from the authoritative
    .auditooor/inscope_units.jsonl. Empty set when the manifest is absent (no
    enumerated scope -> caller does not filter). This manifest is the scope-correct
    one (the inscope emitter + _source_file_records honor the SCOPE.md enumerated
    allowlist), so intersecting against it drops OOS units that the heatmap's
    enumerate_units(scope) - which keys on scope_globs, not the allowlist - still
    returns (Strata 2026-06-30: 64 files vs the 17 in scope -> 77.8% of seeded
    unhunted-surface exploit-queue rows were OOS DYSAccounting/StrataCDO/strategies)."""
    out: set[str] = set()
    mf = ws_path / ".auditooor" / "inscope_units.jsonl"
    if not mf.is_file():
        return out
    for line in mf.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        f = str(rec.get("file") or rec.get("path") or rec.get("source") or "")
        if f:
            out.add(f.rsplit("/", 1)[-1])
    return out


def _enumerate_live_units(ws_path: Path | None) -> tuple[Any | None, set[str], dict]:
    if ws_path is None or not ws_path.is_dir():
        return None, set(), {}
    heatmap = _load_heatmap_module()
    if heatmap is None:
        return None, set(), {}
    try:
        scope = None
        resolve_scope = getattr(heatmap, "resolve_scope", None)
        if callable(resolve_scope):
            scope = resolve_scope(ws_path)
        enumerate_units = getattr(heatmap, "enumerate_units", None)
        if not callable(enumerate_units):
            return heatmap, set(), {}
        if scope is None:
            units, detail = enumerate_units(ws_path)
        else:
            units, detail = enumerate_units(ws_path, scope=scope)
        detail_out = detail if isinstance(detail, dict) else {}
        unit_set = {str(unit) for unit in units}
        # SCOPE-ALLOWLIST intersection (L8 unhunted-surface scope-bleed): drop any
        # enumerated unit whose file is NOT in the authoritative inscope manifest.
        # No manifest -> keep all (whole-tree behaviour for non-enumerated scope).
        inscope = _inscope_file_bases(ws_path)
        if inscope:
            unit_set = {u for u in unit_set if _unit_basename(u) in inscope}
        return heatmap, unit_set, detail_out
    except Exception:
        return heatmap, set(), {}


def _bases_with_fn_precise_tokens(tokens: set[str]) -> set[str]:
    return {token.split("::", 1)[0] for token in tokens if "::" in token}


def _unique_file_keys_by_basename(units: set[str]) -> dict[str, str]:
    by_base: dict[str, set[str]] = {}
    for unit in units:
        by_base.setdefault(_unit_basename(unit), set()).add(_unit_file_key(unit))
    return {
        base: next(iter(keys))
        for base, keys in by_base.items()
        if len(keys) == 1
    }


def _unit_is_covered_local(
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
        _base, _sep, fn_name = unit.partition("::")
        return unique_file_keys.get(basename) == file_key and "%s::%s" % (
            basename, fn_name,
        ) in tokens
    return file_key in tokens or (
        unique_file_keys.get(basename) == file_key and basename in tokens
    )


def _units_for_tokens(
    heatmap: Any | None,
    units: set[str],
    tokens: set[str],
    enum_detail: dict,
) -> set[str]:
    if not units or not tokens:
        return set()
    bases_with_fn = getattr(heatmap, "_bases_with_fn_precise_tokens", None)
    unique_by_base = getattr(heatmap, "_unique_file_keys_by_basename", None)
    unit_is_covered = getattr(heatmap, "_unit_is_covered", None)
    fn_precise = (
        bases_with_fn(tokens)
        if callable(bases_with_fn)
        else _bases_with_fn_precise_tokens(tokens)
    )
    if callable(unique_by_base):
        unique_file_keys = unique_by_base(
            sorted(units),
            set(enum_detail.get("ambiguous_source_basenames") or []),
        )
    else:
        unique_file_keys = _unique_file_keys_by_basename(units)
    out: set[str] = set()
    for unit in units:
        if callable(unit_is_covered):
            try:
                matched = unit_is_covered(unit, tokens, fn_precise, unique_file_keys)
            except Exception:
                matched = _unit_is_covered_local(
                    unit, tokens, fn_precise, unique_file_keys,
                )
        else:
            matched = _unit_is_covered_local(unit, tokens, fn_precise, unique_file_keys)
        if matched:
            out.add(unit)
    return out


def _units_referenced_by_tokens(
    heatmap: Any | None,
    units: set[str],
    tokens: set[str],
    enum_detail: dict,
) -> set[str]:
    """Map detector or stale row references to concrete denominator units.

    For obligation rows, a file-level token means every in-scope function in
    that file needs a hunt seed. This differs from coverage credit, where a
    file-only token is not precise enough to cover function units.
    """
    out = _units_for_tokens(heatmap, units, tokens, enum_detail)
    fn_precise_files = {
        token.split("::", 1)[0] for token in tokens if "::" in token
    }
    fn_precise_basenames = {Path(token).name for token in fn_precise_files}
    file_tokens = {
        token for token in tokens
        if "::" not in token
        and token not in fn_precise_files
        and Path(token).name not in fn_precise_basenames
    }
    for unit in units:
        if _unit_file_key(unit) in file_tokens or _unit_basename(unit) in file_tokens:
            out.add(unit)
    return out


def _collect_scanned_tokens(heatmap: Any | None, ws_path: Path | None) -> set[str]:
    if heatmap is None or ws_path is None or not ws_path.is_dir():
        return set()
    tokens: set[str] = set()
    mega_harvester = getattr(heatmap, "_harvest_mega_mimo_anchor_tokens", None)
    if callable(mega_harvester):
        before = set(tokens)
        try:
            mega_harvester(ws_path.name, tokens, workspace_path=ws_path)
        except Exception:
            tokens = before
    sidecars = ws_path / "hunt_findings_sidecars"
    json_harvester = getattr(heatmap, "_harvest_json_tokens", None)
    if sidecars.is_dir() and callable(json_harvester):
        for path in sorted(sidecars.glob("*.json")):
            before = set(tokens)
            try:
                json_harvester(path, tokens)
            except Exception:
                tokens = before
    for rel_dir in SCANNED_REVIEW_DIRS:
        review_dir = ws_path / rel_dir
        if not review_dir.is_dir():
            continue
        for path in sorted(review_dir.rglob("*.json")):
            tokens.update(_review_tokens_from_json(path))
    for fn_name in (
        "_harvest_submission_draft_tokens",
        "_harvest_agent_artifact_tokens",
    ):
        harvester = getattr(heatmap, fn_name, None)
        if not callable(harvester):
            continue
        before = set(tokens)
        try:
            harvester(ws_path, tokens)
        except Exception:
            tokens = before
    return tokens


def _read_skip_log(ws_path: Path | None) -> dict[str, str]:
    if ws_path is None:
        return {}
    path = ws_path / DEFAULT_SKIP_LOG_REL
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, OSError):
        return {}
    out: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        token = parts[0].strip()
        if not token:
            continue
        reason = parts[1].strip() if len(parts) > 1 else "missing skip-log reason"
        out[token] = reason
    return out


def _report_skipped_record(record: Any) -> tuple[str, str] | None:
    if isinstance(record, str):
        unit = record.strip()
        return (unit, REPORT_SKIP_REASON) if unit else None
    if not isinstance(record, dict):
        return None
    in_scope = record.get("in_scope")
    if isinstance(in_scope, bool) and not in_scope:
        return None
    unit = (
        record.get("unit_id") or record.get("source_unit")
        or record.get("unit") or record.get("target_unit")
    )
    if isinstance(unit, str) and unit.strip():
        unit_s = unit.strip()
    else:
        file_ref = (
            record.get("file") or record.get("source_file")
            or record.get("path") or record.get("contract")
        )
        fn_name = (
            record.get("function") or record.get("function_name")
            or record.get("fn") or record.get("method")
        )
        if not isinstance(file_ref, str) or not file_ref.strip():
            return None
        file_s = _normalise_source_ref(file_ref) or ""
        if isinstance(fn_name, str) and fn_name.strip():
            unit_s = "%s::%s" % (file_s, fn_name.strip().split("(", 1)[0].strip())
        else:
            unit_s = file_s
    reason = (
        record.get("skip_reason") or record.get("reason")
        or record.get("why") or REPORT_SKIP_REASON
    )
    reason_s = str(reason).strip() if reason is not None else REPORT_SKIP_REASON
    return unit_s, reason_s or REPORT_SKIP_REASON


def _report_skipped_targets(report: dict) -> dict[str, str]:
    fields = (
        "skipped_units", "skipped_in_scope_units", "skipped_functions",
        "skipped_in_scope_functions", "skipped_source_units",
    )
    out: dict[str, str] = {}
    for field in fields:
        raw = report.get(field)
        if isinstance(raw, dict):
            for unit, reason in raw.items():
                if unit:
                    out[str(unit)] = str(reason or REPORT_SKIP_REASON)
        elif isinstance(raw, list):
            for item in raw:
                parsed = _report_skipped_record(item)
                if parsed:
                    out[parsed[0]] = parsed[1]
    skip_logged = report.get("skip_logged_reasons")
    if isinstance(skip_logged, dict):
        for unit, reason in skip_logged.items():
            if unit:
                out[str(unit)] = str(reason or SKIP_LOG_REASON)
    return out


def _add_target(targets: dict[str, str], unit: str, reason: str) -> None:
    unit = str(unit or "").strip()
    if not unit:
        return
    reason = str(reason or UNCOVERED_SKIP_REASON).strip() or UNCOVERED_SKIP_REASON
    existing = targets.get(unit)
    if existing is None or existing == UNCOVERED_SKIP_REASON:
        targets[unit] = reason


def _build_target_reasons(
    report: dict,
    queue_path: Path,
    workspace_path: Path | None,
) -> tuple[dict[str, str], dict[str, int]]:
    targets: dict[str, str] = {}
    uncovered_units = [str(unit) for unit in report.get("uncovered_units", [])]
    for unit in uncovered_units:
        _add_target(targets, unit, UNCOVERED_SKIP_REASON)

    heatmap, live_units, enum_detail = _enumerate_live_units(workspace_path)
    for unit, reason in _report_skipped_targets(report).items():
        if live_units:
            for live_unit in live_units:
                if _unit_matches_token(live_unit, unit):
                    _add_target(targets, live_unit, reason)
        else:
            _add_target(targets, unit, reason)

    skip_log = _read_skip_log(workspace_path)
    if skip_log:
        if live_units:
            for unit in live_units:
                for token, reason in skip_log.items():
                    if _unit_matches_token(unit, token):
                        _add_target(targets, unit, reason)
        else:
            for token, reason in skip_log.items():
                _add_target(targets, token, reason)

    valid_queue_tokens, invalid_by_reason = _collect_queue_token_sets(queue_path)
    scanned_tokens = _collect_scanned_tokens(heatmap, workspace_path)
    valid_units = _units_for_tokens(
        heatmap, live_units, valid_queue_tokens | scanned_tokens, enum_detail,
    )
    invalid_counts: dict[str, int] = {}
    for reason, tokens in invalid_by_reason.items():
        invalid_units = _units_referenced_by_tokens(
            heatmap, live_units, tokens, enum_detail,
        )
        invalid_counts[reason] = len(invalid_units)
        for unit in sorted(invalid_units - valid_units):
            _add_target(targets, unit, reason)

    return targets, invalid_counts


def seed_from_report(
    report: dict,
    queue_path: Path,
    dry_run: bool,
    workspace_path: Path | None = None,
    run_id: str = "",
) -> dict:
    """UPSERT one unhunted-surface row per actionable coverage gap.

    Existing foreign rows (corpus-hunt, preflight, real hunt hits) are
    preserved untouched; unhunted-surface rows are deduped and idempotently
    re-written. Detector-only and stale queue rows are treated as obligations,
    not coverage.
    """
    workspace_path = _report_workspace_path(report, fallback=workspace_path)
    workspace_name = (
        report.get("workspace_name")
        or (workspace_path.name if workspace_path is not None else "")
        or Path(report.get("workspace", "")).name
    )
    uncovered_units = list(report.get("uncovered_units", []))
    true_uncovered = int(report.get("uncovered", len(uncovered_units)))

    # Hard guard against silent truncation: the inlined list MUST equal the
    # true count, or we refuse to proceed (the caller should have rebuilt).
    if report.get("uncovered_units_truncated") or len(uncovered_units) != true_uncovered:
        raise RuntimeError(
            "coverage report is truncated (%d inlined vs %d true uncovered); "
            "rebuild with --uncovered-list-cap -1 before seeding"
            % (len(uncovered_units), true_uncovered)
        )

    source_root = (report.get("enumeration") or {}).get("source_root", "")
    target_reasons, invalid_counts = _build_target_reasons(
        report, queue_path, workspace_path,
    )

    queue_data = _load_exploit_queue(queue_path, workspace_name)
    existing_rows = list(queue_data.get("queue", []))
    # PRUNE stale OOS unhunted-surface rows (L8 scope-bleed, 2026-06-30): the seed
    # enumeration is now scope-filtered (_enumerate_live_units intersects with the
    # in-scope manifest), but UPSERT preserves rows from a prior UNSCOPED build, so
    # OOS rows would persist forever (Strata: 447 OOS rows survived a re-seed). Drop
    # unhunted-surface rows whose file is not in the in-scope manifest; FOREIGN
    # sources (corpus-hunt / preflight / real hunt hits) are preserved untouched.
    _inscope_bases = _inscope_file_bases(workspace_path) if workspace_path else set()
    if _inscope_bases:
        existing_rows = [
            r for r in existing_rows
            if str(r.get("source") or "") != UNHUNTED_SURFACE_SOURCE
            or str(r.get("file") or "").rsplit("/", 1)[-1] in _inscope_bases
        ]
    existing_index = {_dedup_key(r): i for i, r in enumerate(existing_rows)}

    written = 0
    updated = 0
    seeded_units = []
    seeded_targets = []
    for unit in sorted(target_reasons):
        file_key, _fn = _unit_parts(unit)
        skip_reason = target_reasons[unit]
        sp = _unit_source_path(source_root, file_key, workspace_path)
        row = build_seed_row(
            workspace_name,
            unit,
            sp,
            skip_reason=skip_reason,
            run_id=run_id,
        )
        key = _dedup_key(row)
        seeded_units.append(unit)
        seeded_targets.append({
            "unit_id": unit,
            "file": row["file"],
            "function": row["function"],
            "source_path": sp,
            "skip_reason": skip_reason,
        })
        if key in existing_index:
            idx = existing_index[key]
            prev = existing_rows[idx]
            if prev.get("source") == UNHUNTED_SURFACE_SOURCE:
                existing_rows[idx] = row
                updated += 1
            # never clobber a foreign row that happens to collide
        else:
            existing_rows.append(row)
            existing_index[key] = len(existing_rows) - 1
            written += 1

    queue_data["queue"] = existing_rows
    queue_data["total_candidates"] = len(existing_rows)
    queue_data["generated_at_utc"] = _utc_now()
    consumed = queue_data.get("source_artifacts_consumed") or []
    if UNHUNTED_SURFACE_SOURCE not in consumed:
        consumed.append(UNHUNTED_SURFACE_SOURCE)
    queue_data["source_artifacts_consumed"] = consumed

    snapshot_written = False
    snapshot_path = ""
    if not dry_run:
        _atomic_write_json(queue_path, queue_data)
        snapshot_written, snapshot_path = _write_seed_snapshot(
            workspace_path=workspace_path,
            queue_path=queue_path,
            report=report,
            seeded_targets=seeded_targets,
            seeded_units=seeded_units,
            invalid_counts=invalid_counts,
            run_id=run_id,
        )

    return {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "run_id": run_id or None,
        "workspace": workspace_name,
        "queue_path": str(queue_path),
        "true_uncovered": true_uncovered,
        "seed_rows_total": len(seeded_units),
        "invalid_coverage_rows_reseeded": invalid_counts,
        "rows_written": written,
        "rows_updated": updated,
        "queue_total": len(existing_rows),
        "seeded_units": seeded_units,
        "seeded_targets": seeded_targets,
        "seed_snapshot_written": snapshot_written,
        "seed_snapshot_path": snapshot_path,
        "dry_run": dry_run,
        "verdict": ("pass-seeded" if (written or updated) else "pass-nothing-to-seed"),
    }


def seed_undriven_flows(ws_path: Path, queue_path: Path, *, dry_run: bool = False,
                        run_id: str = "") -> dict:
    """P2b: seed a per-flow hunt task for each UNDRIVEN cross-module business
    flow, so the canonical hunt drives the COMBINATION (not just each member in
    isolation). Reuses build_seed_row (the honest, claim-free target builder)
    for every member unit of an undriven flow, tagging it with flow_context so a
    hunter knows to test the cross-module flow. Idempotent (dedup by lead_id).
    Absent flow tooling -> no-op (never a false seed)."""
    try:
        import importlib.util as _il
        p = Path(__file__).resolve().parent / "business_flow_decompose.py"
        spec = _il.spec_from_file_location("business_flow_decompose", p)
        bf = _il.module_from_spec(spec)
        spec.loader.exec_module(bf)
        dec = bf.decompose(ws_path)
        cov = bf.coverage(ws_path, dec)
    except Exception:
        return {"flow_seed_rows": 0, "undriven_flows": 0}
    undriven = set(cov.get("undriven_flows") or [])
    if not undriven:
        return {"flow_seed_rows": 0, "undriven_flows": 0}
    by_id = {fl["flow_id"]: fl for fl in dec["flows"]}
    ws_name = ws_path.name
    existing = {_dedup_key(r) for r in _load_queue_rows(queue_path)}
    new_rows = []
    for flow_id in sorted(undriven):
        fl = by_id.get(flow_id) or {}
        members = fl.get("members") or []
        sibs = [m.split("::", 1)[-1] for m in members]
        for member in members:
            row = build_seed_row(ws_name, member, member.split("::", 1)[0],
                                 skip_reason="undriven-business-flow", run_id=run_id)
            row["flow_context"] = {"flow_id": flow_id, "flow_type": fl.get("flow_type", ""),
                                   "siblings": sibs}
            row["reason"] = (f"unhunted-surface: member of UNDRIVEN cross-module flow {flow_id} "
                             f"({fl.get('flow_type','')}); hunt the combination across {sibs}")
            if _dedup_key(row) not in existing:
                existing.add(_dedup_key(row))
                new_rows.append(row)
    if new_rows and not dry_run:
        try:
            data = json.loads(queue_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {"schema": EXPLOIT_QUEUE_SCHEMA, "queue": []}
        if isinstance(data, list):
            data = {"schema": EXPLOIT_QUEUE_SCHEMA, "queue": data}
        data.setdefault("queue", [])
        data["queue"].extend(new_rows)
        _atomic_write_json(queue_path, data)
    return {"flow_seed_rows": len(new_rows), "undriven_flows": len(undriven)}


def run(
    ws_path: Path,
    rebuild: bool,
    dry_run: bool,
    queue_path_override: str | None,
    run_id: str = "",
) -> dict:
    report = load_coverage_report(ws_path, rebuild=rebuild)
    queue_path = (Path(queue_path_override) if queue_path_override
                  else ws_path / EXPLOIT_QUEUE_REL)
    result = seed_from_report(
        report,
        queue_path,
        dry_run=dry_run,
        workspace_path=ws_path,
        run_id=run_id,
    )
    # P2b: also seed per-flow tasks for undriven cross-module business flows.
    flow_res = seed_undriven_flows(ws_path, queue_path, dry_run=dry_run, run_id=run_id)
    result["flow_seed_rows"] = flow_res["flow_seed_rows"]
    result["undriven_flows"] = flow_res["undriven_flows"]
    return result


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--workspace-path", required=True,
                   help="Absolute workspace PATH (contains .auditooor/).")
    p.add_argument("--rebuild-report", action="store_true",
                   help="Regenerate the coverage report (no cap) before seeding.")
    p.add_argument("--queue-path",
                   help="Override the exploit_queue.json path "
                        "(default <ws>/.auditooor/exploit_queue.json).")
    p.add_argument("--dry-run", action="store_true",
                   help="Compute seed rows but do not write the queue.")
    p.add_argument(
        "--run-id",
        default=os.environ.get("AUDITOOOR_AUDIT_RUN_FULL_ID", ""),
        help="Optional audit-run-full run id to bind the seed snapshot and queue rows.",
    )
    p.add_argument("--json", action="store_true", help="Emit verdict JSON to stdout.")
    args = p.parse_args(argv)

    ws_path = Path(args.workspace_path)
    if not ws_path.is_absolute():
        ws_path = (Path.cwd() / ws_path).resolve()
    if not ws_path.is_dir():
        print("error: workspace path not found: %s" % ws_path, file=sys.stderr)
        return 2

    result = run(ws_path, rebuild=args.rebuild_report, dry_run=args.dry_run,
                 queue_path_override=args.queue_path, run_id=args.run_id)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("%s: seeded %d unhunted-surface targets "
              "(%d new / %d refreshed), queue total %d%s"
              % (result["workspace"], result["seed_rows_total"],
                 result["rows_written"], result["rows_updated"],
                 result["queue_total"],
                 " [dry-run]" if result["dry_run"] else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
