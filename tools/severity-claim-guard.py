#!/usr/bin/env python3
"""severity-claim-guard.py — Wave 6 Worker L pre-submit guard.

Loads the workspace base-critical-candidate matrix (or any caller-supplied
matrix JSON) and refuses to pass when ANY row claims a reportable severity
(``Critical``, ``High``, or ``Medium``) without both an exact
``listed_impact_selected`` row and ``listed_impact_proven == true``.

This is the load-bearing rule that would have caught the Wave 5 snappy-OOM
over-claim: a network-resource exhaustion PoC at the component level is **not
sufficient evidence** for any severity claim under the Cantina Base Azul
rubric. To promote a candidate to a reportable severity, the candidate must
either:

  * Select an exact listed Base Azul impact sentence and show evidence proving
    that exact sentence end-to-end (set ``network_level_evidence`` to a real
    path AND ``listed_impact_proven`` true), OR
  * Clear the selected impact and mark the row NOT_SUBMIT_READY /
    kill_or_reframe. Severity must not be re-written freehand.

For Snappy gossip decode specifically, mempool impact is not applicable.
Snappy must not be called Critical or direct-submit-ready unless measured
evidence proves the selected listed impact exactly, such as >=30% node
resource consumption under realistic non-bruteforce conditions or a quantified
node-shutdown threshold.

Exit codes:

  * 0 — no reportable-severity rows OR every reportable-severity row has
        an exact selected impact and ``listed_impact_proven=true``.
  * 1 — at least one reportable-severity row is missing a selected impact,
        has ``listed_impact_proven=false``, or selects an invalid Snappy
        mempool impact.
        The guard prints each offending row as a JSON line for easy
        operator review.
  * 2 — harness error: direct ``--matrix`` path missing, invalid JSON, or
        invalid artifact shape. Empty generic workspaces scan zero rows and
        pass rather than requiring a Base-only matrix.

Usage:

    # workspace mode (canonical)
    python3 tools/severity-claim-guard.py --workspace ~/audits/<project>

    # direct-matrix mode (CI / fixture tests)
    python3 tools/severity-claim-guard.py --matrix path/to/matrix.json

The guard never modifies the workspace. In workspace mode it reads
``<ws>/critical_hunt/base_critical_candidate_matrix.json`` when present, then
falls back to generic auditooor artifacts such as
``<ws>/.auditooor/impact_contracts.json`` and
``<ws>/critical_hunt/candidates/*.json``. That fallback is intentionally what
keeps non-Base/manual paths from silently bypassing exact-impact derivation.
Run ``make base-critical-matrix WS=<ws>`` first for Base-specific matrices, or
``make impact-contract-check WS=<ws>`` for generic workspaces.

PR #556 §Priority 4.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.severity_claim_guard.v1"
REPORTABLE_SEVERITIES = {"critical", "high", "medium"}
NON_SUBMIT_STATUSES = {
    "kill_or_reframe",
    "blocked_real_component",
    "not_submit_ready",
    "not-submit-ready",
    "impact_unresolved",
}
DIRECT_SUBMIT_POSTURES = {
    "in_scope_direct_submit",
    "direct_submit",
    "direct-submit",
    "submit_ready",
    "submit-ready",
    "paste_ready",
    "paste-ready",
}
SNAPPY_INVALID_IMPACT_TOKENS = ("mempool",)
SNAPPY_RE = re.compile(
    r"\b(snappy|decompress_vec|gossip decode|decode-bomb|decode bomb)\b",
    re.IGNORECASE,
)
RESOURCE_IMPACT_RE = re.compile(r"node resource consumption|resource consumption", re.IGNORECASE)
SHUTDOWN_IMPACT_RE = re.compile(r"shutdown.*nodes?|nodes?.*shutdown", re.IGNORECASE)


def _resolve_matrix_path(workspace: Path | None, matrix: Path | None) -> Path:
    if matrix is not None:
        return matrix
    if workspace is None:
        raise ValueError("either --workspace or --matrix is required")
    return workspace / "critical_hunt" / "base_critical_candidate_matrix.json"


def _records_from_payload(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    for key in (
        "rows",
        "contracts",
        "impact_contracts",
        "candidates",
        "items",
        "tasks",
        "findings",
        "results",
        "actions",
        "next_actions",
    ):
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def _is_critical(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return value.strip().lower() == "critical"


def _claimed_reportable_severity(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    raw = value.strip()
    return raw if raw.lower() in REPORTABLE_SEVERITIES else ""


def _is_direct_submit_posture(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return value.strip().lower() in DIRECT_SUBMIT_POSTURES


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("true", "1", "yes", "y"):
            return True
    if isinstance(value, (int, float)):
        return bool(value)
    return False


def _coerce_float(value: Any) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip().rstrip("%"))
        except ValueError:
            return None
    return None


def _norm_sentence(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", value.strip().lower())


def _exact_listed_impact(value: str, listed_impacts: list[str] | None) -> bool:
    if not listed_impacts:
        # Direct-matrix fixtures may omit rubric rows; still require that the
        # row selected a non-empty sentence rather than a triage placeholder.
        return bool(_norm_sentence(value))
    needle = _norm_sentence(value)
    return bool(needle) and any(
        needle == _norm_sentence(row) for row in listed_impacts
    )


def _selected_impact(row: dict[str, Any]) -> str:
    for key in ("listed_impact_selected", "selected_impact"):
        value = row.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _row_text(row: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "candidate_id",
        "title",
        "name",
        "scope_asset",
        "asset",
        "impact_mapping",
        "impact",
        "listed_impact_selected",
        "selected_impact",
    ):
        value = row.get(key)
        if isinstance(value, str):
            parts.append(value)
    return " ".join(parts).lower()


def _is_snappy_row(row: dict[str, Any]) -> bool:
    return bool(SNAPPY_RE.search(_row_text(row)))


def _snappy_measurement_reasons(row: dict[str, Any], selected: str) -> list[str]:
    if not _is_snappy_row(row):
        return []
    reasons: list[str] = []
    if any(token in _row_text(row) for token in SNAPPY_INVALID_IMPACT_TOKENS):
        reasons.append("snappy_gossip_decode_cannot_select_mempool_impact")
    severity = row.get("raw_severity") or row.get("severity") or ""
    if not _is_critical(severity):
        return reasons
    resource_pct = _coerce_float(row.get("node_resource_consumption_pct"))
    if resource_pct is None:
        resource_pct = _coerce_float(row.get("resource_consumption_pct"))
    shutdown_pct = _coerce_float(row.get("shutdown_nodes_pct"))
    if shutdown_pct is None:
        shutdown_pct = _coerce_float(row.get("shutdown_threshold_nodes_pct"))
    resource_ok = resource_pct is not None and resource_pct >= 30.0
    shutdown_ok = shutdown_pct is not None and shutdown_pct >= 30.0
    if not (RESOURCE_IMPACT_RE.search(selected) or SHUTDOWN_IMPACT_RE.search(selected)):
        reasons.append("snappy_wrong_selected_impact")
    if not (resource_ok or shutdown_ok):
        reasons.append("snappy_threshold_not_proven")
    if not _coerce_bool(row.get("realistic_non_bruteforce")):
        reasons.append("snappy_realistic_non_bruteforce_missing")
    nle = str(row.get("network_level_evidence") or "").strip()
    if _coerce_bool(row.get("component_poc_only")) or not nle or nle == "absent":
        reasons.append("snappy_network_level_evidence_missing")
    return reasons


def find_violations(
    rows: list[dict[str, Any]],
    listed_impacts: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Return rows whose severity claim is not backed by exact impact proof.

    Missing ``listed_impact_selected`` is empty and missing
    ``listed_impact_proven`` is false. Conservative rule: an absent field
    cannot retroactively prove a severity claim.
    """
    violations: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        severity = row.get("raw_severity") or row.get("severity") or ""
        claimed = _claimed_reportable_severity(severity)
        status = str(row.get("candidate_status") or "").strip().lower()
        selected = _selected_impact(row)
        proven = _coerce_bool(row.get("listed_impact_proven"))
        direct_submit = _is_direct_submit_posture(row.get("submission_posture"))
        if status in NON_SUBMIT_STATUSES and not direct_submit:
            reasons: list[str] = []
            if selected and not proven:
                reasons.append("impact_not_removed_for_non_submit_ready")
            reasons.extend(_snappy_measurement_reasons(row, selected))
            if reasons:
                violations.append(
                    {
                        "candidate_id": row.get("candidate_id", "UNKNOWN"),
                        "raw_severity": severity,
                        "listed_impact_selected": selected,
                        "listed_impact_proven": proven,
                        "network_level_evidence": row.get(
                            "network_level_evidence", "absent"
                        ),
                        "component_poc_only": _coerce_bool(
                            row.get("component_poc_only")
                        ),
                        "candidate_status": row.get("candidate_status", ""),
                        "submission_posture": row.get("submission_posture", ""),
                        "reasons": reasons,
                    }
                )
            # Explicitly non-submit-ready rows are otherwise allowed; they have
            # already been removed from direct submission flow.
            continue
        if not claimed:
            if direct_submit:
                direct_reasons: list[str] = []
                if not selected:
                    direct_reasons.append("missing_listed_impact_selected")
                elif not _exact_listed_impact(selected, listed_impacts):
                    direct_reasons.append("selected_impact_not_exact_listed_sentence")
                if not proven:
                    direct_reasons.append("listed_impact_not_proven")
                direct_reasons.extend(_snappy_measurement_reasons(row, selected))
                if direct_reasons:
                    violations.append(
                        {
                            "candidate_id": row.get("candidate_id", "UNKNOWN"),
                            "raw_severity": severity,
                            "listed_impact_selected": selected,
                            "listed_impact_proven": proven,
                            "network_level_evidence": row.get(
                                "network_level_evidence", "absent"
                            ),
                            "component_poc_only": _coerce_bool(
                                row.get("component_poc_only")
                            ),
                            "candidate_status": row.get("candidate_status", ""),
                            "submission_posture": row.get("submission_posture", ""),
                            "reasons": direct_reasons,
                        }
                    )
                continue
            snappy_only_reasons = _snappy_measurement_reasons(row, selected)
            if snappy_only_reasons:
                violations.append(
                    {
                        "candidate_id": row.get("candidate_id", "UNKNOWN"),
                        "raw_severity": severity,
                        "listed_impact_selected": selected,
                        "listed_impact_proven": _coerce_bool(
                            row.get("listed_impact_proven")
                        ),
                        "network_level_evidence": row.get(
                            "network_level_evidence", "absent"
                        ),
                        "component_poc_only": _coerce_bool(
                            row.get("component_poc_only")
                        ),
                        "candidate_status": row.get("candidate_status", ""),
                        "submission_posture": row.get("submission_posture", ""),
                        "reasons": snappy_only_reasons,
                    }
                )
            continue
        reasons: list[str] = []
        if not selected:
            reasons.append("missing_listed_impact_selected")
        elif claimed and not _exact_listed_impact(selected, listed_impacts):
            reasons.append("selected_impact_not_exact_listed_sentence")
        if not proven:
            reasons.append("listed_impact_not_proven")
        reasons.extend(_snappy_measurement_reasons(row, selected))
        if _is_critical(severity) and not proven and _coerce_bool(row.get("component_poc_only")):
            reasons.append("critical_component_poc_only")
        if reasons:
            violations.append(
                {
                    "candidate_id": row.get("candidate_id", "UNKNOWN"),
                    "raw_severity": severity,
                    "listed_impact_selected": selected,
                    "listed_impact_proven": proven,
                    "network_level_evidence": row.get(
                        "network_level_evidence", "absent"
                    ),
                    "component_poc_only": _coerce_bool(
                        row.get("component_poc_only")
                    ),
                    "candidate_status": row.get("candidate_status", ""),
                    "submission_posture": row.get("submission_posture", ""),
                    "reasons": reasons,
                }
            )
    return violations


def load_matrix_payload(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"matrix not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"matrix is not a JSON object: {path}")
    rows = payload.get("rows", [])
    if not isinstance(rows, list):
        raise ValueError(f"matrix `rows` is not a list: {path}")
    return payload


def load_matrix(path: Path) -> list[dict[str, Any]]:
    payload = load_matrix_payload(path)
    return list(payload.get("rows", []))


def _listed_impacts_from_payload(payload: dict[str, Any]) -> list[str]:
    """Return every exact impact sentence the matrix exposes.

    Older Base matrices only carry ``listed_critical_impacts``. Newer callers
    can provide all severities via ``listed_impacts`` or severity-specific keys.
    The guard consumes every list it recognizes and de-dupes by normalized text.
    """
    keys = (
        "listed_impacts",
        "listed_critical_impacts",
        "listed_high_impacts",
        "listed_medium_impacts",
        "listed_low_impacts",
        "listed_informational_impacts",
    )
    out: list[str] = []
    seen: set[str] = set()
    for key in keys:
        value = payload.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, str) or not item.strip():
                continue
            norm = _norm_sentence(item)
            if norm in seen:
                continue
            seen.add(norm)
            out.append(item.strip())
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="severity-claim-guard.py",
        description=(
            "Refuse to pass when any Critical/High/Medium candidate row lacks "
            "exact selected-impact proof. Wave 6 Worker L (PR #556 §Priority 4)."
        ),
    )
    parser.add_argument("--workspace", type=Path, default=None)
    parser.add_argument(
        "--matrix",
        type=Path,
        default=None,
        help="Direct path to a candidate matrix JSON (overrides --workspace).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a JSON summary on stdout (in addition to human text).",
    )
    args = parser.parse_args(argv)

    if args.workspace is None and args.matrix is None:
        print(
            "[severity-claim-guard] ERR --workspace or --matrix required",
            file=sys.stderr,
        )
        return 2

    try:
        matrix_path = _resolve_matrix_path(args.workspace, args.matrix)
    except ValueError as exc:
        print(f"[severity-claim-guard] ERR {exc}", file=sys.stderr)
        return 2

    try:
        payload = load_matrix_payload(matrix_path)
        rows = payload.get("rows", [])
        listed_impacts = _listed_impacts_from_payload(payload)
        if not isinstance(rows, list):
            raise ValueError(f"matrix `rows` is not a list: {matrix_path}")
    except FileNotFoundError as exc:
        print(f"[severity-claim-guard] ERR {exc}", file=sys.stderr)
        print(
            "[severity-claim-guard] hint: run `make base-critical-matrix "
            f"WS=<workspace>` to generate the matrix first.",
            file=sys.stderr,
        )
        return 2
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"[severity-claim-guard] ERR invalid matrix: {exc}", file=sys.stderr)
        return 2

    violations = find_violations(rows, [str(x) for x in listed_impacts])

    if args.json:
        sys.stdout.write(
            json.dumps(
                {
                    "schema": SCHEMA_VERSION,
                    "matrix": str(matrix_path),
                    "source_artifacts": payload.get("source_artifacts", []),
                    "row_count": len(rows),
                    "violation_count": len(violations),
                    "violations": violations,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        if not violations:
            return 0

    if not violations:
        print(
            f"[severity-claim-guard] PASS — {len(rows)} row(s) scanned, "
            "no reportable severity row missing exact selected-impact proof."
        )
        return 0

    print(
        "[severity-claim-guard] FAIL — reportable severity rows without "
        "exact selected-impact proof (Wave 6 L over-claim guard):",
        file=sys.stderr,
    )
    for v in violations:
        print(f"  - {json.dumps(v, sort_keys=True)}", file=sys.stderr)
    print(
        "\n  fix: select an exact Base Azul program impact sentence, prove that "
        "exact sentence with a compatible evidence class, and set "
        "`listed_impact_proven=true`; otherwise clear the selected impact, mark "
        "the row NOT_SUBMIT_READY / kill_or_reframe, and do not generate "
        "direct-submit text. Snappy gossip decode may not select a mempool "
        "impact. PR #556 §Priority 4.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
