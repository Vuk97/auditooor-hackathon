#!/usr/bin/env python3
"""Compute a conservative P3 TP-PoC-PASS baseline.

This tool joins existing candidate, source-proof, impact-contract, live-target,
and PoC execution artifacts to P3 anti-pattern IDs when the artifact itself
contains an explicit catalog ``pattern_id`` or when a local semantic attribution
sidecar explicitly maps the candidate to a catalog pattern with
``attribution_status=accepted_by_local_review``. Live-target P5
``matched_anti_patterns`` rows and suggested/category-only sidecar rows are
retained as non-semantic attribution hints only; they do not count as semantic
true positives.

Schema: ``auditooor.p3_tp_poc_pass_measure.v1``.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.p3_tp_poc_pass_measure.v2"
REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG_ROOT = REPO_ROOT / "obsidian-vault" / "anti-patterns" / "v2"
DEFAULT_SEMANTIC_ATTRIBUTION_SIDECAR = "p3_semantic_attribution_sidecar.json"


def _load_catalog_tool() -> Any:
    tool = REPO_ROOT / "tools" / "antipattern-catalog-build.py"
    spec = importlib.util.spec_from_file_location("antipattern_catalog_build", tool)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _read_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc


def _iter_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _iter_strings(v)


def _candidate_id_from_record(record: dict[str, Any]) -> str | None:
    for key in ("candidate_id", "lead_id", "row_id", "id"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _rel(path: str | Path, base: Path) -> str:
    p = Path(path)
    if not p.is_absolute():
        return str(p)
    try:
        return str(p.relative_to(base))
    except ValueError:
        return str(p)


def _manifest_passed_poc(manifest: dict[str, Any]) -> bool:
    if manifest.get("final_result") != "proved":
        return False
    if manifest.get("impact_assertion") != "exploit_impact":
        return False
    commands = manifest.get("commands_attempted") or []
    return any(
        isinstance(cmd, dict)
        and cmd.get("status") == "pass"
        and cmd.get("exit_code") == 0
        for cmd in commands
    )


def _proved_source_verdict(verdict: Any) -> bool:
    return isinstance(verdict, str) and verdict.startswith("proved")


@dataclass
class Attribution:
    pattern_id: str
    basis: str
    semantic_tp_eligible: bool
    source: str


@dataclass
class Candidate:
    candidate_id: str
    artifact_sources: set[str] = field(default_factory=set)
    attributions: dict[tuple[str, str], Attribution] = field(default_factory=dict)
    source_verdicts: list[str] = field(default_factory=list)
    impact_contract_listed_impact_proven: bool = False
    poc_execution_manifest: str | None = None
    poc_final_result: str | None = None
    poc_impact_assertion: str | None = None
    poc_pass: bool = False
    notes: list[str] = field(default_factory=list)

    def add_attribution(self, attribution: Attribution) -> None:
        self.attributions[(attribution.pattern_id, attribution.basis)] = attribution

    @property
    def semantic_attributed(self) -> bool:
        return any(a.semantic_tp_eligible for a in self.attributions.values())

    @property
    def has_any_attribution(self) -> bool:
        return bool(self.attributions)

    @property
    def has_tp_evidence(self) -> bool:
        return self.impact_contract_listed_impact_proven or any(
            _proved_source_verdict(v) for v in self.source_verdicts
        )

    @property
    def status(self) -> str:
        if self.semantic_attributed and self.has_tp_evidence:
            return "semantic_tp_attributed"
        if self.has_tp_evidence and not self.semantic_attributed:
            return "unknown_unattributed_tp_evidence"
        if self.has_any_attribution and not self.semantic_attributed:
            return "category_join_only_not_semantic_tp"
        return "unknown_unattributed"

    def to_json(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "artifact_sources": sorted(self.artifact_sources),
            "pattern_attributions": [
                {
                    "pattern_id": a.pattern_id,
                    "basis": a.basis,
                    "semantic_tp_eligible": a.semantic_tp_eligible,
                    "source": a.source,
                }
                for a in sorted(
                    self.attributions.values(),
                    key=lambda x: (x.pattern_id, x.basis, x.source),
                )
            ],
            "tp_evidence": self.has_tp_evidence,
            "tp_status": self.status,
            "source_verdicts": sorted(set(self.source_verdicts)),
            "impact_contract_listed_impact_proven": self.impact_contract_listed_impact_proven,
            "poc_execution_manifest": self.poc_execution_manifest,
            "poc_final_result": self.poc_final_result,
            "poc_impact_assertion": self.poc_impact_assertion,
            "poc_pass": self.poc_pass,
            "notes": self.notes,
        }


def _candidate(candidates: dict[str, Candidate], candidate_id: str) -> Candidate:
    if candidate_id not in candidates:
        candidates[candidate_id] = Candidate(candidate_id=candidate_id)
    return candidates[candidate_id]


def _attach_explicit_pattern_ids(
    cand: Candidate,
    *,
    artifact: Any,
    known_pattern_ids: set[str],
    source: str,
) -> None:
    text = "\n".join(_iter_strings(artifact))
    for pid in sorted(known_pattern_ids):
        if pid in text:
            cand.add_attribution(
                Attribution(
                    pattern_id=pid,
                    basis="explicit_pattern_id_in_artifact",
                    semantic_tp_eligible=True,
                    source=source,
                )
            )


def _add_record_artifact(
    candidates: dict[str, Candidate],
    *,
    record: dict[str, Any],
    source: str,
    known_pattern_ids: set[str],
) -> None:
    candidate_id = _candidate_id_from_record(record)
    if not candidate_id:
        return
    cand = _candidate(candidates, candidate_id)
    cand.artifact_sources.add(source)
    _attach_explicit_pattern_ids(
        cand,
        artifact=record,
        known_pattern_ids=known_pattern_ids,
        source=source,
    )
    verdict = record.get("final_verdict") or record.get("source_mined_proof_status")
    if isinstance(verdict, str) and verdict:
        cand.source_verdicts.append(verdict)
    if record.get("listed_impact_proven") is True:
        cand.impact_contract_listed_impact_proven = True


def _load_queue_artifacts(
    candidates: dict[str, Candidate],
    *,
    workspace: Path,
    known_pattern_ids: set[str],
) -> list[str]:
    consumed: list[str] = []
    aud = workspace / ".auditooor"
    queue_paths = [
        aud / "exploit_queue.json",
        aud / "exploit_queue.source_mined.json",
    ]
    contract_paths = [
        aud / "impact_contracts.json",
        aud / "prove_top_leads_source_mined_impact_contracts.json",
    ]
    for path in queue_paths:
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        consumed.append(str(path))
        for row in data.get("queue") or []:
            if isinstance(row, dict):
                _add_record_artifact(
                    candidates,
                    record=row,
                    source=str(path),
                    known_pattern_ids=known_pattern_ids,
                )
    for path in contract_paths:
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        consumed.append(str(path))
        for row in data.get("contracts") or []:
            if isinstance(row, dict):
                _add_record_artifact(
                    candidates,
                    record=row,
                    source=str(path),
                    known_pattern_ids=known_pattern_ids,
                )
    for path in sorted(aud.glob("field_manifest_links*.json")):
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        consumed.append(str(path))
        for row in data.get("rows") or []:
            if isinstance(row, dict):
                _add_record_artifact(
                    candidates,
                    record=row,
                    source=str(path),
                    known_pattern_ids=known_pattern_ids,
                )
    return consumed


def _load_source_proofs(
    candidates: dict[str, Candidate],
    *,
    workspace: Path,
    known_pattern_ids: set[str],
) -> list[str]:
    consumed: list[str] = []
    root = workspace / "source_proofs"
    if not root.is_dir():
        return consumed
    for path in sorted(root.glob("*/source_proof.json")):
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        consumed.append(str(path))
        _add_record_artifact(
            candidates,
            record=data,
            source=str(path),
            known_pattern_ids=known_pattern_ids,
        )
    return consumed


def _load_poc_manifests(
    candidates: dict[str, Candidate],
    *,
    poc_execution_root: Path,
    known_pattern_ids: set[str],
) -> list[str]:
    consumed: list[str] = []
    if not poc_execution_root.is_dir():
        return consumed
    for path in sorted(poc_execution_root.glob("*/execution_manifest.json")):
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        consumed.append(str(path))
        candidate_id = data.get("candidate_id") or path.parent.name
        if not isinstance(candidate_id, str) or not candidate_id:
            continue
        cand = _candidate(candidates, candidate_id)
        cand.artifact_sources.add(str(path))
        cand.poc_execution_manifest = str(path)
        if isinstance(data.get("final_result"), str):
            cand.poc_final_result = data["final_result"]
        if isinstance(data.get("impact_assertion"), str):
            cand.poc_impact_assertion = data["impact_assertion"]
        cand.poc_pass = _manifest_passed_poc(data)
        _attach_explicit_pattern_ids(
            cand,
            artifact=data,
            known_pattern_ids=known_pattern_ids,
            source=str(path),
        )
    return consumed


def _sidecar_rows(data: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("mappings", "rows", "attributions"):
        rows = data.get(key)
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    return []


def _is_nonsemantic_sidecar_row(row: dict[str, Any]) -> bool:
    if row.get("suggested_only") is True or row.get("category_only") is True:
        return True
    for key in ("basis", "attribution_type", "evidence_class", "status"):
        value = row.get(key)
        if isinstance(value, str) and value in {"suggested_only", "category_only"}:
            return True
    return False


def _load_semantic_attribution_sidecars(
    candidates: dict[str, Candidate],
    *,
    sidecar_paths: list[Path],
    workspace: Path,
    known_pattern_ids: set[str],
) -> list[str]:
    consumed: list[str] = []
    for path in sidecar_paths:
        path = path.expanduser()
        if not path.is_absolute():
            path = workspace / path
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        consumed.append(str(path))
        for row in _sidecar_rows(data):
            candidate_id = row.get("candidate_id")
            pattern_id = row.get("p3_pattern_id") or row.get("pattern_id")
            if not isinstance(candidate_id, str) or not candidate_id.strip():
                continue
            if not isinstance(pattern_id, str) or pattern_id not in known_pattern_ids:
                continue
            attribution_status = row.get("attribution_status")
            semantic = (
                attribution_status == "accepted_by_local_review"
                and not _is_nonsemantic_sidecar_row(row)
            )
            cand = _candidate(candidates, candidate_id.strip())
            cand.artifact_sources.add(str(path))
            if isinstance(row.get("evidence"), str) and row["evidence"].strip():
                cand.notes.append(f"semantic sidecar evidence: {row['evidence'].strip()}")
            cand.add_attribution(
                Attribution(
                    pattern_id=pattern_id,
                    basis=(
                        "local_semantic_attribution_sidecar"
                        if semantic
                        else "sidecar_nonsemantic_hint"
                    ),
                    semantic_tp_eligible=semantic,
                    source=str(path),
                )
            )
    return consumed


def _load_live_target_reports(
    candidates: dict[str, Candidate],
    *,
    live_target_reports: list[Path],
    workspace: Path,
    known_pattern_ids: set[str],
) -> tuple[list[str], list[dict[str, Any]]]:
    consumed: list[str] = []
    summaries: list[dict[str, Any]] = []
    for path in live_target_reports:
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        if Path(str(data.get("workspace", ""))).expanduser() != workspace:
            summaries.append({
                "path": str(path),
                "status": "skipped_workspace_mismatch",
                "workspace": data.get("workspace"),
            })
            continue
        consumed.append(str(path))
        entries = [e for e in data.get("entry_points") or [] if isinstance(e, dict)]
        real_match_count = 0
        sentinel_count = 0
        for entry in entries:
            pids = [
                pid for pid in entry.get("matched_anti_patterns") or []
                if isinstance(pid, str)
            ]
            real_pids = [
                pid for pid in pids
                if pid in known_pattern_ids and not pid.startswith("no-P3-match:")
            ]
            sentinel_count += len([pid for pid in pids if pid.startswith("no-P3-match:")])
            if not real_pids:
                continue
            real_match_count += len(real_pids)
            raw_id = f"{entry.get('cluster_id', '')}:{entry.get('file_line', '')}"
            digest = hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:12]
            cand = _candidate(candidates, f"p5-live-target:{digest}")
            cand.artifact_sources.add(str(path))
            cand.notes.append(
                "P5 live-target anti-pattern match is a cluster category join; "
                "not counted as semantic TP."
            )
            for pid in sorted(set(real_pids)):
                cand.add_attribution(
                    Attribution(
                        pattern_id=pid,
                        basis="p5_cluster_category_join",
                        semantic_tp_eligible=False,
                        source=str(path),
                    )
                )
        summaries.append({
            "path": str(path),
            "status": "consumed",
            "entry_point_count": len(entries),
            "real_p3_category_join_count": real_match_count,
            "no_p3_match_sentinel_count": sentinel_count,
        })
    return consumed, summaries


def build_measurement(
    *,
    workspace: Path,
    catalog_root: Path,
    poc_execution_root: Path,
    live_target_reports: list[Path],
    semantic_attribution_sidecars: list[Path] | None = None,
    engage_report: Path | None = None,
    submissions: Path | None = None,
) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    catalog_root = catalog_root.expanduser().resolve()
    poc_execution_root = poc_execution_root.expanduser().resolve()
    catalog_tool = _load_catalog_tool()
    catalog = catalog_tool.load_catalog(catalog_root)
    known_pattern_ids = {str(r["pattern_id"]) for r in catalog}

    candidates: dict[str, Candidate] = {}
    consumed: list[str] = []
    sidecars = list(semantic_attribution_sidecars or [])
    default_sidecar = workspace / ".auditooor" / DEFAULT_SEMANTIC_ATTRIBUTION_SIDECAR
    if default_sidecar not in sidecars:
        sidecars.append(default_sidecar)
    consumed.extend(
        _load_queue_artifacts(
            candidates,
            workspace=workspace,
            known_pattern_ids=known_pattern_ids,
        )
    )
    consumed.extend(
        _load_source_proofs(
            candidates,
            workspace=workspace,
            known_pattern_ids=known_pattern_ids,
        )
    )
    consumed.extend(
        _load_poc_manifests(
            candidates,
            poc_execution_root=poc_execution_root,
            known_pattern_ids=known_pattern_ids,
        )
    )
    consumed.extend(
        _load_semantic_attribution_sidecars(
            candidates,
            sidecar_paths=sidecars,
            workspace=workspace,
            known_pattern_ids=known_pattern_ids,
        )
    )
    live_consumed, live_summaries = _load_live_target_reports(
        candidates,
        live_target_reports=live_target_reports,
        workspace=workspace,
        known_pattern_ids=known_pattern_ids,
    )
    consumed.extend(live_consumed)

    rows = [c.to_json() for c in sorted(candidates.values(), key=lambda c: c.candidate_id)]
    semantic_tp_rows = [
        r for r in rows
        if r["tp_status"] == "semantic_tp_attributed"
    ]
    semantic_tp_poc_pass_rows = [
        r for r in semantic_tp_rows
        if r["poc_pass"] is True
    ]
    unknown_unattributed_tp_rows = [
        r for r in rows
        if r["tp_status"] == "unknown_unattributed_tp_evidence"
    ]
    category_join_rows = [
        r for r in rows
        if r["tp_status"] == "category_join_only_not_semantic_tp"
    ]
    unattributed_poc_pass_rows = [
        r for r in rows
        if r["poc_pass"] is True and r["tp_status"] != "semantic_tp_attributed"
    ]

    tp_count = len(semantic_tp_rows)
    pass_count = len(semantic_tp_poc_pass_rows)
    rate = (pass_count / tp_count) if tp_count else None

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "engage_report": str(engage_report.expanduser()) if engage_report else None,
        "submissions": str(submissions.expanduser()) if submissions else None,
        "catalog_root": str(catalog_root),
        "catalog_pattern_count": len(catalog),
        "artifact_policy": {
            "semantic_tp_rule": (
                "Only explicit P3 pattern IDs found in candidate/proof artifacts "
                "or accepted local semantic attribution sidecars are eligible "
                "for semantic TP attribution."
            ),
            "sidecar_semantic_attribution_rule": (
                "A sidecar row counts only when attribution_status is "
                "accepted_by_local_review and the row is not suggested-only "
                "or category-only."
            ),
            "p5_category_join_rule": (
                "P5 matched_anti_patterns are retained as category joins and do "
                "not count as semantic TP without separate proof attribution."
            ),
            "poc_pass_rule": (
                "PoC pass requires final_result=proved, "
                "impact_assertion=exploit_impact, and at least one passing command."
            ),
        },
        "summary": {
            "candidate_count": len(rows),
            "tp_evidence_count": tp_count,
            "poc_pass_count": pass_count,
            "tp_poc_pass_rate": rate,
            "tp_poc_pass_rate_state": "computed" if rate is not None else "unknown_no_semantic_tp_denominator",
            "unknown_unattributed_tp_evidence_count": len(unknown_unattributed_tp_rows),
            "category_join_only_count": len(category_join_rows),
            "unattributed_poc_pass_count": len(unattributed_poc_pass_rows),
            "pattern_attributed_candidate_count": len([
                r for r in rows if r["pattern_attributions"]
            ]),
            "semantic_pattern_attributed_candidate_count": len([
                r for r in rows
                if any(a["semantic_tp_eligible"] for a in r["pattern_attributions"])
            ]),
        },
        "live_target_reports": live_summaries,
        "consumed_artifacts": sorted(set(consumed)),
        "candidates": rows,
    }


def write_markdown(payload: dict[str, Any], path: Path) -> None:
    summary = payload["summary"]
    lines = [
        "# P3 TP-PoC-PASS Measurement",
        "",
        f"Workspace: `{payload['workspace']}`",
        f"Catalog patterns: `{payload['catalog_pattern_count']}`",
        "",
        "## Summary",
        "",
        "| metric | value |",
        "|---|---:|",
        f"| candidate_count | {summary['candidate_count']} |",
        f"| TP evidence count | {summary['tp_evidence_count']} |",
        f"| PoC pass count | {summary['poc_pass_count']} |",
        f"| TP-PoC-PASS rate | {summary['tp_poc_pass_rate'] if summary['tp_poc_pass_rate'] is not None else 'unknown'} |",
        f"| unknown/unattributed TP evidence | {summary['unknown_unattributed_tp_evidence_count']} |",
        f"| category-join-only rows | {summary['category_join_only_count']} |",
        f"| unattributed PoC passes | {summary['unattributed_poc_pass_count']} |",
        "",
        "## Interpretation",
        "",
        "- P5 `matched_anti_patterns` rows are category joins, not semantic TP evidence.",
        "- Unattributed proved source/PoC evidence is preserved separately and excluded from the semantic denominator.",
        "- A `unknown` rate means the tool found no semantic P3-attributed TP denominator.",
        "",
        "## Candidate Rows",
        "",
        "| candidate_id | tp_status | patterns | poc_pass | source_verdicts |",
        "|---|---|---|---:|---|",
    ]
    for row in payload["candidates"]:
        patterns = ", ".join(
            f"{a['pattern_id']} ({a['basis']})"
            for a in row["pattern_attributions"]
        ) or "unattributed"
        verdicts = ", ".join(row["source_verdicts"]) or ""
        lines.append(
            "| "
            + " | ".join([
                row["candidate_id"].replace("|", "\\|"),
                row["tp_status"],
                patterns.replace("|", "\\|"),
                "true" if row["poc_pass"] else "false",
                verdicts.replace("|", "\\|"),
            ])
            + " |"
        )
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--engage-report")
    parser.add_argument("--catalog-root", default=str(DEFAULT_CATALOG_ROOT))
    parser.add_argument("--submissions")
    parser.add_argument("--poc-execution-root")
    parser.add_argument(
        "--live-target-report-json",
        action="append",
        default=[],
        help="Optional P5 live-target JSON report. May be provided multiple times.",
    )
    parser.add_argument(
        "--semantic-attribution-sidecar",
        action="append",
        default=[],
        help=(
            "Optional candidate_id -> p3_pattern_id semantic attribution sidecar. "
            f"Defaults to .auditooor/{DEFAULT_SEMANTIC_ATTRIBUTION_SIDECAR} when present."
        ),
    )
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output", required=True, help="Markdown output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    workspace = Path(args.workspace)
    poc_root = Path(args.poc_execution_root) if args.poc_execution_root else workspace / "poc_execution"
    payload = build_measurement(
        workspace=workspace,
        engage_report=Path(args.engage_report) if args.engage_report else None,
        catalog_root=Path(args.catalog_root),
        submissions=Path(args.submissions) if args.submissions else None,
        poc_execution_root=poc_root,
        live_target_reports=[Path(p) for p in args.live_target_report_json],
        semantic_attribution_sidecars=[
            Path(p) for p in args.semantic_attribution_sidecar
        ],
    )
    out_json = Path(args.output_json)
    out_md = Path(args.output)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_markdown(payload, out_md)
    print(json.dumps(payload["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
