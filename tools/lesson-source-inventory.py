#!/usr/bin/env python3
"""Inventory lesson-bearing sources and their enforcement status.

This tool answers a different question from lesson-enforcement-inventory.py:
not "which predicates are active?", but "which local sources could teach the
system a lesson, and are those sources actually feeding an enforcement gate?"

It is deliberately conservative. Unreviewed agent artifacts, case studies, raw
audit prose, and broad corpus records are surfaced as promotion candidates or
context, not as automatic hard blockers for reports.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
COMPILER_PATH = Path(__file__).resolve().with_name("prose-to-lesson-compiler.py")
SCHEMA = "auditooor.lesson_source_inventory.v1"
SCHEMA_VERSION = "1.0"
TOOL_VERSION = "1.0.0"
DEFAULT_MAX_COMPILE_FILES = 80
DEFAULT_DECISIONS = ROOT / ".auditooor" / "lesson_source_decisions.json"
TERMINAL_AGENT_ARTIFACT_DECISIONS = {"NO_ACTION", "NEEDS_HUMAN_PRIMARY_REVIEW"}
SUPPORTED_TEXT_SUFFIXES = {".json", ".jsonl", ".md", ".markdown", ".txt", ".text"}
PATTERN_DSL_SUFFIXES = {".json", ".jsonl", ".md", ".markdown", ".txt", ".yaml", ".yml"}
PROVIDER_OUTPUT_SUFFIXES = {
    ".err",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".out",
    ".text",
    ".txt",
}
RAW_AUDIT_DIR_NAMES = {
    "prior_audits",
    "extracted_audits",
    "external-prior-audits",
    "known-vulns-pdf",
    "cantina-pdfs",
}


def _load_compiler():
    spec = importlib.util.spec_from_file_location("prose_to_lesson_compiler_for_sources", COMPILER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load compiler from {COMPILER_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path)


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_source_decisions(path: Path | None) -> tuple[dict[str, Any], dict[tuple[str, str], dict[str, Any]]]:
    if path is None:
        return {"path": "", "loaded": False, "decision_count": 0, "terminal_decision_count": 0}, {}
    decision_path = path.expanduser().resolve()
    payload = _read_json(decision_path)
    if not isinstance(payload, dict):
        return {
            "path": str(decision_path),
            "loaded": False,
            "decision_count": 0,
            "terminal_decision_count": 0,
        }, {}

    decisions: dict[tuple[str, str], dict[str, Any]] = {}
    rows = [row for row in payload.get("decisions") or [] if isinstance(row, dict)]
    for row in rows:
        if row.get("terminal_for_source_coverage") is not True:
            continue
        source_kind = str(row.get("source_kind") or "")
        source_ref = str(row.get("source_ref") or "")
        outcome = str(row.get("decision_outcome") or "")
        if source_kind == "case_study" and source_ref and outcome in {"CURATED_LESSON", "NO_ACTION"}:
            decisions[(source_kind, source_ref)] = row
        elif source_kind == "agent_artifacts" and source_ref and outcome in TERMINAL_AGENT_ARTIFACT_DECISIONS:
            decisions[(source_kind, source_ref)] = row

    return {
        "path": str(decision_path),
        "loaded": True,
        "schema": payload.get("schema"),
        "decision_count": len(rows),
        "terminal_decision_count": len(decisions),
    }, decisions


def _iter_files(paths: Iterable[Path], suffixes: set[str] = SUPPORTED_TEXT_SUFFIXES) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = raw.expanduser().resolve()
        if path.is_file() and path.suffix.lower() in suffixes:
            files.append(path)
        elif path.is_dir():
            files.extend(
                sorted(
                    candidate
                    for candidate in path.rglob("*")
                    if candidate.is_file()
                    and candidate.suffix.lower() in suffixes
                    and ".git" not in candidate.parts
                )
            )
    return sorted(dict.fromkeys(files), key=lambda item: str(item))


def _jsonl_count(path: Path) -> int:
    try:
        return sum(1 for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
    except OSError:
        return 0


def _compile_summary(files: Sequence[Path], *, max_files: int = DEFAULT_MAX_COMPILE_FILES) -> dict[str, Any]:
    if not files:
        return {
            "files_compiled": 0,
            "compile_truncated": False,
            "lesson_candidates": 0,
            "compiled_predicates": [],
            "enforcement_level_counts": {},
            "warnings": [],
        }
    compiler = _load_compiler()
    generated = compiler.utc_now_iso()
    lessons: list[dict[str, Any]] = []
    warnings: list[str] = []
    for path in files[:max_files]:
        try:
            payload = compiler.compile_path(path, max_lessons=40, generated_at=generated, max_chars_per_source=80_000)
        except Exception as exc:  # noqa: BLE001 - local malformed source should not crash inventory.
            warnings.append(f"compile failed for {path}: {exc}")
            continue
        lessons.extend(row for row in payload.get("lessons") or [] if isinstance(row, dict))
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        warnings.extend(str(item) for item in summary.get("warnings") or [])
    predicates = sorted({str(row.get("predicate") or "") for row in lessons if row.get("predicate")})
    levels: Counter[str] = Counter(str(row.get("enforcement_level") or "") for row in lessons if row.get("enforcement_level"))
    return {
        "files_compiled": min(len(files), max_files),
        "compile_truncated": len(files) > max_files,
        "lesson_candidates": len(lessons),
        "compiled_predicates": predicates,
        "enforcement_level_counts": dict(sorted(levels.items())),
        "warnings": warnings[:12],
    }


def _row(
    *,
    root: Path,
    source_kind: str,
    path: Path,
    source_refs: Sequence[Path] = (),
    records_seen: int = 0,
    lesson_candidates: int = 0,
    compiled_predicates: Sequence[str] = (),
    admissibility: str,
    gate_role: str,
    included_in_default_lesson_enforcement: bool,
    reason: str,
    compile_truncated: bool = False,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source_kind": source_kind,
        "path": _rel(path, root),
        "records_seen": records_seen,
        "lesson_candidates": lesson_candidates,
        "compiled_predicates": list(compiled_predicates),
        "compiled_predicate_count": len(set(compiled_predicates)),
        "admissibility": admissibility,
        "gate_role": gate_role,
        "included_in_default_lesson_enforcement": included_in_default_lesson_enforcement,
        "compile_truncated": compile_truncated,
        "reason": reason,
        "source_refs": [_rel(item, root) for item in source_refs[:10]],
    }
    if extra:
        payload.update(extra)
    return payload


def _reference_rows(root: Path, max_compile_files: int) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []

    curated = root / "reference" / "curated_lessons.jsonl"
    if curated.exists():
        compiled = _compile_summary([curated], max_files=max_compile_files)
        warnings.extend(compiled["warnings"])
        rows.append(
            _row(
                root=root,
                source_kind="curated_lessons",
                path=curated,
                source_refs=[curated],
                records_seen=_jsonl_count(curated),
                lesson_candidates=int(compiled["lesson_candidates"]),
                compiled_predicates=compiled["compiled_predicates"],
                admissibility="hard_enforcement_input",
                gate_role="default_lesson_enforcement",
                included_in_default_lesson_enforcement=True,
                reason="operator-curated lesson sink is trusted only after explicit human promotion into this file",
                compile_truncated=bool(compiled["compile_truncated"]),
            )
        )

    outcomes = root / "reference" / "outcomes.jsonl"
    if outcomes.exists():
        compiled = _compile_summary([outcomes], max_files=max_compile_files)
        warnings.extend(compiled["warnings"])
        rows.append(
            _row(
                root=root,
                source_kind="outcomes",
                path=outcomes,
                source_refs=[outcomes],
                records_seen=_jsonl_count(outcomes),
                lesson_candidates=int(compiled["lesson_candidates"]),
                compiled_predicates=compiled["compiled_predicates"],
                admissibility="hard_enforcement_input",
                gate_role="default_lesson_enforcement",
                included_in_default_lesson_enforcement=True,
                reason="structured outcome rows are trusted hard-lesson inputs",
                compile_truncated=bool(compiled["compile_truncated"]),
            )
        )

    triager_files = _iter_files(
        [
            root / "reference" / "triager_patterns.md",
            root / "reference" / "triager_patterns.json",
        ]
    )
    if triager_files:
        compiled = _compile_summary(triager_files, max_files=max_compile_files)
        warnings.extend(compiled["warnings"])
        rows.append(
            _row(
                root=root,
                source_kind="triager_patterns",
                path=root / "reference",
                source_refs=triager_files,
                records_seen=len(triager_files),
                lesson_candidates=int(compiled["lesson_candidates"]),
                compiled_predicates=compiled["compiled_predicates"],
                admissibility="hard_enforcement_input",
                gate_role="default_lesson_enforcement",
                included_in_default_lesson_enforcement=True,
                reason="curated triager patterns are trusted hard-lesson inputs",
                compile_truncated=bool(compiled["compile_truncated"]),
            )
        )

    case_files = _iter_files([root / "case_study"], {".md", ".markdown"})
    if case_files:
        compiled = _compile_summary(case_files, max_files=max_compile_files)
        warnings.extend(compiled["warnings"])
        rows.append(
            _row(
                root=root,
                source_kind="case_study",
                path=root / "case_study",
                source_refs=case_files,
                records_seen=len(case_files),
                lesson_candidates=max(len(case_files), int(compiled["lesson_candidates"])),
                compiled_predicates=compiled["compiled_predicates"],
                admissibility="candidate_hard_requires_review",
                gate_role="candidate_lesson_promotion_queue",
                included_in_default_lesson_enforcement=False,
                reason="case studies carry operator lessons but require explicit promotion before hard blocking reports",
                compile_truncated=bool(compiled["compile_truncated"]),
            )
        )

    corpus_files = _iter_files([root / "reference" / "corpus_mined"], {".md", ".markdown", ".txt", ".json", ".jsonl"})
    if corpus_files:
        compiled = _compile_summary(corpus_files, max_files=max_compile_files)
        warnings.extend(compiled["warnings"])
        rows.append(
            _row(
                root=root,
                source_kind="reference_corpus_mined",
                path=root / "reference" / "corpus_mined",
                source_refs=corpus_files,
                records_seen=len(corpus_files),
                lesson_candidates=int(compiled["lesson_candidates"]),
                compiled_predicates=compiled["compiled_predicates"],
                admissibility="corpus_context_requires_promotion",
                gate_role="hackerman_context_and_candidate_lesson_promotion",
                included_in_default_lesson_enforcement=False,
                reason="mined exploit/audit corpus feeds Hackerman recall but uncurated prose is not a hard lesson gate",
                compile_truncated=bool(compiled["compile_truncated"]),
            )
        )

    return rows, warnings


def _first_class_corpus_rows(root: Path, max_compile_files: int) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []

    pattern_dirs = sorted(
        path
        for path in (root / "reference").glob("patterns.dsl*")
        if path.is_dir()
    )
    pattern_files = _iter_files(pattern_dirs, PATTERN_DSL_SUFFIXES)
    if pattern_files:
        rows.append(
            _row(
                root=root,
                source_kind="reference_patterns_dsl",
                path=root / "reference",
                source_refs=pattern_files,
                records_seen=len(pattern_files),
                lesson_candidates=0,
                compiled_predicates=[],
                admissibility="corpus_context_candidate_only",
                gate_role="detector_pattern_recall_and_candidate_lesson_context",
                included_in_default_lesson_enforcement=False,
                reason="pattern DSL records are detector/context corpus; they require explicit curation before hard lesson enforcement",
                extra={"pattern_dsl_roots": [_rel(path, root) for path in pattern_dirs[:50]]},
            )
        )

    corpus_txt = root / "reference" / "corpus_txt"
    corpus_txt_files = _iter_files([corpus_txt], {".txt", ".text", ".md", ".markdown", ".json", ".jsonl"})
    if corpus_txt_files:
        compiled = _compile_summary(corpus_txt_files, max_files=max_compile_files)
        warnings.extend(compiled["warnings"])
        rows.append(
            _row(
                root=root,
                source_kind="reference_corpus_txt",
                path=corpus_txt,
                source_refs=corpus_txt_files,
                records_seen=len(corpus_txt_files),
                lesson_candidates=int(compiled["lesson_candidates"]),
                compiled_predicates=compiled["compiled_predicates"],
                admissibility="corpus_context_requires_promotion",
                gate_role="audit_corpus_context_and_candidate_lesson_promotion",
                included_in_default_lesson_enforcement=False,
                reason="raw audit corpus text is first-class recall context but cannot hard-block reports without explicit promotion",
                compile_truncated=bool(compiled["compile_truncated"]),
            )
        )

    exploit_predicates = root / "audit" / "corpus_tags" / "derived" / "exploit_predicates.d"
    exploit_files = _iter_files([exploit_predicates], {".jsonl", ".json"})
    if exploit_files:
        records_seen = sum(_jsonl_count(path) if path.suffix.lower() == ".jsonl" else 1 for path in exploit_files)
        rows.append(
            _row(
                root=root,
                source_kind="exploit_predicates",
                path=exploit_predicates,
                source_refs=exploit_files,
                records_seen=records_seen,
                lesson_candidates=0,
                compiled_predicates=[],
                admissibility="corpus_database_context",
                gate_role="exploit_predicate_recall_and_proof_obligation_context",
                included_in_default_lesson_enforcement=False,
                reason="typed exploit predicates are proof/context sidecars, not hard lesson inputs",
            )
        )

    return rows, warnings


def _workspace_rows(root: Path, workspace: Path | None, max_compile_files: int) -> tuple[list[dict[str, Any]], list[str]]:
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []

    workspace = workspace.expanduser().resolve() if workspace is not None else None
    if workspace is not None:
        raw_dirs = [workspace / name for name in RAW_AUDIT_DIR_NAMES if (workspace / name).exists()]
        raw_files = _iter_files(raw_dirs)
        if raw_files:
            compiled = _compile_summary(raw_files, max_files=max_compile_files)
            warnings.extend(compiled["warnings"])
            rows.append(
                _row(
                    root=root,
                    source_kind="workspace_raw_audit_text",
                    path=workspace,
                    source_refs=raw_files,
                    records_seen=len(raw_files),
                    lesson_candidates=int(compiled["lesson_candidates"]),
                    compiled_predicates=compiled["compiled_predicates"],
                    admissibility="workspace_context_requires_promotion",
                    gate_role="originality_and_context_before_candidate_promotion",
                    included_in_default_lesson_enforcement=False,
                    reason="workspace prior-audit prose informs originality/dupe/context but needs source-specific promotion for hard lessons",
                    compile_truncated=bool(compiled["compile_truncated"]),
                )
            )

    artifact_root = workspace if workspace is not None else root
    agent_report = artifact_root / ".auditooor" / "agent_artifact_mining_report.json"
    candidate_report = artifact_root / ".auditooor" / "agent_artifact_lesson_candidates.json"
    if agent_report.exists() or candidate_report.exists():
        artifacts = 0
        artifact_types: dict[str, Any] = {}
        candidate_count = 0
        candidate_ids: list[str] = []
        if agent_report.exists():
            data = _read_json(agent_report)
            if isinstance(data, dict):
                artifacts = int(data.get("total_artifacts") or 0)
                artifact_types = data.get("artifact_type_counts") if isinstance(data.get("artifact_type_counts"), dict) else {}
        if candidate_report.exists():
            data = _read_json(candidate_report)
            if isinstance(data, dict):
                candidates = data.get("lesson_candidates") or data.get("candidates") or []
                if isinstance(candidates, list):
                    candidate_count = len(candidates)
                    candidate_ids = [
                        str(candidate.get("candidate_id") or "")
                        for candidate in candidates
                        if isinstance(candidate, dict) and candidate.get("candidate_id")
                    ]
                else:
                    candidate_count = int(data.get("candidate_count") or 0)
        rows.append(
            _row(
                root=root,
                source_kind="agent_artifacts",
                path=artifact_root / ".auditooor",
                source_refs=[p for p in (agent_report, candidate_report) if p.exists()],
                records_seen=artifacts,
                lesson_candidates=candidate_count,
                compiled_predicates=[],
                admissibility="candidate_hard_requires_human_review",
                gate_role="agent_learning_candidate_queue",
                included_in_default_lesson_enforcement=False,
                reason="agent artifacts can contain useful reasoning but are secondary evidence and must be reviewed before enforcement",
                extra={"artifact_type_counts": artifact_types, "agent_artifact_candidate_ids": candidate_ids[:200]},
            )
        )

    return rows, warnings


def _provider_outputs_row(root: Path, workspace: Path | None = None) -> dict[str, Any] | None:
    base_candidates = [
        root / "provider_outputs",
        root / "agent_outputs" / "provider_outputs",
    ]
    if workspace is not None:
        base_candidates.extend(
            [
                workspace / "provider_outputs",
                workspace / "agent_outputs" / "provider_outputs",
            ]
        )
    candidates = list(base_candidates)
    for base in (root, workspace) if workspace is not None else (root,):
        candidates.extend((base / ".auditooor" / "provider_fanout").glob("*" + "/provider_outputs"))
        candidates.extend((base / ".auditooor" / "provider_fanout").glob("*" + "/runs/provider_outputs"))
        candidates.extend((base / ".auditooor" / "provider_fanout").glob("*" + "/runs/*/provider_outputs"))
    provider_roots = sorted(dict.fromkeys(path.resolve() for path in candidates if path.exists() and path.is_dir()))
    provider_files = _iter_files(provider_roots, PROVIDER_OUTPUT_SUFFIXES)
    if not provider_files:
        return None
    return _row(
        root=root,
        source_kind="provider_outputs",
        path=provider_roots[0],
        source_refs=provider_files,
        records_seen=len(provider_files),
        lesson_candidates=0,
        compiled_predicates=[],
        admissibility="provider_artifact_context_only",
        gate_role="advisory_provider_review_context",
        included_in_default_lesson_enforcement=False,
        reason="provider outputs are secondary advisory artifacts and are never promoted to hard lessons automatically",
        extra={"provider_output_roots": [_rel(path, root) for path in provider_roots]},
    )


def _corpus_database_row(root: Path) -> dict[str, Any] | None:
    tags = root / "audit" / "corpus_tags" / "tags"
    if not tags.is_dir():
        return None
    record_files = [
        path
        for path in tags.rglob("*")
        if path.is_file()
        and path.suffix.lower() in {".json", ".yaml", ".yml"}
        and (path.name == "record.json" or path.name == "record.yaml" or path.name == "record.yml" or path.parent == tags)
    ]
    return _row(
        root=root,
        source_kind="hackerman_corpus_tags",
        path=tags,
        source_refs=record_files,
        records_seen=len(record_files),
        lesson_candidates=0,
        compiled_predicates=[],
        admissibility="corpus_database_context",
        gate_role="hackerman_mcp_recall_and_sidecar_extractors",
        included_in_default_lesson_enforcement=False,
        reason="corpus records are used by Hackerman recall and sidecar extractors; sidecar coverage gates extraction parity separately",
    )


def build_inventory(
    root: Path = ROOT,
    *,
    workspace: Path | None = None,
    max_compile_files: int = DEFAULT_MAX_COMPILE_FILES,
    decisions_path: Path | None = None,
) -> dict[str, Any]:
    root = root.expanduser().resolve()
    workspace = workspace.expanduser().resolve() if workspace is not None else None
    if decisions_path is None:
        decisions_path = root / ".auditooor" / "lesson_source_decisions.json"
    decision_summary, source_decisions = _load_source_decisions(decisions_path)
    rows, warnings = _reference_rows(root, max_compile_files)
    corpus_rows, corpus_warnings = _first_class_corpus_rows(root, max_compile_files)
    rows.extend(corpus_rows)
    warnings.extend(corpus_warnings)
    workspace_rows, workspace_warnings = _workspace_rows(root, workspace, max_compile_files)
    rows.extend(workspace_rows)
    warnings.extend(workspace_warnings)
    corpus_row = _corpus_database_row(root)
    if corpus_row is not None:
        rows.append(corpus_row)
    provider_row = _provider_outputs_row(root, workspace)
    if provider_row is not None:
        rows.append(provider_row)

    for row in rows:
        if row.get("source_kind") == "case_study":
            source_dir = root / str(row.get("path") or "case_study")
            candidate_refs = [_rel(path, root) for path in _iter_files([source_dir], {".md", ".markdown"})]
            resolved = [
                ref
                for ref in candidate_refs
                if ("case_study", ref) in source_decisions
            ]
            outcome_counts: Counter[str] = Counter(
                str(source_decisions[("case_study", ref)].get("decision_outcome") or "unknown") for ref in resolved
            )
            unresolved = max(0, int(row.get("lesson_candidates") or 0) - len(resolved))
            row["review_decisions"] = {
                "decision_sidecar": decision_summary.get("path", ""),
                "candidate_source_count": len(candidate_refs),
                "terminal_decision_count": len(resolved),
                "decision_counts": dict(sorted(outcome_counts.items())),
                "unresolved_candidate_sources": max(0, len(candidate_refs) - len(resolved)),
            }
            row["lesson_candidates_unresolved"] = unresolved
        elif row.get("source_kind") == "agent_artifacts":
            candidate_ids = [str(item) for item in row.get("agent_artifact_candidate_ids") or [] if str(item)]
            resolved = [
                candidate_id
                for candidate_id in candidate_ids
                if ("agent_artifacts", candidate_id) in source_decisions
            ]
            outcome_counts = Counter(
                str(source_decisions[("agent_artifacts", candidate_id)].get("decision_outcome") or "unknown")
                for candidate_id in resolved
            )
            unresolved = max(0, int(row.get("lesson_candidates") or 0) - len(resolved))
            row["review_decisions"] = {
                "decision_sidecar": decision_summary.get("path", ""),
                "candidate_source_count": len(candidate_ids),
                "terminal_decision_count": len(resolved),
                "decision_counts": dict(sorted(outcome_counts.items())),
                "unresolved_candidate_sources": max(0, len(candidate_ids) - len(resolved)),
            }
            row["lesson_candidates_unresolved"] = unresolved

    included = [row for row in rows if row.get("included_in_default_lesson_enforcement")]
    promotion_candidates = [
        row
        for row in rows
        if not row.get("included_in_default_lesson_enforcement")
        and int(row.get("lesson_candidates_unresolved", row.get("lesson_candidates") or 0) or 0) > 0
        and "candidate" in str(row.get("admissibility") or "")
    ]
    context_only = [
        row
        for row in rows
        if not row.get("included_in_default_lesson_enforcement")
        and int(row.get("records_seen") or 0) > 0
        and row not in promotion_candidates
    ]
    coverage_blockers = [
        {
            "code": "lesson_source_requires_promotion_review",
            "source_kind": row["source_kind"],
            "path": row["path"],
            "lesson_candidates": int(row.get("lesson_candidates_unresolved", row["lesson_candidates"]) or 0),
            "lesson_candidates_total": row["lesson_candidates"],
            "admissibility": row["admissibility"],
            "gate_role": row["gate_role"],
            "reason": row["reason"],
            "review_decisions": row.get("review_decisions", {}),
        }
        for row in promotion_candidates
    ]
    status = "partial" if coverage_blockers else ("pass" if included else "warn")
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "tool_version": TOOL_VERSION,
        "root": str(root),
        "workspace": str(workspace) if workspace is not None else "",
        "offline_only": True,
        "network_access": False,
        "promotion_authority": False,
        "status": status,
        "summary": {
            "sources_seen": len(rows),
            "default_enforcement_sources": len(included),
            "promotion_candidate_sources": len(promotion_candidates),
            "context_only_sources": len(context_only),
            "coverage_blocker_count": len(coverage_blockers),
            "lesson_candidates_total": sum(int(row.get("lesson_candidates") or 0) for row in rows),
            "lesson_candidates_unresolved_total": sum(
                int(row.get("lesson_candidates_unresolved", row.get("lesson_candidates") or 0) or 0)
                for row in rows
                if not row.get("included_in_default_lesson_enforcement")
                and "candidate" in str(row.get("admissibility") or "")
            ),
            "records_seen_total": sum(int(row.get("records_seen") or 0) for row in rows),
            "source_decisions": decision_summary,
            "warnings": warnings[:20],
        },
        "rows": rows,
        "coverage_blockers": coverage_blockers,
        "policy": (
            "Only curated lessons, curated outcomes, and triager patterns are default hard lesson inputs. "
            "Case studies, agent artifacts, provider outputs, raw audit prose, and mined corpus text require "
            "explicit promotion before they can block a report."
        ),
    }


def render_text(payload: dict[str, Any]) -> str:
    summary = payload.get("summary", {})
    lines = [
        "lesson-source inventory",
        f"schema={payload.get('schema')} status={payload.get('status')} offline_only={payload.get('offline_only')}",
        (
            f"sources_seen={summary.get('sources_seen', 0)} default_enforcement_sources="
            f"{summary.get('default_enforcement_sources', 0)} promotion_candidate_sources="
            f"{summary.get('promotion_candidate_sources', 0)} coverage_blockers="
            f"{summary.get('coverage_blocker_count', 0)}"
        ),
        "",
    ]
    for row in payload.get("rows") or []:
        lines.append(
            f"- {row['source_kind']} records={row['records_seen']} lessons={row['lesson_candidates']} "
            f"in_default_gate={row['included_in_default_lesson_enforcement']} role={row['gate_role']}"
        )
    return "\n".join(lines).rstrip() + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Repository root to inspect.")
    parser.add_argument("--workspace", type=Path, default=None, help="Optional audit workspace for raw audit and agent-artifact sources.")
    parser.add_argument("--max-compile-files", type=int, default=DEFAULT_MAX_COMPILE_FILES)
    parser.add_argument("--decisions", type=Path, default=None, help="Optional lesson-source decisions sidecar.")
    parser.add_argument("--out-json", type=Path, default=None)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    payload = build_inventory(
        args.root,
        workspace=args.workspace,
        max_compile_files=args.max_compile_files,
        decisions_path=args.decisions,
    )
    if args.out_json:
        out = args.out_json.expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(payload), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
