#!/usr/bin/env python3
"""Run advisory local verification over provider-result candidate harvest rows."""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TRIAGE = ROOT / ".audit_logs" / "pr560_worker_an" / "live_provider_result_triage.json"
DEFAULT_QUEUE = ROOT / ".audit_logs" / "pr560_worker_at" / "local_provider_verification_queue.json"
DEFAULT_OUT_JSON = ROOT / ".audit_logs" / "pr560_worker_av" / "provider_result_local_verification.json"
DEFAULT_OUT_MD = ROOT / ".audit_logs" / "pr560_worker_av" / "provider_result_local_verification.md"
TRIAGE_TOOL = ROOT / "tools" / "live-provider-result-triage.py"

TEXT_SUFFIXES = {
    ".cfg",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".sh",
    ".sol",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
SKIP_PARTS = {".audit_logs", ".git", "__pycache__", "node_modules", "target", "vendor"}
STOP_TERMS = {"*test*", "main", "target", "tools/"}
FIXTURE_WORDS = ("fixture", "harness", "poc", "forge test", "smoke", "regression test", "test fixture")
NON_DETECTORIZABLE_WORDS = (
    "non-detectorizable",
    "not detectorizable",
    "not a security",
    "non-security",
    "tooling concern",
    "code-review nit",
    "common code-review",
    "oos",
    "advisory only",
)
CLASSIFICATION_BUCKETS = ("impossible", "off_repo", "needs_fixture", "non_detectorizable", "local_grep_advisory")
GENERATED_EVIDENCE_CLASS = "generated_hypothesis"


def _load_triage_parser():
    spec = importlib.util.spec_from_file_location("live_provider_result_triage", TRIAGE_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {TRIAGE_TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _safe_rel(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _flatten(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, dict):
        out: list[Any] = []
        for item in value.values():
            out.extend(_as_list(item))
        return out
    return [value]


def _split_checks(value: Any) -> list[str]:
    checks: list[str] = []
    for item in _as_list(value):
        text = str(item).strip()
        if not text or text.lower() in {"true", "false"}:
            continue
        parts = re.split(r";\s+|\(\d+\)\s+", text)
        checks.extend(part.strip(" .") for part in parts if part.strip(" ."))
    return checks


def _repo_text_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if any(part in SKIP_PARTS for part in path.parts):
            continue
        rel_parts = path.relative_to(root).parts
        if len(rel_parts) >= 3 and rel_parts[0] == ".auditooor" and rel_parts[1] == "provider_assist":
            continue
        if path.name in {"provider-result-local-verify.py", "test_provider_result_local_verify.py"}:
            continue
        if path.is_file() and (path.suffix in TEXT_SUFFIXES or path.name in {"Makefile"}):
            yield path


def _normalize_candidate_path(raw: Any, root: Path) -> Path | None:
    if not raw:
        return None
    text = str(raw)
    if ":" in text and not text.startswith("/"):
        text = text.split(":", 1)[0]
    if re.search(r":\d", text):
        text = re.split(r":\d", text, maxsplit=1)[0]
    path = Path(text)
    if not path.is_absolute():
        path = root / path
    return path


def _source_path_from_facts(facts: dict[str, Any], root: Path) -> Path | None:
    for key in ("file", "source_file", "file_path"):
        path = _normalize_candidate_path(facts.get(key), root)
        if path is not None:
            return path
    location = facts.get("location")
    if location:
        return _normalize_candidate_path(location, root)
    return None


def _symbols_from_facts(facts: dict[str, Any]) -> list[str]:
    symbols = []
    for key in ("symbol", "source_symbol", "function", "symbol_name"):
        value = facts.get(key)
        if isinstance(value, str) and value:
            symbols.append(value)
    return sorted(set(symbols))


def _terms_from_objects(objects: Sequence[dict[str, Any]]) -> list[str]:
    terms: list[str] = []
    for obj in objects:
        facts = obj.get("extracted_source_facts")
        if isinstance(facts, dict):
            terms.extend(_symbols_from_facts(facts))
        shape = obj.get("candidate_detector_shape")
        if isinstance(shape, dict):
            for key in ("local_verification_grep_patterns", "local_check_targets", "detection_triggers"):
                for item in _as_list(shape.get(key)):
                    item_text = str(item).strip()
                    if item_text and len(item_text) <= 80:
                        terms.append(item_text)
        for check in _split_checks(obj.get("local_checks_required")):
            match = re.search(r"['\"]([^'\"]{3,80})['\"]", check)
            if match:
                terms.append(match.group(1))
    return sorted(
        {
            term
            for term in terms
            if term
            and term not in STOP_TERMS
            and not term.startswith("grep ")
            and not term.startswith("/")
        }
    )


def _terms_from_checks(checks: Sequence[str]) -> list[str]:
    terms: list[str] = []
    for check in checks:
        terms.extend(re.findall(r"[`'\"]([^`'\"]{3,80})[`'\"]", check))
        command_match = re.match(r"\s*(?:rg|grep)\s+(?:-n\s+)?(.+)$", check)
        if command_match:
            terms.append(command_match.group(1).strip(" '\""))
    return sorted(
        {
            term
            for term in terms
            if term
            and term not in STOP_TERMS
            and not term.startswith("/")
        }
    )


def _unique_text(values: Sequence[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _build_text_index(root: Path) -> list[tuple[Path, str]]:
    index: list[tuple[Path, str]] = []
    for path in _repo_text_files(root):
        try:
            index.append((path, _read_text(path)))
        except OSError:
            continue
    return index


def _grep_terms(root: Path, index: Sequence[tuple[Path, str]], terms: Sequence[str], *, max_hits_per_term: int = 5) -> dict[str, list[str]]:
    if not terms:
        return {}
    hits: dict[str, list[str]] = {term: [] for term in terms}
    for path, text in index:
        for term in terms:
            if len(hits[term]) >= max_hits_per_term:
                continue
            if term in text:
                hits[term].append(_safe_rel(path, root))
    return {term: paths for term, paths in hits.items() if paths}


def _provider_objects(row: dict[str, Any], parser: Any) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for key in ("kimi_output", "minimax_output"):
        path_text = row.get(key)
        if not path_text:
            continue
        path = Path(path_text)
        if not path.is_file():
            continue
        parsed, _notes = parser.parse_provider_objects(_read_text(path))
        objects.extend(parsed)
    return objects


def _queue_index(queue_path: Path) -> dict[str, list[dict[str, Any]]]:
    if not queue_path.is_file():
        return {}
    payload = _read_json(queue_path)
    indexed: dict[str, list[dict[str, Any]]] = {}
    for item in payload.get("rows", []):
        if not isinstance(item, dict):
            continue
        task_id = item.get("task_id")
        if isinstance(task_id, str) and task_id:
            indexed.setdefault(task_id, []).append(item)
    return indexed


def _row_verification(
    row: dict[str, Any],
    parser: Any,
    root: Path,
    text_index: Sequence[tuple[Path, str]] | None = None,
    queue_rows: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    objects = _provider_objects(row, parser)
    facts_list = [obj.get("extracted_source_facts") for obj in objects if isinstance(obj.get("extracted_source_facts"), dict)]
    checks: list[str] = []
    checks.extend(_split_checks(row.get("local_checks_required")))
    checks.extend(_split_checks(row.get("minimum_followup_checks")))
    checks.extend(_split_checks(row.get("minimum_followup_check")))
    for obj in objects:
        checks.extend(_split_checks(obj.get("local_checks_required")))
        checks.extend(_split_checks(obj.get("minimum_followup_check")))
    checks = _unique_text(checks)
    source_paths = [_source_path_from_facts(facts, root) for facts in facts_list]
    source_paths = [path for path in source_paths if path is not None]
    symbols = sorted({symbol for facts in facts_list for symbol in _symbols_from_facts(facts)})
    terms = sorted(set(_terms_from_objects(objects) + _terms_from_checks(checks)))
    if not terms:
        terms = symbols
    if text_index is None:
        text_index = _build_text_index(root)
    term_hits = _grep_terms(root, text_index, terms[:12])

    existing_sources = [path for path in source_paths if path.exists()]
    off_repo_sources = [
        path
        for path in source_paths
        if path.is_absolute() and root.resolve() not in path.resolve().parents and path.resolve() != root.resolve()
    ]
    missing_sources = [path for path in source_paths if not path.exists() and path not in off_repo_sources]

    source_hits = []
    for path in existing_sources:
        text = _read_text(path)
        matched_symbols = [symbol for symbol in symbols if symbol in text]
        source_hits.append({"path": _safe_rel(path, root), "matched_symbols": matched_symbols})

    combined_text = "\n".join([_flatten(row), _flatten(objects), "\n".join(checks)]).lower()
    classifications = set()
    if (not objects and not checks) or (not source_paths and not symbols and not checks):
        classifications.add("impossible")
    if off_repo_sources:
        classifications.add("off_repo")
    if missing_sources and not existing_sources and not term_hits:
        classifications.add("impossible")
    if "needs_fixture" in row.get("categories", []) or any(word in combined_text for word in FIXTURE_WORDS):
        classifications.add("needs_fixture")
    if "non_detectorizable" in row.get("categories", []) or any(word in combined_text for word in NON_DETECTORIZABLE_WORDS):
        classifications.add("non_detectorizable")

    if source_hits and any(hit["matched_symbols"] for hit in source_hits):
        local_status = "source_symbol_confirmed"
    elif source_hits:
        local_status = "source_file_confirmed"
    elif term_hits:
        local_status = "repo_grep_confirmed"
    elif off_repo_sources:
        local_status = "off_repo_source"
    else:
        local_status = "no_local_evidence"

    return {
        "task_id": row["task_id"],
        "provider_primary_category": row["primary_category"],
        "advisory_only": True,
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "promotion_authority": False,
        "local_status": local_status,
        "classifications": sorted(classifications) or ["local_grep_advisory"],
        "source_paths": [_safe_rel(path, root) for path in source_paths],
        "missing_sources": [_safe_rel(path, root) for path in missing_sources],
        "off_repo_sources": [str(path) for path in off_repo_sources],
        "symbols": symbols,
        "source_hits": source_hits,
        "term_hits": term_hits,
        "verification_queue": {
            "queue_ids": [str(item.get("queue_id")) for item in queue_rows or [] if item.get("queue_id")],
            "routes": sorted({str(item.get("route")) for item in queue_rows or [] if item.get("route")}),
            "next_commands": [str(item.get("next_command")) for item in queue_rows or [] if item.get("next_command")],
        },
        "local_check_count": len(checks),
        "local_checks": checks,
        "provider_outputs": {
            "kimi": _safe_rel(Path(row["kimi_output"]), root) if row.get("kimi_output") else "",
            "minimax": _safe_rel(Path(row["minimax_output"]), root) if row.get("minimax_output") else "",
            "final": _safe_rel(Path(row["final"]), root) if row.get("final") else "",
        },
    }


def build_verification(triage_path: Path, root: Path, queue_path: Path = DEFAULT_QUEUE) -> dict[str, Any]:
    parser = _load_triage_parser()
    triage = _read_json(triage_path)
    rows = [row for row in triage.get("rows", []) if row.get("primary_category") == "candidate_harvest"]
    text_index = _build_text_index(root)
    queue_by_task = _queue_index(queue_path)
    verified = [_row_verification(row, parser, root, text_index, queue_by_task.get(str(row.get("task_id")), [])) for row in rows]
    class_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    for row in verified:
        status_counts[row["local_status"]] += 1
        class_counts.update(row["classifications"])
    for bucket in CLASSIFICATION_BUCKETS:
        class_counts.setdefault(bucket, 0)
    return {
        "schema": "auditooor.provider_result_local_verification.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "triage_source": _safe_rel(triage_path, root),
        "verification_queue_source": _safe_rel(queue_path, root) if queue_path.is_file() else "",
        "verification_queue_matched_tasks": sum(1 for row in verified if row["verification_queue"]["queue_ids"]),
        "candidate_harvest_count": len(rows),
        "verified_row_count": len(verified),
        "executed_local_check_items": sum(row["local_check_count"] for row in verified),
        "advisory_only": True,
        "evidence_class": GENERATED_EVIDENCE_CLASS,
        "promotion_authority": False,
        "severity_assigned": False,
        "local_status_counts": dict(sorted(status_counts.items())),
        "classification_counts": dict(sorted(class_counts.items())),
        "rows": verified,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Provider Result Local Verification",
        "",
        "Worker AV advisory verification over provider-result candidate harvest rows.",
        "",
        "No row is promoted to a detector, finding, submission, severity decision, or PoC.",
        "",
        f"- triage source: `{payload['triage_source']}`",
        f"- verification queue source: `{payload['verification_queue_source'] or 'not found'}`",
        f"- candidate harvest rows: `{payload['candidate_harvest_count']}`",
        f"- verified rows: `{payload['verified_row_count']}`",
        f"- verification queue matched tasks: `{payload['verification_queue_matched_tasks']}`",
        f"- local check items cataloged: `{payload['executed_local_check_items']}`",
        f"- advisory only: `{str(payload['advisory_only']).lower()}`",
        f"- promotion authority: `{str(payload['promotion_authority']).lower()}`",
        "",
        "## Counts",
        "",
        "| Bucket | Count |",
        "|---|---:|",
    ]
    for key, value in payload["local_status_counts"].items():
        lines.append(f"| local_status `{key}` | {value} |")
    for key, value in payload["classification_counts"].items():
        lines.append(f"| classification `{key}` | {value} |")
    lines.extend(["", "## Rows", "", "| Task | Local Status | Classifications | Source/Symbol Evidence | Checks |", "|---|---|---|---|---:|"])
    for row in payload["rows"]:
        evidence_parts = []
        if row["source_hits"]:
            evidence_parts.extend(f"{hit['path']} ({', '.join(hit['matched_symbols']) or 'file'})" for hit in row["source_hits"][:2])
        if row["term_hits"]:
            terms = list(row["term_hits"].items())[:2]
            evidence_parts.extend(f"`{term}` -> {', '.join(paths[:2])}" for term, paths in terms)
        if row["missing_sources"]:
            evidence_parts.append("missing: " + ", ".join(row["missing_sources"][:2]))
        if row["off_repo_sources"]:
            evidence_parts.append("off-repo: " + ", ".join(row["off_repo_sources"][:1]))
        if row["verification_queue"]["queue_ids"]:
            evidence_parts.append("queue: " + ", ".join(row["verification_queue"]["queue_ids"][:3]))
        evidence = "<br>".join(evidence_parts) if evidence_parts else "_none_"
        lines.append(
            "| `{task}` | `{status}` | `{classes}` | {evidence} | {checks} |".format(
                task=row["task_id"],
                status=row["local_status"],
                classes=", ".join(row["classifications"]),
                evidence=evidence.replace("|", "\\|"),
                checks=row["local_check_count"],
            )
        )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--triage", type=Path, default=DEFAULT_TRIAGE)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--workspace-root", type=Path, default=ROOT)
    args = parser.parse_args(argv)

    payload = build_verification(args.triage, args.workspace_root, args.queue)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text(render_markdown(payload), encoding="utf-8")
    print(f"wrote {args.out_json}")
    print(f"wrote {args.out_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
