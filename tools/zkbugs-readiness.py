#!/usr/bin/env python3
"""Validate local zkBugs repo-content ingest and queue readiness.

This is deliberately about the ``zksecurity/zkbugs`` repository contents:
``dataset/**/zkbugs_config.json`` records, local report metadata/text, generated
briefs, and provider prompt queues. It does not treat GitHub issues as the
canonical corpus, does not clone, and does not call providers.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = ROOT / ".audit_logs" / "zkbugs_farming"
DEFAULT_REPORT_JSON = ROOT / ".audit_logs" / "zkbugs_farming" / "zkbugs_readiness.json"
DEFAULT_REPORT_MD = ROOT / ".audit_logs" / "zkbugs_farming" / "zkbugs_readiness.md"


def _load_ingest_module() -> Any:
    tool = ROOT / "tools" / "zkbugs-ingest.py"
    spec = importlib.util.spec_from_file_location("zkbugs_ingest_for_readiness", tool)
    if spec is None or spec.loader is None:
        raise SystemExit(f"[zkbugs-readiness] unable to load {tool}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[zkbugs-readiness] invalid JSON at {path}: {exc}") from None


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.rstrip() + "\n", encoding="utf-8")


def resolve_zkbugs_root(farming_dir: Path) -> Path | None:
    """Recover the source zkBugs checkout from a generated farming index."""
    index = _load_json(farming_dir.expanduser().resolve() / "zkbugs_index.json")
    if isinstance(index, dict):
        root = str(index.get("zkbugs_root") or "").strip()
        if root:
            return Path(root).expanduser()
    return None


def write_reports(payload: dict[str, Any], report_json: Path, report_md: Path) -> None:
    _write_json(report_json, payload)
    _write_text(report_md, render_markdown(payload))


def _parse_generated_at(value: object) -> float:
    if not isinstance(value, str) or not value.strip():
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _repo_status(root: Path | None) -> dict[str, Any]:
    if root is None:
        return {
            "path": "",
            "exists": False,
            "dataset_dir_present": False,
            "config_files": 0,
            "repo_content_records": 0,
            "reports_json_present": False,
            "report_pdf_count": 0,
            "report_text_count": 0,
            "code_or_doc_file_count": 0,
            "load_error": "",
        }
    root = root.expanduser().resolve()
    dataset = root / "dataset"
    reports_dir = root / "reports" / "documents"
    code_suffixes = {".circom", ".rs", ".cairo", ".go", ".cpp", ".c", ".h", ".js", ".ts", ".py", ".json", ".md"}
    status = {
        "path": str(root),
        "exists": root.exists(),
        "dataset_dir_present": dataset.is_dir(),
        "config_files": 0,
        "repo_content_records": 0,
        "reports_json_present": (root / "reports" / "reports.json").is_file(),
        "report_pdf_count": len(list(reports_dir.glob("*.pdf"))) if reports_dir.is_dir() else 0,
        "report_text_count": len(list(reports_dir.glob("*.txt"))) if reports_dir.is_dir() else 0,
        "code_or_doc_file_count": 0,
        "load_error": "",
    }
    if root.is_dir():
        status["code_or_doc_file_count"] = sum(
            1 for path in root.rglob("*") if path.is_file() and path.suffix.lower() in code_suffixes
        )
    if dataset.is_dir():
        ingest = _load_ingest_module()
        try:
            records = ingest.load_records(root)
        except Exception as exc:  # noqa: BLE001 - report exact local corpus parse blocker.
            status["load_error"] = str(exc)
        else:
            status["repo_content_records"] = len(records)
            status["config_files"] = len(list(dataset.rglob("zkbugs_config.json")))
    return status


def build_payload(zkbugs_root: Path | None, out_dir: Path) -> dict[str, Any]:
    out_dir = out_dir.expanduser().resolve()
    index_path = out_dir / "zkbugs_index.json"
    index_md = out_dir / "zkbugs_index.md"
    brief_dir = out_dir / "briefs"
    queue_path = out_dir / "provider_queue" / "zkbugs_provider_queue.json"
    queue_md = out_dir / "provider_queue" / "zkbugs_provider_queue.md"
    prompts_dir = out_dir / "provider_queue" / "prompts"

    repo = _repo_status(zkbugs_root)
    index = _load_json(index_path)
    queue = _load_json(queue_path)
    index_records = len(index.get("records") or []) if isinstance(index, dict) else 0
    index_total = int(((index.get("summary") or {}).get("total") or 0) if isinstance(index, dict) else 0)
    index_briefs = len(index.get("briefs") or []) if isinstance(index, dict) else 0
    queue_rows = len(queue.get("rows") or []) if isinstance(queue, dict) else 0
    queue_count = int(queue.get("count") or 0) if isinstance(queue, dict) else 0
    brief_files = len(list(brief_dir.glob("*.md"))) if brief_dir.is_dir() else 0
    kimi_prompts = len(list(prompts_dir.glob("*.kimi.md"))) if prompts_dir.is_dir() else 0
    minimax_prompts = len(list(prompts_dir.glob("*.minimax.template.md"))) if prompts_dir.is_dir() else 0

    blockers: list[str] = []
    if not repo["exists"]:
        blockers.append("zkbugs_root_missing")
    elif not repo["dataset_dir_present"]:
        blockers.append("zkbugs_dataset_dir_missing")
    elif repo["load_error"]:
        blockers.append("zkbugs_repo_content_parse_failed")
    elif repo["repo_content_records"] == 0:
        blockers.append("zkbugs_repo_content_records_empty")
    if not index_path.is_file():
        blockers.append("zkbugs_index_json_missing")
    if not index_md.is_file():
        blockers.append("zkbugs_index_md_missing")
    if not queue_path.is_file():
        blockers.append("zkbugs_provider_queue_json_missing")
    if not queue_md.is_file():
        blockers.append("zkbugs_provider_queue_md_missing")
    if repo["repo_content_records"] and index_total != repo["repo_content_records"]:
        blockers.append("zkbugs_index_count_mismatch")
    if index_total and index_records != index_total:
        blockers.append("zkbugs_index_records_mismatch")
    if index_total and index_briefs != index_total:
        blockers.append("zkbugs_index_brief_refs_mismatch")
    if index_total and brief_files != index_total:
        blockers.append("zkbugs_brief_files_mismatch")
    if index_total and queue_rows != index_total:
        blockers.append("zkbugs_provider_queue_rows_mismatch")
    if queue_rows and queue_count != queue_rows:
        blockers.append("zkbugs_provider_queue_count_mismatch")
    if queue_rows and kimi_prompts != queue_rows:
        blockers.append("zkbugs_kimi_prompt_count_mismatch")
    if queue_rows and minimax_prompts != queue_rows:
        blockers.append("zkbugs_minimax_prompt_count_mismatch")

    index_generated = _parse_generated_at(index.get("generated_at") if isinstance(index, dict) else None)
    queue_generated = _parse_generated_at(queue.get("generated_at") if isinstance(queue, dict) else None)
    repo_newer_than_index = bool(
        repo["exists"] and index_path.is_file() and Path(repo["path"]).stat().st_mtime > max(index_path.stat().st_mtime, index_generated)
    )
    if repo_newer_than_index:
        blockers.append("zkbugs_root_newer_than_index")

    status = "ready" if not blockers else "blocked"
    if status == "ready" and not repo["path"]:
        status = "blocked"
        blockers.append("zkbugs_root_missing")

    return {
        "schema": "auditooor.zkbugs_repo_content_readiness.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "blockers": blockers,
        "repo_content_corpus": repo,
        "artifacts": {
            "out_dir": str(out_dir),
            "index_json": str(index_path),
            "index_json_present": index_path.is_file(),
            "index_md": str(index_md),
            "index_md_present": index_md.is_file(),
            "brief_dir": str(brief_dir),
            "brief_file_count": brief_files,
            "provider_queue_json": str(queue_path),
            "provider_queue_json_present": queue_path.is_file(),
            "provider_queue_md": str(queue_md),
            "provider_queue_md_present": queue_md.is_file(),
            "kimi_prompt_count": kimi_prompts,
            "minimax_prompt_count": minimax_prompts,
            "index_generated_at": index.get("generated_at") if isinstance(index, dict) else "",
            "queue_generated_at": queue.get("generated_at") if isinstance(queue, dict) else "",
            "index_newer_than_root": not repo_newer_than_index,
        },
        "counts": {
            "repo_content_records": repo["repo_content_records"],
            "index_summary_total": index_total,
            "index_records": index_records,
            "index_brief_refs": index_briefs,
            "brief_files": brief_files,
            "provider_queue_count": queue_count,
            "provider_queue_rows": queue_rows,
        },
        "next_commands": [
            "make extract DIR=<zkbugs-root>/reports/documents",
            "make zkbugs-ingest ZKBUGS_ROOT=<zkbugs-root> BRIEF_LIMIT=0 INDEX_LIMIT=0",
            "make zkbugs-brief-queue BRIEF_DIR=.audit_logs/zkbugs_farming/briefs LIMIT=0",
            "python3 tools/zkbugs-readiness.py --zkbugs-root <zkbugs-root> --strict",
        ],
        "proof_boundary": "Ready means local zksecurity/zkbugs repo-content records are normalized and queued. It does not mean provider triage, detector promotion, exploit proof, or GitHub issue mining.",
    }


def render_markdown(payload: dict[str, Any]) -> str:
    repo = payload["repo_content_corpus"]
    artifacts = payload["artifacts"]
    counts = payload["counts"]
    lines = [
        "# zkBugs Repo-Content Readiness",
        "",
        f"- Status: `{payload['status']}`",
        f"- Local root: `{repo['path'] or '<missing>'}`",
        f"- Dataset configs: `{repo['config_files']}`",
        f"- Repo-content records: `{repo['repo_content_records']}`",
        f"- Report PDFs / text files: `{repo['report_pdf_count']}` / `{repo['report_text_count']}`",
        f"- Code/config/doc files sampled: `{repo['code_or_doc_file_count']}`",
        f"- Index records: `{counts['index_records']}`",
        f"- Brief files: `{counts['brief_files']}`",
        f"- Queue rows: `{counts['provider_queue_rows']}`",
        f"- Kimi / Minimax prompts: `{artifacts['kimi_prompt_count']}` / `{artifacts['minimax_prompt_count']}`",
        "",
        "## Blockers",
        "",
    ]
    for blocker in payload["blockers"] or ["none"]:
        lines.append(f"- `{blocker}`")
    lines.extend(["", "## Evidence Paths", ""])
    for key in ("index_json", "index_md", "brief_dir", "provider_queue_json", "provider_queue_md"):
        lines.append(f"- {key}: `{artifacts[key]}`")
    lines.extend(["", "## Next Commands", ""])
    for command in payload["next_commands"]:
        lines.append(f"- `{command}`")
    lines.extend(["", "## Boundary", "", payload["proof_boundary"]])
    return "\n".join(lines) + "\n"


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zkbugs-root", type=Path, help="Local zksecurity/zkbugs checkout")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--report-json", type=Path, default=DEFAULT_REPORT_JSON)
    parser.add_argument("--report-md", type=Path, default=DEFAULT_REPORT_MD)
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument("--strict", action="store_true", help="Exit 2 when readiness blockers remain")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    payload = build_payload(args.zkbugs_root, args.out_dir)
    _write_json(args.report_json, payload)
    _write_text(args.report_md, render_markdown(payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    if args.strict and payload["blockers"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
