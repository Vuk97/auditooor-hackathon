#!/usr/bin/env python3
"""L33 changelog drift coverage gate for Solidity stale-invariant prose."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.l33_changelog_drift_check.v1"
REPO_ROOT = Path(__file__).resolve().parents[1]
MINER_TOOL = REPO_ROOT / "tools" / "changelog-source-drift-miner.py"
MODE_GATE = "gate"
MODE_HOOK = "hook"

SOURCE_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "artifacts",
    "cache",
    "out",
    "broadcast",
}

CHANGELOG_REF_RE = re.compile(
    r"(?P<path>("
    r"(?:[A-Za-z0-9_.-]+/)*CHANGELOG(?:-[A-Za-z0-9_.-]+)?\.md|"
    r"(?:[A-Za-z0-9_.-]+/)*(?:MIGRATION|BREAKING|RELEASES)\.md|"
    r"docs/changelog[A-Za-z0-9_.-]*\.md"
    r")):(?P<line>[0-9]+)\b",
    re.IGNORECASE,
)
REBUTTAL_RE = re.compile(r"<!--\s*l33-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
SOLIDITY_HINT_RE = re.compile(
    r"\b("
    r"pragma\s+solidity|"
    r"\.sol\b|"
    r"contract\s+[A-Za-z_][A-Za-z0-9_]*|"
    r"interface\s+[A-Za-z_][A-Za-z0-9_]*|"
    r"library\s+[A-Za-z_][A-Za-z0-9_]*|"
    r"modifier\s+[A-Za-z_][A-Za-z0-9_]*|"
    r"function\s+[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"forge\s+test|foundry|"
    r"msg\.sender|address\(0\)|uint(?:8|16|24|32|64|96|128|160|192|224|256)|"
    r"mapping\s*\("
    r")\b",
    re.IGNORECASE,
)
STALE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("stale", re.compile(r"\bstale\b", re.IGNORECASE)),
    ("outdated", re.compile(r"\boutdated\b", re.IGNORECASE)),
    ("no longer", re.compile(r"\bno\s+longer\b", re.IGNORECASE)),
    ("ordering changed", re.compile(r"\bordering\s+changed\b", re.IGNORECASE)),
    ("invariant change", re.compile(r"\binvariant\s+change\b", re.IGNORECASE)),
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _is_under_skip_dir(path: Path) -> bool:
    return any(part in SOURCE_SKIP_DIRS or part.startswith(".") for part in path.parts)


def _resolve_workspace_from_draft(draft: Path) -> Path | None:
    draft = draft.expanduser().resolve()
    for parent in [draft.parent, *draft.parents]:
        if (parent / "submissions").is_dir() or (parent / "poc-tests").is_dir():
            return parent
    return None


def _workspace_has_solidity_sources(workspace: Path | None) -> bool:
    if workspace is None or not workspace.is_dir():
        return False
    for path in workspace.rglob("*.sol"):
        try:
            rel = path.relative_to(workspace)
        except ValueError:
            rel = path
        if path.is_file() and not _is_under_skip_dir(rel):
            return True
    return False


def _extract_changelog_refs(text: str) -> list[dict[str, Any]]:
    refs: list[dict[str, Any]] = []
    for match in CHANGELOG_REF_RE.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        refs.append(
            {
                "path": match.group("path"),
                "line_ref": int(match.group("line")),
                "draft_line": line_no,
                "excerpt": match.group(0),
            }
        )
    return refs


def _extract_stale_hits(text: str) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for label, pattern in STALE_PATTERNS:
        for match in pattern.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            hits.append(
                {
                    "phrase": label,
                    "draft_line": line_no,
                    "excerpt": match.group(0),
                }
            )
    hits.sort(key=lambda item: (item["draft_line"], item["phrase"]))
    return hits


def _parse_rebuttal(text: str) -> dict[str, Any]:
    match = REBUTTAL_RE.search(text)
    if not match:
        return {"present": False, "accepted": False, "reason": ""}
    reason = " ".join(match.group(1).split())
    accepted = bool(reason) and len(reason) <= 200
    return {
        "present": True,
        "accepted": accepted,
        "reason": reason,
        "too_long": bool(reason) and len(reason) > 200,
    }


def _appears_solidity_relevant(text: str, workspace: Path | None) -> bool:
    return bool(SOLIDITY_HINT_RE.search(text) or _workspace_has_solidity_sources(workspace))


def _gate_status_sidecar_path(draft: Path, workspace: Path | None) -> Path:
    base = workspace if workspace is not None else draft.parent
    try:
        rel = draft.resolve().relative_to(base.resolve())
    except ValueError:
        rel = Path(draft.name)
    digest = hashlib.sha256(str(rel).encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(rel))[-140:]
    return base / ".auditooor" / "gate-status" / f"{slug}.{digest}.l33-changelog-drift.gate-status.json"


def _miner_output_path(draft: Path, workspace: Path) -> Path:
    try:
        rel = draft.resolve().relative_to(workspace.resolve())
    except ValueError:
        rel = Path(draft.name)
    digest = hashlib.sha256(str(rel).encode("utf-8")).hexdigest()[:12]
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(rel))[-140:]
    return workspace / ".auditooor" / "changelog-drift" / f"{slug}.{digest}.miner.json"


def _load_miner_module() -> Any:
    spec = importlib.util.spec_from_file_location("l33_changelog_source_drift_miner", MINER_TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load miner: {MINER_TOOL}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _run_miner(workspace: Path) -> dict[str, Any]:
    module = _load_miner_module()
    return module.mine(workspace)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def evaluate_draft(
    draft: Path,
    *,
    mode: str,
    workspace_hint: Path | None = None,
) -> tuple[int, dict[str, Any], dict[str, Any] | None]:
    draft = draft.expanduser().resolve()
    text = _read(draft)
    workspace = None
    if workspace_hint is not None:
        candidate = workspace_hint.expanduser().resolve()
        if candidate.is_dir():
            workspace = candidate
    if workspace is None:
        workspace = _resolve_workspace_from_draft(draft)

    changelog_refs = _extract_changelog_refs(text)
    stale_hits = _extract_stale_hits(text)
    rebuttal = _parse_rebuttal(text)
    solidity_relevant = _appears_solidity_relevant(text, workspace)
    trigger_reasons: list[str] = []
    if solidity_relevant:
        if changelog_refs:
            trigger_reasons.append("changelog_refs")
        if mode == MODE_GATE and stale_hits:
            trigger_reasons.append("stale_invariant_prose")
    triggered = bool(trigger_reasons)

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "draft_path": str(draft),
        "mode": mode,
        "workspace_path": str(workspace) if workspace is not None else None,
        "workspace_resolved": workspace is not None,
        "solidity_relevant": solidity_relevant,
        "triggered": triggered,
        "trigger_reasons": trigger_reasons,
        "changelog_refs": changelog_refs,
        "stale_hits": stale_hits,
        "rebuttal": rebuttal,
        "verdict": "not-applicable",
        "reason": "draft does not cite Solidity changelog drift cues",
        "miner": {
            "attempted": False,
            "status": "not-run",
            "exposed_count": 0,
            "verdict_counts": {},
            "claims": 0,
            "exposed_call_sites": [],
            "output_path": None,
        },
    }

    if not triggered:
        return 0, payload, None

    if mode == MODE_GATE and rebuttal.get("accepted"):
        payload["verdict"] = "ok-rebuttal"
        payload["reason"] = "accepted l33 rebuttal overrides exposed-row requirement"
        return 0, payload, None

    if workspace is None:
        payload["verdict"] = "advisory-workspace-unresolved"
        payload["reason"] = "workspace could not be resolved for changelog drift mining"
        return (2 if mode == MODE_HOOK else 1), payload, None

    if not MINER_TOOL.is_file():
        payload["verdict"] = "advisory-miner-missing" if mode == MODE_HOOK else "fail-miner-missing"
        payload["reason"] = f"miner not found: {MINER_TOOL}"
        return (2 if mode == MODE_HOOK else 1), payload, None

    try:
        miner_payload = _run_miner(workspace)
    except Exception as exc:
        payload["verdict"] = "advisory-miner-error" if mode == MODE_HOOK else "fail-miner-error"
        payload["reason"] = f"miner execution failed: {exc}"
        payload["miner"]["attempted"] = True
        payload["miner"]["status"] = "error"
        return (2 if mode == MODE_HOOK else 1), payload, None

    exposed_sites = list(miner_payload.get("ranked_exposed_call_sites") or [])
    verdict_counts = dict((miner_payload.get("stats") or {}).get("verdict_counts") or {})
    miner_output_path = _miner_output_path(draft, workspace)
    payload["miner"] = {
        "attempted": True,
        "status": "ok",
        "exposed_count": len(exposed_sites),
        "verdict_counts": verdict_counts,
        "claims": len(miner_payload.get("claims") or []),
        "exposed_call_sites": exposed_sites[:5],
        "output_path": str(miner_output_path),
    }

    if exposed_sites:
        payload["verdict"] = "pass-exposed-drift"
        payload["reason"] = "miner surfaced consumer-NOT-updated-EXPOSED coverage"
        return 0, payload, miner_payload

    payload["verdict"] = "fail-no-exposed-drift"
    payload["reason"] = "stale Solidity changelog framing lacks consumer-NOT-updated-EXPOSED miner evidence"
    return 1, payload, miner_payload


def _build_summary(payload: dict[str, Any]) -> str:
    verdict = payload.get("verdict") or "unknown"
    reason = payload.get("reason") or ""
    bits = [f"verdict={verdict}"]
    if payload.get("triggered"):
        bits.append("triggered=yes")
    miner = payload.get("miner") or {}
    if miner.get("attempted"):
        bits.append(f"exposed={miner.get('exposed_count', 0)}")
    if reason:
        bits.append(reason)
    return " | ".join(bits)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path, help="submission markdown draft to evaluate")
    parser.add_argument("--workspace", type=Path, help="optional workspace root override")
    parser.add_argument("--mode", choices=(MODE_GATE, MODE_HOOK), default=MODE_GATE)
    parser.add_argument("--json", action="store_true", help="emit structured JSON to stdout")
    parser.add_argument(
        "--write-sidecar",
        action="store_true",
        help="write hook-style gate-status sidecar when triggered or advisory",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    rc, payload, miner_payload = evaluate_draft(
        args.draft,
        mode=args.mode,
        workspace_hint=args.workspace,
    )

    if args.write_sidecar and (payload.get("triggered") or payload.get("verdict", "").startswith("advisory-")):
        sidecar_path = _gate_status_sidecar_path(args.draft, args.workspace or _resolve_workspace_from_draft(args.draft))
        payload["sidecar_path"] = str(sidecar_path)
        if miner_payload is not None and payload.get("workspace_path"):
            miner_path = Path(str((payload.get("miner") or {}).get("output_path")))
            _write_json(miner_path, miner_payload)
        _write_json(sidecar_path, payload)

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_build_summary(payload))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
