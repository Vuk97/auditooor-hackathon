#!/usr/bin/env python3
"""Ingest a local Swival Rust stdlib/Rust bug corpus into auditooor artifacts.

This tool is intentionally offline-first. It never clones a corpus. Operators
must provide a local checkout/path with ``--corpus-root`` or declare one in
``<workspace>/.auditooor/rust_corpus_roots.json``. The primary supported shape
is ``Swival/security-audits/rust-stdlib`` (151 published findings: 27 High,
115 Medium, 9 Low). When no local corpus is available, the tool emits exact
blocker rows so the Rust corpus coverage gap is truthful instead of skipped.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.rust_corpus_ingest.v1"
DEFAULT_OUT_DIR = Path(".audit_logs") / "rust_corpus_mining"
EXPECTED_SWIVAL_RUST_STDLIB_TOTAL = 151
EXPECTED_SWIVAL_SEVERITIES = {"High": 27, "Medium": 115, "Low": 9}

RUST_EXTENSIONS = {".rs", ".toml", ".md", ".txt", ".json", ".yaml", ".yml"}
SKIP_PARTS = {".git", "target", "node_modules", ".auditooor", ".audit_logs"}

FAMILY_RULES: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\b(snappy|zstd|brotli|lz4|decode|decompress|inflate|parser|serde|bincode)\b", re.I), "detector", "rust_decode_or_parser_boundary"),
    (re.compile(r"\b(unsafe|from_raw_parts|set_len|get_unchecked|transmute|assume_init|ffi|pointer)\b", re.I), "detector", "rust_unsafe_memory_boundary"),
    (re.compile(r"\b(overflow|underflow|truncat|usize|u64|u128|length|index|integer)\b", re.I), "detector", "rust_integer_or_length_boundary"),
    (re.compile(r"\b(race|atomic|relaxed|ordering|deadlock|lock|mutex|concurrent)\b", re.I), "invariant", "rust_concurrency_state_invariant"),
    (re.compile(r"\b(trait|dyn|impl|generic|macro|cfg|feature|cross-crate|cross crate)\b", re.I), "invariant", "rust_trait_macro_cfg_resolution"),
    (re.compile(r"\b(consensus|reth|evm|fork|finality|state root|engine api|node|liveness)\b", re.I), "replay", "rust_dlt_runtime_execution"),
    (re.compile(r"\b(tee|enclave|attestation|quote|measurement)\b", re.I), "replay", "rust_tee_runtime_execution"),
    (re.compile(r"\b(zk|snark|stark|proof|verifier|constraint|circuit)\b", re.I), "replay", "rust_zk_runtime_execution"),
]


@dataclass(frozen=True)
class RustCorpusRecord:
    item_id: str
    title: str
    corpus_root: str
    rel_path: str
    source_kind: str
    component: str
    corpus_severity: str
    category: str
    family: str
    route: str
    normalized: bool
    fixture_backed: bool
    detector_candidate: bool
    invariant_candidate: bool
    replay_candidate: bool
    terminal_state: str
    blockers: list[str]
    source_pointers: list[str]
    patch_pointers: list[str]
    poc_pointers: list[str]
    fixture_pointers: list[str]
    replay_commands: list[str]
    next_commands: list[str]
    severity: str = "none"
    selected_impact: str = ""
    submission_posture: str = "NOT_SUBMIT_READY"
    impact_contract_required: bool = True


def _slug(text: str, fallback: str = "rust-corpus") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return (slug or fallback)[:96]


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(_read_text(path))
    except (OSError, json.JSONDecodeError):
        return None


def _records_from_json(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if isinstance(payload, dict):
        for key in ("records", "rows", "bugs", "advisories", "findings", "candidates", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
        if any(key in payload for key in ("id", "title", "name", "description", "bug")):
            return [payload]
    return []


def _skip(path: Path) -> bool:
    return any(part in SKIP_PARTS for part in path.parts)


def _candidate_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or _skip(path):
            continue
        if path.suffix.lower() in RUST_EXTENSIONS:
            yield path


def _resolve_corpus_root(root: Path) -> Path:
    root = root.expanduser().resolve()
    if (root / "rust-stdlib").is_dir():
        return root / "rust-stdlib"
    return root


def _declared_roots(workspace: Path) -> list[Path]:
    path = workspace / ".auditooor" / "rust_corpus_roots.json"
    payload = _read_json(path)
    if not isinstance(payload, dict):
        return []
    roots = payload.get("roots")
    if not isinstance(roots, list):
        return []
    out: list[Path] = []
    for row in roots:
        if isinstance(row, str):
            out.append(Path(row))
        elif isinstance(row, dict) and isinstance(row.get("path"), str):
            out.append(Path(row["path"]))
    return out


def _text_value(record: dict[str, Any], *keys: str) -> str:
    parts: list[str] = []
    for key in keys:
        value = record.get(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.extend(str(v) for v in value if isinstance(v, (str, int, float)))
        elif isinstance(value, dict):
            parts.extend(str(v) for v in value.values() if isinstance(v, (str, int, float)))
    return "\n".join(parts)


def _record_id(record: dict[str, Any], rel: str, index: int) -> str:
    for key in ("id", "bug_id", "advisory_id", "cve", "rustsec_id", "name", "title"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return f"{Path(rel).stem or 'row'}-{index:04d}"


def _title(record: dict[str, Any], fallback: str) -> str:
    for key in ("title", "name", "bug", "vulnerability", "summary", "description"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().splitlines()[0][:180]
    return fallback


def _source_pointers(record: dict[str, Any], rel_path: str) -> list[str]:
    keys = ("source", "source_path", "source_file", "file", "path", "location", "affected", "package")
    out = [rel_path]
    for key in keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
        elif isinstance(value, list):
            out.extend(str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip())
        elif isinstance(value, dict):
            out.extend(str(v).strip() for v in value.values() if isinstance(v, (str, int, float)) and str(v).strip())
    return sorted(set(out))


def _fixture_pointers(root: Path, rel_path: str, record: dict[str, Any]) -> list[str]:
    hay = "\n".join(_source_pointers(record, rel_path)).lower()
    pointers: set[str] = set()
    for key in ("fixture", "fixtures", "poc", "pocs", "test", "tests", "reproducer", "reproduction"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            pointers.add(value.strip())
        elif isinstance(value, list):
            pointers.update(str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip())
    rel_dir = root / Path(rel_path).parent
    for path in rel_dir.glob("*"):
        name = path.name.lower()
        if path.is_file() and any(token in name for token in ("poc", "repro", "fixture", "test", "exploit")):
            pointers.add(str(path.relative_to(root)))
    if any(token in hay for token in ("test", "poc", "repro", "fixture")):
        pointers.add(rel_path)
    return sorted(pointers)


def _nearby_named_files(root: Path, rel_path: str, tokens: tuple[str, ...], suffixes: tuple[str, ...]) -> list[str]:
    path = root / rel_path
    candidates: set[str] = set()
    dirs = [path.parent, root / "patches", root / "pocs", root / "PoCs", root / "proofs"]
    stem = path.stem.lower()
    for directory in dirs:
        if not directory.is_dir():
            continue
        for item in directory.iterdir():
            if not item.is_file():
                continue
            name = item.name.lower()
            if suffixes and item.suffix.lower() not in suffixes:
                continue
            if stem and stem in name:
                candidates.add(str(item.relative_to(root)))
            elif any(token in name for token in tokens):
                candidates.add(str(item.relative_to(root)))
    return sorted(candidates)


def _replay_commands(record: dict[str, Any], text: str) -> list[str]:
    out: list[str] = []
    for key in ("command", "commands", "reproduce", "reproduction", "test_command", "replay_command"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
        elif isinstance(value, list):
            out.extend(str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip())
        elif isinstance(value, dict):
            out.extend(str(v).strip() for v in value.values() if isinstance(v, (str, int, float)) and str(v).strip())
    for match in re.findall(r"`((?:cargo|python3|pytest|make|forge|bash|./)[^`]+)`", text):
        out.append(match.strip())
    return sorted(set(out))


def _classify(blob: str) -> tuple[str, str]:
    for pattern, route, family in FAMILY_RULES:
        if pattern.search(blob):
            return route, family
    return "invariant", "rust_manual_semantic_review"


def _corpus_severity(blob: str, rel_path: str) -> str:
    classification = re.search(
        r"(?im)^##\s+Classification\s*$\s*(?P<body>.*?)(?:\n##\s+|\Z)",
        blob,
        re.S,
    )
    if classification:
        body = classification.group("body")
        for severity in ("Critical", "High", "Medium", "Low", "Informational"):
            if re.search(rf"\b{severity}\b", body, re.I):
                return severity
    hay = f"{rel_path}\n{blob}"
    for severity in ("Critical", "High", "Medium", "Low", "Informational"):
        if re.search(rf"\b{severity}\b", hay, re.I):
            return severity
    return "unknown"


def _component(blob: str, rel_path: str) -> str:
    hay = f"{rel_path}\n{blob}".lower()
    for name, pattern in (
        ("alloc", r"\balloc\b|vec|box|string"),
        ("io", r"\bio\b|read|write|cursor|buf"),
        ("sync", r"\bsync\b|atomic|mutex|thread"),
        ("collections", r"hashmap|btree|vecdeque|collections"),
        ("net", r"\bnet\b|socket|tcp|udp"),
        ("std_runtime", r"panic|process|env|fs|path"),
        ("rust_dlt_runtime", r"consensus|reth|evm|engine|state root|node"),
    ):
        if re.search(pattern, hay):
            return name
    parts = Path(rel_path).parts
    return parts[0] if parts else "unknown"


def _category(blob: str) -> str:
    route, family = _classify(blob)
    if route == "detector":
        return family
    if route == "replay":
        return family
    return "semantic_invariant_or_manual_review"


def _record_from_dict(root: Path, rel_path: str, record: dict[str, Any], index: int) -> RustCorpusRecord:
    sid = _record_id(record, rel_path, index)
    title = _title(record, sid)
    blob = "\n".join([
        sid,
        title,
        rel_path,
        _text_value(record, "description", "summary", "details", "root_cause", "vulnerability", "impact", "category", "keywords"),
    ])
    route, family = _classify(blob)
    corpus_severity = _corpus_severity(blob, rel_path)
    category = _category(blob)
    component = _component(blob, rel_path)
    sources = _source_pointers(record, rel_path)
    patches = _nearby_named_files(root, rel_path, ("patch", "fix", "diff"), (".patch", ".diff"))
    pocs = _nearby_named_files(root, rel_path, ("poc", "repro", "exploit"), (".rs", ".md", ".sh", ".py", ".txt"))
    fixtures = _fixture_pointers(root, rel_path, record)
    fixtures = sorted(set(fixtures + patches + pocs))
    commands = _replay_commands(record, blob)
    blockers: list[str] = []
    if not sources:
        blockers.append("missing_source_pointer")
    if not fixtures:
        blockers.append("missing_vulnerable_clean_or_replay_fixture")
    if route in {"replay", "invariant"} and not commands:
        blockers.append("missing_replay_or_adjudication_command")
    if "trait" in family or "cfg" in family or "runtime" in family:
        blockers.append("requires_cross_crate_trait_macro_cfg_resolution")
    terminal_state = "routed_with_fixture_or_replay" if not blockers else "routed_with_exact_blockers"
    next_commands = [
        "make corpus-detectorization-inventory WS=<workspace> RUST_CORPUS_INDEX=<index>",
        "make rust-runtime-semantic-blockers WS=<workspace> GENERATE=1",
    ]
    if route == "detector":
        next_commands.append("add detector plus vulnerable/clean Rust fixtures, then run the detector smoke")
    elif route == "replay":
        next_commands.append("make poc-execution-record WS=<workspace> BRIEF=<brief> CMD='<project-bound replay command>' RESULT=needs_human IMPACT=unknown")
    else:
        next_commands.append("record invariant-ledger row or kill with exact source evidence")
    return RustCorpusRecord(
        item_id=sid,
        title=title,
        corpus_root=str(root),
        rel_path=rel_path,
        source_kind=Path(rel_path).suffix.lower().lstrip(".") or "unknown",
        component=component,
        corpus_severity=corpus_severity,
        category=category,
        family=family,
        route=route,
        normalized=True,
        fixture_backed=bool(fixtures),
        detector_candidate=route == "detector",
        invariant_candidate=route == "invariant",
        replay_candidate=route == "replay" or bool(commands),
        terminal_state=terminal_state,
        blockers=sorted(set(blockers)),
        source_pointers=sources,
        patch_pointers=patches,
        poc_pointers=pocs,
        fixture_pointers=fixtures,
        replay_commands=commands,
        next_commands=next_commands,
    )


def _records_from_markdown(root: Path, path: Path, index: int) -> list[RustCorpusRecord]:
    if path.name.lower() == "readme.md" and _looks_like_swival_rust_stdlib(root):
        return []
    rel = str(path.relative_to(root))
    text = _read_text(path)
    heading = next((line.lstrip("# ").strip() for line in text.splitlines() if line.startswith("#")), path.stem)
    record = {
        "id": path.stem,
        "title": heading,
        "description": text[:8000],
        "path": rel,
    }
    return [_record_from_dict(root, rel, record, index)]


def _records_from_rust_file(root: Path, path: Path, index: int) -> list[RustCorpusRecord]:
    # In Swival/security-audits/rust-stdlib, pocs/*.rs are evidence for the
    # numbered markdown findings, not separate findings.
    if _looks_like_swival_rust_stdlib(root):
        return []
    rel = str(path.relative_to(root))
    text = _read_text(path)
    if not any(token in text.lower() for token in ("bug", "vuln", "poc", "repro", "panic", "unsafe", "overflow", "decode", "proof", "consensus")):
        return []
    record = {
        "id": path.stem,
        "title": f"Rust corpus source: {path.stem}",
        "description": text[:8000],
        "path": rel,
    }
    return [_record_from_dict(root, rel, record, index)]


def _looks_like_swival_rust_stdlib(root: Path) -> bool:
    if not root.is_dir():
        return False
    md_count = sum(1 for path in root.glob("[0-9][0-9][0-9]-*.md") if path.is_file())
    patch_count = sum(1 for path in root.glob("[0-9][0-9][0-9]-*.patch") if path.is_file())
    return md_count >= 100 and patch_count >= 100


def load_records(root: Path) -> list[RustCorpusRecord]:
    root = _resolve_corpus_root(root)
    if not root.is_dir():
        raise FileNotFoundError(f"missing Rust corpus root: {root}")
    records: list[RustCorpusRecord] = []
    index = 1
    for path in _candidate_files(root):
        rel = str(path.relative_to(root))
        if path.suffix.lower() == ".json":
            rows = _records_from_json(_read_json(path))
            for row in rows:
                records.append(_record_from_dict(root, rel, row, index))
                index += 1
        elif path.suffix.lower() in {".md", ".txt"}:
            records.extend(_records_from_markdown(root, path, index))
            index += 1
        elif path.suffix.lower() == ".rs":
            added = _records_from_rust_file(root, path, index)
            records.extend(added)
            if added:
                index += 1
    seen: set[tuple[str, str]] = set()
    unique: list[RustCorpusRecord] = []
    for rec in records:
        key = (rec.item_id, rec.rel_path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(rec)
    unique.sort(key=lambda rec: (rec.route, rec.family, rec.item_id, rec.rel_path))
    return unique


def _missing_root_blockers(workspace: Path, requested_roots: list[Path]) -> list[dict[str, Any]]:
    commands = [
        "git clone https://github.com/Swival/security-audits /path/to/security-audits",
        "make rust-corpus-ingest WS=<workspace> RUST_CORPUS_ROOT=/path/to/security-audits/rust-stdlib",
        "make corpus-detectorization-inventory WS=<workspace>",
    ]
    return [
        {
            "blocker_id": "rust-corpus-local-checkout-missing",
            "status": "terminal_missing_local_corpus_root",
            "workspace": str(workspace),
            "requested_roots": [str(p) for p in requested_roots],
            "required_input": "local Swival/security-audits rust-stdlib checkout or .auditooor/rust_corpus_roots.json declaration",
            "expected_corpus": {
                "url": "https://github.com/Swival/security-audits/tree/main/rust-stdlib",
                "expected_total": EXPECTED_SWIVAL_RUST_STDLIB_TOTAL,
                "expected_severities": EXPECTED_SWIVAL_SEVERITIES,
            },
            "why_not_closed": "cannot prove all 151 Swival Rust stdlib findings mined/normalized/fixture-backed without the local corpus",
            "next_commands": commands,
        }
    ]


def summarize(records: list[RustCorpusRecord], roots: list[Path], blockers: list[dict[str, Any]]) -> dict[str, Any]:
    by_route: dict[str, int] = {}
    by_family: dict[str, int] = {}
    by_state: dict[str, int] = {}
    for rec in records:
        by_route[rec.route] = by_route.get(rec.route, 0) + 1
        by_family[rec.family] = by_family.get(rec.family, 0) + 1
        by_state[rec.terminal_state] = by_state.get(rec.terminal_state, 0) + 1
    return {
        "corpus_present": bool(roots and not blockers),
        "roots": [str(root) for root in roots],
        "item_count": len(records),
        "expected_swival_rust_stdlib_total": EXPECTED_SWIVAL_RUST_STDLIB_TOTAL,
        "coverage_complete_for_expected_swival_total": len(records) == EXPECTED_SWIVAL_RUST_STDLIB_TOTAL,
        "mined_normalized_count": sum(1 for rec in records if rec.normalized),
        "fixture_backed_count": sum(1 for rec in records if rec.fixture_backed),
        "patch_backed_count": sum(1 for rec in records if rec.patch_pointers),
        "poc_backed_count": sum(1 for rec in records if rec.poc_pointers),
        "routed_count": sum(1 for rec in records if rec.route in {"detector", "invariant", "replay"}),
        "detector_candidates": sum(1 for rec in records if rec.detector_candidate),
        "invariant_candidates": sum(1 for rec in records if rec.invariant_candidate),
        "replay_candidates": sum(1 for rec in records if rec.replay_candidate),
        "items_with_blockers": sum(1 for rec in records if rec.blockers),
        "missing_fixture_count": sum(1 for rec in records if "missing_vulnerable_clean_or_replay_fixture" in rec.blockers),
        "semantic_resolution_required_count": sum(1 for rec in records if "requires_cross_crate_trait_macro_cfg_resolution" in rec.blockers),
        "by_route": dict(sorted(by_route.items())),
        "by_family": dict(sorted(by_family.items())),
        "by_terminal_state": dict(sorted(by_state.items())),
        "expected_swival_severities": EXPECTED_SWIVAL_SEVERITIES,
        "by_corpus_severity": {
            sev: sum(1 for rec in records if rec.corpus_severity == sev)
            for sev in sorted({rec.corpus_severity for rec in records})
        },
        "blocker_count": len(blockers),
    }


def build_payload(workspace: Path, roots: list[Path]) -> dict[str, Any]:
    ready_roots = [root.expanduser().resolve() for root in roots if root.expanduser().is_dir()]
    records: list[RustCorpusRecord] = []
    for root in ready_roots:
        records.extend(load_records(root))
    blockers = [] if ready_roots else _missing_root_blockers(workspace, roots)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "workspace": str(workspace),
        "summary": summarize(records, ready_roots, blockers),
        "blockers": blockers,
        "records": [asdict(rec) for rec in records],
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# Rust Corpus Mining Coverage",
        "",
        f"_Schema: `{payload['schema']}`_",
        "",
        "This artifact proves or blocks the RustBugs/Rust corpus mining gap. It is",
        "advisory only: rows are detector/invariant/replay candidates, not findings.",
        "",
        "## Summary",
        "",
        f"- corpus present: `{summary['corpus_present']}`",
        f"- items: `{summary['item_count']}`",
        f"- expected Swival rust-stdlib total: `{summary['expected_swival_rust_stdlib_total']}`",
        f"- complete for expected Swival total: `{summary['coverage_complete_for_expected_swival_total']}`",
        f"- normalized: `{summary['mined_normalized_count']}`",
        f"- fixture/replay backed: `{summary['fixture_backed_count']}`",
        f"- patch-backed: `{summary['patch_backed_count']}`",
        f"- PoC-backed: `{summary['poc_backed_count']}`",
        f"- routed: `{summary['routed_count']}`",
        f"- detector candidates: `{summary['detector_candidates']}`",
        f"- invariant candidates: `{summary['invariant_candidates']}`",
        f"- replay candidates: `{summary['replay_candidates']}`",
        f"- items with blockers: `{summary['items_with_blockers']}`",
        "",
    ]
    if payload["blockers"]:
        lines.extend(["## Exact Blockers", ""])
        for blocker in payload["blockers"]:
            lines.append(f"- `{blocker['blocker_id']}`: {blocker['why_not_closed']}")
        lines.append("")
    lines.extend(["## Routed Rows", ""])
    if not payload["records"]:
        lines.append("_No Rust corpus rows indexed._")
    else:
        lines.append("| ID | Severity | Component | Route | Family | Fixture-backed | State | Blockers | Title |")
        lines.append("|---|---|---|---|---|---:|---|---|---|")
        for rec in payload["records"][:200]:
            blockers = ", ".join(rec.get("blockers") or [])
            title = str(rec.get("title", "")).replace("|", "\\|")
            lines.append(
                f"| `{rec['item_id']}` | `{rec['corpus_severity']}` | `{rec['component']}` | `{rec['route']}` | `{rec['family']}` | "
                f"`{rec['fixture_backed']}` | `{rec['terminal_state']}` | {blockers or '(none)'} | {title} |"
            )
    lines.append("")
    return "\n".join(lines)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--corpus-root", type=Path, action="append", default=[], help="Local RustBugs/Rust corpus checkout/path. Repeatable.")
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[rust-corpus-ingest] workspace not found: {workspace}")
        return 2
    roots = list(args.corpus_root) or _declared_roots(workspace)
    payload = build_payload(workspace, roots)
    out_dir = (args.out_dir or (workspace / DEFAULT_OUT_DIR)).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "rust_corpus_index.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "rust_corpus_index.md").write_text(render_markdown(payload), encoding="utf-8")
    # Mirror a compact pointer under .auditooor for roadmap/accounting tools.
    auditooor = workspace / ".auditooor"
    auditooor.mkdir(parents=True, exist_ok=True)
    (auditooor / "rust_corpus_mining_coverage.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (auditooor / "rust_corpus_mining_coverage.md").write_text(render_markdown(payload), encoding="utf-8")
    if args.print_json:
        print(json.dumps({"summary": payload["summary"], "blockers": payload["blockers"]}, indent=2, sort_keys=True))
    else:
        print(f"[rust-corpus-ingest] wrote {out_dir / 'rust_corpus_index.json'}")
        print(f"[rust-corpus-ingest] items={payload['summary']['item_count']} blockers={payload['summary']['blocker_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
