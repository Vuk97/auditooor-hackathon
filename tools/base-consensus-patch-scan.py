#!/usr/bin/env python3
"""Base consensus patch-regression scanner.

This is a narrow, offline detector for mined Base patch signals that are too
semantic for generic grep output but small enough to lock with regression
fixtures. It currently covers:

* ``0bbd206a`` — ``is_deposits_only`` must iterate every transaction, not just
  the first element of the ``Option<Vec<Bytes>>`` wrapper.

Rows are advisory regression evidence only. They are not submission-ready
findings; the Base Azul loop-2 triage killed the deposits-only lane unless a
future proof supplies a non-privileged ``UnexpectedPayloadStatus`` trigger.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    from lib.project_source_roots import rust_crate_scan_roots
except ModuleNotFoundError:  # pragma: no cover - direct import from test loaders.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib.project_source_roots import rust_crate_scan_roots


SCHEMA_VERSION = "auditooor.base_consensus_patch_scan.v1"

DEFAULT_SCAN_ROOTS = (
    "external/base/crates",
    "crates",
)

TEST_PATH_TOKENS = (
    "/tests/",
    "/test_",
    "/testing/",
    "_tests.rs",
    "/benches/",
    "/examples/",
    "/fuzz/",
)

FN_START_RE = re.compile(
    r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*"
)

TARGET_IMPL_RE = re.compile(r"\bimpl(?:\s*<[^>{}]*>)?\s+AttributesWithParent\b[^{]*\{")


@dataclass
class PatchRow:
    file: str
    line: int
    pattern_id: str
    function: str
    patch_commit: str
    snippet: str
    recommendation: str
    evidence_class: str = "detector_hit"
    candidate_kind: str = "patch_regression_candidate"
    submission_posture: str = "NOT_SUBMIT_READY"
    severity: str = "none"
    trigger_precondition_required: str = (
        "A non-privileged input must make an otherwise honest mixed payload "
        "return UnexpectedPayloadStatus before this can become impact evidence."
    )


def _line_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _safe_rel(path: Path, workspace: Path) -> str:
    try:
        return str(path.relative_to(workspace))
    except ValueError:
        return str(path)


def _strip_test_blocks(text: str) -> str:
    out_parts: list[str] = []
    i = 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*\n?\s*mod\s+\w+\s*\{", text[i:])
        if not m:
            out_parts.append(text[i:])
            break
        out_parts.append(text[i:i + m.start()])
        depth = 0
        j = i + m.end() - 1
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        i = j
    return "".join(out_parts)


def _find_matching_brace(text: str, open_brace: int) -> int:
    depth = 0
    for idx in range(open_brace, len(text)):
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
            if depth == 0:
                return idx + 1
    return len(text)


def _target_impl_blocks(text: str) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for match in TARGET_IMPL_RE.finditer(text):
        open_brace = text.find("{", match.start(), match.end())
        if open_brace == -1:
            continue
        end = _find_matching_brace(text, open_brace)
        out.append((match.start(), text[match.start():end]))
    return out


def _function_bodies(text: str, base_offset: int = 0) -> list[tuple[str, int, str]]:
    out: list[tuple[str, int, str]] = []
    matches = list(FN_START_RE.finditer(text))
    for idx, match in enumerate(matches):
        start = match.start()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
        out.append((match.group(1), base_offset + start, text[start:end]))
    return out


def _snippet(text: str, offset: int) -> str:
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:160]


def _is_vulnerable_deposits_only_body(body: str) -> bool:
    compact = re.sub(r"\s+", "", body)
    if "self.attributes.transactions.iter()" not in compact:
        return False
    chain_start = compact.find("self.attributes.transactions.iter()")
    chain_end = compact.find(".all(", chain_start)
    if chain_end == -1:
        return False
    pre_all_chain = compact[chain_start:chain_end]
    if ".flatten()" in pre_all_chain:
        return False
    if "tx.first()" not in compact:
        return False
    if ".all(|tx|" not in compact and ".all(|tx:" not in compact:
        return False
    return "OpTxType::Depositasu8" in compact


def scan_file(file_path: Path, workspace: Path) -> list[PatchRow]:
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    cleaned = _strip_test_blocks(text)
    rel = _safe_rel(file_path, workspace)
    rows: list[PatchRow] = []
    for impl_start, impl_body in _target_impl_blocks(cleaned):
        for fn_name, start, body in _function_bodies(impl_body, impl_start):
            if fn_name != "is_deposits_only":
                continue
            if not _is_vulnerable_deposits_only_body(body):
                continue
            iter_pos = body.find(".iter()")
            offset = start + (iter_pos if iter_pos >= 0 else 0)
            rows.append(
                PatchRow(
                    file=rel,
                    line=_line_for_offset(cleaned, offset),
                    pattern_id="base_deposits_only_option_iter_first_tx_only",
                    function="AttributesWithParent::is_deposits_only",
                    patch_commit="0bbd206a",
                    snippet=_snippet(cleaned, offset),
                    recommendation=(
                        "Insert `.flatten()` before `.all(...)` so the classifier "
                        "checks every transaction, not just the first tx in the "
                        "Option<Vec<Bytes>> wrapper."
                    ),
                )
            )
    return rows


def enumerate_files(workspace: Path, extra_roots: list[str]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for rel in [*rust_crate_scan_roots(workspace, DEFAULT_SCAN_ROOTS), *extra_roots]:
        root = (workspace / rel).resolve()
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*.rs")):
            spath = str(path)
            if any(tok in spath for tok in TEST_PATH_TOKENS):
                continue
            if path in seen:
                continue
            seen.add(path)
            out.append(path)
    return out


def run(workspace: Path, extra_roots: list[str]) -> list[PatchRow]:
    rows: list[PatchRow] = []
    for path in enumerate_files(workspace, extra_roots):
        rows.extend(scan_file(path, workspace))
    rows.sort(key=lambda r: (r.file, r.line, r.pattern_id))
    return rows


def _count_by(rows: list[PatchRow], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows:
        k = key(row)
        out[k] = out.get(k, 0) + 1
    return out


def render_markdown(rows: list[PatchRow]) -> str:
    out: list[str] = [
        "# Base consensus patch scan",
        "",
        f"_Schema: `{SCHEMA_VERSION}`_",
        "",
        "Rows are regression candidates only and stay `NOT_SUBMIT_READY` "
        "without a separate non-privileged trigger proof.",
        "",
        "## Pattern counts",
        "",
    ]
    counts = _count_by(rows, lambda r: r.pattern_id)
    if counts:
        for key, value in sorted(counts.items()):
            out.append(f"- `{key}`: {value}")
    else:
        out.append("- _(no rows)_")
    out.extend(["", "## Rows", ""])
    if not rows:
        out.append("_No Base consensus patch-regression rows found._")
        return "\n".join(out) + "\n"
    out.append("| file:line | pattern_id | fn | patch | posture | recommendation |")
    out.append("|---|---|---|---|---|---|")
    for row in rows:
        out.append(
            "| `{file}:{line}` | `{pattern}` | `{fn}` | `{patch}` | `{posture}` | {rec} |".format(
                file=row.file,
                line=row.line,
                pattern=row.pattern_id,
                fn=row.function,
                patch=row.patch_commit,
                posture=row.submission_posture,
                rec=row.recommendation,
            )
        )
    return "\n".join(out) + "\n"


def write_outputs(workspace: Path, rows: list[PatchRow]) -> tuple[Path, Path]:
    out_dir = workspace / "critical_hunt" / "consensus_patch_scan"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "base_consensus_patch_scan.json"
    md_path = out_dir / "base_consensus_patch_scan.md"
    payload = {
        "schema": SCHEMA_VERSION,
        "workspace": str(workspace),
        "pattern_counts": _count_by(rows, lambda r: r.pattern_id),
        "rows": [asdict(row) for row in rows],
    }
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_markdown(rows), encoding="utf-8")
    return json_path, md_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="base-consensus-patch-scan.py",
        description="Offline Base consensus patch-regression scanner.",
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--root", action="append", default=[])
    parser.add_argument("--print-json", action="store_true")
    parser.add_argument("--out-json", default="")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when any patch-regression row is emitted.",
    )
    args = parser.parse_args(argv)

    workspace: Path = args.workspace
    if not workspace.is_dir():
        print(f"[base-consensus-patch-scan] ERR workspace not found: {workspace}", file=sys.stderr)
        return 2

    rows = run(workspace, list(args.root))
    if args.print_json or args.out_json == "-":
        sys.stdout.write(
            json.dumps(
                {
                    "schema": SCHEMA_VERSION,
                    "pattern_counts": _count_by(rows, lambda r: r.pattern_id),
                    "rows": [asdict(row) for row in rows],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
    else:
        json_path, md_path = write_outputs(workspace, rows)
        print(f"[base-consensus-patch-scan] wrote {json_path.relative_to(workspace)}", file=sys.stderr)
        print(f"[base-consensus-patch-scan] wrote {md_path.relative_to(workspace)}", file=sys.stderr)
        print(f"[base-consensus-patch-scan] {len(rows)} row(s)", file=sys.stderr)

    if args.strict and rows:
        print(
            f"[base-consensus-patch-scan] STRICT FAIL: {len(rows)} regression row(s)",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
