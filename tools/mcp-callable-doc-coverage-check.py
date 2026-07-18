#!/usr/bin/env python3
"""Check whether the MCP callable reference docs cover an inventory.

This tool compares documented callable names extracted from
`docs/HACKERMAN_MCP_CALLABLE_REFERENCE_2026-05-16.md` against either:

1. The live callable inventory discovered from `tools/vault-mcp-server.py`
   (`TOOL_SCHEMAS`-style `"name": "vault_x"` entries), or
2. A supplied fixture inventory file (JSON or JSONL).

Typical use:

  - `python3 tools/mcp-callable-doc-coverage-check.py --json`
  - `python3 tools/mcp-callable-doc-coverage-check.py --inventory /tmp/inventory.jsonl --strict --json`

Output schema: auditooor.mcp_callable_doc_coverage_check.v1
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import OrderedDict
from pathlib import Path

SCHEMA_ID = "auditooor.mcp_callable_doc_coverage_check.v1"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DOC_PATH = REPO_ROOT / "docs" / "HACKERMAN_MCP_CALLABLE_REFERENCE_2026-05-16.md"
DEFAULT_SERVER_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"

DOC_SECTION_RE = re.compile(r"^###\s+`(vault_[a-z0-9_]+)`")
SERVER_CALLABLE_RE = re.compile(r'"name"\s*:\s*"(vault_[a-z0-9_]+)"')
JSON_NAME_RE = re.compile(r"^vault_[a-z0-9_]+$")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_callables_from_doc(path: Path) -> list[tuple[int, str]]:
    """Return ordered (line_no, callable_name) from doc section headers."""
    if not path.is_file():
        return []
    out: list[tuple[int, str]] = []
    for lineno, line in enumerate(_read_text(path).splitlines(), 1):
        match = DOC_SECTION_RE.match(line)
        if match:
            out.append((lineno, match.group(1)))
    return out


def _collect_names(obj: object, out: set[str]) -> None:
    """Collect every vault_* string appearing under a `name` key."""
    if isinstance(obj, dict):
        if isinstance(obj.get("name"), str):
            name = obj["name"]
            if JSON_NAME_RE.match(name):
                out.add(name)
        for value in obj.values():
            _collect_names(value, out)
        return
    if isinstance(obj, list):
        for value in obj:
            _collect_names(value, out)


def _extract_callables_from_json_text(text: str) -> list[str]:
    data = json.loads(text)
    names: set[str] = set()
    _collect_names(data, names)
    return sorted(names)


def load_fixture_inventory(path: Path) -> list[str]:
    """Load callable names from a JSON/JSONL fixture inventory."""
    if not path.is_file():
        raise FileNotFoundError(f"fixture inventory not found: {path}")

    text = _read_text(path)
    text = text.strip()
    if not text:
        return []

    if path.suffix.lower() == ".jsonl":
        names: set[str] = set()
        for line_no, raw in enumerate(text.splitlines(), 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError as exc:  # pragma: no cover - defensive path
                raise ValueError(f"invalid JSONL at line {line_no}: {path}") from exc
            _collect_names(payload, names)
        return sorted(names)

    return _extract_callables_from_json_text(text)


def load_server_inventory(server_path: Path) -> list[str]:
    """Load callable names from the local vault-mcp-server file."""
    if not server_path.is_file():
        raise FileNotFoundError(f"server file not found: {server_path}")
    text = _read_text(server_path)
    return sorted(set(SERVER_CALLABLE_RE.findall(text)))


def build_report(
    *,
    doc_path: Path,
    inventory_path: Path | None = None,
    server_path: Path = DEFAULT_SERVER_PATH,
    strict: bool = False,
) -> dict:
    report: dict[str, object] = {
        "schema": SCHEMA_ID,
        "doc_path": str(doc_path),
        "inventory_path": None,
        "strict": strict,
        "overall": "pass",
        "doc_sections": [],
        "doc_unique": 0,
        "inventory_count": 0,
        "covered_count": 0,
        "coverage_pct": 0.0,
        "missing_in_doc": [],
        "extra_in_doc": [],
        "warnings": [],
        "errors": [],
    }

    if not doc_path.is_file():
        report["overall"] = "fail"
        report["errors"].append({"type": "missing-doc", "path": str(doc_path)})
        return report

    doc_items = _extract_callables_from_doc(doc_path)
    doc_seen: OrderedDict[str, int] = OrderedDict()
    for lineno, name in doc_items:
        if name not in doc_seen:
            doc_seen[name] = lineno
    report["doc_sections"] = [{"callable": n, "line": ln} for n, ln in doc_seen.items()]

    try:
        if inventory_path is not None:
            inventory_names = load_fixture_inventory(inventory_path)
            report["inventory_path"] = str(inventory_path)
        else:
            inventory_names = load_server_inventory(server_path)
            report["inventory_path"] = str(server_path)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        report["overall"] = "fail"
        report["errors"].append({"type": "inventory-load-failed", "message": str(exc)})
        return report

    inventory_set = set(inventory_names)
    doc_set = set(doc_seen.keys())

    missing = sorted(inventory_set - doc_set)
    extra = sorted(doc_set - inventory_set)

    report["inventory_count"] = len(inventory_names)
    report["doc_unique"] = len(doc_set)
    covered = sorted(inventory_set & doc_set)
    report["covered_count"] = len(covered)
    report["coverage_pct"] = (
        round((len(covered) / len(inventory_names)) * 100.0, 2)
        if inventory_names
        else 0.0
    )
    report["missing_in_doc"] = [{"callable": name} for name in missing]
    report["extra_in_doc"] = [
        {"callable": name, "line": doc_seen[name]}
        for name in extra
    ]

    if missing:
        report["overall"] = "fail"
        report["errors"].append(
            {
                "type": "missing-callable-documentation",
                "count": len(missing),
            }
        )
    if strict and extra:
        report["overall"] = "fail"
        report["errors"].append(
            {
                "type": "extra-callable-documentation",
                "count": len(extra),
            }
        )
    if (extra and not strict) and report["overall"] == "pass":
        report["warnings"].append(
            {
                "type": "extra-callable-documentation",
                "count": len(extra),
            }
        )

    return report


def render_human(report: dict) -> None:
    print(f"[mcp-doc-coverage] doc: {report['doc_path']}")
    print(f"[mcp-doc-coverage] inventory: {report['inventory_path']}")
    print(f"[mcp-doc-coverage] strict: {report['strict']}")
    if report["errors"]:
        print(f"overall: {report['overall']} (issues: {len(report['errors'])})")
    else:
        print(f"overall: {report['overall']}")
    print(
        f"inventory_count: {report['inventory_count']} "
        f"documented: {report['doc_unique']} covered: {report['covered_count']} "
        f"coverage: {report['coverage_pct']}%"
    )

    if report["missing_in_doc"]:
        print(f"missing_in_doc: {len(report['missing_in_doc'])}")
        for entry in report["missing_in_doc"]:
            print(f"  - {entry['callable']}")
    else:
        print("missing_in_doc: 0")

    if report["extra_in_doc"]:
        print(f"extra_in_doc: {len(report['extra_in_doc'])}")
        for entry in report["extra_in_doc"]:
            print(f"  - {entry['callable']} (line {entry['line']})")
    else:
        print("extra_in_doc: 0")

    if report["warnings"]:
        print(f"warnings: {len(report['warnings'])}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--doc-path",
        type=Path,
        default=DEFAULT_DOC_PATH,
        help="Path to MCP callable reference markdown (default: docs/HACKERMAN_MCP_CALLABLE_REFERENCE_2026-05-16.md)",
    )
    parser.add_argument(
        "--inventory-path",
        type=Path,
        default=None,
        help="Optional JSON or JSONL fixture inventory containing callable rows",
    )
    parser.add_argument(
        "--server-path",
        type=Path,
        default=DEFAULT_SERVER_PATH,
        help="Server file used as default inventory source when --inventory-path is omitted",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "Treat extra documented callables (not in inventory) as hard failure "
            "in addition to missing coverage"
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    doc_path = args.doc_path
    if not doc_path.is_absolute():
        doc_path = (Path.cwd() / doc_path).resolve()

    inventory_path = args.inventory_path
    if inventory_path is not None and not inventory_path.is_absolute():
        inventory_path = (Path.cwd() / inventory_path).resolve()

    server_path = args.server_path
    if not server_path.is_absolute():
        server_path = (Path.cwd() / server_path).resolve()

    report = build_report(
        doc_path=doc_path,
        inventory_path=inventory_path,
        server_path=server_path,
        strict=args.strict,
    )

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        render_human(report)

    return 0 if report["overall"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
