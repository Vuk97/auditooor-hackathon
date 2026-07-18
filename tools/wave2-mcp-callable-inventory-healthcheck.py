#!/usr/bin/env python3
"""Wave-2 MCP callable inventory healthcheck.

Validates internal consistency of the MCP callables shipped in
`tools/vault-mcp-server.py`. Three parity dimensions:

1. TOOL_SCHEMAS entries (advertised via MCP `tools/list`).
2. `def vault_*` class-method definitions (the actual callable bodies).
3. Dispatch entries (`if name == "vault_..."` inside `call_tool`).

Plus a fourth dimension scanned across `tools/tests/`:

4. Test files covering each callable (best-effort longest-prefix match).

Emits JSON schema `auditooor.wave2_mcp_callable_inventory_healthcheck.v1`.

This is a READ-ONLY analyzer; it never modifies vault-mcp-server.py.

Usage:
    python3 tools/wave2-mcp-callable-inventory-healthcheck.py \
        --workspace /Users/wolf/auditooor-702-full

Optional:
    --json                  emit JSON only (no stderr summary)
    --strict                exit 1 when overall_status != PASS
    --list-untested         print full untested callables list (no cap)
    --server-path PATH      override path to vault-mcp-server.py
    --tests-dir PATH        override tests directory
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA_ID = "auditooor.wave2_mcp_callable_inventory_healthcheck.v1"
DEFAULT_SERVER_RELPATH = Path("tools/vault-mcp-server.py")
DEFAULT_TESTS_RELPATH = Path("tools/tests")
UNTESTED_CAP_DEFAULT = 30
COVERAGE_PASS_THRESHOLD = 0.80

# Regex patterns. Anchored to the documented structure of vault-mcp-server.py:
#   - TOOL_SCHEMAS entries:  "name": "vault_<word>"
#   - Method defs:           ^    def vault_<word>(self, ...
#   - Dispatch entries:      ^        if name == "vault_<word>":
_SCHEMA_NAME_RE = re.compile(r'^\s*"name":\s*"(vault_[a-z0-9_]+)"', re.MULTILINE)
_METHOD_DEF_RE = re.compile(r"^    def (vault_[a-z0-9_]+)\s*\(", re.MULTILINE)
_DISPATCH_RE = re.compile(r'^\s+if name == "(vault_[a-z0-9_]+)":', re.MULTILINE)
# Versioned-name suffix (vault_foo_v2, vault_foo_v3, ...). For schema-version
# consistency: when a callable has a versioned-name suffix, we expect at least
# one sibling (the original) to exist as well; or its predecessor.
_VERSION_SUFFIX_RE = re.compile(r"_v(\d+)$")


@dataclass
class ParityIssue:
    callable_name: str
    issue_type: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {
            "callable_name": self.callable_name,
            "issue_type": self.issue_type,
            "detail": self.detail,
        }


@dataclass
class InventoryReport:
    server_path: str
    tests_dir: str
    total_schemas: int = 0
    total_methods: int = 0
    total_dispatch: int = 0
    total_callables: int = 0
    total_tests: int = 0
    parity_issues: list[ParityIssue] = field(default_factory=list)
    untested_callables: list[str] = field(default_factory=list)
    schema_version_mismatches: list[dict[str, str]] = field(default_factory=list)
    tested_callables: list[str] = field(default_factory=list)
    test_coverage_pct: float = 0.0
    overall_status: str = "PASS"
    schema_id: str = SCHEMA_ID

    def to_dict(self, untested_cap: int | None) -> dict[str, Any]:
        cap = untested_cap if untested_cap is not None else UNTESTED_CAP_DEFAULT
        truncated = self.untested_callables[:cap] if cap > 0 else list(self.untested_callables)
        return {
            "schema_id": self.schema_id,
            "server_path": self.server_path,
            "tests_dir": self.tests_dir,
            "total_callables": self.total_callables,
            "total_schemas": self.total_schemas,
            "total_methods": self.total_methods,
            "total_dispatch": self.total_dispatch,
            "total_tests": self.total_tests,
            "parity_issues": [issue.to_dict() for issue in self.parity_issues],
            "parity_issues_count": len(self.parity_issues),
            "schema_version_mismatches": list(self.schema_version_mismatches),
            "untested_callables": truncated,
            "untested_callables_total": len(self.untested_callables),
            "untested_callables_truncated": len(self.untested_callables) > len(truncated),
            "tested_callables_count": len(self.tested_callables),
            "test_coverage_pct": round(self.test_coverage_pct, 4),
            "coverage_pass_threshold": COVERAGE_PASS_THRESHOLD,
            "overall_status": self.overall_status,
        }


def _extract_names(source: str, pattern: re.Pattern[str]) -> list[str]:
    return pattern.findall(source)


def _scan_test_files(tests_dir: Path) -> list[Path]:
    if not tests_dir.is_dir():
        return []
    return sorted(p for p in tests_dir.glob("test_vault_*.py") if p.is_file())


def _assign_tests_to_callables(
    callable_names: list[str], test_files: list[Path]
) -> dict[str, list[str]]:
    """Longest-prefix-match assignment of test files to callables.

    Each test file is associated with the callable whose name is the longest
    prefix-match against the test file's basename (after stripping the
    leading ``test_``). A test file is associated with at most one callable.

    Example:
        test_vault_corpus_search_callable.py  -> vault_corpus_search
        test_vault_corpus_search_v3_callable.py -> vault_corpus_search_v3
                                                   (if that callable exists,
                                                    otherwise vault_corpus_search)
    """
    # Sort callable names by descending length to prefer longest prefix.
    sorted_callables = sorted(callable_names, key=lambda n: -len(n))
    coverage: dict[str, list[str]] = {name: [] for name in callable_names}
    for tf in test_files:
        stem = tf.stem  # test_vault_foo_bar
        if not stem.startswith("test_"):
            continue
        body = stem[len("test_") :]  # vault_foo_bar
        for name in sorted_callables:
            # Match either exact `name` or `name_` prefix to avoid
            # vault_corpus_search matching vault_corpus_search_v3.
            if body == name or body.startswith(name + "_"):
                coverage[name].append(tf.name)
                break
    return coverage


def _detect_schema_version_mismatches(
    callable_names: list[str],
) -> list[dict[str, str]]:
    """Detect versioned callables (vault_foo_v2) whose predecessor is missing.

    A versioned name `vault_foo_vN` (N >= 2) is consistent only when one of:
      - `vault_foo` exists (unversioned predecessor), OR
      - `vault_foo_v(N-1)` exists (immediate predecessor).
    Otherwise we record a version-namespace mismatch.
    """
    names_set = set(callable_names)
    mismatches: list[dict[str, str]] = []
    for name in callable_names:
        m = _VERSION_SUFFIX_RE.search(name)
        if not m:
            continue
        version = int(m.group(1))
        if version < 2:
            # v1 suffix is trivially consistent (treat as a self-version tag).
            continue
        base = name[: m.start()]
        prev_version = f"{base}_v{version - 1}"
        if base in names_set or prev_version in names_set:
            continue
        mismatches.append(
            {
                "callable_name": name,
                "detail": (
                    f"versioned callable {name!r} has no unversioned base"
                    f" {base!r} and no predecessor {prev_version!r}"
                ),
            }
        )
    return mismatches


def build_inventory_report(
    server_path: Path, tests_dir: Path
) -> InventoryReport:
    if not server_path.is_file():
        raise FileNotFoundError(f"vault-mcp-server.py not found: {server_path}")
    source = server_path.read_text(encoding="utf-8")

    schema_names = _extract_names(source, _SCHEMA_NAME_RE)
    method_names = _extract_names(source, _METHOD_DEF_RE)
    dispatch_names = _extract_names(source, _DISPATCH_RE)

    schema_set = set(schema_names)
    method_set = set(method_names)
    dispatch_set = set(dispatch_names)

    # The authoritative callable set: union of all three. A name appearing
    # in only one or two dimensions is a parity issue.
    callable_set = schema_set | method_set | dispatch_set
    callable_names = sorted(callable_set)

    parity_issues: list[ParityIssue] = []
    for name in callable_names:
        in_schema = name in schema_set
        in_method = name in method_set
        in_dispatch = name in dispatch_set
        if in_schema and not in_method:
            parity_issues.append(
                ParityIssue(
                    callable_name=name,
                    issue_type="orphan_schema_no_method",
                    detail=(
                        f"{name} has a TOOL_SCHEMAS entry but no matching "
                        f"`def {name}` method definition"
                    ),
                )
            )
        if in_method and not in_schema:
            parity_issues.append(
                ParityIssue(
                    callable_name=name,
                    issue_type="orphan_method_no_schema",
                    detail=(
                        f"{name} has a `def {name}` method but no matching "
                        f"TOOL_SCHEMAS entry"
                    ),
                )
            )
        if (in_schema or in_method) and not in_dispatch:
            parity_issues.append(
                ParityIssue(
                    callable_name=name,
                    issue_type="missing_dispatch",
                    detail=(
                        f"{name} is registered (schema={in_schema}, "
                        f"method={in_method}) but the CLI dispatch site "
                        f"contains no `if name == {name!r}:` branch"
                    ),
                )
            )
        if in_dispatch and not (in_schema and in_method):
            parity_issues.append(
                ParityIssue(
                    callable_name=name,
                    issue_type="dispatch_orphan",
                    detail=(
                        f"{name} is dispatched but missing schema "
                        f"(={in_schema}) and/or method (={in_method})"
                    ),
                )
            )

    test_files = _scan_test_files(tests_dir)
    coverage = _assign_tests_to_callables(callable_names, test_files)
    tested_callables = sorted(name for name, files in coverage.items() if files)
    untested_callables = sorted(
        name for name in callable_names if not coverage[name]
    )

    schema_version_mismatches = _detect_schema_version_mismatches(callable_names)

    test_coverage_pct = (
        (len(tested_callables) / len(callable_names)) if callable_names else 0.0
    )

    has_parity_violations = bool(parity_issues)
    has_version_violations = bool(schema_version_mismatches)
    coverage_ok = test_coverage_pct >= COVERAGE_PASS_THRESHOLD

    if has_parity_violations or has_version_violations:
        overall_status = "FAIL"
    elif not coverage_ok:
        overall_status = "WARNING"
    else:
        overall_status = "PASS"

    return InventoryReport(
        server_path=str(server_path),
        tests_dir=str(tests_dir),
        total_schemas=len(schema_names),
        total_methods=len(method_names),
        total_dispatch=len(dispatch_names),
        total_callables=len(callable_names),
        total_tests=len(test_files),
        parity_issues=parity_issues,
        untested_callables=untested_callables,
        schema_version_mismatches=schema_version_mismatches,
        tested_callables=tested_callables,
        test_coverage_pct=test_coverage_pct,
        overall_status=overall_status,
    )


def _emit_summary(report: InventoryReport, stream: Any) -> None:
    print(f"[wave2-mcp-inventory] schema_id={report.schema_id}", file=stream)
    print(
        f"[wave2-mcp-inventory] server={report.server_path}",
        file=stream,
    )
    print(
        f"[wave2-mcp-inventory] tests_dir={report.tests_dir}",
        file=stream,
    )
    print(
        f"[wave2-mcp-inventory] total_callables={report.total_callables}"
        f" schemas={report.total_schemas}"
        f" methods={report.total_methods}"
        f" dispatch={report.total_dispatch}"
        f" tests={report.total_tests}",
        file=stream,
    )
    print(
        f"[wave2-mcp-inventory] parity_issues={len(report.parity_issues)}"
        f" version_mismatches={len(report.schema_version_mismatches)}"
        f" test_coverage_pct={report.test_coverage_pct:.4f}"
        f" untested={len(report.untested_callables)}",
        file=stream,
    )
    print(f"[wave2-mcp-inventory] status={report.overall_status}", file=stream)


def _resolve_server_path(workspace: Path | None, override: Path | None) -> Path:
    if override is not None:
        return override
    if workspace is not None:
        return (workspace / DEFAULT_SERVER_RELPATH).resolve()
    return DEFAULT_SERVER_RELPATH.resolve()


def _resolve_tests_dir(workspace: Path | None, override: Path | None) -> Path:
    if override is not None:
        return override
    if workspace is not None:
        return (workspace / DEFAULT_TESTS_RELPATH).resolve()
    return DEFAULT_TESTS_RELPATH.resolve()


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate parity between TOOL_SCHEMAS, vault_* methods, dispatch "
            "branches, and tests in tools/vault-mcp-server.py."
        )
    )
    parser.add_argument(
        "--workspace",
        type=Path,
        default=None,
        help="Workspace root containing tools/vault-mcp-server.py and tools/tests/.",
    )
    parser.add_argument(
        "--server-path",
        type=Path,
        default=None,
        help="Override path to vault-mcp-server.py.",
    )
    parser.add_argument(
        "--tests-dir",
        type=Path,
        default=None,
        help="Override tests directory.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON only (no stderr summary).",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when overall_status != PASS.",
    )
    parser.add_argument(
        "--list-untested",
        action="store_true",
        help="List the full set of untested callables (no truncation cap).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    server_path = _resolve_server_path(args.workspace, args.server_path)
    tests_dir = _resolve_tests_dir(args.workspace, args.tests_dir)

    try:
        report = build_inventory_report(server_path, tests_dir)
    except FileNotFoundError as exc:
        err = {
            "schema_id": SCHEMA_ID,
            "overall_status": "FAIL",
            "error": str(exc),
        }
        print(json.dumps(err, sort_keys=True))
        return 2

    cap = 0 if args.list_untested else UNTESTED_CAP_DEFAULT
    payload = report.to_dict(untested_cap=cap)
    print(json.dumps(payload, sort_keys=True, indent=2))
    if not args.json:
        _emit_summary(report, sys.stderr)

    if args.strict and report.overall_status != "PASS":
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
