#!/usr/bin/env python3
"""Map fixture-less P1 pattern sources to local workspaces or archives.

Issue #311 is intentionally operator/archive dependent: agents must not
fabricate ``~/audits/<name>`` directories when a pattern's original source is
not locally available. This helper makes that dependency explicit. It groups
DSL patterns by their ``source:`` field, checks which groups still lack
vulnerable+clean regression rows, and searches only operator-supplied local
roots for plausible source archives.

The tool is stdlib-only and offline-safe. It never clones, downloads, or
mutates a workspace.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DSL_DIR = ROOT / "reference" / "patterns.dsl"
DEFAULT_RUN_TESTS = ROOT / "detectors" / "test_fixtures" / "run_tests.sh"

STOP_TOKENS = {
    "auditooor",
    "source",
    "pattern",
    "finding",
    "cluster",
    "slice",
    "loop",
    "cycle",
    "from",
}

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "node_modules",
    "target",
    "out",
    "cache",
    "artifacts",
    "broadcast",
}


@dataclass(frozen=True)
class PatternRecord:
    pattern: str
    source: str
    path: str
    has_vuln_row: bool
    has_clean_row: bool

    @property
    def fixture_complete(self) -> bool:
        return self.has_vuln_row and self.has_clean_row


@dataclass(frozen=True)
class SourceGroup:
    source: str
    source_key: str
    pattern_count: int
    fixtureless_count: int
    status: str
    matches: list[str]
    patterns: list[str]
    searched_roots: list[str]  # roots checked when status == "missing"; empty when archive-found/local-workspace


def _read_scalar(raw: str, key: str) -> str | None:
    match = re.search(rf"^{re.escape(key)}:\s*(.*?)\s*$", raw, re.M)
    if not match:
        return None
    value = match.group(1).strip()
    if (value.startswith('"') and value.endswith('"')) or (
        value.startswith("'") and value.endswith("'")
    ):
        return value[1:-1]
    return value


def _normalize(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _tokens(value: str) -> list[str]:
    out: list[str] = []
    for token in re.split(r"[^A-Za-z0-9]+", value):
        if not token or not token[0].isalpha():
            continue
        cleaned = token.lower()
        if len(cleaned) >= 4 and cleaned not in STOP_TOKENS:
            out.append(cleaned)
    return out


def source_key(source: str) -> str:
    first = source.split("/", 1)[0].strip()
    return first or source.strip()


def parse_run_tests(path: Path) -> tuple[set[str], set[str]]:
    if not path.is_file():
        return set(), set()
    vuln: set[str] = set()
    clean: set[str] = set()
    row_re = re.compile(r'^\s*(run_test|run_clean_test)\s+"([^"]+)"', re.M)
    for kind, pattern in row_re.findall(path.read_text(encoding="utf-8", errors="ignore")):
        if kind == "run_test":
            vuln.add(pattern)
        else:
            clean.add(pattern)
    return vuln, clean


def load_patterns(dsl_dir: Path, run_tests: Path) -> list[PatternRecord]:
    vuln_rows, clean_rows = parse_run_tests(run_tests)
    records: list[PatternRecord] = []
    for path in sorted(dsl_dir.glob("*.yaml")):
        raw = path.read_text(encoding="utf-8", errors="ignore")
        if re.search(r"^status:\s*documentation-only\b", raw, re.M):
            continue
        pattern = _read_scalar(raw, "pattern") or path.stem
        source = _read_scalar(raw, "source") or ""
        if not source:
            continue
        records.append(
            PatternRecord(
                pattern=pattern,
                source=source,
                path=str(path),
                has_vuln_row=pattern in vuln_rows,
                has_clean_row=pattern in clean_rows,
            )
        )
    return records


def _iter_search_paths(roots: Iterable[Path], max_depth: int, exclude_dirs: set[str]) -> Iterable[Path]:
    for root in roots:
        root = root.expanduser()
        if not root.exists():
            continue
        root = root.resolve()
        for current, dirnames, filenames in os.walk(root):
            cur = Path(current)
            try:
                rel_depth = len(cur.relative_to(root).parts)
            except ValueError:
                continue
            dirnames[:] = [
                name
                for name in dirnames
                if name not in exclude_dirs and (max_depth <= 0 or rel_depth < max_depth)
            ]
            for name in dirnames:
                yield cur / name
            if max_depth <= 0 or rel_depth < max_depth:
                for name in filenames:
                    yield cur / name


def find_archive_matches(
    source: str,
    roots: list[Path],
    max_depth: int,
    limit: int,
    exclude_dirs: set[str] | None = None,
    search_paths: list[Path] | None = None,
) -> list[str]:
    norm_source = _normalize(source)
    toks = _tokens(source)
    matches: list[str] = []
    seen: set[str] = set()
    excludes = exclude_dirs if exclude_dirs is not None else DEFAULT_EXCLUDE_DIRS
    paths = search_paths if search_paths is not None else list(_iter_search_paths(roots, max_depth, excludes))
    for path in paths:
        name = path.name.lower()
        norm_name = _normalize(path.name)
        token_hits = sum(1 for tok in toks if tok and tok in name)
        exactish = bool(norm_source and (norm_source in norm_name or norm_name in norm_source))
        if not exactish and token_hits < 2:
            continue
        value = str(path)
        if value not in seen:
            seen.add(value)
            matches.append(value)
        if len(matches) >= limit:
            break
    return matches


def local_workspace_keys(audits_dir: Path) -> set[str]:
    audits_dir = audits_dir.expanduser()
    if not audits_dir.is_dir():
        return set()
    return {p.name for p in audits_dir.iterdir() if p.is_dir()}


def build_groups(
    records: list[PatternRecord],
    *,
    audits_dir: Path,
    search_roots: list[Path],
    max_depth: int,
    match_limit: int,
    only_fixtureless: bool,
    exclude_dirs: set[str] | None = None,
) -> list[SourceGroup]:
    workspace_names = local_workspace_keys(audits_dir)
    excludes = exclude_dirs if exclude_dirs is not None else DEFAULT_EXCLUDE_DIRS
    search_paths = list(_iter_search_paths(search_roots, max_depth, excludes)) if search_roots else []
    by_source: dict[str, list[PatternRecord]] = {}
    for rec in records:
        if only_fixtureless and rec.fixture_complete:
            continue
        by_source.setdefault(rec.source, []).append(rec)

    groups: list[SourceGroup] = []
    searched_root_strs = [str(r.expanduser().resolve()) for r in search_roots if r.expanduser().exists()]
    for source, items in by_source.items():
        key = source_key(source)
        fixtureless = [item for item in items if not item.fixture_complete]
        matches: list[str] = []
        group_searched_roots: list[str] = []
        if key in workspace_names:
            status = "local-workspace"
            matches = [str(audits_dir.expanduser() / key)]
        else:
            matches = find_archive_matches(
                source,
                search_roots,
                max_depth,
                match_limit,
                excludes,
                search_paths=search_paths,
            )
            if matches:
                status = "archive-found"
            else:
                status = "missing"
                # Record which roots were searched so "missing" carries explicit evidence,
                # not just unknown status.  Satisfies P0-5 burndown requirement.
                group_searched_roots = searched_root_strs
        groups.append(
            SourceGroup(
                source=source,
                source_key=key,
                pattern_count=len(items),
                fixtureless_count=len(fixtureless),
                status=status,
                matches=matches,
                patterns=sorted(item.pattern for item in items),
                searched_roots=group_searched_roots,
            )
        )
    groups.sort(key=lambda g: (-g.fixtureless_count, g.status, g.source))
    return groups


def _extract_workspace_and_source(match: str) -> tuple[str, str]:
    path = Path(match).expanduser()
    if path.is_file():
        return str(path.parent), str(path)
    return str(path), ""


def extraction_queue(groups: list[SourceGroup], *, max_patterns_per_group: int = 0) -> list[dict[str, object]]:
    """Return explicit extraction work for available groups plus deferred evidence rows for missing ones.

    Available groups (local-workspace / archive-found) get actionable shell commands.
    Missing groups get deferred rows with ``source_status: "missing"`` and ``searched_roots``
    so that every fixture-less pattern has an explicit evidence trail rather than unknown status.
    This satisfies the P0-5 burndown requirement: "Missing-source groups need explicit evidence,
    not unknown status."
    """
    items: list[dict[str, object]] = []
    for group in groups:
        if group.status in {"local-workspace", "archive-found"} and group.matches:
            workspace, source_file = _extract_workspace_and_source(group.matches[0])
            patterns = group.patterns[:max_patterns_per_group] if max_patterns_per_group > 0 else group.patterns
            for pattern in patterns:
                argv = [
                    "python3",
                    "tools/p1-fixture-extractor.py",
                    "--pattern",
                    pattern,
                    "--workspace",
                    workspace,
                ]
                if source_file:
                    argv.extend(["--source-file", source_file])
                argv.extend(["--strict-smoke-fire"])
                items.append(
                    {
                        "source": group.source,
                        "source_status": group.status,
                        "pattern": pattern,
                        "workspace": workspace,
                        "source_file": source_file,
                        "requires_llm_consent": True,
                        "guardrails": [
                            "Do not fabricate workspaces.",
                            "Only accept fixtures after vulnerable>=1 and clean==0 smoke-fire.",
                            "Use Kimi for fixture drafting and Minimax for adversarial review; Codex verifies final diff.",
                        ],
                        "argv": argv,
                        "shell_command": " ".join(shlex.quote(part) for part in argv),
                    }
                )
        elif group.status == "missing" and group.fixtureless_count > 0:
            # Deferred row: no actionable command, but explicit evidence that we searched.
            patterns = group.patterns[:max_patterns_per_group] if max_patterns_per_group > 0 else group.patterns
            for pattern in patterns:
                items.append(
                    {
                        "source": group.source,
                        "source_status": "missing",
                        "pattern": pattern,
                        "workspace": None,
                        "source_file": None,
                        "requires_llm_consent": False,
                        "searched_roots": group.searched_roots,
                        "missing_reason": (
                            "No local workspace or archive match found in searched roots. "
                            "Operator must supply source before fixture extraction can proceed."
                        ),
                        "guardrails": [
                            "Do not fabricate workspaces.",
                            "Do not attempt extraction until an operator supplies the source archive.",
                        ],
                        "argv": None,
                        "shell_command": None,
                    }
                )
    return items


def render_markdown(groups: list[SourceGroup]) -> str:
    lines = [
        "# P1 Source Archive Map",
        "",
        "Generated by `tools/p1-source-archive-map.py`. Do not treat `missing`",
        "as proof that no archive exists; it only means the configured local",
        "search roots did not contain a plausible match.",
        "",
        "| Fixture-less | Status | Source | Matches / Searched Roots |",
        "|---:|---|---|---|",
    ]
    for group in groups:
        if group.matches:
            detail = "<br>".join(group.matches[:3])
        elif group.searched_roots:
            detail = "searched: " + "; ".join(group.searched_roots[:3])
        else:
            detail = "(no search roots configured)"
        lines.append(
            f"| {group.fixtureless_count} | {group.status} | `{group.source}` | {detail} |"
        )
    lines.append("")
    return "\n".join(lines)


def render_queue_markdown(items: list[dict[str, object]]) -> str:
    actionable = [i for i in items if i.get("shell_command")]
    deferred = [i for i in items if not i.get("shell_command")]
    lines = [
        "# P1 Fixture Extraction Queue",
        "",
        "Generated by `tools/p1-source-archive-map.py`. Actionable rows have shell",
        "commands for available local/archive-backed source groups. Deferred rows",
        "record `missing` groups with explicit evidence of which roots were searched,",
        "satisfying the P0-5 requirement that missing-source groups carry evidence",
        "rather than unknown status.",
        "",
    ]
    if not actionable and not deferred:
        lines.extend(["No extraction items.", ""])
        return "\n".join(lines)
    if actionable:
        lines.extend([
            "## Actionable",
            "",
            "| Pattern | Source | Status | Command |",
            "|---|---|---|---|",
        ])
        for item in actionable:
            command = str(item["shell_command"]).replace("|", "\\|")
            lines.append(
                f"| `{item['pattern']}` | `{item['source']}` | `{item['source_status']}` | `{command}` |"
            )
        lines.append("")
    if deferred:
        lines.extend([
            "## Deferred (source missing — explicit evidence)",
            "",
            "| Pattern | Source | Searched Roots |",
            "|---|---|---|",
        ])
        for item in deferred:
            roots = "; ".join(str(r) for r in (item.get("searched_roots") or [])[:3]) or "(none)"
            lines.append(
                f"| `{item['pattern']}` | `{item['source']}` | {roots} |"
            )
        lines.append("")
    lines.extend([
        "## Guardrails",
        "",
        "- Set `AUDITOOOR_LLM_NETWORK_CONSENT=1` before real provider calls.",
        "- Use `--mock-dispatcher` only in tests.",
        "- Do not commit fixtures unless smoke-fire proves vulnerable hits >= 1 and clean hits == 0.",
        "- Do not attempt extraction for deferred rows until an operator supplies the source archive.",
    ])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsl-dir", type=Path, default=DEFAULT_DSL_DIR)
    parser.add_argument("--run-tests", type=Path, default=DEFAULT_RUN_TESTS)
    parser.add_argument("--audits-dir", type=Path, default=Path("~/audits"))
    parser.add_argument(
        "--search-root",
        type=Path,
        action="append",
        default=[],
        help="Local archive root to search. Repeatable.",
    )
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--match-limit", type=int, default=5)
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        help=(
            "Directory basename to prune while searching archive roots. "
            "Defaults include .git, node_modules, target, out, cache, artifacts, and broadcast."
        ),
    )
    parser.add_argument("--top", type=int, default=0, help="Limit output groups.")
    parser.add_argument(
        "--all-patterns",
        action="store_true",
        help="Include groups whose patterns already have complete fixture rows.",
    )
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--out-queue-json", type=Path)
    parser.add_argument("--out-queue-md", type=Path)
    parser.add_argument(
        "--queue-max-patterns-per-group",
        type=int,
        default=0,
        help="Limit extraction queue rows per available source group. 0 means all patterns.",
    )
    args = parser.parse_args(argv)

    search_roots = args.search_root or [args.audits_dir, Path("~/Downloads/auditooor")]
    records = load_patterns(args.dsl_dir, args.run_tests)
    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir)
    groups = build_groups(
        records,
        audits_dir=args.audits_dir,
        search_roots=search_roots,
        max_depth=args.max_depth,
        match_limit=args.match_limit,
        only_fixtureless=not args.all_patterns,
        exclude_dirs=exclude_dirs,
    )
    if args.top > 0:
        groups = groups[: args.top]
    queue = extraction_queue(groups, max_patterns_per_group=args.queue_max_patterns_per_group)

    missing_groups = [g for g in groups if g.status == "missing"]
    missing_with_evidence = [g for g in missing_groups if g.searched_roots]
    payload = {
        "total_patterns": len(records),
        "fixtureless_patterns": sum(1 for rec in records if not rec.fixture_complete),
        "group_count": len(groups),
        "missing_group_count": len(missing_groups),
        "missing_with_evidence_count": len(missing_with_evidence),
        "search_roots": [str(path.expanduser()) for path in search_roots],
        "exclude_dirs": sorted(exclude_dirs),
        "extraction_queue_count": len(queue),
        "groups": [asdict(group) for group in groups],
    }

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(render_markdown(groups), encoding="utf-8")
    if args.out_queue_json:
        args.out_queue_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_queue_json.write_text(json.dumps(queue, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.out_queue_md:
        args.out_queue_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_queue_md.write_text(render_queue_markdown(queue), encoding="utf-8")

    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
