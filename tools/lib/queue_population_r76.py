"""Queue-population R76 source-existence gate.

RELATED TOOLS:
- tools/r76-hallucination-guard.py: draft and MIMO-sidecar R76 promotion gate.
  This helper is stricter for queue ingress because it validates cited paths,
  line numbers, and excerpts against production source before scoring.
- tools/exploit-queue.py: canonical queue builder that assigns priority_score.
- tools/exploit-queue-source-miner.py: source-artifact bridge for needs_source rows.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.queue_population_r76_gate.v1"
QUARANTINE_STATUS = "quarantined_r76_hallucination"
QUARANTINE_BLOCKER = "queue_population_r76_gate_failed"
SOURCE_EXTENSIONS = {".sol", ".go", ".rs", ".move", ".cairo", ".vy", ".ts", ".js", ".py"}
SOURCE_REF_RE = re.compile(
    # The extension alternation is followed by a negative lookahead
    # `(?![A-Za-z0-9])` so the matched extension is a real path-component
    # terminus, not the prefix of a longer extension. Without it,
    # `reference/outcomes.jsonl` greedily matched `reference/outcomes.js`
    # (truncating `.jsonl` / `.json` to a phantom `.js` source path that never
    # resolves) and quarantined the whole queue row as an R76 hallucination.
    r"(?P<path>[A-Za-z0-9_./~@+-]+\.(?:sol|go|rs|move|cairo|vy|ts|js|py)(?![A-Za-z0-9]))"
    r"(?:(?:#|:)L?(?P<line>\d+)(?:-(?P<end>\d+))?)?",
    re.IGNORECASE,
)
HALLUCINATION_PHRASE_RE = re.compile(
    r"\b(N/?A|conceptual|illustrative|hypothetical|typical|"
    r"vulnerable\s+pattern|generic\s+pattern|sample\s+code)\b",
    re.IGNORECASE,
)
TERMINAL_PROOF_STATUSES = {
    "killed",
    "disproved",
    "closed_negative",
    "false_positive",
    "not_exploitable",
    "drop",
    "dropped",
}
TERMINAL_QUALITY_GATE_STATUSES = {
    "killed",
    "kill",
    "drop",
    "dropped",
    "rejected_internally",
    "fp",
    "false_positive",
    "false-positive",
    "not_exploitable",
    "out_of_scope_internal",
    "disqualified",
    "advisory_not_candidate",
}
SKIP_DIR_NAMES = {
    ".git",
    ".auditooor",
    ".audit_logs",
    ".venv",
    "__pycache__",
    "node_modules",
    "target",
    "build",
    "dist",
    "out",
    "coverage",
}
NON_PRODUCTION_PARTS = {
    "test",
    "tests",
    "__tests__",
    "fixture",
    "fixtures",
    "mock",
    "mocks",
    "poc-tests",
    "pocs",
}
NON_PRODUCTION_FILE_RE = re.compile(
    r"(^test_|_test\.go$|\.t\.sol$|\.s\.sol$|\.test\.(?:ts|js|py)$|\.spec\.(?:ts|js|py)$)",
    re.IGNORECASE,
)
SOURCE_CLAIM_FIELDS = (
    "file_line",
    "target_file_line",
    "source_ref",
    "source_path",
    "source_file",
    "file",
    "path",
    "location",
    "dispatch_site",
)
TEXT_CLAIM_FIELDS = (
    "title",
    "root_cause_hypothesis",
    "impact_path",
    "reachability_trace",
    "production_path_requirement",
)
CODE_EXCERPT_FIELDS = (
    "code_excerpt",
    "source_excerpt",
    "cited_code",
    "claim_excerpt",
    "vulnerable_code_excerpt",
)


def _as_list(value: Any) -> list[Any]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return sorted(value)
    return [value]


def _is_terminal_row(row: dict[str, Any]) -> bool:
    proof_status = (
        str(row.get("proof_status") or row.get("source_mined_proof_status") or "")
        .strip()
        .lower()
    )
    gate = str(row.get("quality_gate_status") or "").strip().lower()
    return (
        proof_status in TERMINAL_PROOF_STATUSES
        or gate in TERMINAL_QUALITY_GATE_STATUSES
        or gate.startswith("closed_negative")
        or gate.startswith("drop")
    )


def _path_within_workspace(path: Path, workspace: Path) -> bool:
    try:
        resolved = path.resolve(strict=False)
        root = workspace.resolve(strict=False)
    except OSError:
        return False
    return resolved == root or root in resolved.parents


def _rel(path: Path, workspace: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(workspace.resolve(strict=False)).as_posix()
    except ValueError:
        return path.as_posix()


def is_production_source_path(path: Path, workspace: Path) -> bool:
    if path.suffix.lower() not in SOURCE_EXTENSIONS:
        return False
    if not _path_within_workspace(path, workspace):
        return False
    rel_parts = tuple(part.lower() for part in _rel(path, workspace).split("/"))
    if any(part in NON_PRODUCTION_PARTS for part in rel_parts):
        return False
    return not bool(NON_PRODUCTION_FILE_RE.search(path.name))


def _source_files(workspace: Path) -> list[Path]:
    out: list[Path] = []
    for root, dirs, files in os.walk(workspace):
        dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES]
        root_path = Path(root)
        for name in files:
            path = root_path / name
            if path.suffix.lower() in SOURCE_EXTENSIONS:
                out.append(path)
    return out


class _Resolver:
    def __init__(self, workspace: Path) -> None:
        self.workspace = workspace.expanduser().resolve()
        self._all_files: list[Path] | None = None
        self._by_basename: dict[str, list[Path]] | None = None
        self._production_text_cache: list[tuple[Path, str]] | None = None

    @property
    def all_files(self) -> list[Path]:
        if self._all_files is None:
            self._all_files = _source_files(self.workspace)
        return self._all_files

    @property
    def by_basename(self) -> dict[str, list[Path]]:
        if self._by_basename is None:
            by_name: dict[str, list[Path]] = {}
            for path in self.all_files:
                by_name.setdefault(path.name, []).append(path)
            self._by_basename = by_name
        return self._by_basename

    @property
    def production_texts(self) -> list[tuple[Path, str]]:
        if self._production_text_cache is None:
            texts: list[tuple[Path, str]] = []
            for path in self.all_files:
                if not is_production_source_path(path, self.workspace):
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                texts.append((path, _normalise_ws(text)))
            self._production_text_cache = texts
        return self._production_text_cache

    def resolve(self, raw_path: str) -> Path | None:
        raw = _clean_raw_path(raw_path)
        if not raw:
            return None
        direct = Path(raw).expanduser()
        candidates: list[Path] = []
        if direct.is_absolute():
            candidates.append(direct)
        else:
            candidates.extend(
                [
                    self.workspace / raw,
                    self.workspace / "src" / raw,
                    self.workspace / "contracts" / raw,
                    self.workspace / "protocol" / raw,
                    self.workspace / "modules" / raw,
                    self.workspace / "crates" / raw,
                ]
            )
            if raw.startswith("contracts/"):
                candidates.append(self.workspace / "src" / raw)
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=False)
            except OSError:
                continue
            if resolved.is_file() and _path_within_workspace(resolved, self.workspace):
                return resolved
        basename = Path(raw).name
        if basename:
            matches = self.by_basename.get(basename) or []
            for match in matches:
                if _rel(match, self.workspace) == raw:
                    return match.resolve(strict=False)
            if len(matches) == 1:
                return matches[0].resolve(strict=False)
            production = [m for m in matches if is_production_source_path(m, self.workspace)]
            if len(production) == 1:
                return production[0].resolve(strict=False)
            if matches:
                return matches[0].resolve(strict=False)
        return None


def _clean_raw_path(raw_path: str) -> str:
    raw = str(raw_path or "").strip().strip("`'\"()[]{}<>,;")
    if raw.startswith("workspace:"):
        raw = raw.split(":", 1)[1]
    while raw.startswith("./"):
        raw = raw[2:]
    line_match = SOURCE_REF_RE.search(raw)
    if line_match:
        return str(line_match.group("path") or "").strip()
    return raw


def _row_claims_source_backed(row: dict[str, Any]) -> bool:
    proof_status = (
        str(row.get("proof_status") or row.get("source_mined_proof_status") or row.get("_proof_status") or "")
        .strip()
        .lower()
    )
    gate = str(row.get("quality_gate_status") or "").strip().lower()
    route = str(row.get("learning_route") or "").strip().lower()
    return (
        bool(row.get("source_artifacts_complete"))
        or gate == "pass"
        or proof_status in {"proved", "needs_harness"}
        or route in {"build-harness", "prove", "falsify"}
    )


def _source_claims(
    row: dict[str, Any],
    *,
    strict_source_refs: bool = True,
    strict_field_refs: bool = True,
) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    include_derived_refs = strict_source_refs or _row_claims_source_backed(row)

    def add(field: str, text: Any, *, excerpt: str = "") -> None:
        if text in (None, "", [], {}):
            return
        raw = str(text).strip()
        if not raw:
            return
        matches = list(SOURCE_REF_RE.finditer(raw))
        if matches:
            for match in matches:
                path = str(match.group("path") or "").strip()
                line = str(match.group("line") or "").strip()
                if field in TEXT_CLAIM_FIELDS and not line:
                    continue
                key = (field, path, line)
                if key in seen:
                    continue
                seen.add(key)
                claims.append(
                    {
                        "field": field,
                        "raw": raw[:500],
                        "path": path,
                        "line": int(line) if line.isdigit() else None,
                        "excerpt": excerpt,
                    }
                )
            return
        if Path(raw).suffix.lower() in SOURCE_EXTENSIONS or HALLUCINATION_PHRASE_RE.search(raw):
            key = (field, raw, "")
            if key not in seen:
                seen.add(key)
                claims.append({"field": field, "raw": raw[:500], "path": raw, "line": None, "excerpt": excerpt})

    always_claim_fields = {"file_line", "target_file_line", "source_ref"}
    for field in SOURCE_CLAIM_FIELDS:
        if not strict_field_refs and field not in always_claim_fields:
            continue
        add(field, row.get(field))
    if include_derived_refs:
        for item in _as_list(row.get("source_refs")):
            if isinstance(item, dict):
                excerpt = str(item.get("excerpt") or "")
                for key in ("path", "source_ref", "file_line", "source_path", "file"):
                    add(f"source_refs.{key}", item.get(key), excerpt=excerpt)
            else:
                add("source_refs", item)
        for field in TEXT_CLAIM_FIELDS:
            add(field, row.get(field))
    return claims


def _code_excerpts(row: dict[str, Any]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        for item in _as_list(value):
            text = str(item or "").strip()
            if text and text not in seen:
                seen.add(text)
                out.append(text)

    for field in CODE_EXCERPT_FIELDS:
        add(row.get(field))
    for item in _as_list(row.get("source_refs")):
        if isinstance(item, dict):
            add(item.get("excerpt"))
    return out


def _normalise_ws(text: str) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()


def _excerpt_needles(excerpt: str) -> list[str]:
    text = str(excerpt or "").strip()
    if not text:
        return []
    lines = [_normalise_ws(line) for line in text.splitlines() if len(_normalise_ws(line)) >= 8]
    if not lines and len(_normalise_ws(text)) >= 8:
        lines = [_normalise_ws(text)]
    needles: list[str] = []
    seen: set[str] = set()
    for line in sorted(lines, key=len, reverse=True):
        needle = line[:180].strip()
        if len(needle) < 8 or needle in seen:
            continue
        seen.add(needle)
        needles.append(needle)
        if len(needles) >= 3:
            break
    return needles


def _excerpt_hits_production_source(resolver: _Resolver, excerpt: str) -> bool | None:
    needles = _excerpt_needles(excerpt)
    if not needles:
        return None
    for _path, text in resolver.production_texts:
        for needle in needles:
            if needle in text:
                return True
    return False


def _line_exists(path: Path, line: int | None) -> bool:
    if not line:
        return True
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for index, _line in enumerate(handle, 1):
                if index >= line:
                    return True
    except OSError:
        return False
    return False


def check_queue_row_source_existence(
    row: dict[str, Any],
    workspace: Path,
    resolver: _Resolver | None = None,
    *,
    strict_source_refs: bool = True,
    enforce_source_backed_refs: bool = True,
    strict_field_refs: bool = True,
) -> dict[str, Any]:
    resolver = resolver or _Resolver(workspace)
    if _is_terminal_row(row):
        return {
            "schema": SCHEMA,
            "verdict": "pass-terminal-row",
            "hallucinated": False,
            "reason": "terminal rows are preserved and not reopened",
            "failures": [],
            "checks": [],
        }

    failures: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    claims = _source_claims(
        row,
        strict_source_refs=strict_source_refs or (enforce_source_backed_refs and _row_claims_source_backed(row)),
        strict_field_refs=strict_field_refs,
    )
    for claim in claims:
        raw = str(claim.get("raw") or "")
        path_text = str(claim.get("path") or "")
        if HALLUCINATION_PHRASE_RE.search(raw) and not SOURCE_REF_RE.search(raw):
            failures.append({"reason": "conceptual_file_line", "field": claim.get("field"), "raw": raw[:200]})
            continue
        resolved = resolver.resolve(path_text)
        if resolved is None:
            failures.append({"reason": "missing_source_path", "field": claim.get("field"), "path": path_text})
            continue
        production = is_production_source_path(resolved, resolver.workspace)
        rel = _rel(resolved, resolver.workspace)
        if not production:
            failures.append({"reason": "test_only_or_non_production_source", "field": claim.get("field"), "path": rel})
            continue
        line = claim.get("line")
        if isinstance(line, int) and not _line_exists(resolved, line):
            failures.append({"reason": "source_line_missing", "field": claim.get("field"), "path": rel, "line": line})
            continue
        checks.append({"field": claim.get("field"), "path": rel, "line": line, "status": "production_source_exists"})

    excerpt_checks = 0
    for excerpt in _code_excerpts(row):
        hit = _excerpt_hits_production_source(resolver, excerpt)
        if hit is None:
            continue
        excerpt_checks += 1
        if hit is False:
            failures.append(
                {
                    "reason": "code_excerpt_not_in_production_source",
                    "excerpt_needle": _excerpt_needles(excerpt)[:1],
                }
            )
        else:
            checks.append({"field": "code_excerpt", "status": "production_excerpt_hit"})

    if failures:
        return {
            "schema": SCHEMA,
            "verdict": "fail-source-claim-not-in-production",
            "hallucinated": True,
            "reason": "one or more cited source claims did not resolve in production source",
            "failures": failures,
            "checks": checks,
            "source_claim_count": len(claims),
            "code_excerpt_check_count": excerpt_checks,
        }
    if claims or excerpt_checks:
        return {
            "schema": SCHEMA,
            "verdict": "pass-verified-source-claim",
            "hallucinated": False,
            "reason": "all cited source claims resolve in production source",
            "failures": [],
            "checks": checks,
            "source_claim_count": len(claims),
            "code_excerpt_check_count": excerpt_checks,
        }
    return {
        "schema": SCHEMA,
        "verdict": "pass-no-source-claim",
        "hallucinated": False,
        "reason": "row has no cited source claim for R76 queue gate",
        "failures": [],
        "checks": [],
        "source_claim_count": 0,
        "code_excerpt_check_count": 0,
    }


def _failure_categories(verdict: dict[str, Any]) -> set[str]:
    return {str(f.get("reason") or "unknown") for f in verdict.get("failures") or [] if isinstance(f, dict)}


def quarantine_row(row: dict[str, Any], verdict: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    out.pop("priority_score", None)
    out.pop("_chain_boost", None)
    out["hallucinated"] = True
    out["r76_queue_population_status"] = QUARANTINE_STATUS
    out["r76_queue_population_gate"] = verdict
    out["quality_gate_status"] = QUARANTINE_STATUS
    out["proof_status"] = "killed"
    out["learning_route"] = "closed-negative"
    out["source_artifacts_complete"] = False
    blockers = [str(item) for item in (out.get("blockers") or []) if str(item).strip()]
    blockers.append(QUARANTINE_BLOCKER)
    for category in sorted(_failure_categories(verdict)):
        blockers.append(f"r76_{category}")
    out["blockers"] = sorted(set(blockers))
    gaps = [str(item) for item in (out.get("source_artifact_gaps") or []) if str(item).strip()]
    gaps.append("r76_hallucinated_source_claim")
    out["source_artifact_gaps"] = sorted(set(gaps))
    tt = dict(out.get("truth_table_summary") or {})
    tt.update(
        {
            "source_state": "r76_quarantined",
            "next_action": "none",
            "proof_shell": "none",
            "triager_objection": "cited source claim not found in production source",
        }
    )
    out["truth_table_summary"] = tt
    return out


def is_quarantined_row(row: dict[str, Any]) -> bool:
    return bool(row.get("hallucinated") is True or row.get("r76_queue_population_status") == QUARANTINE_STATUS)


def queue_population_r76_gate(
    workspace: Path,
    rows: list[dict[str, Any]],
    *,
    strict_source_refs: bool = True,
    enforce_source_backed_refs: bool = True,
    strict_field_refs: bool = True,
) -> dict[str, Any]:
    resolver = _Resolver(workspace)
    gated_rows: list[dict[str, Any]] = []
    survived_rows: list[dict[str, Any]] = []
    quarantined_rows: list[dict[str, Any]] = []
    verdicts: list[dict[str, Any]] = []
    reason_counts: dict[str, int] = {}
    source_claim_rows = 0

    for index, row in enumerate(rows):
        verdict = check_queue_row_source_existence(
            row,
            workspace,
            resolver,
            strict_source_refs=strict_source_refs,
            enforce_source_backed_refs=enforce_source_backed_refs,
            strict_field_refs=strict_field_refs,
        )
        verdict["row_index"] = index
        verdict["lead_id"] = row.get("lead_id") or row.get("candidate_id") or row.get("id") or ""
        verdicts.append(verdict)
        if int(verdict.get("source_claim_count") or 0) > 0 or int(verdict.get("code_excerpt_check_count") or 0) > 0:
            source_claim_rows += 1
        if verdict.get("hallucinated") is True:
            qrow = quarantine_row(row, verdict)
            gated_rows.append(qrow)
            quarantined_rows.append(qrow)
            for category in _failure_categories(verdict):
                reason_counts[category] = reason_counts.get(category, 0) + 1
            continue
        out = dict(row)
        if verdict.get("verdict") == "pass-verified-source-claim":
            out["r76_queue_population_status"] = "pass_verified_source_claim"
        gated_rows.append(out)
        survived_rows.append(out)

    total = len(rows)
    dropped = len(quarantined_rows)
    summary = {
        "schema": SCHEMA,
        "candidate_rows": total,
        "total_rows": total,
        "source_claim_rows": source_claim_rows,
        "survived_rows": total - dropped,
        "passed": total - dropped,
        "blocked": dropped,
        "quarantined": dropped,
        "drop_count": dropped,
        "reason_counts": reason_counts,
    }
    for key, value in reason_counts.items():
        summary[f"blocked_{key}"] = value
    return {
        "schema": SCHEMA,
        "summary": summary,
        "rows": gated_rows,
        "survived_rows": survived_rows,
        "quarantined_rows": quarantined_rows,
        "verdicts": verdicts,
    }
