#!/usr/bin/env python3
"""Score prior-audit saturation per active target module.

HACKERMAN V3 Lane E1 is a target-selection intake guard: before spending
cold-read time, count which in-scope modules have already been covered by
prior audits and write a bounded advisory artifact:

    <workspace>/.auditooor/target_saturation.json

The score is an attention-routing signal only. It should redirect effort away
from saturated core modules and toward cold reads, peripherals, or state
divergence where appropriate.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "auditooor.target_saturation.v1"

SOURCE_HINT_FILES = ("SCOPE.md", "scope.json", "README.md")
PRIOR_AUDIT_MAX_BYTES = 2_000_000
TEXT_EXTENSIONS = {
    ".csv",
    ".json",
    ".jsonl",
    ".md",
    ".rst",
    ".text",
    ".tsv",
    ".txt",
    ".yaml",
    ".yml",
}

PATH_HINT_RE = re.compile(
    r"(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.-]+\."
    r"(?:sol|rs|go|move|cairo|vy|ts|js|tsx|jsx)",
    re.IGNORECASE,
)
CODE_SPAN_RE = re.compile(r"`([^`\n]{2,160})`")
IDENTIFIER_RE = re.compile(r"\b[A-Z][A-Za-z0-9_]{2,80}\b")

GENERIC_IDENTIFIERS = {
    "Assets",
    "Audit",
    "Audits",
    "Blockchain",
    "Contract",
    "Contracts",
    "Critical",
    "High",
    "Low",
    "Medium",
    "README",
    "Scope",
    "SCOPE",
    "Severity",
    "Smart",
    "TODO",
}

CORE_TERMS = (
    "accounting",
    "controller",
    "core",
    "exchange",
    "kernel",
    "ledger",
    "market",
    "protocol",
    "router",
    "settlement",
    "trading",
    "vault",
)

PERIPHERAL_TERMS = (
    "adapter",
    "bridge",
    "constructor",
    "factory",
    "init",
    "oracle",
    "peripheral",
    "wrapper",
)

KNOWN_FIRMS = (
    "ackee",
    "certora",
    "chainsecurity",
    "chain security",
    "consensys",
    "dedaub",
    "halborn",
    "hexens",
    "informal systems",
    "mixbytes",
    "nethermind",
    "openzeppelin",
    "open zeppelin",
    "openzeppelin contracts",
    "pashov",
    "peckshield",
    "spearbit",
    "trail of bits",
    "trailofbits",
    "zellic",
)


@dataclass
class ModuleHint:
    module: str
    aliases: set[str] = field(default_factory=set)
    hint_sources: set[str] = field(default_factory=set)


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compact(value: str, limit: int = 500) -> str:
    return " ".join(str(value or "").split())[:limit]


def _read_text(path: Path, limit: int | None = None) -> str:
    data = path.read_bytes()
    if limit is not None:
        data = data[:limit]
    return data.decode("utf-8", errors="replace")


def _canonical_module(value: str) -> str:
    value = str(value or "").strip().strip("`'\"")
    value = value.replace("\\", "/").rstrip("/")
    if "/" in value:
        value = value.rsplit("/", 1)[-1]
    suffix = Path(value).suffix
    if suffix:
        value = value[: -len(suffix)]
    value = re.sub(r"[^A-Za-z0-9_ -]+", "", value).strip(" _-")
    return value


def _is_useful_module_name(value: str) -> bool:
    if not value or len(value) < 3:
        return False
    if value in GENERIC_IDENTIFIERS:
        return False
    if value.lower() in {v.lower() for v in GENERIC_IDENTIFIERS}:
        return False
    if re.fullmatch(r"[0-9a-fA-F]{6,}", value):
        return False
    return bool(re.search(r"[A-Za-z]", value))


def _camel_words(value: str) -> list[str]:
    return re.findall(r"[A-Z]+(?=[A-Z][a-z]|\b)|[A-Z]?[a-z]+|[0-9]+", value)


def _alias_variants(module: str) -> set[str]:
    aliases = {module}
    lowered = module.lower()
    aliases.add(lowered)
    snake = re.sub(r"[^A-Za-z0-9]+", "_", module).strip("_")
    if snake:
        aliases.add(snake)
        aliases.add(snake.lower())
        aliases.add(snake.replace("_", "-").lower())
        aliases.add(snake.replace("_", " ").lower())
    words = _camel_words(module)
    if len(words) > 1:
        aliases.add(" ".join(words).lower())
        aliases.add("-".join(words).lower())
        aliases.add("_".join(words).lower())
    return {a for a in aliases if _is_useful_module_name(a)}


def _path_context_aliases(value: str) -> list[str]:
    parts = [p for p in str(value or "").replace("\\", "/").split("/") if p]
    if len(parts) <= 1:
        return []
    return [_canonical_module(part) for part in parts[:-1]]


def _add_module(
    modules: dict[str, ModuleHint],
    raw: str,
    source: str,
    extra_aliases: Iterable[str] = (),
) -> None:
    module = _canonical_module(raw)
    if not _is_useful_module_name(module):
        return
    entry = modules.setdefault(module, ModuleHint(module=module))
    entry.hint_sources.add(source)
    entry.aliases.update(_alias_variants(module))
    for alias in extra_aliases:
        cleaned = _canonical_module(alias)
        if _is_useful_module_name(cleaned):
            entry.aliases.update(_alias_variants(cleaned))


def _strings_from_json(value: Any, key_path: tuple[str, ...] = ()) -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _strings_from_json(child, key_path + (str(key),))
    elif isinstance(value, list):
        for child in value:
            yield from _strings_from_json(child, key_path)
    elif isinstance(value, str):
        yield ".".join(key_path), value


def _load_scope_json_modules(path: Path, modules: dict[str, ModuleHint]) -> None:
    try:
        data = json.loads(_read_text(path))
    except Exception:
        return
    key_markers = ("scope", "path", "contract", "module", "target", "asset")
    for key_path, value in _strings_from_json(data):
        low_key = key_path.lower()
        if not any(marker in low_key for marker in key_markers):
            continue
        if "/" in value or Path(value).suffix:
            _add_module(modules, value, str(path.name), extra_aliases=_path_context_aliases(value))
        elif re.fullmatch(r"[A-Za-z][A-Za-z0-9_ -]{2,80}", value):
            _add_module(modules, value, str(path.name))


def _load_markdown_modules(path: Path, modules: dict[str, ModuleHint]) -> None:
    text = _read_text(path, limit=500_000)
    for match in PATH_HINT_RE.finditer(text):
        value = match.group(0)
        _add_module(modules, value, path.name, extra_aliases=_path_context_aliases(value))
    for match in CODE_SPAN_RE.finditer(text):
        span = match.group(1).strip()
        if "/" in span or Path(span).suffix:
            _add_module(modules, span, path.name, extra_aliases=_path_context_aliases(span))
        elif re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{2,80}", span):
            _add_module(modules, span, path.name)
    for match in re.finditer(
        r"(?im)^\s*(?:[-*]\s*)?(?:contract|module|target|asset)\s*[:\-]\s*([A-Za-z][A-Za-z0-9_ ./-]{2,160})$",
        text,
    ):
        value = match.group(1).strip()
        if "," in value:
            for part in value.split(","):
                _add_module(modules, part, path.name)
        else:
            _add_module(modules, value, path.name)
    for match in IDENTIFIER_RE.finditer(text):
        value = match.group(0)
        if value not in GENERIC_IDENTIFIERS and (
            value.endswith(("Adapter", "Factory", "Module", "Oracle", "Router", "Vault", "Wrapper"))
            or len(_camel_words(value)) > 1
        ):
            _add_module(modules, value, path.name)


def load_module_hints(workspace: Path) -> dict[str, ModuleHint]:
    modules: dict[str, ModuleHint] = {}
    for name in SOURCE_HINT_FILES:
        path = workspace / name
        if not path.is_file():
            continue
        if path.name == "scope.json":
            _load_scope_json_modules(path, modules)
        else:
            _load_markdown_modules(path, modules)
    return modules


def _iter_prior_audit_files(workspace: Path) -> list[Path]:
    prior_dir = workspace / "prior_audits"
    if not prior_dir.is_dir():
        return []
    files: list[Path] = []
    for path in sorted(prior_dir.rglob("*")):
        if not path.is_file() or path.name.startswith("."):
            continue
        if path.suffix.lower() and path.suffix.lower() not in TEXT_EXTENSIONS:
            continue
        files.append(path)
    return files


def _alias_regex(alias: str) -> re.Pattern[str]:
    escaped = re.escape(alias)
    if re.search(r"[\s_-]", alias):
        escaped = re.sub(r"\\[ _-]+", r"[\\s_-]+", escaped)
    return re.compile(rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])", re.IGNORECASE)


def _count_alias_mentions(text: str, aliases: Iterable[str]) -> int:
    total = 0
    for alias in sorted(set(aliases), key=len, reverse=True):
        if not _is_useful_module_name(alias):
            continue
        total += len(_alias_regex(alias).findall(text))
    return total


def _firm_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def infer_firm(path: Path, text: str) -> str:
    haystack = f"{path.name}\n{text[:4000]}".lower()
    for firm in KNOWN_FIRMS:
        if firm in haystack:
            return _firm_slug(firm.replace(" ", "-"))
    for pattern in (
        r"\baudit(?:ed)?\s+by\s+([A-Z][A-Za-z0-9 &.-]{2,40})",
        r"\bby\s+([A-Z][A-Za-z0-9 &.-]{2,40})\s+(?:audit|security review)",
        r"\b([A-Z][A-Za-z0-9 &.-]{2,40})\s+(?:audit|security review)\b",
    ):
        match = re.search(pattern, text[:4000])
        if match:
            return _firm_slug(match.group(1))
    stem = path.stem.lower()
    for sep in ("_", "-", " "):
        if sep in stem:
            first = stem.split(sep, 1)[0]
            if len(first) >= 3 and first not in {"digest", "audit", "report"}:
                return _firm_slug(first)
    return _firm_slug(path.stem)


def _is_core_module(module: str, aliases: Iterable[str]) -> bool:
    joined = " ".join([module, *aliases]).lower()
    return any(term in joined for term in CORE_TERMS)


def _has_peripheral_signal(module: str, aliases: Iterable[str]) -> bool:
    joined = " ".join([module, *aliases]).lower()
    return any(term in joined for term in PERIPHERAL_TERMS)


def _saturation_score(audit_mentions: int, firm_count: int, evidence_count: int) -> int:
    if audit_mentions <= 0 and firm_count <= 0:
        return 0
    return min(100, audit_mentions * 12 + firm_count * 24 + evidence_count * 8)


def _recommend_action(
    *,
    prior_audits_present: bool,
    audit_mentions: int,
    firm_count: int,
    score: int,
    active: bool,
    core: bool,
    peripheral_signal: bool,
) -> str:
    if not prior_audits_present:
        return "insufficient_data"
    if score >= 70 or firm_count >= 2 or audit_mentions >= 5:
        if core and not peripheral_signal:
            return "state_divergence_only"
        return "deprioritize"
    if active:
        return "cold_read"
    return "insufficient_data"


def build_payload(workspace: Path) -> dict[str, Any]:
    workspace = workspace.expanduser().resolve()
    module_hints = load_module_hints(workspace)
    prior_files = _iter_prior_audit_files(workspace)
    prior_audits_present = bool(prior_files)

    mention_counts: Counter[str] = Counter()
    evidence: dict[str, set[str]] = defaultdict(set)
    firms: dict[str, set[str]] = defaultdict(set)

    for path in prior_files:
        try:
            text = _read_text(path, limit=PRIOR_AUDIT_MAX_BYTES)
        except OSError:
            continue
        rel = str(path.relative_to(workspace))
        firm = infer_firm(path, text)
        for module, hint in module_hints.items():
            count = _count_alias_mentions(text, hint.aliases | {module})
            if count <= 0:
                continue
            mention_counts[module] += count
            evidence[module].add(rel)
            firms[module].add(firm)

    rows: list[dict[str, Any]] = []
    for module in sorted(module_hints):
        hint = module_hints[module]
        audit_mentions = int(mention_counts[module])
        firm_count = len(firms[module])
        evidence_paths = sorted(evidence[module])
        score = _saturation_score(audit_mentions, firm_count, len(evidence_paths))
        core = _is_core_module(module, hint.aliases)
        peripheral_signal = _has_peripheral_signal(module, hint.aliases)
        rows.append(
            {
                "module": module,
                "audit_mentions": audit_mentions,
                "firm_count": firm_count,
                "evidence_paths": evidence_paths,
                "saturation_score": score,
                "recommended_action": _recommend_action(
                    prior_audits_present=prior_audits_present,
                    audit_mentions=audit_mentions,
                    firm_count=firm_count,
                    score=score,
                    active=True,
                    core=core,
                    peripheral_signal=peripheral_signal,
                ),
                "active_hint": True,
                "core_hint": core,
                "hint_sources": sorted(hint.hint_sources),
            }
        )

    action_counts = Counter(row["recommended_action"] for row in rows)
    summary = {
        "module_count": len(rows),
        "prior_audit_files_scanned": len(prior_files),
        "prior_audits_present": prior_audits_present,
        "actions": dict(sorted(action_counts.items())),
        "high_saturation_modules": sum(1 for row in rows if row["saturation_score"] >= 70),
        "cold_read_modules": action_counts.get("cold_read", 0),
    }
    if not module_hints:
        summary["warning"] = "no_scope_module_hints"
    elif not prior_audits_present:
        summary["warning"] = "missing_prior_audits"

    return {
        "schema": SCHEMA_VERSION,
        "generated_at": now_utc(),
        "workspace_path": str(workspace),
        "modules": rows,
        "summary": summary,
    }


def write_payload(payload: dict[str, Any], workspace: Path, out: Path | None = None) -> Path:
    workspace = workspace.expanduser().resolve()
    if out is None:
        out = workspace / ".auditooor" / "target_saturation.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score prior-audit saturation per target module.")
    parser.add_argument("workspace", nargs="?", help="Audit workspace path.")
    parser.add_argument("--workspace", dest="workspace_flag", help="Audit workspace path.")
    parser.add_argument("--out", type=Path, help="Override output path.")
    parser.add_argument("--print-json", action="store_true", help="Print payload JSON to stdout.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv or sys.argv[1:]))
    workspace_arg = args.workspace_flag or args.workspace
    if not workspace_arg:
        print("usage: target-saturation-score.py <workspace>", file=sys.stderr)
        return 2
    workspace = Path(workspace_arg)
    payload = build_payload(workspace)
    out = write_payload(payload, workspace, args.out)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[target-saturation-score] wrote {out}")
        print(
            "[target-saturation-score] "
            f"modules={payload['summary']['module_count']} "
            f"prior_audit_files={payload['summary']['prior_audit_files_scanned']} "
            f"actions={payload['summary']['actions']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
