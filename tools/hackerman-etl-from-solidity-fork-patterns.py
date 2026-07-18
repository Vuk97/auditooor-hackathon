#!/usr/bin/env python3
"""Convert Solidity fork-pattern markdown/DSL rows into hackerman_record v1 YAML."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
DEFAULT_PATTERNS_DIR = REPO_ROOT / "patterns"
DEFAULT_DSL_DIR = REPO_ROOT / "reference" / "patterns.dsl"
TEXT_EXTENSIONS = {".md", ".markdown"}


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_solidity_fork_patterns",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


@dataclass(frozen=True)
class PatternSource:
    source_kind: str
    path: Path
    language: str
    title: str
    family: str
    target: str
    trigger_shape: str
    fix_shape: str
    detector_regex: str
    applicability_heuristic: str
    origin_commit_sha: str
    source_report_reference: str
    severity: str
    confidence: str
    text: str


SUPPORTED_DSL_LANGUAGES = {
    "assembly",
    "cairo",
    "go",
    "huff",
    "move",
    "python-onchain",
    "rust",
    "solidity",
    "typescript-onchain",
    "vyper",
}


def load_yaml(path: Path) -> dict[str, Any]:
    data = _VALIDATOR.load_yaml(path)
    return data if isinstance(data, dict) else {}


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def one_line(text: object, fallback: str, *, max_len: int = 1000) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    return (cleaned[:max_len].strip() if cleaned else fallback)


def contains_any(text: str, needles: Iterable[str]) -> bool:
    low = text.lower()
    return any(needle in low for needle in needles)


def yaml_scalar(value: object) -> str:
    if isinstance(value, int):
        return str(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#-]+", text)
        and not text.endswith(":")
        and not text.startswith(("#", "-", "?", ":"))
    )
    if plain_safe and not numeric and not ambiguous:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: dict[str, Any]) -> str:
    lines: list[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for subkey, subvalue in value.items():
                if isinstance(subvalue, list):
                    lines.append(f"  {subkey}:")
                    for item in subvalue:
                        lines.append(f"    - {yaml_scalar(item)}")
                else:
                    lines.append(f"  {subkey}: {yaml_scalar(subvalue)}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        first = True
                        for subkey, subvalue in item.items():
                            lines.append(f"{'  -' if first else '  '} {subkey}: {yaml_scalar(subvalue)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def _markdown_field(text: str, field: str) -> str:
    match = re.search(rf"(?m)^-\s+{re.escape(field)}:\s*(.*)$", text)
    if not match:
        return ""
    value = match.group(1).strip()
    if len(value) >= 2 and value[0] == "`" and value[-1] == "`":
        value = value[1:-1]
    return value.strip()


def _markdown_title(text: str, path: Path) -> str:
    match = re.search(r"(?m)^#\s+(.+?)\s*$", text)
    return match.group(1).strip() if match else path.stem


def discover_markdown(patterns_dir: Path) -> list[Path]:
    if not patterns_dir.is_dir():
        return []
    return sorted(
        path
        for path in patterns_dir.rglob("*")
        if path.is_file()
        and path.suffix.lower() in TEXT_EXTENSIONS
        and path.name.lower() != "index.md"
    )


def markdown_source(path: Path, patterns_dir: Path) -> PatternSource:
    text = path.read_text(encoding="utf-8", errors="replace")
    title = _markdown_title(text, path)
    family = _markdown_field(text, "family") or path.parent.name
    target = _markdown_field(text, "target") or "unknown"
    trigger = _markdown_field(text, "trigger-shape") or title
    fix = _markdown_field(text, "fix-shape") or "Replay the upstream semantic fix in downstream forks."
    detector = _markdown_field(text, "detector-regex") or slugify(title)
    heuristic = _markdown_field(text, "applicability heuristic") or "Applicable to forks retaining the same invariant surface."
    origin = _markdown_field(text, "origin commit SHA") or "unknown"
    source_ref = _markdown_field(text, "source report reference") or f"patterns:{path.relative_to(patterns_dir).as_posix()}"
    return PatternSource(
        source_kind="fork-pattern-markdown",
        path=path,
        language="solidity",
        title=title,
        family=family,
        target=target,
        trigger_shape=trigger,
        fix_shape=fix,
        detector_regex=detector,
        applicability_heuristic=heuristic,
        origin_commit_sha=origin,
        source_report_reference=source_ref,
        severity="medium",
        confidence="medium",
        text=text,
    )


def discover_dsl(dsl_dir: Path) -> list[Path]:
    if not dsl_dir.is_dir():
        return []
    return sorted(path for path in dsl_dir.glob("*.yaml") if path.is_file())


def _dsl_backend(data: dict[str, Any]) -> str:
    return str(data.get("backend") or data.get("language") or "solidity").strip().lower()


def _dsl_language(data: dict[str, Any]) -> str:
    backend = _dsl_backend(data)
    if backend == "documentation_only":
        return str(data.get("language") or "solidity").strip().lower()
    return backend


def _source_target(source: str) -> str:
    paren = re.search(r"\(([^/)]+/[^/)]+)\)", source)
    if paren:
        return paren.group(1)
    bare = re.search(r"\b([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)\b", source)
    return bare.group(1) if bare else "unknown"


def dsl_source(path: Path, data: dict[str, Any]) -> PatternSource | None:
    language = _dsl_language(data)
    if language not in SUPPORTED_DSL_LANGUAGES:
        return None
    source = str(data.get("source") or "")
    source_id = str(data.get("source_id") or "").strip()
    title = str(data.get("wiki_title") or data.get("title") or data.get("help") or data.get("pattern") or data.get("id") or path.stem)
    description = str(data.get("wiki_description") or data.get("help") or data.get("real_world_example") or "")
    exploit = str(data.get("wiki_exploit_scenario") or data.get("real_world_example") or description or title)
    recommendation = str(data.get("wiki_recommendation") or data.get("suggested_remediation") or "")
    indicators = data.get("indicators") if isinstance(data.get("indicators"), list) else []
    pattern = str(data.get("pattern") or data.get("id") or path.stem)
    text = "\n".join(
        [
            title,
            description,
            exploit,
            recommendation,
            source,
            str(data.get("source_url") or ""),
            str(data.get("platform") or ""),
            str(data.get("protocol") or ""),
            " ".join(str(item) for item in indicators),
            pattern,
        ]
    )
    rel = path.relative_to(REPO_ROOT).as_posix() if path.is_relative_to(REPO_ROOT) else path.name
    source_ref = source or f"dsl:{rel}"
    if source_id:
        source_ref = f"{source_ref}:{source_id}"
    return PatternSource(
        source_kind="canonical-dsl",
        path=path,
        language=language,
        title=title,
        family=str(data.get("family") or data.get("platform") or infer_family(text)),
        target=_source_target(source),
        trigger_shape=exploit,
        fix_shape=recommendation or "Apply the source DSL remediation and add invariant regression coverage.",
        detector_regex=pattern,
        applicability_heuristic=str(data.get("help") or f"Canonical {language} DSL detector pattern."),
        origin_commit_sha=str(data.get("origin_commit_sha") or "canonical"),
        source_report_reference=source_ref,
        severity=normalize_severity(str(data.get("severity") or "medium"), text),
        confidence=str(data.get("confidence") or "medium").lower(),
        text=text,
    )


def infer_family(text: str) -> str:
    rules = (
        ("aave-collateral", ("aave", "emode", "health factor")),
        ("compound-comptroller", ("compound", "comptroller", "comp", "ctoken")),
        ("cdp", ("maker", "cdp", "dai", "vat", "flap", "flip", "clip")),
        ("curve-stableswap", ("curve", "stableswap", "virtual price")),
        ("balancer-pool", ("balancer", "weighted pool")),
        ("oz-upgrade", ("openzeppelin", "proxy", "upgrade", "uups")),
        ("liquity-fork", ("liquity", "trove", "stability pool")),
    )
    for family, needles in rules:
        if contains_any(text, needles):
            return family
    return "solidity-fork"


def infer_domain(text: str, family: str) -> str:
    haystack = f"{family}\n{text}"
    rules = (
        ("rpc-infra", ("listenfinalizeblock", "indexer", "rpc", "mempool", "node")),
        ("rollup", ("l1-l2", "l2", "rollup", "storage root", "state root", "tree finalization")),
        ("bridge", ("bridge", "cross-chain", "layerzero", "ccip", "wormhole", "axelar")),
        ("bridge", ("ibc", "bitcoin observer", "sighash", "channel version")),
        ("consensus", ("cosmos", "cosmos-sdk", "cometbft", "finalizeblock", "prepareproposal", "processproposal", "validator", "consensus")),
        ("oracle", ("oracle", "price", "twap", "chainlink", "pyth")),
        ("governance", ("governance", "vote", "proposal", "timelock", "dao")),
        ("dex", ("swap", "amm", "pool", "liquidity", "curve", "balancer", "uniswap", "flap", "flip", "auction")),
        ("lending", ("borrow", "debt", "liquidation", "collateral", "trove", "compound", "aave", "cdp")),
        ("staking", ("stake", "validator", "delegat", "stability pool")),
        ("nft", ("nft", "erc721", "erc-721", "seaport")),
        ("vault", ("vault", "shares", "deposit", "withdraw", "erc4626")),
    )
    for domain, needles in rules:
        if contains_any(haystack, needles):
            return domain
    return "vault"


def infer_bug_attack(text: str) -> tuple[str, str]:
    rules = (
        ("denial-of-service", "dos-griefing", ("dos", "denial of service", "blocked", "stuck", "grief", "rejects signed", "prevents the block from being indexed")),
        ("input-validation", "missing-input-validation", ("validate", "validation", "unchecked", "unvalidated", "guard", "check", "version negotiation", "negotiated finalversion")),
        ("access-control", "admin-bypass", ("access", "auth", "authorization", "unauthorized", "permission", "role", "admin")),
        ("reentrancy", "reentrancy", ("reentrancy", "reentrant", "callback")),
        ("oracle-manipulation", "stale-or-manipulated-oracle", ("oracle", "twap", "price", "spot")),
        ("signature-replay", "signature-replay", ("signature", "replay", "eip712", "permit", "nonce")),
        ("precision-loss", "rounding-precision-loss", ("rounding", "precision", "overflow", "underflow", "division", "units")),
        ("liquidation-logic", "liquidation-invariant-bypass", ("liquidation", "collateral", "health factor")),
        ("fee-accounting", "state-accounting-drift", ("fee", "reward", "emission", "accrual", "accounting")),
        ("upgrade-safety", "upgrade-invariant-bypass", ("upgrade", "proxy", "storage")),
    )
    for bug_class, attack_class, needles in rules:
        if contains_any(text, needles):
            return bug_class, attack_class
    return "logic-error", "protocol-invariant-bypass"


def infer_impact(text: str) -> str:
    if contains_any(text, ("steal", "drain", "theft", "loss of funds", "fund loss")):
        return "theft"
    if contains_any(text, ("freeze", "stuck", "locked")):
        return "freeze"
    if contains_any(text, ("dos", "denial of service", "blocked", "bricked")):
        return "dos"
    if contains_any(text, ("reward", "yield", "fee", "accrual", "interest")):
        return "yield-redistribution"
    if contains_any(text, ("governance", "proposal", "vote", "quorum")):
        return "governance-takeover"
    if contains_any(text, ("admin", "role", "unauthorized", "privilege")):
        return "privilege-escalation"
    if contains_any(text, ("rounding", "precision", "overflow", "underflow")):
        return "precision-loss"
    return "griefing"


def infer_attacker_role(text: str) -> str:
    if contains_any(text, ("governance", "proposal", "voter", "dao")):
        return "governance"
    if contains_any(text, ("admin", "owner", "privileged", "role")):
        return "privileged-compromised"
    if "validator" in text.lower():
        return "validator"
    if "sequencer" in text.lower():
        return "sequencer"
    if contains_any(text, ("block proposer", "miner", "mev")):
        return "block-proposer"
    return "unprivileged"


def infer_impact_actor(text: str) -> str:
    if contains_any(text, ("treasury", "protocol")):
        return "protocol-treasury"
    if "validator" in text.lower():
        return "validator-set"
    if "sequencer" in text.lower():
        return "sequencer"
    if contains_any(text, ("depositor", "lender", "borrower", "lp", "liquidity provider", "vault")):
        return "depositor-class"
    if contains_any(text, ("reward", "yield", "interest")):
        return "yield-recipient"
    if contains_any(text, ("victim", "specific user")):
        return "specific-user"
    return "arbitrary-user"


def normalize_severity(raw: str, text: str) -> str:
    value = (raw or "").strip().lower()
    aliases = {"c": "critical", "crit": "critical", "h": "high", "m": "medium"}
    value = aliases.get(value, value)
    if value in {"critical", "high", "medium", "low", "info"}:
        return value
    low = text.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"\b{severity}\b", low):
            return severity
    return "medium"


def infer_dollar_class(severity: str, impact: str) -> str:
    if severity == "critical":
        return ">=$1M"
    if severity == "high":
        return "$100K-$1M"
    if severity == "low":
        return "<$10K"
    if impact in {"dos", "griefing"}:
        return "non-financial"
    return "$10K-$100K"


def infer_component(source: PatternSource) -> str:
    haystack = f"{source.trigger_shape}\n{source.text}"
    for pattern in (
        r"`([^`\n]{1,120})`",
        r"\b([A-Za-z0-9_./-]+\.(?:sol|go|rs|move|cairo|vy|huff))\b",
        r"\b(function\s+[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)",
        r"\b(func\s+(?:\([^)]*\)\s*)?[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)",
        r"\b(fn\s+[A-Za-z_][A-Za-z0-9_]*(?:\([^)]*\))?)",
    ):
        match = re.search(pattern, haystack)
        if match:
            return match.group(1).strip()[:240]
    return source.title[:240] or source.family


def infer_signature(component: str, language: str = "solidity") -> str:
    if component.startswith(("function ", "func ", "fn ")):
        return component
    if "(" in component and ")" in component:
        if language == "go":
            return f"func {component}"
        if language == "rust":
            return f"fn {component}"
        return f"function {component}"
    if language == "go":
        return f"func {slugify(component, max_len=48).replace('-', '_')}()"
    if language == "rust":
        return f"fn {slugify(component, max_len=48).replace('-', '_')}()"
    if language == "move":
        return f"public fun {slugify(component, max_len=48).replace('-', '_')}()"
    return f"function {slugify(component, max_len=48).replace('-', '_')}()"


def normalize_repo(raw: str) -> str:
    text = (raw or "").strip()
    if re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", text):
        return text
    return "unknown"


def shape_tags(language: str, bug_class: str, attack_class: str, family: str) -> list[str]:
    out = [slugify(attack_class), slugify(f"{language}-{bug_class}")]
    fam = slugify(family, max_len=64)
    if fam not in out:
        out.append(fam)
    return out


def required_preconditions(source: PatternSource, domain: str, bug_class: str) -> list[str]:
    items = [
        one_line(source.applicability_heuristic, "", max_len=220),
        one_line(source.detector_regex, "", max_len=220),
    ]
    cleaned = [item for item in items if item]
    if cleaned:
        return list(dict.fromkeys(cleaned))[:3]
    return [f"{domain} fork preserves the source pattern's {bug_class} invariant surface"]


def source_ref_for(source: PatternSource) -> str:
    if source.source_kind == "fork-pattern-markdown":
        rel = source.path.relative_to(REPO_ROOT).as_posix() if source.path.is_relative_to(REPO_ROOT) else source.path.name
        return f"solidity-fork-pattern:{rel}:{slugify(source.origin_commit_sha, max_len=16)}"
    rel = source.path.relative_to(REPO_ROOT).as_posix() if source.path.is_relative_to(REPO_ROOT) else source.path.name
    suffix = slugify(source.source_report_reference, max_len=80)
    return f"canonical-dsl:{rel}:{suffix}" if suffix else f"canonical-dsl:{rel}"


def build_record(source: PatternSource) -> dict[str, Any]:
    text = "\n".join(
        [
            source.family,
            source.title,
            source.trigger_shape,
            source.fix_shape,
            source.detector_regex,
            source.applicability_heuristic,
            source.text,
        ]
    )
    severity = normalize_severity(source.severity, text)
    domain = infer_domain(text, source.family)
    bug_class, attack_class = infer_bug_attack(text)
    impact = infer_impact(text)
    component = infer_component(source)
    source_ref = source_ref_for(source)
    digest = hashlib.sha256(f"{source_ref}\n{source.title}\n{source.trigger_shape}".encode("utf-8")).hexdigest()[:12]
    if source.source_kind == "canonical-dsl":
        record_id = f"dsl-pattern:{source.language}:{slugify(source.path.stem, max_len=72)}:{digest}"
    else:
        record_id = f"solidity-fork-pattern:{slugify(source.path.stem, max_len=72)}:{digest}"
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": source_ref[:240],
        "target_domain": domain,
        "target_language": source.language,
        "target_repo": normalize_repo(source.target),
        "target_component": component,
        "function_shape": {
            "raw_signature": infer_signature(component, source.language),
            "shape_tags": shape_tags(source.language, bug_class, attack_class, source.family),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": infer_attacker_role(text),
        "attacker_action_sequence": one_line(
            source.trigger_shape,
            f"Exercise the fork path described by {source.title}.",
            max_len=1000,
        ),
        "required_preconditions": required_preconditions(source, domain, bug_class),
        "impact_class": impact,
        "impact_actor": infer_impact_actor(text),
        "impact_dollar_class": infer_dollar_class(severity, impact),
        "fix_pattern": one_line(source.fix_shape, "Replay the upstream semantic fix and add invariant regression coverage."),
        "fix_anti_pattern_avoided": "assuming fork inheritance preserves upstream security fixes without checking invariant drift",
        "severity_at_finding": severity,
        "year": 2000,
        "cross_language_analogues": [],
        "related_records": [],
    }


def output_filename(record: dict[str, Any]) -> str:
    digest = str(record["record_id"]).rsplit(":", 1)[-1]
    return f"{slugify(record['record_id'], max_len=110)}-{digest}.yaml"


def collect_sources(patterns_dirs: Sequence[Path], dsl_dirs: Sequence[Path], *, include_dsl: bool) -> tuple[list[PatternSource], dict[str, int], list[str]]:
    sources: list[PatternSource] = []
    warnings: list[str] = []
    counters = {"markdown_scanned": 0, "dsl_scanned": 0, "dsl_skipped": 0}
    for patterns_dir in patterns_dirs:
        for path in discover_markdown(patterns_dir):
            counters["markdown_scanned"] += 1
            try:
                sources.append(markdown_source(path, patterns_dir))
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"{path}: {exc}")
    if include_dsl:
        for dsl_dir in dsl_dirs:
            for path in discover_dsl(dsl_dir):
                counters["dsl_scanned"] += 1
                try:
                    source = dsl_source(path, load_yaml(path))
                except Exception as exc:  # noqa: BLE001
                    counters["dsl_skipped"] += 1
                    warnings.append(f"{path}: {exc}")
                    continue
                if source is None:
                    counters["dsl_skipped"] += 1
                    continue
                sources.append(source)
    return sources, counters, warnings


def convert_patterns(
    patterns_dirs: Sequence[Path],
    out_dir: Path,
    *,
    dsl_dirs: Sequence[Path] = (),
    include_dsl: bool = False,
    dry_run: bool = False,
    limit: int | None = None,
) -> dict[str, Any]:
    sources, counters, warnings = collect_sources(patterns_dirs, dsl_dirs, include_dsl=include_dsl)
    records = [build_record(source) for source in sources]
    if limit is not None:
        records = records[:limit]

    files: list[str] = []
    errors: list[str] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    schema = _VALIDATOR.load_schema()
    for record in records:
        out_path = out_dir / output_filename(record)
        files.append(str(out_path))
        rendered = yaml_dump(record)
        try:
            rendered_doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{out_path}: rendered YAML did not parse: {exc}")
            continue
        errs = _VALIDATOR.validate_doc(rendered_doc, schema)
        if errs:
            errors.extend(f"{out_path}: {err}" for err in errs)
            continue
        if not dry_run:
            out_path.write_text(rendered, encoding="utf-8")
    return {
        "schema_version": SCHEMA_VERSION,
        "patterns_dirs": [str(path) for path in patterns_dirs],
        "dsl_dirs": [str(path) for path in dsl_dirs],
        "include_dsl": include_dsl,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        **counters,
        "records_emitted": len(records),
        "warnings": warnings,
        "errors": errors,
        "file_count": len(files),
        "files": files[:50],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patterns-dir", action="append", default=[], help="Fork-pattern markdown directory; repeatable.")
    parser.add_argument("--dsl-dir", action="append", default=[], help="Canonical patterns.dsl directory; repeatable.")
    parser.add_argument("--include-dsl", action="store_true", help="Also convert top-level Solidity DSL YAML rows.")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    patterns_dirs = [Path(item).expanduser().resolve() for item in args.patterns_dir] or [DEFAULT_PATTERNS_DIR.resolve()]
    dsl_dirs = [Path(item).expanduser().resolve() for item in args.dsl_dir] or [DEFAULT_DSL_DIR.resolve()]
    summary = convert_patterns(
        patterns_dirs,
        Path(args.out_dir).expanduser().resolve(),
        dsl_dirs=dsl_dirs,
        include_dsl=args.include_dsl,
        dry_run=args.dry_run,
        limit=args.limit,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman Solidity-fork-pattern ETL: "
            f"markdown={summary['markdown_scanned']} dsl={summary['dsl_scanned']} "
            f"records={summary['records_emitted']} errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
