#!/usr/bin/env python3
"""Convert legacy verdict-tag YAML files into hackerman_record v1 records."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_OUT_DIR = REPO_ROOT / "audit" / "corpus_tags" / "hackerman_records"

LEGACY_VERDICT_SCHEMAS = {"auditooor.verdict_tag.v1", "auditooor.verdict_tag.v2"}
HACKERMAN_SCHEMA = "auditooor.hackerman_record.v1"
SUMMARY_SCHEMA = "auditooor.hackerman_etl_from_verdict_tags.summary.v1"

REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
YEAR_RE = re.compile(r"\b(20[0-9]{2})\b")
PROOF_ARTIFACT_PATH_RE = re.compile(
    r"^(?![A-Za-z][A-Za-z0-9+.-]*://)(?!/)(?!\.\.?/)(?![A-Za-z]:[\\/])"
    r"(?!\\\\)(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+$"
)

LANGUAGE_MAP = {
    "solidity": "solidity",
    "go": "go",
    "rust": "rust",
    "vyper": "vyper",
    "move": "move",
    "cairo": "cairo",
    "huff": "huff",
    "assembly": "assembly",
    "python": "python-onchain",
    "python-onchain": "python-onchain",
    "ts": "typescript-onchain",
    "js": "typescript-onchain",
    "typescript": "typescript-onchain",
    "typescript-onchain": "typescript-onchain",
}

EXTENSION_LANGUAGE = {
    ".sol": "solidity",
    ".go": "go",
    ".rs": "rust",
    ".vy": "vyper",
    ".move": "move",
    ".cairo": "cairo",
    ".huff": "huff",
    ".py": "python-onchain",
    ".ts": "typescript-onchain",
    ".js": "typescript-onchain",
}

DOMAIN_KEYWORDS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("bridge", ("bridge", "cross-chain", "crosschain", "exit-finalization", "portal")),
    ("zk-proof", ("zk", "zero-knowledge", "proof", "verifier", "circuit", "halo2", "circom")),
    ("oracle", ("oracle", "price-feed", "stale-price", "exchange-rate", "rate")),
    ("governance", ("governance", "governor", "proposal", "quorum", "vote", "voting")),
    ("dao", ("dao", "ragequit", "fork-dao")),
    ("staking", ("staking", "staker", "validator-withdrawal", "delegate")),
    ("consensus", ("consensus", "validator", "blocksync", "fork-lag")),
    ("rpc-infra", ("rpc", "jsonrpc", "jsonrpsee", "admin-route")),
    ("rollup", ("rollup", "sequencer", "l2", "optimism")),
    ("nft", ("nft", "erc721", "royalty")),
    ("gaming", ("game", "card", "loot")),
    ("vault", ("vault", "erc4626", "share", "deposit", "redeem", "withdraw")),
    ("dex", ("dex", "amm", "swap", "clob", "liquidity", "pool", "market")),
    ("lending", ("lending", "borrow", "collateral", "liquidation", "debt", "loan")),
)


def _load_verdict_schema_tool() -> Any:
    path = REPO_ROOT / "tools" / "verdict-tag-schema.py"
    spec = importlib.util.spec_from_file_location("_hackerman_etl_verdict_tag_schema", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VTS = _load_verdict_schema_tool()


def load_yaml(path: Path) -> Any:
    return _VTS._load_yaml(path)  # type: ignore[attr-defined]


def _stable_hash(value: Any, length: int = 12) -> str:
    payload = json.dumps(value, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:length]


def _slug(value: Any, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._/-]+", "-", text)
    text = text.replace("/", "-")
    text = re.sub(r"-+", "-", text).strip(".-")
    return (text or "unknown")[:max_len].strip(".-") or "unknown"


def _string(value: Any) -> str:
    return str(value).strip() if value not in (None, "") else ""


def _unique_strings(values: Iterable[Any]) -> List[str]:
    out: List[str] = []
    seen: set[str] = set()
    for value in values:
        text = _string(value)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _sites(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    raw = doc.get("sites")
    if not isinstance(raw, list):
        return []
    return [site for site in raw if isinstance(site, dict)]


def _surface(doc: Dict[str, Any], source_path: Path) -> str:
    parts: List[str] = [source_path.name]
    for key in (
        "verdict_id",
        "target_repo",
        "language",
        "bug_class",
        "realized_attack_class",
        "severity_final",
        "severity_claimed",
        "notes",
        "poc_path",
        "filing_id",
    ):
        value = doc.get(key)
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
        elif value not in (None, ""):
            parts.append(str(value))
    for key in ("attack_classes_to_try", "predicted_attack_classes", "cross_lang_canonical_bug_classes"):
        value = doc.get(key)
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
    for site in _sites(doc):
        parts.extend(str(site.get(key) or "") for key in ("file_path", "function_name", "function_signature"))
    return " ".join(parts).lower()


def is_legacy_verdict_tag(doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    schema = doc.get("schema_version")
    if schema == HACKERMAN_SCHEMA:
        return False
    if schema in LEGACY_VERDICT_SCHEMAS:
        return True
    return "verdict_id" in doc and "target_repo" in doc


def derive_source_audit_ref(doc: Dict[str, Any], source_path: Path) -> str:
    ref = _string(doc.get("source_audit_ref")) or _string(doc.get("verdict_id")) or _string(doc.get("filing_id"))
    if len(ref) < 5:
        ref = f"tag:{source_path.name}"
    if len(ref) <= 240:
        return ref
    return f"{ref[:224].rstrip()}:{_stable_hash(ref, 10)}"


def derive_target_repo(doc: Dict[str, Any]) -> str:
    repo = _string(doc.get("target_repo"))
    lower = repo.lower()
    artifact_prefixes = ("results/", "reports/", "tools/")
    artifact_suffixes = (".log", ".sh", ".md", ".json", ".txt", ".py", ".yaml", ".yml")
    if lower.startswith(artifact_prefixes) or lower.endswith(artifact_suffixes):
        return "unknown"
    return repo if REPO_RE.match(repo) else "unknown"


def derive_target_language(doc: Dict[str, Any]) -> Optional[str]:
    raw = _string(doc.get("target_language") or doc.get("language")).lower()
    if raw in LANGUAGE_MAP:
        return LANGUAGE_MAP[raw]
    for site in _sites(doc):
        file_path = _string(site.get("file_path")).lower()
        suffix = Path(file_path).suffix
        if suffix in EXTENSION_LANGUAGE:
            return EXTENSION_LANGUAGE[suffix]
    return None


def derive_bug_class(doc: Dict[str, Any], source_path: Path) -> str:
    canonical = doc.get("cross_lang_canonical_bug_classes")
    if isinstance(canonical, list) and canonical:
        return _string(canonical[0]) or "uncategorized"
    return _string(doc.get("bug_class")) or _slug(doc.get("verdict_id") or source_path.stem, max_len=120)


def derive_attack_class(doc: Dict[str, Any], bug_class: str) -> str:
    for key in ("realized_attack_class", "attack_class"):
        value = _string(doc.get(key))
        if value:
            return value
    for key in ("predicted_attack_classes", "attack_classes_to_try"):
        values = doc.get(key)
        if isinstance(values, list):
            first = _unique_strings(values)
            if first:
                return first[0]
    return bug_class or "uncategorized"


def derive_severity(doc: Dict[str, Any]) -> str:
    raw = _string(doc.get("severity_final") or doc.get("severity_claimed") or doc.get("severity")).upper()
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFORMATIONAL": "info",
        "INFO": "info",
        "N/A": "info",
    }
    if raw in mapping:
        return mapping[raw]
    verdict_class = _string(doc.get("verdict_class")).upper()
    if verdict_class in {"CONFIRMED", "FILED", "AMENDED"}:
        return "high"
    if verdict_class in {"NEAR-MISS", "CANDIDATE", "HOLD"}:
        return "medium"
    return "info"


def derive_year(doc: Dict[str, Any], source_path: Path) -> int:
    candidates = [
        doc.get("extracted_at_utc"),
        doc.get("verdict_id"),
        doc.get("filing_id"),
        doc.get("notes"),
        source_path.name,
    ]
    for value in candidates:
        match = YEAR_RE.search(_string(value))
        if match:
            return int(match.group(1))
    return 2000


def derive_target_domain(doc: Dict[str, Any], source_path: Path) -> str:
    text = _surface(doc, source_path)
    for domain, needles in DOMAIN_KEYWORDS:
        if any(needle in text for needle in needles):
            return domain
    return "lending"


def derive_target_component(doc: Dict[str, Any], source_path: Path) -> str:
    for site in _sites(doc):
        for key in ("function_name", "function_signature", "file_path"):
            value = _string(site.get(key))
            if value:
                return value[:240]
    return _slug(doc.get("verdict_id") or source_path.stem, max_len=160)


def derive_function_shape(doc: Dict[str, Any], bug_class: str, attack_class: str) -> Dict[str, Any]:
    sites = _sites(doc)
    raw_signature = ""
    shape_tags: List[str] = []
    for site in sites:
        raw_signature = raw_signature or _string(site.get("function_signature"))
        shape_tags.extend([site.get("shape_hash_fine"), site.get("shape_hash")])
    if not raw_signature:
        for site in sites:
            raw_signature = _string(site.get("function_name")) or _string(site.get("file_path"))
            if raw_signature:
                break
    if not raw_signature:
        raw_signature = bug_class or attack_class or "unknown-function-shape"
    tags = _unique_strings(shape_tags)
    if not tags:
        tags = [_slug(attack_class or bug_class, max_len=120)]
    return {
        "raw_signature": raw_signature[:500],
        "shape_tags": [tag[:160] for tag in tags],
    }


def derive_attacker_role(surface: str) -> str:
    if "governance" in surface or "proposal" in surface or "vote" in surface:
        return "governance"
    if "validator" in surface:
        return "validator"
    if "sequencer" in surface:
        return "sequencer"
    if "block-proposer" in surface or "proposer" in surface:
        return "block-proposer"
    if "admin" in surface or "owner" in surface or "privileged" in surface:
        return "privileged-compromised"
    return "unprivileged"


def derive_impact_class(surface: str) -> str:
    if any(term in surface for term in ("governance", "proposal", "quorum", "vote")):
        return "governance-takeover"
    if any(term in surface for term in ("admin", "owner", "privilege", "access-control")):
        return "privilege-escalation"
    if any(term in surface for term in ("theft", "steal", "drain", "liquidation", "reward", "fee", "share", "mint")):
        return "theft"
    if any(term in surface for term in ("freeze", "locked", "stuck", "cancel-lock")):
        return "freeze"
    if any(term in surface for term in ("dos", "denial", "grief")):
        return "dos"
    if any(term in surface for term in ("rounding", "precision", "truncat", "decimal")):
        return "precision-loss"
    return "griefing"


def derive_impact_actor(surface: str) -> str:
    if "validator" in surface:
        return "validator-set"
    if "sequencer" in surface:
        return "sequencer"
    if any(term in surface for term in ("treasury", "fee", "protocol")):
        return "protocol-treasury"
    if any(term in surface for term in ("depositor", "deposit", "vault", "share", "liquidation", "borrow")):
        return "depositor-class"
    return "arbitrary-user"


def derive_impact_dollar_class(severity: str) -> str:
    return {
        "critical": ">=$1M",
        "high": "$100K-$1M",
        "medium": "$10K-$100K",
        "low": "non-financial",
        "info": "non-financial",
    }[severity]


def derive_related_records(doc: Dict[str, Any]) -> List[str]:
    related: List[Any] = []
    related.extend(doc.get("parity_precedents") if isinstance(doc.get("parity_precedents"), list) else [])
    upstream_refs = doc.get("upstream_refs")
    if isinstance(upstream_refs, list):
        for ref in upstream_refs:
            if not isinstance(ref, dict):
                continue
            repo = _string(ref.get("repo"))
            sha = _string(ref.get("sha"))
            relation = _string(ref.get("relation"))
            label = repo
            if sha:
                label = f"{label}@{sha}"
            if relation:
                label = f"{label}:{relation}"
            related.append(label)
    return _unique_strings(related)


def derive_proof_artifact_path(doc: Dict[str, Any]) -> str:
    raw = _string(doc.get("proof_artifact_path")) or _string(doc.get("poc_path"))
    if not raw:
        return ""
    candidate = raw.replace("\\", "/").strip()
    if not PROOF_ARTIFACT_PATH_RE.match(candidate):
        return ""
    return candidate


def build_record(doc: Dict[str, Any], source_path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    target_language = derive_target_language(doc)
    if not target_language:
        return None, f"unsupported language: {doc.get('language')!r}"

    source_ref = derive_source_audit_ref(doc, source_path)
    bug_class = derive_bug_class(doc, source_path)
    attack_class = derive_attack_class(doc, bug_class)
    severity = derive_severity(doc)
    component = derive_target_component(doc, source_path)
    surface = _surface(doc, source_path)
    hash_payload = {
        "tag_file": source_path.name,
        "source_audit_ref": source_ref,
        "target_repo": doc.get("target_repo"),
        "bug_class": bug_class,
        "attack_class": attack_class,
    }
    record_hash = _stable_hash(hash_payload)
    record_slug = _slug(source_path.stem, max_len=70)

    record: Dict[str, Any] = {
        "schema_version": HACKERMAN_SCHEMA,
        "record_id": f"legacy:{record_slug}:{record_hash}",
        "source_audit_ref": source_ref,
        "target_domain": derive_target_domain(doc, source_path),
        "target_language": target_language,
        "target_repo": derive_target_repo(doc),
        "target_component": component,
        "function_shape": derive_function_shape(doc, bug_class, attack_class),
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": derive_attacker_role(surface),
        "attacker_action_sequence": (
            f"Exploit {attack_class} against {component} using the legacy verdict pattern "
            f"recorded in {source_ref}."
        ),
        "required_preconditions": [
            f"{component} is reachable in the audited target.",
            f"The {bug_class} condition is present at the vulnerable state transition.",
        ],
        "impact_class": derive_impact_class(surface),
        "impact_actor": derive_impact_actor(surface),
        "impact_dollar_class": derive_impact_dollar_class(severity),
        "fix_pattern": f"Add or restore the guard/invariant that prevents {attack_class} at {component}.",
        "fix_anti_pattern_avoided": (
            "Avoid relying on off-path assumptions without checking the affected state transition."
        ),
        "severity_at_finding": severity,
        "year": derive_year(doc, source_path),
        "cross_language_analogues": [],
        "related_records": derive_related_records(doc),
    }
    proof_artifact_path = derive_proof_artifact_path(doc)
    if proof_artifact_path:
        record["proof_artifact_path"] = proof_artifact_path
    return record, None


def output_filename(source_path: Path, record: Dict[str, Any]) -> str:
    suffix = str(record["record_id"]).rsplit(":", 1)[-1]
    return f"{_slug(source_path.stem, max_len=90)}-{suffix}.yaml"


def dump_record_yaml(record: Dict[str, Any], source_path: Path, source_ref: str) -> str:
    comments = (
        f"# source_tag_file: {source_path.name.replace(chr(10), ' ')}\n"
        f"# source_verdict_id: {source_ref.replace(chr(10), ' ')}\n"
    )
    try:
        import yaml  # type: ignore

        body = yaml.safe_dump(record, sort_keys=False, default_flow_style=False, width=120)
    except ImportError:
        body = _dump_yaml_minimal(record)
    return comments + body


def _dump_yaml_minimal(value: Any, indent: int = 0) -> str:
    lines: List[str] = []
    pad = " " * indent
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}{key}:")
                lines.append(_dump_yaml_minimal(item, indent + 2).rstrip())
            else:
                lines.append(f"{pad}{key}: {_yaml_scalar(item)}")
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                lines.append(f"{pad}-")
                lines.append(_dump_yaml_minimal(item, indent + 2).rstrip())
            else:
                lines.append(f"{pad}- {_yaml_scalar(item)}")
    return "\n".join(lines) + "\n"


def _yaml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    text = str(value)
    if not text:
        return '""'
    if re.fullmatch(r"[A-Za-z0-9._:/@ -]+", text) and not text.startswith(("$", ">", "@", "-")):
        return text
    return json.dumps(text)


def discover_yaml_files(tag_dir: Path) -> List[Path]:
    return sorted(list(tag_dir.glob("*.yaml")) + list(tag_dir.glob("*.yml")), key=lambda p: p.name)


def run_etl(tag_dir: Path, out_dir: Path, *, dry_run: bool = False, limit: Optional[int] = None) -> Dict[str, Any]:
    if not tag_dir.is_dir():
        raise FileNotFoundError(f"tag dir not found: {tag_dir}")
    summary: Dict[str, Any] = {
        "schema_version": SUMMARY_SCHEMA,
        "tag_dir": str(tag_dir),
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "limit": limit,
        "scanned": 0,
        "emitted": 0,
        "skipped": 0,
        "errors": [],
        "outputs": [],
    }
    converted = 0
    for path in discover_yaml_files(tag_dir):
        if limit is not None and converted >= limit:
            break
        summary["scanned"] += 1
        try:
            doc = load_yaml(path)
        except Exception as exc:
            summary["errors"].append({"tag_file": path.name, "error": f"YAML parse error: {exc}"})
            continue
        if not is_legacy_verdict_tag(doc):
            summary["skipped"] += 1
            continue
        record, skip_reason = build_record(doc, path)
        if record is None:
            summary["skipped"] += 1
            summary["outputs"].append({"tag_file": path.name, "status": "skipped", "reason": skip_reason})
            continue
        converted += 1
        out_file = output_filename(path, record)
        out_path = out_dir / out_file
        source_ref = str(record["source_audit_ref"])
        if not dry_run:
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path.write_text(dump_record_yaml(record, path, source_ref), encoding="utf-8")
        summary["emitted"] += 1
        summary["outputs"].append(
            {
                "tag_file": path.name,
                "out_file": out_file,
                "record_id": record["record_id"],
                "source_audit_ref": source_ref,
                "status": "planned" if dry_run else "written",
            }
        )
    return summary


def print_text_summary(summary: Dict[str, Any]) -> None:
    print(
        "hackerman-etl-from-verdict-tags: "
        f"scanned={summary['scanned']} emitted={summary['emitted']} "
        f"skipped={summary['skipped']} errors={len(summary['errors'])} "
        f"dry_run={summary['dry_run']}"
    )
    for row in summary["outputs"]:
        if row.get("status") == "skipped":
            print(f"SKIP {row['tag_file']}: {row.get('reason')}")
        else:
            print(f"{row['status'].upper()} {row['tag_file']} -> {row['out_file']}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR), help=f"Legacy verdict tag directory. Default: {DEFAULT_TAG_DIR}")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR), help=f"Output directory. Default: {DEFAULT_OUT_DIR}")
    parser.add_argument("--dry-run", action="store_true", help="Plan conversions without writing YAML records.")
    parser.add_argument("--limit", type=int, help="Maximum number of legacy verdict tags to convert.")
    parser.add_argument("--json-summary", action="store_true", help="Print machine-readable JSON summary.")
    args = parser.parse_args(argv)

    try:
        summary = run_etl(Path(args.tag_dir), Path(args.out_dir), dry_run=args.dry_run, limit=args.limit)
    except (OSError, ValueError) as exc:
        print(f"hackerman-etl-from-verdict-tags: {exc}", file=sys.stderr)
        return 2
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True, indent=2))
    else:
        print_text_summary(summary)
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
