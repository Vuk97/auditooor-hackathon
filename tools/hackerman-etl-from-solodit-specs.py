#!/usr/bin/env python3
"""Convert generated Solodit detector specs into hackerman_record v1 YAML."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
DEFAULT_SPEC_DIRS = (
    REPO_ROOT / "detectors" / "_specs" / "drafts_solodit",
    REPO_ROOT / "detectors" / "_specs" / "drafts_solodit_move",
    REPO_ROOT / "detectors" / "_specs" / "drafts_code4rena_rust",
    REPO_ROOT / "detectors" / "_specs" / "drafts_cyfrin_rust",
    REPO_ROOT / "detectors" / "_specs" / "drafts_sherlock_rust",
    REPO_ROOT / "detectors" / "_specs" / "drafts_trailofbits_rust",
    REPO_ROOT / "detectors" / "_specs" / "drafts_rust_soroban",
    REPO_ROOT / "detectors" / "_specs" / "drafts_ottersec_solana",
    # B7: ingest unmined detector-spec drafts (EXEC-WAVE-2-MULTI).
    # Each dir below was operator-curated and sitting on disk but not
    # previously registered in DEFAULT_SPEC_DIRS.
    REPO_ROOT / "detectors" / "_specs" / "drafts_halborn-k2-2025-09",
    REPO_ROOT / "detectors" / "_specs" / "drafts_halborn_soroban_general",
    REPO_ROOT / "detectors" / "_specs" / "drafts_v12-critical",
    REPO_ROOT / "detectors" / "_specs" / "drafts_v12-high",
    REPO_ROOT / "detectors" / "_specs" / "drafts_v12-med-low",
)
PRIMARY_SOLODIT_SPEC_DIR_NAMES = {"drafts_solodit", "drafts_solodit_move"}
SLUG_YEAR_RE = re.compile(r"(?<!\d)(20(?:1[8-9]|2[0-9]|30))(?!\d)")
SYNTHETIC_FUNCTION_HINT_TAG = "inferred-function-name"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_solodit_specs",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


def load_yaml(path: Path) -> dict[str, Any]:
    try:
        data = _VALIDATOR.load_yaml(path)
    except Exception:
        # Some generated Solodit specs escaped literal "$" / "%" inside
        # double-quoted strings. YAML does not define those as escape
        # sequences, but the intended scalar is unambiguous.
        text = path.read_text(encoding="utf-8")
        repaired = text.replace(r"\$", "$").replace(r"\%", "%")
        data = yaml.safe_load(repaired)
    return data if isinstance(data, dict) else {}


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def repo_slug_part(value: object, *, max_len: int = 64) -> str:
    text = str(value or "").strip().lower()
    text = re.split(r"[:\s]", text, maxsplit=1)[0]
    text = re.sub(r"[^a-z0-9._-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "unknown")


def contains_any(text: str, needles: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(needle in low for needle in needles)


def extract_year_from_slug(*parts: object) -> int | None:
    for part in parts:
        text = str(part or "")
        for match in SLUG_YEAR_RE.finditer(text):
            year = int(match.group(1))
            if 2018 <= year <= 2030:
                return year
    return None


def infer_domain(text: str) -> str:
    rules = (
        ("bridge", ("bridge", "cross-chain", "axelar", "wormhole", "layerzero")),
        ("oracle", ("oracle", "price", "twap", "chainlink", "pyth")),
        ("lending", ("borrow", "debt", "liquidation", "collateral", "loan")),
        ("dex", ("swap", "amm", "pool", "uniswap", "balancer", "curve", "liquidity")),
        ("vault", ("vault", "deposit", "withdraw", "shares", "erc4626")),
        ("governance", ("governance", "vote", "proposal", "timelock", "role", "admin")),
        ("staking", ("stake", "unstake", "validator", "delegat")),
        ("nft", ("nft", "erc721", "erc-721")),
    )
    for domain, needles in rules:
        if contains_any(text, needles):
            return domain
    return "vault"


def infer_bug_attack(text: str, explicit_bug: str = "") -> tuple[str, str]:
    explicit = slugify(explicit_bug, max_len=64)
    if explicit and explicit not in {"tbd", "none", "record"}:
        return explicit, explicit
    rules = (
        ("access-control", "admin-bypass", ("access control", "unauthorized", "admin", "role", "permission")),
        ("reentrancy", "reentrancy", ("reentrancy", "reentrant", "callback")),
        ("signature-replay", "signature-replay", ("signature", "permit", "eip712", "replay")),
        ("oracle-manipulation", "stale-or-manipulated-oracle", ("oracle", "price", "twap")),
        ("precision-loss", "rounding-precision-loss", ("rounding", "precision", "overflow", "underflow")),
        ("missing-approval", "approval-or-allowance-gap", ("approve", "allowance", "approval")),
        ("fee-on-transfer-accounting", "fee-on-transfer-accounting-drift", ("fee on transfer", "fee-on-transfer")),
        ("denial-of-service", "dos-griefing", ("dos", "denial of service", "grief", "blocked")),
        ("accounting", "state-accounting-drift", ("accounting", "balance", "reward", "shares", "debt")),
        ("input-validation", "missing-input-validation", ("validation", "unchecked", "not checked", "missing check")),
    )
    for bug_class, attack_class, needles in rules:
        if contains_any(text, needles):
            return bug_class, attack_class
    return "logic-error", "protocol-invariant-bypass"


def infer_impact(text: str) -> str:
    if contains_any(text, ("drain", "steal", "theft", "loss of funds", "lose funds")):
        return "theft"
    if contains_any(text, ("freeze", "stuck", "locked")):
        return "freeze"
    if contains_any(text, ("dos", "denial of service", "grief")):
        return "dos"
    if contains_any(text, ("reward", "yield", "fee")):
        return "yield-redistribution"
    return "griefing"


def dollar_class(severity: str, impact: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return ">=$1M"
    if sev == "high":
        return "$100K-$1M"
    if sev == "medium":
        return "$10K-$100K"
    if sev == "low":
        return "<$10K"
    if impact in {"theft", "freeze"}:
        return "$10K-$100K"
    return "non-financial"


def target_repo_from_source(source: str) -> str:
    match = re.search(r"\(([^/)]+)/([^/)]+)\)", source or "")
    if match:
        return f"{repo_slug_part(match.group(1))}/{repo_slug_part(match.group(2))}"
    return "unknown/solodit"


def explicit_function_signature(data: dict[str, Any]) -> str:
    return str(data.get("vuln_fn_sig") or data.get("vuln_fn_signature") or "").strip()


def function_hint_name(data: dict[str, Any], title: str) -> str:
    name = str(data.get("vuln_fn_name") or "").strip()
    if not name:
        name = slugify(data.get("name") or title, max_len=48).replace("-", "_")
    return name or "unknown_function"


def is_weak_generated_function_hint(data: dict[str, Any], language: str) -> bool:
    """Return true for Solodit detector-name hints that are not real signatures."""
    if language != "solidity" or explicit_function_signature(data):
        return False
    confidence = str(data.get("vuln_fn_source") or data.get("vuln_fn_confidence") or "").strip().lower()
    if confidence in {"explicit", "source", "source-code", "verified", "manual", "human", "high"}:
        return False
    skeleton = slugify(data.get("skeleton") or "", max_len=64)
    if skeleton != "name_match_missing_call":
        return False
    params = str(data.get("vuln_fn_params") or "").strip()
    mutability = str(data.get("vuln_fn_mutability_clean") or data.get("vuln_fn_mutability") or "").strip()
    ret = str(data.get("vuln_fn_return") or "").strip()
    return params == "" and mutability in {"", "internal"} and ret in {"", "bool"}


def raw_signature(data: dict[str, Any], language: str, title: str) -> str:
    explicit_sig = explicit_function_signature(data)
    if explicit_sig:
        return explicit_sig
    if language == "move":
        name = slugify(data.get("id") or title, max_len=48).replace("-", "_")
        return f"public entry fun {name}()"
    name = function_hint_name(data, title)
    if is_weak_generated_function_hint(data, language):
        return f"function-name-hint: {name}"
    params = str(data.get("vuln_fn_params") or "").strip()
    mutability = str(data.get("vuln_fn_mutability_clean") or data.get("vuln_fn_mutability") or "").strip()
    ret = str(data.get("vuln_fn_return") or "").strip()
    suffix = f" {mutability}" if mutability else ""
    if ret:
        suffix += f" returns ({ret})"
    return f"function {name}({params}){suffix}"


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
        and not text.startswith(("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ","))
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


def source_path_ref(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.name


def build_record(path: Path, spec_dir: Path, data: dict[str, Any]) -> dict[str, Any]:
    title = str(data.get("wiki_title") or data.get("title") or data.get("help") or data.get("name") or path.stem)
    description = str(data.get("wiki_description") or data.get("real_world_example") or "")
    exploit = str(data.get("wiki_exploit_scenario") or data.get("exploit_precondition") or description)
    recommendation = str(data.get("wiki_recommendation") or data.get("suggested_remediation") or "")
    tags = str(data.get("solodit_tags") or "")
    language = str(data.get("language") or "solidity").lower()
    severity = str(data.get("severity") or "info").lower()
    source_id = str(data.get("solodit_id") or data.get("source_id") or path.stem)
    source = str(data.get("source") or "solodit")
    text = "\n".join([title, description, exploit, recommendation, tags, source])
    domain = infer_domain(text)
    bug_class, attack_class = infer_bug_attack(text, str(data.get("bug_class") or ""))
    impact = infer_impact(text)
    component = str(data.get("contract_name") or title).strip()[:240]
    weak_function_hint = is_weak_generated_function_hint(data, language)
    has_precise_function_shape = bool(explicit_function_signature(data)) or (
        bool(str(data.get("vuln_fn_name") or "").strip()) and not weak_function_hint
    )
    signature = raw_signature(data, language, title)
    source_path = source_path_ref(path)
    namespace = "" if spec_dir.name in PRIMARY_SOLODIT_SPEC_DIR_NAMES else slugify(spec_dir.name, max_len=48)
    identity_basis = source_id or source_path
    identity_seed = f"solodit-spec\n{namespace}\n{identity_basis}" if namespace else f"solodit-spec\n{identity_basis}"
    digest = hashlib.sha256(identity_seed.encode("utf-8")).hexdigest()[:12]
    source_ref = f"solodit-spec:{source_path}:{source_id}"
    record_slug = slugify(identity_basis or path.stem, max_len=96)
    if namespace:
        record_slug = f"{namespace}:{record_slug}"
    record_id = f"solodit-spec:{record_slug}:{digest}"
    shape_tags = [slugify(attack_class), slugify(f"{language}-{bug_class}")]
    for extra in (data.get("skeleton"), tags.split(",")[0] if tags else ""):
        item = slugify(extra, max_len=48)
        if has_precise_function_shape and item == "name_match_missing_call":
            continue
        if item and item not in shape_tags:
            shape_tags.append(item)
    if weak_function_hint and SYNTHETIC_FUNCTION_HINT_TAG not in shape_tags:
        shape_tags.append(SYNTHETIC_FUNCTION_HINT_TAG)
    year = extract_year_from_slug(
        data.get("audit_year"),
        data.get("year"),
        data.get("source_date"),
        data.get("reported_date"),
        data.get("report_date"),
        data.get("published_at"),
        data.get("publishedAt"),
        data.get("published_date"),
        data.get("created_at"),
        data.get("createdAt"),
        data.get("updated_at"),
        data.get("updatedAt"),
        data.get("date"),
        data.get("solodit_slug"),
        source,
        title,
        description,
        exploit,
        recommendation,
        path.stem,
        source_id,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": source_ref,
        "target_domain": domain,
        "target_language": language,
        "target_repo": target_repo_from_source(source),
        "target_component": component,
        "function_shape": {
            "raw_signature": signature,
            "shape_tags": shape_tags,
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": re.sub(r"\s+", " ", exploit).strip()[:800]
        or f"Exercise the {component} path described by {title}.",
        "required_preconditions": [
            re.sub(r"\s+", " ", str(data.get("exploit_precondition") or "")).strip()[:220]
            or f"{domain} component matches Solodit detector spec {path.stem}",
        ],
        "impact_class": impact,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": dollar_class(severity, impact),
        "fix_pattern": re.sub(r"\s+", " ", recommendation).strip()[:800]
        or "Apply the source report remediation and add invariant regression coverage.",
        "fix_anti_pattern_avoided": "shipping detector-shaped symptoms without proving the underlying invariant",
        "severity_at_finding": severity,
        "year": year or 2000,
        "cross_language_analogues": [],
        "related_records": [],
    }


def output_filename(record: dict[str, Any]) -> str:
    digest = str(record["record_id"]).rsplit(":", 1)[-1]
    return f"{slugify(record['record_id'], max_len=110)}-{digest}.yaml"


def convert_specs(spec_dirs: list[Path], out_dir: Path, *, dry_run: bool = False, limit: int | None = None) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    scanned = 0
    errors: list[str] = []
    for spec_dir in spec_dirs:
        if not spec_dir.is_dir():
            continue
        for path in sorted(spec_dir.glob("*.yaml")):
            scanned += 1
            try:
                data = load_yaml(path)
                records.append(build_record(path, spec_dir, data))
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{path}: {exc}")
                continue
            if limit is not None and len(records) >= limit:
                break
        if limit is not None and len(records) >= limit:
            break

    files: list[str] = []
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
        "spec_dirs": [str(path) for path in spec_dirs],
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "scanned": scanned,
        "records_emitted": len(records),
        "errors": errors,
        "file_count": len(files),
        "files": files[:50],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec-dir", action="append", default=[], help="Solodit spec directory; repeatable")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    spec_dirs = [Path(item).expanduser().resolve() for item in args.spec_dir] or [path.resolve() for path in DEFAULT_SPEC_DIRS]
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert_specs(spec_dirs, Path(args.out_dir).expanduser().resolve(), dry_run=args.dry_run, limit=args.limit)
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman Solodit-spec ETL: "
            f"scanned={summary['scanned']} records={summary['records_emitted']} errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
