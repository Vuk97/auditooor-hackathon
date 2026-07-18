#!/usr/bin/env python3
"""Convert validated reference/findings_go*.jsonl rows into Hackerman records."""
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
DEFAULT_FINDINGS = tuple(sorted((REPO_ROOT / "reference").glob("findings_go*.jsonl")))
REQUIRED_FIELDS = (
    "finding_id",
    "protocol",
    "language",
    "impact_tier",
    "bug_class",
    "github_ref",
    "summary",
    "provenance",
)
YEAR_RE = re.compile(r"(?<!\d)(20(?:1[8-9]|2[0-9]|30))(?!\d)")


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_findings_go",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def yaml_scalar(value: object) -> str:
    if isinstance(value, int):
        return str(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#@+-]+", text)
        and not text.endswith(":")
        and not text.startswith(("#", "-", "?", ":", "<", ">", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ","))
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


def validate_row(row: dict[str, Any], path: Path, lineno: int) -> list[str]:
    errors: list[str] = []
    for field in REQUIRED_FIELDS:
        value = row.get(field)
        if value is None or value == "" or value == []:
            errors.append(f"{path}:{lineno}: missing or empty required field {field!r}")
    if row.get("language") != "go":
        errors.append(f"{path}:{lineno}: language must be 'go', got {row.get('language')!r}")
    if row.get("provenance") is not None and not isinstance(row.get("provenance"), dict):
        errors.append(f"{path}:{lineno}: provenance must be an object")
    return errors


def repo_from_github_ref(github_ref: str) -> str:
    match = re.search(r"github\.com[:/]([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)", github_ref)
    if not match:
        return "unknown"
    return f"{match.group(1)}/{match.group(2)}"


def contains_any(text: str, needles: tuple[str, ...]) -> bool:
    low = text.lower()
    return any(needle in low for needle in needles)


def infer_domain(row: dict[str, Any]) -> str:
    provenance = row.get("provenance") if isinstance(row.get("provenance"), dict) else {}
    blob = " ".join(
        str(item or "")
        for item in (
            row.get("protocol"),
            row.get("bug_class"),
            row.get("github_ref"),
            row.get("summary"),
            provenance.get("category"),
            provenance.get("affected_location"),
            provenance.get("corpus"),
        )
    )
    rules = (
        ("zk-proof", ("zk", "gnark", "groth", "plonk", "fiat-shamir", "range check", "soundness")),
        ("bridge", ("bridge", "ibc", "cross-chain", "assetsunlocked", "unlock", "burnerc20", "wormhole")),
        ("consensus", ("consensus", "comet", "tendermint", "validator", "vote extension", "block proposer")),
        ("staking", ("staking", "delegat", "liquid stake", "validator bond", "lsm")),
        ("oracle", ("oracle", "price", "twap", "slinky")),
        ("lending", ("lend", "borrow", "debt", "collateral", "liquidation")),
        ("dex", ("swap", "amm", "pool", "liquidity")),
        ("governance", ("governance", "proposal", "vote")),
        ("rpc-infra", ("tls", "x509", "certificate", "scep", "acme", "rpc", "authz", "authorization")),
    )
    for domain, needles in rules:
        if contains_any(blob, needles):
            return domain
    return "l1-client"


def infer_attack_class(row: dict[str, Any]) -> str:
    bug_class = str(row.get("bug_class") or "")
    summary = str(row.get("summary") or "")
    blob = f"{bug_class} {summary}"
    rules = (
        ("zk-soundness-bypass", ("soundness", "range check", "wrong upper bound", "constraint", "unconstrained", "wrong field")),
        ("callback-reentrancy", ("reentrancy", "callback before state", "callback")),
        (
            "missing-input-validation",
            (
                "input_validation",
                "input validation",
                "unvalidated",
                "precondition",
                "invalid_",
                "invalid ",
                "not_rejected",
                "not rejected",
                "accepted",
                "field_mismatch",
                "zero_or_negative",
                "trailing_input",
                "bounds",
                "length",
                "validation gap",
            ),
        ),
        (
            "state-accounting-drift",
            (
                "state_drift",
                "state drift",
                "accounting",
                "aliased_to_caller",
                "stale_fee_rate",
                "not_returned_to_change",
                "partial processing",
                "queue leak",
                "not_drained",
                "silent_drop",
            ),
        ),
        (
            "protocol-invariant-bypass",
            (
                "invariant",
                "consensus",
                "threshold",
                "quorum",
                "vote_extension",
                "vote extension",
                "fork",
                "emulator",
                "missing in",
                "wrong field",
                "wrong-size",
                "mismatch",
                "single node",
                "non_atomic",
                "non-atomic",
            ),
        ),
        (
            "authorization-bypass",
            (
                "authorization",
                "authz",
                "access",
                "unsupported message",
                "token accept",
                "policy_check_skipped",
                "policy check skipped",
                "csrf",
                "session_segregation",
                "session segregation",
                "no_mix",
            ),
        ),
        ("bridge-accounting-bypass", ("bridgeout", "unlock", "burn", "staledb", "stale outer-statedb")),
        (
            "txid-proof-bypass",
            (
                "txid",
                "utxo",
                "spend check",
                "chain_watcher",
                "chain watcher",
                "multi_spend",
                "multi spend",
                "double_spend",
                "double spend",
            ),
        ),
        ("missing-state-guard", ("guard only on one path", "missing leaf-status", "missing validation")),
        ("stale-state-overwrite", ("stale", "dirtyStorage", "overwrite", "cache")),
        (
            "lifecycle-race",
            (
                "race",
                "cancel",
                "after completion",
                "close completed",
                "concurrent",
                "goroutine",
                "parallel",
                "no_lock",
                "no synchronization",
            ),
        ),
        ("commitment-binding-break", ("fiat-shamir", "binding", "collision", "hash", "commitment")),
        ("panic-dos", ("panic", "crash", "nil pointer")),
        (
            "precision-loss",
            ("rounding", "precision", "divide", "multiply", "overflow", "underflow", "counter_wrap", "counter wrap", "integer"),
        ),
        ("signature-replay", ("signature", "sighash", "replay", "malleability", "nonce", "der", "bip143", "bip341", "bip66")),
        (
            "dos-griefing",
            (
                "dos",
                "denial of service",
                "grief",
                "resource_exhaustion",
                "resource exhaustion",
                "unbounded",
                "halt",
                "stack overflow",
                "blocks signing",
                "blocks_signing",
                "block signing",
                "can't sign",
                "cant-sign",
                "funds_locked",
                "funds locked",
            ),
        ),
        ("precision-loss", ("reversed_comparison", "reversed comparison", "off-by-one", "off by one")),
    )
    for attack_class, needles in rules:
        if contains_any(blob, needles):
            return attack_class
    return slugify(bug_class.removeprefix("go."), max_len=96)


def infer_impact(row: dict[str, Any], domain: str, attack_class: str) -> tuple[str, str]:
    summary = str(row.get("summary") or "")
    bug_class = str(row.get("bug_class") or "")
    blob = f"{summary} {bug_class} {attack_class}"
    if contains_any(blob, ("drain", "theft", "steal", "loss of", "released to attacker", "direct loss")):
        return "theft", "arbitrary-user"
    if contains_any(blob, ("freeze", "locked", "stuck")):
        return "freeze", "specific-user"
    if contains_any(blob, ("panic", "crash", "denial of service", " dos", "grief")):
        return "dos", "validator-set" if domain == "consensus" else "arbitrary-user"
    if contains_any(blob, ("authorization", "authz", "privilege", "access")):
        return "privilege-escalation", "arbitrary-user"
    if contains_any(blob, ("rounding", "precision")):
        return "precision-loss", "arbitrary-user"
    if domain == "consensus":
        return "dos", "validator-set"
    return "griefing", "arbitrary-user"


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


def normalize_severity(value: object) -> str:
    severity = str(value or "info").strip().lower()
    return "info" if severity == "informational" else severity


def extract_year(row: dict[str, Any], source_path: Path) -> int:
    provenance = row.get("provenance") if isinstance(row.get("provenance"), dict) else {}
    parts: list[object] = [
        row.get("finding_id"),
        row.get("github_ref"),
        row.get("summary"),
        source_path.name,
    ]
    parts.extend(provenance.values())
    if isinstance(row.get("fix_commit"), dict):
        parts.extend(row["fix_commit"].values())
    for part in parts:
        if isinstance(part, (dict, list)):
            part = json.dumps(part, sort_keys=True, default=str)
        for match in YEAR_RE.finditer(str(part or "")):
            year = int(match.group(1))
            if 2018 <= year <= 2030:
                return year
    return 2000


def target_component(row: dict[str, Any]) -> str:
    provenance = row.get("provenance") if isinstance(row.get("provenance"), dict) else {}
    location = str(provenance.get("affected_location") or "").strip()
    if location:
        return location[:240]
    source_refs = row.get("source_refs")
    if isinstance(source_refs, list) and source_refs and isinstance(source_refs[0], dict):
        file_ref = str(source_refs[0].get("file") or "").strip()
        if file_ref:
            return file_ref[:240]
    return str(row.get("protocol") or row.get("github_ref") or "go-component")[:240]


def raw_signature(row: dict[str, Any], component: str) -> str:
    name = slugify(row.get("bug_class") or row.get("finding_id") or component, max_len=64)
    name = name.replace(".", "_").replace("-", "_").replace("/", "_").replace(":", "_")
    return f"func {name}()"


def fix_pattern(row: dict[str, Any]) -> str:
    fix_commit = row.get("fix_commit") if isinstance(row.get("fix_commit"), dict) else {}
    if fix_commit.get("summary"):
        return str(fix_commit["summary"])[:1000]
    detector_seeds = row.get("detector_seeds")
    if isinstance(detector_seeds, list) and detector_seeds:
        first = detector_seeds[0]
        if isinstance(first, dict) and first.get("desc"):
            return f"Patch the source invariant and add detector coverage: {first['desc']}"[:1000]
    return "Apply the upstream remediation and add a regression test covering the vulnerable Go execution path."


def required_preconditions(row: dict[str, Any], domain: str) -> list[str]:
    provenance = row.get("provenance") if isinstance(row.get("provenance"), dict) else {}
    conditions = [
        f"{row.get('protocol')} exposes the affected {domain} Go path",
    ]
    for key in ("category", "affected_location", "severity_label"):
        value = str(provenance.get(key) or "").strip()
        if value:
            conditions.append(value[:1000])
            break
    return list(dict.fromkeys(conditions))


def build_record(row: dict[str, Any], source_path: Path) -> dict[str, Any]:
    source_ref_path = source_path_ref(source_path)
    finding_id = str(row["finding_id"])
    digest = hashlib.sha256(f"findings-go\n{source_ref_path}\n{finding_id}".encode("utf-8")).hexdigest()[:12]
    record_slug = slugify(finding_id, max_len=96)
    source_ref = f"findings-go:{source_ref_path}:{finding_id}"
    record_id = f"findings-go:{record_slug}:{digest}"
    domain = infer_domain(row)
    attack_class = infer_attack_class(row)
    impact, impact_actor = infer_impact(row, domain, attack_class)
    severity = normalize_severity(row.get("impact_tier"))
    component = target_component(row)
    bug_class = str(row.get("bug_class") or "go.logic_error").strip()
    shape_tags = list(
        dict.fromkeys(
            [
                slugify(attack_class, max_len=96),
                slugify(bug_class, max_len=120),
                slugify(domain, max_len=64),
            ]
        )
    )
    summary = re.sub(r"\s+", " ", str(row.get("summary") or "")).strip()
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": source_ref,
        "target_domain": domain,
        "target_language": "go",
        "target_repo": repo_from_github_ref(str(row.get("github_ref") or "")),
        "target_component": component,
        "function_shape": {
            "raw_signature": raw_signature(row, component),
            "shape_tags": shape_tags,
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": summary[:5000] or f"Exercise the vulnerable Go path for {finding_id}.",
        "required_preconditions": required_preconditions(row, domain),
        "impact_class": impact,
        "impact_actor": impact_actor,
        "impact_dollar_class": dollar_class(severity, impact),
        "fix_pattern": fix_pattern(row),
        "fix_anti_pattern_avoided": "treating Go corpus findings as free-text notes without runnable pattern recall",
        "severity_at_finding": severity,
        "year": extract_year(row, source_path),
        "cross_language_analogues": [],
        "related_records": [],
    }


def output_filename(record: dict[str, Any]) -> str:
    digest = str(record["record_id"]).rsplit(":", 1)[-1]
    return f"{slugify(record['record_id'], max_len=110)}-{digest}.yaml"


def duplicate_key(row: dict[str, Any]) -> str:
    provenance = row.get("provenance") if isinstance(row.get("provenance"), dict) else {}
    ghsa = str(provenance.get("ghsa_id") or "").strip()
    if ghsa:
        return f"ghsa:{ghsa}"
    return ""


def iter_rows(paths: list[Path]) -> tuple[list[tuple[Path, int, dict[str, Any]]], list[str], list[str], int]:
    rows: list[tuple[Path, int, dict[str, Any]]] = []
    errors: list[str] = []
    seen_ids: dict[str, str] = {}
    seen_duplicate_keys: dict[str, str] = {}
    skipped_duplicates: list[str] = []
    rows_scanned = 0
    for path in paths:
        if not path.exists():
            errors.append(f"file not found: {path}")
            continue
        with path.open("r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                stripped = raw.strip()
                if not stripped:
                    continue
                rows_scanned += 1
                try:
                    row = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    errors.append(f"{path}:{lineno}: invalid JSON: {exc}")
                    continue
                if not isinstance(row, dict):
                    errors.append(f"{path}:{lineno}: row must be a JSON object")
                    continue
                errors.extend(validate_row(row, path, lineno))
                fid = str(row.get("finding_id") or "")
                if fid:
                    previous = seen_ids.get(fid)
                    if previous:
                        errors.append(f"{path}:{lineno}: duplicate finding_id {fid!r} also seen at {previous}")
                    else:
                        seen_ids[fid] = f"{path}:{lineno}"
                key = duplicate_key(row)
                if key:
                    previous = seen_duplicate_keys.get(key)
                    if previous:
                        skipped_duplicates.append(f"{path}:{lineno}:{key}:canonical={previous}")
                        continue
                    seen_duplicate_keys[key] = f"{path}:{lineno}"
                rows.append((path, lineno, row))
    return rows, errors, skipped_duplicates, rows_scanned


def convert_findings(paths: list[Path], out_dir: Path, *, dry_run: bool = False, limit: int | None = None) -> dict[str, Any]:
    rows, errors, skipped_duplicates, rows_scanned = iter_rows(paths)
    records: list[dict[str, Any]] = []
    for source_path, _, row in rows:
        if limit is not None and len(records) >= limit:
            break
        try:
            records.append(build_record(row, source_path))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{source_path}:{row.get('finding_id', '?')}: {exc}")

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
        "source_files": [str(path) for path in paths],
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "rows_scanned": rows_scanned,
        "rows_after_dedupe": len(rows),
        "duplicates_skipped": len(skipped_duplicates),
        "duplicate_keys_skipped": skipped_duplicates[:50],
        "records_emitted": len(records),
        "errors": errors,
        "file_count": len(files),
        "files": files[:50],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", action="append", default=[], help="findings_go*.jsonl path; repeatable")
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = [Path(item).expanduser().resolve() for item in args.path] or [path.resolve() for path in DEFAULT_FINDINGS]
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert_findings(paths, Path(args.out_dir).expanduser().resolve(), dry_run=args.dry_run, limit=args.limit)
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman findings-go ETL: "
            f"rows={summary['rows_scanned']} records={summary['records_emitted']} errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
