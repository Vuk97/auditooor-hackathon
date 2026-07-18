#!/usr/bin/env python3
"""Convert git-commits-mining JSON reports into hackerman_record v1 YAML."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORTS_DIR = REPO_ROOT / "reports"
DEFAULT_OUT_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
SCHEMA_VERSION = "auditooor.hackerman_record.v1"

LANG_BY_EXT = {
    ".sol": "solidity",
    ".go": "go",
    ".rs": "rust",
    ".vy": "vyper",
    ".move": "move",
    ".cairo": "cairo",
    ".huff": "huff",
    ".s": "assembly",
    ".asm": "assembly",
    ".ts": "typescript-onchain",
    ".tsx": "typescript-onchain",
    ".py": "python-onchain",
}

LANG_ALIASES = {
    "sol": "solidity",
    "solidity": "solidity",
    "go": "go",
    "golang": "go",
    "rust": "rust",
    "rs": "rust",
    "vyper": "vyper",
    "move": "move",
    "cairo": "cairo",
    "huff": "huff",
    "assembly": "assembly",
    "typescript": "typescript-onchain",
    "typescript-onchain": "typescript-onchain",
    "python": "python-onchain",
    "python-onchain": "python-onchain",
}

DOMAIN_KEYWORDS = (
    ("bridge", ("bridge", "crosschain", "cross-chain", "gateway", "tbtc")),
    ("dex", ("swap", "amm", "pool", "balancer", "curve", "uniswap", "dex")),
    ("oracle", ("oracle", "price", "feed")),
    ("governance", ("governance", "governor", "vote", "timelock")),
    ("staking", ("staking", "stake", "validator", "delegat")),
    ("vault", ("vault", "erc4626", "share", "adapter")),
    ("rollup", ("rollup", "sequencer", "l2")),
    ("zk-proof", ("zk", "proof", "circuit", "halo2", "circom")),
    ("consensus", ("consensus", "frost", "dkg", "threshold", "signer")),
    ("rpc-infra", ("rpc", "grpc", "api")),
    ("dao", ("dao",)),
    ("escrow", ("escrow",)),
    ("nft", ("nft", "erc721", "erc1155")),
    ("gaming", ("game", "gaming")),
    ("l1-client", ("client", "geth", "reth")),
    ("lending", ("lend", "borrow", "liquidat", "trove", "collateral", "aave", "compound", "maker", "liquity")),
)


def slugify(value: Any, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[\s_]+", "-", text)
    text = re.sub(r"[^a-z0-9._/-]+", "-", text)
    text = re.sub(r"-+", "-", text).strip("-._/")
    return (text or "unknown")[:max_len].strip("-._/") or "unknown"


def dedupe(values: Iterable[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def short_hash(payload: Any, length: int = 10) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()[:length]


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level JSON must be an object")
    return data


def discover_reports(reports_dir: Path) -> list[Path]:
    # rglob (recursive) + dual pattern so a single --reports-dir <workspace> sweeps both
    # <ws>/.auditooor/git_commits_mining_*.json (MCP single-file form) AND
    # <ws>/mining_rounds/*/<slug>_<lang>_git_commits_mining.json (canonical pipeline form).
    # Before: glob() of one dir for one prefix -> workspace mines never reached the corpus.
    seen: set = set()
    out: list[Path] = []
    for pat in ("git_commits_mining_*.json", "*_git_commits_mining.json"):
        for p in reports_dir.rglob(pat):
            if p.is_file() and p not in seen:
                seen.add(p)
                out.append(p)
    return sorted(out)


def normalize_repo(value: Any, report_path: Path, row: dict[str, Any]) -> str:
    repo = str(value or "").strip()
    if re.match(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$", repo):
        return repo
    url = str(row.get("url") or "")
    match = re.search(r"github\.com/([^/\s]+)/([^/\s]+)/commit/", url)
    if match:
        return f"{match.group(1)}/{match.group(2)}"
    name = report_path.stem.removeprefix("git_commits_mining_")
    name = re.sub(r"_(?:l\d+_)?(?:FORWARD_|BACKWARD_)?\d{4}[-]?\d{2}[-]?\d{2}.*$", "", name)
    return repo if "/" in repo else "unknown"


def row_subject(row: dict[str, Any]) -> str:
    return str(row.get("subject") or row.get("message") or row.get("title") or "").strip()


def row_sha(row: dict[str, Any]) -> str:
    return str(row.get("sha") or row.get("commit") or row.get("commit_sha") or "").strip()


def row_date(row: dict[str, Any], report: dict[str, Any]) -> str:
    return str(row.get("date") or row.get("committed_at") or report.get("generated_at") or "").strip()


def row_files(row: dict[str, Any]) -> list[str]:
    keys = (
        "files_in_scope_src",
        "affected_solidity_paths",
        "files",
        "paths",
        "changed_files",
        "file_paths",
        "affected_paths",
    )
    values: list[Any] = []
    for key in keys:
        value = row.get(key)
        if isinstance(value, list):
            values.extend(value)
    return dedupe(str(v) for v in values if str(v).strip())


def pattern_id(pattern: Any) -> str:
    if isinstance(pattern, str):
        return pattern.strip()
    if not isinstance(pattern, dict):
        return ""
    for key in ("id", "pattern_id", "slug", "detector", "detector_slug", "name", "ref"):
        value = pattern.get(key)
        if value:
            return str(value).strip()
    return ""


def row_patterns(row: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    for key in ("matched_patterns", "patterns", "detector_refs", "detectors", "matched_detectors"):
        value = row.get(key)
        if isinstance(value, list):
            values.extend(value)
        elif value:
            values.append(value)
    return dedupe(pattern_id(v) for v in values)


def infer_language(report: dict[str, Any], row: dict[str, Any]) -> str:
    for value in (report.get("language"), row.get("language")):
        lang = LANG_ALIASES.get(str(value or "").strip().lower())
        if lang:
            return lang
    for pattern in row.get("patterns") or row.get("matched_patterns") or []:
        if isinstance(pattern, dict):
            lang = LANG_ALIASES.get(str(pattern.get("language") or "").strip().lower())
            if lang:
                return lang
    for file_path in row_files(row):
        lang = LANG_BY_EXT.get(Path(file_path).suffix.lower())
        if lang:
            return lang
        if Path(file_path).name in ("Cargo.toml", "Cargo.lock"):
            return "rust"
        if Path(file_path).name == "go.mod":
            return "go"
    if "solidity" in str(report.get("schema") or "").lower():
        return "solidity"
    text = " ".join([str(report.get("upstream_repo") or ""), row_subject(row), " ".join(row_files(row))]).lower()
    if "frost" in text or "cargo" in text or "dkg" in text:
        return "rust"
    return "go"


def infer_domain(repo: str, row: dict[str, Any]) -> str:
    text = " ".join([repo, row_subject(row), str(row.get("summary") or ""), " ".join(row_files(row))]).lower()
    for domain, needles in DOMAIN_KEYWORDS:
        if any(needle in text for needle in needles):
            return domain
    return "lending"


def explicit_bug_class(row: dict[str, Any]) -> str:
    # "explicit_bug_class" is the key the LLM diff-classify merge writes; honor it
    # first so a precisely-classified mined commit (e.g. access-control / reentrancy)
    # is both recordable (row_is_recordable) AND carries that class into the record,
    # instead of falling back to the subject-keyword "security-shaped-commit" stub.
    for key in ("explicit_bug_class", "bug_class", "bug_class_primary", "bug_class_secondary", "bug_class_tertiary"):
        value = row.get(key)
        if value:
            return str(value).strip()
    patterns = row_patterns(row)
    if patterns:
        return patterns[0]
    return ""


def classify_text(row: dict[str, Any]) -> str:
    # The DIFF is the highest-signal classification input - the subject alone is
    # noise ("fix ci", "Fix units in comments" -> security-shaped-commit). When a
    # diff/patch has been backfilled (tools/git-mining-diff-backfill.py), include
    # it (bounded) so the keyword maps below fire on real code (onlyOwner /
    # nonReentrant / require / initializer / ...) instead of the commit subject.
    # Use only the CHANGED (+/-) lines of the diff, not unchanged context: a
    # contract's pervasive vocabulary (DSAuth `auth` modifier, `owner`) sits in the
    # surrounding context and would false-fire the broad access-control bucket on
    # every commit. The actual fix lives in the +/- lines.
    raw = str(row.get("diff") or row.get("patch") or "")
    changed = "\n".join(
        ln for ln in raw.splitlines()
        if (ln.startswith("+") or ln.startswith("-"))
        and not ln.startswith(("+++", "---"))
    )[:12000]
    return " ".join(
        [
            row_subject(row),
            str(row.get("summary") or ""),
            str(row.get("exploitability_note") or ""),
            " ".join(row_files(row)),
            " ".join(row_patterns(row)),
            changed,
        ]
    ).lower()


def infer_bug_class(row: dict[str, Any]) -> str:
    explicit = explicit_bug_class(row)
    if explicit:
        return slugify(explicit, max_len=150)
    text = classify_text(row)
    if any(k in text for k in ("reentrancy", "re-enter")):
        return "reentrancy"
    if any(k in text for k in ("access", "onlyowner", "role", "sentinel", "permission", "privilege", "msg.sender ==", "require(msg.sender")):
        return "access-control"
    if any(k in text for k in ("oracle", "price", "feed")):
        return "oracle-manipulation"
    if any(k in text for k in ("overflow", "underflow", "precision", "rounding", "fraction")):
        return "arithmetic-precision"
    if any(k in text for k in ("storage", "initializer", "initialize", "upgrade", "proxy")):
        return "upgrade-storage"
    if any(k in text for k in ("liquidation", "trove", "collateral")):
        return "liquidation-accounting"
    if any(k in text for k in ("zeroize", "secret", "key", "dkg", "frost", "crypto", "k256", "ecies")):
        return "crypto-secret-handling"
    if any(k in text for k in ("dos", "grief", "revert", "unreachable")):
        return "denial-of-service"
    if any(k in text for k in ("guard", "invariant", "check", "validate")):
        return "missing-guard"
    return "security-shaped-commit"


def infer_attack_class(bug_class: str, row: dict[str, Any]) -> str:
    text = f"{bug_class} {classify_text(row)}"
    if "reentrancy" in text:
        return "reentrancy"
    if any(k in text for k in ("access", "auth", "role", "owner", "permission", "privilege", "sentinel")):
        return "privileged-role-abuse"
    if any(k in text for k in ("oracle", "price", "feed")):
        return "oracle-price-manipulation"
    if any(k in text for k in ("precision", "rounding", "overflow", "underflow", "fraction")):
        return "precision-rounding-exploit"
    if any(k in text for k in ("storage", "initializer", "upgrade", "proxy")):
        return "upgrade-storage-corruption"
    if any(k in text for k in ("liquidation", "trove", "collateral")):
        return "liquidation-accounting-exploit"
    if any(k in text for k in ("zeroize", "secret", "key", "dkg", "frost", "crypto", "ecies")):
        return "key-material-exposure"
    if any(k in text for k in ("dos", "grief", "revert")):
        return "denial-of-service"
    if any(k in text for k in ("guard", "invariant", "check", "validate")):
        return "missing-guard-bypass"
    return "security-fix-regression"


def infer_attacker_role(row: dict[str, Any], attack_class: str) -> str:
    text = f"{attack_class} {classify_text(row)}"
    if any(k in text for k in ("admin", "owner", "curator", "sentinel", "guardian", "role", "privileged")):
        return "privileged-compromised"
    if any(k in text for k in ("validator", "consensus")):
        return "validator"
    if any(k in text for k in ("proposer", "block")):
        return "block-proposer"
    if any(k in text for k in ("local", "memory", "secret", "zeroize")):
        return "local-host-observer"
    return "unprivileged"


def infer_impact(row: dict[str, Any], bug_class: str, attack_class: str) -> tuple[str, str, str]:
    text = f"{bug_class} {attack_class} {classify_text(row)}"
    if "dos" in text or "denial" in text:
        impact_class = "dos"
    elif "grief" in text:
        impact_class = "griefing"
    elif any(k in text for k in ("freeze", "pause")):
        impact_class = "freeze"
    elif any(k in text for k in ("access", "role", "privilege", "owner", "sentinel")):
        impact_class = "privilege-escalation"
    elif any(k in text for k in ("precision", "rounding")):
        impact_class = "precision-loss"
    else:
        impact_class = "theft"

    if any(k in text for k in ("treasury", "fee", "protocol")):
        impact_actor = "protocol-treasury"
    elif any(k in text for k in ("validator", "consensus")):
        impact_actor = "validator-set"
    elif any(k in text for k in ("deposit", "vault", "share", "liquidation", "trove", "collateral")):
        impact_actor = "depositor-class"
    else:
        impact_actor = "arbitrary-user"

    severity = infer_severity(row)
    if severity in ("critical", "high"):
        dollars = ">=$1M"
    elif severity == "medium":
        dollars = "$100K-$1M"
    elif impact_class in ("dos", "griefing", "privilege-escalation"):
        dollars = "non-financial"
    else:
        dollars = "<$10K"
    return impact_class, impact_actor, dollars


def infer_severity(row: dict[str, Any]) -> str:
    explicit = str(row.get("severity") or row.get("severity_at_finding") or "").strip().lower()
    if explicit in {"critical", "high", "medium", "low", "info"}:
        return explicit
    confidence = " ".join(
        str(p.get("confidence") or "") for p in row.get("patterns", []) if isinstance(p, dict)
    ).lower()
    if "high" in confidence:
        return "high"
    if row.get("classification") == "security_fix" or row.get("derivable_pattern") == "yes":
        return "medium"
    if row.get("derivable_pattern") == "maybe":
        return "low"
    score = row.get("solidity_score")
    if isinstance(score, (int, float)) and score >= 12:
        return "medium"
    return "low"


def infer_year(row: dict[str, Any], report: dict[str, Any]) -> int:
    date = row_date(row, report)
    match = re.search(r"(20\d{2})", date)
    if match:
        return int(match.group(1))
    return datetime.utcnow().year


def infer_component(row: dict[str, Any], repo: str) -> str:
    for key in ("function", "function_name", "signature", "raw_signature", "target_component"):
        value = row.get(key)
        if value:
            return str(value).strip()[:240]
    files = row_files(row)
    if files:
        return files[0][:240]
    return repo[:240]


def infer_function_shape(row: dict[str, Any], language: str) -> dict[str, Any]:
    raw = ""
    for key in ("signature", "raw_signature", "function_signature", "function", "function_name"):
        if row.get(key):
            raw = str(row[key]).strip()
            break
    files = row_files(row)
    if not raw and files:
        raw = f"file:{files[0]}"
    if not raw:
        raw = row_subject(row) or row_sha(row) or "commit-level-security-shape"

    tags = [f"language:{language}"]
    if files:
        tags.append(f"site:{files[0]}")
        tags.extend(f"ext:{Path(f).suffix.lower().lstrip('.')}" for f in files if Path(f).suffix)
    tags.extend(f"pattern:{p}" for p in row_patterns(row))
    for keyword in ("proxy_storage_layout_changed", "inheritance_changed", "oz_upgradeable_initialize_changed"):
        if row.get(keyword):
            tags.append(keyword)
    for key in ("classification", "derivable_pattern"):
        if row.get(key):
            tags.append(f"{key}:{row[key]}")
    return {"raw_signature": raw[:500], "shape_tags": dedupe(tags)[:12] or ["commit-level-security-shape"]}


def record_from_row(report: dict[str, Any], report_path: Path, row: dict[str, Any]) -> Optional[dict[str, Any]]:
    sha = row_sha(row)
    if not sha:
        return None
    repo = normalize_repo(report.get("upstream_repo"), report_path, row)
    language = infer_language(report, row)
    bug_class = infer_bug_class(row)
    attack_class = infer_attack_class(bug_class, row)
    source_ref = f"git-mining:{relative_ref(report_path)}@{sha[:12]}"
    record_hash = short_hash({"source_audit_ref": source_ref, "bug_class": bug_class, "attack_class": attack_class}, 10)
    impact_class, impact_actor, dollars = infer_impact(row, bug_class, attack_class)
    summary = str(row.get("summary") or row_subject(row) or "Security-shaped upstream commit.").strip()

    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": f"git-mining:{slugify(repo.replace('/', '-'), max_len=46)}:{sha[:12]}:{record_hash}",
        "source_audit_ref": source_ref,
        "target_domain": infer_domain(repo, row),
        "target_language": language,
        "target_repo": repo,
        "target_component": infer_component(row, repo),
        "function_shape": infer_function_shape(row, language),
        "bug_class": bug_class[:160],
        "attack_class": attack_class[:160],
        "attacker_role": infer_attacker_role(row, attack_class),
        "attacker_action_sequence": build_action_sequence(row, attack_class),
        "required_preconditions": build_preconditions(row),
        "impact_class": impact_class,
        "impact_actor": impact_actor,
        "impact_dollar_class": dollars,
        "fix_pattern": f"Upstream commit fixes or hardens: {summary}"[:1000],
        "fix_anti_pattern_avoided": f"Do not retain the vulnerable pattern classified as {bug_class}."[:1000],
        "severity_at_finding": infer_severity(row),
        "year": infer_year(row, report),
        "cross_language_analogues": [],
        "related_records": [],
    }


def build_action_sequence(row: dict[str, Any], attack_class: str) -> str:
    subject = row_subject(row) or "the vulnerable code path"
    files = row_files(row)
    site = f" touching {files[0]}" if files else ""
    return (
        f"Step 1: identify the {attack_class} condition in the pre-fix behavior{site}. "
        f"Step 2: trigger the affected path before the upstream fix represented by commit '{subject}'. "
        "Step 3: rely on the missing or incorrect guard/accounting behavior to realize impact."
    )[:5000]


def build_preconditions(row: dict[str, Any]) -> list[str]:
    preconditions = ["target deployment contains the pre-fix commit behavior"]
    files = row_files(row)
    if files:
        preconditions.append(f"affected site is reachable: {files[0]}")
    patterns = row_patterns(row)
    if patterns:
        preconditions.append(f"matched mining pattern: {patterns[0]}")
    return dedupe(preconditions)


def row_is_recordable(row: dict[str, Any]) -> bool:
    if row_patterns(row) or explicit_bug_class(row):
        return True
    if row.get("classification") == "security_fix":
        return True
    if str(row.get("derivable_pattern") or "").lower() in {"yes", "maybe"}:
        return True
    if row.get("solidity_score") or row.get("affected_solidity_paths"):
        return True
    return False


def iter_report_rows(report: dict[str, Any]) -> Iterable[dict[str, Any]]:
    seen: set[str] = set()
    for section in ("commits", "shaped_commits_index"):
        value = report.get(section)
        if not isinstance(value, list):
            continue
        for row in value:
            if not isinstance(row, dict) or not row_is_recordable(row):
                continue
            sha = row_sha(row)
            identity = sha or short_hash(row)
            if identity in seen:
                continue
            seen.add(identity)
            yield row


def relative_ref(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def output_filename(record: dict[str, Any]) -> str:
    repo = slugify(str(record["target_repo"]).replace("/", "-"), max_len=48)
    bug = slugify(record["bug_class"], max_len=36)
    sha_match = re.search(r"@([A-Fa-f0-9]{7,40})", record["source_audit_ref"])
    sha = sha_match.group(1)[:12] if sha_match else short_hash(record["record_id"], 12)
    suffix = short_hash(record["record_id"], 8)
    return f"git-mining-{repo}-{sha}-{bug}-{suffix}.yaml"


def yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


def yaml_lines(value: Any, indent: int = 0) -> list[str]:
    pad = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item != []:
                lines.append(f"{pad}{key}:")
                lines.extend(yaml_lines(item, indent + 2))
            else:
                lines.append(f"{pad}{key}: {yaml_scalar(item) if not isinstance(item, list) else '[]'}")
        return lines
    if isinstance(value, list):
        if not value:
            return [f"{pad}[]"]
        lines = []
        for item in value:
            if isinstance(item, dict):
                first = True
                for key, sub in item.items():
                    prefix = "-" if first else " "
                    if isinstance(sub, (dict, list)) and sub != []:
                        lines.append(f"{pad}{prefix} {key}:")
                        lines.extend(yaml_lines(sub, indent + 4))
                    else:
                        lines.append(
                            f"{pad}{prefix} {key}: {yaml_scalar(sub) if not isinstance(sub, list) else '[]'}"
                        )
                    first = False
            else:
                lines.append(f"{pad}- {yaml_scalar(item)}")
        return lines
    return [f"{pad}{yaml_scalar(value)}"]


def dump_yaml(record: dict[str, Any]) -> str:
    return "\n".join(yaml_lines(record)) + "\n"


def convert_reports(reports_dir: Path, out_dir: Path, *, dry_run: bool = False, limit: int = 0) -> dict[str, Any]:
    reports = discover_reports(reports_dir)
    written: list[str] = []
    planned: list[str] = []
    errors: list[str] = []
    records_seen = 0

    for report_path in reports:
        try:
            report = load_json(report_path)
        except Exception as exc:
            errors.append(f"{report_path}: {exc}")
            continue
        for row in iter_report_rows(report):
            if limit and records_seen >= limit:
                break
            # Skip LLM-classified NOISE (doc/ci/typo/version/pure-refactor commits the
            # diff-classify workflow flagged is_noise=true). Ingesting them as
            # hackerman_records pollutes the corpus with non-security "fix-shape"
            # stubs - exactly the low-signal records the diff-classification exists to
            # cut. Only rows with a genuine security bug_class flow through.
            if isinstance(row, dict) and (row.get("llm_is_noise") is True
                                          or row.get("explicit_bug_class") == "non-security"):
                continue
            record = record_from_row(report, report_path, row)
            if not record:
                continue
            records_seen += 1
            out_path = out_dir / output_filename(record)
            planned.append(str(out_path))
            if not dry_run:
                out_dir.mkdir(parents=True, exist_ok=True)
                out_path.write_text(dump_yaml(record), encoding="utf-8")
                written.append(str(out_path))
        if limit and records_seen >= limit:
            break

    return {
        "schema": "auditooor.hackerman_git_mining_etl.summary.v1",
        "reports_dir": str(reports_dir),
        "out_dir": str(out_dir),
        "reports_scanned": len(reports),
        "records": records_seen,
        "files_planned": planned,
        "files_written": written,
        "dry_run": dry_run,
        "errors": errors,
    }


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports-dir", action="append", default=None,
                        help="Repeatable; defaults to repo reports/. Pass a workspace root to sweep its .auditooor/ + mining_rounds/.")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int, default=0, help="Maximum records to emit; 0 means no limit.")
    parser.add_argument("--json-summary", action="store_true")
    args = parser.parse_args(argv)

    reports_dirs = [Path(d) for d in (args.reports_dir or [str(DEFAULT_REPORTS_DIR)])]
    out_dir = Path(args.out_dir)
    missing = [d for d in reports_dirs if not d.is_dir()]
    if missing:
        print(f"reports dir(s) not found: {', '.join(map(str, missing))}", file=sys.stderr)
        return 2
    if args.limit < 0:
        print("--limit must be >= 0", file=sys.stderr)
        return 2

    # Merge summaries across all reports dirs (convert_reports handles one dir).
    # Fast path: a single dir returns its summary verbatim (preserves shape for callers).
    if len(reports_dirs) == 1:
        summary = convert_reports(reports_dirs[0], out_dir, dry_run=args.dry_run, limit=args.limit)
    else:
        summary = {"records": 0, "reports_scanned": 0, "files_planned": 0, "files_written": 0,
                   "reports_dir": [str(d) for d in reports_dirs], "errors": []}
        for d in reports_dirs:
            s = convert_reports(d, out_dir, dry_run=args.dry_run, limit=args.limit)
            for k in ("records", "reports_scanned", "files_planned", "files_written"):
                v = s.get(k, 0)
                summary[k] += len(v) if isinstance(v, list) else (v or 0)
            if isinstance(s.get("errors"), list):
                summary["errors"] += s["errors"]
    if args.json_summary:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        action = "planned" if args.dry_run else "wrote"
        print(
            f"[OK] {action} {summary['records']} hackerman records "
            f"from {summary['reports_scanned']} git mining reports"
        )
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
