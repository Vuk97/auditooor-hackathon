#!/usr/bin/env python3
"""
hackerman-etl-from-major-defi-fix-history.py — Mine fix-commit history of
major DeFi protocols (Aave / Compound / Morpho / Euler / Seaport /
LooksRare / Lido / RocketPool / Pendle / Frax / GMX / Vertex) for the
auditooor Hackerman corpus.

Wave-1 lane: wave-1-hackerman-capability-lift (PR #726). Sibling miner to
`tools/hackerman-etl-from-dex-fix-history.py` (9 DEX repos / 224 records).

HARD RULES (M14-trap discipline):
- Real-source-only. Every record is anchored to a verifiable commit SHA via
  `gh api /repos/<org>/<repo>/commits/<sha>`. Commit metadata embedded in
  each record comes from the live API response; nothing is invented.
- No invented CVE / GHSA IDs. The commit URL itself is the source.
- Per-repo cap = 30 to keep yields balanced across orgs.

Repos mined (16; redirects resolved against live gh api):
  aave/aave-v3-core, aave/aave-v3-periphery,
  compound-finance/compound-protocol, compound-finance/comet,
  morpho-org/morpho-blue, morpho-org/morpho-aavev3-optimizer,
  euler-xyz/euler-vault-kit, euler-xyz/ethereum-vault-connector,
  ProjectOpenSea/seaport, LooksRare/contracts-exchange-v2,
  lidofinance/core, rocket-pool/rocketpool,
  pendle-finance/pendle-core-v2-public, FraxFinance/fraxlend,
  gmx-io/gmx-synthetics, vertex-protocol/vertex-contracts.

Filter: commit message must match one of the (extended) fix-shape keywords;
negative filter drops obvious non-protocol churn.

Output:
  audit/corpus_tags/tags/major_defi_fix_history/<repo>__<sha8>/record.{yaml,json}

CLI:
  python3 tools/hackerman-etl-from-major-defi-fix-history.py \\
      --out-dir audit/corpus_tags/tags/major_defi_fix_history --json-summary
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1.2"  # lane227: incident-mining shape (DeFi fix history post-mortems with incident_date) -> v1.2 permissive wide-shape


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_major_defi_fix_history",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Target repos. 16 redirect-resolved owner/repo strings.
# ---------------------------------------------------------------------------

REPOS: List[str] = [
    "aave/aave-v3-core",
    "aave/aave-v3-periphery",
    "compound-finance/compound-protocol",
    "compound-finance/comet",
    "morpho-org/morpho-blue",
    "morpho-org/morpho-aavev3-optimizer",
    "euler-xyz/euler-vault-kit",
    "euler-xyz/ethereum-vault-connector",
    "ProjectOpenSea/seaport",
    "LooksRare/contracts-exchange-v2",
    "lidofinance/core",
    "rocket-pool/rocketpool",
    "pendle-finance/pendle-core-v2-public",
    "FraxFinance/fraxlend",
    "gmx-io/gmx-synthetics",
    "vertex-protocol/vertex-contracts",
]


# Per-repo domain tag. Drives `target_domain` in the emitted record.
# Values restricted to the hackerman-record-validate schema enum:
# {lending, dex, bridge, oracle, governance, staking, vault, rollup,
#  zk-proof, consensus, rpc-infra, dao, escrow, nft, gaming, l1-client}.
# Mapping notes: NFT marketplaces -> 'nft', liquid-staking -> 'staking',
# yield-tokenization (Pendle) -> 'vault', perps DEXes -> 'dex'.
REPO_DOMAIN: Dict[str, str] = {
    "aave/aave-v3-core": "lending",
    "aave/aave-v3-periphery": "lending",
    "compound-finance/compound-protocol": "lending",
    "compound-finance/comet": "lending",
    "morpho-org/morpho-blue": "lending",
    "morpho-org/morpho-aavev3-optimizer": "lending",
    "euler-xyz/euler-vault-kit": "lending",
    "euler-xyz/ethereum-vault-connector": "lending",
    "ProjectOpenSea/seaport": "nft",
    "LooksRare/contracts-exchange-v2": "nft",
    "lidofinance/core": "staking",
    "rocket-pool/rocketpool": "staking",
    "pendle-finance/pendle-core-v2-public": "vault",
    "FraxFinance/fraxlend": "lending",
    "gmx-io/gmx-synthetics": "dex",
    "vertex-protocol/vertex-contracts": "dex",
}


# Extended fix-shape keyword set per task spec.
FIX_KEYWORDS = [
    "fix",
    "security",
    "vulnerability",
    "audit",
    "revert",
    "guard",
    "validate",
    "check",
    "patch",
    "CVE",
    "GHSA",
    "underflow",
    "overflow",
    "reentrancy",
    "manipulation",
    "slippage",
    "rounding",
]

FIX_REGEX = re.compile(
    r"\b(" + "|".join(re.escape(k) for k in FIX_KEYWORDS) + r")\b",
    re.IGNORECASE,
)

# Negative filter: obvious non-protocol churn.
NON_PROTOCOL_REGEX = re.compile(
    r"(typo|formatting|natspec|coverage\b|^docs|README|^CI\b|\bci\)|"
    r"deployment|deploy|registry|spell|wiring|env\b|^script|whitespace|"
    r"comment only|comments\)|^chore\b|^lint\b|^style\b|gas-?golf|gas opt|"
    r"prettier|eslint|^bump\b|version bump|update version|dependabot)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# gh API helpers
# ---------------------------------------------------------------------------


def gh_api(path: str, *, paginate: bool = False) -> Any:
    """Return parsed JSON from `gh api <path>`. Returns None on failure."""
    cmd = ["gh", "api"]
    if paginate:
        cmd.append("--paginate")
    cmd.append(path)
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=180)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
        sys.stderr.write(f"[warn] gh api {path}: {exc}\n")
        return None
    text = out.decode("utf-8", errors="replace")
    if paginate:
        text = text.replace("][", ",")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"[warn] gh api {path}: JSON decode failed: {exc}\n")
        return None


def list_commits(repo: str, per_page: int = 100, pages: int = 3) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for page in range(1, pages + 1):
        data = gh_api(f"/repos/{repo}/commits?per_page={per_page}&page={page}")
        if not isinstance(data, list) or not data:
            break
        out.extend(data)
        if len(data) < per_page:
            break
    return out


def get_commit_detail(repo: str, sha: str) -> Optional[Dict[str, Any]]:
    data = gh_api(f"/repos/{repo}/commits/{sha}")
    if not isinstance(data, dict):
        return None
    return data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def dedupe(items: Iterable[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for x in items:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def infer_domain_for_repo(repo: str) -> str:
    return REPO_DOMAIN.get(repo, "defi")


def infer_severity(subject: str, body: str, repo: str) -> str:
    low = (subject + " " + body).lower()
    if any(k in low for k in ("critical", "exploit", "drain", "loss of funds", "hardfork")):
        return "high"
    if "security" in low or re.search(r"\bcve\b|\bghsa\b", low):
        return "high"
    if "vulnerab" in low or "reentran" in low or "audit" in low:
        return "high"
    if any(k in low for k in ("revert", "rollback")):
        return "medium"
    if any(k in low for k in ("guard", "validate", "check", "manipulation", "slippage")):
        return "medium"
    if any(k in low for k in ("rounding", "underflow", "overflow")):
        return "medium"
    return "low"


def infer_impact(subject: str, body: str) -> str:
    low = (subject + " " + body).lower()
    if any(k in low for k in ("drain", "steal", "theft", "loss of funds", "siphon", "withdraw all")):
        return "theft"
    if any(k in low for k in ("freeze", "stuck", "locked", "brick", "permanent lock")):
        return "freeze"
    if any(k in low for k in ("dos", "denial of service", "panic", "halt")):
        return "dos"
    if any(k in low for k in ("rounding", "precision", "overflow", "underflow", "rebase")):
        return "precision-loss"
    if any(k in low for k in ("yield", "reward", "fee", "rebate", "slippage")):
        return "yield-redistribution"
    if any(k in low for k in ("priv", "admin", "authority", "unauthorized", "owner")):
        return "privilege-escalation"
    return "griefing"


def dollar_class(severity: str, impact: str) -> str:
    s = severity.lower()
    if s == "critical":
        return ">=$1M"
    if s == "high":
        return "$100K-$1M"
    if s == "medium":
        return "$10K-$100K"
    if s == "low":
        return "<$10K"
    if impact in {"theft", "freeze"}:
        return "$10K-$100K"
    return "non-financial"


# ---------------------------------------------------------------------------
# YAML rendering
# ---------------------------------------------------------------------------


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    text = str(value if value is not None else "")
    if text == "":
        return '""'
    numeric = re.fullmatch(r"[-+]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?", text)
    ambiguous = text.lower() in {"true", "false", "null", "yes", "no", "on", "off", "~"}
    plain_safe = (
        re.fullmatch(r"[A-Za-z0-9._:/<>=,$#-]+", text)
        and not text.endswith(":")
        and not text.startswith(
            ("#", "-", "?", ":", "<", ">", "@", "`", "&", "*", "!", "|", "%", "{", "}", "[", "]", ",")
        )
    )
    if plain_safe and not numeric and not ambiguous:
        return text
    return json.dumps(text, ensure_ascii=False)


def yaml_dump(data: Dict[str, Any]) -> str:
    lines: List[str] = []
    for key, value in data.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            for sk, sv in value.items():
                if isinstance(sv, list):
                    if not sv:
                        lines.append(f"  {sk}: []")
                    else:
                        lines.append(f"  {sk}:")
                        for item in sv:
                            lines.append(f"    - {yaml_scalar(item)}")
                else:
                    lines.append(f"  {sk}: {yaml_scalar(sv)}")
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key}: []")
            else:
                lines.append(f"{key}:")
                for item in value:
                    if isinstance(item, dict):
                        first = True
                        for sk, sv in item.items():
                            prefix = "  -" if first else "   "
                            lines.append(f"{prefix} {sk}: {yaml_scalar(sv)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Detector-seed extraction from diff hunks (shared with sibling miner shape).
# ---------------------------------------------------------------------------


REQUIRE_RE = re.compile(r"^\+\s*require\s*\(([^;]{0,200});?", re.IGNORECASE)
ASSERT_RE = re.compile(r"^\+\s*assert\s*\(([^;]{0,200});?", re.IGNORECASE)
REVERT_RE = re.compile(r"^\+.*\brevert\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MODIFIER_RE = re.compile(r"^\+.*\b(nonReentrant|onlyOwner|onlyAdmin|whenNotPaused|whenPaused|onlyGovernance|onlyByOwnerGovernanceOrManager|notDelegateCall)\b")
SAFEMATH_RE = re.compile(r"^\+.*\b(SafeMath|FixedPoint|FullMath|mulDiv|safeMul|safeAdd|safeSub|safeCast|checked_(?:mul|add|sub|div))\b")
UNCHECKED_RE = re.compile(r"^-.*\bunchecked\b\s*\{")
OVERFLOW_RE = re.compile(r"^\+.*\b(overflow|underflow)\b", re.IGNORECASE)
ZERO_CHECK_RE = re.compile(r"^\+\s*require\s*\([^,]*!=\s*(address\(0\)|0)", re.IGNORECASE)


def extract_detector_seed(patch_text: str, subject: str) -> str:
    seeds: List[str] = []

    for line in patch_text.splitlines():
        if not line:
            continue
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue

        m = REQUIRE_RE.match(line)
        if m:
            cond = m.group(1).strip()
            cond = re.sub(r"\s+", " ", cond)[:80]
            seeds.append(f"added require({cond})")
            continue

        m = ASSERT_RE.match(line)
        if m:
            cond = m.group(1).strip()
            cond = re.sub(r"\s+", " ", cond)[:80]
            seeds.append(f"added assert({cond})")
            continue

        m = REVERT_RE.match(line)
        if m:
            seeds.append(f"added revert {m.group(1)}()")
            continue

        m = MODIFIER_RE.match(line)
        if m:
            seeds.append(f"added {m.group(1)} modifier")
            continue

        m = SAFEMATH_RE.match(line)
        if m:
            seeds.append(f"added {m.group(1)} arithmetic guard")
            continue

        if UNCHECKED_RE.match(line):
            seeds.append("removed unchecked block")
            continue

        m = OVERFLOW_RE.match(line)
        if m:
            seeds.append(f"comment / fix references {m.group(1).lower()}")
            continue

        m = ZERO_CHECK_RE.match(line)
        if m:
            seeds.append("added zero-address / zero-value guard")
            continue

    if not seeds:
        sub_low = subject.lower()
        if "revert" in sub_low:
            seeds.append("revert / rollback prior change")
        elif "audit" in sub_low:
            seeds.append("audit-driven fix")
        elif "patch" in sub_low:
            seeds.append("upstream patch")
        else:
            seeds.append("diff-shape-fix")

    return "; ".join(dedupe(seeds)[:8])


# ---------------------------------------------------------------------------
# Record builder
# ---------------------------------------------------------------------------


def commit_to_record(
    repo: str,
    detail: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    sha = detail.get("sha")
    if not isinstance(sha, str) or len(sha) < 8:
        return None
    parents = [p.get("sha", "") for p in detail.get("parents", []) or []]
    parent_sha = parents[0] if parents else ""
    commit = detail.get("commit", {}) or {}
    message = str(commit.get("message", "") or "").strip()
    if not message:
        return None
    subject = message.splitlines()[0][:200]
    files = detail.get("files", []) or []
    if not files:
        return None

    patch_chunks: List[str] = []
    file_paths: List[str] = []
    total_add = 0
    total_del = 0
    for f in files:
        fn = f.get("filename", "")
        if fn:
            file_paths.append(fn)
        total_add += int(f.get("additions", 0) or 0)
        total_del += int(f.get("deletions", 0) or 0)
        patch = f.get("patch", "")
        if isinstance(patch, str):
            patch_chunks.append(patch)
        if sum(len(p) for p in patch_chunks) > 20000:
            break
    patch_text = "\n".join(patch_chunks)[:20000]
    detector_seed = extract_detector_seed(patch_text, subject)

    # Restrict to fix-shape commits that touch protocol source. Major DeFi
    # is predominantly Solidity; we also accept .vy (e.g. Curve-adjacent
    # files inside Frax) and protocol .ts (Seaport ships TS contract
    # helpers, GMX-synthetics has TS test/utility paths). Drop if NONE.
    protocol_extensions = (".sol", ".vy", ".cairo")
    has_protocol_src = any(fp.endswith(protocol_extensions) for fp in file_paths)
    has_typescript_src = any(
        fp.endswith(".ts") and ("contracts" in fp or "pkg/" in fp) for fp in file_paths
    )
    if not (has_protocol_src or has_typescript_src):
        return None

    if any(fp.endswith(".vy") for fp in file_paths):
        target_language = "vyper"
    elif any(fp.endswith(".sol") for fp in file_paths):
        target_language = "solidity"
    else:
        target_language = "solidity"

    severity = infer_severity(subject, message, repo)
    impact = infer_impact(subject, message)

    sub_low = (subject + " " + message).lower()
    bug_class = "fix-commit-shape-unclassified"
    attack_class = "diff-derived-pattern"
    for needle, bc, ac in [
        ("reentran", "reentrancy", "external-call-reentrancy"),
        ("overflow", "arithmetic-overflow", "unchecked-multiplication-overflow"),
        ("underflow", "arithmetic-underflow", "unchecked-subtraction-underflow"),
        ("rounding", "rounding-direction", "shares-rounding-favors-attacker"),
        ("oracle", "oracle-stale-or-manipulated", "twap-tick-manipulation"),
        ("manipulation", "price-manipulation", "oracle-or-pool-state-manipulation"),
        ("slippage", "slippage-bypass", "missing-min-out-on-swap"),
        ("flash", "flashloan-callback", "flashloan-callback-mismatch"),
        ("init", "uninitialized-storage", "double-initialization"),
        ("auth", "access-control", "missing-modifier-on-state-write"),
        ("approve", "erc20-approval-race", "approve-race-front-run"),
        ("permit", "erc20-permit-replay", "permit-signature-replay"),
        ("delegate", "delegatecall-misuse", "delegatecall-to-untrusted-target"),
        ("hook", "callback-hook-malicious-impl", "hook-reentrancy"),
        ("revert", "behavior-rollback-of-prior-change", "diff-derived-rollback"),
    ]:
        if needle in sub_low:
            bug_class = bc
            attack_class = ac
            break

    raw_signature = f"// commit {sha[:12]} in {repo} touched {len(file_paths)} files"
    fn_re_sol = re.compile(r"^\+\s*(function\s+[A-Za-z_][A-Za-z0-9_]*\([^)]{0,200}\)[^\n{]{0,80})")
    fn_re_vy = re.compile(r"^\+\s*(def\s+[A-Za-z_][A-Za-z0-9_]*\([^)]{0,200}\)[^\n:]{0,80})")
    for line in patch_text.splitlines():
        m = fn_re_sol.match(line) or fn_re_vy.match(line)
        if m:
            raw_signature = m.group(1).strip()[:500]
            break

    short_sha = sha[:8]
    record_id_input = f"major-defi-fix-history|{repo}|{sha}".encode("utf-8")
    digest = hashlib.sha256(record_id_input).hexdigest()[:12]
    repo_slug = slugify(repo.replace("/", "-"), max_len=60)
    record_id = f"git-mining:{repo_slug}:{sha}:{digest}"[:160]
    commit_url = f"https://github.com/{repo}/commit/{sha}"

    domain_label = infer_domain_for_repo(repo)
    action = (
        f"Upstream protocol fix commit at {commit_url} on {repo} ({domain_label}). "
        f"Parent commit: {parent_sha or 'n/a'}. Commit subject: {subject!r}. "
        f"Files changed: {len(file_paths)} ({total_add} additions / {total_del} deletions). "
        f"Detector seed: {detector_seed}. "
        f"Attacker pre-fix path: trigger the unchecked / pre-fix behavior in "
        f"{file_paths[0] if file_paths else 'unknown'} before the linked fix was merged. "
        "Reviewers downstream should verify the fix-shape against the protocol-source diff at the commit URL."
    )

    fix_pattern = (
        f"Diff at {commit_url} applies: {detector_seed}. "
        f"Reviewers porting this guard should mirror the added check / modifier across structurally adjacent call sites "
        f"in the same {domain_label} contract / module."
    )
    fix_anti_pattern = (
        f"shipping {file_paths[0] if file_paths else f'a {domain_label} contract'} without the upstream fix from {commit_url} - "
        "i.e. omitting the guard, modifier, or arithmetic check that this commit added."
    )

    sa_ref_raw = f"git-mining:{repo}@{sha}"
    if len(sa_ref_raw) > 230:
        sa_ref_raw = sa_ref_raw[:230]

    author_date = (
        commit.get("author", {}).get("date", "")
        or commit.get("committer", {}).get("date", "")
        or ""
    )
    year_match = re.match(r"(\d{4})", author_date)
    year = int(year_match.group(1)) if year_match else 2024
    if year < 2015:
        year = 2024

    shape_tags = dedupe(
        [
            slugify(attack_class),
            slugify(domain_label),
            "src-git-fix-history",
            slugify(bug_class),
            slugify(repo_slug),
            f"sha-{short_sha}",
        ]
    )

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": sa_ref_raw,
        "target_domain": domain_label,
        "target_language": target_language,
        "target_repo": repo,
        "target_component": (file_paths[0] if file_paths else f"{repo} fix-commit-shape")[:240],
        "function_shape": {
            "raw_signature": raw_signature,
            "shape_tags": shape_tags,
        },
        "bug_class": bug_class[:160],
        "attack_class": attack_class[:160],
        "attacker_role": "unprivileged",
        "attacker_action_sequence": action[:5000],
        "required_preconditions": [
            f"Pre-fix deployment of {repo} at parent SHA {parent_sha[:12] if parent_sha else 'unknown'}",
            f"Code path in {file_paths[0] if file_paths else 'affected module'} unchanged by an out-of-band patch",
            f"Subject signal: {subject[:160]}",
        ],
        "impact_class": impact,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": dollar_class(severity, impact),
        "fix_pattern": fix_pattern[:1000],
        "fix_anti_pattern_avoided": fix_anti_pattern[:1000],
        "severity_at_finding": severity,
        "year": year,
        "record_tier": "public-corpus",
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.9,
        "verification_method": "",
        "cross_language_analogues": [
            {
                "target_language": "vyper" if target_language == "solidity" else "solidity",
                "pattern_translation": (
                    f"Same fix-shape ({detector_seed}) in the sibling language: scan equivalent "
                    f"{domain_label}-pool / vault / router code for the missing guard."
                ),
            },
        ],
        "related_records": [],
    }
    return record


# ---------------------------------------------------------------------------
# Filtering pipeline
# ---------------------------------------------------------------------------


def is_fix_shape(subject: str, body: str) -> bool:
    if NON_PROTOCOL_REGEX.search(subject):
        return False
    if FIX_REGEX.search(subject):
        return True
    if FIX_REGEX.search(body[:400]):
        return True
    return False


def mine_repo(
    repo: str,
    *,
    pages: int = 3,
    per_page: int = 100,
    max_records_per_repo: int = 30,
    detail_cap: int = 80,
) -> Tuple[List[Dict[str, Any]], int, int]:
    commits = list_commits(repo, per_page=per_page, pages=pages)
    candidates: List[Dict[str, Any]] = []
    for c in commits:
        commit_msg = (c.get("commit") or {}).get("message", "") or ""
        if not commit_msg:
            continue
        subject = commit_msg.splitlines()[0]
        if is_fix_shape(subject, commit_msg):
            candidates.append(c)
        if len(candidates) >= detail_cap:
            break

    records: List[Dict[str, Any]] = []
    for c in candidates:
        sha = c.get("sha")
        if not sha:
            continue
        detail = get_commit_detail(repo, sha)
        if not detail:
            continue
        rec = commit_to_record(repo, detail)
        if rec is None:
            continue
        records.append(rec)
        if len(records) >= max_records_per_repo:
            break
    return records, len(commits), len(candidates)


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    repos: Sequence[str] = REPOS,
    pages: int = 3,
    per_page: int = 100,
    max_records_per_repo: int = 30,
    detail_cap: int = 80,
) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    per_repo_counts: Dict[str, int] = {}
    sample_urls: List[str] = []

    for repo in repos:
        if limit is not None and len(records) >= limit:
            break
        try:
            repo_records, scanned, _candidates = mine_repo(
                repo,
                pages=pages,
                per_page=per_page,
                max_records_per_repo=max_records_per_repo,
                detail_cap=detail_cap,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"mine_repo({repo}): {exc}")
            continue
        per_repo_counts[repo] = len(repo_records)
        for r in repo_records:
            if limit is not None and len(records) >= limit:
                break
            records.append(r)

    schema = _VALIDATOR.load_schema()
    file_paths: List[str] = []
    valid = 0
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    for rec in records:
        rendered = yaml_dump(rec)
        try:
            doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{rec['record_id']}: yaml render: {exc}")
            continue
        verrs = _VALIDATOR.validate_doc(doc, schema)
        if verrs:
            for e in verrs:
                errors.append(f"{rec['record_id']}: {e}")
            continue
        valid += 1
        m = re.search(r"https?://\S+", rec.get("attacker_action_sequence", ""))
        if m and len(sample_urls) < 16:
            sample_urls.append(m.group(0).rstrip(".,;|"))
        repo_tail = rec["target_repo"].split("/")[-1]
        parts = rec["record_id"].split(":")
        full_sha = parts[-2] if len(parts) >= 3 else "unknown"
        short_sha = full_sha[:8] if re.fullmatch(r"[0-9a-f]+", full_sha) else full_sha
        slug_dir = slugify(f"{repo_tail}__{short_sha}", max_len=120)
        rec_dir = out_dir / slug_dir
        if not dry_run:
            rec_dir.mkdir(parents=True, exist_ok=True)
            (rec_dir / "record.yaml").write_text(rendered, encoding="utf-8")
            (rec_dir / "record.json").write_text(
                json.dumps(doc, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        file_paths.append(str(rec_dir / "record.yaml"))

    return {
        "schema_version": SCHEMA_VERSION,
        "verification_tier": "tier-1-verified-realtime-api",
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "records_total": len(records),
        "records_valid": valid,
        "records_per_repo": per_repo_counts,
        "sample_urls": sample_urls,
        "errors": errors[:50],
        "error_count": len(errors),
        "file_count": len(file_paths),
        "files_sample": file_paths[:20],
        "negative_verdict": valid < 100,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default="audit/corpus_tags/tags/major_defi_fix_history",
        help="Output directory (per-record sub-dir). Default: %(default)s",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--pages", type=int, default=3, help="Commit-list pages per repo.")
    parser.add_argument("--per-page", type=int, default=100, help="Commits per API page.")
    parser.add_argument(
        "--max-records-per-repo",
        type=int,
        default=30,
        help="Hard cap on records emitted per repo (post-detail filter).",
    )
    parser.add_argument(
        "--detail-cap",
        type=int,
        default=80,
        help="Hard cap on per-repo detail-API fetches (cost control).",
    )
    parser.add_argument(
        "--repos",
        nargs="*",
        default=None,
        help="Override the default repo list (space-separated owner/repo strings).",
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    out_dir = (REPO_ROOT / args.out_dir).resolve() if not os.path.isabs(args.out_dir) else Path(args.out_dir).resolve()
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    repos = args.repos if args.repos else REPOS
    summary = convert(
        out_dir,
        dry_run=args.dry_run,
        limit=args.limit,
        repos=repos,
        pages=args.pages,
        per_page=args.per_page,
        max_records_per_repo=args.max_records_per_repo,
        detail_cap=args.detail_cap,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True, indent=2))
    else:
        print(
            "hackerman major-defi-fix-history ETL: "
            f"valid={summary['records_valid']}/{summary['records_total']} "
            f"per_repo={summary['records_per_repo']} "
            f"errors={summary['error_count']}"
        )
        if summary["negative_verdict"]:
            print("[NEGATIVE] yield < 100 verifiable records - widen --pages / --repos before relying on this corpus.")
    return 0 if summary["error_count"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
