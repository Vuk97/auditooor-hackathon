#!/usr/bin/env python3
"""Convert published Immunefi audit-competition disclosures into hackerman_record v1 YAML.

EXEC-IMMUNEFI-PUBLIC-MINER. Real-source-driven ETL: reads disclosure markdown
files published in the public ``immunefi-team/Past-Audit-Competitions`` GitHub
repo, parses the structured header (Report ID / severity / target / impacts /
report type / submitter / submission date), and emits one
``auditooor.hackerman_record.v1`` per disclosure.

Source-truth contract (do not violate):

* Records are emitted ONLY from on-disk markdown files that were really
  downloaded from ``immunefi-team/Past-Audit-Competitions``. The ETL never
  synthesizes a disclosure record from memory.
* The ``--cache-dir`` flag controls where the markdown files live. The
  ``--fetch`` flag drives a ``gh api`` download into the cache. If neither
  --fetch nor an existing populated cache is available, the tool emits
  ``BLOCKED-NO-REAL-SOURCE`` and exits with rc=3.
* ``source_audit_ref`` is set to the canonical public URL of the disclosure
  on GitHub (raw text, no Cantina/Solodit indirection).
* ``severity_at_finding`` is verbatim from the disclosure header
  (Critical / High / Medium / Low / Insight). Insight is normalised to
  ``info`` (the schema enum lacks ``insight``).
* ``impact_dollar_class`` is mapped from severity to a public-disclosure
  default band (Critical: >=$1M, High: $100K-$1M, Medium: $10K-$100K,
  Low: <$10K, Info: non-financial). The Immunefi disclosure feed publishes
  the report title + severity + impact bullet but does NOT consistently
  publish the per-report payout amount in the report body, so we use the
  severity-derived band rather than inventing a dollar figure. Honest by
  construction; not a fabricated payout claim.
* Every record carries ``record_tier: public-corpus`` and
  ``source_extraction_method: corpus-etl`` plus a
  ``mitigation-state=post-fix-released`` marker embedded in
  ``attacker_action_sequence`` (Immunefi disclosures are post-fix by the
  bounty platform's definition; only competitions whose fix is shipped get
  archived to Past-Audit-Competitions).

CLI:

    # one-shot fetch + emit
    python3 tools/hackerman-etl-from-immunefi-public.py \\
        --fetch \\
        --cache-dir /tmp/immunefi-public-cache \\
        --out-dir /tmp/etl-immunefi-public-out \\
        --dry-run --json-summary

    # fixture run (existing cache)
    python3 tools/hackerman-etl-from-immunefi-public.py \\
        --cache-dir tools/tests/fixtures/hackerman_etl_from_immunefi_public/raw \\
        --out-dir /tmp/etl-immunefi-public-out \\
        --dry-run --json-summary

Hard rules followed:

* New file only; does NOT modify any existing file.
* Does NOT touch ``tools/calibration/llm_budget_log.jsonl``.
* Cross-links (in docstring + comments) are relative paths only.
* All emitted records validate against
  ``audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json``.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
SOURCE_REPO = "immunefi-team/Past-Audit-Competitions"
DEFAULT_BRANCH = "main"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_immunefi_public",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Helpers (mirrored from sibling ETL hackerman-etl-from-near-ink.py so the
# YAML rendering stays byte-stable across the family).
# ---------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def one_line(text: object, fallback: str, *, max_len: int = 1000) -> str:
    cleaned = re.sub(r"\s+", " ", str(text or "")).strip()
    return (cleaned[:max_len].strip() if cleaned else fallback)


def yaml_scalar(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
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


def yaml_dump(data: Dict[str, Any]) -> str:
    lines: List[str] = []
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


# ---------------------------------------------------------------------------
# Disclosure header parsing.
#
# Real format observed on the immunefi-team/Past-Audit-Competitions repo:
#
#   # <title>
#
#   Submitted on <date> by @<handle> for [<program>](<bounty-url>)
#
#   Report ID: #<id>
#
#   Report type: <Smart Contract|Blockchain/DLT|Websites/Apps|...>
#
#   Report severity: <Critical|High|Medium|Low|Insight>
#
#   Target: <github-url-or-other>
#
#   Impacts:
#   - <impact bullet 1>
#   - <impact bullet 2>
#
#   ## Description
#   ...body...
# ---------------------------------------------------------------------------


HEADER_FIELDS = (
    ("report_id", re.compile(r"^Report\s+ID:\s*#?\s*([0-9]+)\s*$", re.MULTILINE | re.IGNORECASE)),
    ("report_type", re.compile(r"^Report\s+type:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)),
    ("severity", re.compile(r"^Report\s+severity:\s*([A-Za-z][A-Za-z _/-]+?)\s*$", re.MULTILINE | re.IGNORECASE)),
    ("target", re.compile(r"^Target:\s*(.+?)\s*$", re.MULTILINE | re.IGNORECASE)),
)
SUBMITTED_RE = re.compile(
    r"^Submitted\s+on\s+(?P<date>.+?)\s+by\s+@?(?P<handle>\S+)\s+for\s+\[(?P<program>[^\]]+)\]\((?P<url>[^)]+)\)",
    re.MULTILINE | re.IGNORECASE,
)
YEAR_RE = re.compile(r"\b(20[2-9][0-9])\b")
IMPACTS_BLOCK_RE = re.compile(r"^Impacts:\s*\n((?:[ \t]*-[^\n]*\n)+)", re.MULTILINE | re.IGNORECASE)
TITLE_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
GITHUB_URL_RE = re.compile(
    r"https?://github\.com/(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+)",
    re.IGNORECASE,
)
DESCRIPTION_HEAD_RE = re.compile(r"^##\s+Description\s*$", re.MULTILINE | re.IGNORECASE)


SEVERITY_TO_DOLLAR_CLASS = {
    "critical": ">=$1M",
    "high": "$100K-$1M",
    "medium": "$10K-$100K",
    "low": "<$10K",
    "insight": "non-financial",
    "info": "non-financial",
}


SEVERITY_TO_SCHEMA = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "insight": "info",  # schema enum has no `insight`; normalise to info
    "info": "info",
}


REPORT_TYPE_TO_LANGUAGE = {
    # explicit Smart Contract → solidity (the dominant Immunefi smart-contract
    # asset language). If the target_repo basename / URL hints at a Rust /
    # Go / Move asset, ``override_language_from_target_repo`` flips it.
    "smart contract": "solidity",
    "smart contracts": "solidity",
    "blockchain/dlt": "go",  # most DLT bounties (Firedancer, dYdX cosmos, etc.) are Go/Rust
    "blockchain_dlt": "go",
    "websites and applications": "typescript-onchain",
    "websites_and_applications": "typescript-onchain",
}


REPO_LANGUAGE_HINTS = (
    # (substring, language)
    ("firedancer", "rust"),
    ("solana-program", "rust"),
    ("solana-labs", "rust"),
    ("substrate", "rust"),
    ("polkadot", "rust"),
    ("aleph", "rust"),
    ("astar", "rust"),
    ("near-sdk", "rust"),
    ("aurora-engine", "rust"),
    ("aptos", "move"),
    ("sui", "move"),
    ("cosmos-sdk", "go"),
    ("cometbft", "go"),
    ("dydxprotocol", "go"),
    ("v4-chain", "go"),
    ("celo-org", "go"),
)


# Bug-class / attack-class inference (sibling of the historic ETL's
# ``infer_bug_attack``; specialised to disclosure-title vocabulary).
BUG_ATTACK_PATTERNS: Tuple[Tuple[re.Pattern, str, str], ...] = (
    (re.compile(r"\b(reentran|reenter|callback)\b", re.I), "reentrancy", "reentrancy"),
    (re.compile(r"\b(unauthori[sz]ed|access[- ]control|missing[- ]onlyowner|missing[- ]role)\b", re.I),
     "access-control-bypass", "access-control-bypass"),
    (re.compile(r"\b(oracle|price[- ]manipulation|tw[- ]?ap)\b", re.I), "oracle-manipulation", "oracle-manipulation"),
    (re.compile(r"\b(front[- ]?run|sandwich)\b", re.I), "frontrunning", "frontrunning"),
    (re.compile(r"\b(integer\s+(under|over)flow|memory\s+corruption|out\s+of\s+bound|oob)\b", re.I),
     "memory-corruption", "memory-corruption"),
    (re.compile(r"\b(unlimited\s+minting|infinite\s+mint|mint\s+unlimited|unlimited\s+amount)\b", re.I),
     "unbounded-mint", "unbounded-mint"),
    (re.compile(r"\b(permanent\s+freezing|frozen|freeze)\b", re.I), "permanent-freeze", "fund-freeze"),
    (re.compile(r"\b(stealing|theft|stolen|drain)\b", re.I), "theft", "fund-theft"),
    (re.compile(r"\b(precision[- ]loss|rounding)\b", re.I), "precision-loss", "precision-loss"),
    (re.compile(r"\b(dos|denial[- ]of[- ]service|grief|griefing)\b", re.I), "dos", "dos"),
    (re.compile(r"\b(slippage|slippage[- ]control)\b", re.I), "slippage-bypass", "slippage-bypass"),
    (re.compile(r"\b(replay|nonce)\b", re.I), "replay-attack", "signature-replay"),
    (re.compile(r"\b(signature|sig[- ]verif|malleab)\b", re.I), "signature-bypass", "signature-malleability"),
    (re.compile(r"\b(insolven|bad[- ]debt|under[- ]collateral)\b", re.I),
     "insolvency", "liquidation-solvency"),
    (re.compile(r"\b(governance|quorum|vote|voting)\b", re.I), "governance-bypass", "governance-bypass"),
    (re.compile(r"\b(double[- ]spend|double[- ]claim|double[- ]reward)\b", re.I),
     "double-spend", "accounting-double-spend"),
)


IMPACT_PATTERNS: Tuple[Tuple[re.Pattern, str, str], ...] = (
    (re.compile(r"\btheft\b|\bstolen\b|\bsteal\b|\bdrain\b", re.I), "theft", "arbitrary-user"),
    (re.compile(r"\bpermanent\s+freezing|\bfreez", re.I), "freeze", "arbitrary-user"),
    (re.compile(r"\bgriefing\b|\bbrick", re.I), "griefing", "arbitrary-user"),
    (re.compile(r"\bdenial[- ]of[- ]service\b|\bdos\b", re.I), "dos", "arbitrary-user"),
    (re.compile(r"\byield[- ]?redistribut", re.I), "yield-redistribution", "yield-recipient"),
    (re.compile(r"\bprecision[- ]loss\b|\brounding\b", re.I), "precision-loss", "arbitrary-user"),
    (re.compile(r"\bgovernance[- ]?take", re.I), "governance-takeover", "validator-set"),
    (re.compile(r"\bprivilege[- ]escalation\b", re.I), "privilege-escalation", "arbitrary-user"),
)


DOMAIN_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bbridge\b|cross[- ]chain", re.I), "bridge"),
    (re.compile(r"\boracle\b", re.I), "oracle"),
    (re.compile(r"\bgovernance|\bdao\b|\bvote\b|\bvoting", re.I), "governance"),
    (re.compile(r"\blending\b|\bborrow\b|\baave\b|\bcompound\b", re.I), "lending"),
    (re.compile(r"\bdex\b|\buniswap\b|\bcurve\b|\bbalancer\b|\bswap\b", re.I), "dex"),
    (re.compile(r"\bstaking\b|\brestaking\b", re.I), "staking"),
    (re.compile(r"\bvault\b|\b4626\b", re.I), "vault"),
    (re.compile(r"\brollup\b|\boptimistic\b|\bzk[- ]?rollup\b", re.I), "rollup"),
    (re.compile(r"\bzk[- ]?proof\b|\bplonk\b|\bgroth", re.I), "zk-proof"),
    (re.compile(r"\bconsensus\b|\bvalidator\b|\bfinaliz", re.I), "consensus"),
    (re.compile(r"\brpc\b|\bsequencer\b|\bmempool\b|\bblockchain[- /]?dlt\b|firedancer", re.I), "rpc-infra"),
    (re.compile(r"\bescrow\b", re.I), "escrow"),
    (re.compile(r"\bnft\b|\berc[- ]?721\b", re.I), "nft"),
    (re.compile(r"\bgaming\b", re.I), "gaming"),
    (re.compile(r"\bl1[- ]?client\b", re.I), "l1-client"),
)


def infer_bug_attack(text: str) -> Tuple[str, str]:
    for pattern, bug, attack in BUG_ATTACK_PATTERNS:
        if pattern.search(text):
            return bug, attack
    return "logic-error", "protocol-invariant-bypass"


def infer_impact(text: str) -> Tuple[str, str]:
    for pattern, impact, actor in IMPACT_PATTERNS:
        if pattern.search(text):
            return impact, actor
    return "griefing", "arbitrary-user"


def infer_domain(text: str) -> str:
    for pattern, domain in DOMAIN_PATTERNS:
        if pattern.search(text):
            return domain
    return "dex"  # safe default; most Immunefi disclosures land on DeFi


def infer_target_language(report_type: str, target_url: str) -> str:
    rt = (report_type or "").strip().lower().replace("/", "_")
    base = REPORT_TYPE_TO_LANGUAGE.get(rt, "solidity")
    url_low = (target_url or "").lower()
    for hint, language in REPO_LANGUAGE_HINTS:
        if hint in url_low:
            return language
    return base


def extract_target_repo(target_url: str, program_slug: str) -> str:
    m = GITHUB_URL_RE.search(target_url or "")
    if m:
        owner = m.group("owner")
        repo = m.group("repo").rstrip(".git")
        # repo path may include things like `/blob/...`; the regex already
        # captured only the second segment so we're safe.
        return f"{owner}/{repo}"
    return f"immunefi-public/{slugify(program_slug, max_len=64) or 'unknown'}"


# ---------------------------------------------------------------------------
# Disclosure parsing
# ---------------------------------------------------------------------------


def parse_disclosure_markdown(text: str) -> Optional[Dict[str, Any]]:
    """Parse a single disclosure markdown body. Returns None if the file is
    not a recognised disclosure (e.g. README.md / SUMMARY.md).
    """
    fields: Dict[str, Any] = {}
    title_match = TITLE_RE.search(text)
    if not title_match:
        return None
    fields["title"] = one_line(title_match.group(1), "untitled-disclosure", max_len=240)
    for name, pattern in HEADER_FIELDS:
        m = pattern.search(text)
        if m:
            fields[name] = one_line(m.group(1), "", max_len=500)
    if "report_id" not in fields or "severity" not in fields:
        return None  # not a disclosure-shape file
    submitted_match = SUBMITTED_RE.search(text)
    if submitted_match:
        fields["submission_date"] = one_line(submitted_match.group("date"), "", max_len=120)
        fields["submitter"] = one_line(submitted_match.group("handle"), "", max_len=80)
        fields["program"] = one_line(submitted_match.group("program"), "", max_len=120)
        fields["bounty_url"] = one_line(submitted_match.group("url"), "", max_len=240)
    impacts: List[str] = []
    iblock = IMPACTS_BLOCK_RE.search(text)
    if iblock:
        for line in iblock.group(1).splitlines():
            stripped = line.strip()
            if stripped.startswith("-"):
                impacts.append(stripped.lstrip("-").strip())
    fields["impacts"] = impacts
    # description body, capped
    descr_match = DESCRIPTION_HEAD_RE.search(text)
    if descr_match:
        fields["description"] = one_line(text[descr_match.end(): descr_match.end() + 1500], "", max_len=1500)
    else:
        fields["description"] = one_line(text[:1500], "", max_len=1500)
    return fields


def disclosure_year(fields: Dict[str, Any]) -> int:
    date = str(fields.get("submission_date") or "")
    m = YEAR_RE.search(date)
    if m:
        return int(m.group(1))
    return 2024  # public disclosures in this repo span 2022-2025; safe mid-band default


# ---------------------------------------------------------------------------
# Record assembly
# ---------------------------------------------------------------------------


def build_record(
    *,
    fields: Dict[str, Any],
    repo_path: str,
    branch: str = DEFAULT_BRANCH,
) -> Optional[Dict[str, Any]]:
    """Build one hackerman_record from parsed disclosure fields.

    ``repo_path`` is the markdown file's path inside the source repo, e.g.
    ``Alchemix/30634 - [SC - Critical] ....md``. It becomes the canonical
    GitHub URL for ``source_audit_ref``.
    """
    severity_raw = str(fields.get("severity") or "").strip().lower()
    if severity_raw not in SEVERITY_TO_SCHEMA:
        return None
    severity = SEVERITY_TO_SCHEMA[severity_raw]
    impact_class_dollar = SEVERITY_TO_DOLLAR_CLASS[severity_raw]
    report_id = str(fields.get("report_id") or "").strip()
    if not report_id:
        return None
    target_url = str(fields.get("target") or "")
    program_slug = str(fields.get("program") or repo_path.split("/", 1)[0])
    target_repo = extract_target_repo(target_url, program_slug)
    target_language = infer_target_language(str(fields.get("report_type") or ""), target_url)
    title = str(fields.get("title") or "untitled")
    description = str(fields.get("description") or "")
    impacts_joined = " ; ".join(fields.get("impacts") or [])
    full_text = f"{title}\n{description}\n{impacts_joined}\n{program_slug}"
    bug_class, attack_class = infer_bug_attack(full_text)
    impact_class, impact_actor = infer_impact(full_text + " " + impacts_joined)
    domain = infer_domain(full_text)
    year = disclosure_year(fields)

    encoded_path = urllib.parse.quote(repo_path, safe="/")
    canonical_url = f"https://github.com/{SOURCE_REPO}/blob/{branch}/{encoded_path}"
    source_audit_ref = canonical_url[:240]

    identity_seed = (
        f"immunefi-public\n{SOURCE_REPO}\n{report_id}\n{repo_path}"
    )
    digest = hashlib.sha256(identity_seed.encode("utf-8")).hexdigest()[:12]
    record_id = f"immunefi-public:{report_id}:{digest}"

    component = (program_slug or title).strip()[:240] or "unknown-component"
    function_hint = slugify(title, max_len=48).replace("-", "_") or "unknown_function"
    if target_language == "solidity":
        signature = f"function-name-hint: {function_hint}"
    elif target_language == "rust":
        signature = f"fn-name-hint: {function_hint}"
    elif target_language == "go":
        signature = f"func-name-hint: {function_hint}"
    elif target_language == "move":
        signature = f"public-fun-name-hint: {function_hint}"
    else:
        signature = f"name-hint: {function_hint}"
    shape_tags = [
        slugify(attack_class),
        slugify(f"{target_language}-{bug_class}", max_len=64),
        slugify(f"immunefi-program-{program_slug}", max_len=64),
        f"severity-{severity}",
        "source-immunefi-public",
        "mitigation-state-post-fix-released",
    ]
    seen: set = set()
    shape_tags = [t for t in shape_tags if t and not (t in seen or seen.add(t))]

    submission_handle = str(fields.get("submitter") or "anon")
    submission_date = str(fields.get("submission_date") or "")
    action_seq = one_line(
        (
            f"[mitigation-state=post-fix-released; source=immunefi-public-disclosure; "
            f"report_id=#{report_id}; submitter=@{submission_handle}; submitted={submission_date}] "
            f"Exercise the {component} component path described by the public disclosure: {title}. "
            f"Impacts as listed by the reporter: {impacts_joined or 'see disclosure body'}. "
            f"Description excerpt: {description}"
        ),
        fallback=f"Exercise the {component} path described by {title}.",
        max_len=3000,
    )

    preconditions: List[str] = []
    if impacts_joined:
        preconditions.append(
            one_line(
                f"Impact listed verbatim by Immunefi disclosure: {impacts_joined}",
                fallback="public disclosure path reachable",
                max_len=1000,
            )
        )
    preconditions.append(
        one_line(
            f"Target reachable via {target_url or 'program scope'}; reproduce against the audit-pin "
            f"snapshot referenced in the disclosure (post-fix-released by competition close).",
            fallback="public disclosure path reachable",
            max_len=1000,
        )
    )

    record: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": source_audit_ref,
        "target_domain": domain,
        "target_language": target_language,
        "target_repo": target_repo,
        "target_component": component,
        "function_shape": {
            "raw_signature": signature,
            "shape_tags": shape_tags,
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": action_seq,
        "required_preconditions": preconditions,
        "impact_class": impact_class,
        "impact_actor": impact_actor,
        "impact_dollar_class": impact_class_dollar,
        "fix_pattern": one_line(
            (
                f"Refer to the public Immunefi disclosure at {canonical_url} for the recommended "
                f"mitigation. The competition's fix is post-released by the time the disclosure is "
                f"archived to immunefi-team/Past-Audit-Competitions; verify the upstream fix commit "
                f"on {target_repo} before assuming the same shape is still vulnerable in any newer "
                f"audit-pin."
            ),
            fallback=f"see {canonical_url}",
            max_len=1000,
        ),
        "fix_anti_pattern_avoided": one_line(
            (
                "Assuming a public disclosure is automatically fixed in every fork or downstream "
                "deployment; the fix only applies to the bounty-program's canonical repo."
            ),
            fallback="assuming post-fix coverage of forks",
            max_len=1000,
        ),
        "severity_at_finding": severity,
        "year": year,
        "record_tier": "public-corpus",
        "source_extraction_method": "corpus-etl",
        "source_extraction_confidence": 0.85,
        "cross_language_analogues": [],
        "related_records": [],
    }
    return record


def output_filename(record: Dict[str, Any]) -> str:
    digest = str(record["record_id"]).rsplit(":", 1)[-1]
    base = slugify(record["record_id"], max_len=110)
    return f"{base}-{digest}.yaml"


# ---------------------------------------------------------------------------
# Fetch (optional; gh api driven). Cache files are written directly into
# --cache-dir as <Competition>/<original_filename>.md, mirroring the
# upstream repo layout.
# ---------------------------------------------------------------------------


def _gh_api(path: str, *, allow_fail: bool = False) -> Optional[Dict[str, Any]]:
    try:
        out = subprocess.check_output(
            ["gh", "api", path],
            stderr=subprocess.DEVNULL,
            timeout=60,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        if allow_fail:
            return None
        raise
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def fetch_into_cache(
    cache_dir: Path,
    *,
    max_competitions: Optional[int] = None,
    max_files_per_competition: Optional[int] = None,
) -> Dict[str, Any]:
    """Drive a gh-api download of the disclosure markdown files.

    Honest behaviour: if ``gh api`` is unavailable / unauthenticated, this
    returns a BLOCKED-shape summary; the caller is responsible for emitting
    rc=3.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    summary: Dict[str, Any] = {
        "competitions_listed": 0,
        "competitions_downloaded": 0,
        "files_downloaded": 0,
        "skipped_existing": 0,
        "errors": [],
    }
    root = _gh_api(f"repos/{SOURCE_REPO}/contents", allow_fail=True)
    if not isinstance(root, list):
        summary["errors"].append("gh api repos/<source>/contents unavailable")
        return summary
    competitions = [e for e in root if e.get("type") == "dir"]
    summary["competitions_listed"] = len(competitions)
    if max_competitions is not None:
        competitions = competitions[:max_competitions]
    for comp in competitions:
        comp_name = comp["name"]
        encoded = urllib.parse.quote(comp_name, safe="")
        listing = _gh_api(f"repos/{SOURCE_REPO}/contents/{encoded}", allow_fail=True)
        if not isinstance(listing, list):
            summary["errors"].append(f"listing failed for {comp_name}")
            continue
        files = [e for e in listing if e.get("type") == "file" and e.get("name", "").endswith(".md")]
        if max_files_per_competition is not None:
            files = files[:max_files_per_competition]
        comp_dir = cache_dir / comp_name
        comp_dir.mkdir(parents=True, exist_ok=True)
        for f in files:
            out_path = comp_dir / f["name"]
            if out_path.exists() and out_path.stat().st_size > 0:
                summary["skipped_existing"] += 1
                continue
            enc_path = urllib.parse.quote(f"{comp_name}/{f['name']}", safe="")
            blob = _gh_api(f"repos/{SOURCE_REPO}/contents/{enc_path}", allow_fail=True)
            if not isinstance(blob, dict) or "content" not in blob:
                summary["errors"].append(f"fetch failed for {comp_name}/{f['name']}")
                continue
            try:
                body = base64.b64decode(blob["content"]).decode("utf-8", errors="replace")
            except Exception as exc:  # noqa: BLE001
                summary["errors"].append(f"decode failed for {comp_name}/{f['name']}: {exc}")
                continue
            out_path.write_text(body, encoding="utf-8")
            summary["files_downloaded"] += 1
        summary["competitions_downloaded"] += 1
    return summary


# ---------------------------------------------------------------------------
# Cache walking + record emission
# ---------------------------------------------------------------------------


def walk_cache(cache_dir: Path) -> Iterable[Tuple[str, Path]]:
    """Yield (repo_path, abs_path) for every .md file in cache_dir.

    ``repo_path`` is the cache-relative path (Competition/<file>.md). This is
    the canonical path used to construct GitHub source URLs.
    """
    if not cache_dir.is_dir():
        return
    for p in sorted(cache_dir.rglob("*.md")):
        if p.name.lower() in {"readme.md", "summary.md"}:
            continue
        rel = p.relative_to(cache_dir).as_posix()
        yield rel, p


def convert(
    cache_dir: Path,
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    branch: str = DEFAULT_BRANCH,
    severity_filter: Optional[str] = None,
) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "cache_dir": str(cache_dir),
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "scanned_files": 0,
        "parsed_disclosures": 0,
        "records_attempted": 0,
        "records_emitted": 0,
        "file_count": 0,
        "files": [],
        "by_severity": {},
        "by_target_language": {},
        "by_competition": {},
        "errors": [],
        "validation_errors": [],
        "parse_errors": [],
    }
    schema = _VALIDATOR.load_schema()
    schema_dir_made = False
    sev_filter_norm = (severity_filter or "").strip().lower() or None
    for rel_path, abs_path in walk_cache(cache_dir):
        summary["scanned_files"] += 1
        try:
            text = abs_path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            summary["parse_errors"].append(f"{rel_path}: read error: {exc}")
            continue
        fields = parse_disclosure_markdown(text)
        if not fields:
            continue
        summary["parsed_disclosures"] += 1
        sev_raw = str(fields.get("severity") or "").strip().lower()
        if sev_filter_norm and sev_raw != sev_filter_norm:
            continue
        record = build_record(fields=fields, repo_path=rel_path, branch=branch)
        if record is None:
            summary["parse_errors"].append(f"{rel_path}: unrecognised severity {sev_raw!r}")
            continue
        summary["records_attempted"] += 1
        rendered = yaml_dump(record)
        try:
            import yaml as _yaml

            rendered_doc = _yaml.safe_load(rendered)
        except Exception as exc:  # noqa: BLE001
            summary["validation_errors"].append(f"{rel_path}: yaml parse failure: {exc}")
            continue
        errs = _VALIDATOR.validate_doc(rendered_doc, schema)
        if errs:
            summary["validation_errors"].extend(f"{rel_path}: {err}" for err in errs)
            continue
        summary["records_emitted"] += 1
        sev = record["severity_at_finding"]
        summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
        lang = record["target_language"]
        summary["by_target_language"][lang] = summary["by_target_language"].get(lang, 0) + 1
        comp_key = rel_path.split("/", 1)[0]
        summary["by_competition"][comp_key] = summary["by_competition"].get(comp_key, 0) + 1
        out_path = out_dir / output_filename(record)
        summary["files"].append(str(out_path))
        if not dry_run:
            if not schema_dir_made:
                out_dir.mkdir(parents=True, exist_ok=True)
                schema_dir_made = True
            out_path.write_text(rendered, encoding="utf-8")
        if limit is not None and summary["records_emitted"] >= limit:
            break
    summary["file_count"] = len(summary["files"])
    if summary["parse_errors"] or summary["validation_errors"]:
        summary["errors"] = summary["parse_errors"] + summary["validation_errors"]
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cache-dir",
        required=True,
        help="Directory of disclosure markdown files (Competition/<name>.md layout).",
    )
    parser.add_argument("--out-dir", required=True, help="Output dir for emitted YAML records.")
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Drive a gh-api download of the immunefi-team/Past-Audit-Competitions feed into --cache-dir.",
    )
    parser.add_argument(
        "--max-competitions",
        type=int,
        default=None,
        help="When --fetch is set, cap competitions downloaded (for testing / rate-limit safety).",
    )
    parser.add_argument(
        "--max-files-per-competition",
        type=int,
        default=None,
        help="When --fetch is set, cap files-per-competition downloaded.",
    )
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument(
        "--severity-filter",
        default=None,
        help="Optional severity filter (critical/high/medium/low/insight).",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    cache_dir = Path(args.cache_dir).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    fetch_summary: Optional[Dict[str, Any]] = None
    if args.fetch:
        fetch_summary = fetch_into_cache(
            cache_dir,
            max_competitions=args.max_competitions,
            max_files_per_competition=args.max_files_per_competition,
        )
        if fetch_summary["files_downloaded"] == 0 and fetch_summary["skipped_existing"] == 0:
            print(
                json.dumps(
                    {
                        "verdict": "BLOCKED-NO-REAL-SOURCE",
                        "reason": "gh api fetch returned 0 files; "
                                  "Immunefi public disclosure feed unavailable.",
                        "fetch_summary": fetch_summary,
                    },
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 3
    if not cache_dir.is_dir():
        print(
            json.dumps(
                {
                    "verdict": "BLOCKED-NO-REAL-SOURCE",
                    "reason": f"cache dir {cache_dir} does not exist; "
                              f"pass --fetch or seed it with real disclosure markdown files.",
                }
            ),
            file=sys.stderr,
        )
        return 3
    if not any(cache_dir.rglob("*.md")):
        print(
            json.dumps(
                {
                    "verdict": "BLOCKED-NO-REAL-SOURCE",
                    "reason": f"cache dir {cache_dir} contains no markdown files.",
                }
            ),
            file=sys.stderr,
        )
        return 3
    summary = convert(
        cache_dir,
        out_dir,
        dry_run=args.dry_run,
        limit=args.limit,
        branch=args.branch,
        severity_filter=args.severity_filter,
    )
    if fetch_summary is not None:
        summary["fetch_summary"] = fetch_summary
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman Immunefi-public ETL: "
            f"files={summary['scanned_files']} parsed={summary['parsed_disclosures']} "
            f"records={summary['records_emitted']} "
            f"validation_errors={len(summary['validation_errors'])}"
        )
    rc = 0
    if summary["parse_errors"] or summary["validation_errors"]:
        rc = 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
