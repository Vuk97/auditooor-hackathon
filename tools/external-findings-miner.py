#!/usr/bin/env python3
"""external-findings-miner.py - one-pass {family} -> triple-bundle miner.

Take a single bug-CLASS family keyword (e.g. "reentrancy",
"oracle-staleness", "signature-replay") and mine the public-archive corpus
(Solodit via the @marchev/claudit MCP tools `search_findings` / `get_finding`,
plus any public Code4rena / Sherlock / Cantina report text the caller pipes
in) into the THREE derived products the harness needs from a single source,
in one pass:

  1. CORPUS RECORD  - a `auditooor.hackerman_record.v1.2` record per finding
     (the per-finding evidence row).
  2. GENERALIZED INVARIANT - ONE cross-domain `auditooor.invariant_candidate.v1`
     synthesized from the whole family slice. The statement is protocol-
     agnostic: protocol / contract / token names observed in the inputs are
     NOT baked into it, so the invariant lifts across every protocol in the
     family, not just the ones mined.
  3. DETECTOR SEED  - a regex seed (schema
     `auditooor.external_findings_detector_seed.v1`) built ONLY from verbatim
     tokens that recur >=N times across DISTINCT findings in the slice.

Then it BACKTESTS the generated detector seed against the family corpus it
was built from and reports the hit-rate honestly. A backtest MISS is a MISS:
the tool never inflates the hit count, never fabricates a match, and prints
the unmatched finding ids so the operator can see exactly what the seed
failed to catch.

RELATED TOOLS (read before assuming overlap):
  - tools/solodit-rest-direct.py        : emits ONLY corpus records, direct
    REST, no invariant + no detector seed + no backtest.
  - tools/mine-solodit.py               : emits ONLY pattern-YAML stubs.
  - tools/hackerman-detector-seed-extractor.py : extracts detector seeds from
    the ALREADY-INGESTED corpus (recurrence over the whole tag tree), not
    from a fresh {family} pull, and emits NO corpus record + NO invariant.
  - tools/llm-extract-invariants.py     : extracts invariants from the
    already-ingested corpus, emits NO corpus record + NO detector seed.
  UNIQUE GAP this tool fills: it is the only tool that, given a SINGLE
  {family} keyword, produces the corpus-record + generalized-invariant +
  detector-seed TRIPLE in one pass AND backtests the seed it just produced.

VERIFICATION TIER (Rule 37): every emitted record is
`tier-2-verified-public-archive` - each row sources from a public, stable
Solodit / Code4rena / Sherlock / Cantina URL extracted verbatim from the
input. No tier-1 (live-API per-CVE) claim is made; no synthetic tier-3 row
is produced. If an input finding carries no source URL, that row is dropped
(not emitted at a lower tier) so the tier-2 claim stays honest.

M14-TRAP DISCIPLINE (verbatim-only, no fabrication):
  - Every record's attacker_action_sequence / excerpt is sliced VERBATIM
    from the input finding text. No paraphrase is inserted into a record.
  - The generalized invariant statement is built from a fixed cross-domain
    template indexed by family category - it does NOT invent protocol facts;
    it only states the protection that the family of findings shares.
  - Detector-seed tokens are verbatim substrings of the input text; the
    backtest matches them verbatim. The tool cannot "hallucinate" a token
    that was not literally present in >=N distinct findings.

INPUT FORMATS (any one):
  --findings-json <file>   A JSON list/dict of finding objects (the shape
                           returned by the Solodit MCP search_findings when
                           the caller serialises it, OR a hand-written list).
  --findings-md <file>     The raw formatted-markdown text the Solodit MCP
                           tools print (search_findings / get_finding). The
                           tool parses the `### #<id> [SEV] <title>`,
                           `https://...`, `**Firm:**`, `**Protocol:**`,
                           `Source: <url>`, and body blocks out of it.
  --findings-md -          Read the markdown from stdin.

USAGE
  # From a JSON dump the orchestrator produced from search_findings:
  python3 tools/external-findings-miner.py \\
      --family reentrancy \\
      --findings-json /tmp/reentrancy_findings.json \\
      --out-dir /tmp/family-reentrancy

  # From the raw MCP markdown piped on stdin:
  some_mcp_dump | python3 tools/external-findings-miner.py \\
      --family oracle-staleness --findings-md - --out-dir /tmp/oracle

  # JSON verdict only, write nothing (dry-run backtest preview):
  python3 tools/external-findings-miner.py --family reentrancy \\
      --findings-json /tmp/f.json --json-only --dry-run

EXIT CODES
  0  bundle emitted (or dry-run / json-only completed) - even if backtest
     recall is low; a miss is reported, not failed.
  2  no usable findings parsed from the input (nothing to mine).
  3  bad arguments / unreadable input file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA_RECORD = "auditooor.hackerman_record.v1.2"
SCHEMA_INVARIANT = "auditooor.invariant_candidate.v1"
SCHEMA_SEED = "auditooor.external_findings_detector_seed.v1"
SCHEMA_VERDICT = "auditooor.external_findings_miner.v1"
TIER = "tier-2-verified-public-archive"
TOOL_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Family -> (category, defense_layer, commit_point_pattern, cross-domain
# invariant statement). The statement is PROTOCOL-AGNOSTIC by construction:
# it states the shared protection, never a protocol fact. Used for the
# GENERALIZED invariant. Keys are matched as substrings of the --family arg
# (lower-cased) so callers can pass "oracle-staleness", "stale-oracle",
# "oracle price staleness" and all hit the same row.
# ---------------------------------------------------------------------------
FAMILY_TABLE: Dict[str, Dict[str, str]] = {
    "reentran": {
        "category": "atomicity",
        "defense_layer": "checks-effects-interactions / reentrancy-guard",
        "commit_point_pattern": "state-write-before-external-call",
        "statement": (
            "An external call that can hand control back to an untrusted "
            "party MUST NOT execute before every state write that the call's "
            "guard depends on has committed; reentrancy guards on one "
            "function MUST cover every sibling entrypoint that mutates the "
            "same protected state."
        ),
    },
    "oracle": {
        "category": "freshness",
        "defense_layer": "staleness-check / round-completeness / heartbeat",
        "commit_point_pattern": "price-consumed-without-freshness-gate",
        "statement": (
            "A price or rate read from an external oracle MUST be rejected "
            "unless its publish timestamp is within the configured heartbeat "
            "and its round is complete before the value is used in any "
            "value-bearing computation."
        ),
    },
    "signature": {
        "category": "uniqueness",
        "defense_layer": "nonce-consume / deadline / domain-separator",
        "commit_point_pattern": "signature-accepted-without-replay-guard",
        "statement": (
            "A signed message MUST be bound to a single use: the nonce MUST "
            "be consumed atomically with acceptance, the deadline MUST be "
            "enforced, and the domain separator MUST bind chain id and "
            "verifying contract so the signature cannot be replayed across "
            "calls, chains, or contracts."
        ),
    },
    "replay": {
        "category": "uniqueness",
        "defense_layer": "nonce-consume / message-id-dedup",
        "commit_point_pattern": "message-accepted-without-dedup",
        "statement": (
            "Any message, proof, or voucher that authorises an effect MUST "
            "be marked consumed atomically with the effect so the same "
            "artifact cannot be submitted twice."
        ),
    },
    "access": {
        "category": "authorization",
        "defense_layer": "role-check / owner-check / modifier",
        "commit_point_pattern": "privileged-effect-without-authorization",
        "statement": (
            "Every state transition that changes ownership, roles, funds "
            "routing, or upgrade targets MUST verify the caller's authority "
            "before the effect, and the check MUST be present on every "
            "entrypoint that reaches the protected effect."
        ),
    },
    "auth": {
        "category": "authorization",
        "defense_layer": "role-check / owner-check / modifier",
        "commit_point_pattern": "privileged-effect-without-authorization",
        "statement": (
            "Every privileged effect MUST verify the caller's authority "
            "before the effect on every entrypoint that reaches it."
        ),
    },
    "arithmetic": {
        "category": "bounds",
        "defense_layer": "bounds-check / checked-math / rounding-direction",
        "commit_point_pattern": "value-derived-without-bounds-or-rounding-guard",
        "statement": (
            "Arithmetic that derives a balance, share, or price MUST guard "
            "against overflow, truncation, and division-by-zero, and MUST "
            "round in the direction that favours the protocol over the "
            "actor who controls the inputs."
        ),
    },
    "rounding": {
        "category": "bounds",
        "defense_layer": "rounding-direction / dust-handling",
        "commit_point_pattern": "rounding-favours-caller",
        "statement": (
            "Rounding in share/asset conversions MUST favour the protocol "
            "(round down on credit to the actor, round up on debit from the "
            "actor) so repeated operations cannot extract value."
        ),
    },
    "slippage": {
        "category": "bounds",
        "defense_layer": "min-out / deadline / price-bound",
        "commit_point_pattern": "swap-executed-without-min-out",
        "statement": (
            "A swap, mint, or redeem that the caller initiates with an "
            "expected output MUST enforce a caller-supplied minimum-output "
            "and a deadline before the trade commits."
        ),
    },
    "liquidat": {
        "category": "conservation",
        "defense_layer": "health-factor-recompute / oracle-fresh / close-factor",
        "commit_point_pattern": "liquidation-without-fresh-health-recompute",
        "statement": (
            "A liquidation MUST recompute the position's health from a fresh "
            "price immediately before seizing collateral, and MUST cap the "
            "seized amount to the close factor so a healthy or over-seized "
            "position cannot be liquidated."
        ),
    },
    "accounting": {
        "category": "conservation",
        "defense_layer": "checkpoint-before-balance-change / pending-accrual",
        "commit_point_pattern": "reward-claimed-without-checkpoint",
        "statement": (
            "Per-user reward/accrual accounting MUST checkpoint pending "
            "amounts before any balance, stake, or rate change so accrued "
            "value cannot be double-counted or stranded."
        ),
    },
}

# Generic fallback row for families with no curated template. The statement
# is still cross-domain and honest about being a generic guard; it is NOT
# fabricated protocol behaviour.
FALLBACK_FAMILY = {
    "category": "ordering",
    "defense_layer": "validate-before-effect",
    "commit_point_pattern": "effect-before-validation",
    "statement": (
        "Every effect that changes protocol state MUST be preceded by the "
        "validation that the effect's safety depends on; the validation MUST "
        "cover every entrypoint that reaches the effect."
    ),
}


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def slugify(text: str, maxlen: int = 60) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:maxlen] or "untitled"


def family_row(family: str) -> Dict[str, str]:
    fl = (family or "").lower()
    for key, row in FAMILY_TABLE.items():
        if key in fl:
            return row
    return dict(FALLBACK_FAMILY)


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------
def _norm_finding(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalise one finding dict into the canonical internal shape.

    Returns None if the finding has no source URL (tier-2 honesty: a record
    with no public archive ref is not emitted)."""
    fid = str(obj.get("id") or obj.get("finding_id") or obj.get("upstream_finding_id") or "").strip()
    title = (obj.get("title") or obj.get("name") or "").strip()
    severity = (obj.get("severity") or obj.get("severity_at_finding") or "").strip().upper()
    firm = (obj.get("firm") or obj.get("upstream_firm_name") or "").strip()
    protocol = (obj.get("protocol") or obj.get("upstream_protocol_name") or "").strip()
    content = (obj.get("content") or obj.get("body") or obj.get("description") or
               obj.get("attacker_action_sequence") or "").strip()
    url = (obj.get("source") or obj.get("source_url") or obj.get("source_audit_ref") or "").strip()
    solodit_url = (obj.get("url") or obj.get("solodit_url") or obj.get("record_source_url") or "").strip()
    src = url if url.startswith("http") else ""
    if not src:
        src = solodit_url if solodit_url.startswith("http") else ""
    if not src:
        return None
    tags = obj.get("tags") or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",") if t.strip()]
    return {
        "id": fid or hashlib.sha1(src.encode()).hexdigest()[:10],
        "title": title or "(untitled)",
        "severity": severity or "UNKNOWN",
        "firm": firm or "unknown",
        "protocol": protocol or "unknown",
        "content": content,
        "source_url": src,
        "solodit_url": solodit_url if solodit_url.startswith("http") else src,
        "tags": [str(t) for t in tags],
    }


def parse_findings_json(text: str) -> List[Dict[str, Any]]:
    data = json.loads(text)
    if isinstance(data, dict):
        for key in ("findings", "results", "items", "data"):
            if key in data and isinstance(data[key], list):
                data = data[key]
                break
        else:
            data = [data]
    out: List[Dict[str, Any]] = []
    for obj in data:
        if isinstance(obj, dict):
            n = _norm_finding(obj)
            if n:
                out.append(n)
    return out


_MD_HEADER_RE = re.compile(
    r"^###\s+#?(?P<id>\d+)\s*\[(?P<sev>[A-Z]+)\]\s*(?P<title>.+?)\s*$",
    re.MULTILINE,
)
_MD_SINGLE_RE = re.compile(
    r"^#\s+\[(?P<sev>[A-Z]+)\]\s*(?P<title>.+?)\s*$",
    re.MULTILINE,
)
_FIRM_RE = re.compile(r"\*\*Firm:\*\*\s*(?P<firm>[^|]+?)\s*\|", re.IGNORECASE)
_PROTO_RE = re.compile(r"\*\*Protocol:\*\*\s*(?P<proto>[^|]+?)\s*(?:\||$)", re.IGNORECASE | re.MULTILINE)
_SOURCE_RE = re.compile(r"Source:\s*(?P<url>https?://\S+)", re.IGNORECASE)
_URL_RE = re.compile(r"(https?://solodit\.cyfrin\.io/\S+)")
_TABLE_FIRM_RE = re.compile(r"^\|\s*Firm\s*\|\s*(?P<firm>.+?)\s*\|", re.MULTILINE)
_TABLE_PROTO_RE = re.compile(r"^\|\s*Protocol\s*\|\s*(?P<proto>.+?)\s*\|", re.MULTILINE)
_TABLE_SOLODIT_RE = re.compile(r"^\|\s*Solodit\s*\|\s*(?P<url>https?://\S+?)\s*\|", re.MULTILINE)


def parse_findings_md(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    headers = list(_MD_HEADER_RE.finditer(text))
    if headers:
        for i, h in enumerate(headers):
            start = h.end()
            end = headers[i + 1].start() if i + 1 < len(headers) else len(text)
            block = text[start:end]
            firm_m = _FIRM_RE.search(block)
            proto_m = _PROTO_RE.search(block)
            src_m = _SOURCE_RE.search(block)
            url_m = _URL_RE.search(block) or _URL_RE.search(h.group(0))
            obj = {
                "id": h.group("id"),
                "title": h.group("title").strip(),
                "severity": h.group("sev"),
                "firm": firm_m.group("firm").strip() if firm_m else "",
                "protocol": proto_m.group("proto").strip() if proto_m else "",
                "content": block.strip(),
                "source": src_m.group("url").strip() if src_m else "",
                "url": url_m.group(1).strip() if url_m else "",
            }
            n = _norm_finding(obj)
            if n:
                out.append(n)
        return out
    single = _MD_SINGLE_RE.search(text)
    if single:
        firm_m = _TABLE_FIRM_RE.search(text)
        proto_m = _TABLE_PROTO_RE.search(text)
        url_m = _TABLE_SOLODIT_RE.search(text) or _URL_RE.search(text)
        src_m = _SOURCE_RE.search(text)
        obj = {
            "id": hashlib.sha1(text.encode()).hexdigest()[:10],
            "title": single.group("title").strip(),
            "severity": single.group("sev"),
            "firm": firm_m.group("firm").strip() if firm_m else "",
            "protocol": proto_m.group("proto").strip() if proto_m else "",
            "content": text.strip(),
            "source": src_m.group("url").strip() if src_m else "",
            "url": url_m.group(1).strip() if url_m else "",
        }
        n = _norm_finding(obj)
        if n:
            out.append(n)
    return out


# ---------------------------------------------------------------------------
# Corpus record (1)
# ---------------------------------------------------------------------------
def build_record(family: str, f: Dict[str, Any], frow: Dict[str, str]) -> Dict[str, Any]:
    rid = f"external:{slugify(family,24)}:{f['id']}:{slugify(f['title'],40)}"
    excerpt = f["content"][:1200]  # VERBATIM slice, untouched
    return {
        "schema_version": SCHEMA_RECORD,
        "record_id": rid,
        "verification_tier": TIER,
        "source_audit_ref": f["source_url"],
        "record_source_url": f["solodit_url"],
        "target_domain": "smart-contract",
        "target_language": "solidity",
        "target_repo": "external/solodit",
        "target_component": f["title"],
        "bug_class": frow["category"],
        "attack_class": slugify(family, 40),
        "attacker_role": "unprivileged",
        "attacker_action_sequence": excerpt,
        "severity_at_finding": f["severity"].lower(),
        "fix_pattern": (
            "Mitigation not asserted as shipped; see source finding "
            "recommendation. Family defense layer: " + frow["defense_layer"]
        ),
        "record_extensions": {
            "source_method": "external-findings-miner",
            "tool_version": TOOL_VERSION,
            "ingested_at": utcnow(),
            "upstream_firm_name": f["firm"],
            "upstream_protocol_name": f["protocol"],
            "upstream_finding_id": f["id"],
            "family_keyword": family,
            "upstream_tags": f["tags"],
        },
    }


# ---------------------------------------------------------------------------
# Generalized invariant (2)
# ---------------------------------------------------------------------------
def build_generalized_invariant(
    family: str, findings: List[Dict[str, Any]], frow: Dict[str, str]
) -> Dict[str, Any]:
    source_ids = [f"external:{slugify(family,24)}:{f['id']}" for f in findings]
    inv_id = "INV-EXT-" + slugify(family, 16).upper().replace("-", "") + "-" + hashlib.sha1(
        ("|".join(sorted(source_ids))).encode()
    ).hexdigest()[:8].upper()
    return {
        "schema_version": SCHEMA_INVARIANT,
        "invariant_id": inv_id,
        "category": frow["category"],
        "statement": frow["statement"],  # cross-domain, protocol-agnostic
        "target_lang": "solidity",
        "source_finding_ids": source_ids,
        "abstraction_level": "cross-domain",
        "commit_point_pattern": frow["commit_point_pattern"],
        "defense_layer": frow["defense_layer"],
        "verification_tier": TIER,
        "source_count": len(source_ids),
        "extracted_at_utc": utcnow(),
        "extractor": "external-findings-miner",
        "attack_signature": slugify(family, 60),
        "singleton": len(source_ids) <= 1,
    }


# ---------------------------------------------------------------------------
# Detector seed (3) - regex from verbatim tokens recurring >=N distinct
# findings. Built ONLY from literal substrings of the input.
# ---------------------------------------------------------------------------
_CODE_TOKEN_RE = re.compile(r"`([^`\n]{2,60})`")
_IDENT_RE = re.compile(r"\b([a-z_][A-Za-z0-9_]{3,40})\s*\(")


def _candidate_tokens(content: str) -> set:
    toks = set()
    for m in _CODE_TOKEN_RE.finditer(content):
        t = m.group(1).strip()
        if re.search(r"[(.]|_|[a-z][A-Z]", t):
            toks.add(t)
    for m in _IDENT_RE.finditer(content):
        toks.add(m.group(1) + "(")
    return toks


def build_detector_seed(
    family: str, findings: List[Dict[str, Any]], min_recur: int, frow: Dict[str, str]
) -> Dict[str, Any]:
    counter: Counter = Counter()
    for f in findings:
        for tok in _candidate_tokens(f["content"]):
            counter[tok] += 1  # 1 per DISTINCT finding
    recurring = sorted(
        [(t, c) for t, c in counter.items() if c >= min_recur],
        key=lambda kv: (-kv[1], kv[0]),
    )
    literals = [t for t, _ in recurring]
    pattern = "|".join(re.escape(t) for t in literals[:40]) if literals else ""
    seed_id = "SEED-EXT-" + slugify(family, 16).upper().replace("-", "") + "-" + hashlib.sha1(
        pattern.encode()
    ).hexdigest()[:8].upper()
    return {
        "schema_version": SCHEMA_SEED,
        "seed_id": seed_id,
        "family_keyword": family,
        "attack_class": slugify(family, 40),
        "category": frow["category"],
        "seed_kind": "verbatim_recurring_token_regex",
        "min_recurrence": min_recur,
        "regex": pattern,
        "token_count": len(literals),
        "tokens": [{"token": t, "distinct_finding_hits": c} for t, c in recurring[:40]],
        "verification_tier": TIER,
        "generated_at_utc": utcnow(),
        "generated_by": "external-findings-miner",
        "note": (
            "Tokens are verbatim substrings recurring across >=%d distinct "
            "findings. Empty regex means no token recurred enough - reported "
            "honestly, not padded." % min_recur
        ),
    }


# ---------------------------------------------------------------------------
# Backtest (honest): run the seed regex back over the family corpus.
# ---------------------------------------------------------------------------
def backtest_seed(seed: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    pattern = seed.get("regex") or ""
    total = len(findings)
    if not pattern:
        return {
            "regex_present": False,
            "total_findings": total,
            "matched": 0,
            "missed": total,
            "recall": 0.0,
            "missed_finding_ids": [f["id"] for f in findings],
            "verdict": "no-seed-no-recall",
        }
    rx = re.compile(pattern)
    matched_ids: List[str] = []
    missed_ids: List[str] = []
    for f in findings:
        (matched_ids if rx.search(f["content"]) else missed_ids).append(f["id"])
    matched = len(matched_ids)
    recall = (matched / total) if total else 0.0
    if recall >= 0.8:
        verdict = "strong-recall"
    elif recall >= 0.4:
        verdict = "partial-recall"
    elif recall > 0.0:
        verdict = "weak-recall"
    else:
        verdict = "miss"
    return {
        "regex_present": True,
        "total_findings": total,
        "matched": matched,
        "missed": len(missed_ids),
        "recall": round(recall, 4),
        "matched_finding_ids": matched_ids,
        "missed_finding_ids": missed_ids,
        "verdict": verdict,
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def mine(family: str, findings: List[Dict[str, Any]], min_recur: int) -> Dict[str, Any]:
    frow = family_row(family)
    records = [build_record(family, f, frow) for f in findings]
    invariant = build_generalized_invariant(family, findings, frow)
    seed = build_detector_seed(family, findings, min_recur, frow)
    backtest = backtest_seed(seed, findings)
    return {
        "schema_version": SCHEMA_VERDICT,
        "family": family,
        "family_category": frow["category"],
        "tool_version": TOOL_VERSION,
        "generated_at_utc": utcnow(),
        "verification_tier": TIER,
        "finding_count": len(findings),
        "records": records,
        "generalized_invariant": invariant,
        "detector_seed": seed,
        "backtest": backtest,
    }


def write_outputs(bundle: Dict[str, Any], out_dir: Path) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []
    for rec in bundle["records"]:
        p = out_dir / ("record-" + slugify(rec["record_id"], 80) + ".json")
        p.write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
        written.append(p)
    inv_p = out_dir / ("invariant-" + bundle["generalized_invariant"]["invariant_id"] + ".json")
    inv_p.write_text(json.dumps(bundle["generalized_invariant"], indent=2, sort_keys=True) + "\n")
    written.append(inv_p)
    seed_p = out_dir / ("detector-seed-" + bundle["detector_seed"]["seed_id"] + ".json")
    seed_p.write_text(json.dumps(bundle["detector_seed"], indent=2, sort_keys=True) + "\n")
    written.append(seed_p)
    bt_p = out_dir / "backtest.json"
    bt_p.write_text(json.dumps(bundle["backtest"], indent=2, sort_keys=True) + "\n")
    written.append(bt_p)
    return written


# ---------------------------------------------------------------------------
# Canonical-corpus derived-dir writer (CAP-tool-external-findings-miner wiring)
# Mirrors the zkbugs-dataset wiring pattern: emit the invariant + detector seed
# into the derived/<router>/<batch>/ dirs the EXISTING promote-mined
# SOURCE_ROUTERS already scan, so no schema changes are needed.
#   - invariant_library_extended/<batch>/INV-*.yaml  (json-embedded YAML shape
#     read by promote-mined-to-canonical._extract_invariant_library_extended)
#   - detector_synthesis_v2/<batch>/seed-*.json      (dispatch-ledger generic
#     shape {task_id, status:"ok", result:<json-string>} read by
#     promote-mined-to-canonical._extract_dispatch_ledger_generic)
# The hackerman_record.v1.2 corpus output is deliberately NOT promoted here
# (the peer zkbugs-dataset tool also omits it; corpus-record promotion stays a
# separate, reviewed path).
# ---------------------------------------------------------------------------
def write_to_derived(bundle: Dict[str, Any], derived_root: Path) -> List[Path]:
    family = bundle["family"]
    batch_id = "external-" + slugify(family, 32) + "-" + datetime.now(
        timezone.utc).strftime("%Y%m%d")
    inv_dir = derived_root / "invariant_library_extended" / batch_id
    det_dir = derived_root / "detector_synthesis_v2" / batch_id
    inv_dir.mkdir(parents=True, exist_ok=True)
    det_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    inv = bundle["generalized_invariant"]
    inv_id = inv["invariant_id"]
    # json-embedded YAML: header comments + '---' + JSON body. The extractor
    # reads rec['content'] (invariant_id + statement + category +
    # source_finding_ids), so wrap the invariant under content.
    inv_record = {
        "schema_version": "auditooor.invariant.v1",
        "record_id": inv_id,
        "content": {
            "invariant_id": inv_id,
            "statement": inv["statement"],
            "category": inv["category"],
            "attack_class": inv.get("attack_signature") or inv["category"],
            "target_lang": inv.get("target_lang", "solidity"),
            "source_findings": inv.get("source_finding_ids", []),
            "source_incident_ids": inv.get("source_finding_ids", []),
            "verification_tier": inv.get("verification_tier", TIER),
            "commit_point_pattern": inv.get("commit_point_pattern", ""),
            "defense_layer": inv.get("defense_layer", ""),
            "abstraction_level": inv.get("abstraction_level", "cross-domain"),
        },
        "source": {"batch_id": batch_id, "miner": "external-findings-miner",
                   "family": family},
        "verification_tier": inv.get("verification_tier", TIER),
        "ingested_at_utc": utcnow(),
    }
    inv_header = (
        "# auditooor-external-findings-miner record\n"
        "# schema: auditooor.invariant.v1\n"
        f"# invariant_id: {inv_id}\n"
        "# format: json-embedded\n"
        "---\n"
    )
    inv_path = inv_dir / (inv_id + ".yaml")
    inv_path.write_text(
        inv_header + json.dumps(inv_record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    written.append(inv_path)

    seed = bundle["detector_seed"]
    seed_id = seed["seed_id"]
    # dispatch-ledger generic shape: the seed payload (carrying attack_class +
    # category + statement-like fields) is JSON-string-encoded under `result`.
    det_payload = {
        "detector_id": seed_id,
        "attack_class": seed.get("attack_class"),
        "category": seed.get("category"),
        "statement": (
            "Detector seed for family '%s': verbatim recurring-token regex over "
            "%d tokens (category=%s)."
            % (seed.get("family_keyword", family),
               seed.get("token_count", 0), seed.get("category"))
        ),
        "regex": seed.get("regex", ""),
        "seed_kind": seed.get("seed_kind"),
        "min_recurrence": seed.get("min_recurrence"),
        "tokens": seed.get("tokens", []),
        "target_lang": "solidity",
        "verification_tier_self_label": seed.get("verification_tier", TIER),
        "known_corpus_anchor": "external-findings-miner:" + family,
    }
    det_record = {
        "schema_version": "auditooor.detector_seed.v1",
        "record_id": seed_id,
        "task_id": seed_id,
        "task_type": "external_findings_detector_seed",
        "status": "ok",
        "result": json.dumps(det_payload),
        "source": {"batch_id": batch_id, "miner": "external-findings-miner",
                   "family": family},
        "verification_tier": seed.get("verification_tier", TIER),
        "ingested_at_utc": utcnow(),
    }
    det_path = det_dir / ("seed-" + seed_id + ".json")
    det_path.write_text(
        json.dumps(det_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    written.append(det_path)
    return written


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--family", required=True, help="bug-class family keyword")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--findings-json", help="JSON file of findings ('-' for stdin)")
    src.add_argument("--findings-md", help="Solodit-MCP markdown dump ('-' for stdin)")
    ap.add_argument("--out-dir", help="output dir for the bundle")
    ap.add_argument(
        "--to-derived", nargs="?", const="audit/corpus_tags/derived",
        default=None, metavar="DERIVED_ROOT",
        help="instead of (or in addition to) --out-dir, emit the invariant + "
             "detector seed into the canonical derived/<router>/<batch>/ dirs "
             "(invariant_library_extended + detector_synthesis_v2) that "
             "promote-mined-to-canonical already scans. Optional value = "
             "derived root (default audit/corpus_tags/derived).")
    ap.add_argument("--min-recurrence", type=int, default=2,
                    help="min distinct-finding recurrence for a seed token (default 2)")
    ap.add_argument("--dry-run", action="store_true", help="compute, write nothing")
    ap.add_argument("--json-only", action="store_true", help="print full bundle JSON to stdout")
    args = ap.parse_args(argv)

    def _read(spec: str) -> Optional[str]:
        if spec == "-":
            return sys.stdin.read()
        p = Path(spec)
        if not p.is_file():
            print(json.dumps({"error": "input-not-found", "path": spec}))
            return None
        return p.read_text()

    try:
        if args.findings_json is not None:
            text = _read(args.findings_json)
            if text is None:
                return 3
            findings = parse_findings_json(text)
        else:
            text = _read(args.findings_md)
            if text is None:
                return 3
            findings = parse_findings_md(text)
    except (json.JSONDecodeError, OSError) as e:
        print(json.dumps({"error": "input-parse-failed", "detail": str(e)}))
        return 3

    if not findings:
        print(json.dumps({
            "schema_version": SCHEMA_VERDICT,
            "family": args.family,
            "finding_count": 0,
            "verdict": "no-usable-findings",
            "note": "no finding carried a source URL / parseable block (tier-2 honesty: nothing emitted)",
        }))
        return 2

    bundle = mine(args.family, findings, args.min_recurrence)
    written: List[Path] = []
    derived_written: List[Path] = []
    if args.out_dir and not args.dry_run:
        written = write_outputs(bundle, Path(args.out_dir))
    if args.to_derived is not None and not args.dry_run:
        derived_written = write_to_derived(bundle, Path(args.to_derived))

    summary = {
        "schema_version": SCHEMA_VERDICT,
        "family": bundle["family"],
        "finding_count": bundle["finding_count"],
        "invariant_id": bundle["generalized_invariant"]["invariant_id"],
        "seed_id": bundle["detector_seed"]["seed_id"],
        "seed_token_count": bundle["detector_seed"]["token_count"],
        "backtest": bundle["backtest"],
        "files_written": [str(p) for p in written],
        "derived_files_written": [str(p) for p in derived_written],
        "dry_run": args.dry_run,
    }
    if args.json_only:
        print(json.dumps(bundle, indent=2, sort_keys=True))
    else:
        print(json.dumps(summary, indent=2, sort_keys=True))
        bt = bundle["backtest"]
        if bt["verdict"] in ("miss", "no-seed-no-recall", "weak-recall"):
            print(
                "BACKTEST %s: recall=%.2f matched=%d/%d missed_ids=%s"
                % (bt["verdict"].upper(), bt["recall"], bt["matched"],
                   bt["total_findings"], bt.get("missed_finding_ids", [])[:10]),
                file=sys.stderr,
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
