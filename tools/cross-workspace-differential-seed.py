#!/usr/bin/env python3
# r36-rebuttal: PR7b lane cross-workspace-differential-seed; orchestrator commits
"""
cross-workspace-differential-seed.py - Differential proof-queue seeding from
the K most-similar prior audits.

WHAT IT DOES (the ADD-A gap):
  At audit start (or as a hunt-fuel refresh) this tool:
    1. Derives the TARGET workspace's primary language + protocol families.
    2. Scans every SIBLING workspace under ~/audits/* (their SUBMISSIONS.md,
       findings/, submissions/staging|paste_ready notes, and
       invariant_hunt/) PLUS the in-repo trusted corpus
       (audit/corpus_tags/derived/*.jsonl) and scores each by
       language + protocol-family overlap with the target.
    3. Auto-selects the K most-similar prior audits/advisories.
    4. Maps each prior finding / invariant to the target's ANALOGOUS
       function (file:line) by bug-class keyword -> function-name affinity.
    5. Emits a DIFFERENTIAL HYPOTHESIS per (prior finding -> target function)
       pair: "prior workspace had <bug class> in <prior fn>; the analogous
       target fn <target fn @ file:line> may have the same gap - prove or
       falsify". The hypotheses are written into the proof queue so the
       prove/falsify lanes pick them up.

ANCHOR (calibration fixture): ~/audits/morpho (Morpho Blue R89/R90/R91 +
I2.A oracle SCALE_FACTOR=0, I2.B preLiquidate atomic reentrancy) ->
~/audits/morpho-midnight. Both are language=solidity, family=morpho-blue, so
morpho is auto-selected as the top sibling and its oracle/reentrancy/fee/IRM
findings map onto Midnight's price/liquidate/take/fee functions.

OUTPUTS (under <target-ws>/.auditooor/):
  - differential_seed_queue.json   the differential hypotheses (schema v1)
  - differential_seed_queue.md     brief-injectable markdown block
  - proof_obligation_queue.json    MERGED (additive) so prove lanes see them.
    Existing rows are preserved; differential rows are appended with a
    "source": "cross-workspace-differential-seed" tag and de-duplicated by
    obligation_id. The original file (if any) is backed up to
    proof_obligation_queue.json.pre-diffseed.bak ONLY when --merge-proof-queue
    is passed (default OFF so we never silently mutate a hand-curated queue).

RELATED TOOLS (tool-duplication preflight, CLAUDE.md operational anchor):
  - tools/cross-workspace-seed.py            : INTAKE seed. Derives family/
        language and pulls SAME-family learnings from the VAULT corpus into
        <ws>/.auditooor/cross_workspace_seed.json. It does NOT scan sibling
        ~/audits/* workspaces' findings/invariants, does NOT map prior
        findings to the target's analogous functions, and does NOT emit
        differential hypotheses into the proof queue. This tool is the
        DIFFERENTIAL-seed step (sibling-workspace-to-target function mapping
        + proof-queue emit); cross-workspace-seed is the corpus-pull step.
  - tools/cross-workspace-finding-linker.py  : post-hoc finding-to-finding
        GRAPH across already-filed findings. Not an intake/hunt-fuel step;
        does not target a fresh workspace's functions.
  - tools/cross-ws-pattern-mapper.py / cross-workspace-state-aggregator.py /
    cross-workspace-duplicate-check.py        : coverage matrix / dashboard /
        dedup gate. None map prior findings to a target's analogous
        functions and emit proof-queue hypotheses.
  - tools/adversarial-hypothesis-differential-hunter.py : per-function
        adversarial hypotheses derived from the TARGET source ALONE (no
        prior-audit transfer). This tool is the cross-workspace transfer
        complement: it seeds hypotheses FROM sibling prior audits.
  GAP THIS TOOL FILLS: select-K-similar-priors + map-prior-finding-to-target-
        function + emit-differential-hypotheses-into-the-proof-queue. No
        existing tool does this end-to-end.

Usage:
    cross-workspace-differential-seed.py --workspace <ws> [--k N]
        [--audits-dir ~/audits] [--merge-proof-queue] [--json] [--quiet]

Exit codes:
    0  seed written (degraded sibling/source reads are recorded, not fatal)
    2  usage error (missing/invalid workspace)
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "auditooor.cross_workspace_differential_seed.v1"

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_AUDITS_DIR = Path(os.path.expanduser("~/audits"))
DEFAULT_K = 3
MAX_HYPOTHESES = 60
MAX_SOURCE_FILES = 4000

# ---------------------------------------------------------------------------
# Language / family derivation (kept self-contained so this tool has no hard
# import dependency on cross-workspace-seed.py; the maps are deliberately the
# same vocabulary so the two tools agree on family/language tokens).
# ---------------------------------------------------------------------------
EXT_TO_LANGUAGE: Dict[str, str] = {
    ".sol": "solidity",
    ".go": "go",
    ".rs": "rust",
    ".move": "move",
    ".cairo": "cairo",
    ".vy": "vyper",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".js": "javascript",
    ".py": "python",
    ".circom": "circom",
    ".nr": "noir",
}

SECURITY_LANGUAGES = frozenset(
    {"solidity", "go", "rust", "move", "cairo", "vyper", "circom", "noir"}
)

FAMILY_SIGNALS: List[Tuple[str, str]] = [
    ("morpho", "morpho-blue"),
    ("midnight", "morpho-blue"),
    ("aave", "aave"),
    ("compound", "compound"),
    ("euler", "euler"),
    ("uniswap", "uniswap"),
    ("curve", "curve"),
    ("balancer", "balancer"),
    ("erc4626", "erc4626-vault"),
    ("erc-4626", "erc4626-vault"),
    ("dydx", "dydx-perps"),
    ("cosmos", "cosmos-sdk"),
    ("cometbft", "cosmos-sdk"),
    ("tendermint", "cosmos-sdk"),
    ("substrate", "substrate"),
    ("polkadot", "substrate"),
    ("parachain", "substrate"),
    ("hyperbridge", "cross-chain-bridge"),
    ("ismp", "cross-chain-bridge"),
    ("bridge", "cross-chain-bridge"),
    ("optimism", "l2-rollup"),
    ("arbitrum", "l2-rollup"),
    ("rollup", "l2-rollup"),
    ("spark", "bitcoin-statechain"),
    ("statechain", "bitcoin-statechain"),
    ("lightning", "bitcoin-lightning"),
    ("frost", "threshold-signing"),
    ("solana", "solana"),
    ("anchor", "solana"),
    ("aztec", "zk-rollup"),
    ("zk", "zk-rollup"),
    ("circom", "zk-circuit"),
    # Bitcoin / Zcash consensus-node family (zebra, zcashd, bitcoin core forks).
    ("zebra", "zcash-consensus-node"),
    ("zcash", "zcash-consensus-node"),
    ("zcashd", "zcash-consensus-node"),
    ("bitcoin", "bitcoin-consensus-node"),
    ("btcd", "bitcoin-consensus-node"),
    ("consensus", "consensus-node"),
    ("blockchain node", "consensus-node"),
    ("full node", "consensus-node"),
    ("p2p", "p2p-network"),
    ("peer-to-peer", "p2p-network"),
]

# Bug-class -> (signal keywords found in a prior finding/invariant title,
#               target-function-name affinity tokens).
# A prior finding whose text contains a class's signal keyword is mapped onto
# every target function whose name contains an affinity token for that class.
BUG_CLASS_AFFINITY: List[Tuple[str, Tuple[str, ...], Tuple[str, ...]]] = [
    (
        "oracle-price-zero-or-truncation",
        ("oracle", "scale_factor", "scalefactor", "price", "feed", "round",
         "stale", "chainlink", "truncat"),
        ("price", "oracle", "feed", "scale", "convert", "quote", "rate",
         "lossfactor", "tick"),
    ),
    (
        "reentrancy",
        ("reentr", "reenter", "nonreentrant", "callback", "flashloan",
         "flash loan", "atomic", "preliquidat"),
        ("liquidate", "preliquidate", "callback", "flashloan", "flash",
         "withdraw", "borrow", "repay", "supply", "take", "on", "multicall"),
    ),
    (
        "fee-accounting",
        ("fee", "premium", "lif", "rebate", "dust", "rounding", "round"),
        ("fee", "claim", "premium", "settlement", "continuous", "accrue",
         "touchmarket"),
    ),
    (
        "interest-rate-model",
        ("irm", "interest", "rate", "accrue", "borrowrate", "utilization"),
        ("accrue", "rate", "interest", "borrow", "touchmarket", "lossfactor"),
    ),
    (
        "authorization-signature",
        ("authoriz", "signature", "sig", "permit", "ecrecover", "setter",
         "ratifier", "role", "owner"),
        ("setrole", "setfee", "setisauthorized", "setconsumed", "authorize",
         "permit", "setter", "setmarket", "setdefault", "settickspacing"),
    ),
    (
        "bad-debt-socialization",
        ("bad debt", "baddebt", "socializ", "insolven", "loss factor",
         "lossfactor", "default"),
        ("liquidate", "lossfactor", "totalunits", "credit", "debt",
         "updateposition", "take"),
    ),
    (
        "accounting-units-conversion",
        ("units", "shares", "conversion", "vaultconversion", "totalunits",
         "rounding", "precision"),
        ("totalunits", "credit", "debt", "convert", "toid", "tomarket",
         "updateposition", "collateral"),
    ),
    # --- Bitcoin / Zcash consensus-node bug classes (zebra GHSA corpus) ------
    (
        "attacker-controlled-allocation-dos",
        ("allocation", "alloc", "with_capacity", "pre-read", "amplification",
         "cwe-770", "length-prefix", "memory amplification", "over-alloc",
         "external_count", "oom"),
        ("deserialize", "external_count", "read", "with_capacity",
         "allocation", "alloc", "count", "decode", "parse", "from_bytes"),
    ),
    (
        "non-canonical-encoding-divergence",
        ("non-canonical", "noncanonical", "canonical", "compactsize",
         "compact_size", "minimal", "non-minimal", "varint", "encoding",
         "malleab", "serialization"),
        ("compact_size", "compactsize", "deserialize", "serialize", "read",
         "write", "decode", "encode", "round_trip", "from_bytes", "to_bytes"),
    ),
    (
        "consensus-divergence-sigop-script",
        ("consensus-divergence", "consensus divergence", "sigop",
         "sigops", "p2sh", "zip-truncation", "undercount", "script",
         "disabled-opcode", "legacy_sigop"),
        ("sigop", "script", "legacy_sigop", "count", "verify",
         "transaction_sigop", "block_sigop", "is_p2sh", "interpret"),
    ),
    (
        "p2p-misbehavior-score-evasion",
        ("misbehavior", "misbehaviour", "score-evasion", "per-peer",
         "identity-keying", "ip-port", "peer", "ban", "dos",
         "block-suppression", "address-book"),
        ("misbehavior", "peer", "update", "ban", "score", "address",
         "addressbook", "by_ip", "key", "handle", "report"),
    ),
    (
        "incomplete-cleanup-state-residue",
        ("incomplete-cleanup", "incomplete revert", "state-residue",
         "residue", "on-disk-state-corruption", "state corruption",
         "incomplete-revert", "cleanup", "poptip", "multisubtree",
         "senthash"),
        ("revert", "cleanup", "clear", "remove", "delete", "rollback",
         "pop", "finalize", "commit", "prune", "reset", "rewind"),
    ),
    (
        "panic-unwrap-liveness",
        ("unwrap", "panic", "config-gated-panic", "option-unwrap",
         "mutex-poison", "poison", "expect", "shared-mutex",
         "cascade", "most-recent-by-ip"),
        ("unwrap", "expect", "lock", "most_recent", "by_ip", "get",
         "peer", "handle", "process", "update"),
    ),
    (
        "silent-error-drop-footgun",
        ("silent-error-drop", "silent drop", "result-intoiterator",
         "intoiterator", "footgun", "value-balance-bypass", "flatmap",
         "flat_map", "error drop", "ignored error"),
        ("value_balance", "verify", "check", "validate", "deserialize",
         "collect", "sum", "balance", "flat_map", "iter"),
    ),
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _now_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _resolve_workspace(raw: str) -> Optional[Path]:
    p = Path(os.path.expanduser(raw)).resolve()
    if p.is_dir():
        return p
    cand = (DEFAULT_AUDITS_DIR / raw).resolve()
    if cand.is_dir():
        return cand
    return None


def _read_text(path: Path, limit: int = 400_000) -> str:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            return fh.read(limit)
    except OSError:
        return ""


def _load_json(path: Path) -> Any:
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _read_targets_tsv(ws: Path) -> List[str]:
    out: List[str] = []
    f = ws / "targets.tsv"
    txt = _read_text(f)
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.extend(c.strip() for c in line.split("\t") if c.strip())
    return out


def _scan_extension_counts(ws: Path) -> Dict[str, int]:
    counts: Counter[str] = Counter()
    seen = 0
    skip = {".git", "node_modules", "lib", "out", "cache", "artifacts",
            "broadcast", "target", ".auditooor", "prior_audits"}
    for root, dirs, files in os.walk(ws):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext in EXT_TO_LANGUAGE:
                counts[ext] += 1
                seen += 1
                if seen >= MAX_SOURCE_FILES:
                    return dict(counts)
    return dict(counts)


def derive_language(ws: Path) -> Tuple[str, Dict[str, int]]:
    intake = _load_json(ws / "INTAKE_BASELINE.json") or {}
    ext_counts: Dict[str, int] = {}
    raw = intake.get("file_extension_counts")
    if isinstance(raw, dict):
        ext_counts = {str(k): int(v) for k, v in raw.items()
                      if isinstance(v, (int, float))}
    if not ext_counts:
        ext_counts = _scan_extension_counts(ws)
    lang_counts: Counter[str] = Counter()
    for ext, n in ext_counts.items():
        lang = EXT_TO_LANGUAGE.get(ext if ext.startswith(".") else "." + ext)
        if lang:
            lang_counts[lang] += int(n)
    if not lang_counts:
        return "", ext_counts
    # Prefer a security-relevant compiled/chain language when present.
    sec = {l: c for l, c in lang_counts.items() if l in SECURITY_LANGUAGES}
    pool = sec if sec else dict(lang_counts)
    primary = max(pool.items(), key=lambda kv: kv[1])[0]
    return primary, ext_counts


def derive_families(ws: Path) -> List[str]:
    repos = _read_targets_tsv(ws)
    intake = _load_json(ws / "INTAKE_BASELINE.json") or {}
    assets = intake.get("assets_in_scope") or []
    blob = " ".join([ws.name] + repos + [str(a) for a in assets]).lower()
    families: List[str] = []
    for needle, family in FAMILY_SIGNALS:
        if needle in blob and family not in families:
            families.append(family)
    return families


# ---------------------------------------------------------------------------
# Sibling prior-finding / invariant extraction
# ---------------------------------------------------------------------------
_TITLE_RE = re.compile(r"^\s{0,3}#{1,4}\s+(.+?)\s*$")
_SLUG_FINDING_RE = re.compile(r"\b(#?[A-Z]\d+(?:\.[A-Z])?|R\d{2,3}[-A-Za-z0-9]*)\b")


def _classify_bug_classes(text: str) -> List[str]:
    low = text.lower()
    hits: List[str] = []
    for cls, signals, _aff in BUG_CLASS_AFFINITY:
        if any(sig in low for sig in signals):
            hits.append(cls)
    return hits


def extract_prior_findings(sib: Path) -> List[Dict[str, Any]]:
    """Return prior finding / invariant descriptors from a sibling workspace.

    Each descriptor: {kind, title, bug_classes, source}. Bounded and advisory.
    """
    out: List[Dict[str, Any]] = []
    seen_titles: set[str] = set()

    def _add(kind: str, title: str, source: str) -> None:
        title = title.strip()
        if not title or len(title) < 4:
            return
        key = (kind, title.lower())
        if key in seen_titles:
            return
        seen_titles.add(key)
        classes = _classify_bug_classes(title)
        if not classes:
            return
        out.append({"kind": kind, "title": title[:200],
                    "bug_classes": classes, "source": source})

    # 1. SUBMISSIONS.md headings + 6-point review section titles.
    subs = sib / "submissions" / "SUBMISSIONS.md"
    txt = _read_text(subs)
    for line in txt.splitlines():
        m = _TITLE_RE.match(line)
        if m:
            _add("submission", m.group(1), "submissions/SUBMISSIONS.md")

    # 2. submissions/staging|paste_ready notes & drafts (titles only).
    for status in ("paste_ready", "staging", "filed", "held", "superseded"):
        d = sib / "submissions" / status
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*.md"))[:120]:
            stem = f.stem
            if stem.lower() in ("readme", "submissions"):
                continue
            # Use the slug stem as a coarse title; also pull first H1.
            _add("draft", stem.replace("-", " ").replace("_", " "),
                 f"submissions/{status}/{f.name}")

    # 3. findings/<id>/ directories.
    fd = sib / "findings"
    if fd.is_dir():
        for child in sorted(fd.iterdir())[:80]:
            if child.is_dir():
                _add("finding", child.name.replace("-", " "),
                     f"findings/{child.name}")

    # 4. invariant_hunt/ - invariant filenames + auto-proposed specs.
    ih = sib / "invariant_hunt"
    if ih.is_dir():
        for f in sorted(ih.rglob("*.sol"))[:120]:
            base = f.stem.replace(".invariants", "").replace(".", " ")
            _add("invariant", base, f"invariant_hunt/{f.name}")
        for f in sorted(ih.rglob("*.md"))[:60]:
            _add("invariant", f.stem.replace("-", " ").replace("_", " "),
                 f"invariant_hunt/{f.name}")

    # 5. Tier-6 hunt-finding sidecars (.auditooor/hunt_findings_sidecars/*.json).
    #    These carry the richest prior-finding corpus for non-DeFi targets:
    #    published-GHSA Tier-6 mining (zebra: 25 published Zcash GHSAs), plus
    #    DROP/FP/HARDENED hunt verdicts. The attack_class + summary text drives
    #    bug-class classification (titles alone are too sparse for these).
    sidecar_dir = sib / ".auditooor" / "hunt_findings_sidecars"
    if sidecar_dir.is_dir():
        for f in sorted(sidecar_dir.glob("*.json"))[:200]:
            rec = _load_json(f)
            if not isinstance(rec, dict):
                continue
            attack_class = str(rec.get("attack_class") or "")
            summary = str(rec.get("summary") or rec.get("title") or "")
            title = (attack_class or rec.get("id") or f.stem)
            classify_text = f"{attack_class} {summary} {f.stem}"
            title = str(title).strip()
            if not title or len(title) < 4:
                continue
            key = ("sidecar", title.lower())
            if key in seen_titles:
                continue
            seen_titles.add(key)
            classes = _classify_bug_classes(classify_text)
            if not classes:
                continue
            out.append({
                "kind": "sidecar",
                "title": title[:200],
                "bug_classes": classes,
                "source": f".auditooor/hunt_findings_sidecars/{f.name}",
            })

    return out


# ---------------------------------------------------------------------------
# In-repo trusted-corpus ingestion (docstring step 2) and the TARGET's OWN
# prior submissions. Both are first-class differential-seed sources: the
# corpus carries same-family (e.g. cross-chain-bridge) prior advisories, and
# the target's own SUBMISSIONS.md / findings/ carry prior filings whose root
# causes may recur in not-yet-reviewed analogous functions.
# ---------------------------------------------------------------------------
# Map each derived protocol family to the corpus token(s) that select the
# family-relevant slice of audit/corpus_tags/derived/*.jsonl.
FAMILY_CORPUS_TOKENS: Dict[str, Tuple[str, ...]] = {
    "cross-chain-bridge": ("hyperbridge", "ismp", "bridge", "cross-chain",
                           "cross_chain", "relayer", "state machine",
                           "statemachine"),
    "morpho-blue": ("morpho", "midnight", "preliquidat", "oracle", "irm"),
    "l2-rollup": ("optimism", "arbitrum", "rollup", "l2oracle",
                  "output oracle", "sequencer"),
    "cosmos-sdk": ("cosmos", "cometbft", "tendermint", "ante", "keeper"),
    "substrate": ("substrate", "polkadot", "parachain", "pallet"),
    "zk-rollup": ("aztec", "zk", "proof", "circuit"),
    "bitcoin-statechain": ("spark", "statechain", "leaf", "coop-exit"),
}


def _corpus_record_text(rec: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in ("attack_class", "category", "title", "summary", "claim",
                "statement", "source_audit_ref", "record_id"):
        v = rec.get(key)
        if isinstance(v, str):
            parts.append(v)
    return " ".join(parts)


def extract_corpus_findings(
    repo_root: Path, target_families: List[str], max_records: int = 400
) -> List[Dict[str, Any]]:
    """Pull family-relevant prior advisories from the in-repo trusted corpus.

    Reads audit/corpus_tags/derived/*.jsonl (bounded), keeps records whose
    text matches a family corpus token AND classifies into a known bug class.
    Returns prior-finding descriptors in the same shape as
    extract_prior_findings so build_hypotheses consumes them uniformly.
    """
    derived = repo_root / "audit" / "corpus_tags" / "derived"
    if not derived.is_dir():
        return []
    tokens: set[str] = set()
    for fam in target_families:
        tokens.update(FAMILY_CORPUS_TOKENS.get(fam, ()))
    if not tokens:
        return []
    out: List[Dict[str, Any]] = []
    seen_titles: set[str] = set()
    kept = 0
    # Prefer the family-named advisory seed files; fall back to the broader
    # derived corpus only for the same family-token filter.
    files = sorted(derived.glob("*.jsonl"))
    for jf in files:
        if kept >= max_records:
            break
        try:
            with jf.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if kept >= max_records:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    text = _corpus_record_text(rec)
                    low = text.lower()
                    if not any(tok in low for tok in tokens):
                        continue
                    classes = _classify_bug_classes(text)
                    if not classes:
                        continue
                    title = (rec.get("title") or rec.get("attack_class")
                             or rec.get("record_id") or "corpus advisory")
                    title = str(title)[:200]
                    key = title.lower()
                    if key in seen_titles:
                        continue
                    seen_titles.add(key)
                    out.append({
                        "kind": "corpus",
                        "title": title,
                        "bug_classes": classes,
                        "source": f"audit/corpus_tags/derived/{jf.name}",
                    })
                    kept += 1
        except OSError:
            continue
    return out


def build_corpus_pseudo_sibling(
    repo_root: Path, target_families: List[str]
) -> Optional[Dict[str, Any]]:
    """Wrap the family-relevant corpus advisories as a pseudo-sibling so the
    existing build_hypotheses round-robin treats the corpus as one more
    finding source.
    """
    findings = extract_corpus_findings(repo_root, target_families)
    if not findings:
        return None
    return {
        "workspace": "in-repo-corpus",
        "path": str(repo_root / "audit" / "corpus_tags" / "derived"),
        "language": "",
        "families": list(target_families),
        "similarity_score": 0.0,
        "prior_finding_count": len(findings),
        "_findings": findings,
        "_is_corpus": True,
    }


def build_own_prior_pseudo_sibling(ws: Path) -> Optional[Dict[str, Any]]:
    """Wrap the TARGET workspace's OWN prior submissions/findings/invariants
    as a pseudo-sibling. select_siblings deliberately skips the target itself
    (it is the cross-workspace step); this restores the target's own prior
    filings as a differential-seed source so already-filed root causes are
    re-checked against not-yet-reviewed analogous functions.
    """
    findings = extract_prior_findings(ws)
    if not findings:
        return None
    return {
        "workspace": f"{ws.name} (own-prior)",
        "path": str(ws / "submissions"),
        "language": "",
        "families": [],
        "similarity_score": 0.0,
        "prior_finding_count": len(findings),
        "_findings": findings,
        "_is_own_prior": True,
    }


# ---------------------------------------------------------------------------
# Sibling selection (top-K by similarity)
# ---------------------------------------------------------------------------
def score_sibling(
    target_lang: str,
    target_families: List[str],
    sib_lang: str,
    sib_families: List[str],
) -> float:
    score = 0.0
    if target_lang and sib_lang and target_lang == sib_lang:
        score += 2.0
    fam_overlap = len(set(target_families) & set(sib_families))
    score += 3.0 * fam_overlap
    return score


def select_siblings(
    target_ws: Path,
    target_lang: str,
    target_families: List[str],
    audits_dir: Path,
    k: int,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    notes: List[str] = []
    candidates: List[Dict[str, Any]] = []
    if not audits_dir.is_dir():
        notes.append(f"audits-dir not found: {audits_dir}")
        return [], notes
    for child in sorted(audits_dir.iterdir()):
        if not child.is_dir():
            continue
        if child.resolve() == target_ws.resolve():
            continue
        if child.name.startswith(".") or child.name.startswith("_"):
            continue
        try:
            sib_lang, _ = derive_language(child)
            sib_families = derive_families(child)
        except OSError:
            continue
        sc = score_sibling(target_lang, target_families, sib_lang, sib_families)
        if sc <= 0:
            continue
        findings = extract_prior_findings(child)
        if not findings:
            continue
        candidates.append({
            "workspace": child.name,
            "path": str(child),
            "language": sib_lang,
            "families": sib_families,
            "similarity_score": round(sc, 2),
            "prior_finding_count": len(findings),
            "_findings": findings,
        })
    candidates.sort(
        key=lambda c: (c["similarity_score"], c["prior_finding_count"]),
        reverse=True,
    )
    selected = candidates[: max(0, k)]
    notes.append(
        f"{len(candidates)} similar siblings found; selected top "
        f"{len(selected)} (k={k})"
    )
    return selected, notes


# ---------------------------------------------------------------------------
# Target function index (file:line per function name)
# ---------------------------------------------------------------------------
_FN_RE = {
    "solidity": re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)"),
    "vyper": re.compile(r"\bdef\s+([A-Za-z_][A-Za-z0-9_]*)"),
    "rust": re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)"),
    "go": re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)"),
    "move": re.compile(r"\bfun\s+([A-Za-z_][A-Za-z0-9_]*)"),
    "cairo": re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)"),
}


def _is_real_source(path: Path) -> bool:
    p = str(path).replace(os.sep, "/")
    bad = ("/test/", "/tests/", "/out/", "/lib/", "/node_modules/",
           "/cache/", "/artifacts/", "/poc-tests/", "/certora/", "/helpers/",
           "/mocks/", "/script/", "/mock", "/Mock", ".t.sol", ".s.sol",
           # Workspace-local PoC / generated trees: a target function index
           # must span real in-scope source, not the workspace's own filed
           # PoC harnesses or generated protobuf/grpc stubs.
           "/poc/", "/submissions/", "/__generated__/", "/.generated/",
           ".generated.", "/fuzz_runs/", "/deep_counterexamples/")
    if any(b in p for b in bad):
        return False
    name = path.name.lower()
    if name.endswith(("test.sol", "mock.sol")):
        return False
    # Rust unit-test modules live as tests.rs / test.rs / *_tests.rs files
    # inside a src/ dir (not under a /tests/ path), so the path-token filter
    # above misses them. Exclude by basename so the function index spans
    # production code only.
    if name in ("tests.rs", "test.rs") or name.endswith(("_tests.rs",
                                                          "_test.rs")):
        return False
    return True


def build_target_function_index(
    ws: Path, language: str
) -> List[Dict[str, Any]]:
    fn_re = _FN_RE.get(language)
    if fn_re is None:
        return []
    ext = {v: k for k, v in EXT_TO_LANGUAGE.items() if v == language}
    target_ext = next((e for e, l in EXT_TO_LANGUAGE.items()
                       if l == language), None)
    if not target_ext:
        return []
    index: List[Dict[str, Any]] = []
    seen = 0
    skip = {".git", "node_modules", "lib", "out", "cache", "artifacts",
            "broadcast", "target", ".auditooor", "prior_audits",
            "submissions", "poc-tests", "poc", "fuzz_runs",
            "deep_counterexamples", "mining_rounds", "reports", "docs",
            "scanners", "cost_runs", "__generated__"}
    for root, dirs, files in os.walk(ws):
        dirs[:] = [d for d in dirs if d not in skip]
        for name in files:
            if not name.lower().endswith(target_ext):
                continue
            fpath = Path(root) / name
            if not _is_real_source(fpath):
                continue
            rel = os.path.relpath(fpath, ws)
            txt = _read_text(fpath)
            for lineno, line in enumerate(txt.splitlines(), start=1):
                m = fn_re.search(line)
                if m:
                    index.append({
                        "function": m.group(1),
                        "file": rel,
                        "line": lineno,
                    })
                    seen += 1
                    if seen >= 6000:
                        return index
    return index


# ---------------------------------------------------------------------------
# Differential hypothesis emit
# ---------------------------------------------------------------------------
def _affinity_for_class(cls: str) -> Tuple[str, ...]:
    for c, _sig, aff in BUG_CLASS_AFFINITY:
        if c == cls:
            return aff
    return ()


def _hyp_id(target_fn: Dict[str, Any], sib_ws: str, cls: str) -> str:
    raw = f"{sib_ws}|{cls}|{target_fn['file']}|{target_fn['function']}"
    return "DIFF-" + hashlib.sha1(raw.encode()).hexdigest()[:12]


# Production source-path tokens that mark a file as core protocol logic rather
# than RPC-method dispatch / generated stubs. A hypothesis landing in one of
# these crates is a higher-signal analogous-function match than one landing in
# the RPC method table. Tuned for Rust consensus nodes (zebra crate layout);
# the substrings are generic enough to help any multi-crate workspace.
_CORE_SOURCE_TOKENS: Tuple[str, ...] = (
    "serialize", "serialization", "deserialize", "compact_size", "script",
    "sigop", "consensus", "-chain/", "-state/", "-network/", "-script/",
    "transaction", "block", "merkle", "verif", "primitives", "parameters",
    "/protocol/", "/codec/", "/parse",
)
_LOW_SIGNAL_PATH_TOKENS: Tuple[str, ...] = (
    "/rpc/", "methods.rs", "/__generated__/", ".generated.", "/proto/",
)


def _bucket_relevance(hyp: Dict[str, Any], aff: Tuple[str, ...]) -> int:
    """Rank a candidate hypothesis within its (sibling, bug-class) bucket.

    Higher = more relevant. Combines (a) function-name affinity strength
    (exact token equality > token is a whole word in the name > substring)
    and (b) source-path priority (core protocol crate > RPC dispatch >
    generated stub). Used only for ordering; never drops candidates.
    """
    fname = hyp["target_function"].lower()
    fpath = hyp["target_file_line"].lower()
    score = 0
    # (a) affinity-token strength.
    for tok in aff:
        if fname == tok:
            score += 6
        elif tok in fname.split("_"):
            score += 4
        elif tok in fname:
            score += 1
    # (b) source-path priority.
    if any(t in fpath for t in _CORE_SOURCE_TOKENS):
        score += 5
    if any(t in fpath for t in _LOW_SIGNAL_PATH_TOKENS):
        score -= 4
    return score


def build_hypotheses(
    selected: List[Dict[str, Any]],
    fn_index: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    seen_ids: set[str] = set()
    # Group candidate hypotheses by (sibling, bug_class) so the MAX_HYPOTHESES
    # budget is fairly distributed across bug classes via round-robin instead
    # of being exhausted by whichever class is enumerated first.
    groups: "Dict[Tuple[str, str], List[Dict[str, Any]]]" = {}
    for sib in selected:
        # Keep the highest-signal prior finding per (sibling, class) so the
        # hypothesis text cites a representative prior rather than every dupe.
        rep_by_class: Dict[str, Dict[str, Any]] = {}
        for pf in sib["_findings"]:
            for cls in pf["bug_classes"]:
                rep_by_class.setdefault(cls, pf)
        for cls, pf in rep_by_class.items():
            aff = _affinity_for_class(cls)
            if not aff:
                continue
            bucket: List[Dict[str, Any]] = []
            for fn in fn_index:
                fname = fn["function"].lower()
                if not any(tok in fname for tok in aff):
                    continue
                hid = _hyp_id(fn, sib["workspace"], cls)
                if hid in seen_ids:
                    continue
                seen_ids.add(hid)
                bucket.append({
                    "hypothesis_id": hid,
                    "bug_class": cls,
                    "prior_workspace": sib["workspace"],
                    "prior_finding": pf["title"],
                    "prior_finding_kind": pf["kind"],
                    "prior_source": pf["source"],
                    "target_function": fn["function"],
                    "target_file_line": f"{fn['file']}:{fn['line']}",
                    "differential_hypothesis": (
                        f"{sib['workspace']} had a {cls} issue "
                        f"({pf['title']}); the analogous target function "
                        f"{fn['function']} at {fn['file']}:{fn['line']} "
                        f"may share the same gap - prove or falsify."
                    ),
                    "verdict": "unproven",
                })
            if bucket:
                # Relevance-rank within the bucket so the highest-signal
                # analogous functions (exact affinity-token match in a
                # production consensus-source crate) surface ahead of generic
                # RPC dispatch getters that match the same affinity token only
                # incidentally (e.g. get_block_count vs zcash_deserialize_
                # external_count for the allocation-DoS class). Without this,
                # fn_index alphabetical order let dense RPC-method files win
                # the round-robin slots.
                bucket.sort(key=lambda h: _bucket_relevance(h, aff),
                            reverse=True)
                groups[(sib["workspace"], cls)] = bucket
    # Round-robin draw one hypothesis from each group per pass until the cap
    # is hit or every group is drained.
    hyps: List[Dict[str, Any]] = []
    order = list(groups.keys())
    idx = {k: 0 for k in order}
    while order and len(hyps) < MAX_HYPOTHESES:
        progressed = False
        for k in list(order):
            bucket = groups[k]
            if idx[k] < len(bucket):
                hyps.append(bucket[idx[k]])
                idx[k] += 1
                progressed = True
                if len(hyps) >= MAX_HYPOTHESES:
                    break
        if not progressed:
            break
    return hyps


def _to_proof_obligation_rows(
    hyps: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for h in hyps:
        rows.append({
            "obligation_id": h["hypothesis_id"],
            "source": "cross-workspace-differential-seed",
            "bug_class": h["bug_class"],
            "claim": h["differential_hypothesis"],
            "file_hint": h["target_file_line"],
            "target_function": h["target_function"],
            "prior_workspace": h["prior_workspace"],
            "prior_finding": h["prior_finding"],
            "proof_status": "needs_source",
            "verdict": "unproven",
        })
    return rows


def _diff_row_to_task(row: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a differential-seed obligation row into the corpus-driven
    `tasks`-schema shape so it can be appended to a queue that uses `tasks`
    (keyed by task_id) without losing the differential metadata.
    """
    return {
        "task_id": row["obligation_id"],
        "source": row.get("source", "cross-workspace-differential-seed"),
        "source_ref": row.get("prior_workspace", ""),
        "source_question": row.get("claim", ""),
        "proof_needed": row.get("file_hint", ""),
        "bug_class": row.get("bug_class", ""),
        "target_function": row.get("target_function", ""),
        "blocker": None,
        "verdict": row.get("verdict", "unproven"),
    }


def merge_proof_queue(ws: Path, rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    pq = ws / ".auditooor" / "proof_obligation_queue.json"
    existing: Any = _load_json(pq)
    # The queue can take three shapes, in priority order:
    #   1. a {"tasks": [...]} object (corpus-driven proof-queue schema; rows
    #      keyed by task_id) - PRESERVE the full object, append into tasks;
    #   2. a {"rows": [...]} object - append into rows;
    #   3. a bare list of obligation rows.
    # Anything else (or missing) starts a fresh bare list. This is critical:
    # treating a {"tasks": [...]} queue as "unrecognized -> empty" silently
    # destroyed an 86-task hand-curated queue once; never again.
    container = "list"
    list_key: Optional[str] = None
    if isinstance(existing, dict) and isinstance(existing.get("tasks"), list):
        container = "tasks"
        list_key = "tasks"
        existing_rows: List[Any] = existing["tasks"]
    elif isinstance(existing, dict) and isinstance(existing.get("rows"), list):
        container = "rows"
        list_key = "rows"
        existing_rows = existing["rows"]
    elif isinstance(existing, list):
        existing_rows = existing
    else:
        existing_rows = []

    id_field = "task_id" if container == "tasks" else "obligation_id"
    existing_ids = {
        str(r.get(id_field))
        for r in existing_rows
        if isinstance(r, dict) and r.get(id_field)
    }
    # Render the new rows in the container's native shape.
    if container == "tasks":
        candidate_rows = [_diff_row_to_task(r) for r in rows]
    else:
        candidate_rows = list(rows)
    appended = [r for r in candidate_rows
                if str(r[id_field]) not in existing_ids]

    if appended and pq.exists():
        bak = pq.with_suffix(".json.pre-diffseed.bak")
        try:
            bak.write_text(pq.read_text(encoding="utf-8"), encoding="utf-8")
        except OSError:
            pass
    merged_rows = existing_rows + appended
    pq.parent.mkdir(parents=True, exist_ok=True)
    if list_key is not None:
        existing[list_key] = merged_rows
        out_obj = existing
    else:
        out_obj = merged_rows
    pq.write_text(json.dumps(out_obj, indent=2) + "\n", encoding="utf-8")
    return {"appended": len(appended), "total": len(merged_rows),
            "queue_path": str(pq), "container": container}


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------
def render_md(payload: Dict[str, Any]) -> str:
    lines: List[str] = []
    lines.append("# Cross-Workspace Differential Seed")
    lines.append("")
    lines.append(f"- Generated: {payload['generated_at']}")
    lines.append(f"- Target workspace: `{payload['target_workspace']}`")
    lines.append(f"- Target language: `{payload['target_language'] or 'n/a'}`")
    lines.append(
        f"- Target families: {', '.join(payload['target_families']) or 'n/a'}"
    )
    lines.append(f"- Siblings selected (k={payload['k']}): "
                 + (", ".join(s["workspace"] for s in payload["selected_siblings"])
                    or "none"))
    lines.append(f"- Differential hypotheses: {len(payload['hypotheses'])}")
    lines.append("")
    if payload["selected_siblings"]:
        lines.append("## Selected prior audits")
        lines.append("")
        lines.append("| Sibling | Lang | Families | Score | Prior findings |")
        lines.append("|---|---|---|---|---|")
        for s in payload["selected_siblings"]:
            lines.append(
                f"| {s['workspace']} | {s['language'] or '-'} | "
                f"{', '.join(s['families']) or '-'} | "
                f"{s['similarity_score']} | {s['prior_finding_count']} |"
            )
        lines.append("")
    if payload["hypotheses"]:
        lines.append("## Differential hypotheses (proof-queue seeded)")
        lines.append("")
        lines.append("| ID | Bug class | Target fn @ file:line | From prior |")
        lines.append("|---|---|---|---|")
        for h in payload["hypotheses"]:
            lines.append(
                f"| {h['hypothesis_id']} | {h['bug_class']} | "
                f"`{h['target_function']}` @ {h['target_file_line']} | "
                f"{h['prior_workspace']}: {h['prior_finding'][:60]} |"
            )
        lines.append("")
    else:
        lines.append("_No differential hypotheses emitted "
                     "(no analogous functions matched the prior findings)._")
        lines.append("")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def build_payload(
    ws: Path, audits_dir: Path, k: int
) -> Dict[str, Any]:
    notes: List[str] = []
    language, ext_counts = derive_language(ws)
    families = derive_families(ws)
    selected, sel_notes = select_siblings(
        ws, language, families, audits_dir, k
    )
    notes.extend(sel_notes)

    # Two additional first-class differential-seed sources (docstring step 2 +
    # the target's own prior filings). They are prepended so build_hypotheses'
    # round-robin draws from them alongside the cross-workspace siblings.
    seed_sources: List[Dict[str, Any]] = []
    own_prior = build_own_prior_pseudo_sibling(ws)
    if own_prior is not None:
        seed_sources.append(own_prior)
        notes.append(
            f"own-prior submissions source: {own_prior['prior_finding_count']} "
            "prior finding(s)"
        )
    else:
        notes.append("own-prior submissions source: none")
    corpus = build_corpus_pseudo_sibling(REPO_ROOT, families)
    if corpus is not None:
        seed_sources.append(corpus)
        notes.append(
            f"in-repo corpus source: {corpus['prior_finding_count']} "
            f"family-relevant advisory record(s) (families={','.join(families) or 'n/a'})"
        )
    else:
        notes.append("in-repo corpus source: none")

    # Cross-workspace siblings stay first so selected_siblings[0] remains the
    # top-ranked similarity match; the corpus + own-prior pseudo-sources are
    # appended (round-robin in build_hypotheses is order-independent for the
    # MAX_HYPOTHESES fairness budget).
    all_sources = selected + seed_sources
    fn_index = build_target_function_index(ws, language)
    notes.append(f"target function index: {len(fn_index)} functions")
    hyps = build_hypotheses(all_sources, fn_index)
    notes.append(f"differential hypotheses: {len(hyps)}")
    # Strip the heavy _findings list from the persisted siblings. The corpus
    # and own-prior pseudo-sources are included so the report shows every
    # differential-seed source that contributed hypotheses.
    sib_public = [
        {kk: vv for kk, vv in s.items() if not kk.startswith("_")}
        for s in all_sources
    ]
    return {
        "schema": SCHEMA,
        "generated_at": _now_utc(),
        "target_workspace": ws.name,
        "target_workspace_path": str(ws),
        "target_language": language,
        "target_families": families,
        "k": k,
        "audits_dir": str(audits_dir),
        "selected_siblings": sib_public,
        "hypotheses": hyps,
        "notes": notes,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--k", type=int, default=DEFAULT_K)
    parser.add_argument("--audits-dir", default=str(DEFAULT_AUDITS_DIR))
    parser.add_argument(
        "--merge-proof-queue", action="store_true",
        help="Append differential rows into "
             ".auditooor/proof_obligation_queue.json (backs up first).",
    )
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    ws = _resolve_workspace(args.workspace)
    if ws is None:
        print(f"error: workspace not found: {args.workspace}", file=sys.stderr)
        return 2
    audits_dir = Path(os.path.expanduser(args.audits_dir)).resolve()

    payload = build_payload(ws, audits_dir, max(0, args.k))

    out_dir = ws / ".auditooor"
    out_dir.mkdir(parents=True, exist_ok=True)
    seed_json = out_dir / "differential_seed_queue.json"
    seed_md = out_dir / "differential_seed_queue.md"
    seed_json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    seed_md.write_text(render_md(payload), encoding="utf-8")
    payload["seed_json_path"] = str(seed_json)
    payload["seed_md_path"] = str(seed_md)

    if args.merge_proof_queue:
        rows = _to_proof_obligation_rows(payload["hypotheses"])
        payload["proof_queue_merge"] = merge_proof_queue(ws, rows)

    if args.json:
        print(json.dumps(payload, indent=2))
    elif not args.quiet:
        print(f"differential-seed: target={ws.name} "
              f"lang={payload['target_language'] or 'n/a'} "
              f"families={','.join(payload['target_families']) or 'n/a'}")
        print(f"  selected siblings (k={payload['k']}): "
              + (", ".join(s["workspace"]
                           for s in payload["selected_siblings"]) or "none"))
        print(f"  differential hypotheses: {len(payload['hypotheses'])}")
        print(f"  -> {seed_json}")
        print(f"  -> {seed_md}")
        if "proof_queue_merge" in payload:
            m = payload["proof_queue_merge"]
            print(f"  proof-queue: +{m['appended']} (total {m['total']}) "
                  f"-> {m['queue_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
