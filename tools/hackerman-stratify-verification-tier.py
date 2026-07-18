#!/usr/bin/env python3
"""hackerman-stratify-verification-tier.

Scans Hackerman corpus YAML records under `audit/corpus_tags/tags/` and emits a
JSONL candidate file mapping each `record_id` to one of five `verification_tier`
levels:

  - tier-1-verified-realtime-api      record sourced from live API fetch (NVD,
                                       GHSA, Solodit live, Immunefi, GitHub
                                       advisories, or real git-mining SHAs).
  - tier-1-officially-disclosed       advisory from an official disclosure
                                       channel (NVD/GHSA/vendor security
                                       advisory) manually verified at
                                       miner-build time. Anchor: Wave-2 PR-B
                                       Vyper-CVE real-source rebuilder
                                       (commit a428d287c4, 2026-05-16) where a
                                       single CVE/GHSA pair is hard-coded
                                       after manual NVD+GHSA inspection. The
                                       classifier never assigns this tier
                                       automatically; emitters set it
                                       explicitly via record_tier or shape_tag
                                       and the stratifier returns
                                       passthrough.
  - tier-2-verified-public-archive    record cites a public audit report
                                       (auditor digest, solodit numeric finding
                                       id, public-corpus findings-go reference,
                                       contest-platform finding, or audit-firm
                                       published report). Contest platforms:
                                       code4rena, sherlock, cantina, hats,
                                       immunefi. Audit firms: spearbit, cyfrin,
                                       pashov, chainsecurity, trailofbits,
                                       zellic, openzeppelin (plus the
                                       `audit-firm:<firm>-...` umbrella prefix).
  - tier-3-synthetic-taxonomy-anchored taxonomy fan-out structured on a real
                                       attack class / protocol name, but the
                                       specific incident details are templated.
  - tier-4-bundled-fixture            record from a miner's bundled fixture
                                       (auto-fork patterns, dsl-synthetic,
                                       unknown/dsl-synthetic target_repo).
  - tier-5-quarantine                 known fabricated set (Wave 3b Vyper-CVE
                                       fabrications, _QUARANTINE_FABRICATED_*
                                       paths).

The classifier is heuristic and additive: it never modifies records. It writes
candidates to `.auditooor/verification-tier-candidates.jsonl` (one JSON object
per line: {record_id, file, verification_tier, reason}).

Run a `--dry-run` first to print the per-tier distribution and a sample. Then
run again without flags (or with `--write`) to persist the JSONL.

Usage:

    python3 tools/hackerman-stratify-verification-tier.py --dry-run
    python3 tools/hackerman-stratify-verification-tier.py --write
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

REPO_ROOT_GUESS = Path(__file__).resolve().parent.parent
DEFAULT_TAGS_DIR = REPO_ROOT_GUESS / "audit" / "corpus_tags" / "tags"
DEFAULT_OUTPUT = REPO_ROOT_GUESS / ".auditooor" / "verification-tier-candidates.jsonl"

VERIFICATION_TIERS = (
    "tier-1-verified-realtime-api",
    "tier-1-officially-disclosed",
    "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
    "tier-5-quarantine",
)

# Wave-3b fabricated-CVE Vyper set (documented quarantine cohort). New entries
# can be added here as additional fabrications surface.
WAVE_3B_QUARANTINE_RECORD_SUBSTRINGS = (
    "vyper-reentrancy-lock-slot-drift",
)

# Wave-3b quarantine path markers (look for these in source_audit_ref or
# record_id; treat any record citing such a path as tier-5).
QUARANTINE_PATH_MARKERS = (
    "_QUARANTINE_FABRICATED_CVE",
    "_QUARANTINE_FABRICATED",
    "quarantine_fabricated",
)

# tier-1 source_audit_ref / record_id prefix substrings. Real-API or
# canonical-CVE-id-bearing records.
TIER1_SUBSTRINGS = (
    "api.github.com",
    "nvd.nist.gov",
    "cve.mitre.org",
    "ghsa-",          # GitHub Security Advisory
    "immunefi-public:",
    "immunefi-live:",
    "cantina-live:",
    "historic:",      # historic CVE_DB feed
    "critical:",      # operator-curated CRIT feed
    "cve_db:",
)
# Real git commit SHA reference (10+ hex chars after @ marker)
TIER1_GIT_SHA_RE = re.compile(r"^git-mining:[^@]+@[0-9a-f]{8,}")

# tier-2 public archive prefixes (real public audit reports indexed but not
# live-fetched at record-build time).
TIER2_PREFIXES = (
    "prior-audit:",       # auditor PDF digests (Monetrix, Mezo, Morpho ...)
    "findings-go:",        # public findings_go corpus
    # Contest platforms (verified-public-archive: published findings on a
    # contest-platform site, citing real github.com URLs in required_preconditions
    # / source_audit_ref). Wave-2 roadmap item W2.3.
    "code4rena:",
    "sherlock:",
    "cantina:",
    "hats:",
    "immunefi:",
    # Audit firms (verified-public-archive: published audit reports on the
    # firm's website, often archived in dedicated GitHub repos). The
    # `audit-firm:` umbrella prefix below covers firm-namespaced records;
    # these bare-prefix entries cover legacy / move_aptos_sui / starknet-cairo
    # records emitted with the firm name as the top-level prefix.
    "spearbit:",
    "cyfrin:",
    "pashov:",
    "chainsecurity:",
    "trailofbits:",
    "zellic:",
    "openzeppelin:",
    # Umbrella prefix used by the audit-firm public-reports ETL. The
    # sub-prefix (e.g. `audit-firm:trailofbits-publications:...`) names the
    # firm; all current sub-prefixes (chainsecurity-audits, cyfrin-audit-reports,
    # openzeppelin-contracts-audits, pashov-audits, sherlock-reports,
    # spearbit-portfolio, trailofbits-publications, zellic-publications) are
    # public-archive sources.
    "audit-firm:",
    # Canonical Solidity team bug taxonomy (`docs/bugs.json` in
    # ethereum/solidity), one record per SOL-YYYY-N entry. Each record cites
    # the verbatim `docs/bugs.json` anchor (real github.com URL) and a real
    # `https://blog.soliditylang.org/<year>/<month>/<day>/<bug>/` writeup
    # under fix_pattern / attacker_action_sequence. The Solidity team's own
    # bugs.json is the authoritative public archive of solc bug disclosures
    # (structurally equivalent to `findings-go:` / `audit-firm:` archives).
    "solc-bugs-json:",
    # W2.3-residual additions (Wave-2, PR #728). Each prefix is classified
    # "deeper-attribution-possible" by tools/hackerman-tier3-deep-attribution-
    # analyzer.py because every sampled record cites a real-world URL,
    # public audit report, post-mortem, or canonical CVE / bug-tracker entry
    # in `source_audit_ref` / `required_preconditions`. They are structurally
    # equivalent to the existing tier-2 archives (`findings-go:`, `audit-firm:`,
    # `solc-bugs-json:`) and were missed by Wave-1's prefix-table extension.
    #
    # Audit-firm reports targeting ZK circuits (asymmetric-research, trail-of-
    # bits, veridise, zellic). source_audit_ref cites the firm + protocol +
    # finding slug; mining state references real public PDFs / github URLs.
    "zk-auditor:",
    # Cantina / code4rena ZK-targeted contests (linea, aleo, taiko, aztec).
    # source_audit_ref cites the contest platform + protocol + finding id.
    "zk-contest:",
    # zksecurity/zkbugs dataset - every record cites a real github URL under
    # `0xPolygonHermez/`, `taikoxyz/`, `0xbok/circom-bigint/`, etc.
    "zkbugs:",
    # zksecurity/zkbugs catalog - circuit-aliased-witness taxonomy with real
    # protocol anchors (aztec-note-merge, light-compressed-leaf, maci-vote-merge).
    "zkbugs-catalog:",
    # 0xPARC zk-bug-tracker (https://github.com/0xPARC/zk-bug-tracker) - every
    # record is keyed by the public-tracker entry (aleo-1, aztec-1, pse-zkevm-2).
    "zkbugtracker:",
    # L2 zkrollup incident references - consensys-diligence-linea, aztec-internal,
    # etc. Each cites the named protocol incident + finding sub-slug; mining
    # state pin points to a real github audit-report URL.
    "l2-zkrollup:",
    # MEV write-ups from canonical sources (flashbots, blocknative, eigenphi).
    # source_audit_ref points to real https://writings.flashbots.net / blocknative
    # blog URLs. Verified sample: flashbots-sitemap-order-flow-auctions-and-
    # centralisation-ii cites https://writings.flashbots.net/...
    "mev-exploits:",
    # Flash-loan canonical attack classes (aave-v2 donation, uniswap-v2 PGA).
    # Each pre-fix / post-fix slice anchors against the real protocol + named
    # attack class; corpus mining maps to real github URLs.
    "mev-flashloan:",
    # Bridge-incident post-mortems (Ronin, Wormhole, Harmony, Multichain,
    # Qubit, Heco, Orbit, Li-Fi, Chainswap, Anyswap). source_audit_ref cites
    # real https://rekt.news/<incident>-rekt URLs. Verified sample:
    # harmony-horizon-2022-06 cites https://rekt.news/harmony-rekt.
    "bridge-incident:",
    # Starknet/Cairo audit PDFs published by ChainSecurity, ConsenSys
    # Diligence, OpenZeppelin. source_audit_ref includes real
    # https://raw.githubusercontent.com/OpenZeppelin/cairo-contracts/.../*.pdf
    # URLs. Verified sample: argentlabs__argent-contracts-starknet__audit__
    # chainsecurity-argent-argent-account.
    "starknet-cairo-corpus:",
    # Movebit audit reports (Aptos / Sui ecosystem). source_audit_ref cites
    # real https://github.com/movebit/Sampled-Audit-Reports/blob/main/reports/
    # *.pdf URLs. Verified sample: MoveDID-Aptos-Contracts-Audit-Report.pdf.
    "movebit:",
    # Solana SVM canonical write-ups (Neodyme breakpoint workshop, Sec3
    # sealevel categories, ghsa-* solana_rbpf advisories). source_audit_ref
    # references real sealevel-attacks repo + ghsa advisory ids.
    "solana-svm:",
    # CVE-2023-39363 Vyper compiler bug family. Each record pre-/post-fix
    # slice anchors against the canonical CVE id and the named curve pool
    # contract address (e.g. 0x8301ae4fc9c624d1d396cbdaa1ed877821d7c511 =
    # crv-eth crypto pool). Real CVE + real on-chain contract = real-archive.
    "vyper-39363:",
    # CVE database entries - canonical NIST/MITRE CVE ids (cve-2018-10299,
    # cve-2018-10468, etc.). source_audit_ref is the verbatim CVE id which
    # resolves to https://cve.mitre.org / https://nvd.nist.gov pages.
    "cve-db:",
)
# tier-2 sub-pattern: solodit records with numeric finding id (the id is a
# real Solodit finding key fetched from the Solodit REST API). Two prefixes
# exist in the corpus:
#   - solodit-spec:NNNNN:  (older spec-shape records)
#   - solodit:NNNNN:       (wave3 REST-direct backfill records, e.g.
#                           solodit_cairo_backfill_20260520 / solodit_go_backfill_20260520)
# Both cite a real numeric Solodit finding id and are therefore tier-2.
SOLODIT_NUMERIC_RE = re.compile(r"^solodit(?:-spec)?:[^:]*?:?(\d+):")

# tier-3 fan-out signals: corpus-mined slice records, regex-derived taxonomy
# expansions over real call sites.
TIER3_PREFIXES = (
    "corpus-mined:",
    "corpus-txt:",
)

# --------------------------------------------------------------------------- #
# W2.5 deep-attribution backfill safety primitives
# (docs/WAVE2_W25_TIER3_BACKFILL_SPEC_2026-05-16.md §4.1)
# --------------------------------------------------------------------------- #
#
# The W2.5 prefix-table extension above (zk-auditor, mev-flashloan,
# mev-exploits, ...) promotes ~2,098 records (upper-band 100% confirm) from
# tier-3 to tier-2 via plain prefix match. Per spec §6.1, the safer design
# is a dual-gate: prefix match AND `source_audit_ref` matches an allow-listed
# host regex. The dual-gate is intentionally OPTIONAL at this stage (gated
# by `AUDITOOOR_W25_ENFORCE_URL_GATE=1`) because most W2.5 records currently
# hold structured non-URL tokens in `source_audit_ref` (e.g.
# "zk-auditor:asymmetric-research:polygon-zkevm-bridge:..."); they will be
# rewritten to http URLs by the W2.5 source_audit_ref migrator (spec §4.2;
# follow-up PR).
#
# Until the migrator lands, enforcing the URL gate would drop promotions
# from ~2,098 to ~320 - far below the canonical p=1,790 target (commit
# 04ec79ba74, docs/WAVE2_W25_P_ANCHOR_DECISION_2026-05-16.md). The constants
# below ship now so:
#   1. Future hardening can flip `AUDITOOOR_W25_ENFORCE_URL_GATE=1` once the
#      migrator populates URL `source_audit_ref` everywhere.
#   2. The W2.5 source_audit_ref migrator (`tools/hackerman-w25-source-audit-
#      ref-migrator.py`, follow-up PR) imports this regex as the canonical
#      allow-list of legal target URLs.
#   3. The acceptance harness can sample records on the URL-allow-listed
#      subset for the 200-record manual-review (spec §5).
W25_REAL_ARCHIVE_PREFIXES = (
    "zk-auditor:",
    "mev-flashloan:",
    "mev-exploits:",
    "zkbugs:",
    "zkbugs-catalog:",
    "zkbugtracker:",
    "l2-zkrollup:",
    "zk-contest:",
    "starknet-cairo-corpus:",
    "bridge-incident:",
    "solana-svm:",
    "movebit:",
    "vyper-39363:",
    "cve-db:",
)

# Allow-list of host patterns that count as a "real public archive" citation
# in `source_audit_ref`. Includes the canonical post-mortem aggregators,
# audit-firm sites, advisory / NVD feeds, and the
# `raw.githubusercontent.com` / `github.com/<auditor>/` PDF anchors used by
# the starknet-cairo / movebit / zellic miners.
W25_ALLOWED_SOURCE_HOST_RE = re.compile(
    r"^https?://("
    r"nvd\.nist\.gov|"
    r"github\.com/advisories/|"
    r"github\.com/0xPARC/zk-bug-tracker|"
    r"github\.com/Zellic/|"
    r"github\.com/movebit/|"
    r"raw\.githubusercontent\.com/|"
    r"rekt\.news/|"
    r"www\.asymmetric\.re/|"
    r"veridise\.com/|"
    r"eigenphi\.io/|"
    r"transparency\.flashbots\.net/|"
    r"www\.blocknative\.com/|"
    r"writings\.flashbots\.net/|"
    r"www\.movebit\.xyz/|"
    r"osec\.io/|"
    r"neodyme\.io/"
    r")",
    re.IGNORECASE,
)

# Opt-in flag that flips the W2.5 prefixes from plain-prefix tier-2 promotion
# to dual-gate (prefix AND allow-listed URL in source_audit_ref). Default
# OFF; flip to ON after the W2.5 source_audit_ref migrator (spec §4.2)
# populates URL `source_audit_ref` across the affected records.
W25_ENFORCE_URL_GATE = os.environ.get("AUDITOOOR_W25_ENFORCE_URL_GATE", "").strip() == "1"

# tier-4 bundled-fixture signals: dsl-synthetic patterns, solidity-fork-pattern
# fixtures, manual canonical-dsl seeds, plus the catch-all
# target_repo=unknown/dsl-synthetic + extraction_method=dsl-synthetic combo.
TIER4_PREFIXES = (
    "solidity-fork-pattern:",
    "dsl-pattern:",
    "dsl_pattern",
    "canonical-dsl:",
)
TIER4_TARGET_REPO_MARKERS = (
    "unknown/dsl-synthetic",
)


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


# Minimal YAML scalar extractor. The corpus uses a stable hand-written shape
# (top-level `key: value` lines with quoted or unquoted scalars). We avoid a
# full PyYAML dependency to keep the tool import-free and fast on 25k files.
TOP_LEVEL_SCALAR_RE = re.compile(r"^([a-z_][a-z0-9_]*):\s*(.*)$", re.IGNORECASE)


def _unquote(val: str) -> str:
    val = val.strip()
    if not val:
        return ""
    if (val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'"):
        return val[1:-1]
    return val


def parse_record_minimal(path: Path) -> Dict[str, str]:
    """Extract a small set of top-level scalar fields from a hackerman record.

    Supports both YAML (`*.yaml`, `record.yaml`) and JSON (`record.json`)
    record forms. Returns a dict containing whichever of {schema_version,
    record_id, source_audit_ref, source_extraction_method,
    source_extraction_confidence, target_repo, target_language,
    target_component, record_tier} were found at top level. Nested fields
    (function_shape, etc.) are intentionally ignored.
    """
    fields: Dict[str, str] = {}
    if path.suffix.lower() == ".json":
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return fields
        if not isinstance(payload, dict):
            return fields
        for key in (
            "schema_version",
            "record_id",
            "source_audit_ref",
            "source_extraction_method",
            "source_extraction_confidence",
            "target_repo",
            "target_language",
            "target_component",
            "record_tier",
        ):
            v = payload.get(key)
            if isinstance(v, str):
                fields[key] = v
        return fields
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                # Stop reading once we descend into a nested block (we only
                # need top-level scalars and they all appear before nested
                # mappings in the canonical writer output, but defensive
                # parsing is cheap).
                if line.startswith(" ") or line.startswith("\t") or line.startswith("-"):
                    continue
                m = TOP_LEVEL_SCALAR_RE.match(line)
                if not m:
                    continue
                key = m.group(1).strip().lower()
                val = _unquote(m.group(2))
                if key in {
                    "schema_version",
                    "record_id",
                    "source_audit_ref",
                    "source_extraction_method",
                    "source_extraction_confidence",
                    "target_repo",
                    "target_language",
                    "target_component",
                    "record_tier",
                    "verification_tier",
                }:
                    # Only keep first occurrence (canonical hackerman records
                    # define each top-level scalar exactly once).
                    fields.setdefault(key, val)
    except OSError:
        return fields
    return fields


# --------------------------------------------------------------------------- #
# Classifier
# --------------------------------------------------------------------------- #


def classify(record: Dict[str, str]) -> Tuple[str, str]:
    """Return (verification_tier, reason) for a parsed record dict.

    Priority order (first match wins): tier-5 → tier-1 → tier-2 → tier-4 →
    tier-3 default. This intentionally privileges quarantine and live-API
    signals over the broad "regex-derived" tier-3 default.
    """
    record_id = record.get("record_id", "")
    source_ref = record.get("source_audit_ref", "")
    extract_method = record.get("source_extraction_method", "").lower()
    target_repo = record.get("target_repo", "")
    target_language = record.get("target_language", "")
    # Include the on-disk file path (when available) so quarantine path markers
    # such as `_QUARANTINE_FABRICATED_CVE/` participate in the tier-5 check
    # even when record_id/source_audit_ref are silent about the quarantine subtree.
    file_path = record.get("__file_path", "")
    haystack = f"{record_id}\n{source_ref}\n{file_path}".lower()

    # tier-5: quarantine markers (path-based or known fabrication set)
    for marker in QUARANTINE_PATH_MARKERS:
        if marker.lower() in haystack:
            return ("tier-5-quarantine", f"quarantine-path-marker:{marker}")
    for sub in WAVE_3B_QUARANTINE_RECORD_SUBSTRINGS:
        if sub.lower() in haystack:
            return ("tier-5-quarantine", f"wave3b-fabricated-set:{sub}")

    # top-level verification_tier passthrough (v1.1 schema first-class field).
    # When the miner set `verification_tier: tier-N-*` at emit time (recorded
    # in `parse_record_minimal` via the `verification_tier` key), trust it and
    # return it directly. This prevents the heuristic classifier from
    # contradicting a miner-asserted tier (e.g. solodit wave3 REST-direct
    # backfill records that set tier-2 at emit but whose record_id prefix is
    # not yet in the stratifier's TIER2_PREFIXES or SOLODIT_NUMERIC_RE).
    # Exception: tier-5 quarantine is already handled above and must not be
    # bypassed by a non-tier-5 top-level field.
    top_level_tier = record.get("verification_tier", "")
    if top_level_tier and top_level_tier in VERIFICATION_TIERS and not top_level_tier.startswith("tier-5"):
        return (top_level_tier, "top-level-verification_tier-passthrough")

    # tier-1-officially-disclosed: emitter-asserted passthrough (Wave-2 PR-A
    # follow-up to ad3cc4bda7, 2026-05-16). Miners that hard-code a
    # manually-verified CVE/GHSA pair from official disclosure channels (NVD,
    # GHSA, vendor security advisories) set `record_tier` or the
    # `verification_tier:` shape_tag explicitly to this value; the stratifier
    # never assigns it heuristically, only honours the emitter's claim.
    record_tier_early = record.get("record_tier", "")
    if record_tier_early == "tier-1-officially-disclosed":
        return ("tier-1-officially-disclosed",
                "record-tier:tier-1-officially-disclosed")
    function_shape_early = record.get("function_shape") or {}
    shape_tags_early = function_shape_early.get("shape_tags") or []
    if isinstance(shape_tags_early, list):
        for tag in shape_tags_early:
            if str(tag) == "verification_tier:tier-1-officially-disclosed":
                return ("tier-1-officially-disclosed",
                        "shape-tag:verification_tier:tier-1-officially-disclosed")

    # tier-1: live API / canonical CVE id / real-SHA git-mining
    for sub in TIER1_SUBSTRINGS:
        if sub.lower() in haystack:
            return ("tier-1-verified-realtime-api", f"tier1-marker:{sub}")
    if TIER1_GIT_SHA_RE.match(source_ref) or TIER1_GIT_SHA_RE.match(record_id):
        return ("tier-1-verified-realtime-api", "git-mining-with-sha")

    # tier-2: public audit archives (prior-audit digests, findings-go, solodit
    # numeric ids)
    for pref in TIER2_PREFIXES:
        if record_id.startswith(pref) or source_ref.startswith(pref):
            # W2.5 dual-gate (opt-in via AUDITOOOR_W25_ENFORCE_URL_GATE=1).
            # When enabled, W2.5 prefixes additionally require an allow-listed
            # URL in `source_audit_ref`; otherwise they fall through to tier-3.
            # See spec docs/WAVE2_W25_TIER3_BACKFILL_SPEC_2026-05-16.md §4.1 / §6.1.
            if W25_ENFORCE_URL_GATE and pref in W25_REAL_ARCHIVE_PREFIXES:
                sar = (source_ref or "").strip()
                if not sar or not W25_ALLOWED_SOURCE_HOST_RE.match(sar):
                    # Fall through to the default tier-3 path; the W2.5
                    # source_audit_ref migrator (spec §4.2) will rewrite
                    # `source_audit_ref` to an allow-listed URL on a later run.
                    continue
                return ("tier-2-verified-public-archive",
                        f"w25-dual-gate:{pref}")
            return ("tier-2-verified-public-archive", f"tier2-prefix:{pref}")
    if SOLODIT_NUMERIC_RE.match(record_id) or SOLODIT_NUMERIC_RE.match(source_ref):
        return ("tier-2-verified-public-archive", "solodit-numeric-id")

    # tier-4: bundled fixtures (dsl-synthetic, fork patterns, canonical seeds,
    # or any record explicitly marked extraction_method=dsl-synthetic, or
    # synthesised against unknown/dsl-synthetic)
    for pref in TIER4_PREFIXES:
        if record_id.startswith(pref) or source_ref.startswith(pref):
            return ("tier-4-bundled-fixture", f"tier4-prefix:{pref}")
    if extract_method == "dsl-synthetic":
        return ("tier-4-bundled-fixture", "extraction-method-dsl-synthetic")
    for marker in TIER4_TARGET_REPO_MARKERS:
        if marker in target_repo.lower():
            return ("tier-4-bundled-fixture", f"target-repo-synthetic:{marker}")

    # tier-3: corpus-mined slices and other regex-derived fan-outs (real
    # protocol/class anchor, templated specifics)
    for pref in TIER3_PREFIXES:
        if record_id.startswith(pref) or source_ref.startswith(pref):
            return ("tier-3-synthetic-taxonomy-anchored", f"tier3-prefix:{pref}")

    # Solodit named drafts (no numeric id) → tier-2-verified-public-archive
    # because the underlying Solodit spec entries are mirrors of public audit
    # findings even when the local filename uses a slug rather than the id.
    if record_id.startswith("solodit-spec:") or source_ref.startswith("solodit-spec:"):
        return ("tier-2-verified-public-archive", "solodit-spec-fallback")

    # Local-workspace / submission-derived legacy records - tier-2 because
    # they originate from concrete in-tree workspace artifacts (worker
    # verdicts, paste-ready drafts, sibling lane reports) tied to real audit
    # workspaces, not synthetic taxonomies. These often carry
    # `extraction_method: regex-derived` but the underlying artifact is real
    # so we override the extraction-method fallback here.
    record_tier = record.get("record_tier", "")
    if record_tier in {"local-workspace", "submission-derived", "dydx-filed"}:
        return ("tier-2-verified-public-archive", f"record-tier:{record_tier}")
    # W2.7.a (2026-05-16): off-GitHub miners may emit
    # record_tier=tier-2-verified-public-archive as a single canonical
    # provenance marker. Honour it as a tier-2 passthrough (no upgrade
    # needed, no downgrade allowed) because the underlying artifact is a
    # public-archive snapshot recorded by the W2.7.a/b/c miner family.
    if record_tier == "tier-2-verified-public-archive":
        return ("tier-2-verified-public-archive", "record-tier:tier-2-verified-public-archive")
    if record_id.startswith("legacy:") or record_id.startswith("solidity-pattern:"):
        return ("tier-2-verified-public-archive", "legacy-workspace-derived")

    if extract_method == "regex-derived":
        return ("tier-3-synthetic-taxonomy-anchored", "extraction-method-regex-derived")

    # Conservative default: tier-3 (templated). This is the safest fallback
    # because misclassifying as tier-1/2 would over-trust a record while
    # tier-3 still allows MCP consumers to surface it with appropriate prior.
    return ("tier-3-synthetic-taxonomy-anchored", "fallback-unknown-prefix")


# --------------------------------------------------------------------------- #
# Driver
# --------------------------------------------------------------------------- #


def iter_record_files(tags_dir: Path) -> Iterable[Path]:
    """Yield every candidate record file under tags_dir (recursively).

    Mirrors the iteration logic in `tools/hackerman-record-verification-tier-check.py`:
      - `record.yaml` / `record.json` per-directory bundles are emitted.
      - Flat `*.yaml` at the top of tags_dir.
      - Flat `*.yaml` inside sub-buckets (e.g. quarantine subdirs) when no
        sibling `record.yaml` is present.
    Both YAML and JSON record forms are emitted because the gate audits both.
    """
    for path in sorted(tags_dir.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name == "readme.md":
            continue
        if name in {"record.yaml", "record.json"}:
            yield path
            continue
        if path.suffix.lower() == ".yaml" and path.parent == tags_dir:
            yield path
            continue
        if path.suffix.lower() == ".yaml" and path.parent != tags_dir:
            sibling = path.parent / "record.yaml"
            if sibling.exists() and sibling != path:
                continue
            yield path


def stratify(
    tags_dir: Path,
    output_path: Path,
    *,
    write: bool,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    distribution: Counter[str] = Counter()
    samples: Dict[str, List[Dict[str, str]]] = {tier: [] for tier in VERIFICATION_TIERS}
    candidates: List[Dict[str, str]] = []

    scanned = 0
    skipped = 0
    for path in iter_record_files(tags_dir):
        scanned += 1
        if limit is not None and scanned > limit:
            break
        record = parse_record_minimal(path)
        # Accept both v1 and v1.1 (Wave-2 Phase-3 schema migration). Use
        # prefix-match so future v1.x minor bumps remain in-gate without a
        # tool-side rev. Sibling verdict_tag.v2 YAMLs still skip via this
        # check because their schema_version starts with "verdict_tag.v2".
        if not str(record.get("schema_version") or "").startswith(
            "auditooor.hackerman_record.v1"
        ):
            # Skip non-hackerman-v1.x records (older verdict_tag files share
            # the directory).
            skipped += 1
            continue
        record_id = record.get("record_id") or path.stem
        # Pass absolute file path into the classifier so quarantine subtree
        # markers (e.g. `_QUARANTINE_FABRICATED_CVE/`) participate in the
        # tier-5 path-marker check even when record_id/source_audit_ref are
        # silent about the quarantine subtree.
        record["__file_path"] = str(path)
        tier, reason = classify(record)
        distribution[tier] += 1
        candidates.append(
            {
                "record_id": record_id,
                "file": str(path.relative_to(tags_dir.parent.parent.parent)) if tags_dir.is_absolute() and tags_dir.parent.parent.parent in path.parents else str(path),
                "verification_tier": tier,
                "reason": reason,
            }
        )
        if len(samples[tier]) < 3:
            samples[tier].append(
                {
                    "record_id": record_id,
                    "source_audit_ref": record.get("source_audit_ref", ""),
                    "extraction_method": record.get("source_extraction_method", ""),
                    "target_repo": record.get("target_repo", ""),
                    "reason": reason,
                }
            )

    if write:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as fh:
            for entry in candidates:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")

    total_classified = sum(distribution.values())
    pct = {
        tier: (100.0 * distribution[tier] / total_classified) if total_classified else 0.0
        for tier in VERIFICATION_TIERS
    }

    return {
        "scanned": scanned,
        "skipped_non_hackerman_v1": skipped,
        "classified": total_classified,
        "distribution": dict(distribution),
        "distribution_pct": pct,
        "samples_per_tier": samples,
        "candidates_written": len(candidates) if write else 0,
        "output_path": str(output_path) if write else None,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument(
        "--tags-dir",
        type=Path,
        default=DEFAULT_TAGS_DIR,
        help="Directory of hackerman YAML records.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Candidate JSONL output path.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Scan and report distribution but do NOT write JSONL.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write the JSONL candidate file (default when --dry-run absent).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Cap scanned files (for smoke tests).",
    )
    args = parser.parse_args(argv)

    if not args.tags_dir.exists():
        print(f"error: tags dir does not exist: {args.tags_dir}", file=sys.stderr)
        return 2

    write = args.write or not args.dry_run

    summary = stratify(args.tags_dir, args.output, write=write, limit=args.limit)

    print("# hackerman verification-tier stratification")
    print(f"scanned:                {summary['scanned']}")
    print(f"skipped_non_hackerman:  {summary['skipped_non_hackerman_v1']}")
    print(f"classified:             {summary['classified']}")
    print()
    print("# distribution")
    for tier in VERIFICATION_TIERS:
        count = summary["distribution"].get(tier, 0)
        pct = summary["distribution_pct"].get(tier, 0.0)
        print(f"  {tier:<40} {count:>7} ({pct:5.2f}%)")
    if write:
        print()
        print(f"wrote candidates: {summary['output_path']}  ({summary['candidates_written']} rows)")
    else:
        print()
        print("(dry-run; no JSONL written)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
