#!/usr/bin/env python3
# r36-rebuttal: lane-189-CONSOLIDATE-TX-TOOLS registered in agent_pathspec.json (Task #189)
"""DEPRECATED: see tools/incident-corpus-tx-enrichment.py instead.

This tool was consolidated into the unified
`tools/incident-corpus-tx-enrichment.py` per Task #189 (2026-05-26),
together with the sibling `tools/incident-corpus-tx-enrichment.py`
(formerly P2.7). Both implementations are now reachable via a single
entrypoint with a `--corpus-shape` selector.

This file is retained as a backward-compatibility shim. It forwards
every invocation to the consolidated tool with
`--corpus-shape defimon-tg`, emits a deprecation warning to stderr, and
keeps the legacy CLI flags (`--input-dir`, `--cross-corpus-dirs`,
`--json-summary`, `--dry-run`, `--limit`). The output structured-
extraction blocks remain byte-identical to the legacy emissions because
the consolidated tool re-uses the original defimon-TG-shape regex
library + per-record dispatcher.

Soft-deprecation per WF10 protocol: this shim is kept for 30 days, then
becomes a candidate for tier-5 retirement.

Migration path:

  # Old:
  python3 tools/defimon-tg-tx-enrichment.py \
      --input-dir audit/corpus_tags/tags/defimon_telegram_incidents/

  # New:
  python3 tools/incident-corpus-tx-enrichment.py \
      --input-dir audit/corpus_tags/tags/defimon_telegram_incidents/ \
      --corpus-shape defimon-tg

Both forms produce the same structured_extraction block with schema
version `auditooor.defimon_tg_tx_enrichment.v1`. Re-running either form
against an already-enriched corpus is idempotent (only the
`enriched_at_utc` timestamp drifts; all functional fields are
identical).
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# Import the consolidated tool by file path (filename has a hyphen).
import importlib.util as _ilu

REPO_ROOT = Path(__file__).resolve().parent.parent
CONSOLIDATED_TOOL = REPO_ROOT / "tools" / "incident-corpus-tx-enrichment.py"

DEFAULT_INPUT_DIR = (
    REPO_ROOT / "audit" / "corpus_tags" / "tags" / "defimon_telegram_incidents"
)
DEFAULT_CROSS_CORPUS_DIRS = [
    REPO_ROOT / "audit" / "corpus_tags" / "tags" / "bridge_incidents",
    REPO_ROOT / "audit" / "corpus_tags" / "tags" / "darknavy_web3_incidents",
    REPO_ROOT / "audit" / "corpus_tags" / "tags" / "rekt_news_incidents",
    REPO_ROOT / "audit" / "corpus_tags" / "tags" / "defimon_blog_incidents",
]


def _emit_deprecation_warning() -> None:
    if os.environ.get("AUDITOOOR_SUPPRESS_DEPRECATION_WARNINGS"):
        return
    print(
        "[DEPRECATION] tools/defimon-tg-tx-enrichment.py is deprecated. "
        "Use `tools/incident-corpus-tx-enrichment.py --corpus-shape "
        "defimon-tg` instead. This shim forwards to the consolidated "
        "tool; output is byte-identical for functional fields. "
        "Soft-deprecation window: 30 days from 2026-05-26.",
        file=sys.stderr,
    )


def _load_consolidated_module():
    """Load the consolidated tool as a module (for legacy programmatic
    callers of `walk_records`, `enrich_record`, etc.).
    """
    spec = _ilu.spec_from_file_location(
        "incident_corpus_tx_enrichment", str(CONSOLIDATED_TOOL)
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"failed to load consolidated tool at {CONSOLIDATED_TOOL}"
        )
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Re-export the legacy programmatic API so any callers that import this
# module continue to work. Each name resolves to the consolidated tool's
# equivalent function.
_consolidated = _load_consolidated_module()

# Defimon-TG-shape extraction helpers (legacy names).
extract_evidence = _consolidated.extract_evidence
extract_tx_hashes = _consolidated.extract_tx_hashes
extract_contract_addresses = _consolidated.extract_contract_addresses
refine_amount_usd = _consolidated.refine_amount_usd
infer_chain = _consolidated.infer_chain
extract_asset_tokens = _consolidated.extract_asset_tokens
extract_explorer_urls = _consolidated.extract_explorer_urls
build_cross_corpus_address_index = (
    _consolidated.build_cross_corpus_address_index
)
resolve_target_via_cross_corpus = (
    _consolidated.resolve_target_via_cross_corpus
)
enrich_record = _consolidated.enrich_record_defimon_tg
walk_records = _consolidated.walk_records


# Legacy regex names (some external callers reference these directly).
EVM_TX_HASH_RE = _consolidated.DTG_EVM_TX_HASH_RE
EVM_ADDRESS_RE = _consolidated.DTG_EVM_ADDRESS_RE
TRON_TX_URL_RE = _consolidated.DTG_TRON_TX_URL_RE
TRON_ADDR_URL_RE = _consolidated.DTG_TRON_ADDR_URL_RE
TRON_ADDR_RE = _consolidated.DTG_TRON_ADDR_RE
BTC_TX_URL_RE = _consolidated.DTG_BTC_TX_URL_RE
SOLANA_TX_URL_RE = _consolidated.DTG_SOLANA_TX_URL_RE
SOLANA_ADDR_URL_RE = _consolidated.DTG_SOLANA_ADDR_URL_RE
EXPLORER_URL_RE = _consolidated.DTG_EXPLORER_URL_RE
AMOUNT_PATTERNS = _consolidated.DTG_AMOUNT_PATTERNS
URL_HOST_TO_CHAIN = _consolidated.DTG_URL_HOST_TO_CHAIN
NETWORK_TOKEN_TO_CHAIN = _consolidated.DTG_NETWORK_TOKEN_TO_CHAIN
NETWORK_MARKER_RE = _consolidated.DTG_NETWORK_MARKER_RE
KNOWN_ASSET_TOKENS = _consolidated.DTG_KNOWN_ASSET_TOKENS
ASSET_TOKEN_RE = _consolidated.DTG_ASSET_TOKEN_RE


def main(argv: list) -> int:
    """Forward to the consolidated tool with `--corpus-shape defimon-tg`.

    Accepts the legacy CLI flags and re-builds the equivalent invocation
    of `tools/incident-corpus-tx-enrichment.py`. Exit code matches the
    delegated process.
    """
    _emit_deprecation_warning()

    forwarded = [sys.executable, str(CONSOLIDATED_TOOL)]
    # Insert the corpus-shape selector. If the user passes their own
    # --corpus-shape we let it through, but emit a hint that this shim
    # always defaults to defimon-tg.
    has_shape = any(a == "--corpus-shape" for a in argv)
    if not has_shape:
        forwarded += ["--corpus-shape", "defimon-tg"]
    forwarded += list(argv)

    # Default --input-dir if none supplied (legacy behavior pinned
    # to defimon_telegram_incidents).
    if not any(a.startswith("--input-dir") for a in argv):
        forwarded += ["--input-dir", str(DEFAULT_INPUT_DIR)]
    if not any(a.startswith("--cross-corpus-dirs") for a in argv):
        forwarded += [
            "--cross-corpus-dirs",
            ",".join(str(d) for d in DEFAULT_CROSS_CORPUS_DIRS),
        ]

    result = subprocess.run(forwarded, check=False)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
