#!/usr/bin/env python3
"""corpus-registry-build — index all r94_solodit_* corpus directories.

Walks ``reference/patterns.dsl.r94_solodit_*`` directories and emits
``reference/corpus_registry.json``.  Idempotent: rerunning produces
byte-identical output (sorted by slug, stable JSON formatting).

Output schema: auditooor.corpus_registry.v1

Usage:
    python3 tools/corpus-registry-build.py [--ref-dir <path>] [--out <path>]

Defaults:
    --ref-dir  <repo-root>/reference
    --out      <repo-root>/reference/corpus_registry.json
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Human-readable topic labels for known slugs.  Unknown slugs fall back to
# title-cased slug text.
SLUG_TO_TOPIC: dict[str, str] = {
    "aa":             "Account Abstraction (ERC-4337)",
    "accesscontrol":  "Access Control",
    "amm":            "Automated Market Maker",
    "amm2":           "Automated Market Maker (extended)",
    "bridge":         "Cross-Chain Bridge",
    "cairo":          "Cairo / StarkNet",
    "callback":       "Callback / Hook Reentrancy",
    "circom":         "Circom / ZK Circuits",
    "clob":           "Central Limit Order Book",
    "crypto":         "Cryptography",
    "erc4626":        "ERC-4626 Tokenized Vaults",
    "flashloan":      "Flash Loan",
    "func":           "FunC / TON",
    "go":             "Go / Golang",
    "governance":     "Governance",
    "governance2":    "Governance (extended)",
    "hooks":          "UniswapV4 Hooks",
    "layerzero":      "LayerZero Messaging",
    "liquidation":    "Liquidation",
    "mev":            "MEV / Sandwich / Frontrunning",
    "move":           "Move Language (Aptos / Sui)",
    "nft":            "NFT / ERC-721",
    "oracle":         "Oracle Manipulation",
    "oracle2":        "Oracle Manipulation (extended)",
    "perps":          "Perpetuals / Derivatives",
    "proxy":          "Proxy / Upgradeable Contracts",
    "reentrancy":     "Reentrancy",
    "reentrancy2":    "Reentrancy (extended)",
    "restaking":      "Restaking / EigenLayer",
    "rust":           "Rust",
    "sig":            "Signature Validation",
    "sigreplay":      "Signature Replay",
    "sigreplay2":     "Signature Replay (extended)",
    "stablecoin":     "Stablecoin",
    "staking":        "Staking / Rewards",
    "sway":           "Sway / Fuel",
    "token_standard": "Token Standards (ERC-20 / ERC-777)",
    "tokenomics":     "Tokenomics / Emission",
    "vault2":         "Vault (extended)",
    "vesting":        "Vesting / Time-Locks",
    "vyper":          "Vyper",
    "wrongmath":      "Integer / Math Errors",
    "zk":             "Zero-Knowledge Proofs",
}

PREFIX = "patterns.dsl.r94_solodit_"


def _slug_to_topic(slug: str) -> str:
    if slug in SLUG_TO_TOPIC:
        return SLUG_TO_TOPIC[slug]
    # Fallback: title-case, replace underscores with spaces
    return slug.replace("_", " ").title()


def _iso_mtime(ts: float) -> str:
    """Return ISO-8601 UTC timestamp string for a POSIX timestamp."""
    dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _scan_directory(dirpath: pathlib.Path) -> tuple[int, int, float]:
    """Return (file_count, total_size_bytes, newest_mtime) for a directory."""
    file_count = 0
    total_size = 0
    newest_mtime = 0.0
    for entry in os.scandir(dirpath):
        if entry.is_file(follow_symlinks=False):
            stat = entry.stat(follow_symlinks=False)
            file_count += 1
            total_size += stat.st_size
            if stat.st_mtime > newest_mtime:
                newest_mtime = stat.st_mtime
    return file_count, total_size, newest_mtime


def build_registry(ref_dir: pathlib.Path, out_path: pathlib.Path) -> int:
    """Walk ref_dir for corpus dirs, build registry, write JSON. Returns count."""
    corpora = []
    for entry in sorted(ref_dir.iterdir()):
        if not entry.is_dir():
            continue
        name = entry.name
        if not name.startswith(PREFIX):
            continue
        slug = name[len(PREFIX):]
        file_count, size_bytes, newest_mtime = _scan_directory(entry)
        corpora.append({
            "slug": slug,
            "path": str(entry.relative_to(ref_dir.parent)),  # relative to repo root
            "file_count": file_count,
            "size_bytes": size_bytes,
            "newest_mtime": _iso_mtime(newest_mtime) if newest_mtime else None,
            "topic": _slug_to_topic(slug),
        })

    # corpora already sorted by slug (iterdir is sorted above)
    now_iso = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    registry = {
        "schema": "auditooor.corpus_registry.v1",
        "generated_at": now_iso,
        "corpora": corpora,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(registry, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return len(corpora)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--ref-dir",
        type=pathlib.Path,
        default=ROOT / "reference",
        help="Path to the reference/ directory (default: <repo-root>/reference)",
    )
    parser.add_argument(
        "--out",
        type=pathlib.Path,
        default=ROOT / "reference" / "corpus_registry.json",
        help="Output JSON path (default: reference/corpus_registry.json)",
    )
    args = parser.parse_args(argv)

    count = build_registry(args.ref_dir, args.out)
    print(f"[corpus-registry] wrote {count} corpora to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
