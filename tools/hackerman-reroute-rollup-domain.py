#!/usr/bin/env python3
"""Re-route hackerman_record v1 YAML files whose target_repo matches an L2 /
rollup-stack signal into the canonical ``target_domain: rollup`` bucket.

Phase 1 (this commit): emit candidate rows only.

Reads ``audit/corpus_tags/tags/*.yaml``. For every record whose ``target_repo``
or text body matches an L2-stack signal (Optimism, Arbitrum, ZkSync, Linea,
Scroll, Polygon zkEVM, Base, StarkNet, Mantle, Taiko, Fraxtal, Blast, Metis,
Kroma) and whose existing ``target_domain`` is NOT already ``rollup`` /
``zk-proof``, write a candidate row to
``.auditooor/reroute-rollup-candidates.jsonl``.

Each candidate row carries ``target_domain_original`` (rollback hint), the
detected L2 stack sub-bucket (``op-stack`` / ``arbitrum-nitro`` / ``zksync-era``
/ ``scroll-zkevm`` / ``linea-zkevm`` / ``polygon-zkevm`` / ``starknet-cairo``
/ ``base-l2`` / ``mantle-l2`` / ``taiko-l2`` / ``fraxtal-l2`` / ``blast-l2``
/ ``metis-l2`` / ``kroma-l2``), and the signal that triggered the match
(``target_repo`` vs ``body``).

When invoked with ``--apply`` the tool also rewrites
``target_domain: <old>`` -> ``target_domain: rollup`` in the YAML body. The
sub-bucket and rollback information stays in the JSONL ledger (the strict
hackerman_record schema disallows additional top-level properties).

Usage:
    python3 tools/hackerman-reroute-rollup-domain.py --dry-run
    python3 tools/hackerman-reroute-rollup-domain.py --apply
    python3 tools/hackerman-reroute-rollup-domain.py --dry-run --json-summary
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


SCHEMA = "auditooor.hackerman_reroute_rollup_domain.v1"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_LEDGER_PATH = REPO_ROOT / ".auditooor" / "reroute-rollup-candidates.jsonl"

HACKERMAN_SCHEMA_RE = re.compile(
    r"^schema_version:\s+auditooor\.hackerman_record\.v1\s*$", re.MULTILINE
)
TARGET_DOMAIN_RE = re.compile(
    r"^(target_domain:\s*)([\"']?)([A-Za-z0-9._\-]+)\2\s*$", re.MULTILINE
)
TARGET_REPO_RE = re.compile(
    r"^target_repo:\s*([\"']?)(.+?)\1\s*$", re.MULTILINE
)


# Order matters: more specific stack tokens first so e.g. ``polygon-zkevm``
# is matched before bare ``polygon``.
ROLLUP_STACK_SIGNALS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("polygon-zkevm", ("polygonzkevm", "polygon-zkevm", "polygon_zkevm", "polygon zkevm")),
    ("zksync-era", ("zksync", "zk-sync", "zk sync", "boojum", "matterlabs", "matter-labs")),
    ("scroll-zkevm", ("scroll-tech", "scrollowner", "scroll-zkevm", "scroll/", "/scroll", "scroll ")),
    ("linea-zkevm", ("consensys/linea", "openzeppelin/linea", "cyfrin/linea", "linea-besu", "linea zkevm", "linea-zkevm", "/linea", "linea/")),
    ("starknet-cairo", ("starknet", "starkware", "cairo-lang", "starknet-cairo")),
    ("op-stack", ("ethereum-optimism", "optimism", "op-stack", "op stack", "optimismgovernor", "op-geth", "op-node", "op-batcher", "op-proposer", "op-program")),
    ("arbitrum-nitro", ("arbitrum", "offchainlabs", "offchain labs", "arb-os", "arb-node", "nitro", "arbitrum-nitro", "arbitrum-stylus")),
    ("base-l2", ("base-org", "base-org/", "base/azul", "base-azul", "spearbit/base", "cantina/base", "code4rena/base", "base-l2", "/base ", "base supply")),
    ("polygon-pos", ("polygon-pos", "matic-network", "maticnetwork", "sigmaprime/polygon", "spearbit/polygon", "quantstamp/polygon", "/polygon ", "polygon/")),
    ("mantle-l2", ("mantlenetworkio", "mantle-v2", "mantle/", "mantle l2", "mantle network", "mantle-l2")),
    ("taiko-l2", ("taikoxyz", "taiko-l2", "taiko/", "taiko ")),
    ("fraxtal-l2", ("fraxtal", "frax-l2")),
    ("blast-l2", ("blast-io", "blastoff", "blast-l2", "blast network")),
    ("metis-l2", ("metis", "metis-l2")),
    ("kroma-l2", ("kroma", "kroma-l2")),
)


# Rubric: which existing target_domain values are allowed to be re-routed.
# We do NOT re-route already-rollup or already-zk-proof records (zk-proof is a
# more specific bucket that the operator may have set on purpose, e.g. Linea
# / ZkSync circuit findings).
REROUTABLE_DOMAINS = frozenset(
    {
        "bridge",
        "vault",
        "governance",
        "lending",
        "dex",
        "oracle",
        "staking",
        "consensus",
        "dao",
        "escrow",
        "nft",
        "gaming",
        "rpc-infra",
        "l1-client",
    }
)


def _is_hackerman_record(text: str) -> bool:
    return bool(HACKERMAN_SCHEMA_RE.search(text))


def _extract(text: str, pattern: re.Pattern, group: int) -> str:
    m = pattern.search(text)
    if not m:
        return ""
    return m.group(group).strip()


def detect_stack(target_repo: str, body: str) -> Tuple[str, str]:
    """Return (sub_bucket, signal_source) or ("", "")."""
    haystacks = (
        ("target_repo", target_repo.lower() if target_repo else ""),
        ("body", body.lower()),
    )
    for sub_bucket, needles in ROLLUP_STACK_SIGNALS:
        for source, hay in haystacks:
            if not hay:
                continue
            for needle in needles:
                if needle in hay:
                    return sub_bucket, source
    return "", ""


def _build_candidate(
    path: Path,
    text: str,
    current_domain: str,
    target_repo: str,
    sub_bucket: str,
    signal_source: str,
) -> Dict[str, Any]:
    record_id_match = re.search(r"^record_id:\s*(.+?)\s*$", text, re.MULTILINE)
    return {
        "tag_file": path.name,
        "record_id": record_id_match.group(1).strip().strip("'\"") if record_id_match else "",
        "target_repo": target_repo,
        "target_domain_original": current_domain,
        "target_domain_new": "rollup",
        "rollup_sub_bucket": sub_bucket,
        "signal_source": signal_source,
    }


def _rewrite_domain(text: str) -> str:
    """Rewrite target_domain to rollup; preserves original quoting style."""
    def repl(m: re.Match) -> str:
        prefix, quote, _ = m.group(1), m.group(2), m.group(3)
        return f"{prefix}{quote}rollup{quote}"
    return TARGET_DOMAIN_RE.sub(repl, text, count=1)


def scan(
    tag_dir: Path,
    *,
    apply: bool = False,
    limit: int = 0,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    scanned = 0
    matched_by_repo = 0
    matched_by_body = 0
    already_rollup_skip = 0
    domain_not_reroutable_skip = 0
    updated_files: List[str] = []
    sub_bucket_counts: Dict[str, int] = {}

    paths = sorted(p for p in tag_dir.glob("*.yaml") if p.is_file())
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if not _is_hackerman_record(text):
            continue
        scanned += 1
        current_domain = _extract(text, TARGET_DOMAIN_RE, 3)
        if current_domain == "rollup" or current_domain == "zk-proof":
            already_rollup_skip += 1
            continue
        target_repo = _extract(text, TARGET_REPO_RE, 2)
        sub_bucket, signal_source = detect_stack(target_repo, text)
        if not sub_bucket:
            continue
        if current_domain not in REROUTABLE_DOMAINS:
            domain_not_reroutable_skip += 1
            continue
        if signal_source == "target_repo":
            matched_by_repo += 1
        else:
            matched_by_body += 1
        sub_bucket_counts[sub_bucket] = sub_bucket_counts.get(sub_bucket, 0) + 1
        cand = _build_candidate(
            path, text, current_domain, target_repo, sub_bucket, signal_source
        )
        candidates.append(cand)

        if apply:
            new_text = _rewrite_domain(text)
            if new_text != text:
                path.write_text(new_text, encoding="utf-8")
                updated_files.append(path.name)

        if limit and len(candidates) >= limit:
            break

    summary = {
        "schema": SCHEMA,
        "scanned": scanned,
        "candidate_count": len(candidates),
        "matched_by_repo": matched_by_repo,
        "matched_by_body": matched_by_body,
        "already_rollup_or_zkproof_skipped": already_rollup_skip,
        "domain_not_reroutable_skipped": domain_not_reroutable_skip,
        "sub_bucket_counts": dict(
            sorted(sub_bucket_counts.items(), key=lambda kv: -kv[1])
        ),
        "applied": apply,
        "updated_files": updated_files,
    }
    return candidates, summary


def write_ledger(candidates: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in candidates:
            fh.write(json.dumps(row, sort_keys=True) + "\n")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--tag-dir", type=Path, default=DEFAULT_TAG_DIR,
        help=f"Directory of YAML records (default: {DEFAULT_TAG_DIR})",
    )
    parser.add_argument(
        "--ledger", type=Path, default=DEFAULT_LEDGER_PATH,
        help=f"Output JSONL ledger (default: {DEFAULT_LEDGER_PATH})",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Scan only, never modify YAML.",
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Rewrite target_domain to rollup in matched YAML files.",
    )
    parser.add_argument(
        "--limit", type=int, default=0, help="Stop after N candidates.",
    )
    parser.add_argument(
        "--json-summary", action="store_true",
        help="Emit a JSON summary line to stdout instead of human text.",
    )
    args = parser.parse_args(argv)

    if args.apply and args.dry_run:
        print("ERROR: --apply and --dry-run are mutually exclusive", file=sys.stderr)
        return 2

    apply = bool(args.apply)
    candidates, summary = scan(args.tag_dir, apply=apply, limit=args.limit)
    write_ledger(candidates, args.ledger)
    summary["ledger_path"] = str(args.ledger)

    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            f"[reroute-rollup-domain] scanned={summary['scanned']} "
            f"candidates={summary['candidate_count']} "
            f"matched_by_repo={summary['matched_by_repo']} "
            f"matched_by_body={summary['matched_by_body']} "
            f"applied={summary['applied']} "
            f"ledger={summary['ledger_path']}"
        )
        for bucket, count in summary["sub_bucket_counts"].items():
            print(f"    {bucket}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
