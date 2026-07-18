#!/usr/bin/env python3
"""Per-Chain Blast Radius Enumerator.

For a filed finding that identifies a pallet / module / consensus-client as
the affected component, this tool enumerates every additional chain /
consensus-client / configuration that ALSO routes through the same affected
component via `register_*`, `set_*`, `add_*`, `addClient*`, or
`registerChain*` call sites in the workspace's source tree. The resulting
JSON record is the per-finding blast radius: how many other chains would be
impacted by the same root cause.

Empirical anchor: Hyperbridge `hb-optimism-l2oracle-unfinalized-output-HIGH`
identifies the affected component as `modules/ismp/clients/ismp-optimism`
(pallet `pallet_ismp`, `IsmpOptimism` consensus client). A blast-radius
enumeration over the workspace source tree would surface every OP-stack
chain registered via `add_state_machine(...)` in the same pallet, so the
operator can decide whether the original finding should be widened or a
sibling submission filed against the additional surfaces.

Usage:
  python3 tools/per-chain-blast-radius-enumerator.py \\
      --filed-finding-path <path/to/finding.md> \\
      --workspace <workspace-root> \\
      [--source-root <path>] [--json] [--output-dir <dir>]

Output:
  <workspace>/.auditooor/per_chain_blast_radius/<finding-slug>.json

Schema: auditooor.per_chain_blast_radius.v1

Exit codes:
  0 - enumeration ran successfully (may report blast_radius_count=0)
  1 - usage / input error
  2 - finding path not readable

<!-- r36-rebuttal: build lane -->
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "auditooor.per_chain_blast_radius.v1"

# ---------------------------------------------------------------------------
# Pallet / module identifier extraction
# ---------------------------------------------------------------------------

# Patterns for pulling pallet/module identifiers out of finding text.
PALLET_PATTERNS: list[tuple[str, str]] = [
    (r"`(pallet_[a-z_][a-z0-9_]*)`", "substrate-pallet"),
    (r"\b(pallet[_-][a-z][a-z0-9_-]*)\b", "substrate-pallet"),
    (r"`(modules/[a-z][a-z0-9_/-]+)`", "rust-module"),
    (r"`([A-Z][A-Za-z0-9]*Optimism|[A-Z][A-Za-z0-9]*Arbitrum|[A-Z][A-Za-z0-9]*Grandpa|[A-Z][A-Za-z0-9]*Beefy)`", "rust-module"),
    (r"`(ismp[_-][a-z][a-z0-9_-]*)`", "rust-module"),
    (r"`(x/[a-z][a-z0-9_-]*)`", "go-module"),
    (r"`(contracts?/[A-Za-z][A-Za-z0-9/_-]+\.sol)`", "solidity-contract"),
]

# Registration / setter call-site patterns (file-source greps).
REGISTRATION_PATTERNS: list[tuple[str, str]] = [
    # Substrate-style register / add_state_machine
    (r"add_state_machine\s*\(\s*([A-Za-z0-9_:]+)", "register_fn"),
    (r"register_state_machine\s*\(\s*([A-Za-z0-9_:]+)", "register_fn"),
    (r"register_consensus_client\s*\(\s*([A-Za-z0-9_:]+)", "register_fn"),
    (r"register_chain\s*\(\s*([A-Za-z0-9_:]+)", "register_fn"),
    # set_*
    (r"set_state_machine\s*\(\s*([A-Za-z0-9_:]+)", "set_fn"),
    (r"set_consensus_state\s*\(\s*([A-Za-z0-9_:]+)", "set_fn"),
    # add_*
    (r"add_client\s*\(\s*([A-Za-z0-9_:]+)", "add_fn"),
    (r"add_consensus_client\s*\(\s*([A-Za-z0-9_:]+)", "add_fn"),
    # Solidity-style
    (r"addClient\s*\(\s*([A-Za-z0-9_]+)", "add_fn"),
    (r"registerChain\s*\(\s*([A-Za-z0-9_]+)", "register_fn"),
    (r"setChain\s*\(\s*([A-Za-z0-9_]+)", "set_fn"),
    # Constants / enums identifying chains
    (r"StateMachine::(?:Evm|Polkadot|Kusama|Beefy|Grandpa)\s*\(\s*([0-9_]+)\s*\)", "constant_decl"),
    (r"chain_id\s*[:=]\s*([0-9_]+)", "constant_decl"),
]

CHAIN_TOKEN_PATTERN = re.compile(
    r"\b(?:OPTIMISM|ARBITRUM|BASE|BLAST|MODE|MANTLE|SCROLL|ZKSYNC|POLYGON|"
    r"ETHEREUM|BSC|AVALANCHE|FANTOM|MOONBEAM|MOONRIVER|ASTAR|KUSAMA|POLKADOT|"
    r"Optimism|Arbitrum|Base|Blast|Mode|Mantle|Scroll|Polygon|Ethereum|"
    r"Bsc|Avalanche|Fantom|Moonbeam|Moonriver|Astar|Kusama|Polkadot)\b"
)

SOURCE_FILE_EXTENSIONS = {".rs", ".go", ".sol", ".ts", ".js", ".py", ".move"}
SKIP_DIR_NAMES = {
    ".git", "node_modules", "target", "dist", "build", "__pycache__",
    ".venv", "venv", ".idea", ".vscode", "vendor",
    ".auditooor", "submissions", "audit", "agent_outputs", "_archive",
    "prior_audits", "scope_review", "poc_execution",
}


def extract_pallet_or_module(text: str) -> tuple[str, str, str] | None:
    """Find the first pallet / module / contract identifier in the finding text."""
    for pattern, kind in PALLET_PATTERNS:
        match = re.search(pattern, text)
        if match:
            ident = match.group(1)
            start = max(0, match.start() - 40)
            end = min(len(text), match.end() + 40)
            snippet = text[start:end].replace("\n", " ").strip()
            return ident, kind, snippet
    return None


def iter_source_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".")]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix in SOURCE_FILE_EXTENSIONS:
                yield p


def grep_registrations(
    source_root: Path,
    identifier: str | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Grep source tree for registration anchors and chain identifiers."""
    anchors: list[dict[str, Any]] = []
    chain_evidence: dict[str, list[str]] = {}
    warnings: list[str] = []

    if not source_root.exists():
        warnings.append(f"source_root_missing: {source_root}")
        return anchors, [], warnings

    compiled_reg = [(re.compile(p), k) for p, k in REGISTRATION_PATTERNS]

    file_count = 0
    for path in iter_source_files(source_root):
        file_count += 1
        if file_count > 5000:
            warnings.append("file_scan_truncated_at_5000")
            break
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for lineno, line in enumerate(text.splitlines(), start=1):
            for compiled, kind in compiled_reg:
                m = compiled.search(line)
                if m:
                    snippet = line.strip()[:200]
                    try:
                        relpath = str(path.relative_to(source_root))
                    except ValueError:
                        relpath = str(path)
                    anchors.append({
                        "file": relpath,
                        "line": lineno,
                        "snippet": snippet,
                        "kind": kind,
                    })
                    for tok in CHAIN_TOKEN_PATTERN.findall(line):
                        chain_evidence.setdefault(tok, []).append(f"{relpath}:{lineno}")
                    break

    canonicalized: dict[str, dict[str, Any]] = {}
    for name, paths in chain_evidence.items():
        canon = name.upper()
        bucket = canonicalized.setdefault(canon, {
            "name": canon.capitalize(),
            "evidence_paths": [],
            "confidence": "medium",
        })
        for p in paths:
            if p not in bucket["evidence_paths"]:
                bucket["evidence_paths"].append(p)
    for bucket in canonicalized.values():
        if len(bucket["evidence_paths"]) >= 2:
            bucket["confidence"] = "high"
        elif len(bucket["evidence_paths"]) == 1:
            bucket["confidence"] = "low"

    registered_chains = sorted(canonicalized.values(), key=lambda d: d["name"])
    return anchors, registered_chains, warnings


def derive_finding_slug(path: Path) -> str:
    return path.stem


def run(
    filed_finding_path: Path,
    workspace: Path,
    source_root: Path | None = None,
) -> tuple[int, dict[str, Any]]:
    if not filed_finding_path.exists():
        return 2, {"error": f"finding_path_missing: {filed_finding_path}"}
    try:
        text = filed_finding_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return 2, {"error": f"finding_read_failed: {exc}"}

    slug = derive_finding_slug(filed_finding_path)
    extracted = extract_pallet_or_module(text)
    if extracted is None:
        pallet = {"identifier": "", "evidence": "", "kind": "unknown"}
    else:
        ident, kind, snippet = extracted
        pallet = {"identifier": ident, "evidence": snippet, "kind": kind}

    effective_source_root = source_root or workspace
    anchors, chains, warnings = grep_registrations(
        effective_source_root,
        pallet["identifier"] if pallet["identifier"] else None,
    )

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "finding_slug": slug,
        "finding_path": str(filed_finding_path),
        "workspace": str(workspace),
        "pallet_or_module": pallet,
        "registration_anchors": anchors,
        "registered_chains": chains,
        "blast_radius_count": max(0, len(chains) - 1) if chains else 0,
        "search_scope": {
            "roots_grepped": [str(effective_source_root)],
            "patterns_used": [p for p, _ in REGISTRATION_PATTERNS],
        },
        "warnings": warnings,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Per-chain blast-radius enumerator")
    parser.add_argument("--filed-finding-path", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--source-root", type=Path, default=None,
                        help="Source tree to grep (defaults to --workspace).")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Override output dir (defaults to <ws>/.auditooor/per_chain_blast_radius/).")
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout in addition to writing the file.")
    args = parser.parse_args(argv)

    rc, payload = run(args.filed_finding_path, args.workspace, args.source_root)

    if rc == 0:
        out_dir = args.output_dir or (args.workspace / ".auditooor" / "per_chain_blast_radius")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"{payload['finding_slug']}.json"
        out_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        payload["output_path"] = str(out_path)

    if args.json or rc != 0:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        slug = payload.get("finding_slug", "?")
        count = payload.get("blast_radius_count", 0)
        chains = ", ".join(c["name"] for c in payload.get("registered_chains", [])) or "(none)"
        print(f"[per-chain-blast-radius] {slug}: blast_radius_count={count} chains={chains}")
        print(f"[per-chain-blast-radius] output: {payload.get('output_path')}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
