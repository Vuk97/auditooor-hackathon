#!/usr/bin/env python3
"""Rule 18 / Rule 19 in-process-vs-node-level preflight.

HIGH/CRITICAL production-grade claims need production-grade execution evidence:
node, ABCI, BaseApp, real block execution, commit pipeline, or equivalent
state-machine surface. Direct keeper/handler/pallet or function-local evidence
is not enough when the claimed impact is network, consensus, matching-engine,
AppHash, state-root, block-reorg, or state-machine write-path level.

Cross-ecosystem: the built-in node-level / in-process / R19 defaults cover
cosmos-sdk (cometbft/appd), EVM clients (geth/reth/op-geth, foundry forked
mainnet, anvil/hardhat), Substrate (frame_executive/zombienet/try-runtime),
and Solana (solana-test-validator/ProgramTest/BanksClient) without per-
engagement env tuning. Env hooks only APPEND target-specific literals:
  AUDITOOOR_L32_RUBRIC_KEYWORDS    - extra R18 trigger keywords
  AUDITOOOR_L32_R19_KEYWORDS       - extra R19 trigger keywords
  AUDITOOOR_L32_NODE_LEVEL_PATTERNS- extra node-level surface patterns
  AUDITOOOR_L32_NODE_BINARY_RE     - extra node-binary names (e.g. dydxprotocold)
  AUDITOOOR_L32_IN_PROCESS_PATTERNS- extra in-process smells (e.g. ProcessSingleMatch()

Exit codes:
  0 - pass, out-of-scope, or accepted rebuttal
  1 - Rule 18/19 violation
  2 - input error
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.rebuttal_util import apply_rebuttal_gate  # noqa: E402


SCHEMA_VERSION = "auditooor.in_process_vs_node_level_check.v1"
GATE = "L32-IN-PROCESS-VS-NODE-LEVEL"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

R18_KEYWORDS = [
    r"network-level",
    r"validator(?:/full-node| full-node| node)?",
    r"full-node",
    r"node-level",
    r"consensus",
    r"chain halt",
    r"validator halt",
    r"block production",
    r"liveness failure",
    r"liveness failures",
    r"matching-engine (?:SLO|degradation|stall|halt)",
    r"settlement degradation",
    r"production-grade impact",
]

R19_KEYWORDS = [
    # --- cosmos-sdk block-lifecycle (R19-base) ---
    r"state[- ]machine write path",
    r"AppHash (?:divergence|mismatch)",
    r"block execution",
    r"commit pipeline",
    r"FinalizeBlock",
    r"DeliverTx",
    r"BeginBlocker",
    r"EndBlocker",
    # --- EVM clients (R19-extension) ---
    r"block reorg",
    r"state root mismatch",
    r"consensus split",
    r"fork-choice manipulation",
    # --- Substrate (R19-extension) ---
    r"runtime apply",
    r"block import",
    r"finality gadget stall",
]

NODE_LEVEL_PATTERNS = [
    # --- cosmos-sdk / Go ABCI (R18/R19-base) ---
    r"BroadcastTxSync",
    r"BaseApp\.FinalizeBlock",
    r"\bFinalizeBlock\(",
    r"RequestFinalizeBlock",
    r"ResponseFinalizeBlock",
    r"\bapp\.RunTx\(",
    r"\bapp\.PreBlocker\(",
    r"\bapp\.BeginBlocker\(",
    r"\bapp\.EndBlocker\(",
    r"Set(?:Begin|End|Pre)Blocker\(",
    r"AdvanceToBlock\(",
    r"network\.New\(",
    r"testutil/network",
    r"testnet\.New\(",
    r"simapp\.Setup\(",
    r"node\.NewNode",
    r"cometbft start",
    r"rootmulti\.Commit",
    r"MultiStore\.Commit",
    r"commitStores\(",
    r"\bDeliverTx\(",
    # --- Substrate node-level surfaces ---
    r"Executive::execute_block",
    r"frame_executive",
    r"BlockBuilder",
    r"sc_service::new_full",
    r"polkadot --validator",
    r"polkadot --dev",
    r"--chain\b",
    r"TestExternalities",
    r"zombienet",
    r"try-runtime",
    r"construct_runtime!",
    # --- EVM clients (geth / reth / op-stack / foundry / hardhat) ---
    r"BlockExecutor",
    r"geth --dev",
    r"reth node",
    r"\bop-geth\b",
    r"EVM::transact",
    r"vm\.createFork",
    r"vm\.createSelectFork",
    r"--fork-url",
    r"\banvil\b",
    r"hardhat node",
    r"eth_sendRawTransaction",
    # --- Solana ---
    r"bank\.process_transaction",
    r"\bProgramTest\b",
    r"solana-test-validator",
    r"\bBanksClient\b",
    # --- generic node-binary spawn (env-extensible via AUDITOOOR_L32_NODE_BINARY_RE) ---
    r"\b(?:cometbft|geth|reth|op-geth|polkadot|substrate|solana-test-validator|appd)\b",
]

IN_PROCESS_ONLY_PATTERNS = [
    # --- generic in-process / function-local smells ---
    r"in-process runtime PoC",
    r"in-process only",
    r"in-memory only",
    r"microbenchmark",
    r"function-local",
    r"direct keeper",
    r"keeper-level",
    r"directly calls? [A-Za-z0-9_.*]+Keeper",
    r"directly calls? [A-Za-z0-9_.*]+(?:Handler|Pallet)",
    r"\bkeeper\.[A-Za-z0-9_]+\(",
    r"hand-rolled branchedCtx",
    # --- EVM in-process smells ---
    r"\b(?:internal|private) function unit test",
    r"vm\.store-seeded state",
    r"\bvm\.store\(",
    r"\bno fork\b",
    # --- Substrate in-process smells ---
    r"Pallet::<T>::[A-Za-z0-9_]+\(",
    r"\bnew_test_ext\(\)",
    r"bypassing dispatch",
]

# Genuinely target-specific literals are NOT hard defaults: they live in the
# env-extension lists so a non-cosmos audit is correct without env tuning.
# AUDITOOOR_L32_IN_PROCESS_PATTERNS appends dYdX-style names like
# `ProcessSingleMatch(` / `PlacePerpetualLiquidation(` when auditing dYdX.

NEGATIVE_SCOPE_RE = re.compile(
    r"\b(?:not[_ -]?proven|not claimed|does not claim|no claim|"
    r"not in scope|not part of this report|not alleged|not demonstrated)\b",
    re.IGNORECASE,
)

REBUTTAL_RE = re.compile(r"<!--\s*(?:l32|r18|r19)-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:l32|r18|r19)[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)

CODE_SUFFIXES = {".go", ".rs", ".sol", ".ts", ".tsx", ".js", ".mjs", ".py", ".move", ".cairo", ".vy", ".log", ".txt"}


def _compile(patterns: list[str], *env_names: str) -> re.Pattern[str]:
    """Compile defaults plus any newline-separated regex from the named env vars.

    Env vars APPEND to the built-in defaults; they never replace them. This
    keeps the gate correct cross-ecosystem (cosmos / EVM / Substrate / Solana)
    out of the box, with env hooks reserved for target-specific literals only.
    """
    merged = list(patterns)
    for env_name in env_names:
        if env_name and os.environ.get(env_name):
            merged.extend(line.strip() for line in os.environ[env_name].splitlines() if line.strip())
    return re.compile("|".join(f"(?:{pattern})" for pattern in merged), re.IGNORECASE)


R18_RE = _compile(R18_KEYWORDS, "AUDITOOOR_L32_RUBRIC_KEYWORDS")
R19_RE = _compile(R19_KEYWORDS, "AUDITOOOR_L32_R19_KEYWORDS")
NODE_RE = _compile(
    NODE_LEVEL_PATTERNS,
    "AUDITOOOR_L32_NODE_LEVEL_PATTERNS",
    # AUDITOOOR_L32_NODE_BINARY_RE: env-driven node-binary regex; the default
    # node-binary alternation already ships in NODE_LEVEL_PATTERNS, this hook
    # lets an engagement add target-specific binary names (e.g. dydxprotocold).
    "AUDITOOOR_L32_NODE_BINARY_RE",
)
IN_PROCESS_RE = _compile(IN_PROCESS_ONLY_PATTERNS, "AUDITOOOR_L32_IN_PROCESS_PATTERNS")


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override and override.lower() != "auto":
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
    ):
        match = re.search(pattern, text)
        if match:
            return match.group(1).lower(), source
    name = path.name.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", name):
            return severity, "filename"
    return None, "missing"


def _workspace_root(draft: Path) -> Path:
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        if (parent / "poc-tests").is_dir() or (parent / "submissions").is_dir():
            return parent
    return draft.resolve().parent


def _clean_ref(raw: str) -> str:
    return raw.strip().strip("`'\"").rstrip(").,;:")


def _resolve_poc_paths(draft: Path, text: str, explicit: list[str]) -> list[Path]:
    root = _workspace_root(draft)
    refs = list(explicit)
    refs.extend(match.group(1) for match in re.finditer(r"<!--\s*poc-dir:\s*([^>]+?)\s*-->", text, re.IGNORECASE))
    refs.extend(
        match.group(1)
        for match in re.finditer(
            r"(?im)^\s*(?:poc[_ -]?dir|poc[_ -]?path|proof[_ -]?artifact|source[_ -]?proof|PoC directory|PoC)\s*:\s*(.+?)\s*$",
            text,
        )
    )
    refs.extend(match.group(0) for match in re.finditer(r"\b(?:poc-tests|external)/[A-Za-z0-9_.\-/]+", text))

    resolved: list[Path] = []
    for raw in refs:
        ref = _clean_ref(raw)
        if not ref or "<" in ref or ">" in ref:
            continue
        path = Path(ref).expanduser()
        candidates = [path] if path.is_absolute() else [root / path, draft.parent / path, Path.cwd() / path]
        for candidate in candidates:
            if candidate.exists() and candidate not in resolved:
                resolved.append(candidate)
                break
    return resolved


def _source_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if path.is_file() and path.suffix in CODE_SUFFIXES:
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.is_file() and p.suffix in CODE_SUFFIXES))
    return files


def _combined_text(draft: Path, draft_text: str, poc_paths: list[Path]) -> tuple[str, list[str]]:
    chunks = [draft_text]
    scanned: list[str] = []
    for path in _source_files(poc_paths):
        try:
            chunks.append(_read_text(path))
            scanned.append(str(path))
        except Exception:
            continue
    return "\n".join(chunks), scanned


def _line_hits(text: str, pattern: re.Pattern[str], *, ignore_negative: bool = False, limit: int = 16) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    for idx, line in enumerate(text.splitlines(), start=1):
        if ignore_negative and NEGATIVE_SCOPE_RE.search(line):
            continue
        match = pattern.search(line)
        if match:
            hits.append({"line": idx, "token": match.group(0), "text": line.strip()[:240]})
            if len(hits) >= limit:
                break
    return hits


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_RE.search(text)
    if not match:
        match = REBUTTAL_LINE_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


def run(
    draft: Path,
    *,
    poc_dir: list[str] | None = None,
    severity_override: str | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION,
            "gate": GATE,
            "file": str(draft),
            "verdict": "error",
            "error": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity(text, draft, severity_override)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": severity,
        "severity_source": severity_source,
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "Drive the PoC through a node/ABCI/BaseApp/block/commit surface.",
            "For state-machine write-path claims, exercise FinalizeBlock, RunTx, Begin/EndBlocker, or the real commit pipeline.",
            "Walk severity below HIGH if the proof remains function-local or keeper-only.",
            "Use <!-- l32-rebuttal: reason --> only for a bounded, source-backed exception.",
        ],
    }

    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    r18_hits = _line_hits(text, R18_RE, ignore_negative=True)
    r19_hits = _line_hits(text, R19_RE, ignore_negative=True)
    if not r18_hits and not r19_hits:
        payload["verdict"] = "pass-rubric-no-production-keyword"
        payload["reason"] = "no production-grade R18/R19 trigger keyword"
        return 0, payload

    rebuttal = _rebuttal(text)
    if apply_rebuttal_gate(payload, rebuttal):
        return 0, payload

    poc_paths = _resolve_poc_paths(draft, text, poc_dir or [])
    combined, scanned = _combined_text(draft, text, poc_paths)
    node_hits = _line_hits(combined, NODE_RE)
    in_process_hits = _line_hits(combined, IN_PROCESS_RE)
    payload["poc_paths"] = [str(path) for path in poc_paths]
    payload["evidence"] = {
        "r18_trigger_hits": r18_hits,
        "r19_trigger_hits": r19_hits,
        "node_level_hits": node_hits,
        "in_process_only_hits": in_process_hits,
        "scanned_files": scanned,
    }

    if node_hits:
        payload["verdict"] = "pass-production-grade-poc-present"
        payload["reason"] = "node/ABCI/state-machine surface evidence found"
        return 0, payload

    if not poc_paths and strict:
        payload["verdict"] = "fail-missing-poc-dir"
        payload["reason"] = "production-grade claim has no resolvable PoC path and no node-level evidence"
        return 1, payload

    payload["verdict"] = "fail-production-grade-claim-with-in-process-only-poc"
    payload["reason"] = "production-grade claim lacks node/ABCI/state-machine execution evidence"
    return 1, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--poc-dir", action="append", default=[])
    parser.add_argument("--severity", default="auto")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    rc, payload = run(
        args.draft,
        poc_dir=args.poc_dir,
        severity_override=args.severity,
        strict=args.strict,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
