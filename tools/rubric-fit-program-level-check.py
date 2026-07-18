#!/usr/bin/env python3
"""Rule 56 Rubric-Fit-At-Program-Level preflight (Check #102).

# Rule 56: this tool emits no corpus record.

GENERAL RULE - applies to MEDIUM+ drafts that reference a cosmos-sdk module /
Substrate pallet / smart-contract subsystem AS THE AFFECTED COMPONENT.

R56 catches the kill pattern: **the program lists the impact class but the
affected module is non-core for the program's product**. The impact class
exists in the rubric (R52 passes), the impact isn't DoS-class (R35 passes),
and the team hasn't acknowledged the bug (R47 passes), yet the triager
closes the finding because the affected component isn't on the program's
actual product surface.

Distinct from sibling gates:
  R52 (rubric-row-coverage)       : "no row at all" - program doesn't list this impact class
  R35 (DoS-class reframe)          : "wrong impact class" - DoS-class on a non-DoS program
  R47 (acknowledged-won't-fix)    : "team already knows"
  R56 (this rule)                  : "program lists the impact class but the module is non-core
                                     for the program's product"

Empirical anchor: dydx cantina-238 (2026-05-23) "x/feegrant revoke MEDIUM"
killed with verbatim triager rationale:
  "x/feegrant is a non-core module on dYdX v4. dYdX is a perpetual futures
   exchange where the core product is orderbook trading, matching, and
   settlement. The fee sponsorship rotation pattern (grant, revoke, re-grant
   with new expiration) is a niche operational flow on a trading chain."

The bug was real + the triager acknowledged the resurrection scenario.
The kill rationale was "non-core for THIS program's product".

Trigger: MEDIUM+ drafts that name an `affected_component:` / `module:` /
`pallet:` / `subsystem:` field, OR mention a recognizable component
pattern (e.g. `x/feegrant`, `x/clob`, `pallet-*`).

The gate:
  - Extracts the affected component from the draft.
  - Identifies the workspace and loads its SCOPE.md / PRODUCT.md / README.md.
  - Cross-checks the component against a workspace-keyed core/non-core list
    seeded for dydx / spark / hyperbridge.
  - For unknown workspaces, falls back to scanning SCOPE.md text for the
    component name and emitting a WARN-grade verdict (pass-component-context-
    unknown) so operator can curate.
  - Honors override marker `r56-rebuttal: <reason>` (<=200 chars).

Verdict vocabulary:
  pass-out-of-scope                       - severity below MEDIUM
  pass-no-component-cited                 - draft has no component reference (R56 N/A)
  pass-component-is-program-core          - component is on the program's core product surface
  pass-component-context-unknown          - workspace has no curated core list AND SCOPE.md
                                            does not name the component; warn-grade pass
  ok-rebuttal                             - r56-rebuttal marker with <=200-char reason
  fail-component-is-non-core-for-program  - component IS in workspace non-core list
  fail-no-core-product-claim              - workspace has no SCOPE.md and the draft made
                                            no core-product-claim section
  error                                   - cannot read draft or workspace

Exit codes:
  0 - pass, ok-rebuttal, pass-out-of-scope, pass-component-context-unknown
  1 - Rule 56 violation
  2 - input error

Override marker: visible line 'r56-rebuttal: <reason>' (<=200 chars) OR
HTML-comment form '<!-- r56-rebuttal: <reason> -->'. Empty or oversized
reason is ignored.

Env extension hooks:
  AUDITOOOR_R56_CORE_COMPONENTS    - newline-separated workspace=comp1,comp2,...
      e.g. "dydx=x/clob,x/perpetuals,x/prices"
      Components are matched case-insensitively as substrings.
  AUDITOOOR_R56_NONCORE_COMPONENTS - newline-separated workspace=comp1,comp2,...
      e.g. "dydx=x/feegrant,x/gov,x/upgrade"
  AUDITOOOR_R56_COMPONENT_PATTERNS - newline-separated extra regex patterns
      used to detect components in draft text.

Schema: auditooor.r56_rubric_fit_program_level.v1
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.r56_rubric_fit_program_level.v1"
GATE = "R56-RUBRIC-FIT-PROGRAM-LEVEL"

# Minimum severity to trigger.
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
MIN_SEVERITY_RANK = SEVERITY_RANK["medium"]

SCOPE_FILE_NAMES = ("SCOPE.md", "scope.md", "PRODUCT.md", "product.md", "README.md", "readme.md")

# Workspace-keyed core/non-core component lists. Substring match,
# case-insensitive. Empirical anchor: dydx cantina-238 (x/feegrant non-core).
DEFAULT_CORE_COMPONENTS: dict[str, list[str]] = {
    "dydx": [
        "x/clob",
        "x/prices",
        "x/perpetuals",
        "x/subaccounts",
        "x/sending",
        "x/assets",
        "x/affiliates",
        "x/vest",
        "x/rewards",
        "x/bridge",
        "x/delaymsg",
        "x/listing",
        "x/marketmap",
        "x/ratelimit",
        "x/revshare",
        "x/vault",
        "orderbook",
        "matching engine",
        "matching-engine",
        "settlement",
        "clearinghouse",
        "cometbft",
        "comet",
        "consensus",
        "tendermint",
        "blocksync",
        "abci",
    ],
    "spark": [
        "chain-watcher",
        "chain_watcher",
        "watch_chain",
        "coop-exit",
        "coop_exit",
        "cooperative-exit",
        "cooperative_exit",
        "claim-path",
        "claim_path",
        "claim_leaf",
        "finalize",
        "signing",
        "signer",
        "frost",
        "schnorr",
        "tweakKeysForCoopExit",
        "transfer claim",
        "settle receiver",
        "leaf-status",
        "leaf_status",
        "ssp",
        "spark operator",
        "tree-state",
        "tree state",
    ],
    "hyperbridge": [
        "ismp-optimism",
        "ismp-arbitrum",
        "ismp-bsc",
        "ismp-polygon",
        "ismp-ethereum",
        "ismp-grandpa",
        "ismp-beefy",
        "ismp-sync-committee",
        "ismp-near",
        "intentgateway",
        "intent-gateway",
        "intent_gateway",
        "consensus-client",
        "consensus_client",
        "state-machine client",
        "state_machine client",
        "state-machine-client",
        "fishermen",
        "fraud-proof",
        "fraud_proof",
        "merkle",
        "verifier",
        "state-root",
        "state_root",
        "pallet-ismp",
        "pallet-hyperbridge",
        "host-executive",
    ],
    # polymarket: prediction-market exchange (CLOB) + ConditionalTokens
    # integration + UMA oracle adapter + collateral wrappers + Vault.
    # Core surface derived directly from SCOPE.md asset table + SEVERITY.md
    # Critical/High impact rows. Confidence: HIGH (SCOPE.md unambiguous).
    "polymarket": [
        "ctfexchange",
        "ctf-exchange",
        "ctf_exchange",
        "ctfexchangev2",
        "negriskctfexchange",
        "negriskctfexchangev2",
        "negriskadapter",
        "neg-risk-adapter",
        "negriskoperator",
        "negriskumactfadapter",
        "umactfadapter",
        "uma-ctf-adapter",
        "uma_ctf_adapter",
        "feemodule",
        "fee-module",
        "fee_module",
        "negriskfeemodule",
        "calculatorhelper",
        "noncemanager",
        "nonce-manager",
        "nonce_manager",
        "userpausable",
        "user-pausable",
        "conditionaltokens",
        "conditional-tokens",
        "splitposition",
        "split-position",
        "redeempositions",
        "mergepositions",
        "collateraltoken",
        "collateral-token",
        "collateralonramp",
        "collateraloframp",
        "ctfcollateraladapter",
        "negriskctfcollateraladapter",
        "permissionedramp",
        "permissioned-ramp",
        "negriskwrappedcollateral",
        "wrappedcollateral",
        "proxyfactory",
        "safefactory",
        "vault",
        "matching engine",
        "order matching",
        "auction settlement",
        "settlement",
        "auth",
        # Wallet types used by the exchange's signature paths
        "poly_proxy",
        "poly_gnosis_safe",
        "poly_1271",
    ],
    # morpho: lending network. Core = morpho-blue (V1 $2.5M tier) + IRM +
    # vault v2 + metamorpho vaults + bundler3 + oracle factory. Non-core =
    # legacy bundlers / migration adapters / docs / test utilities. Note that
    # SCOPE.md explicitly lists migration adapters as in-scope but they are
    # NOT the program's product surface ("DeFi lending network"); the core
    # is the matching/lending engine. Confidence: HIGH for blue/vaults/IRM,
    # MEDIUM for adapters (operator-curated).
    "morpho": [
        "morpho",
        "morpho-blue",
        "morpho_blue",
        "morphoblue",
        "morpho blue",
        "vaultv2",
        "vault-v2",
        "vault_v2",
        "metamorpho",
        "metamorpho-v1.1",
        "metamorpho_v1_1",
        "metamorphofactory",
        "public-allocator",
        "publicallocator",
        "adaptive-curve-irm",
        "adaptive_curve_irm",
        "adaptive curve irm",
        "irm",
        "interest-rate-model",
        "morphomarketv1adapterv2",
        "morphovaultv1adapter",
        "morphomarketv1adapterv2factory",
        "morphovaultv1adapterfactory",
        "vaultv2factory",
        "morpho registry",
        "morphochainlinkoraclev2",
        "morpho-blue-oracles",
        "morpho_blue_oracles",
        "pre-liquidation",
        "preliquidation",
        "bundler3",
        "bundler",
        "generaladapter1",
        "ethereumgeneraladapter1",
        "erc20wrapperadapter",
        "paraswapadapter",
        "supply",
        "withdraw",
        "borrow",
        "repay",
        "liquidate",
        "matching engine",
        "lending market",
        "lending vault",
        "match-engine",
        "match_engine",
        "bad-debt accounting",
        "bad_debt_accounting",
        "bad-debt-accounting",
        "rewards emission",
        "universal rewards distributor",
        "universal-rewards-distributor",
    ],
    # base-azul: Base hardfork. Core = consensus (CL) + execution (EL) +
    # proof + builder + batcher + multiproof verifiers (TEE/ZK). The Critical
    # impact list in SCOPE.md is explicit: TEE/ZK proof verification, dispute
    # game, withdrawal proofs, state-root derivation. Non-core = infra/,
    # devnet, baseup, etc, actions, utilities (utility/tooling). Confidence:
    # HIGH (SCOPE.md "In scope" tables vs OOS carveouts unambiguous).
    "base-azul": [
        "consensus",
        "base-consensus",
        "execution",
        "base-reth-node",
        "base_reth_node",
        "proof",
        "batcher",
        "base-batcher",
        "builder",
        "base-builder",
        "engine",
        "engine-tree",
        "payload",
        "txpool",
        "txpool-rpc",
        "chainspec",
        "flashblocks",
        "evm",
        "trie",
        "storage",
        "gossip",
        "derive",
        "registry",
        "rpc",
        "safedb",
        "aggregateverifier",
        "verifier",
        "teeverifier",
        "tee-verifier",
        "nitroenclaveverifier",
        "teeproverregistry",
        "zkverifier",
        "zk-verifier",
        "multiproof",
        "dispute-game",
        "dispute_game",
        "anchorstateregistry",
        "anchor-state-registry",
        "withdrawal",
        "withdrawal-proof",
        "withdrawal_proof",
        "state-root",
        "state_root",
        "state root derivation",
        "nitrovalidator",
        "nitro-validator",
        "cbordecode",
        "certmanager",
        "bridge",
        "op-succinct",
        "op_succinct",
        "client",
        "common",
        "service",
    ],
    # sei: Cosmos-SDK + Tendermint fork with EVM. Core = x/evm (parallelized
    # EVM exec layer), x/oracle, x/dex, ABCI wiring, mempool, OCC. Non-core =
    # giga (HARD OOS per SCOPE.md), statesync peer (HARD OOS), test infra.
    # Confidence: HIGH (SCOPE.md "Excluded Giga functionality" + "Excluded
    # StateSync Peer functionality" are verbatim hard OOS).
    "sei": [
        "x/evm",
        "evm",
        "evm execution",
        "x/oracle",
        "oracle",
        "x/dex",
        "dex",
        "x/mint",
        "x/tokenfactory",
        "tokenfactory",
        "x/epoch",
        "epoch",
        "x/store",
        "store",
        "abci",
        "occ",
        "parallel execution",
        "parallel-execution",
        "parallel_execution",
        "mempool",
        "go-ethereum",
        "geth",
        "cometbft",
        "tendermint",
        "consensus",
        "matching engine",
        "state-machine",
        "state machine",
    ],
    # thegraph: indexing protocol. Smart-contracts-only program; bounty page
    # lists 35 deployed addresses. Core = packages/contracts (main protocol),
    # packages/horizon (upgrade), packages/issuance (issuance), packages/
    # subgraph-service. Non-core = packages/address-book, packages/deployment,
    # packages/hardhat-graph-protocol, packages/token-distribution, packages/
    # toolshed (tooling), packages/contracts-test. Confidence: MEDIUM-HIGH;
    # SCOPE.md lists package directories without explicit core/non-core split,
    # but the "Asset type for all 35: Smart Contract" + the audit-reports
    # directory location both signal that the contract surface is the core
    # product.
    "thegraph": [
        "contracts",
        "horizon",
        "issuance",
        "subgraph-service",
        "subgraph_service",
        "data-edge",
        "data_edge",
        "interfaces",
        "staking",
        "delegation",
        "indexer",
        "curation",
        "rewards manager",
        "rewardsmanager",
        "dispute manager",
        "disputemanager",
        "service registry",
        "serviceregistry",
        "graphtoken",
        "grt",
        "epochmanager",
        "epoch manager",
        "controller",
        "l1graphtokengateway",
        "l2graphtokengateway",
        "gns",
        "billing",
    ],
}

DEFAULT_NONCORE_COMPONENTS: dict[str, list[str]] = {
    "dydx": [
        "x/feegrant",
        "feegrant",
        "x/gov",
        "x/governance",
        "x/upgrade",
        "x/group",
        "x/nft",
        "x/crisis",
        "x/evidence",
        "x/slashing",
        "x/distribution",
        "x/mint",
        "x/staking",
        "x/authz",
    ],
    "spark": [
        "logging",
        "log infra",
        "log infrastructure",
        "metrics",
        "telemetry",
        "tracing",
        "instrumentation",
        "config loading",
        "configuration loader",
        "cli helpers",
        "doc generation",
        "test fixtures",
    ],
    "hyperbridge": [
        "call-decompressor",
        "call_decompressor",
        "validation helpers",
        "validation_helpers",
        "logging",
        "metrics",
        "rpc helpers",
        "rpc_helpers",
        "telemetry",
        "doc generation",
    ],
    # polymarket: non-core = audit scripts, deployment manifests, test
    # files (SCOPE.md explicit OOS: "Impacts on test files and configuration
    # files"), webapp surfaces / docs / dev tooling, and any third-party
    # Gnosis CTF generic bugs (explicit OOS).
    "polymarket": [
        "test files",
        "test_files",
        "test-files",
        "configuration files",
        "configuration_files",
        "deployment scripts",
        "deployment_scripts",
        "deployment-scripts",
        "polygon bridge",
        "polygon-bridge",
        "polygon_bridge",
        "dashboard",
        "telemetry",
        "metrics",
        "logging",
        "log infra",
        "documentation",
        "docs",
        "readme",
        "auxiliary scripts",
        "auxiliary-scripts",
        "auxiliary_scripts",
        "dev tooling",
        "dev-tooling",
        "scripts",
    ],
    # morpho: non-core = documentation, test utilities, helper packages.
    # SCOPE.md explicit OOS: "Issues in testing/utilities packages",
    # "Bugs in third-party contracts or applications that integrate Morpho".
    # Note: third-party integrators are OOS but the integrator-name itself
    # is not a "module" string typically cited; non-core list focuses on
    # internal surfaces. Confidence: HIGH (explicit OOS phrasing).
    "morpho": [
        "testing",
        "test utilities",
        "test_utilities",
        "test-utilities",
        "testing packages",
        "documentation",
        "docs",
        "natspec",
        "comments",
        "readme",
        "documentation issues",
        "logging",
        "metrics",
        "telemetry",
        "scripts",
        "deployment scripts",
        "rewards emission cli",
        "config",
    ],
    # base-azul: non-core = explicit SCOPE.md carveouts. /actions, /devnet,
    # /baseup, /etc are explicitly OOS per SCOPE.md L42; op-node, op-geth,
    # op-batcher, op-reth, Optimism audit code are explicitly OOS per L39;
    # ZK prover internals + Op-Succinct core (only Base's changes are in-
    # scope) are explicitly OOS per L40-41. Confidence: HIGH (verbatim
    # SCOPE.md OOS list).
    "base-azul": [
        "actions",
        "devnet",
        "baseup",
        "etc",
        "infra",
        "utilities",
        "op-node",
        "op_node",
        "op-geth",
        "op_geth",
        "op-batcher",
        "op_batcher",
        "op-reth",
        "op_reth",
        "sp1",
        "succinct prover network",
        "succinct-prover-network",
        "zk circuits",
        "zk-circuits",
        "zk_circuits",
        "logging",
        "metrics",
        "telemetry",
        "documentation",
        "docs",
        "readme",
        "scripts",
        "deployment manifests",
    ],
    # sei: non-core = HARD OOS (giga package + statesync peer) per SCOPE.md
    # L62-77 verbatim, plus typical operational surfaces. Confidence: HIGH
    # (verbatim "Excluded Giga functionality" + "Excluded StateSync Peer
    # functionality" sections in SCOPE.md).
    "sei": [
        "giga",
        "giga package",
        "x/giga",
        "statesync peer",
        "state-sync peer",
        "state_sync_peer",
        "statesync_peer",
        "p2p state sync",
        "p2p-state-sync",
        "p2p_state_sync",
        "x/crisis",
        "x/evidence",
        "x/feegrant",
        "feegrant",
        "x/gov",
        "x/group",
        "x/upgrade",
        "x/nft",
        "x/authz",
        "x/distribution",
        "x/slashing",
        "logging",
        "telemetry",
        "metrics",
        "docs",
        "documentation",
    ],
    # thegraph: non-core = address-book (deployment metadata), deployment
    # (deployment scripts), hardhat-graph-protocol (dev tooling), token-
    # distribution (one-off distribution scripts), toolshed (helpers),
    # contracts-test (test utilities). Confidence: MEDIUM (SCOPE.md lists
    # all packages without explicit core/non-core but tooling/test packages
    # are conventionally non-core for smart-contract bounties).
    "thegraph": [
        "address-book",
        "address_book",
        "addressbook",
        "deployment",
        "deployments",
        "deployment scripts",
        "hardhat-graph-protocol",
        "hardhat_graph_protocol",
        "hardhat plugin",
        "token-distribution",
        "token_distribution",
        "vesting",
        "toolshed",
        "contracts-test",
        "contracts_test",
        "test utilities",
        "test_utilities",
        "logging",
        "metrics",
        "telemetry",
        "docs",
        "documentation",
        "readme",
        "subgraph tooling",
        "subgraph-tooling",
    ],
}


# Field extractors: affected_component, module, pallet, subsystem
COMPONENT_FIELD_RE = re.compile(
    r"(?im)^\s*[-*]?\s*(?:affected[_ ]component|module|pallet|subsystem|"
    r"affected[_ ]module|affected[_ ]pallet|affected[_ ]subsystem|"
    r"impacted[- ]surface|impacted[_ ]surface|affected[_ ]surface)\s*:\s*(.+?)(?:\n|$)"
)

# Recognizable component-name patterns (cosmos x/*, Substrate pallet-*, smart-contract subsystems)
COMPONENT_PATTERN_RE = re.compile(
    r"\b(?:"
    r"x/[a-z][a-z0-9_-]*|"
    r"pallet[-_][a-z][a-z0-9_-]*|"
    r"ismp-[a-z][a-z0-9_-]*"
    r")\b",
    re.IGNORECASE,
)

# Core-product claim section header
CORE_PRODUCT_SECTION_RE = re.compile(
    r"(?im)^#+\s*(?:core[- ]product[- ]claim|program[- ]core[- ]product|core[- ]component[- ]claim|"
    r"product[- ]surface[- ]claim)",
)

# Rebuttal patterns
REBUTTAL_HTML_RE = re.compile(
    r"<!--\s*r56-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL
)
REBUTTAL_LINE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?r56[-_ ]rebuttal\s*:\s*(.+?)\s*$"
)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _env_lines(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw.strip():
        return []
    return [item.strip() for item in raw.splitlines() if item.strip()]


def _env_overrides(name: str) -> dict[str, list[str]]:
    """Parse env override of the form 'workspace=comp1,comp2,...' per line."""
    out: dict[str, list[str]] = {}
    for line in _env_lines(name):
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        items = [c.strip() for c in val.split(",") if c.strip()]
        if key.strip() and items:
            out[key.strip().lower()] = items
    return out


def _merge_component_lists(default: dict[str, list[str]], override: dict[str, list[str]]) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {k: list(v) for k, v in default.items()}
    for ws, comps in override.items():
        merged.setdefault(ws, []).extend(comps)
    return merged


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override:
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    for pattern, source in (
        (r"(?im)^\s*\**\s*Severity\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-header"),
        (r"(?im)^\s*severity_implied\s*:\s*(Critical|High|Medium|Low)\b", "program-impact-mapping"),
        (r"(?im)^\s*severity_tier\s*:\s*(Critical|High|Medium|Low)\b", "impact-contract"),
        (r"(?im)^\s*selected_severity\s*:\s*(Critical|High|Medium|Low)\b", "selected-severity"),
        (r"(?im)^\s*\**\s*Severity\s+selector\s*:\**\s*(Critical|High|Medium|Low)\b", "severity-selector"),
    ):
        m = re.search(pattern, text)
        if m:
            return m.group(1).lower(), source
    for sev in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){sev}(?:[-_.]|$)", path.name.lower()):
            return sev, "filename"
    return None, "missing"


def _detect_workspace(workspace: Path | None, draft: Path) -> str | None:
    """Infer the workspace identifier (lowercase short name)."""
    # 1. Explicit workspace path: use the final directory name.
    if workspace:
        name = workspace.resolve().name.lower()
        if name:
            return name
    # 2. Walk up from draft looking for a known parent under /audits/<ws>/
    for parent in draft.resolve().parents:
        # /Users/wolf/audits/dydx/...
        if parent.parent.name.lower() == "audits":
            return parent.name.lower()
    # 3. Fallback: workspace marker file
    for parent in draft.resolve().parents:
        if any((parent / m).exists() for m in ("SCOPE.md", "SEVERITY.md")):
            return parent.name.lower()
    return None


def _find_scope_files(workspace: Path | None, draft: Path) -> list[Path]:
    """Return any SCOPE.md / PRODUCT.md / README.md found near the draft."""
    candidates: list[Path] = []
    roots: list[Path] = []
    if workspace:
        roots.append(workspace.resolve())
    # Walk up from draft
    cur = draft.resolve().parent
    for parent in [cur, *cur.parents]:
        roots.append(parent)
    seen: set[Path] = set()
    for root in roots:
        if root in seen:
            continue
        seen.add(root)
        for name in SCOPE_FILE_NAMES:
            candidate = root / name
            if candidate.is_file():
                candidates.append(candidate)
    return candidates


def _rebuttal(text: str) -> str | None:
    m = REBUTTAL_LINE_RE.search(text)
    if not m:
        m = REBUTTAL_HTML_RE.search(text)
    if not m:
        return None
    return " ".join(m.group(1).split())


def _extract_components(text: str) -> list[str]:
    """Return all component names cited by the draft, dedup'd, in citation order."""
    found: list[str] = []
    seen: set[str] = set()

    # 1. Explicit fields. For each match, extract only the bounded
    # component identifier(s) (x/<module>, pallet-<name>, ismp-<name>) from
    # the value, or accept a short single-word/dash-word/dot-word token.
    for m in COMPONENT_FIELD_RE.finditer(text):
        val = m.group(1).strip()
        # Pull all recognizable tokens out of the value first.
        token_hits = [t.group(0) for t in COMPONENT_PATTERN_RE.finditer(val)]
        if token_hits:
            for tok in token_hits:
                key = tok.lower()
                if key not in seen:
                    seen.add(key)
                    found.append(tok)
            continue
        # No structured tokens; accept only a short ident-like value.
        for part in re.split(r"[;,]", val):
            piece = part.strip().strip("`").strip()
            piece = re.split(r"[(:]|\s+-\s+", piece, maxsplit=1)[0].strip()
            piece = piece.rstrip(".,;` ")
            if not piece:
                continue
            # Reject prose (anything with whitespace + multi-word) and very long entries.
            if len(piece) > 60 or " " in piece.strip():
                continue
            key = piece.lower()
            if key not in seen:
                seen.add(key)
                found.append(piece)

    # 2. Recognizable patterns anywhere in the text.
    extra_patterns: list[re.Pattern[str]] = [COMPONENT_PATTERN_RE]
    for raw in _env_lines("AUDITOOOR_R56_COMPONENT_PATTERNS"):
        try:
            extra_patterns.append(re.compile(raw, re.IGNORECASE))
        except re.error:
            continue

    for pat in extra_patterns:
        for m in pat.finditer(text):
            p = m.group(0).strip()
            if p and p.lower() not in seen:
                seen.add(p.lower())
                found.append(p)

    return found


def _classify_component(
    component: str,
    workspace: str | None,
    core_map: dict[str, list[str]],
    noncore_map: dict[str, list[str]],
) -> str:
    """Return 'core' / 'noncore' / 'unknown' for the given component."""
    if not workspace:
        return "unknown"
    comp_lower = component.lower()
    noncore = noncore_map.get(workspace, [])
    for nc in noncore:
        if nc.lower() in comp_lower or comp_lower in nc.lower():
            return "noncore"
    core = core_map.get(workspace, [])
    for c in core:
        if c.lower() in comp_lower or comp_lower in c.lower():
            return "core"
    return "unknown"


def _scope_mentions_component(scope_text: str, component: str) -> bool:
    comp_lower = component.lower()
    text_lower = scope_text.lower()
    # Direct substring
    if comp_lower in text_lower:
        return True
    # x/feegrant -> feegrant
    if comp_lower.startswith("x/"):
        if comp_lower[2:] in text_lower:
            return True
    # pallet-foo -> foo
    if comp_lower.startswith("pallet-") or comp_lower.startswith("pallet_"):
        if comp_lower[7:] in text_lower:
            return True
    return False


def _has_core_product_claim_section(text: str) -> bool:
    return bool(CORE_PRODUCT_SECTION_RE.search(text))


def run(
    draft: Path,
    *,
    workspace: Path | None = None,
    severity_override: str | None = None,
    strict: bool = False,
) -> tuple[int, dict[str, Any]]:
    """Run the R56 gate. Returns (exit_code, payload)."""
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
    workspace_name = _detect_workspace(workspace, draft)

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "gate": GATE,
        "file": str(draft),
        "severity": severity,
        "severity_source": severity_source,
        "workspace": workspace_name,
        "strict": strict,
        "evidence": {},
        "remediation_options": [
            "If the affected component truly is non-core for the program's product, drop the finding.",
            "If the component is core but is misclassified, add a '## Core Product Claim' section "
            "to the draft citing SCOPE.md / PRODUCT.md / README evidence showing the component is "
            "on the program's revenue/product surface.",
            "Override: visible line 'r56-rebuttal: <reason>' (<=200 chars) "
            "or <!-- r56-rebuttal: <reason> -->.",
        ],
    }

    # Severity below MEDIUM -> pass-out-of-scope.
    if severity is None or SEVERITY_RANK[severity] < MIN_SEVERITY_RANK:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below MEDIUM; R56 not applicable"
        return 0, payload

    # Rebuttal check
    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 200:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

    # Extract components.
    components = _extract_components(text)
    payload["evidence"]["components_cited"] = components

    if not components:
        payload["verdict"] = "pass-no-component-cited"
        payload["reason"] = (
            "draft does not cite an affected component (module/pallet/subsystem); "
            "R56 component-scope check not applicable"
        )
        return 0, payload

    # Load core/non-core lists with env overrides.
    core_map = _merge_component_lists(
        DEFAULT_CORE_COMPONENTS,
        _env_overrides("AUDITOOOR_R56_CORE_COMPONENTS"),
    )
    noncore_map = _merge_component_lists(
        DEFAULT_NONCORE_COMPONENTS,
        _env_overrides("AUDITOOOR_R56_NONCORE_COMPONENTS"),
    )

    # Read available scope files for context (used for unknown-workspace warn-grade pass).
    scope_files = _find_scope_files(workspace, draft)
    scope_texts: list[tuple[Path, str]] = []
    for p in scope_files:
        try:
            scope_texts.append((p, _read_text(p)))
        except Exception:
            continue
    payload["evidence"]["scope_files_read"] = [str(p) for p, _ in scope_texts]

    # Classify each component.
    classifications: list[dict[str, str]] = []
    for comp in components:
        cls = _classify_component(comp, workspace_name, core_map, noncore_map)
        classifications.append({"component": comp, "classification": cls})
    payload["evidence"]["classifications"] = classifications

    # Decision logic.
    noncore_hits = [c for c in classifications if c["classification"] == "noncore"]
    core_hits = [c for c in classifications if c["classification"] == "core"]
    unknown_hits = [c for c in classifications if c["classification"] == "unknown"]

    if noncore_hits:
        # At least one cited component is in this workspace's non-core list.
        # Allow rescue if the draft includes an explicit Core Product Claim
        # section asserting the bug still impacts the core product surface.
        if _has_core_product_claim_section(text):
            payload["verdict"] = "pass-component-is-program-core"
            payload["reason"] = (
                f"component(s) {[c['component'] for c in noncore_hits]!r} are normally non-core, "
                f"but draft includes a 'Core Product Claim' section asserting product-surface impact"
            )
            payload["evidence"]["core_product_claim_present"] = True
            return 0, payload
        payload["verdict"] = "fail-component-is-non-core-for-program"
        payload["reason"] = (
            f"component(s) {[c['component'] for c in noncore_hits]!r} are non-core "
            f"for workspace '{workspace_name}'; add a '## Core Product Claim' "
            f"section with SCOPE.md/PRODUCT.md citation or drop the finding"
        )
        return 1, payload

    if core_hits:
        payload["verdict"] = "pass-component-is-program-core"
        payload["reason"] = (
            f"component(s) {[c['component'] for c in core_hits]!r} are core for workspace "
            f"'{workspace_name}'"
        )
        return 0, payload

    # All unknown classifications. Fall back to SCOPE.md mention check.
    if scope_texts:
        any_mention = False
        mentions: list[str] = []
        for _, t in scope_texts:
            for comp in components:
                if _scope_mentions_component(t, comp):
                    any_mention = True
                    mentions.append(comp)
        if any_mention:
            payload["verdict"] = "pass-component-context-unknown"
            payload["reason"] = (
                f"component(s) cited but not classified by R56 curated lists; "
                f"SCOPE.md mentions {sorted(set(mentions))!r} - treating as warn-grade pass; "
                f"operator should curate workspace='{workspace_name}' core/non-core lists"
            )
            return 0, payload

    # No scope text at all and no curated classification.
    if not scope_texts and not workspace_name:
        # No curated list, no SCOPE.md, no workspace -> require core-product claim section
        if _has_core_product_claim_section(text):
            payload["verdict"] = "pass-component-is-program-core"
            payload["reason"] = "Core Product Claim section present"
            return 0, payload
        payload["verdict"] = "fail-no-core-product-claim"
        payload["reason"] = (
            "no SCOPE.md / PRODUCT.md / README found and workspace cannot be "
            "identified; add a '## Core Product Claim' section to the draft"
        )
        return 1, payload

    payload["verdict"] = "pass-component-context-unknown"
    payload["reason"] = (
        f"component(s) cited but workspace '{workspace_name}' has no curated "
        f"core/non-core list and SCOPE.md does not name the components; warn-grade pass "
        f"(operator should curate)"
    )
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--workspace", type=Path, default=None,
                        help="Path to workspace root (containing SCOPE.md)")
    parser.add_argument(
        "--severity",
        choices=["auto", "Critical", "High", "Medium", "Low",
                 "critical", "high", "medium", "low"],
        default="auto",
    )
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    override = None if args.severity == "auto" else args.severity
    rc, payload = run(
        args.draft,
        workspace=args.workspace,
        severity_override=override,
        strict=args.strict,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    if not args.json:
        sys.stderr.write(
            f"[{GATE}] {payload.get('verdict')}: "
            f"{payload.get('reason', payload.get('error', ''))}\n"
        )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
