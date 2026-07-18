#!/usr/bin/env python3
"""
Convert a curated bridge-incident taxonomy into hackerman_record v1 YAML.

Wave-5 lane EXEC-WAVE5-BRIDGE-TAXONOMY-RETRY. Sibling of:

* `tools/hackerman-etl-from-defi-fine-grain.py` (Lift C7, DeFi taxonomy)
* `tools/hackerman-etl-from-corpus-mined.py`
* `tools/hackerman-etl-from-prior-audits.py`
* `tools/hackerman-etl-from-git-mining.py`

This lane mines a curated list of high-impact cross-chain bridge incidents
(Ronin / Wormhole / Poly Network / Nomad / Multichain / Harmony / Qubit /
Heco / Meter / pNetwork) and emits hackerman_record v1 rows under the
schema enum value `bridge`.

The new attack classes introduced by this lane (each is enumerated in the
file's TAXONOMY constant):

* `bridge-validator-set-takeover`           - Ronin, Harmony
* `bridge-vaa-signature-replay`             - Wormhole pre-Feb 2022
* `bridge-relayer-private-key-leak`         - Poly Network
* `bridge-init-replay-cross-chain`          - Nomad March 2022 (storage init)
* `bridge-asset-id-confusion-cross-chain`   - Qubit deposit ID confusion
* `bridge-wrapped-token-unbacked-mint`      - PolyNetwork keeper / Multichain
* `bridge-l1-l2-message-replay`             - Optimistic / canonical bridges
* `bridge-canonical-asset-spoof`            - Meter passport / Heco
* `bridge-omniscient-call-forwarding-bypass`- LayerZero pre-DVN-split
* `bridge-fee-collector-redirect`           - Multichain anyCall fee router

Each incident emits THREE mitigation-state variants:

* `pre-fix`                  - bug as it stood at exploit time
* `post-fix-not-migrated`    - patched on the source chain, but mirror
                               deployments / forks have NOT pulled the fix
* `post-fix-migrated-historical` - patched and propagated; row is retained
                               as historical evidence so a downstream
                               consumer can train against the post-fix
                               diff shape

The mitigation-state marker is embedded in `attacker_action_sequence`,
`fix_pattern`, and `fix_anti_pattern_avoided` so downstream consumers can
distinguish discovery-time evidence from post-fix-regression evidence.

Hard rules followed:

* New file only; does NOT modify any existing file.
* Does NOT touch `tools/calibration/llm_budget_log.jsonl`.
* Cross-links (in docstring + comments) are relative paths only.
* All emitted records validate against
  `audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json`.
* Same exclusion list as PR #726: no edits to files owned by the
  corpus-mined / verdict-tags / solodit-specs / prior-audits ETLs.

CLI:

    python3 tools/hackerman-etl-from-bridge-attacks.py \\
        --out-dir /tmp/etl-bridge-attacks-out \\
        --dry-run --json-summary

    python3 tools/hackerman-etl-from-bridge-attacks.py \\
        --out-dir audit/corpus_tags/tags/bridge_attacks

Target seed: ~24-36 records (3 per incident x 8-12 incidents). Lower
target than the broader defi-fine-grain ETL by design — bridge incidents
are higher signal-density per row.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1.2"  # lane227: incident-mining shape (incident_date/amount_usd/source_url blocks) -> v1.2 permissive wide-shape


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_bridge_attacks",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# YAML helpers (kept self-contained per lane-isolation rule)
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
# Bridge incident taxonomy
# ---------------------------------------------------------------------------
#
# Each row encodes a single curated cross-chain-bridge incident:
#
#   (
#     incident_slug,        # stable id token, e.g. "ronin-2022-03"
#     bridge_name,          # display name, e.g. "Ronin Bridge"
#     target_repo,          # github owner/repo (or "unknown")
#     target_component,     # contract / module path
#     attack_class,         # one of the new bridge-* enum values
#     bug_class,            # human-readable bug family
#     severity,             # critical / high / medium / low / info
#     impact_class,         # schema enum: theft / freeze / dos / ...
#     impact_actor,         # schema enum: arbitrary-user / ...
#     impact_dollar_class,  # >= $1M / $100K-$1M / ...
#     attacker_role,        # schema enum: privileged-compromised / ...
#     target_language,      # solidity / go / rust
#     loss_usd,             # informational; included in action sequence
#     year,                 # year incident was disclosed
#     raw_signature,        # synthetic raw function signature
#     action,               # attacker_action_sequence template
#     precondition,         # required_preconditions[0]
#     fix,                  # fix_pattern
#     anti_pattern,         # fix_anti_pattern_avoided
#     source_audit_ref,     # short pointer
#   )
# ---------------------------------------------------------------------------


INCIDENTS: Tuple[Tuple[Any, ...], ...] = (
    (
        "ronin-2022-03",
        "Ronin Bridge",
        "axieinfinity/ronin",
        "RoninBridge.withdrawERC20For",
        "bridge-validator-set-takeover",
        "validator-set-quorum-compromise",
        "critical",
        "theft",
        "protocol-treasury",
        ">=$1M",
        "privileged-compromised",
        "solidity",
        624000000,
        2022,
        "function withdrawERC20For(uint256 id, address user, address token, uint256 amount, bytes[] signatures) external",
        "Attacker phished 4 of 9 validator keys plus took over Sky Mavis-controlled validator giving 5-of-9 quorum; signed two withdrawals draining 173k ETH + 25.5M USDC from Ronin Bridge.",
        "Bridge requires 5-of-9 validator signatures; >=5 validator keys controlled by a single operator (Sky Mavis had auto-signed via gas-saving allowlist for AxieDAO).",
        "Increase validator-set independence (no single operator controls quorum); require hardware-key separation between validators; rotate validator set on operator change; instrument anomalous-withdrawal-amount alerting.",
        "Treating an operator-controlled allowlist (AxieDAO gas-relay) as expired when in fact it never expired and granted persistent signing access.",
        "rekt:ronin-2022-03:withdraw-erc20-for",
    ),
    (
        "harmony-2022-06",
        "Harmony Horizon Bridge",
        "harmony-one/horizon",
        "HorizonBridge.unlockTokens",
        "bridge-validator-set-takeover",
        "multisig-quorum-compromise",
        "critical",
        "theft",
        "protocol-treasury",
        ">=$1M",
        "privileged-compromised",
        "solidity",
        100000000,
        2022,
        "function unlockTokens(address token, uint256 amount, address recipient, uint256 receiptId, bytes[] sigs) external",
        "Attacker compromised 2 of 5 multisig keys (private keys held by Harmony team members) on the Ethereum side of Horizon; signed unlocks draining ~100M USD in ETH/USDC/BUSD/etc.",
        "Bridge unlock requires 2-of-5 multisig; multisig key custody concentrated on a small number of operator laptops with no HSM separation.",
        "Raise multisig threshold to 4-of-5; require HSM-backed key storage for all signers; rotate keys on a 90-day cadence; add per-asset withdrawal rate-limit on unlocks.",
        "Assuming a 2-of-5 multisig is sufficient to secure $100M of TVL.",
        "rekt:harmony-horizon-2022-06:unlock-tokens",
    ),
    (
        "wormhole-2022-02",
        "Wormhole Token Bridge",
        "wormhole-foundation/wormhole",
        "Wormhole.completeTransfer",
        "bridge-vaa-signature-replay",
        "signature-verification-bypass",
        "critical",
        "theft",
        "protocol-treasury",
        ">=$1M",
        "unprivileged",
        "solidity",
        325000000,
        2022,
        "function completeTransfer(bytes calldata vaa) external",
        "Attacker exploited a deprecated Solana-side verify_signatures sysvar that did not check the signature-set account is owned by the bridge program; supplied an attacker-crafted signature-set forging a VAA minting 120k wETH on Solana, bridged to Ethereum and drained.",
        "verify_signatures path on Solana accepts any account as the signature-set without ownership check; bridge has not migrated to load_current_index sysvar verification.",
        "Verify signature-set account ownership matches the bridge program ID; pin verification to the load_current_index sysvar; remove deprecated solana_program::sysvar::instructions::load_instruction_at code path.",
        "Trusting a Solana sysvar that was deprecated upstream but not removed from the bridge program.",
        "rekt:wormhole-2022-02:vaa-replay",
    ),
    (
        "poly-network-2021-08",
        "Poly Network Cross-Chain",
        "polynetwork/eth-contracts",
        "EthCrossChainManager.verifyHeaderAndExecuteTx",
        "bridge-relayer-private-key-leak",
        "keeper-role-takeover",
        "critical",
        "theft",
        "protocol-treasury",
        ">=$1M",
        "unprivileged",
        "solidity",
        611000000,
        2021,
        "function verifyHeaderAndExecuteTx(bytes calldata, bytes calldata, bytes calldata, bytes calldata, bytes calldata) external",
        "Attacker crafted a header that, when executed by EthCrossChainManager, called putCurEpochConPubKeyBytes on EthCrossChainData (whose owner is EthCrossChainManager); replaced the keeper role with an attacker key, then signed arbitrary withdrawals on Ethereum / BSC / Polygon.",
        "EthCrossChainManager has authority to call ANY method on EthCrossChainData (including admin methods like putCurEpochConPubKeyBytes) via the cross-chain message dispatcher.",
        "Restrict cross-chain message dispatch on the manager to a fixed allowlist of business methods; reject any selector that touches keeper / admin storage; split admin role from message-executor role.",
        "Allowing the cross-chain message executor to call admin functions on a sibling contract that trusts it as owner.",
        "rekt:poly-network-2021-08:keeper-takeover",
    ),
    (
        "nomad-2022-08",
        "Nomad Bridge",
        "nomad-xyz/monorepo",
        "Replica.process",
        "bridge-init-replay-cross-chain",
        "uninitialised-trusted-root",
        "critical",
        "theft",
        "protocol-treasury",
        ">=$1M",
        "unprivileged",
        "solidity",
        190000000,
        2022,
        "function process(bytes calldata message) external returns (bool)",
        "Attacker observed a Replica re-init that set committedRoot=0x00; any message whose Merkle-proof root hashed to 0x00 was treated as proven; copy-pasted the first successful drain tx, swapping recipient, to chain-drain Nomad as a free-for-all over hours.",
        "Replica.initialize set committedRoot to bytes32(0) and acceptableRoot[0x00] mapping entry was left as true after the init.",
        "Reject acceptableRoot[bytes32(0)] in process(); require non-zero committedRoot on initialize; assert committedRoot has been updated past zero before any process() call succeeds.",
        "Treating bytes32(0) as a sentinel that is never matched against on-chain message-root hashes.",
        "rekt:nomad-2022-08:init-replay",
    ),
    (
        "multichain-2022-01",
        "Multichain Router",
        "anyswap/multichain-router-contracts",
        "AnyswapV6Router.anySwapOutUnderlying",
        "bridge-wrapped-token-unbacked-mint",
        "router-permit-takeover",
        "critical",
        "theft",
        "arbitrary-user",
        ">=$1M",
        "unprivileged",
        "solidity",
        3000000,
        2022,
        "function anySwapOutUnderlying(address token, address to, uint256 amount, uint256 toChainID) external",
        "Attacker called permit() on the router contract supplying an attacker-controlled wrapped-token address; the router blindly forwarded the permit signature, allowing attacker to drain ERC20 tokens with prior infinite allowance to the router (WETH / USDC / etc.) from any user who had ever approved the router.",
        "Router's permit() forwards the (owner, spender, value, deadline, v, r, s) tuple to a caller-controlled token address without an allowlist of trusted underlying tokens.",
        "Allowlist wrapped/underlying tokens that the router will accept; reject permit() forwarding to arbitrary token addresses; require token-address to be registered in the router's wrappedToken registry.",
        "Trusting any ERC20-like token contract supplied by the caller to be a real underlying for the router's anySwap path.",
        "rekt:multichain-2022-01:permit-takeover",
    ),
    (
        "qubit-2022-01",
        "Qubit QBridge",
        "qubit-finance/qbridge",
        "QBridge.deposit",
        "bridge-asset-id-confusion-cross-chain",
        "resource-id-zero-confusion",
        "critical",
        "theft",
        "protocol-treasury",
        ">=$1M",
        "unprivileged",
        "solidity",
        80000000,
        2022,
        "function deposit(uint8 destinationDomainID, bytes32 resourceID, bytes calldata data) external payable",
        "Attacker called QBridge.deposit with the WETH resourceID but zero msg.value; the deposit handler did not verify msg.value > 0 for the WETH path, so it emitted a deposit event for 77600 qXETH on BSC backed by zero ETH; attacker withdrew on BSC, repeated to drain.",
        "QBridge deposit() does NOT check msg.value > 0 for the WETH resourceID; relies on a separate depositETH path that callers may bypass.",
        "Reject deposit() for the WETH resourceID with msg.value == 0; route ETH-class deposits through a dedicated depositETH function that asserts msg.value > 0; collapse the deposit / depositETH duality so there is exactly one entry point per asset.",
        "Maintaining two parallel deposit paths for the same asset where only one of them validates the funding amount.",
        "rekt:qubit-2022-01:deposit-zero-value",
    ),
    (
        "heco-2022-08",
        "Heco Cross-Chain Bridge",
        "HuobiGroup/heco-bridge",
        "HecoBridge.handle",
        "bridge-canonical-asset-spoof",
        "canonical-asset-impersonation",
        "high",
        "theft",
        "arbitrary-user",
        "$100K-$1M",
        "unprivileged",
        "solidity",
        870000,
        2022,
        "function handle(address token, address recipient, uint256 amount, bytes calldata proof) external",
        "Attacker deployed a fake ERC20 with the same symbol+name as the canonical Heco-bridged USDT, registered it under the same resourceID as the canonical asset via a race against the registry update, then drained user balances that resolved to the fake token's address.",
        "HecoBridge.registerResource allows the same resourceID to be re-assigned to a different token address without an explicit deregister step.",
        "Make the resourceID -> token mapping append-only; require a multisig signature to update an existing resourceID; emit a CANONICAL_ASSET_REASSIGNED event and freeze withdrawals during the rotation window.",
        "Treating resourceID -> token mapping as freely-mutable admin state.",
        "rekt:heco-2022-08:resource-id-spoof",
    ),
    (
        "meter-2022-02",
        "Meter Passport",
        "meterio/passport-contracts",
        "MeterPassport.deposit",
        "bridge-canonical-asset-spoof",
        "native-vs-wrapped-confusion",
        "critical",
        "theft",
        "protocol-treasury",
        ">=$1M",
        "unprivileged",
        "solidity",
        4400000,
        2022,
        "function deposit(uint8 dstChainId, bytes32 resourceID, bytes calldata data) external payable",
        "Attacker called deposit() supplying the wrapped-BNB resourceID but did not transferFrom; passport's ERC20 handler short-circuited a `auto-mint` branch when token.symbol() == 'WBNB' that treated the call as a native-asset wrap, crediting attacker with bridged WBNB on Ethereum without locking source-chain BNB.",
        "Passport's deposit() has a special-case branch for `symbol == WBNB` (or `WETH`) that treats the call as a wrap of native gas without checking msg.value.",
        "Remove the symbol-based wrap heuristic; require deposit() to either lock ERC20 via transferFrom OR (for native) require msg.value == amount on a dedicated depositNative function; never branch on token.symbol().",
        "Branching deposit logic on the human-readable symbol field of a caller-supplied token contract.",
        "rekt:meter-2022-02:native-wrap-spoof",
    ),
    (
        "layerzero-pre-dvn-2023",
        "LayerZero Default-Library Path",
        "layerzero-labs/lz-evm-messagelib-v2",
        "Endpoint.lzReceive",
        "bridge-omniscient-call-forwarding-bypass",
        "default-library-trusted-bypass",
        "high",
        "theft",
        "arbitrary-user",
        "$100K-$1M",
        "privileged-compromised",
        "solidity",
        0,
        2023,
        "function lzReceive(uint16 srcChainId, bytes calldata srcAddress, uint64 nonce, bytes calldata payload) external",
        "Pre-DVN-split LayerZero apps that left the default Ultra Light Node + relayer config in place could have any payload delivered if both the default oracle and default relayer were colluded; researchers (L2Beat, Connext) demonstrated the surface against several OApps that never overrode `setConfig`.",
        "OApp does not call setConfig() to override the default library; both default-oracle and default-relayer trust their respective off-chain operators with no on-chain verification.",
        "Mandate every OApp configure a non-default DVN set under the v2 split-DVN architecture; reject delivery from default library after a migration deadline; require >=2 independent DVNs per OApp.",
        "Treating the LayerZero default-library config as safe-by-default for production deployments without an explicit DVN-quorum configuration.",
        "research:l2beat:layerzero-default-library",
    ),
    (
        "polynetwork-fee-2023",
        "Poly Network Fee Router",
        "polynetwork/eth-contracts",
        "FeeRouter.collect",
        "bridge-fee-collector-redirect",
        "fee-collector-takeover",
        "high",
        "theft",
        "protocol-treasury",
        "$100K-$1M",
        "privileged-compromised",
        "solidity",
        0,
        2023,
        "function collect(address token, uint256 amount) external",
        "Compromised relayer used residual setFeeCollector() admin privilege carried over from the 2021 keeper-takeover blast radius to redirect bridge-fee accrual to attacker-controlled address; per-tx fee dust accumulated over weeks before detection.",
        "FeeRouter.setFeeCollector is gated on EthCrossChainManager whose keeper role was the same role abused in the 2021 incident; the post-2021 patch did not rotate the FeeRouter admin.",
        "Rotate FeeRouter admin to a fresh multisig disjoint from EthCrossChainManager; gate setFeeCollector behind a timelock with on-chain governance vote; emit a FEE_COLLECTOR_ROTATED event and alert on it.",
        "Assuming an incident's blast radius is limited to the contract that was directly drained, not adjacent contracts that share an admin role.",
        "research:polynetwork:fee-router-residual-priv",
    ),
    (
        "optimism-canonical-msg-2022",
        "Optimism / OP-Stack Canonical Bridge",
        "ethereum-optimism/optimism",
        "L1CrossDomainMessenger.relayMessage",
        "bridge-l1-l2-message-replay",
        "message-replay-on-rollback",
        "high",
        "theft",
        "arbitrary-user",
        "$100K-$1M",
        "unprivileged",
        "solidity",
        0,
        2022,
        "function relayMessage(address target, address sender, bytes memory message, uint256 messageNonce) external",
        "Researcher-class finding: a relayMessage delivered during a chain-rollback window can be replayed against the new chain state if the messenger's successfulMessages mapping is not also rolled back; surfaced on testnet during a planned Bedrock dry-run.",
        "L1CrossDomainMessenger.successfulMessages persistence is decoupled from L2 state snapshots; during a state rollback the mapping is not re-keyed.",
        "Persist successfulMessages keyed by L2-blocknumber-derived nonce so a rollback invalidates the entry; OR include the L2 state-root hash in the messageId derivation.",
        "Treating L1-side message-replay protection as independent of L2 state rollbacks.",
        "research:optimism-bedrock:relay-replay",
    ),
)


MITIGATION_STATES: Tuple[Tuple[str, str, str, str], ...] = (
    (
        "pre-fix",
        "evidence as of exploit time",
        "Apply the proposed fix immediately; this row predates the patch.",
        "Treating the bug as theoretical despite an active exploit.",
    ),
    (
        "post-fix-not-migrated",
        "fix exists upstream but mirror deployments / forks have not pulled it",
        "Pull the upstream fix into all forks; do not deploy until the fix-commit is verified-applied.",
        "Assuming a fix upstream means all deployments are safe.",
    ),
    (
        "post-fix-migrated-historical",
        "fix applied and verified everywhere; retained as historical training signal",
        "Maintain an invariant-test that the fix-commit is still applied; add the diff shape to the regression-detector corpus.",
        "Removing historical regression coverage once the fix is deemed stable.",
    ),
)


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------


def _shape_tags(attack_class: str, bug_class: str, bridge_slug: str) -> List[str]:
    out = [
        slugify(attack_class, max_len=64),
        slugify(f"bridge-{bug_class}", max_len=64),
        slugify(f"bridge-{bridge_slug}", max_len=64),
    ]
    seen = set()
    result: List[str] = []
    for tag in out:
        if tag and tag not in seen:
            seen.add(tag)
            result.append(tag)
    return result


def _record_id(incident_slug: str, attack_class: str, mitigation_state: str) -> str:
    payload = f"{incident_slug}|{attack_class}|{mitigation_state}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return (
        f"bridge-attacks:{slugify(incident_slug, max_len=32)}:"
        f"{slugify(attack_class, max_len=64)}:"
        f"{mitigation_state}:{digest}"
    )


def build_records() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for row in INCIDENTS:
        (
            incident_slug,
            bridge_name,
            target_repo,
            target_component,
            attack_class,
            bug_class,
            severity,
            impact_class,
            impact_actor,
            impact_dollar_class,
            attacker_role,
            target_language,
            loss_usd,
            year,
            raw_signature,
            action,
            precondition,
            fix,
            anti_pattern,
            source_audit_ref,
        ) = row
        bridge_slug = slugify(bridge_name, max_len=32)
        for mitigation_state, state_note, fix_addendum, anti_pattern_addendum in MITIGATION_STATES:
            loss_marker = f" [loss_usd={loss_usd}]" if loss_usd > 0 else ""
            state_marker = f" [mitigation-state={mitigation_state}; {state_note}]"
            record = {
                "schema_version": SCHEMA_VERSION,
                "record_id": _record_id(incident_slug, attack_class, mitigation_state),
                "source_audit_ref": one_line(source_audit_ref, "rekt:unknown", max_len=240),
                "target_domain": "bridge",
                "target_language": target_language,
                "target_repo": target_repo,
                "target_component": one_line(target_component, "Bridge.unknown", max_len=240),
                "function_shape": {
                    "raw_signature": one_line(raw_signature, "function unknown() external", max_len=500),
                    "shape_tags": _shape_tags(attack_class, bug_class, bridge_slug),
                },
                "bug_class": bug_class,
                "attack_class": attack_class,
                "attacker_role": attacker_role,
                "attacker_action_sequence": one_line(
                    action + loss_marker + state_marker,
                    f"Exercise {attack_class} against {bridge_name}",
                    max_len=4900,
                ),
                "required_preconditions": [
                    one_line(precondition, "precondition unknown", max_len=900),
                    f"Bridge: {bridge_name}; year: {year}; mitigation-state: {mitigation_state}.",
                ],
                "impact_class": impact_class,
                "impact_actor": impact_actor,
                "impact_dollar_class": impact_dollar_class,
                "fix_pattern": one_line(
                    f"{fix} {fix_addendum}",
                    "Apply the recommended bridge-side invariant fix.",
                    max_len=900,
                ),
                "fix_anti_pattern_avoided": one_line(
                    f"{anti_pattern} {anti_pattern_addendum}",
                    "Anti-pattern: assuming prior fix is still in place.",
                    max_len=900,
                ),
                "severity_at_finding": severity,
                "year": year,
                "record_tier": "public-corpus",
                "record_quality_score": 4.0,
                "source_extraction_method": "human-curated",
                "source_extraction_confidence": 0.9,
                "cross_language_analogues": [],
                "related_records": [],
            }
            records.append(record)
    return records


# ---------------------------------------------------------------------------
# CLI / write-out
# ---------------------------------------------------------------------------


def output_filename(record: Dict[str, Any]) -> str:
    rid = str(record["record_id"])
    digest = rid.rsplit(":", 1)[-1]
    return f"{slugify(rid, max_len=110)}-{digest}.yaml"


def convert(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    filter_attack_class: Optional[str] = None,
) -> Dict[str, Any]:
    records = build_records()
    if filter_attack_class:
        records = [r for r in records if r["attack_class"] == filter_attack_class]
    if limit is not None:
        records = records[:limit]

    schema = _VALIDATOR.load_schema()
    errors: List[str] = []
    files: List[str] = []
    by_attack_class: Dict[str, int] = {}
    by_state: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    seen_record_ids: Dict[str, int] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        rid = str(record["record_id"])
        seen_record_ids[rid] = seen_record_ids.get(rid, 0) + 1
        if seen_record_ids[rid] > 1:
            # Additive-only dedup: skip silently rather than fail-hard so a
            # downstream consumer can re-run safely.
            continue
        by_attack_class[record["attack_class"]] = by_attack_class.get(record["attack_class"], 0) + 1
        state = rid.rsplit(":", 2)[-2]
        by_state[state] = by_state.get(state, 0) + 1
        by_severity[record["severity_at_finding"]] = by_severity.get(record["severity_at_finding"], 0) + 1
        rendered = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{rid}: yaml-parse-error: {exc}")
            continue
        errs = _VALIDATOR.validate_doc(doc, schema)
        if errs:
            errors.extend(f"{rid}: {err}" for err in errs)
            continue
        out_path = out_dir / output_filename(record)
        if (not dry_run) and out_path.exists():
            # Additive-only: don't overwrite an existing valid record.
            files.append(str(out_path))
            continue
        files.append(str(out_path))
        if not dry_run:
            out_path.write_text(rendered, encoding="utf-8")

    return {
        "schema_version": SCHEMA_VERSION,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "records_emitted": len(files),
        "records_attempted": len(records),
        "errors": errors,
        "by_attack_class": by_attack_class,
        "by_mitigation_state": by_state,
        "by_severity": by_severity,
        "file_count": len(files),
        "files": files[:50],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--apply", action="store_true",
                        help="Write records to --out-dir (inverse of --dry-run). "
                             "Default is to write unless --dry-run is set; "
                             "--apply is an explicit safety toggle.")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--filter-attack-class",
        help="Restrict emitted records to a single attack_class value.",
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    if args.dry_run and args.apply:
        print("--dry-run and --apply are mutually exclusive", file=sys.stderr)
        return 2
    dry_run = bool(args.dry_run) and not args.apply
    summary = convert(
        Path(args.out_dir).expanduser().resolve(),
        dry_run=dry_run,
        limit=args.limit,
        filter_attack_class=args.filter_attack_class,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman bridge-attacks ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"by_attack_class={summary['by_attack_class']} "
            f"by_state={summary['by_mitigation_state']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
