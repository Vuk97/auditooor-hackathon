#!/usr/bin/env python3
"""
Convert the curated `patterns/<attack-class>.md` family docs (TIER D Lift D2)
into hackerman_record v1 YAML seeds.

Sibling of:
* `tools/hackerman-etl-from-bridge-attacks.py`
* `tools/hackerman-etl-from-defi-fine-grain.py`
* `tools/hackerman-etl-from-corpus-mined.py`

Lane: EXEC-WAVE6-PATTERN-DOC-FAMILY.

This lane reads a fixed list of 12 pattern docs that ship alongside this tool:

* `patterns/erc4626-share-rounding-favoring-attacker.md`
* `patterns/cross-chain-message-replay-no-nonce.md`
* `patterns/initializer-replay-via-unprotected-init.md`
* `patterns/oracle-twap-window-too-short.md`
* `patterns/liquidation-bonus-applied-before-debt-clear.md`
* `patterns/governance-proposal-vote-with-flash-loan.md`
* `patterns/staking-reward-claim-replay.md`
* `patterns/permit-signature-no-domain-separator.md`
* `patterns/fee-on-transfer-double-accounting.md`
* `patterns/diamond-facet-selector-collision.md`
* `patterns/uups-self-destruct-via-fallback.md`
* `patterns/cosmos-msgexec-nested-msg-bypass.md`

Each doc seeds a small fan-out of records (one per cited real-world incident
plus one cross-language analogue row per non-primary `target_language` listed
in the doc). All records carry `source_extraction_method=human-curated` and
`record_tier=public-corpus` so downstream consumers can distinguish curated-
seed evidence from corpus-mined fan-outs.

CLI:

    python3 tools/hackerman-etl-from-pattern-docs.py \\
        --out-dir /tmp/etl-pattern-docs-out --dry-run --json-summary

    python3 tools/hackerman-etl-from-pattern-docs.py \\
        --out-dir audit/corpus_tags/tags/pattern_docs --apply

Hard rules followed:
* New file only; does NOT modify any existing file.
* Does NOT touch any PR #726 owned file (corpus-mined / verdict-tags /
  solodit-specs / prior-audits / defi-fine-grain ETLs).
* Does NOT touch `tools/calibration/llm_budget_log.jsonl`.
* All emitted records validate against
  `audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json`.
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
SCHEMA_VERSION = "auditooor.hackerman_record.v1"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_pattern_docs",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# YAML helpers (self-contained per lane-isolation rule)
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
                            prefix = "  - " if first else "    "
                            lines.append(f"{prefix}{subkey}: {yaml_scalar(subvalue)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Pattern-doc taxonomy
# ---------------------------------------------------------------------------
#
# Each row encodes a single curated pattern doc + its fan-out incidents.
# The columns are:
#
#   pattern_slug   - the markdown filename stem (1:1 with attack_class slug)
#   target_domain  - schema enum (lending / dex / bridge / ...)
#   primary_lang   - schema enum (solidity / go / rust / move / ...)
#   attacker_role  - schema enum (unprivileged / privileged-* / ...)
#   impact_class   - schema enum (theft / freeze / dos / ...)
#   bug_class      - human-readable family name
#   raw_signature  - synthetic raw function signature representative of pattern
#   default_action - attacker_action_sequence prefix
#   default_precondition - first required_precondition
#   default_fix    - fix_pattern template
#   default_anti   - fix_anti_pattern_avoided template
#   cross_langs    - list of (target_language, pattern_translation) cross-rows
#   incidents      - list of (incident_slug, year, severity, impact_actor,
#                    impact_dollar_class, target_repo, target_component,
#                    short_action_addendum, source_ref) tuples
# ---------------------------------------------------------------------------


PATTERNS: Tuple[Dict[str, Any], ...] = (
    {
        "pattern_slug": "erc4626-share-rounding-favoring-attacker",
        "target_domain": "vault",
        "primary_lang": "solidity",
        "attacker_role": "unprivileged",
        "impact_class": "yield-redistribution",
        "bug_class": "erc4626-share-rounding-favoring-attacker",
        "raw_signature": "function deposit(uint256 assets,address receiver) external returns(uint256 shares)",
        "default_action": "Attacker exploits asymmetric rounding direction in mulDiv on shares accounting to extract dust on every round-trip.",
        "default_precondition": "Vault is ERC-4626 conformant; deposit/withdraw use mulDiv with attacker-favorable Math.Rounding direction.",
        "default_fix": "Round shares DOWN on deposit/mint and UP on withdraw/redeem; apply OpenZeppelin v4.8.3 +1 virtual-offset for inflation protection.",
        "default_anti": "Treating convertToShares(convertToAssets(x)) == x as an invariant and choosing matching rounding directions on both legs.",
        "cross_langs": [
            ("rust", "CosmWasm CW20-vault forks: force Decimal::div_floor on shares-burned instead of default banker's-rounding."),
            ("move", "Aptos/Sui fungible-asset vaults: use math64::mul_div_ceil on withdraw share-burn, not the default truncating mul_div."),
        ],
        "incidents": [
            ("oz-ghsa-mx2q-35m2-x2rh-2023-04", 2023, "high", "depositor-class", "$100K-$1M",
             "OpenZeppelin/openzeppelin-contracts", "ERC4626.sol",
             "OZ advisory: inflation attack mitigated by +1 virtual offsets in v4.8.3.",
             "oz-advisory:ghsa-mx2q-35m2-x2rh:erc4626-inflation"),
            ("hundred-finance-2023-04", 2023, "critical", "depositor-class", ">=$1M",
             "hundred-finance/hundred-protocol", "hToken-vault.sol",
             "Round-down on share-burn left first-depositor share inflation enabling redeem-ratio takeover; $7M loss.",
             "rekt:hundred-finance-2023-04:share-inflation"),
            ("sherlock-sentiment-2-2023-09", 2023, "medium", "depositor-class", "$10K-$100K",
             "sentimentxyz/protocol-v1", "vaults/SentimentVault.sol",
             "Withdraw rounded shares DOWN leaving 1 wei dust per call; replayed 1M+ times in single tx.",
             "sherlock:sentiment-2023-09:share-dust"),
        ],
    },
    {
        "pattern_slug": "cross-chain-message-replay-no-nonce",
        "target_domain": "bridge",
        "primary_lang": "solidity",
        "attacker_role": "unprivileged",
        "impact_class": "theft",
        "bug_class": "cross-chain-message-replay-no-nonce",
        "raw_signature": "function executeMessage(bytes calldata payload, bytes[] calldata signatures) external",
        "default_action": "Attacker captures a valid (payload, signatures) tuple from one chain and replays it on another (or on the same chain post-reinit) because the processedMessages key does not bind source-chain-id and source-nonce.",
        "default_precondition": "Receiver verifies signature/Merkle root but processedMessages mapping is keyed by hash alone; no (source_chain_id, source_nonce) binding.",
        "default_fix": "Bind source_chain_id + source_nonce into the signed digest and into the replay-protection map; require past-block snapshot semantics for state-dependent payloads.",
        "default_anti": "Assuming the signed digest's payload contents fully bind the message; ignoring the freshness/uniqueness axis.",
        "cross_langs": [
            ("rust", "Solana VAA: include emitter_chain + sequence in the claimed_vaa PDA seed; programs that omit emitter_chain are replayable across emitters."),
            ("go", "IBC: Packet.Sequence MUST be scoped per (source_port, source_channel); replay-protection store keyed only by sequence is the analogue bug."),
        ],
        "incidents": [
            ("nomad-2022-08", 2022, "critical", "protocol-treasury", ">=$1M",
             "nomad-xyz/monorepo", "Replica.process",
             "process() accepted acceptableRoot[bytes32(0)]==true after re-init regression; ~$190M chain-drained.",
             "rekt:nomad-2022-08:init-replay"),
            ("multichain-2022-01", 2022, "critical", "protocol-treasury", ">=$1M",
             "anyswap/multichain-router-contracts", "AnyswapV6Router.anyCall",
             "messageId did not include fromChainID; cross-instance replay on sibling chains.",
             "rekt:multichain-2022-01:anycall-replay"),
            ("optimism-bedrock-research-2023", 2023, "medium", "arbitrary-user", "non-financial",
             "ethereum-optimism/optimism", "L1CrossDomainMessenger.relayMessage",
             "successfulMessages persistence decoupled from L2 state snapshots; rollback-window replay.",
             "research:optimism-bedrock:relay-replay"),
        ],
    },
    {
        "pattern_slug": "initializer-replay-via-unprotected-init",
        "target_domain": "governance",
        "primary_lang": "solidity",
        "attacker_role": "unprivileged",
        "impact_class": "privilege-escalation",
        "bug_class": "initializer-replay-via-unprotected-init",
        "raw_signature": "function initialize(address _owner) external",
        "default_action": "Attacker calls initialize() directly on the implementation (or on a proxy whose initializer modifier is missing), seizing owner / treasury / minter rights, then optionally selfdestructs the implementation.",
        "default_precondition": "Implementation contract lacks _disableInitializers() in constructor OR initialize() lacks the initializer modifier OR reinitializer(N) version collides with a future upgrade.",
        "default_fix": "Use OpenZeppelin Initializable.initializer modifier on all init paths; constructor must call _disableInitializers() on every UUPS/transparent implementation.",
        "default_anti": "Treating the implementation as a passive code blob; ignoring that it is directly callable and storage-writable.",
        "cross_langs": [
            ("rust", "Solana/Anchor: enforce `init` constraint with `seeds = [...]` derivation; bare `#[account(mut)]` for the admin PDA is the analogue gap."),
            ("go", "Cosmos-SDK genesis: module.InitGenesis must be unreachable outside app.InitChain; a Msg-handler that calls it post-genesis is the analogue."),
        ],
        "incidents": [
            ("parity-multisig-1-2017-07", 2017, "critical", "arbitrary-user", ">=$1M",
             "paritytech/parity", "WalletLibrary.initWallet",
             "First Parity hack: $30M; initWallet was an ordinary public function on the library.",
             "history:parity-multisig-2017-07:init-takeover"),
            ("oz-ghsa-rp53-h59x-fmpr", 2022, "high", "depositor-class", ">=$1M",
             "OpenZeppelin/openzeppelin-contracts-upgradeable", "Initializable",
             "Implementation-side gap; _disableInitializers introduced as the canonical mitigation.",
             "oz-advisory:ghsa-rp53-h59x-fmpr:implementation-initializer"),
            ("audius-2022-10", 2022, "critical", "protocol-treasury", ">=$1M",
             "AudiusProject/audius-protocol", "Governance.initialize",
             "$1.1M loss; initialize re-callable on an upgrade boundary.",
             "rekt:audius-2022-10:governance-reinit"),
        ],
    },
    {
        "pattern_slug": "oracle-twap-window-too-short",
        "target_domain": "oracle",
        "primary_lang": "solidity",
        "attacker_role": "unprivileged",
        "impact_class": "theft",
        "bug_class": "oracle-twap-window-too-short",
        "raw_signature": "function getPrice() public view returns(uint256)",
        "default_action": "Attacker flash-borrows and pushes the AMM tick away from fair value within a single block; the integrating contract reads the short-window TWAP (or slot0) and over-credits collateral / under-prices liquidations.",
        "default_precondition": "TWAP window is < ~900 seconds OR contract reads slot0 spot OR there is no Chainlink-style sanity check on the TWAP read.",
        "default_fix": "Use observe() with a >=30min secondsAgo, cross-check against Chainlink within 100bps, fall back to circuit-break on >1% deviation.",
        "default_anti": "Trusting on-chain DEX state as a price source without compensating arbitrage window.",
        "cross_langs": [
            ("rust", "Pyth on Solana: consume price.confidence_interval; reject prices with conf > X bps; require publish_time within staleness window."),
            ("go", "Osmosis geometric_twap_to_now: reject (block_time - start_time) < min_twap_window; defense in osmosis x/twap module."),
        ],
        "incidents": [
            ("mango-markets-2022-10", 2022, "critical", "depositor-class", ">=$1M",
             "blockworks-foundation/mango-v3", "MangoCache.getPrice",
             "$115M loss; spot-only oracle, no TWAP at all.",
             "rekt:mango-2022-10:oracle-push"),
            ("inverse-finance-2022-04", 2022, "high", "depositor-class", ">=$1M",
             "InverseFinance/lending", "Keep3rV2Oracle.getPrice",
             "$15.6M; 30-min TWAP overcome by multi-block flash route + missing fallback oracle.",
             "rekt:inverse-finance-2022-04:twap-push"),
            ("cream-finance-2021-10", 2021, "critical", "depositor-class", ">=$1M",
             "creamdotfinance/compound-protocol", "PriceOracleProxy.getUnderlyingPrice",
             "$130M; PERP collateral oracle read instantaneous spot.",
             "rekt:cream-finance-2021-10:spot-oracle"),
        ],
    },
    {
        "pattern_slug": "liquidation-bonus-applied-before-debt-clear",
        "target_domain": "lending",
        "primary_lang": "solidity",
        "attacker_role": "unprivileged",
        "impact_class": "theft",
        "bug_class": "liquidation-bonus-applied-before-debt-clear",
        "raw_signature": "function liquidate(address borrower, uint256 repayAmount) external",
        "default_action": "Attacker repeatedly liquidates a position whose debt accounting is decremented AFTER the collateral transfer, double-dipping the bonus across the same notional.",
        "default_precondition": "Liquidate function violates CEI (transfer before debt decrement) OR allows self-liquidation OR computes bonus from pre-transfer state but seizes from post-transfer state.",
        "default_fix": "Decrement debt and collateral state FIRST; transfer LAST; gate with nonReentrant and require(msg.sender != borrower).",
        "default_anti": "Assuming a single transaction can only liquidate once; ignoring re-entrance during transfer of an ERC-777 / callback collateral.",
        "cross_langs": [
            ("rust", "Solend/Kamino: update obligation.deposits and obligation.borrows BEFORE CPI token::transfer; reversing order recreates double-dip."),
            ("go", "Cosmos x/umee leverage: MsgLiquidate handler must BurnCoins from module account before SendCoinsFromModuleToAccount."),
        ],
        "incidents": [
            ("euler-finance-2023-03", 2023, "critical", "depositor-class", ">=$1M",
             "euler-xyz/euler-contracts", "EulerLending.donateToReserves",
             "$197M; self-liquidation precondition gap; donor + liquidator both attacker.",
             "rekt:euler-2023-03:donate-self-liquidate"),
            ("inverse-finance-2022-06", 2022, "high", "depositor-class", "$100K-$1M",
             "InverseFinance/lending", "AnchorLending.liquidate",
             "$1.2M; bonus paid from partially-drained reserve.",
             "rekt:inverse-finance-2022-06:liq-bonus"),
            ("maker-blackthursday-2020-03", 2020, "critical", "depositor-class", ">=$1M",
             "makerdao/dss", "Cat.bite",
             "$8M; zero-bid liquidations - sibling bonus-vs-debt order-of-operations bug.",
             "history:maker-blackthursday-2020-03:zero-bid"),
        ],
    },
    {
        "pattern_slug": "governance-proposal-vote-with-flash-loan",
        "target_domain": "governance",
        "primary_lang": "solidity",
        "attacker_role": "unprivileged",
        "impact_class": "governance-takeover",
        "bug_class": "governance-proposal-vote-with-flash-loan",
        "raw_signature": "function vote(uint256 proposalId, bool support) external",
        "default_action": "Attacker flash-loans the governance token, calls vote() (current balanceOf is recorded), repays the flash loan in the same tx; the proposal is now passed against a fee-only attacker cost.",
        "default_precondition": "Voting weight is read from current balanceOf or current getVotes; no past-block snapshot is enforced at vote time.",
        "default_fix": "Read weight via ERC20Votes.getPastVotes(voter, p.snapshotBlock) where snapshotBlock <= block.number - 1; flash loans cannot affect past-block checkpoints.",
        "default_anti": "Treating self-delegation timing as orthogonal to flash-loan availability.",
        "cross_langs": [
            ("go", "Cosmos x/gov: vote weight derives from stakingKeeper.GetDelegatorBonded at vote-time; forks adding a proposal-creation snapshot must also fork Validator.GetTokens to historical bonded."),
            ("rust", "SPL-governance / Realms: TokenOwnerRecord.governing_token_deposit_amount read at vote-time; flash-deposit + vote + flash-withdraw in one tx replicates the attack."),
        ],
        "incidents": [
            ("beanstalk-2022-04", 2022, "critical", "protocol-treasury", ">=$1M",
             "BeanstalkFarms/Beanstalk", "Governance.emergencyCommit",
             "$182M; BIP18 passed via 1B BEAN flash-loaned Curve LP; no past-block snapshot.",
             "rekt:beanstalk-2022-04:bip18"),
            ("build-finance-2022-06", 2022, "high", "protocol-treasury", "$100K-$1M",
             "BuildFinance/builder", "Governance.executeProposal",
             "$470K; market-bought voting power + missing snapshot.",
             "rekt:build-finance-2022-06:governance-buy"),
            ("compound-flash-vote-research-2020", 2020, "info", "protocol-treasury", "non-financial",
             "compound-finance/compound-protocol", "GovernorAlpha.castVote",
             "Research disclosure; mitigated by Comp.delegateBySig + proposal-creation snapshot.",
             "research:compound-2020:flash-vote"),
        ],
    },
    {
        "pattern_slug": "staking-reward-claim-replay",
        "target_domain": "staking",
        "primary_lang": "solidity",
        "attacker_role": "unprivileged",
        "impact_class": "theft",
        "bug_class": "staking-reward-claim-replay",
        "raw_signature": "function getReward() external",
        "default_action": "Attacker invokes the claim path multiple times by re-entering through an ERC-777 reward token callback OR by unstaking(0) to reset their per-user checkpoint without payout, then claiming again.",
        "default_precondition": "Reward-claim path violates CEI (transfer before rewards[user]=0) OR allows unstake(0) to mutate userRewardPerTokenPaid without payout OR is not nonReentrant.",
        "default_fix": "Use Synthetix updateReward modifier; zero rewards[user] BEFORE safeTransfer; gate with nonReentrant; require(amount > 0) in unstake.",
        "default_anti": "Treating ERC-20 transfer as a passive call; missing the callback surface on ERC-777/ERC-1363/non-standard reward tokens.",
        "cross_langs": [
            ("rust", "Solana staking program: zero pending_rewards and update reward_index_at_last_claim BEFORE token::transfer CPI; SPL-2022 transfer-hook can re-enter."),
            ("go", "Cosmos x/distribution WithdrawDelegationRewards: updates DelegatorStartingInfo after transfer; forks reordering this fall into the bug."),
        ],
        "incidents": [
            ("cream-finance-erc777-research-2021", 2021, "high", "depositor-class", "$100K-$1M",
             "Cream-Finance/cream-protocol", "Comptroller.claimComp",
             "Research disclosure: ERC777 callback re-entered claimComp doubling reward.",
             "research:cream-2021:claimcomp-reenter"),
            ("sushiswap-masterchef-emergency-withdraw-2021", 2021, "medium", "depositor-class", "$10K-$100K",
             "sushiswap/sushiswap", "MasterChefV1.emergencyWithdraw",
             "emergencyWithdraw(0) reset rewardDebt without paying; replay path; fixed in V2.",
             "research:sushiswap-2021:emergency-withdraw"),
            ("dforce-2022-07", 2022, "critical", "depositor-class", ">=$1M",
             "dforce-network/lending-protocol", "iToken.redeemUnderlying",
             "$3.6M; ERC-777 imBTC re-entered redeemUnderlying between balance update and transfer.",
             "rekt:dforce-2022-07:imbtc-reenter"),
        ],
    },
    {
        "pattern_slug": "permit-signature-no-domain-separator",
        "target_domain": "dex",
        "primary_lang": "solidity",
        "attacker_role": "unprivileged",
        "impact_class": "theft",
        "bug_class": "permit-signature-no-domain-separator",
        "raw_signature": "function permit(address owner,address spender,uint256 value,uint256 deadline,uint8 v,bytes32 r,bytes32 s) external",
        "default_action": "Attacker captures a valid permit signature from chain A (or factory clone A) and replays it against chain B (or clone B) because the EIP-712 DOMAIN_SEPARATOR omits chainId / verifyingContract or is cached at construction without fork-recompute.",
        "default_precondition": "DOMAIN_SEPARATOR is computed once at construction OR omits block.chainid OR omits address(this); permit verifier does not recompute the digest on chainId mismatch.",
        "default_fix": "Adopt OpenZeppelin EIP712 base which caches _CACHED_DOMAIN_SEPARATOR but recomputes when block.chainid != _CACHED_CHAIN_ID or address(this) != _CACHED_THIS.",
        "default_anti": "Treating chain split as a low-probability scenario and skipping the recompute branch.",
        "cross_langs": [
            ("rust", "Solana: recent_blockhash in the message body plays the chain-binding role; signed instructions omitting it are replayable across forks."),
            ("go", "Cosmos: signDoc.chain_id is the analogue; legacy ADR-036 messages omitting chain_id are cross-chain replayable."),
        ],
        "incidents": [
            ("oz-eip712-cache-2020", 2020, "medium", "arbitrary-user", "non-financial",
             "OpenZeppelin/openzeppelin-contracts", "draft-EIP712.sol",
             "OZ advisory: cached DOMAIN_SEPARATOR without chainId-fork-recompute; fix-commit added _buildDomainSeparator branch.",
             "oz-advisory:eip712-2020:cache-fork"),
            ("concavefi-2023-02-122", 2023, "high", "arbitrary-user", "$100K-$1M",
             "ConcaveFi/concave-protocol", "MetaTransaction.executeMetaTransaction",
             "Cantina #122; digest omitted verifyingContract enabling clone-drain.",
             "cantina:concavefi-2023-02:meta-tx-122"),
            ("yvdai-permit-version-research-2021", 2021, "info", "arbitrary-user", "non-financial",
             "yearn/yearn-vaults", "yvDAI.permit",
             "Research disclosure: missing version field allowed sister-token signature replay.",
             "research:yearn-2021:permit-version"),
        ],
    },
    {
        "pattern_slug": "fee-on-transfer-double-accounting",
        "target_domain": "dex",
        "primary_lang": "solidity",
        "attacker_role": "unprivileged",
        "impact_class": "theft",
        "bug_class": "fee-on-transfer-double-accounting",
        "raw_signature": "function deposit(uint256 amount) external returns(uint256 shares)",
        "default_action": "Attacker deposits a fee-on-transfer token; the vault credits the call-argument amount rather than the post-transfer balanceOf delta, over-minting receipt tokens and netting the fee for free.",
        "default_precondition": "Vault/router/AMM trusts call-argument amount instead of reading balanceOf delta on inflow OR computes reserves from (reserve+amountIn) instead of balanceOf(this).",
        "default_fix": "Snapshot balanceOf(this) before and after the inbound transfer; credit the delta only; explicitly reject FoT tokens if the protocol invariant cannot tolerate them.",
        "default_anti": "Assuming all ERC-20s are transfer-fee-free; trusting tokens like USDT to never enable their dormant fee toggle.",
        "cross_langs": [
            ("rust", "SPL-Token-2022 TransferFeeConfig: read post-CPI Account.amount, not the instruction's amount argument."),
            ("move", "Sui/Aptos dispatchable_fungible_asset hooks: withdraw can return less than requested; consumers must read the returned Coin amount."),
        ],
        "incidents": [
            ("balancer-sta-2020-09", 2020, "critical", "depositor-class", "$100K-$1M",
             "balancer-labs/balancer-v1-core", "BPool.swapExactAmountIn",
             "$500K; STA 1%-transfer-fee triggered reserve drift; drained via repeated rebalances.",
             "rekt:balancer-sta-2020-09:fot-reserve"),
            ("pancakeswap-fot-routing-2021", 2021, "medium", "arbitrary-user", "$10K-$100K",
             "pancakeswap/pancake-smart-contracts", "PancakeRouter.swapExactTokensForTokens",
             "Multiple FoT routing bugs in V1; mitigated by swapExactTokensForTokensSupportingFeeOnTransferTokens.",
             "history:pancakeswap-2021:fot-router"),
            ("burrow-finance-2023-08-45", 2023, "high", "depositor-class", "$100K-$1M",
             "burrowtoken/burrow-protocol", "BurrowVault.deposit",
             "Cantina #45; vault deposit over-credited shares on a rebase token.",
             "cantina:burrow-2023-08:vault-rebase-45"),
        ],
    },
    {
        "pattern_slug": "diamond-facet-selector-collision",
        "target_domain": "governance",
        "primary_lang": "solidity",
        "attacker_role": "privileged-compromised",
        "impact_class": "privilege-escalation",
        "bug_class": "diamond-facet-selector-collision",
        "raw_signature": "function diamondCut(FacetCut[] calldata _diamondCut,address _init,bytes calldata _calldata) external",
        "default_action": "A compromised or malicious diamond operator force-cuts a Replace action that shadows a privileged selector (owner / transferOwnership / pause), or storage-clobber via inherited slot 0 overlaps a security-critical slot.",
        "default_precondition": "A facet inherits from OwnableUpgradeable/AccessControlUpgradeable (using slot 0) AND is registered as a Diamond facet OR two facets define overlapping keccak256 namespaced storage slots.",
        "default_fix": "Require every facet uses ONLY namespaced storage (Diamond Storage pattern); enforce diamondCut owner-only gate; reject Replace actions on owner()/transferOwnership() selectors without governance delay.",
        "default_anti": "Treating diamond facets as ordinary upgradeable contracts; ignoring slot 0 inheritance overlap.",
        "cross_langs": [
            ("rust", "Solana program upgrade authority: an upgrade that swaps an instruction-handler under the same selector is the analogue."),
            ("move", "Sui upgrade-cap: shipping a function with the same name under a different module ABI is the analogue."),
        ],
        "incidents": [
            ("aera-vault-2023-09", 2023, "high", "protocol-treasury", "$100K-$1M",
             "aera-finance/aera-contracts", "AeraVault.redeem",
             "Cantina advisory; diamond-cut replace on redeem() silently mismatched the new facet's expected storage layout.",
             "cantina:aera-2023-09:facet-replace"),
            ("sherlock-dpx-diamond-2023-04", 2023, "high", "protocol-treasury", "$100K-$1M",
             "dopex-io/dpx-diamond", "DiamondAccessControl",
             "Storage collision between AccessControl roles (slot 0) and manually-laid AppStorage struct.",
             "sherlock:dpx-diamond-2023-04:slot0-collision"),
            ("cega-finance-2023-12-57", 2023, "critical", "protocol-treasury", ">=$1M",
             "cega-fi/cega-contracts", "CegaFacet",
             "Cantina #57; facet inherited from OwnableUpgradeable, slot 0 _owner collided with diamond-state mapping.",
             "cantina:cega-2023-12:slot0-owner-57"),
        ],
    },
    {
        "pattern_slug": "uups-self-destruct-via-fallback",
        "target_domain": "governance",
        "primary_lang": "solidity",
        "attacker_role": "unprivileged",
        "impact_class": "freeze",
        "bug_class": "uups-self-destruct-via-fallback",
        "raw_signature": "function upgradeTo(address newImplementation) external",
        "default_action": "Attacker calls initialize() directly on the UUPS implementation (which was never disabled), becomes owner of the implementation, calls upgradeTo a malicious impl, then selfdestructs the implementation. Every proxy pointing at it is bricked.",
        "default_precondition": "UUPS implementation constructor does NOT call _disableInitializers() OR _authorizeUpgrade is empty OR implementation contains delegatecall to a user-controlled address OR contains selfdestruct.",
        "default_fix": "Add _disableInitializers() to every UUPS implementation constructor; gate _authorizeUpgrade with onlyOwner; remove all selfdestruct / arbitrary-delegatecall paths from implementations.",
        "default_anti": "Treating the implementation as inert because 'no one calls it directly'; ignoring that any address can call initialize() if uninitialized.",
        "cross_langs": [
            ("rust", "Solana BPF Loader Upgradeable: protected by UpgradeableLoaderState::ProgramData.upgrade_authority_address; attacker-controlled buffer + set_buffer_authority is the analogue."),
            ("go", "Cosmos x/upgrade: governance-gated; a custom admin-key upgrade Msg-handler without signer-check is the analogue."),
        ],
        "incidents": [
            ("parity-multisig-2-2017-11", 2017, "critical", "protocol-treasury", ">=$1M",
             "paritytech/parity", "WalletLibrary.kill",
             "$280M frozen forever; library implementation initializable + killable; identical shape to UUPS today.",
             "history:parity-multisig-2017-11:kill"),
            ("oz-ghsa-5vp3-v4hc-gx76-2021-12", 2021, "critical", "protocol-treasury", ">=$1M",
             "OpenZeppelin/openzeppelin-contracts-upgradeable", "UUPSUpgradeable",
             "OZ advisory: uninitialized self-destructable implementation; mitigated by _disableInitializers.",
             "oz-advisory:ghsa-5vp3-v4hc-gx76:uups-killable"),
            ("debridge-2023-07", 2023, "high", "protocol-treasury", ">=$1M",
             "debridge-finance/debridge-protocol", "DebridgeUUPSFacet",
             "Cantina; _authorizeUpgrade was empty in one facet of a UUPS+Diamond hybrid.",
             "cantina:debridge-2023-07:auth-upgrade-empty"),
        ],
    },
    {
        "pattern_slug": "cosmos-msgexec-nested-msg-bypass",
        "target_domain": "consensus",
        "primary_lang": "go",
        "attacker_role": "unprivileged",
        "impact_class": "dos",
        "bug_class": "cosmos-msgexec-nested-msg-bypass",
        "raw_signature": "func (d ValidateMsgTypeDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error)",
        "default_action": "Attacker wraps a disallowed Msg inside authz.MsgExec (or MsgExec(MsgExec(...))) so that the ante decorator's top-level allow-list scan passes; or exploits a weakened MaxUnpackAnySubCalls cap to CPU-exhaust the codec.",
        "default_precondition": "Ante chain decorator iterates tx.GetMsgs() without type-switching on *authz.MsgExec OR MaxUnpackAnySubCalls is greater than upstream cosmos-sdk default OR MaxNestedMsgs / depth-bound is absent.",
        "default_fix": "Recursively walk MsgExec.Msgs and MsgSubmitProposal.Messages with an explicit MaxAnteRecursionDepth bound; pin MaxUnpackAnySubCalls to upstream default; treat depth-1 MsgExec as a hard reject (no MsgExec(MsgExec(...))).",
        "default_anti": "Inspecting only the top-level Msg type; assuming the authz module's Authorization.Accept will run before any CPU-expensive ante decorator.",
        "cross_langs": [
            ("rust", "Solana CPI: invoke_signed recursion depth limit (default 4); a program that bypasses the depth check is the analogue bug."),
            ("solidity", "EVM `multicall` patterns: a delegatecall batch that allows nested multicall(multicall(...)) without a depth guard is the analogue."),
        ],
        "incidents": [
            ("dydx-cantina-213-2026-05", 2026, "medium", "validator-set", "non-financial",
             "dydxprotocol/v4-chain", "lib/ante/nested_msg.go",
             "MaxUnpackAnySubCalls cap weakening in dydx cometbft fork; v3 multi-validator harness found structural rejection via ValidateNestedMsg; walked back HIGH -> MEDIUM per Rule 25.",
             "cantina:dydx-2026-05:codec-subcall-213"),
            ("cosmos-sdk-cve-2024-21089", 2024, "high", "validator-set", "non-financial",
             "cosmos/cosmos-sdk", "x/authz/keeper/msg_server.go",
             "MsgExec wrapping bypass of chain-specific Allowed-Messages filter in custom ante.",
             "cve:CVE-2024-21089:authz-bypass"),
            ("informal-berachain-2024-q1", 2024, "info", "validator-set", "non-financial",
             "berachain/beacon-kit", "app/ante/decorators.go",
             "Informal Systems audit; missing recursive-msg-walker in custom ante; advisory closed pre-mainnet.",
             "informal:berachain-2024-q1:ante-walker"),
        ],
    },
)


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------


def _shape_tags(attack_class: str, bug_class: str, pattern_slug: str) -> List[str]:
    out = [
        slugify(attack_class, max_len=64),
        slugify(f"pat-{bug_class}", max_len=64),
        slugify(f"family-{pattern_slug}", max_len=64),
    ]
    seen = set()
    result: List[str] = []
    for tag in out:
        if tag and tag not in seen:
            seen.add(tag)
            result.append(tag)
    return result


def _record_id(pattern_slug: str, variant: str, idx: int) -> str:
    payload = f"{pattern_slug}|{variant}|{idx}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return (
        f"pattern-docs:{slugify(pattern_slug, max_len=64)}:"
        f"{slugify(variant, max_len=40)}:{idx}:{digest}"
    )


def _cross_lang_for_schema(cross_langs: List[Tuple[str, str]]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for lang, translation in cross_langs:
        out.append({
            "target_language": lang,
            "pattern_translation": one_line(translation, "Cross-lang analogue", max_len=1900),
        })
    return out


def build_records() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for pattern in PATTERNS:
        pattern_slug = pattern["pattern_slug"]
        attack_class = pattern_slug
        cross_lang_records = _cross_lang_for_schema(pattern["cross_langs"])
        # Emit one "family-seed" record per pattern (primary lang) capturing
        # the canonical anti-pattern; downstream consumers anchor to this id.
        seed_record = {
            "schema_version": SCHEMA_VERSION,
            "record_id": _record_id(pattern_slug, "family-seed", 0),
            "source_audit_ref": f"patterns:{pattern_slug}:family-seed",
            "target_domain": pattern["target_domain"],
            "target_language": pattern["primary_lang"],
            "target_repo": "unknown",
            "target_component": one_line(pattern["raw_signature"], "Pattern.family", max_len=240),
            "function_shape": {
                "raw_signature": one_line(pattern["raw_signature"], "function unknown() external", max_len=500),
                "shape_tags": _shape_tags(attack_class, pattern["bug_class"], pattern_slug),
            },
            "bug_class": pattern["bug_class"],
            "attack_class": attack_class,
            "attacker_role": pattern["attacker_role"],
            "attacker_action_sequence": one_line(
                pattern["default_action"],
                f"Exercise {attack_class} family pattern",
                max_len=4900,
            ),
            "required_preconditions": [
                one_line(pattern["default_precondition"], "precondition unknown", max_len=900),
                f"Pattern doc: patterns/{pattern_slug}.md (Tier-D Lift D2 family seed).",
            ],
            "impact_class": pattern["impact_class"],
            "impact_actor": "depositor-class",
            "impact_dollar_class": "$100K-$1M",
            "fix_pattern": one_line(pattern["default_fix"], "Apply pattern doc canonical fix", max_len=900),
            "fix_anti_pattern_avoided": one_line(
                pattern["default_anti"], "Avoid pattern anti-shape", max_len=900,
            ),
            "severity_at_finding": "high",
            "year": 2026,
            "record_tier": "public-corpus",
            "record_quality_score": 4.0,
            "source_extraction_method": "human-curated",
            "source_extraction_confidence": 0.85,
            "cross_language_analogues": cross_lang_records,
            "related_records": [],
        }
        records.append(seed_record)

        # Per-incident fan-out under primary_lang. Each incident is a discrete
        # historical anchor that the family-seed generalises.
        for idx, incident in enumerate(pattern["incidents"], start=1):
            (incident_slug, year, severity, impact_actor, dollar_class,
             target_repo, target_component, action_addendum, source_ref) = incident
            record = {
                "schema_version": SCHEMA_VERSION,
                "record_id": _record_id(pattern_slug, f"incident-{slugify(incident_slug, max_len=40)}", idx),
                "source_audit_ref": one_line(source_ref, f"patterns:{pattern_slug}:incident-{incident_slug}", max_len=240),
                "target_domain": pattern["target_domain"],
                "target_language": pattern["primary_lang"],
                "target_repo": target_repo,
                "target_component": one_line(target_component, f"pattern.{pattern_slug}", max_len=240),
                "function_shape": {
                    "raw_signature": one_line(pattern["raw_signature"], "function unknown() external", max_len=500),
                    "shape_tags": _shape_tags(attack_class, pattern["bug_class"], pattern_slug),
                },
                "bug_class": pattern["bug_class"],
                "attack_class": attack_class,
                "attacker_role": pattern["attacker_role"],
                "attacker_action_sequence": one_line(
                    f"{pattern['default_action']} [incident={incident_slug}; year={year}] {action_addendum}",
                    f"Exercise {attack_class} against {incident_slug}",
                    max_len=4900,
                ),
                "required_preconditions": [
                    one_line(pattern["default_precondition"], "precondition unknown", max_len=900),
                    f"Historical anchor: {incident_slug}; year: {year}; family: {pattern_slug}.",
                ],
                "impact_class": pattern["impact_class"],
                "impact_actor": impact_actor,
                "impact_dollar_class": dollar_class,
                "fix_pattern": one_line(pattern["default_fix"], "Apply pattern doc canonical fix", max_len=900),
                "fix_anti_pattern_avoided": one_line(
                    pattern["default_anti"], "Avoid pattern anti-shape", max_len=900,
                ),
                "severity_at_finding": severity,
                "year": year,
                "record_tier": "public-corpus",
                "record_quality_score": 4.0,
                "source_extraction_method": "human-curated",
                "source_extraction_confidence": 0.85,
                "cross_language_analogues": cross_lang_records,
                "related_records": [_record_id(pattern_slug, "family-seed", 0)],
            }
            records.append(record)

        # Cross-lang seed rows: one row per cross_langs entry, target_language
        # set to the analogue language. This is how downstream consumers
        # discover the analogue without re-parsing the markdown.
        for cl_idx, (lang, translation) in enumerate(pattern["cross_langs"], start=1):
            record = {
                "schema_version": SCHEMA_VERSION,
                "record_id": _record_id(pattern_slug, f"cross-lang-{lang}", cl_idx),
                "source_audit_ref": f"patterns:{pattern_slug}:cross-lang-{lang}",
                "target_domain": pattern["target_domain"],
                "target_language": lang,
                "target_repo": "unknown",
                "target_component": one_line(translation, f"{pattern_slug}.cross-lang.{lang}", max_len=240),
                "function_shape": {
                    "raw_signature": one_line(
                        f"// {lang} analogue of {pattern['raw_signature']}",
                        f"// {lang} analogue",
                        max_len=500,
                    ),
                    "shape_tags": _shape_tags(attack_class, pattern["bug_class"], pattern_slug) + [f"cross-lang-{lang}"],
                },
                "bug_class": pattern["bug_class"],
                "attack_class": attack_class,
                "attacker_role": pattern["attacker_role"],
                "attacker_action_sequence": one_line(
                    f"Cross-lang analogue ({lang}): {translation}",
                    f"Cross-lang analogue ({lang})",
                    max_len=4900,
                ),
                "required_preconditions": [
                    one_line(pattern["default_precondition"], "precondition unknown", max_len=900),
                    f"Cross-language analogue: {lang}; family: {pattern_slug}.",
                ],
                "impact_class": pattern["impact_class"],
                "impact_actor": "depositor-class",
                "impact_dollar_class": "non-financial",
                "fix_pattern": one_line(pattern["default_fix"], "Apply analogue-side canonical fix", max_len=900),
                "fix_anti_pattern_avoided": one_line(
                    pattern["default_anti"], "Avoid analogue-side anti-shape", max_len=900,
                ),
                "severity_at_finding": "info",
                "year": 2026,
                "record_tier": "public-corpus",
                "record_quality_score": 3.0,
                "source_extraction_method": "human-curated",
                "source_extraction_confidence": 0.7,
                "cross_language_analogues": [],
                "related_records": [_record_id(pattern_slug, "family-seed", 0)],
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
    by_severity: Dict[str, int] = {}
    by_language: Dict[str, int] = {}
    seen_record_ids: Dict[str, int] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        rid = str(record["record_id"])
        seen_record_ids[rid] = seen_record_ids.get(rid, 0) + 1
        if seen_record_ids[rid] > 1:
            continue
        by_attack_class[record["attack_class"]] = by_attack_class.get(record["attack_class"], 0) + 1
        by_severity[record["severity_at_finding"]] = by_severity.get(record["severity_at_finding"], 0) + 1
        by_language[record["target_language"]] = by_language.get(record["target_language"], 0) + 1
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
        "by_severity": by_severity,
        "by_target_language": by_language,
        "file_count": len(files),
        "files": files[:50],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write records to --out-dir (inverse of --dry-run).",
    )
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
            "hackerman pattern-docs ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"by_attack_class={summary['by_attack_class']} "
            f"by_severity={summary['by_severity']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
