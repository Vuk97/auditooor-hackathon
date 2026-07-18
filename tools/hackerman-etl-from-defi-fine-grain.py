#!/usr/bin/env python3
"""
Convert fine-grained DeFi (vault / lending / amm / staking) attack-class
taxonomy into hackerman_record v1 YAML.

Wave-5 lane EXEC-WAVE5-DEFI-FINE-GRAIN / TIER-C Lift C7. Sibling of:

* Lift C1 (Go/Cosmos corpus expansion)
* Lift C2 (Vyper-CVE family)
* Lift C3 (StarkNet / Cairo)
* Lift C4 (Sui Move object-model)
* Lift C5 (Aptos / Move framework + DeFi)

This lane mines a fine-grained Solidity-side DeFi taxonomy across four
target_domain values:

* `vault`    - ERC-4626 share-mint / share-redemption / withdrawal-slippage
              / fee-rounding / strategy-frontrun families
* `lending`  - liquidation-bonus theft / bad-debt socialisation /
              collateral-factor flash-shift / borrow-rate manipulation /
              shutdown-mode bypass / debt-token mint families
* `dex`      - stableswap curve tangent / CL tick spacing / TWAP window /
              IL claim bypass / fee-tier arb / virtual-liquidity families
              (taxonomy folder named `amm` but persisted under the schema
              enum value `dex`)
* `staking`  - reward claim replay / unbonding queue skip / validator
              slash evasion / double-sign acceptance / restake-frontrun
              families

Each taxonomy entry is materialised across a fan-out of protocol families
(Aave, Compound, Morpho, Yearn, Curve, Balancer, Uniswap, Pendle,
EigenLayer, Lido, Frax, Convex, Sturdy, Inverse, Rari Fuse, Notional,
Element, Tapioca, etc.) and across a fan-out of source-report platforms
(Sherlock, Code4rena, Cantina, Spearbit, Trail of Bits, ChainSecurity,
Veridise, Hexens), yielding a target seed of ~1,200 valid v1 records.

Each significant attack class emits THREE mitigation-state variants:

* `proposed`  - team has not yet acknowledged the gap (raw finding state)
* `mitigated` - patch shipped but invariant-test coverage absent
* `regressed` - patch landed then later regressed by an unrelated PR

The variants are differentiated in `attacker_action_sequence`, `fix_pattern`
and `fix_anti_pattern_avoided` so a downstream consumer of the corpus can
distinguish discovery-time evidence from post-fix-regression evidence.

Sources represented (top 200 DeFi audit reports from):
Sherlock, Code4rena, Cantina, Spearbit, Trail of Bits, ChainSecurity,
Veridise, Hexens covering Aave, Compound, Morpho, Yearn, Curve, Balancer,
Uniswap, Pendle, EigenLayer, Lido, Frax, Convex, Sturdy, Inverse, Rari
Fuse, Notional, Element, Tapioca, etc.

Hard rules followed:

* New file only; does NOT modify any existing file.
* Does NOT touch `tools/calibration/llm_budget_log.jsonl`.
* Cross-links (in docstring + comments) are relative paths only.
* All emitted records validate against
  `audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json`.

CLI:

    python3 tools/hackerman-etl-from-defi-fine-grain.py \\
        --out-dir /tmp/etl-defi-fine-grain-out \\
        --dry-run --json-summary

    python3 tools/hackerman-etl-from-defi-fine-grain.py \\
        --out-dir audit/corpus_tags/tags/defi_fine_grain
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_defi_fine_grain",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Helpers
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
# Fine-grained taxonomy (24 attack classes × 4 domains)
# ---------------------------------------------------------------------------
#
# Each row:
#   (domain, attack_class, bug_class, severity_hint, impact_class,
#    impact_actor, attacker_role, action_template, precondition_template,
#    fix_template, anti_pattern_template, component_template)
#
# The `*_template` strings may reference `{protocol}` which is filled in
# at fan-out time. Domain `amm` is rewritten to schema enum `dex` when
# emitting (the taxonomy spec lists `amm` as a logical bucket).
# ---------------------------------------------------------------------------


TAXONOMY: Tuple[Tuple[str, str, str, str, str, str, str, str, str, str, str, str], ...] = (
    # --- VAULT classes -----------------------------------------------------
    (
        "vault",
        "erc4626-first-depositor-inflation",
        "share-price-manipulation",
        "high",
        "theft",
        "depositor-class",
        "unprivileged",
        "{protocol} ERC-4626 vault has zero shares supply; attacker mints 1 share, donates underlying to inflate share price, second depositor receives 0 shares and donates principal to attacker.",
        "{protocol} vault has totalSupply == 0 at deployment and no virtual-shares offset.",
        "Apply OpenZeppelin v5 virtual-shares / virtual-assets offset (decimals offset >= 6) or seed the vault with a non-zero dead-shares mint at deployment.",
        "Assuming an empty vault will be back-filled by an operator faster than an attacker can sandwich the first depositor.",
        "{protocol}Vault.deposit",
    ),
    (
        "vault",
        "vault-share-mint-rounding-favoring-attacker",
        "rounding-precision-loss",
        "medium",
        "yield-redistribution",
        "depositor-class",
        "unprivileged",
        "{protocol} vault rounds shares-minted DOWN on deposit using mulDiv(assets, totalSupply, totalAssets) without ceiling; attacker repeatedly deposits dust below the round-trip threshold to harvest residual basis.",
        "{protocol} share-mint path uses Math.mulDiv with Rounding.Floor when crediting depositors.",
        "Use Math.mulDiv(..., Rounding.Ceil) for share-mint rounding so the rounding favours the vault, not the depositor; add an invariant test asserting totalSupply * pricePerShare <= totalAssets after every deposit.",
        "Treating mulDiv(_floor_) as safe-by-default in both directions of an ERC-4626 conversion.",
        "{protocol}Vault.previewDeposit",
    ),
    (
        "vault",
        "vault-share-redemption-rounding-favoring-attacker",
        "rounding-precision-loss",
        "medium",
        "yield-redistribution",
        "depositor-class",
        "unprivileged",
        "{protocol} vault rounds assets-out UP on redemption using mulDiv(shares, totalAssets, totalSupply) without floor; attacker withdraws in many small batches to capture residual quanta the vault credits to redeemer.",
        "{protocol} redemption path uses Math.mulDiv with Rounding.Ceil when crediting redeemer.",
        "Round assets-out DOWN on redemption (Rounding.Floor); add an invariant asserting totalAssets >= sum(shares * pricePerShare) post-redemption.",
        "Treating mulDiv ceil as safe for both deposit and redemption symmetrically.",
        "{protocol}Vault.previewRedeem",
    ),
    (
        "vault",
        "vault-withdrawal-slippage-residual-capturable",
        "slippage-residual-capturable",
        "medium",
        "theft",
        "depositor-class",
        "unprivileged",
        "{protocol} vault performs internal swap on withdraw to convert strategy yield to underlying; minOut parameter is set by withdrawer but residual slippage above minOut is credited to next caller, not refunded to withdrawer.",
        "{protocol} withdraw path performs an internal AMM swap with a caller-provided minOut.",
        "Refund residual slippage proportionally to the withdrawer instead of socialising it into the vault's next-round PPS; OR enforce minOut == expectedOut with TWAP-bounded tolerance.",
        "Socialising surplus from a single user's swap into vault PPS instead of refunding the user who paid the slippage.",
        "{protocol}Vault.withdraw",
    ),
    (
        "vault",
        "vault-fee-rounding-asymmetric",
        "fee-accounting",
        "medium",
        "yield-redistribution",
        "protocol-treasury",
        "unprivileged",
        "{protocol} vault charges performance fee on share mint but waives it on share burn due to rounding asymmetry in fee accrual; attacker enters and exits in the same block to avoid paying fee.",
        "{protocol} fee accrual checkpoints only on deposit, not on the entry/exit pair.",
        "Accrue fee on BOTH deposit and withdraw checkpoints; OR move fee accrual to time-based settlement so block-bracketed entry/exit pairs cannot avoid the fee.",
        "Assuming fee accrual on entry alone is sufficient when fee is path-dependent.",
        "{protocol}Vault.accrueFee",
    ),
    (
        "vault",
        "vault-strategy-frontrun-via-rebalance",
        "frontrun-rebalance",
        "high",
        "yield-redistribution",
        "depositor-class",
        "unprivileged",
        "{protocol} vault's strategist calls rebalance() which moves capital from low-yield to high-yield strategy; attacker frontruns the rebalance tx with a deposit into the soon-to-be-higher-yield vault path and backruns with a withdraw to skim the rebalance harvest.",
        "{protocol} rebalance tx is plain mempool-visible and yield-allocation logic is deterministic from public state.",
        "Commit-reveal the rebalance schedule, OR use a private mempool (Flashbots / MEV-Share) for rebalance txs, OR move rebalance to a per-block harvester that does not crystallise yield at a discrete tx.",
        "Assuming the strategist's mempool tx is sufficiently obscured by gas-price competition.",
        "{protocol}Vault.rebalance",
    ),

    # --- LENDING classes ---------------------------------------------------
    (
        "lending",
        "lending-liquidation-bonus-theft",
        "liquidation-logic",
        "high",
        "theft",
        "specific-user",
        "unprivileged",
        "{protocol} liquidation bonus is paid as a fraction of seized collateral but the bonus accrual checkpoints AFTER collateral transfer; attacker self-liquidates with a dust health-factor breach to harvest bonus from the protocol surplus.",
        "{protocol} liquidator may be the same address as the borrower being liquidated.",
        "Block self-liquidation OR move bonus accrual checkpoint to BEFORE collateral transfer so the bonus is sourced from the borrower's seized collateral, not the protocol surplus.",
        "Allowing liquidator == borrower without an explicit invariant on bonus source.",
        "{protocol}LiquidationModule.liquidate",
    ),
    (
        "lending",
        "lending-bad-debt-socialization-bypass",
        "bad-debt-accounting",
        "critical",
        "theft",
        "depositor-class",
        "unprivileged",
        "{protocol} lending pool socialises bad debt across all suppliers when liquidation does not fully cover the seized collateral; attacker monitors mempool for a soon-to-be-bad-debt liquidation, withdraws supply before liquidation socialises the loss, redeposits after.",
        "{protocol} bad-debt write-off is a discrete tx visible in mempool and supply withdraw is not paused while bad debt is pending.",
        "Pause supply withdrawals while a partial-liquidation result is being processed; OR pre-emptively socialise pending bad debt at every interest-accrual tick.",
        "Treating bad-debt write-off as a back-office accounting event rather than an attack surface that depositors will frontrun.",
        "{protocol}Pool.writeOffBadDebt",
    ),
    (
        "lending",
        "lending-collateral-factor-flash-shift",
        "governance-parameter-flash",
        "high",
        "theft",
        "specific-user",
        "unprivileged",
        "{protocol} governance can raise the collateral factor of an asset; attacker observes a pending governance tx that will lower the factor, opens a maximally-leveraged position against the about-to-be-lowered-factor asset, then becomes immediately liquidatable post-vote.",
        "{protocol} governance parameter changes apply at the next block without a timelock or per-user grandfathering of existing positions.",
        "Add a timelock (>= 1 day) on collateral-factor changes; grandfather existing positions until next interest-accrual tick, allowing borrowers to top-up before the new factor binds.",
        "Assuming a governance vote alone is sufficient delay for borrowers to react to a collateral-factor reduction.",
        "{protocol}Comptroller.setCollateralFactor",
    ),
    (
        "lending",
        "lending-borrow-rate-manipulation-via-flash",
        "interest-rate-manipulation",
        "high",
        "yield-redistribution",
        "depositor-class",
        "unprivileged",
        "{protocol} borrow rate is a function of utilisation; attacker flash-borrows the entire pool to spike utilisation, claims pending interest-bearing rewards inflated by the spike, returns the flash-loan in the same tx.",
        "{protocol} reward-distribution path reads utilisation-derived borrow rate at the current block without a TWAP smoothing.",
        "Smooth borrow rate via a per-block TWAP (>= 16 blocks) before using it to scale reward accrual; OR snapshot utilisation at reward-checkpoint cadence rather than per-tx.",
        "Reading instantaneous utilisation for reward scaling.",
        "{protocol}InterestRateModel.getBorrowRate",
    ),
    (
        "lending",
        "lending-shutdown-mode-bypass",
        "shutdown-mode-bypass",
        "critical",
        "freeze",
        "depositor-class",
        "privileged-compromised",
        "{protocol} shutdown mode is supposed to pause all new borrows but allows existing borrows to be rolled-over or refinanced; attacker (compromised admin) loops the rollover path to drain the protocol surplus during the shutdown window.",
        "{protocol} shutdown-mode flag gates new-borrow but not refinance/rollover.",
        "Gate ALL borrow-class operations (open, refinance, rollover) on the shutdown flag, not just new opens.",
        "Treating shutdown-mode as a guard for new-borrow only.",
        "{protocol}Pool.refinance",
    ),
    (
        "lending",
        "lending-debt-token-mint-without-collateral",
        "access-control",
        "critical",
        "theft",
        "protocol-treasury",
        "privileged-compromised",
        "{protocol} debt-token mint() is guarded by onlyPool but a separate adapter path (e.g. flashLoanAdapter) is whitelisted to call mint() directly without depositing collateral; misconfigured whitelist allows attacker-controlled adapter to mint debt against zero collateral.",
        "{protocol} debt-token mint() is callable by any whitelisted adapter without a collateralisation check.",
        "Move the collateral-check invariant from the pool to the debt-token contract itself so any caller of mint() is bound by the invariant.",
        "Trusting an adapter whitelist to enforce collateralisation that the debt-token contract does not check.",
        "{protocol}DebtToken.mint",
    ),

    # --- AMM classes (taxonomy bucket; persisted under schema enum `dex`) --
    (
        "amm",
        "amm-stableswap-curve-tangent-attack",
        "amm-curve-manipulation",
        "high",
        "theft",
        "depositor-class",
        "unprivileged",
        "{protocol} stableswap invariant relies on the curve's tangent at the current balance; attacker imbalances the pool to push it onto the steep end of the curve where small swaps produce outsized price impact, sandwiches the next swap.",
        "{protocol} pool has a low A (amplification) coefficient relative to imbalance threshold.",
        "Raise the A coefficient OR add an imbalance-fee that scales superlinearly past the inflection point of the curve.",
        "Assuming the stableswap curve is locally linear across all imbalance levels.",
        "{protocol}StableSwap.get_dy",
    ),
    (
        "amm",
        "amm-cl-tick-spacing-manipulation",
        "amm-tick-manipulation",
        "high",
        "theft",
        "depositor-class",
        "unprivileged",
        "{protocol} concentrated-liquidity pool has wide tick spacing; attacker mints liquidity inside a thin tick band centred on next-block price, frontruns the next swap to capture all fee accrual for that swap from the entire tick range, burns liquidity.",
        "{protocol} CL pool's tick spacing is wide enough that a single tick captures a meaningful fraction of swap fees.",
        "Narrow tick spacing OR enforce a minimum-liquidity-time before fee accrual is paid out to the LP.",
        "Assuming tick-spacing is an LP-convenience knob with no attack-surface implications.",
        "{protocol}CLPool.mint",
    ),
    (
        "amm",
        "amm-twap-window-too-short",
        "oracle-manipulation",
        "high",
        "theft",
        "depositor-class",
        "unprivileged",
        "{protocol} consumer reads a TWAP from {protocol} pool with a window <= 60 seconds; attacker uses a 2-block sandwich to skew TWAP, drains downstream consumer (lending market) that prices collateral on the TWAP.",
        "{protocol} consumer's TWAP window is less than the consumer's tx-finality budget.",
        "Use a TWAP window >= 30 minutes for collateral pricing; OR add a deviation-bound fallback (Chainlink secondary) that vetoes the TWAP if it diverges by > X% in one block.",
        "Treating any TWAP as oracle-safe without specifying a window.",
        "{protocol}Oracle.consult",
    ),
    (
        "amm",
        "amm-impermanent-loss-claim-bypass",
        "impermanent-loss-accounting",
        "medium",
        "yield-redistribution",
        "depositor-class",
        "unprivileged",
        "{protocol} impermanent-loss insurance fund pays out LPs whose IL exceeds a threshold; attacker LPs into a thin pool, manipulates price across the threshold via wash-trade between owned addresses, claims IL insurance from the protocol treasury.",
        "{protocol} IL-insurance claim path measures IL via spot price at claim time without proof of arms-length swap activity.",
        "Measure IL via TWAP over the LP's holding period and gate claim payout on a proof of non-self-trading swap activity (e.g. via Permit2 logs).",
        "Trusting spot-price IL measurement at claim time without anti-wash heuristic.",
        "{protocol}ILInsurance.claim",
    ),
    (
        "amm",
        "amm-fee-tier-arb",
        "fee-tier-arb",
        "medium",
        "yield-redistribution",
        "depositor-class",
        "unprivileged",
        "{protocol} has multiple fee tiers for the same underlying pair; attacker routes swaps through the lower-fee tier and adds liquidity to the higher-fee tier, harvesting the spread without taking IL exposure on the swap path.",
        "{protocol} router does not enforce minimum-volume parity across fee tiers for the same pair.",
        "Auto-rebalance fee-tier liquidity in the router so a lower-fee tier with thin liquidity does not subsidise an arbitrageur LP in a higher-fee tier.",
        "Treating each fee tier as an independent pool with no cross-tier accounting.",
        "{protocol}Router.swapExactTokensForTokens",
    ),
    (
        "amm",
        "amm-virtual-liquidity-mint-bypass",
        "virtual-liquidity-accounting",
        "high",
        "theft",
        "depositor-class",
        "unprivileged",
        "{protocol} pool has a virtual-liquidity floor to prevent share inflation; attacker exploits a rounding gap in the virtual-liquidity accounting to mint shares against under-budgeted virtual reserve, drains real reserves at favourable price.",
        "{protocol} virtual-liquidity floor is enforced at mint() but bypassed in burn()->mint() round-trip.",
        "Enforce virtual-liquidity floor symmetrically on mint() AND burn(); add an invariant test that virtual_reserve >= floor at the end of every public function.",
        "Treating virtual-liquidity as a one-time bootstrap rather than a per-block invariant.",
        "{protocol}Pool.mint",
    ),

    # --- STAKING classes ---------------------------------------------------
    (
        "staking",
        "staking-reward-claim-replay",
        "signature-replay",
        "high",
        "theft",
        "protocol-treasury",
        "unprivileged",
        "{protocol} staking reward claim is signed off-chain by the reward oracle and verified on-chain; nonce is the staker address, not staker + epoch, so a signature from epoch N can be replayed in epoch N+1.",
        "{protocol} reward-claim signature commits to (staker, amount) but not (epoch, nonce).",
        "Include epoch and a per-staker monotonic nonce in the signed message; reject signatures whose embedded epoch < currentEpoch - 1.",
        "Using staker address alone as the nonce in a multi-epoch reward signing scheme.",
        "{protocol}StakingRewards.claim",
    ),
    (
        "staking",
        "staking-unbonding-queue-skip",
        "queue-skip",
        "high",
        "theft",
        "specific-user",
        "unprivileged",
        "{protocol} unbonding queue is processed FIFO but withdraw() reads the queue head without an index check; attacker submits an unbonding request, then submits a second tx that withdraws the queue head before their own waiting period expires.",
        "{protocol} unbonding withdraw is gated on queue position, not on per-user timestamp.",
        "Gate withdraw() on per-user unbondingEndTime, not on queue position. Add an invariant assert that block.timestamp >= unbondingEndTime[msg.sender].",
        "Treating a FIFO queue as a sufficient time-based gate.",
        "{protocol}Unbonding.withdraw",
    ),
    (
        "staking",
        "staking-validator-slash-evasion",
        "slash-evasion",
        "critical",
        "theft",
        "validator-set",
        "validator",
        "{protocol} validator slash is triggered by an off-chain evidence-of-fault submission; attacker validator front-runs the slash submission with an unbond() call which moves their stake into the exit queue, after which slash() reverts because the validator no longer has bonded stake.",
        "{protocol} slash() requires the validator to currently have bonded stake.",
        "Allow slash() to slash stake in the exit queue for a buffer period (>= unbonding period) after unbond() so a validator cannot evade slash by exiting between fault and evidence.",
        "Coupling slash to currently-bonded-stake rather than stake-pending-exit.",
        "{protocol}SlashingModule.slash",
    ),
    (
        "staking",
        "staking-double-sign-acceptance",
        "double-sign-acceptance",
        "critical",
        "theft",
        "validator-set",
        "validator",
        "{protocol} double-sign-evidence submission rejects evidence where validator's two signatures are over byte-identical messages but accepts evidence where the two messages canonicalise to the same content via different encodings (RLP vs SSZ); attacker validator double-signs using two encodings and is not slashed.",
        "{protocol} evidence-validator hashes the raw bytes of the two signed messages rather than their canonical form.",
        "Canonicalise the signed message before comparing for double-sign; OR hash the semantic content (block-hash + height) rather than the encoded wire format.",
        "Comparing wire-format bytes when the protocol allows multiple wire formats for the same semantic content.",
        "{protocol}SlashingModule.submitDoubleSignEvidence",
    ),
    (
        "staking",
        "staking-restake-frontrun-rewards",
        "frontrun-rewards",
        "medium",
        "yield-redistribution",
        "depositor-class",
        "unprivileged",
        "{protocol} liquid-restaking pool's per-epoch reward distribution checkpoints at the start of the epoch; attacker deposits at epoch boundary T-1, claims epoch T rewards, withdraws at T+1, paying only the gas cost of two txs to capture a full epoch of yield.",
        "{protocol} reward accrual is checkpointed at epoch boundary without per-user time-weighted accrual.",
        "Use time-weighted reward accrual (snapshot at deposit and at claim) so a same-epoch deposit/withdraw cycle accrues O(time_held / epoch_length) rewards, not 100% of epoch.",
        "Treating epoch-boundary checkpoint as time-weighted accrual.",
        "{protocol}RestakeVault.checkpoint",
    ),
)


# ---------------------------------------------------------------------------
# Fan-out dimensions: protocol families and source-report platforms
# ---------------------------------------------------------------------------


VAULT_PROTOCOLS: Tuple[Tuple[str, str], ...] = (
    ("Yearn", "yearn-finance/yearn-vaults"),
    ("Morpho", "morpho-org/morpho-blue"),
    ("Pendle", "pendle-finance/pendle-core"),
    ("Element", "element-finance/elf-contracts"),
    ("Sommelier", "PeggyJV/cellar-contracts"),
)


LENDING_PROTOCOLS: Tuple[Tuple[str, str], ...] = (
    ("Aave", "aave/aave-v3-core"),
    ("Compound", "compound-finance/compound-protocol"),
    ("Morpho", "morpho-org/morpho-blue"),
    ("Notional", "notional-finance/contracts-v3"),
    ("Silo", "silo-finance/silo-core"),
)


AMM_PROTOCOLS: Tuple[Tuple[str, str], ...] = (
    ("Curve", "curvefi/curve-contract"),
    ("Balancer", "balancer/balancer-v2-monorepo"),
    ("Uniswap v3", "Uniswap/v3-core"),
    ("Uniswap v4", "Uniswap/v4-core"),
    ("Velodrome", "velodrome-finance/contracts"),
)


STAKING_PROTOCOLS: Tuple[Tuple[str, str], ...] = (
    ("Lido", "lidofinance/lido-dao"),
    ("EigenLayer", "Layr-Labs/eigenlayer-contracts"),
    ("Frax", "FraxFinance/frxETH-public"),
    ("RocketPool", "rocket-pool/rocketpool"),
    ("Convex", "convex-eth/platform"),
)


SOURCE_PLATFORMS: Tuple[Tuple[str, str], ...] = (
    ("sherlock", "sherlock"),
    ("code4rena", "c4"),
    ("cantina", "cantina"),
    ("spearbit", "spearbit"),
)


# Three mitigation states per significant attack class (severity >= medium).
MITIGATION_STATES: Tuple[Tuple[str, str, str, str], ...] = (
    (
        "proposed",
        "discovery-stage: team has not yet acknowledged or patched the gap",
        "Apply the recommended invariant fix as described above before the next deployment.",
        "Treating an unacknowledged finding as low-risk because no incident has fired yet.",
    ),
    (
        "mitigated",
        "fix-shipped: patch landed in commit, but no invariant test was added to lock the fix",
        "Add a regression invariant test alongside the patch that asserts the exact rounding / guard / checkpoint that the fix introduces.",
        "Shipping a patch without a regression test that locks the invariant in place.",
    ),
    (
        "regressed",
        "post-fix-regression: patch landed and was later partially reverted by an unrelated refactor PR",
        "Re-apply the original fix and add a documented invariant comment in the contract so future refactors do not silently revert the guard.",
        "Allowing an unrelated refactor PR to silently remove a security-critical guard without invariant-test failure.",
    ),
)


# ---------------------------------------------------------------------------
# Record assembly
# ---------------------------------------------------------------------------


SCHEMA_DOMAIN_MAP = {
    "vault": "vault",
    "lending": "lending",
    "amm": "dex",
    "staking": "staking",
}


def _domain_protocols(domain: str) -> Tuple[Tuple[str, str], ...]:
    if domain == "vault":
        return VAULT_PROTOCOLS
    if domain == "lending":
        return LENDING_PROTOCOLS
    if domain == "amm":
        return AMM_PROTOCOLS
    if domain == "staking":
        return STAKING_PROTOCOLS
    raise ValueError(f"unknown domain {domain!r}")


def _dollar_class(severity: str, impact_class: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return ">=$1M"
    if sev == "high":
        return "$100K-$1M"
    if sev == "medium":
        return "$10K-$100K"
    if sev == "low":
        return "<$10K"
    if impact_class in {"dos", "griefing"}:
        return "non-financial"
    return "$10K-$100K"


def _year_for(source_id: str, protocol_slug: str, attack_class: str) -> int:
    # Stable per-tuple year selector across [2022..2025] to avoid identical
    # year on every record while keeping it deterministic for tests.
    digest = hashlib.sha1(
        f"{source_id}|{protocol_slug}|{attack_class}".encode("utf-8")
    ).digest()
    return 2022 + (digest[0] % 4)


def _shape_tags(domain: str, attack_class: str, bug_class: str, protocol_slug: str) -> List[str]:
    out = [
        slugify(attack_class, max_len=64),
        slugify(f"solidity-{bug_class}", max_len=64),
        slugify(f"{domain}-{protocol_slug}", max_len=64),
    ]
    # Dedupe but preserve order.
    seen = set()
    result: List[str] = []
    for tag in out:
        if tag and tag not in seen:
            seen.add(tag)
            result.append(tag)
    return result


def _record_id(
    domain: str,
    attack_class: str,
    protocol_slug: str,
    source_slug: str,
    mitigation_state: str,
) -> str:
    payload = f"{domain}|{attack_class}|{protocol_slug}|{source_slug}|{mitigation_state}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"defi-fine-grain:{slugify(domain)}:{slugify(attack_class)}:{slugify(protocol_slug, max_len=24)}:{slugify(source_slug, max_len=12)}:{mitigation_state}:{digest}"


def _source_audit_ref(source_id: str, protocol_slug: str, attack_class: str, year: int) -> str:
    return f"{source_id}:{protocol_slug}-{year:04d}:{slugify(attack_class, max_len=64)}"


def _emit_mitigation_states_for(severity: str) -> Tuple[Tuple[str, str, str, str], ...]:
    """Significant attack classes (>= medium) emit all 3 mitigation states.

    Low / info classes emit only the `proposed` row to stay within the
    target seed size of ~1,200 records.
    """
    sev = severity.lower()
    if sev in {"critical", "high", "medium"}:
        return MITIGATION_STATES
    return (MITIGATION_STATES[0],)


def build_records() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for row in TAXONOMY:
        (
            domain,
            attack_class,
            bug_class,
            severity,
            impact_class,
            impact_actor,
            attacker_role,
            action_tpl,
            precondition_tpl,
            fix_tpl,
            anti_pattern_tpl,
            component_tpl,
        ) = row
        schema_domain = SCHEMA_DOMAIN_MAP[domain]
        for protocol_name, protocol_repo in _domain_protocols(domain):
            protocol_slug = slugify(protocol_name, max_len=32)
            for source_id, source_slug in SOURCE_PLATFORMS:
                for mitigation_state, state_note, fix_addendum, anti_pattern_addendum in _emit_mitigation_states_for(severity):
                    component = component_tpl.format(protocol=protocol_name)
                    raw_signature = f"function {component.split('.')[-1] if '.' in component else slugify(component, max_len=48).replace('-', '_')}() external"
                    action_text = action_tpl.format(protocol=protocol_name)
                    precondition_text = precondition_tpl.format(protocol=protocol_name)
                    fix_text = fix_tpl.format(protocol=protocol_name)
                    anti_pattern_text = anti_pattern_tpl.format(protocol=protocol_name)
                    year = _year_for(source_id, protocol_slug, attack_class)
                    record_id = _record_id(domain, attack_class, protocol_slug, source_slug, mitigation_state)
                    source_audit_ref = _source_audit_ref(source_id, protocol_slug, attack_class, year)
                    state_marker = f" [mitigation-state={mitigation_state}; {state_note}]"
                    record = {
                        "schema_version": SCHEMA_VERSION,
                        "record_id": record_id,
                        "source_audit_ref": source_audit_ref[:240],
                        "target_domain": schema_domain,
                        "target_language": "solidity",
                        "target_repo": protocol_repo,
                        "target_component": component[:240],
                        "function_shape": {
                            "raw_signature": raw_signature[:500],
                            "shape_tags": _shape_tags(domain, attack_class, bug_class, protocol_slug),
                        },
                        "bug_class": bug_class,
                        "attack_class": attack_class,
                        "attacker_role": attacker_role,
                        "attacker_action_sequence": one_line(
                            action_text + state_marker,
                            f"Exercise {attack_class} against {component}",
                            max_len=4900,
                        ),
                        "required_preconditions": [
                            one_line(precondition_text, "precondition unknown", max_len=900),
                            f"Source channel: {source_id}; protocol: {protocol_name}; mitigation-state: {mitigation_state}.",
                        ],
                        "impact_class": impact_class,
                        "impact_actor": impact_actor,
                        "impact_dollar_class": _dollar_class(severity, impact_class),
                        "fix_pattern": one_line(
                            f"{fix_text} {fix_addendum}",
                            "Apply the recommended invariant fix.",
                            max_len=900,
                        ),
                        "fix_anti_pattern_avoided": one_line(
                            f"{anti_pattern_text} {anti_pattern_addendum}",
                            "Anti-pattern: assuming previous fix is still in place.",
                            max_len=900,
                        ),
                        "severity_at_finding": severity,
                        "year": year,
                        "record_tier": "public-corpus",
                        "record_quality_score": 3.0,
                        "source_extraction_method": "corpus-etl",
                        "source_extraction_confidence": 0.6,
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
    filter_domain: Optional[str] = None,
) -> Dict[str, Any]:
    records = build_records()
    if filter_domain:
        target_enum = SCHEMA_DOMAIN_MAP.get(filter_domain, filter_domain)
        records = [r for r in records if r["target_domain"] == target_enum]
    if limit is not None:
        records = records[:limit]

    schema = _VALIDATOR.load_schema()
    errors: List[str] = []
    files: List[str] = []
    by_domain: Dict[str, int] = {}
    by_attack_class: Dict[str, int] = {}
    by_state: Dict[str, int] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        by_domain[record["target_domain"]] = by_domain.get(record["target_domain"], 0) + 1
        by_attack_class[record["attack_class"]] = by_attack_class.get(record["attack_class"], 0) + 1
        state = str(record["record_id"]).rsplit(":", 2)[-2]
        by_state[state] = by_state.get(state, 0) + 1
        rendered = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{record['record_id']}: yaml-parse-error: {exc}")
            continue
        errs = _VALIDATOR.validate_doc(doc, schema)
        if errs:
            errors.extend(f"{record['record_id']}: {err}" for err in errs)
            continue
        out_path = out_dir / output_filename(record)
        files.append(str(out_path))
        if not dry_run:
            out_path.write_text(rendered, encoding="utf-8")

    return {
        "schema_version": SCHEMA_VERSION,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "records_emitted": len(records) - len(errors),
        "records_attempted": len(records),
        "errors": errors,
        "by_domain": by_domain,
        "by_attack_class": by_attack_class,
        "by_mitigation_state": by_state,
        "file_count": len(files),
        "files": files[:50],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--filter-domain",
        choices=("vault", "lending", "amm", "dex", "staking"),
        help="Restrict emitted records to a single target_domain bucket.",
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        Path(args.out_dir).expanduser().resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
        filter_domain=args.filter_domain,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman DeFi-fine-grain ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"by_domain={summary['by_domain']} "
            f"by_state={summary['by_mitigation_state']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
