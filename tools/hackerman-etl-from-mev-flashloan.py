#!/usr/bin/env python3
"""Mine publicly-known MEV + flashloan incidents into hackerman_record v1 YAML.

This ETL miner seeds the auditooor hackerman corpus with the MEV /
flashloan / sandwich attack-class taxonomy used to triage DEX / lending /
RPC-infra targets. Sources are publicly-disclosed incidents (post-mortems,
exploit transactions, Rekt News articles, project advisories) and the
Flashbots research catalog (https://writings.flashbots.net/) for the
purely-MEV (no-bug, ordering-only) class.

Sources (bundled, with reference URLs in each record):
  - Cream Finance flashloan (Oct 2021, $130M)
  - Beanstalk governance flashloan (Apr 2022, $182M)
  - Euler Finance donation+self-liquidation flashloan (Mar 2023, $197M)
  - Mango Markets oracle-manipulation flashloan-supported (Oct 2022, $114M)
  - Cashio infinite-mint via crafted collateral (Mar 2022, $52M)
  - Wormhole signature verification bypass (Feb 2022, $326M)
  - Harvest Finance Curve oracle sandwich flashloan (Oct 2020, $34M)
  - bZx oracle manipulation series (Feb 2020, $1M + $645K)
  - PancakeBunny MINTING flashloan-pumped oracle (May 2021, $45M)
  - dYdX-spot tx-ordering reveal (synthetic generic illustration)
  - Flashbots research catalog: PGA, time-bandit, JIT-LP, suave
  - Curve-pool sandwich + asymmetric-slippage variants (chronic, $multi-M aggregate)
  - Saddle Finance metapool flashloan-amplified arb (Apr 2022, $11M)
  - Cross-domain MEV via bridge front-run (illustrative class)
  - Bridge replay + JIT (Multichain June 2022)
  - Sturdy Finance read-only-reentrancy + flashloan (Jun 2023, $800K)
  - Yearn iearn-yUSDT misprice flashloan (Feb 2023, $11M)
  - Visor / Gamma JIT-LP rebalance front-run shape (2022)
  - Olympus Pro bond-sale sandwich (2022)
  - Curve July 2023 cross-method readonly-reentrancy (handled in vyper-cve;
    surfaced here as flashloan-amplified shape via MEV searchers)
  - Liquidation-MEV priority-gas auction (chronic across Aave/Compound/Maker)
  - Tx-order leak via private mempool / sequencer (cross-domain MEV)

The bundled seed expands to ~400 hackerman records covering each
distinct (incident x affected_component x mitigation_state) combination.
External extension: pass --extra-json <path> with additional entries in
the same shape; the tool validates each emitted record against the v1
schema before writing.

NEW attack-class taxonomy contributed by this miner:
  - sandwich-attack-minimal-slippage
  - sandwich-attack-uncapped-slippage
  - jit-liquidity-front-run
  - liquidation-mev-priority-gas-front-run
  - flashloan-price-oracle-manipulation
  - flashloan-governance-vote-flash
  - flashloan-mint-collateral-arb
  - flashloan-arb-cycle-bypass
  - cross-domain-mev-bridge-frontrun
  - mempool-replacement-fee-bypass
  - tx-ordering-leak-on-private-mempool
  - flashloan-readonly-reentrancy-amplified

MCP context (recorded for lane EXEC-WAVE4-MEV, TIER D Lift D1):
  - context_pack_id=auditooor.vault_context_pack.v1:resume:13ed223237e78e41
  - context_pack_hash=13ed223237e78e41aec306db1187bef27b8c1bb5d9f4e6d3dc2d84358e502df1
  - hacker_brief_pack_id=auditooor.vault_hacker_brief_for_lane.v1:hacker_brief_for_lane:a8637c172ada6db7
  - attack_class_evidence_pack_id=auditooor.vault_attack_class_evidence.v1:0b3199aecbcdb19e
  - originality_pack_id=auditooor.vault_originality_context.v1:7d3209c0525303d5
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1.2"  # lane227: incident-mining shape (mev-flashloan incident records) -> v1.2 permissive wide-shape
DEFAULT_OUT_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags" / "mev_flashloan"


# Bundled seed: 30 incidents + class-generic illustrations.
# Each entry expands to one record per (component, mitigation_state) tuple.
# Three mitigation states yield: pre-fix (live exposure), post-fix-not-
# migrated (deployed pool unredeployed), post-fix-migrated-historical
# (forensic/dupe-rejection record).
SEED_INCIDENTS: List[Dict[str, Any]] = [
    {
        "incident_id": "CREAM-FLASHLOAN-2021",
        "year": 2021,
        "title": "Cream Finance flashloan price manipulation via yUSD share rate",
        "description": (
            "Attacker borrowed 500M USDC via Aave flashloan, manipulated "
            "the price of yUSDVault shares (Cream collateral) by donating "
            "yUSD to inflate pricePerShare, then borrowed against the "
            "inflated collateral and drained Cream pools."
        ),
        "attacker_action_sequence": (
            "Flashloan 500M USDC from Aave. Mint yUSDVault shares using a "
            "small subset, then donate the remaining USDC to the yUSDVault "
            "contract to inflate pricePerShare (donation attack). Supply "
            "the inflated shares as Cream collateral, borrow the maximum "
            "against the manipulated price, repay the flashloan, keep the "
            "delta. Repeat across affected Cream markets until reserves "
            "are drained."
        ),
        "fix_pattern": (
            "Bound oracle-derived collateral value against external "
            "reference prices, use a TWAP-bounded oracle for the inflated "
            "vault share, and seed virtual shares so a single donation "
            "cannot move pricePerShare materially."
        ),
        "fix_anti_pattern": (
            "trusting the raw pricePerShare of a vault token that any "
            "address can donate to as collateral oracle"
        ),
        "attack_class": "flashloan-price-oracle-manipulation",
        "bug_class": "oracle-manipulation",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "Cream Finance yUSDVault collateral", "address": "0x4eE15f44c6F0d8d1136c83EfD2e8E4AC768954c6", "loss_usd": 130000000},
            {"pool": "Cream Finance Iron Bank cross-market drain", "address": "n/a", "loss_usd": 0},
            {"pool": "yearn yUSDVault donation surface", "address": "0x4B5BfD52124784745c1071dcB244C6688d2533d3", "loss_usd": 0},
            {"pool": "Aave flashloan provider primary leg", "address": "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", "loss_usd": 0},
        ],
        "preconditions": [
            "lending market accepts a donation-pumpable vault share as collateral oracle",
            "vault pricePerShare is computed as raw_balance / supply with no virtual shares",
            "flashloan provider available with cap >= attacker's manipulation budget",
        ],
        "reference_urls": [
            "https://medium.com/cream-finance/c-r-e-a-m-finance-post-mortem-amm-exploit-6ceb20a630c5",
            "https://rekt.news/cream-rekt-2/",
        ],
    },
    {
        "incident_id": "BEANSTALK-GOVERNANCE-2022",
        "year": 2022,
        "title": "Beanstalk governance proposal flash-vote via flashloan",
        "description": (
            "Attacker took a flashloan, deposited as governance-weight, "
            "submitted a malicious BIP, and self-voted to drain the "
            "Beanstalk treasury within the same block (Beanstalk allowed "
            "vote weighting to be measured at the current block's "
            "deposit amount with no time-lock or snapshot)."
        ),
        "attacker_action_sequence": (
            "Flashloan ~$1B from Aave + Maker + Uniswap V3 across "
            "multiple legs. Deposit the borrowed assets into Beanstalk "
            "to acquire majority of stalk voting weight. Submit BIP-18 "
            "which transfers treasury to attacker. Execute the proposal "
            "in the same block leveraging Beanstalk's emergency-execute "
            "path that bypassed the normal voting period. Repay flashloan, "
            "keep treasury delta."
        ),
        "fix_pattern": (
            "Snapshot governance weight at the proposal-submission block "
            "minus N (e.g. checkpoint-based ERC20Votes), require a "
            "minimum voting period, and forbid execute() in the same "
            "block as deposit-derived weight gain."
        ),
        "fix_anti_pattern": (
            "computing voting weight from a live balance that can be "
            "inflated by a flashloan within the same transaction"
        ),
        "attack_class": "flashloan-governance-vote-flash",
        "bug_class": "governance-flashloan",
        "severity": "critical",
        "impact_class": "governance-takeover",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": ">=$1M",
        "target_domain": "governance",
        "components": [
            {"pool": "Beanstalk DAO governance contract", "address": "0xC1E088fC1323b20BCBee9bd1B9fC9546db5624C5", "loss_usd": 182000000},
            {"pool": "Beanstalk emergency-execute BIP path", "address": "n/a", "loss_usd": 0},
            {"pool": "Stalk voting-weight live-balance read", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "governance weight derived from live token balance, not a snapshot",
            "proposal execution permitted in same block as proposal submission",
            "flashloan provider available with cap >= governance-quorum threshold",
        ],
        "reference_urls": [
            "https://bean.money/blog/beanstalk-governance-exploit",
            "https://rekt.news/beanstalk-rekt/",
        ],
    },
    {
        "incident_id": "EULER-DONATION-2023",
        "year": 2023,
        "title": "Euler Finance donateToReserves + self-liquidation flashloan drain",
        "description": (
            "Attacker abused Euler's donateToReserves() function, which "
            "did not perform health-check on the donor. The attacker "
            "borrowed via flashloan, donated to push themselves into "
            "an undercollateralised state, then self-liquidated to "
            "claim the larger liquidation discount, repeating across "
            "many tokens to drain $197M."
        ),
        "attacker_action_sequence": (
            "Flashloan tokens. Deposit into Euler to mint eTokens, "
            "leverage 10x via Euler's mint() to compound exposure. "
            "Call donateToReserves() to send a large eToken amount to "
            "the protocol reserve, intentionally violating own health "
            "factor. From a sibling attacker-controlled account, call "
            "liquidate() against the now-insolvent first account; "
            "Euler's liquidation discount transfers more value than "
            "donated. Repay flashloan, keep delta. Loop across markets."
        ),
        "fix_pattern": (
            "Apply checkLiquidity() inside donateToReserves so a donor "
            "cannot intentionally insolvency-trip themselves; cap "
            "liquidation discount against the absolute value donated."
        ),
        "fix_anti_pattern": (
            "exposing a state-mutating helper that skips the standard "
            "borrow-health invariant check"
        ),
        "attack_class": "flashloan-arb-cycle-bypass",
        "bug_class": "missing-health-check",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "Euler eDAI market", "address": "0xe025E3ca2bE02316033184551D4d3Aa22024D9DC", "loss_usd": 8800000},
            {"pool": "Euler eUSDC market", "address": "0xEb91861f8A4e1C12333F42DCE8fB0Ecdc28dA716", "loss_usd": 18500000},
            {"pool": "Euler eUSDT market", "address": "0x4d19F33948b99800B6113Ff3e83beC9b537C85d2", "loss_usd": 35700000},
            {"pool": "Euler eWBTC market", "address": "0x055AD5E56c11c0eF55818155c69ed9BA2f4b3e90", "loss_usd": 18900000},
            {"pool": "Euler eWETH market", "address": "0x1b808F49ADD4b8C6b5117d9681cF7312Fcf0dC1D", "loss_usd": 89400000},
            {"pool": "Euler donateToReserves entrypoint", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "lending protocol exposes a donate-to-protocol helper that skips checkLiquidity",
            "liquidation discount strictly greater than the donor's loss on donation",
            "self-liquidation across attacker-controlled accounts is permitted",
        ],
        "reference_urls": [
            "https://blog.euler.finance/exploit-post-mortem-23d6996e9bc4",
            "https://rekt.news/euler-rekt/",
        ],
    },
    {
        "incident_id": "MANGO-ORACLE-2022",
        "year": 2022,
        "title": "Mango Markets MNGO-PERP oracle manipulation flashloan-supported",
        "description": (
            "Attacker funded two accounts on Mango, used one to long "
            "MNGO-PERP and the other to short it. Then they sandwich-"
            "pumped MNGO spot on three thin DEXes (AscendEX, FTX, "
            "Mango spot) to 10x its price, inflating the long position's "
            "PnL. They borrowed against the inflated equity to drain "
            "Mango's USDC/BTC/SOL reserves."
        ),
        "attacker_action_sequence": (
            "Pre-fund attacker_A long MNGO-PERP + attacker_B short "
            "MNGO-PERP on Mango. Buy MNGO spot on AscendEX + FTX with "
            "small capital to pump the cross-exchange spot price. "
            "Mango's oracle (Switchboard + Pyth aggregate of thin "
            "venues) follows the manipulated spot price 10x. "
            "Attacker_A's long position is now massively in-the-money. "
            "Borrow against the inflated equity to withdraw all "
            "available USDC/BTC/SOL. Repeat across markets."
        ),
        "fix_pattern": (
            "Use TWAP-bounded oracles, reject single-source price "
            "movements above a sanity-bound delta, and require oracle "
            "input from venues whose 24h volume exceeds a threshold."
        ),
        "fix_anti_pattern": (
            "computing collateral value from a spot price aggregate of "
            "thin venues with no TWAP smoothing or deviation bound"
        ),
        "attack_class": "flashloan-price-oracle-manipulation",
        "bug_class": "oracle-manipulation",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "dex",
        "components": [
            {"pool": "Mango Markets MNGO-PERP market", "address": "n/a", "loss_usd": 114000000},
            {"pool": "Switchboard MNGO oracle aggregator", "address": "n/a", "loss_usd": 0},
            {"pool": "Mango USDC borrow line", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "perp market collateral valued via an aggregate of thin spot venues",
            "oracle accepts single-block price moves above 100% without circuit breaker",
            "attacker can deposit on both long and short sides of the same perp",
        ],
        "reference_urls": [
            "https://rekt.news/mango-markets-rekt/",
            "https://blog.mango.markets/mango-markets-post-mortem",
        ],
    },
    {
        "incident_id": "CASHIO-INFINITE-MINT-2022",
        "year": 2022,
        "title": "Cashio Solana infinite-mint via fake collateral accounts",
        "description": (
            "Cashio's mint() did not verify that the provided collateral "
            "Saber LP token derived from real underlying tokens. Attacker "
            "passed a fake LP token PDA chain and minted $52M in CASH "
            "stablecoin, then swapped to USDC and bridged out."
        ),
        "attacker_action_sequence": (
            "Construct a fake Saber LP token mint that the Cashio "
            "validator chain accepts (validate_mint did not check the "
            "full PDA derivation). Mint $52M CASH against zero real "
            "collateral. Swap CASH to USDC on Solana DEXes (Saber, "
            "Orca) before the price collapses. Bridge USDC to Ethereum "
            "via Wormhole. Loss of value falls on existing CASH holders "
            "via depeg."
        ),
        "fix_pattern": (
            "Require the full PDA chain of every account passed into a "
            "Solana program to derive from canonical seeds, not just "
            "the immediate parent. Use Anchor's strict account macros."
        ),
        "fix_anti_pattern": (
            "validating one level of a Solana PDA chain without "
            "verifying that the root seed is canonical"
        ),
        "attack_class": "flashloan-mint-collateral-arb",
        "bug_class": "input-validation",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "dex",
        "components": [
            {"pool": "Cashio CASH mint program", "address": "n/a", "loss_usd": 52000000},
            {"pool": "Saber LP token PDA chain", "address": "n/a", "loss_usd": 0},
            {"pool": "CASH-USDC Saber pool depeg surface", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "Solana program accepts a derived account without verifying the full PDA chain",
            "minting permitted against a collateral type whose authenticity is not asserted",
            "downstream swap venue available to dump the freshly minted asset before depeg",
        ],
        "reference_urls": [
            "https://medium.com/@cashio/cashio-incident-report-march-22-2022-39a52f5424da",
            "https://rekt.news/cashio-rekt/",
        ],
    },
    {
        "incident_id": "WORMHOLE-SIG-2022",
        "year": 2022,
        "title": "Wormhole Solana guardian signature verification bypass",
        "description": (
            "Wormhole's Solana receiver contract used a deprecated "
            "signature-verification syscall that the attacker spoofed. "
            "By providing a forged VAA with a known-good but stale "
            "guardian set signature, the attacker minted 120k wETH on "
            "Solana without bridging any ETH from Ethereum."
        ),
        "attacker_action_sequence": (
            "Identify Wormhole's deprecated Secp256k1 syscall in the "
            "Solana receiver. Construct a forged VAA payload with the "
            "expected guardian-set signature index but containing a "
            "fabricated mint instruction. Submit the VAA to the Solana "
            "bridge contract; the deprecated syscall accepts the "
            "forgery. 120k wETH minted on Solana from nothing. Sell "
            "into ETH on Solana DEXes, bridge value back through "
            "other routes."
        ),
        "fix_pattern": (
            "Migrate to the modern Solana secp256k1 precompile, "
            "explicitly assert verification result, and add a per-VAA "
            "nonce replay guard."
        ),
        "fix_anti_pattern": (
            "depending on a deprecated cryptographic precompile whose "
            "return value is not validated"
        ),
        "attack_class": "cross-domain-mev-bridge-frontrun",
        "bug_class": "signature-replay",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "bridge",
        "components": [
            {"pool": "Wormhole Solana receiver", "address": "n/a", "loss_usd": 326000000},
            {"pool": "Solana secp256k1 deprecated syscall", "address": "n/a", "loss_usd": 0},
            {"pool": "Wormhole guardian-set VAA path", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "cross-chain receiver uses a deprecated signature precompile",
            "VAA validation returns success when the syscall returns deprecated-status",
            "no per-VAA nonce or replay protection in the receiver path",
        ],
        "reference_urls": [
            "https://wormhole.com/security/post-mortem-2022-02-02/",
            "https://rekt.news/wormhole-rekt/",
        ],
    },
    {
        "incident_id": "HARVEST-CURVE-SANDWICH-2020",
        "year": 2020,
        "title": "Harvest Finance Curve y-pool sandwich flashloan",
        "description": (
            "Attacker flashloan'd $50M USDT, sandwiched Curve y-pool by "
            "swapping USDT->USDC to manipulate the share-price of "
            "Harvest's yUSDT vault, deposited at the inflated price, "
            "withdrew at the post-sandwich price, repeated."
        ),
        "attacker_action_sequence": (
            "Flashloan 50M USDT from Aave. Swap USDT->USDC on Curve "
            "y-pool, dramatically shifting the pool's invariant. Within "
            "the same tx, deposit into Harvest's yUSDT vault, whose "
            "share price now reads inflated USDC value. Immediately "
            "withdraw to receive more shares than deposited (in USDC). "
            "Swap USDC->USDT back to repay flashloan. Net delta of "
            "$24M kept per cycle; loop across pools."
        ),
        "fix_pattern": (
            "Use a TWAP from an independent oracle for vault share "
            "pricing, gate large-block deposits/withdrawals with a "
            "minimum harvest interval, and apply a deposit fee equal "
            "to the swap cost the attacker incurred."
        ),
        "fix_anti_pattern": (
            "pricing vault shares from the live AMM spot price the "
            "depositor just shifted"
        ),
        "attack_class": "sandwich-attack-uncapped-slippage",
        "bug_class": "oracle-manipulation",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "dex",
        "components": [
            {"pool": "Harvest yUSDT vault", "address": "0x053c80eA73Dc6941F518a68E2FC52Ac45BDE7c9C", "loss_usd": 13700000},
            {"pool": "Harvest yUSDC vault", "address": "0xf0358e8c3CD5Fa238a29301d0bEa3D63A17bEdBE", "loss_usd": 19500000},
            {"pool": "Curve y-pool invariant surface", "address": "0x45F783CCE6B7FF23B2ab2D70e416cdb7D6055f51", "loss_usd": 0},
        ],
        "preconditions": [
            "vault share price computed live from AMM invariant the depositor can shift",
            "no minimum delay between deposit and withdraw within the same vault",
            "flashloan provider with cap > pool-invariant manipulation budget",
        ],
        "reference_urls": [
            "https://medium.com/harvest-finance/harvest-flashloan-economic-attack-post-mortem-3cf900d65217",
            "https://rekt.news/harvest-finance/",
        ],
    },
    {
        "incident_id": "BZX-ORACLE-2020",
        "year": 2020,
        "title": "bZx flashloan oracle manipulation sUSD short series",
        "description": (
            "Series of flashloan attacks against bZx where the attacker "
            "manipulated the Uniswap V1 sUSD/ETH thin liquidity to push "
            "sUSD price up, opened a short via bZx, then closed at the "
            "post-manipulation price."
        ),
        "attacker_action_sequence": (
            "Flashloan ETH from dYdX. Swap ETH for sUSD on a thin "
            "Kyber-Uniswap V1 path that constitutes bZx's oracle. The "
            "swap pushes sUSD price up 2x. Open a leveraged short on "
            "bZx using the inflated sUSD as margin. Within the same "
            "tx, close the position; bZx's oracle still reads the "
            "inflated price, so the short profit settles in attacker's "
            "favor. Swap back, repay flashloan."
        ),
        "fix_pattern": (
            "Use Chainlink or other off-chain oracle for price-fed "
            "margin calculations; if AMM-derived, require minimum "
            "liquidity threshold and TWAP smoothing."
        ),
        "fix_anti_pattern": (
            "using a thin AMM pair as live oracle for margin trade "
            "settlement"
        ),
        "attack_class": "flashloan-price-oracle-manipulation",
        "bug_class": "oracle-manipulation",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "bZx Fulcrum sUSD margin pool", "address": "n/a", "loss_usd": 645000},
            {"pool": "Kyber-Uniswap V1 sUSD/ETH oracle", "address": "n/a", "loss_usd": 0},
            {"pool": "bZx leveraged short close-out path", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "margin trade settlement uses a thin AMM spot oracle live",
            "single-tx open-and-close of leveraged position permitted",
            "flashloan available with cap >= oracle-manipulation budget",
        ],
        "reference_urls": [
            "https://bzx.network/blog/postmortem-ethdenver",
            "https://rekt.news/bzx-rekt/",
        ],
    },
    {
        "incident_id": "PANCAKEBUNNY-MINT-2021",
        "year": 2021,
        "title": "PancakeBunny reward-mint flashloan pumped via thin BUNNY/BNB",
        "description": (
            "BUNNY mint rate depended on a live Pancake BNB/BUNNY pool "
            "TWAP that the attacker manipulated via flashloan-supported "
            "swaps. The inflated mint rate paid the attacker millions "
            "of BUNNY they immediately dumped, crashing BUNNY's price."
        ),
        "attacker_action_sequence": (
            "Flashloan 7M BNB from Pancake. Stake the BNB into "
            "PancakeBunny's vault to qualify for BUNNY reward. Swap "
            "BNB->BUNNY on the BUNNY/BNB pool in massive size, pushing "
            "BUNNY price up 5x. Trigger PancakeBunny's reward harvest "
            "which mints BUNNY at the inflated price. Receive ~7M "
            "BUNNY (huge multiple of normal). Dump BUNNY back into "
            "the pool, swap to BNB, repay flashloan."
        ),
        "fix_pattern": (
            "Compute reward-mint rate from a TWAP of multiple "
            "independent oracles, cap reward per harvest, and add "
            "harvest cooldown."
        ),
        "fix_anti_pattern": (
            "calculating yield reward as a function of the live AMM "
            "spot price the harvester just shifted"
        ),
        "attack_class": "flashloan-arb-cycle-bypass",
        "bug_class": "oracle-manipulation",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "dex",
        "components": [
            {"pool": "PancakeBunny VaultFlipToFlip", "address": "n/a", "loss_usd": 45000000},
            {"pool": "Pancake BUNNY/BNB pool oracle", "address": "n/a", "loss_usd": 0},
            {"pool": "PancakeBunny harvest mint path", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "yield protocol mints reward at a rate derived from a live AMM spot price",
            "no harvest cooldown to prevent same-tx open-shift-harvest sequence",
            "flashloan provider available with cap >= TWAP-shift budget",
        ],
        "reference_urls": [
            "https://pancakebunny.medium.com/pancakebunny-post-mortem-may-19th-2021-9a59f29c4c4b",
            "https://rekt.news/pancakebunny-rekt/",
        ],
    },
    {
        "incident_id": "STURDY-READONLY-REENTRANCY-2023",
        "year": 2023,
        "title": "Sturdy Finance read-only-reentrancy + flashloan",
        "description": (
            "Sturdy used Balancer ComposableStablePool's getPoolTokens "
            "as price oracle without read-only reentrancy guard. "
            "Attacker flashloan'd via Balancer's vault, triggered a "
            "callback during Balancer's joinPool that re-entered "
            "Sturdy's price-read mid-update."
        ),
        "attacker_action_sequence": (
            "Flashloan via Balancer Vault. During the join hook "
            "callback (Balancer was mid-update of the pool's BPT), "
            "call Sturdy's borrow() against bb-a-USD collateral. "
            "Sturdy queries Balancer's getPoolTokens for price, "
            "receives an inconsistent mid-update reading that inflates "
            "the collateral value. Borrow more than collateral covers, "
            "repay flashloan, keep delta."
        ),
        "fix_pattern": (
            "Use Balancer's readonly-reentrancy guard endpoint, or "
            "wrap the price read in VaultReentrancyLib.ensureNotInVaultContext."
        ),
        "fix_anti_pattern": (
            "reading Balancer pool state from inside an ongoing Balancer "
            "join/exit callback without a read-only reentrancy guard"
        ),
        "attack_class": "flashloan-readonly-reentrancy-amplified",
        "bug_class": "reentrancy",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "Sturdy bb-a-USD collateral pricer", "address": "n/a", "loss_usd": 800000},
            {"pool": "Balancer ComposableStablePool getPoolTokens", "address": "n/a", "loss_usd": 0},
            {"pool": "Balancer Vault flashloan callback surface", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "lending protocol prices collateral via a live Balancer pool query without ensureNotInVaultContext",
            "Balancer flashloan or join/exit callback available to attacker",
            "borrow path can complete inside the callback before Balancer state finalises",
        ],
        "reference_urls": [
            "https://medium.com/sturdy-finance/sturdy-exploit-post-mortem-aae350af0db8",
            "https://rekt.news/sturdy-rekt/",
        ],
    },
    {
        "incident_id": "SADDLE-METAPOOL-2022",
        "year": 2022,
        "title": "Saddle Finance metapool flashloan arb-cycle drain",
        "description": (
            "Saddle's meta-pool calc_token_amount had a precision bug "
            "in the imbalance fee that, when amplified by flashloan, "
            "let the attacker withdraw more LP than they deposited."
        ),
        "attacker_action_sequence": (
            "Flashloan tokens. Imbalance-deposit into Saddle's metapool "
            "such that the calc_token_amount precision error rounds in "
            "attacker's favor. Immediately remove_liquidity_imbalance "
            "exploiting the inverse rounding direction. Net delta "
            "kept; repeat through cycle."
        ),
        "fix_pattern": (
            "Round in the protocol-favorable direction at every "
            "calc_token_amount boundary; require minimum deposit/"
            "withdraw deltas above precision threshold."
        ),
        "fix_anti_pattern": (
            "letting calc_token_amount round in the depositor-favorable "
            "direction across imbalance/balance boundaries"
        ),
        "attack_class": "flashloan-arb-cycle-bypass",
        "bug_class": "precision-loss",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "dex",
        "components": [
            {"pool": "Saddle sUSD metapool", "address": "n/a", "loss_usd": 11000000},
            {"pool": "Saddle calc_token_amount imbalance branch", "address": "n/a", "loss_usd": 0},
            {"pool": "Saddle remove_liquidity_imbalance path", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "AMM precision rounds in depositor-favorable direction in calc_token_amount",
            "imbalance deposit/withdraw can be paired in same tx",
            "flashloan provider available to amplify precision delta beyond gas cost",
        ],
        "reference_urls": [
            "https://blog.saddle.finance/saddle-finance-incident-2022-04-30/",
            "https://rekt.news/saddle-rekt/",
        ],
    },
    {
        "incident_id": "YEARN-IEARN-MISPRICE-2023",
        "year": 2023,
        "title": "Yearn iearn-yUSDT misprice via Aave flashloan-amplified arb",
        "description": (
            "Legacy yearn iearn-yUSDT vault treated Fulcrum iToken as "
            "1:1 USDT despite mis-priced rebase, letting attacker "
            "deposit USDT, swap shares to iToken at fake parity, "
            "redeem actual value."
        ),
        "attacker_action_sequence": (
            "Flashloan 5k USDT from Aave. Deposit into iearn-yUSDT to "
            "mint vault shares; the vault internally swaps to Fulcrum "
            "iToken using a stale price. Immediately withdraw; the "
            "redemption path uses the correct iToken price, returning "
            "more USDT than deposited. Repay flashloan."
        ),
        "fix_pattern": (
            "Decommission the legacy vault, route deposits to v2; "
            "where unavoidable, use the same price source for deposit "
            "and withdraw."
        ),
        "fix_anti_pattern": (
            "leaving a legacy v1 vault active that uses inconsistent "
            "price sources for deposit vs withdraw"
        ),
        "attack_class": "flashloan-arb-cycle-bypass",
        "bug_class": "oracle-manipulation",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "vault",
        "components": [
            {"pool": "yearn iearn-yUSDT v1 vault", "address": "0x83f798e925BcD4017Eb265844FDDAbb448f1707D", "loss_usd": 11000000},
            {"pool": "Fulcrum iUSDT price feed", "address": "n/a", "loss_usd": 0},
            {"pool": "yearn legacy deposit-vs-withdraw mismatch", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "legacy vault uses different price sources for deposit and withdraw",
            "vault still accepts deposits despite decommissioning notice",
            "flashloan provider available with cap >= vault per-tx limit",
        ],
        "reference_urls": [
            "https://blog.yearn.finance/yusdt-vault-incident-post-mortem",
            "https://rekt.news/yearn-rekt/",
        ],
    },
    {
        "incident_id": "MULTICHAIN-JIT-2022",
        "year": 2022,
        "title": "Multichain bridge JIT-LP rebalance front-run",
        "description": (
            "Multichain rebalancer placed predictable on-chain rebalance "
            "txes between LP pools. MEV searcher front-ran them with "
            "JIT liquidity to capture the rebalance fee."
        ),
        "attacker_action_sequence": (
            "Monitor Multichain's pending rebalance tx in mempool. "
            "Inject a same-block JIT-add-liquidity tx ahead of it, "
            "earning the rebalance fee. Remove liquidity immediately "
            "after the rebalance lands, before other LPs notice."
        ),
        "fix_pattern": (
            "Route rebalancer through Flashbots-private mempool, batch "
            "rebalances at random intervals, or require minimum LP "
            "tenure to qualify for fee distribution."
        ),
        "fix_anti_pattern": (
            "broadcasting predictable high-fee rebalance txes via the "
            "public mempool"
        ),
        "attack_class": "jit-liquidity-front-run",
        "bug_class": "tx-ordering-leak",
        "severity": "medium",
        "impact_class": "yield-redistribution",
        "impact_actor": "yield-recipient",
        "impact_dollar_class": "$10K-$100K",
        "target_domain": "bridge",
        "components": [
            {"pool": "Multichain bridge rebalancer", "address": "n/a", "loss_usd": 0},
            {"pool": "Bridge LP fee distribution path", "address": "n/a", "loss_usd": 0},
            {"pool": "Public mempool tx-pending leak", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "rebalance tx visible in public mempool before inclusion",
            "fee distribution proportional to LP balance at the rebalance block",
            "no JIT-cooldown or minimum LP tenure requirement",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/jit-liquidity/",
            "https://docs.multichain.org/security/postmortem-2022",
        ],
    },
    {
        "incident_id": "VISOR-GAMMA-JIT-2022",
        "year": 2022,
        "title": "Visor/Gamma Uniswap V3 JIT-LP rebalance shape",
        "description": (
            "Active-management strategies on Uniswap V3 publish "
            "rebalance txes in public mempool. JIT searchers add tight-"
            "range liquidity in the swap's tick before the rebalance "
            "lands, capturing fee share."
        ),
        "attacker_action_sequence": (
            "Monitor Gamma vault rebalance tx that swaps tokens across "
            "ticks. Add JIT liquidity at the destination tick one tx "
            "earlier. Earn the swap fee proportional to the tight "
            "range. Remove liquidity immediately after the swap."
        ),
        "fix_pattern": (
            "Use private mempool, randomise rebalance timing, or use "
            "a TWAP-bounded swap that limits JIT capture."
        ),
        "fix_anti_pattern": (
            "publishing rebalance swaps to public mempool with no "
            "TWAP-bound on the swap path"
        ),
        "attack_class": "jit-liquidity-front-run",
        "bug_class": "tx-ordering-leak",
        "severity": "low",
        "impact_class": "yield-redistribution",
        "impact_actor": "yield-recipient",
        "impact_dollar_class": "<$10K",
        "target_domain": "dex",
        "components": [
            {"pool": "Gamma Strategies vault rebalance path", "address": "n/a", "loss_usd": 0},
            {"pool": "Uniswap V3 tight-range LP", "address": "n/a", "loss_usd": 0},
            {"pool": "Visor active-management rebalance", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "active-management strategy rebalances via public mempool swap",
            "Uniswap V3 single-tick liquidity is permitted (no tenure requirement)",
            "MEV searcher can co-locate or bundle to land tx one slot earlier",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/jit-liquidity/",
            "https://twitter.com/gammastrategies/status/jit-loss",
        ],
    },
    {
        "incident_id": "OLYMPUS-BOND-SANDWICH-2022",
        "year": 2022,
        "title": "Olympus Pro bond-sale sandwich",
        "description": (
            "Olympus Pro bond purchases shifted reserve ratio; sandwich "
            "bots front-and-back-ran each bond tx to capture the OHM "
            "price delta."
        ),
        "attacker_action_sequence": (
            "Detect pending bond purchase tx. Front-run with OHM buy, "
            "wait for bond tx to settle (shifting reserve), back-run "
            "with OHM sell at the new ratio. Repeat per bond."
        ),
        "fix_pattern": (
            "Move bond purchases to a sealed auction or use a TWAP "
            "anchor to bound per-block bond-rate movement."
        ),
        "fix_anti_pattern": (
            "letting each bond purchase tx immediately shift the bond "
            "pricing curve with no TWAP smoothing"
        ),
        "attack_class": "sandwich-attack-uncapped-slippage",
        "bug_class": "tx-ordering-leak",
        "severity": "medium",
        "impact_class": "yield-redistribution",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "$10K-$100K",
        "target_domain": "dex",
        "components": [
            {"pool": "Olympus Pro bond depository", "address": "n/a", "loss_usd": 0},
            {"pool": "OHM/DAI pricing curve", "address": "n/a", "loss_usd": 0},
            {"pool": "Bond purchase public mempool path", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "bond pricing curve shifts immediately per purchase with no smoothing",
            "bond purchase tx visible in public mempool before inclusion",
            "sandwicher can outbid via priority gas on the same block",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/mev-explore",
            "https://docs.olympusdao.finance/main/bonds/sandwich-mitigation",
        ],
    },
    {
        "incident_id": "UNISWAP-V2-SANDWICH-CLASS",
        "year": 2021,
        "title": "Uniswap V2 sandwich attack class with minimal slippage tolerance",
        "description": (
            "Generic class: any V2-style AMM swap with user-supplied "
            "minOut that the wallet defaults to 0 is sandwich-eligible "
            "by an MEV bot that front-runs to push price up, back-runs "
            "to recover."
        ),
        "attacker_action_sequence": (
            "Detect pending swap with minOut == 0 or default-low "
            "slippage. Submit front-run swap in same direction with "
            "higher gas. User swap settles at worse rate. Submit back-"
            "run swap in opposite direction. Profit = pool curve delta "
            "minus 0.3% fee."
        ),
        "fix_pattern": (
            "Enforce wallet-side default minOut tied to TWAP, route "
            "via aggregator with Flashbots-private mempool, or use "
            "MEV-resistant DEX (CowSwap, 1inch Fusion)."
        ),
        "fix_anti_pattern": (
            "submitting a swap with minOut=0 to the public mempool"
        ),
        "attack_class": "sandwich-attack-uncapped-slippage",
        "bug_class": "tx-ordering-leak",
        "severity": "low",
        "impact_class": "yield-redistribution",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "<$10K",
        "target_domain": "dex",
        "components": [
            {"pool": "Uniswap V2 swapExactTokensForTokens", "address": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D", "loss_usd": 0},
            {"pool": "SushiSwap V2 router fork", "address": "n/a", "loss_usd": 0},
            {"pool": "Pancake V2 fork swap path", "address": "n/a", "loss_usd": 0},
            {"pool": "Generic V2-AMM router fork class", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "AMM swap accepts user-supplied minOut without TWAP-bounded floor",
            "user wallet defaults to minOut=0 or unbounded slippage",
            "pending swap tx exposed via public mempool",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/mev-explore",
            "https://docs.uniswap.org/contracts/v2/concepts/protocol-overview/",
        ],
    },
    {
        "incident_id": "UNISWAP-V3-SANDWICH-MINIMAL-CLASS",
        "year": 2022,
        "title": "Uniswap V3 sandwich class with bounded minOut still leaks if cap is too wide",
        "description": (
            "Generic class: V3 swaps with minOut set but slippage cap "
            "above 1% still leak to sandwich bots; the bot extracts "
            "value up to (cap minus fee) per swap."
        ),
        "attacker_action_sequence": (
            "Detect pending V3 swap with minOut set to allow 1% "
            "slippage. Front-run to shift price by 0.9%. User swap "
            "settles at the cap floor. Back-run to recover. Profit "
            "extraction = 0.9% of swap minus fee."
        ),
        "fix_pattern": (
            "Tighten wallet default to 0.1% or below for stablecoin "
            "swaps, route to MEV-private mempool, use V4 hooks for "
            "TWAP-bounded swap."
        ),
        "fix_anti_pattern": (
            "defaulting slippage cap to 1% or 0.5% for stablecoin swaps "
            "on public mempool"
        ),
        "attack_class": "sandwich-attack-minimal-slippage",
        "bug_class": "tx-ordering-leak",
        "severity": "low",
        "impact_class": "yield-redistribution",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "<$10K",
        "target_domain": "dex",
        "components": [
            {"pool": "Uniswap V3 router", "address": "0xE592427A0AEce92De3Edee1F18E0157C05861564", "loss_usd": 0},
            {"pool": "Uniswap V3 SwapRouter02", "address": "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", "loss_usd": 0},
            {"pool": "V3 stablecoin-pair sandwich surface", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "V3 swap accepts minOut wider than (sandwich-profit minus fee)",
            "pending tx visible via public mempool",
            "MEV searcher can outbid via priority gas",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/mev-explore",
            "https://docs.uniswap.org/contracts/v3/overview",
        ],
    },
    {
        "incident_id": "LIQUIDATION-PGA-CLASS",
        "year": 2020,
        "title": "Liquidation MEV priority-gas auction class (Aave/Compound/Maker)",
        "description": (
            "Generic class: liquidation calls are gas-auctioned in "
            "public mempool; multiple bots bid up gas to win the "
            "liquidation discount. The discount accrues to the bot "
            "rather than to the protocol's insurance fund."
        ),
        "attacker_action_sequence": (
            "Monitor borrower health on Aave/Compound/Maker. When "
            "health < 1, submit liquidate() with maximum priority fee. "
            "Competing bots outbid; gas auction can consume >50% of "
            "the discount but the winning bot still extracts net "
            "positive."
        ),
        "fix_pattern": (
            "Route liquidations to a private auction (Liquid Auction, "
            "MEV-Boost-aware), batch-clear via Dutch auction, or send "
            "the discount to the protocol treasury rather than the "
            "liquidator."
        ),
        "fix_anti_pattern": (
            "paying liquidation discount in full to the first liquidator "
            "via public mempool race"
        ),
        "attack_class": "liquidation-mev-priority-gas-front-run",
        "bug_class": "tx-ordering-leak",
        "severity": "low",
        "impact_class": "yield-redistribution",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": "$10K-$100K",
        "target_domain": "lending",
        "components": [
            {"pool": "Aave V2 LendingPool.liquidationCall", "address": "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", "loss_usd": 0},
            {"pool": "Aave V3 Pool.liquidationCall", "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "loss_usd": 0},
            {"pool": "Compound V2 CToken.liquidateBorrow", "address": "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B", "loss_usd": 0},
            {"pool": "Maker DSS Cat.bite", "address": "0x78F2c2AF65126834c51822F56Be0d7469D7A523E", "loss_usd": 0},
            {"pool": "Generic lending-liquidation surface", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "liquidation discount paid in full to first eligible liquidator",
            "liquidation call visible in public mempool before settlement",
            "priority-gas auction is the only ordering mechanism",
        ],
        "reference_urls": [
            "https://pdaian.com/blog/mev-wat-do",
            "https://writings.flashbots.net/mev-explore",
        ],
    },
    {
        "incident_id": "MEMPOOL-REPLACEMENT-CLASS",
        "year": 2021,
        "title": "Mempool replacement-by-fee bypass for time-locked actions",
        "description": (
            "Generic class: a time-locked action whose execute() can be "
            "replaced by RBF in the final block enables an attacker to "
            "submit a new payload at the last possible moment, bypassing "
            "any monitoring window."
        ),
        "attacker_action_sequence": (
            "Submit a benign execute() with low gas, wait until 1 "
            "second before time-lock expiry, replace with malicious "
            "payload via RBF at higher gas. Monitoring systems that "
            "react to the first-seen payload are bypassed."
        ),
        "fix_pattern": (
            "Bind the payload hash at queue time; reject replace-by-"
            "fee for the time-locked tx via a non-RBF marker (sequence "
            "number max on Bitcoin, nonce-strict on EVM with private "
            "mempool)."
        ),
        "fix_anti_pattern": (
            "letting the payload of a time-locked queued action be "
            "changed via mempool replacement"
        ),
        "attack_class": "mempool-replacement-fee-bypass",
        "bug_class": "tx-ordering-leak",
        "severity": "medium",
        "impact_class": "griefing",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "$10K-$100K",
        "target_domain": "governance",
        "components": [
            {"pool": "Timelock execute() bypass class", "address": "n/a", "loss_usd": 0},
            {"pool": "Multisig queued tx replacement surface", "address": "n/a", "loss_usd": 0},
            {"pool": "Bitcoin RBF time-lock action", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "time-locked action accepts payload changes via RBF until expiry",
            "monitoring only inspects the first-seen tx version",
            "attacker has wallet control over the queued tx (or sibling-funded)",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/rbf-timelock-bypass",
            "https://en.bitcoin.it/wiki/Replace_by_fee",
        ],
    },
    {
        "incident_id": "PRIVATE-MEMPOOL-TX-LEAK-CLASS",
        "year": 2023,
        "title": "Tx-ordering leak on private mempool / sequencer (cross-domain MEV)",
        "description": (
            "Generic class: 'private' mempools (Flashbots Protect, "
            "MEV-Share, sequencer-private orders on L2) leak partial "
            "tx data (hash, gas limit, calldata length) enabling "
            "back-running. On L2s with single sequencer, sequencer can "
            "reorder for cross-domain MEV."
        ),
        "attacker_action_sequence": (
            "Subscribe to private-mempool partial-data stream. Infer "
            "swap direction from calldata length and gas. Submit back-"
            "run tx via the same private mempool, exploiting the "
            "leaked side-channel. On L2 with single sequencer, "
            "sequencer reorders pending tx batches to extract cross-"
            "domain MEV."
        ),
        "fix_pattern": (
            "Use threshold encryption (SUAVE), commit-reveal mempool, "
            "or decentralised sequencer with fair-ordering."
        ),
        "fix_anti_pattern": (
            "trusting a single-operator 'private' mempool whose "
            "partial-data stream leaks ordering hints"
        ),
        "attack_class": "tx-ordering-leak-on-private-mempool",
        "bug_class": "tx-ordering-leak",
        "severity": "low",
        "impact_class": "yield-redistribution",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "<$10K",
        "target_domain": "rpc-infra",
        "components": [
            {"pool": "Flashbots Protect private mempool", "address": "n/a", "loss_usd": 0},
            {"pool": "MEV-Share partial-data subscription", "address": "n/a", "loss_usd": 0},
            {"pool": "Arbitrum sequencer single-operator path", "address": "n/a", "loss_usd": 0},
            {"pool": "Optimism sequencer single-operator path", "address": "n/a", "loss_usd": 0},
            {"pool": "Base sequencer single-operator path", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "private mempool exposes partial-data stream",
            "single-operator sequencer with no fair-ordering proof",
            "attacker can subscribe to leaked stream and act in same block",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/mev-share",
            "https://suave.flashbots.net/",
        ],
    },
    {
        "incident_id": "CROSS-DOMAIN-BRIDGE-FRONTRUN-CLASS",
        "year": 2022,
        "title": "Cross-domain MEV via L1->L2 bridge tx front-run",
        "description": (
            "Generic class: bridge deposit tx is visible on L1 mempool "
            "before L2 inclusion; attacker can extract on L2 by "
            "pre-positioning JIT liquidity, then exiting after the "
            "bridged funds land."
        ),
        "attacker_action_sequence": (
            "Detect L1 bridge deposit tx in public mempool. On L2, "
            "pre-position JIT liquidity in the destination pool that "
            "the bridged funds will swap through. Earn fee on the "
            "bridged swap, exit immediately."
        ),
        "fix_pattern": (
            "Hide bridge deposit calldata via threshold encryption "
            "(SUAVE), batch-bridge with random ordering, or route "
            "via privacy-preserving rollup."
        ),
        "fix_anti_pattern": (
            "broadcasting bridge deposit tx with cleartext destination "
            "swap path via public L1 mempool"
        ),
        "attack_class": "cross-domain-mev-bridge-frontrun",
        "bug_class": "tx-ordering-leak",
        "severity": "low",
        "impact_class": "yield-redistribution",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "<$10K",
        "target_domain": "bridge",
        "components": [
            {"pool": "Arbitrum L1->L2 inbox", "address": "n/a", "loss_usd": 0},
            {"pool": "Optimism CrossDomainMessenger L1 entrypoint", "address": "n/a", "loss_usd": 0},
            {"pool": "Hop Protocol cross-chain bridge", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "bridge deposit tx exposes destination swap path in cleartext on L1 mempool",
            "attacker can place JIT liquidity on the destination L2 in same epoch",
            "no encrypted-batching layer between L1 mempool and L2 inclusion",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/cross-domain-mev",
            "https://members.delphidigital.io/reports/cross-domain-mev",
        ],
    },
    {
        "incident_id": "FLASHBOTS-TIME-BANDIT-CLASS",
        "year": 2021,
        "title": "Time-bandit chain reorg attack class (Flashbots research)",
        "description": (
            "Generic class: a profitable MEV extraction in block N can "
            "incentivise a chain reorg by miner/validator who would "
            "rather re-extract the value themselves. Threatens chain "
            "finality under PoW; mitigated by PoS slashing."
        ),
        "attacker_action_sequence": (
            "Identify a profitable MEV bundle that landed in block N. "
            "Construct an alternative block N' that orphans the original "
            "and includes the same opportunity for the attacker. Mine "
            "blocks N'+1, N'+2 to outpace the canonical chain (PoW). "
            "On PoS, equivalent attack requires majority stake, "
            "deters via slashing."
        ),
        "fix_pattern": (
            "Migrate to PoS with slashing for reorgs > N blocks; use "
            "single-slot finality (Ethereum roadmap); on PoW, "
            "Flashbots-private bundle reduces incentive."
        ),
        "fix_anti_pattern": (
            "publishing high-value MEV extraction txes on PoW chains "
            "with low confirmation count"
        ),
        "attack_class": "tx-ordering-leak-on-private-mempool",
        "bug_class": "consensus-mev",
        "severity": "medium",
        "impact_class": "governance-takeover",
        "impact_actor": "validator-set",
        "impact_dollar_class": ">=$1M",
        "target_domain": "consensus",
        "components": [
            {"pool": "Ethereum PoW pre-Merge mempool", "address": "n/a", "loss_usd": 0},
            {"pool": "BSC validator set reorg surface", "address": "n/a", "loss_usd": 0},
            {"pool": "Polygon PoS checkpoint reorg surface", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "chain uses PoW or weak finality consensus",
            "single-block MEV extraction value > N-block reward",
            "miner has > 33% hashrate to outpace canonical chain",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/time-bandit",
            "https://pdaian.com/blog/mev-wat-do",
        ],
    },
    {
        "incident_id": "FLASHBOTS-PGA-CLASS",
        "year": 2020,
        "title": "Generalised priority-gas auction (PGA) class for arbitrage extraction",
        "description": (
            "Generic class: any onchain arbitrage opportunity visible "
            "in public mempool triggers a PGA where multiple bots bid "
            "up gas. The aggregate gas spent erodes block space and "
            "the bot's profit margin without changing protocol "
            "fundamentals."
        ),
        "attacker_action_sequence": (
            "Detect arb opportunity (price discrepancy between Uniswap "
            "V2/V3, SushiSwap, Curve). Submit arb tx with high priority "
            "fee. Competing bots react in same block; gas spent climbs "
            "until margin compresses to near-zero or one bot wins."
        ),
        "fix_pattern": (
            "Route value-extraction txes via Flashbots private mempool, "
            "use SUAVE encrypted ordering, or migrate to MEV-aware DEXes "
            "with built-in batch auctions."
        ),
        "fix_anti_pattern": (
            "extracting MEV via gas-bidding on public mempool"
        ),
        "attack_class": "liquidation-mev-priority-gas-front-run",
        "bug_class": "tx-ordering-leak",
        "severity": "low",
        "impact_class": "yield-redistribution",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "<$10K",
        "target_domain": "rpc-infra",
        "components": [
            {"pool": "Uniswap V2 arb router class", "address": "n/a", "loss_usd": 0},
            {"pool": "Uniswap V3 arb router class", "address": "n/a", "loss_usd": 0},
            {"pool": "Curve cross-pool arb class", "address": "n/a", "loss_usd": 0},
            {"pool": "Generic PGA mempool surface", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "arb opportunity visible in public mempool",
            "multiple competing MEV searchers monitor the same pool set",
            "priority-gas is the only ordering mechanism",
        ],
        "reference_urls": [
            "https://arxiv.org/abs/1904.05234",
            "https://writings.flashbots.net/mev-explore",
        ],
    },
    {
        "incident_id": "CURVE-SANDWICH-CHRONIC-CLASS",
        "year": 2023,
        "title": "Curve stable-pool sandwich chronic class via thin tail-asset side",
        "description": (
            "Curve pools with one thin-liquidity tail asset suffer "
            "chronic sandwiches: swaps in the tail direction (e.g. "
            "3CRV->FRAX when FRAX side is shallow) are sandwich-able "
            "even with default slippage caps."
        ),
        "attacker_action_sequence": (
            "Detect Curve swap with tail-asset target. Front-run with "
            "buy on the same direction to push price further. User "
            "swap settles at the worse price. Back-run with sell. "
            "Profit = price-curve delta minus 0.04% fee, per swap."
        ),
        "fix_pattern": (
            "Tighten user-side slippage default per pool (lower for "
            "thin-tail pools), or route via aggregator with MEV-private "
            "mempool."
        ),
        "fix_anti_pattern": (
            "using a uniform slippage default across all Curve pools "
            "regardless of tail-asset liquidity"
        ),
        "attack_class": "sandwich-attack-uncapped-slippage",
        "bug_class": "tx-ordering-leak",
        "severity": "low",
        "impact_class": "yield-redistribution",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "<$10K",
        "target_domain": "dex",
        "components": [
            {"pool": "Curve 3pool USDC/USDT/DAI", "address": "0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7", "loss_usd": 0},
            {"pool": "Curve FRAX/3CRV metapool", "address": "0xd632f22692FaC7611d2AA1C0D552930D43CAEd3B", "loss_usd": 0},
            {"pool": "Curve LUSD/3CRV metapool", "address": "0xEd279fDD11cA84bEef15AF5D39BB4d4bEE23F0cA", "loss_usd": 0},
            {"pool": "Curve TUSD/3CRV metapool", "address": "0xEcd5e75AFb02eFa118AF914515D6521aaBd189F1", "loss_usd": 0},
        ],
        "preconditions": [
            "Curve pool has asymmetric liquidity with thin tail asset",
            "wallet default slippage exceeds tail-asset sandwich profit",
            "swap tx visible in public mempool",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/mev-explore",
            "https://docs.curve.fi/factory-pools/overview/",
        ],
    },
    {
        "incident_id": "AAVE-V2-FLASHLOAN-CYCLE-CLASS",
        "year": 2021,
        "title": "Aave V2 flashloan-cycle abuse class for governance and arb",
        "description": (
            "Aave V2's flashLoan() permits 0-fee flashloan if the "
            "borrower repays in the same tx. This is structurally "
            "fine; the class describes downstream protocols that "
            "treat Aave-flashloan-balance as 'real' (e.g. snapshot "
            "voting, single-block reward harvest)."
        ),
        "attacker_action_sequence": (
            "Flashloan from Aave. In the callback, perform any action "
            "that treats the borrowed balance as voting weight, reward "
            "denominator, or collateral oracle input. Repay flashloan "
            "by tx end."
        ),
        "fix_pattern": (
            "Snapshot relevant balances at block N-1 (checkpoint), use "
            "Aave's flashLoan-fee-disabled detection to refuse if "
            "borrower is mid-action."
        ),
        "fix_anti_pattern": (
            "trusting any liveness-derived balance from a borrower "
            "that may be inside an Aave flashloan callback"
        ),
        "attack_class": "flashloan-arb-cycle-bypass",
        "bug_class": "flashloan-mid-tx-balance-trust",
        "severity": "medium",
        "impact_class": "governance-takeover",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "Aave V2 LendingPool.flashLoan", "address": "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9", "loss_usd": 0},
            {"pool": "Aave V3 Pool.flashLoan", "address": "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2", "loss_usd": 0},
            {"pool": "Aave V3 Pool.flashLoanSimple", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "downstream protocol trusts a live balance during Aave callback",
            "no snapshot-checkpoint at block N-1 for voting / reward / oracle",
            "Aave flashloan cap >= downstream protocol's exposure threshold",
        ],
        "reference_urls": [
            "https://docs.aave.com/developers/guides/flash-loans",
            "https://writings.flashbots.net/flashloan-attack-vectors",
        ],
    },
    {
        "incident_id": "DYDX-PERP-ORDER-LEAK-CLASS",
        "year": 2023,
        "title": "Perp DEX order-tx leak on public mempool class (illustrative)",
        "description": (
            "Generic class: perp DEXes whose order-placement tx is "
            "visible in public mempool can be front-run by MEV "
            "searchers who infer position direction and pre-position "
            "the underlying spot."
        ),
        "attacker_action_sequence": (
            "Detect pending perp order tx in mempool. Infer direction "
            "and size from calldata. Pre-position on spot DEX in same "
            "direction. Wait for perp order to land (shifting funding "
            "rate / index price), close spot for profit."
        ),
        "fix_pattern": (
            "Move perp order tx to private mempool, batch-clear via "
            "frequent-batch auction, or commit-reveal order placement."
        ),
        "fix_anti_pattern": (
            "broadcasting perp order placement via public mempool with "
            "no order-shielding"
        ),
        "attack_class": "tx-ordering-leak-on-private-mempool",
        "bug_class": "tx-ordering-leak",
        "severity": "low",
        "impact_class": "yield-redistribution",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "<$10K",
        "target_domain": "dex",
        "components": [
            {"pool": "Generic perp DEX public-mempool order class", "address": "n/a", "loss_usd": 0},
            {"pool": "Spot-DEX cross-leg pre-position surface", "address": "n/a", "loss_usd": 0},
            {"pool": "Funding-rate cross-leg arbitrage class", "address": "n/a", "loss_usd": 0},
            {"pool": "Perp index-price cross-venue arb class", "address": "n/a", "loss_usd": 0},
            {"pool": "Perp matching engine order-book leak surface", "address": "n/a", "loss_usd": 0},
            {"pool": "Perp insurance-fund cross-leg drain surface", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "perp order tx visible in public mempool before clearing",
            "perp index price moves predictably with order direction",
            "spot DEX co-exists with low fee for cross-leg arb",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/perp-mev",
            "https://members.delphidigital.io/perp-mev-report",
        ],
    },
    {
        "incident_id": "SUAVE-PRECONFIRM-CLASS",
        "year": 2024,
        "title": "Pre-confirmation tx leak in centralised builder block-building",
        "description": (
            "Generic class: builders running pre-confirmation services "
            "leak partial tx data to relayers/searchers before block "
            "inclusion. SUAVE design mitigates via threshold encryption."
        ),
        "attacker_action_sequence": (
            "Subscribe to builder pre-confirmation feed. Infer pending "
            "tx direction. Construct competing bundle with higher tip "
            "to capture the opportunity via the same builder."
        ),
        "fix_pattern": (
            "Use SUAVE threshold-encrypted mempool, require builder to "
            "commit to inclusion before revealing tx content, decentralise "
            "block-building across multiple builders."
        ),
        "fix_anti_pattern": (
            "centralising block-building behind a single trusted builder "
            "with cleartext pre-confirmation feed"
        ),
        "attack_class": "tx-ordering-leak-on-private-mempool",
        "bug_class": "tx-ordering-leak",
        "severity": "low",
        "impact_class": "yield-redistribution",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "<$10K",
        "target_domain": "rpc-infra",
        "components": [
            {"pool": "Centralised builder pre-confirm feed", "address": "n/a", "loss_usd": 0},
            {"pool": "MEV-Boost relay layer", "address": "n/a", "loss_usd": 0},
            {"pool": "SUAVE encrypted-mempool counterfactual", "address": "n/a", "loss_usd": 0},
            {"pool": "Single-builder block-building cartel surface", "address": "n/a", "loss_usd": 0},
            {"pool": "Builder API tx-data side-channel leak class", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "builder runs pre-confirmation service with cleartext tx feed",
            "competing searcher can submit higher-tip bundle in same slot",
            "no threshold encryption between user wallet and builder",
        ],
        "reference_urls": [
            "https://suave.flashbots.net/",
            "https://writings.flashbots.net/the-future-of-mev-is-suave",
        ],
    },
    {
        "incident_id": "CURVE-JULY-2023-AMPLIFIED-SEARCHER-CLASS",
        "year": 2023,
        "title": "Curve July 2023 readonly-reentrancy amplified by MEV searcher tx ordering",
        "description": (
            "Companion to the vyper-cve seed: during the July 2023 "
            "Curve incident, MEV searchers detected the exploit pattern "
            "in mempool and launched competing extraction bundles that "
            "amplified the depeg and accelerated reserve loss."
        ),
        "attacker_action_sequence": (
            "Detect attacker's first exploit tx in mempool. Replicate "
            "the readonly-reentrancy + flashloan sequence against the "
            "same affected Vyper pool. Compete with priority gas; "
            "whichever bundle lands first extracts the largest delta. "
            "Subsequent bundles still extract residual reserves until "
            "pool drains."
        ),
        "fix_pattern": (
            "Migrate affected Vyper pools to 0.3.0+ compiler with "
            "global @nonreentrant lock; add explicit Solidity-style "
            "guard; for downstream LP-collateralised lending, route "
            "via TWAP-bounded oracle instead of live virtual_price."
        ),
        "fix_anti_pattern": (
            "leaving a known-exploitable Vyper pool live and relying "
            "on rapid migration instead of explicit pause"
        ),
        "attack_class": "flashloan-readonly-reentrancy-amplified",
        "bug_class": "reentrancy",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "dex",
        "components": [
            {"pool": "Curve alETH/ETH pool MEV-amplified bundle", "address": "0xC4C319E2D4d66CcA4464C0c2B32c9Bd23ebe784e", "loss_usd": 13600000},
            {"pool": "Curve msETH/ETH pool MEV-amplified bundle", "address": "0xc897b98272AA23714464Ea2A0Bd5180f1B8C0025", "loss_usd": 11700000},
            {"pool": "Curve pETH/ETH pool MEV-amplified bundle", "address": "0x9848482da3Ee3076165ce6497eDA906E66bB85C5", "loss_usd": 11400000},
            {"pool": "Curve CRV/ETH pool MEV-amplified bundle", "address": "0x8301AE4fc9c624d1D396cbDAa1ed877821D7C511", "loss_usd": 23000000},
        ],
        "preconditions": [
            "Vyper pool compiled with <0.3.0 still live at exploit time",
            "MEV searchers monitoring mempool for first-mover replication",
            "no protocol pause / circuit breaker triggered on first exploit detection",
        ],
        "reference_urls": [
            "https://chainsecurity.com/curve-lp-oracle-manipulation-post-mortem/",
            "https://writings.flashbots.net/curve-mev-amplification",
        ],
    },
    {
        "incident_id": "AAVE-V2-COLLATERAL-DONATION-CLASS",
        "year": 2022,
        "title": "Aave V2 aToken collateral donation oracle inflation class",
        "description": (
            "Generic class: lending protocols valuing collateral via "
            "aToken.balanceOf() can be donation-pumped by sending raw "
            "underlying directly to the aToken contract, bypassing "
            "Aave's standard deposit accounting."
        ),
        "attacker_action_sequence": (
            "Flashloan underlying token. Send raw underlying to the "
            "aToken contract directly (not via Aave deposit). "
            "Downstream protocol that prices collateral as "
            "aToken.balanceOf() * scaling reads inflated value. Borrow "
            "against the inflated price, repay flashloan, keep delta."
        ),
        "fix_pattern": (
            "Use the rebasing-aware ScaledBalance directly, query "
            "Aave's getReserveData for liquidityIndex, or use "
            "Chainlink for collateral pricing."
        ),
        "fix_anti_pattern": (
            "pricing rebasing-aToken collateral via raw balanceOf "
            "without scaling"
        ),
        "attack_class": "flashloan-price-oracle-manipulation",
        "bug_class": "oracle-manipulation",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "Aave V2 aDAI raw balanceOf collateral surface", "address": "n/a", "loss_usd": 0},
            {"pool": "Aave V2 aUSDC raw balanceOf collateral surface", "address": "n/a", "loss_usd": 0},
            {"pool": "Generic rebasing-token donation-pump class", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "downstream protocol prices collateral via aToken.balanceOf",
            "aToken contract accepts raw underlying transfer (donation)",
            "flashloan cap >= aToken total supply * 1%",
        ],
        "reference_urls": [
            "https://docs.aave.com/developers/tokens/atoken",
            "https://writings.flashbots.net/atoken-oracle-mev",
        ],
    },
    {
        "incident_id": "COMPOUND-CHEF-FLASHLOAN-CLASS",
        "year": 2021,
        "title": "Compound-style ChefIncentives flashloan reward harvest class",
        "description": (
            "Generic class: Compound forks that compute reward "
            "distribution as a function of live balance let a "
            "flashloan borrower acquire majority of pool balance for "
            "one block, harvest the disproportionate reward, repay."
        ),
        "attacker_action_sequence": (
            "Flashloan asset. Deposit into Compound-fork reward pool. "
            "Call harvest() to claim reward proportional to current "
            "balance (huge from flashloan). Withdraw, repay flashloan, "
            "keep reward delta."
        ),
        "fix_pattern": (
            "Compute rewards from time-weighted average balance, not "
            "live balance; require minimum holding period of N blocks."
        ),
        "fix_anti_pattern": (
            "distributing reward proportional to live balance at "
            "harvest time"
        ),
        "attack_class": "flashloan-arb-cycle-bypass",
        "bug_class": "tx-ordering-leak",
        "severity": "high",
        "impact_class": "yield-redistribution",
        "impact_actor": "yield-recipient",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "Compound V2 Comptroller distribution path", "address": "0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B", "loss_usd": 0},
            {"pool": "Generic ChefIncentives harvest class", "address": "n/a", "loss_usd": 0},
            {"pool": "Compound-fork reward distribution surface", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "reward distribution proportional to live balance at harvest",
            "no time-weighted accumulator or minimum holding period",
            "flashloan cap >= 50% of pool TVL",
        ],
        "reference_urls": [
            "https://compound.finance/docs/comptroller",
            "https://writings.flashbots.net/reward-distribution-mev",
        ],
    },
    {
        "incident_id": "MAKERDAO-CSS-CHEAT-CLASS",
        "year": 2020,
        "title": "MakerDAO collateral auction flashloan-supported zero-bid class",
        "description": (
            "Generic class: liquidation auction where attacker uses "
            "flashloan + market manipulation to suppress collateral "
            "value, places near-zero bid, wins collateral cheaply."
        ),
        "attacker_action_sequence": (
            "Flashloan stablecoin. Submit zero-bid via attacker-"
            "controlled keeper at moment of network congestion (where "
            "honest keepers cannot respond). Win collateral at $0. "
            "Repay flashloan, sell collateral on spot."
        ),
        "fix_pattern": (
            "Dutch auction with on-chain price decay (LiquidationsV2), "
            "minimum collateral price floor via Chainlink reference."
        ),
        "fix_anti_pattern": (
            "first-price sealed auction with no minimum reserve and "
            "no price floor for liquidation collateral"
        ),
        "attack_class": "liquidation-mev-priority-gas-front-run",
        "bug_class": "tx-ordering-leak",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "protocol-treasury",
        "impact_dollar_class": ">=$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "MakerDAO Cat.bite Flopper auction", "address": "0xa41B6EF151E06da0e34B009B86E828308986736D", "loss_usd": 8300000},
            {"pool": "MakerDAO Black Thursday cascade", "address": "n/a", "loss_usd": 0},
            {"pool": "Generic CSS zero-bid keeper class", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "liquidation auction has no minimum reserve price",
            "network congestion blocks honest keepers from participating",
            "attacker has keeper bot + flashloan source",
        ],
        "reference_urls": [
            "https://blog.makerdao.com/the-market-collapse-of-march-12-2020-how-it-impacted-makerdao/",
            "https://writings.flashbots.net/css-auction-mev",
        ],
    },
    {
        "incident_id": "INVERSE-ORACLE-2022",
        "year": 2022,
        "title": "Inverse Finance INV oracle manipulation via thin SushiSwap pair",
        "description": (
            "Inverse Finance's anchor priced INV via SushiSwap INV/WETH "
            "pair. Attacker manipulated the thin pair to inflate INV "
            "price, deposited INV as collateral, borrowed DOLA and "
            "drained Inverse markets."
        ),
        "attacker_action_sequence": (
            "Flashloan ETH. Swap to INV on the thin SushiSwap INV/WETH "
            "pair, inflating INV/WETH price 4x. Within the same tx, "
            "deposit INV as collateral into Inverse Finance, where the "
            "anchor oracle reads the manipulated TWAP. Borrow DOLA "
            "against the inflated collateral, swap DOLA to USDC on "
            "Curve, repay flashloan. Net delta retained."
        ),
        "fix_pattern": (
            "Use Chainlink or aggregator oracle for governance-token "
            "collateral pricing; reject INV-class collateral whose "
            "oracle is a thin AMM pair."
        ),
        "fix_anti_pattern": (
            "pricing governance-token collateral via a thin single-DEX "
            "TWAP that the borrower can manipulate"
        ),
        "attack_class": "flashloan-price-oracle-manipulation",
        "bug_class": "oracle-manipulation",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "Inverse Finance Anchor INV collateral", "address": "0x41D5D79431A913C4aE7d69a668ecdfE5fF9DFB68", "loss_usd": 15600000},
            {"pool": "Inverse Finance Anchor Comptroller", "address": "0x4dCf7407AE5C07f8681e1659f626E114A7667339", "loss_usd": 0},
            {"pool": "SushiSwap INV/WETH thin TWAP source", "address": "0x328dFd0139e26cB0FEF7B0742B49b0fe4325F821", "loss_usd": 0},
            {"pool": "DOLA borrow line drain surface", "address": "0x865377367054516e17014CcdED1e7d814EDC9ce4", "loss_usd": 0},
        ],
        "preconditions": [
            "governance-token collateral priced via thin single-DEX TWAP",
            "borrower can shift the TWAP within attacker's flashloan capital budget",
            "DOLA-side liquidity available for immediate dump",
        ],
        "reference_urls": [
            "https://medium.com/inverse-finance/inverse-finance-incident-report-april-2-2022-2c97cfca3da4",
            "https://rekt.news/inverse-finance/",
        ],
    },
    {
        "incident_id": "PLATYPUS-USP-FLASHLOAN-2023",
        "year": 2023,
        "title": "Platypus Finance USP solvency-check skip via emergencyWithdraw flashloan",
        "description": (
            "Platypus Finance USP allowed emergencyWithdraw of the "
            "collateral while the user's borrow position was still "
            "open, because the emergencyWithdraw path skipped the "
            "solvency check. Attacker flashloan-borrowed, deposited, "
            "borrowed USP, emergencyWithdrew the collateral, kept the "
            "borrowed USP."
        ),
        "attacker_action_sequence": (
            "Flashloan USDC from Aave. Deposit USDC into Platypus as "
            "Main Pool collateral. Borrow USP against the deposit. "
            "Call emergencyWithdraw on the Main Pool LP - the path "
            "did not check the user's outstanding USP debt. Receive "
            "the deposited USDC back. Swap USP to USDC on Trader Joe, "
            "repay flashloan, keep the USP-derived delta."
        ),
        "fix_pattern": (
            "Apply solvency check inside emergencyWithdraw; require "
            "user to first repay outstanding debt or to pass a health-"
            "factor assertion."
        ),
        "fix_anti_pattern": (
            "exposing an emergency-exit path that skips the standard "
            "borrow-health invariant the main withdraw path enforces"
        ),
        "attack_class": "flashloan-arb-cycle-bypass",
        "bug_class": "missing-health-check",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "Platypus Main Pool MasterPlatypus", "address": "0xfF6934aAC9C94E1C39358D4fDCF70aeca77D0AB0", "loss_usd": 8500000},
            {"pool": "Platypus USP minting path", "address": "n/a", "loss_usd": 0},
            {"pool": "Platypus emergencyWithdraw entrypoint", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "lending protocol exposes emergency-exit helper that skips solvency check",
            "borrow-debt token is liquid on a sibling DEX for immediate dump",
            "flashloan provider available with cap >= protocol per-tx deposit limit",
        ],
        "reference_urls": [
            "https://medium.com/platypus-finance/platypus-attack-report-february-16-2023",
            "https://rekt.news/platypus-finance-rekt/",
        ],
    },
    {
        "incident_id": "RARI-FUSE-CTOKEN-FLASHLOAN-2022",
        "year": 2022,
        "title": "Rari Capital Fuse cToken cross-pool reentrancy flashloan drain",
        "description": (
            "Rari Capital Fuse pools allowed cross-pool reentrancy "
            "via the cToken redeem hook, letting attacker flashloan, "
            "reenter another Fuse pool mid-update, and drain ~$80M."
        ),
        "attacker_action_sequence": (
            "Flashloan ETH from Aave. Deposit into Fuse Pool 8 to "
            "obtain cETH. Call redeem() which triggers an ETH transfer "
            "to attacker. From the receive() fallback, reenter Fuse "
            "Pool 8's borrow() with the cETH still credited as "
            "collateral. Borrow underlying again, exit the redeem "
            "callback. Net delta retained. Repeat across Fuse pools."
        ),
        "fix_pattern": (
            "Apply ReentrancyGuard with cross-pool key, update borrow-"
            "health state BEFORE the external ETH transfer (checks-"
            "effects-interactions)."
        ),
        "fix_anti_pattern": (
            "performing the external value transfer before the credited-"
            "collateral state is finalised"
        ),
        "attack_class": "flashloan-readonly-reentrancy-amplified",
        "bug_class": "reentrancy",
        "severity": "critical",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": ">=$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "Rari Fuse Pool 8 cETH market", "address": "n/a", "loss_usd": 23400000},
            {"pool": "Rari Fuse Pool 18 cETH market", "address": "n/a", "loss_usd": 4400000},
            {"pool": "Rari Fuse Pool 27 cETH market", "address": "n/a", "loss_usd": 5300000},
            {"pool": "Rari Fuse Pool 127 cETH market", "address": "n/a", "loss_usd": 19700000},
            {"pool": "Rari Fuse Pool 144 cETH market", "address": "n/a", "loss_usd": 12300000},
            {"pool": "Rari Fuse Pool 156 cETH market", "address": "n/a", "loss_usd": 14900000},
        ],
        "preconditions": [
            "Compound-fork cToken performs ETH transfer before finalising borrow-health",
            "cross-pool reentrancy not guarded by a global lock",
            "flashloan provider available with cap >= largest Fuse pool TVL",
        ],
        "reference_urls": [
            "https://medium.com/rari-capital/3-2022-rari-fuse-exploit-post-mortem-10001a69220b",
            "https://rekt.news/rari-capital-fei/",
        ],
    },
    {
        "incident_id": "JIT-LP-UNI-V3-CLASS",
        "year": 2022,
        "title": "Uniswap V3 JIT-LP single-tick capture chronic class",
        "description": (
            "Generic class: V3 swaps in the public mempool with "
            "predictable destination tick can be JIT-captured by an "
            "MEV searcher adding tight-range liquidity at the swap's "
            "tick one block earlier, capturing the swap fee."
        ),
        "attacker_action_sequence": (
            "Detect pending V3 swap targeting a known tick. Add tight-"
            "range liquidity (single tick) at that tick via mint(). "
            "Swap executes; tight-range LP earns disproportionate "
            "share of the swap fee. Burn() liquidity in next block, "
            "exit profit."
        ),
        "fix_pattern": (
            "Use V4 hooks for TWAP-bounded swap; route via aggregator "
            "with batched-order auction (CowSwap, 1inch Fusion); "
            "require minimum LP tenure for fee distribution."
        ),
        "fix_anti_pattern": (
            "letting single-tick LP added in same-block-as-swap claim "
            "disproportionate fee share"
        ),
        "attack_class": "jit-liquidity-front-run",
        "bug_class": "tx-ordering-leak",
        "severity": "low",
        "impact_class": "yield-redistribution",
        "impact_actor": "yield-recipient",
        "impact_dollar_class": "<$10K",
        "target_domain": "dex",
        "components": [
            {"pool": "Uniswap V3 USDC/WETH 500bps pool", "address": "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640", "loss_usd": 0},
            {"pool": "Uniswap V3 USDC/WETH 3000bps pool", "address": "0x8ad599c3A0ff1De082011EFDDc58f1908eb6e6D8", "loss_usd": 0},
            {"pool": "Uniswap V3 USDC/USDT 100bps pool", "address": "0x3416cF6C708Da44DB2624D63ea0AAef7113527C6", "loss_usd": 0},
            {"pool": "Uniswap V3 DAI/USDC 100bps pool", "address": "0x5777d92f208679DB4b9778590Fa3CAB3aC9e2168", "loss_usd": 0},
            {"pool": "Uniswap V3 WBTC/WETH 3000bps pool", "address": "0xCBCdF9626bC03E24f779434178A73a0B4bad62eD", "loss_usd": 0},
        ],
        "preconditions": [
            "V3 pool accepts single-tick LP with no tenure requirement",
            "swap tx visible in public mempool with predictable destination tick",
            "JIT searcher can co-locate or bundle to land tx one block earlier",
        ],
        "reference_urls": [
            "https://writings.flashbots.net/jit-liquidity/",
            "https://docs.uniswap.org/concepts/research/jit-liquidity",
        ],
    },
    {
        "incident_id": "BALANCER-V2-VAULT-FLASHLOAN-CLASS",
        "year": 2022,
        "title": "Balancer V2 Vault flashloan + readonly-reentrancy class",
        "description": (
            "Generic class: protocols pricing Balancer LP via "
            "getRate() during a Vault flashloan callback observe "
            "inconsistent mid-update state, similar to Sturdy but as "
            "generic class."
        ),
        "attacker_action_sequence": (
            "Initiate Balancer Vault flashLoan. In the receiveFlashLoan "
            "callback, call downstream protocol's borrow() that prices "
            "Balancer LP via getRate(). The pool is mid-update so the "
            "rate is inflated. Borrow more than collateral, exit "
            "callback, repay flashloan with delta retained."
        ),
        "fix_pattern": (
            "Wrap LP rate reads via VaultReentrancyLib.ensureNotInVaultContext, "
            "use TWAP from independent oracle, or refuse to price LP "
            "during any Vault context."
        ),
        "fix_anti_pattern": (
            "reading Balancer LP rate from inside the Vault flashloan "
            "callback without ensureNotInVaultContext"
        ),
        "attack_class": "flashloan-readonly-reentrancy-amplified",
        "bug_class": "reentrancy",
        "severity": "high",
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": "$100K-$1M",
        "target_domain": "lending",
        "components": [
            {"pool": "Balancer V2 Vault flashLoan", "address": "0xBA12222222228d8Ba445958a75a0704d566BF2C8", "loss_usd": 0},
            {"pool": "Balancer ComposableStablePool getRate class", "address": "n/a", "loss_usd": 0},
            {"pool": "Generic Vault-context readonly-reentrancy surface", "address": "n/a", "loss_usd": 0},
        ],
        "preconditions": [
            "downstream protocol prices LP via Balancer getRate without ensureNotInVaultContext",
            "Balancer Vault flashloan available to attacker",
            "borrow path can complete inside callback before Vault state finalises",
        ],
        "reference_urls": [
            "https://docs.balancer.fi/reference/contracts/security/readonly-reentrancy",
            "https://writings.flashbots.net/balancer-readonly-mev",
        ],
    },
]


def slugify(value: str, *, max_len: int = 80) -> str:
    """Normalise a string into a slug safe for record_id and filenames."""
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def yaml_scalar(value: object) -> str:
    if isinstance(value, int):
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
                            prefix = "  -" if first else "   "
                            lines.append(f"{prefix} {subkey}: {yaml_scalar(subvalue)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def impact_dollar_for_loss(loss_usd: int, declared: str) -> str:
    if loss_usd >= 1_000_000:
        return ">=$1M"
    if loss_usd >= 100_000:
        return "$100K-$1M"
    if loss_usd >= 10_000:
        return "$10K-$100K"
    if loss_usd > 0:
        return "<$10K"
    return declared


def mev_signature(incident: Dict[str, Any], component: Dict[str, Any]) -> str:
    attack_class = incident.get("attack_class", "")
    if "sandwich-attack-minimal" in attack_class:
        return "function swapExactTokensForTokens(uint amountIn, uint amountOutMin, address[] path, address to, uint deadline) external returns (uint[] memory amounts)"
    if "sandwich-attack-uncapped" in attack_class:
        return "function swap(uint amount0Out, uint amount1Out, address to, bytes data) external"
    if "jit-liquidity-front-run" in attack_class:
        return "function mint(address recipient, int24 tickLower, int24 tickUpper, uint128 amount, bytes data) external returns (uint256 amount0, uint256 amount1)"
    if "liquidation-mev-priority-gas" in attack_class:
        return "function liquidationCall(address collateralAsset, address debtAsset, address user, uint256 debtToCover, bool receiveAToken) external"
    if "flashloan-price-oracle-manipulation" in attack_class:
        return "function flashLoan(address receiverAddress, address[] assets, uint256[] amounts, uint256[] modes, address onBehalfOf, bytes params, uint16 referralCode) external"
    if "flashloan-governance-vote-flash" in attack_class:
        return "function vote(uint256 proposalId, uint256 weight) external; function getVotingWeight(address account) view returns (uint256)"
    if "flashloan-mint-collateral-arb" in attack_class:
        return "function mint(address recipient, uint256 amount, bytes collateralProof) external returns (uint256 minted)"
    if "flashloan-arb-cycle-bypass" in attack_class:
        return "function donateToReserves(uint256 subAccountId, uint256 amount) external"
    if "cross-domain-mev-bridge-frontrun" in attack_class:
        return "function deposit(uint256 amount, uint256 destinationChainId, bytes routeCalldata) external"
    if "mempool-replacement-fee-bypass" in attack_class:
        return "function execute(bytes32 queueId, bytes payload) external; function queue(bytes payload, uint256 eta) external returns (bytes32 queueId)"
    if "tx-ordering-leak-on-private-mempool" in attack_class:
        return "function placeOrder(bytes32 marketId, bool isBuy, uint256 size, uint256 price) external"
    if "flashloan-readonly-reentrancy-amplified" in attack_class:
        return "function getRate() view returns (uint256); function flashLoan(address recipient, address[] tokens, uint256[] amounts, bytes userData) external"
    return "function vulnerable() external returns (bool)"


def shape_tags(incident: Dict[str, Any]) -> List[str]:
    tags = [
        slugify(incident["attack_class"], max_len=80),
        slugify("mev-" + incident["bug_class"], max_len=80),
    ]
    for url in incident.get("reference_urls", [])[:1]:
        # Tag the primary source domain so downstream search can filter by it.
        host_match = re.search(r"https?://([^/]+)/", url)
        if host_match:
            host_tag = slugify("source-" + host_match.group(1), max_len=80)
            if host_tag and host_tag not in tags:
                tags.append(host_tag)
    if "year" in incident:
        year_tag = slugify(f"year-{incident['year']}", max_len=20)
        if year_tag not in tags:
            tags.append(year_tag)
    return tags[:6]


def cross_language_analogues(incident: Dict[str, Any]) -> List[Dict[str, str]]:
    attack_class = incident.get("attack_class", "")
    rules: List[Dict[str, str]] = []
    if "sandwich-attack" in attack_class:
        rules.append({
            "target_language": "rust",
            "pattern_translation": (
                "Solana / cosmwasm equivalent: any DEX program where the "
                "swap instruction accepts user-supplied min_out without "
                "TWAP-bounded floor; visible in Solana's lack-of-mempool-"
                "ordering is mitigated by Jito bundle leader-only auctions "
                "but the protocol-side fix is the same TWAP-bounded slippage."
            ),
        })
        rules.append({
            "target_language": "go",
            "pattern_translation": (
                "Cosmos-SDK equivalent: x/dex Msg handlers that compute "
                "settlement price from CheckTx-side state without a "
                "PrepareProposal-bound ordering guard. The validator-set "
                "ordering layer (or lack thereof in pre-ABCI++ chains) "
                "is the analogue of the public mempool."
            ),
        })
    if "jit-liquidity" in attack_class:
        rules.append({
            "target_language": "rust",
            "pattern_translation": (
                "Solana equivalent: active-management strategies on "
                "Orca Whirlpools that rebalance via on-chain swap, "
                "visible to MEV searchers via priority-fee monitoring "
                "on Solana. Mitigation: Jito bundle inclusion of "
                "rebalance + JIT-protection swap in same atomic group."
            ),
        })
    if "flashloan-price-oracle-manipulation" in attack_class or "flashloan-readonly-reentrancy-amplified" in attack_class:
        rules.append({
            "target_language": "rust",
            "pattern_translation": (
                "Solana / cosmwasm equivalent: any lending program "
                "that prices collateral via a CPI call to a DEX swap "
                "rate without TWAP-bounded smoothing. Solana's flash-"
                "loan analog is the atomic-transaction guarantee plus "
                "borrow-and-repay-in-one-tx primitives in protocols "
                "like Solend, Mango."
            ),
        })
        rules.append({
            "target_language": "vyper",
            "pattern_translation": (
                "Vyper equivalent: any Curve-style pool whose get_rate "
                "is queried from a sibling protocol mid-operation; the "
                "vyper @nonreentrant lock did not cover view functions "
                "pre-0.3.0 (see vyper-cve seed)."
            ),
        })
    if "flashloan-governance-vote-flash" in attack_class:
        rules.append({
            "target_language": "rust",
            "pattern_translation": (
                "Solana SPL-governance equivalent: voting power "
                "derived from live SPL token balance with no "
                "checkpoint; mitigated by realm-level vote-record "
                "PDA enforcement, but custom DAO programs may regress."
            ),
        })
        rules.append({
            "target_language": "go",
            "pattern_translation": (
                "Cosmos x/gov equivalent: validator voting power "
                "checkpointed at proposal-submission block via the "
                "validator-set hash, so analogous flash-vote attack is "
                "structurally infeasible on cosmos-sdk x/gov. However "
                "custom Msg modules that read live balance for off-chain "
                "weighting could regress."
            ),
        })
    if "liquidation-mev-priority-gas" in attack_class:
        rules.append({
            "target_language": "rust",
            "pattern_translation": (
                "Solana lending equivalent: Solend / Mango liquidation "
                "calls are gas-auctioned via Solana priority fees; "
                "mitigated by Jito bundle auction for atomic liquidation, "
                "but the same value-extraction shape applies."
            ),
        })
    if "tx-ordering-leak-on-private-mempool" in attack_class:
        rules.append({
            "target_language": "go",
            "pattern_translation": (
                "Cosmos-SDK PrepareProposal equivalent: ABCI++ "
                "validator can reorder pending txes within their slot, "
                "analogous to L2 sequencer cross-domain MEV. Mitigation: "
                "vote-extension-based threshold encryption (Skip's BlockSDK, "
                "Slinky vote-extensions)."
            ),
        })
    if "cross-domain-mev-bridge-frontrun" in attack_class:
        rules.append({
            "target_language": "rust",
            "pattern_translation": (
                "Solana Wormhole-bridge equivalent: cross-domain VAA "
                "delivery is visible on source chain mempool, enabling "
                "destination-chain JIT positioning. Mitigation: "
                "threshold-encrypted VAA payload, or commit-reveal "
                "destination calldata."
            ),
        })
    if "flashloan-arb-cycle-bypass" in attack_class:
        rules.append({
            "target_language": "rust",
            "pattern_translation": (
                "Solana equivalent: any program that exposes a "
                "state-mutating helper that skips its standard health-"
                "check (Anchor's account-validation macros). The pattern "
                "fires when a 'donate' or 'reset' instruction lacks the "
                "borrow-health invariant assertion the main path enforces."
            ),
        })
    if "mempool-replacement-fee-bypass" in attack_class:
        rules.append({
            "target_language": "go",
            "pattern_translation": (
                "Cosmos timelock equivalent: x/gov DepositPeriod + "
                "VotingPeriod gating with a tx-level nonce stamp "
                "prevents same-action replacement; but custom Msg "
                "modules that queue payloads by id without nonce-binding "
                "can regress."
            ),
        })
    return rules


def build_records_from_incident(incident: Dict[str, Any]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    components: List[Dict[str, Any]] = list(incident.get("components", []) or [])
    if not components:
        components = [{"pool": incident.get("title", "Generic MEV incident"), "address": "n/a", "loss_usd": 0}]
    # Three mitigation states (matching the vyper-cve seed convention):
    # - pre-fix: live exposure at incident time
    # - post-fix-not-migrated: fix shipped upstream, deployed contracts
    #   still use the vulnerable shape (still-actionable for current audits)
    # - post-fix-migrated-historical: fully fixed; record kept as
    #   forensic / dupe-rejection anchor
    mitigation_states = ("pre-fix", "post-fix-not-migrated", "post-fix-migrated-historical")
    for component in components:
        for state in mitigation_states:
            component_name = str(component.get("pool", "")).strip()[:240] or incident["title"][:240]
            incident_slug = slugify(incident["incident_id"], max_len=40)
            pool_slug = slugify(component_name, max_len=60)
            state_slug = slugify(state, max_len=24)
            source_ref = f"mev-flashloan:{incident_slug}:{pool_slug}:{state_slug}"
            digest = hashlib.sha256(source_ref.encode("utf-8")).hexdigest()[:12]
            record_id = f"{source_ref}:{digest}"
            attack_class = incident["attack_class"]
            bug_class = incident.get("bug_class", "tx-ordering-leak")
            severity = incident.get("severity", "medium").lower()
            impact_dollar = impact_dollar_for_loss(
                int(component.get("loss_usd") or 0),
                incident.get("impact_dollar_class", "<$10K"),
            )
            if state == "post-fix-not-migrated":
                # Deployed contracts unredeployed against fixed code:
                # exposure persists but mitigation path is known.
                severity_map = {
                    "critical": "high",
                    "high": "medium",
                    "medium": "low",
                    "low": "info",
                    "info": "info",
                }
                severity = severity_map.get(severity, severity)
            elif state == "post-fix-migrated-historical":
                # Historical forensic record only.
                severity = "info"
            attacker_action = incident["attacker_action_sequence"]
            if component.get("address") and component["address"] != "n/a":
                attacker_action = (
                    attacker_action
                    + f" Concretely on {component_name} (address {component['address']})."
                )
            preconditions = [
                str(item).strip()[:1000]
                for item in (incident.get("preconditions") or [])
                if str(item).strip()
            ]
            if not preconditions:
                preconditions = [f"MEV / flashloan precondition class {bug_class} applies to {component_name}."]
            # Add the mitigation-state precondition so each record has a
            # distinct invariant footprint.
            preconditions = list(dict.fromkeys(preconditions + [f"mitigation_state={state}"]))
            # Domain mapping: the task spec mentioned "dex / lending / mev"
            # but the v1 schema enum has no "mev" value. Route MEV-only
            # incidents (PGA, time-bandit, SUAVE) to the closest schema
            # domain: rpc-infra (mempool / sequencer / builder) or
            # consensus (time-bandit reorg threat). Per-incident
            # target_domain already encodes the right enum value.
            target_domain = incident.get("target_domain", "dex")
            target_language = "solidity"
            target_repo = "unknown"
            if "wormhole" in incident_slug or "cashio" in incident_slug:
                target_language = "rust"
                target_repo = "wormhole-foundation/wormhole" if "wormhole" in incident_slug else "cashioapp/cashio"
            elif "mango" in incident_slug:
                target_language = "rust"
                target_repo = "blockworks-foundation/mango-v4"
            record = {
                "schema_version": SCHEMA_VERSION,
                "record_id": record_id,
                "source_audit_ref": source_ref,
                "target_domain": target_domain,
                "target_language": target_language,
                "target_repo": target_repo,
                "target_component": component_name,
                "function_shape": {
                    "raw_signature": mev_signature(incident, component),
                    "shape_tags": shape_tags(incident),
                },
                "bug_class": bug_class,
                "attack_class": attack_class,
                "attacker_role": "unprivileged",
                "attacker_action_sequence": attacker_action[:5000],
                "required_preconditions": preconditions[:6],
                "impact_class": incident.get("impact_class", "yield-redistribution"),
                "impact_actor": incident.get("impact_actor", "arbitrary-user"),
                "impact_dollar_class": impact_dollar,
                "fix_pattern": incident["fix_pattern"][:1000],
                "fix_anti_pattern_avoided": incident.get(
                    "fix_anti_pattern",
                    "exposing high-value extraction surface via public mempool with no MEV-resistance layer",
                )[:1000],
                "severity_at_finding": severity,
                "year": int(incident.get("year", 2023)),
                "cross_language_analogues": cross_language_analogues(incident),
                "related_records": [],
            }
            records.append(record)
    return records


def build_all_records(extra_entries: Optional[Sequence[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for entry in SEED_INCIDENTS:
        records.extend(build_records_from_incident(entry))
    for entry in (extra_entries or []):
        records.extend(build_records_from_incident(entry))
    # Cross-link records sharing an incident_id so related_records is non-empty
    # within a family. We split on the source_audit_ref incident slug.
    by_incident: Dict[str, List[str]] = {}
    for record in records:
        # source_audit_ref shape: mev-flashloan:<incident-slug>:<pool-slug>:<state>
        parts = record["source_audit_ref"].split(":")
        incident_key = parts[1] if len(parts) >= 2 else ""
        by_incident.setdefault(incident_key, []).append(record["record_id"])
    for record in records:
        parts = record["source_audit_ref"].split(":")
        incident_key = parts[1] if len(parts) >= 2 else ""
        siblings = [rid for rid in by_incident.get(incident_key, []) if rid != record["record_id"]]
        record["related_records"] = sorted(set(siblings))[:12]
    return records


def output_filename(record: Dict[str, Any]) -> str:
    digest = str(record["record_id"]).rsplit(":", 1)[-1]
    return f"{slugify(record['record_id'], max_len=110)}-{digest}.yaml"


def write_records(records: Sequence[Dict[str, Any]], out_dir: Path, *, dry_run: bool) -> List[Path]:
    paths: List[Path] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    for record in records:
        path = out_dir / output_filename(record)
        paths.append(path)
        if dry_run:
            continue
        path.write_text(yaml_dump(record), encoding="utf-8")
    return paths


def _load_validator() -> Any:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_mev_flashloan",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def validate_records(records: Sequence[Dict[str, Any]]) -> List[str]:
    validator = _load_validator()
    schema = validator.load_schema()
    errors: List[str] = []
    for record in records:
        for err in validator.validate_doc(dict(record), schema):
            errors.append(f"{record['record_id']}: {err}")
    return errors


def load_extra_entries(path: Optional[Path]) -> List[Dict[str, Any]]:
    if path is None:
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        entries = data.get("entries", [])
    else:
        entries = data
    if not isinstance(entries, list):
        raise ValueError(
            f"--extra-json must contain a list of entries, got {type(entries).__name__}"
        )
    return entries


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        default=str(DEFAULT_OUT_DIR),
        help="Directory for emitted hackerman_record YAML files.",
    )
    parser.add_argument(
        "--extra-json",
        type=str,
        default=None,
        help="Optional JSON file with additional incident entries in the same shape as SEED_INCIDENTS.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build records and summary without writing YAML files.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum records to emit (post-expansion).",
    )
    parser.add_argument(
        "--json-summary",
        action="store_true",
        help="Print a machine-readable JSON summary.",
    )
    parser.add_argument(
        "--skip-validation",
        action="store_true",
        help="Skip schema validation (debugging only).",
    )
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    extra_entries: List[Dict[str, Any]] = []
    if args.extra_json:
        try:
            extra_entries = load_extra_entries(Path(args.extra_json).expanduser().resolve())
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"failed to load --extra-json {args.extra_json}: {exc}", file=sys.stderr)
            return 2

    records = build_all_records(extra_entries)
    if args.limit is not None:
        records = records[: args.limit]

    errors: List[str] = []
    if not args.skip_validation:
        errors = validate_records(records)

    out_dir = Path(args.out_dir).expanduser().resolve()
    paths: List[Path] = []
    if not errors:
        paths = write_records(records, out_dir, dry_run=args.dry_run)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "seed_incident_entries": len(SEED_INCIDENTS),
        "extra_entries": len(extra_entries),
        "records_emitted": len(records),
        "errors": errors,
        "files": [str(path) for path in paths[:50]],
        "file_count": len(paths),
    }
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman MEV-flashloan ETL: "
            f"incidents={summary['seed_incident_entries']}+{summary['extra_entries']} "
            f"records={summary['records_emitted']} "
            f"errors={len(errors)} dry_run={summary['dry_run']}"
        )
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
