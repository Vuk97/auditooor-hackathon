#!/usr/bin/env python3
"""parity-report.py — Solidity ↔ Rust library parity north-star metric.

Scans the active Solidity pattern library (reference/patterns.dsl/*.yaml) and
the active Rust detector library (detectors/rust_wave1/*.py), infers bug_class
per pattern/detector, and emits:

 1. Count of patterns on each side per bug_class
 2. Cross-link coverage (does pattern X have a cross_refs pointer to Rust?)
 3. Language-agnostic bug classes with 0 coverage on one side (the "gap")
 4. Platform-only tags (bug classes valid for only one side — expected gaps)

Usage:
    python3 tools/parity-report.py                    # print human summary
    python3 tools/parity-report.py --json             # machine-readable JSON
    python3 tools/parity-report.py --gap-only         # only print the gap rows
    python3 tools/parity-report.py --out <path>       # write markdown report

Exit code:
    0  always (parity is always informational, never a gating failure)

The "parity %" is:
    (# bug-classes with ≥1 detector on BOTH sides) / (# bug-classes-applicable-to-both)

The harness is heuristic (keyword-match on pattern/detector names + file body).
Stubs in reference/patterns.dsl.*_mined/ staging dirs are NOT counted — only
active compiled-detector libraries count toward parity.
"""
import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOL_PATTERNS = ROOT / "reference" / "patterns.dsl"
RUST_DETECTORS = ROOT / "detectors" / "rust_wave1"

# Canonical bug-class registry. Each entry:
#   keywords:         substrings that classify a pattern/detector name
#   applies_to:       "both" | "solidity_only" | "rust_only"
#   description:      one-line invariant the class encodes
BUG_CLASSES = {
    "liquidation": {
        "keywords": ["liquidat", "close-factor", "health-factor", "seize", "bad-debt"],
        "applies_to": "both",
        "description": "liquidation math, seizure, close-factor, health-factor, bad-debt handling",
    },
    "oracle-cascade": {
        "keywords": ["oracle", "price-feed", "reflector", "twap", "chainlink", "pyth",
                     "latestround", "staleness", "freshness", "spot-price"],
        "applies_to": "both",
        "description": "oracle freshness, staleness, cascade failure, spot-price manipulation",
    },
    "oracle-cascade-external-call-without-stale-check": {
        "keywords": ["oracle-cascade-external-call", "oracle-external-call-stale",
                     "oracle-read-external-call", "price-oracle-external-call",
                     "oracle-freshness-external"],
        "applies_to": "solidity_only",
        "tier": "E",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "source": "auditooor-SKILL-219",
        "description": "Function reads from a price oracle and then performs an external call without checking oracle freshness/staleness",
    },
    "rewards-accounting": {
        "keywords": ["reward", "emission", "incentive", "claim", "accrual", "checkpoint"],
        "applies_to": "both",
        "description": "reward emission, accrual, distribution, claim-all semantics",
    },
    "flashloan": {
        "keywords": ["flash", "premium", "fee-rounding"],
        "applies_to": "both",
        "description": "flashloan fee rounding, callback-before-repay, premium underflow",
    },
    "signature-auth": {
        "keywords": ["signature", "ecrecover", "sig-replay", "deadline", "nonce",
                     "eip712", "domain-separator", "chainid", "permit"],
        "applies_to": "both",
        "description": "signature deadline, chainId binding, replay protection, EIP-712 domain",
    },
    "access-control": {
        "keywords": ["auth", "unauthorized", "privileg", "only-owner", "role", "admin",
                     "pause", "permission", "governance", "require_auth"],
        "applies_to": "both",
        "description": "auth/role checks, admin-only paths, pause/timelock gating",
    },
    "input-validation": {
        "keywords": ["missing-check", "zero-address", "zero-amount", "input-valid",
                     "bound", "range", "validate"],
        "applies_to": "both",
        "description": "zero-address, zero-amount, bounds, range checks",
    },
    "arithmetic": {
        "keywords": ["overflow", "underflow", "unchecked", "wrapping", "truncat",
                     "precision", "rounding", "div-before-mul", "div-by-zero"],
        "applies_to": "both",
        "description": "overflow/underflow/precision/rounding/truncation",
    },
    "reentrancy": {
        "keywords": ["reentran", "cei", "callback-mid-state", "callback-before"],
        "applies_to": "both",
        "description": "reentrancy / check-effect-interaction violation",
    },
    "slippage": {
        "keywords": ["slippage", "min-out", "deadline-swap", "amount-out-min"],
        "applies_to": "both",
        "description": "missing/weak slippage guard on swaps/withdrawals",
    },
    "merkle-replay": {
        "keywords": ["merkle", "proof", "claim-flag", "leaf"],
        "applies_to": "both",
        "description": "merkle-claim replay, missing claimed-flag",
    },
    "dex-integration": {
        "keywords": ["swap", "uniswap", "curve", "balancer", "aggregator", "amm", "pool"],
        "applies_to": "both",
        "description": "DEX integration: swap path, router, pool interactions",
    },
    "proxy-upgrade": {
        "keywords": ["proxy", "upgrade", "storage-slot", "initializer", "initializ",
                     "delegatecall"],
        "applies_to": "both",
        "description": "proxy/upgrade/initializer/storage-slot collision",
    },
    "governance": {
        "keywords": ["timelock", "vote", "governor", "dao", "propos"],
        "applies_to": "both",
        "description": "governance: timelock bypass, vote snapshot staleness, propose gap",
    },
    "gas-griefing": {
        "keywords": ["gas-exhaust", "unbounded-loop", "unbounded-array", "dos",
                     "gas-limit", "grief"],
        "applies_to": "both",
        "description": "DoS via unbounded iteration / gas exhaustion",
    },
    "token-standard": {
        "keywords": ["erc20", "erc4626", "erc721", "erc1155", "sep41", "sep-41",
                     "share", "vault-invariant"],
        "applies_to": "both",
        "description": "ERC-20/721/1155/4626 or SEP-41 standard-compliance bugs",
    },
    "fee-accounting": {
        "keywords": ["fee-charged", "fee-wrong", "fee-party", "fee-siphon"],
        "applies_to": "both",
        "description": "fee charged to wrong party / siphoned into wrong bucket",
    },
    "error-handling": {
        "keywords": ["unchecked-return", "unchecked-call", "unchecked-transfer",
                     "unchecked-approve", "unchecked-erc20", "unchecked-ret",
                     "error-swallowed", "approve-return", "silent-fail",
                     "drop-result", "unchecked-result"],
        "applies_to": "both",
        "description": "unchecked return / dropped Result — silent failure surface",
    },
    "bitmap-bounds": {
        "keywords": ["bitmap", "reserve-id", "off-by-one", "overflow-index"],
        "applies_to": "both",
        "description": "bitmap/reserve-index off-by-one or OOB shift",
    },
    "mint-unrestricted": {
        "keywords": ["unrestricted-mint", "mint-no-auth", "infinite-mint",
                     "mint-unrestricted", "permissionless-mint", "arbitrary-mint"],
        "applies_to": "both",
        "description": "mint path without auth or with caller-controlled amount",
    },
    "paired-fn-asymmetry": {
        "keywords": ["paired-function", "paired-fn", "add-remove"],
        "applies_to": "both",
        "description": "add/remove pair write to different storage slots",
    },
    # Platform-only classes (expected gaps — do NOT count against parity).
    # Item-#6 burn-down (PR codex/burndown-item-6-parity-gap-reduce):
    # `deliberate: true` + `rationale` mark these as INTENTIONAL platform-only
    # rows. `tools/detector-lint.py` Check 5 honours this discriminator and
    # excludes deliberate rows from the gap count. Adding a new platform-only
    # class? Set `deliberate: true` and a one-line rationale, or leave it
    # unset to surface as a real gap.
    "ttl-archival": {
        # Tightened (item-#6): the broad `expire` keyword incidentally
        # matched 20 Solidity DSL files (ec-expired-deadline-accepted,
        # r94-loop-oracle-version-expired-stale-return, signature deadline
        # patterns, etc.) that have nothing to do with Soroban TTL/archival
        # semantics. Removed `expire` and `archiv` (too broad — `archive`
        # also appears in non-Soroban contexts) and tightened to Soroban-
        # specific terms. The Rust detectors keep matching via
        # `persistent_storage` / `instance_storage` / `ttl` / `bump`.
        "keywords": ["ttl-bump", "ttl-archival", "ttl-extend",
                     "soroban-archival", "persistent-storage",
                     "instance-storage", "temporary-storage",
                     "extend-ttl", "bump-ttl"],
        "applies_to": "rust_only",
        "deliberate": True,
        "rationale": "Soroban TTL/entry archival is a Stellar-specific ledger "
                     "primitive (no EVM analog). Solidity has no equivalent "
                     "of persistent vs instance storage with archival deadlines.",
        "description": "Soroban TTL / entry archival semantics — platform-specific",
    },
    "anchor-pda": {
        "keywords": ["anchor-pda", "pda-seed", "anchor_pda"],
        "applies_to": "rust_only",
        "deliberate": True,
        "rationale": "Anchor PDA seed binding is Solana-specific (Anchor "
                     "framework on Solana runtime). EVM has no PDA concept.",
        "description": "Anchor PDA seed binding — Solana-specific",
    },
    "anchor-account": {
        "keywords": ["anchor-account", "anchor-signer", "anchor_account", "anchor_signer"],
        "applies_to": "rust_only",
        "deliberate": True,
        "rationale": "Anchor account-struct constraints are Solana-specific "
                     "(Anchor framework). No EVM equivalent of typed account "
                     "structs validated at instruction entry.",
        "description": "Anchor account-struct constraints — Solana-specific",
    },
    "cpi-ordering": {
        "keywords": ["cpi", "invoke_signed", "cross-program"],
        "applies_to": "rust_only",
        "deliberate": True,
        "rationale": "Solana Cross-Program Invocation ordering / signer "
                     "privilege escalation is Solana-specific (no EVM analog "
                     "for CPI seed-signer model).",
        "description": "Solana CPI ordering / re-entrancy — Solana-specific",
    },
    "rust-panic-unwrap": {
        "keywords": ["unwrap", "panic", "expect-call"],
        "applies_to": "rust_only",
        "deliberate": True,
        "rationale": "`unwrap()`/`panic!` are Rust-language constructs. "
                     "Solidity has no direct equivalent — `revert` is "
                     "covered by the `error-handling` class.",
        "description": "Rust panic-on-unwrap — language-specific",
    },
    "solidity-delegatecall": {
        "keywords": ["delegatecall-user", "delegatecall-eoa", "delegatecall-no-code",
                     "delegatecall-to-user-address"],
        "applies_to": "both",  # Phase 29: Rust sibling `delegatecall_to_user_address.py` (Soroban SEP-41 analog) ships real detector
        "description": "EVM delegatecall semantics — Soroban analog: token-client from caller-controlled Address",
    },
    "solidity-selfdestruct": {
        "keywords": ["selfdestruct"],
        "applies_to": "solidity_only",
        "description": "EVM selfdestruct — Solidity-specific",
    },
    "solidity-tx-origin": {
        "keywords": ["tx-origin", "tx_origin"],
        "applies_to": "both",  # Phase 29: Rust sibling `tx_origin_used_for_auth.py` ships; Soroban `env.invoker()` vs require_auth
        "description": "EVM tx.origin auth anti-pattern — Soroban analog: env.invoker() used for auth instead of require_auth",
    },
    "solidity-msgvalue": {
        "keywords": ["msg-value", "msgvalue", "payable"],
        "applies_to": "solidity_only",
        "description": "EVM msg.value / payable handling — Solidity-specific",
    },
    "l2-sequencer": {
        "keywords": ["l2-sequencer", "sequencer-uptime", "arb-sequencer"],
        "applies_to": "solidity_only",
        "description": "L2 sequencer uptime oracle — EVM-L2 specific",
    },
    # New canonical classes added in cycle 3 (raise the ceiling)
    "bridge-token-mismatch": {
        "keywords": ["token-mismatch", "bridge-token", "bridge-mint-confusion",
                     "spl-token-deposit", "wrong-mint", "mint-differentiation"],
        "applies_to": "both",
        "description": "bridge accepts deposit of token A but credits as token B (mint/symbol confusion)",
    },
    "cpi-remaining-accounts": {
        "keywords": ["remaining-accounts", "remaining_accounts", "cpi-remaining",
                     "cpi-account-list"],
        "applies_to": "both",  # Was rust_only; Solidity-side Solana bridges also test this
        "description": "CPI remaining_accounts not validated (Solana / cross-chain)",
    },
    "cpi-sysvar-validation": {
        "keywords": ["sysvar", "instructions-sysvar", "cpi-sysvar",
                     "caller-supplied-sysvar"],
        "applies_to": "both",  # Was rust_only; Solidity bridges and xchain-routers also test this
        "description": "sysvar account not validated in CPI / caller-supplied sysvar in xchain route",
    },
    "observer-untrusted-role": {
        "keywords": ["observer-role", "relayer-untrusted", "observer-untrusted",
                     "bridge-observer"],
        "applies_to": "both",
        "description": "bridge observer/relayer role treated as trusted without attestation verification",
    },
    "stale-snapshot-accounting": {
        "keywords": ["stale-snapshot", "stale-share", "stale-total", "stale-index",
                     "snapshot-reuse"],
        "applies_to": "both",
        "description": "accounting uses a snapshot value that should have been decremented after use",
    },
    "paired-refund-accounting": {
        "keywords": ["refund-calculation", "refund-accounting", "claimed-supply",
                     "refund-stale", "refund-no-supply", "no-supply-decrement",
                     "refund-no-supply-decrement"],
        "applies_to": "both",
        "description": "refund/withdraw path fails to update matching supply counter (paired-asymmetry variant)",
    },
    "queue-spam-dos": {
        "keywords": ["queue-bloat", "queue-dos", "queue-flood", "permissionless-queue",
                     "intake-no-fee", "spam-request", "queue-intake", "intake-permissionless",
                     "queue-intake-permissionless", "no-fee"],
        "applies_to": "both",
        "description": "permissionless intake into a processing queue with no fee/rate-limit — DoS via bloat",
    },
    "division-by-zero": {
        "keywords": ["division-by-zero", "div-by-zero", "zero-divisor",
                     "gasprice-zero", "divisor-zero"],
        "applies_to": "both",
        "description": "caller-supplied parameter becomes a divisor with no >0 check — revert / chain-halt",
    },
    # Cycle-6 ceiling raise (5 new canonical classes)
    "init-race-admin-takeover": {
        "keywords": ["frontrun-initialize", "init-takeover", "first-caller-initialize",
                     "public-initialize-takeover", "initializer-admin-takeover",
                     "init-race", "init-race-admin", "init-race-admin-takeover"],
        "applies_to": "both",
        "description": "public initialize() lets first caller become admin (no deployer-bind)",
    },
    "self-transfer-double-account": {
        "keywords": ["self-transfer", "double-count-on-transfer", "from-equal-to",
                     "self-transfer-share", "share-double-count"],
        "applies_to": "both",
        "description": "transfer path doesn't short-circuit `from == to`; debit then credit doubles",
    },
    "stableswap-precision-overflow": {
        "keywords": ["stableswap-precision", "intermediate-precision", "uint256-narrow",
                     "precision-overflow", "high-decimals-overflow"],
        "applies_to": "both",
        "description": "stableswap intermediate math uses too-narrow accumulator for high-decimal tokens",
    },
    "airdrop-double-claim": {
        "keywords": ["double-claim", "claim-flag-missing", "re-claim", "claim-replay",
                     "airdrop-double", "already-claimed"],
        "applies_to": "both",
        "description": "airdrop/distribution claim path re-entered by same user — flag absent or overwritten",
    },
    "rent-exempt-lifecycle": {
        "keywords": ["rent-exempt", "rent-exemption", "rent-collected",
                     "minimum-balance-rent"],
        "applies_to": "rust_only",
        "description": "Solana account not rent-exempt across close/init lifecycle — reclaim surface",
    },
    "zk-proof-missing-constraint": {
        "keywords": ["zk-proof", "missing-constraint", "circuit-constraint",
                     "load-store-constraint", "prover-free-write",
                     "zk-missing-constraint", "zk-circuit-missing"],
        "applies_to": "both",
        "description": "ZK circuit lacks a constraint linking read/written values — malicious prover writes free",
    },
    # Cycle-9 ceiling raise (5 new canonical classes)
    "asymmetric-liquidity-flat-oracle": {
        "keywords": ["asymmetric-liquidity", "flat-oracle", "flat-price",
                     "one-sided-liquidity", "asymmetric-pool"],
        "applies_to": "both",
        "description": "Asymmetric one-sided liquidity lets attacker trade at flat oracle price irrespective of size",
    },
    "swap-split-matching-bypass": {
        "keywords": ["swap-split", "small-swap-splitting", "order-matching",
                     "passive-order", "split-swap-better", "order-flow-split"],
        "applies_to": "solidity_only",  # Reclassified: CLOB/orderbook algo
        "description": "Small-swap splitting yields better price than intended bulk matching (CLOB/orderbook algo flaw — EVM-common)",
    },
    "fiat-shamir-missing-observation": {
        "keywords": ["fiat-shamir", "observation-missing", "transcript-missing",
                     "challenge-not-bound", "non-interactive-transform"],
        "applies_to": "both",
        "description": "Fiat-Shamir / transcript misses a protocol value — prover forges via omitted observe",
    },
    "beacon-lookahead-ignored": {
        "keywords": ["beacon-lookahead", "proposer-lookahead", "beacon-proposer",
                     "effective-balance-stale", "lookahead-ignored"],
        "applies_to": "rust_only",
        "description": "Ethereum consensus: proposer_lookahead ignored — stale effective-balance between slot and lookahead",
    },
    "order-rounding-theft": {
        "keywords": ["rounding-direction", "dex-rounding", "rounding-direction-theft",
                     "user-favorable-rounding", "floor-div-user-favor"],
        "applies_to": "both",
        "description": "DEX/AMM rounds toward user instead of pool — per-swap wei dust",
    },
    # Cycle-11 ceiling raise (6 new classes drawn from 109 Zellic stubs)
    "pda-seed-collision": {
        "keywords": ["seed-collision", "pda-seed-collision", "potential-seed-collision",
                     "hash-to-same-pda"],
        "applies_to": "rust_only",
        "description": "Solana PDA seeds allow two different inputs to derive the same PDA",
    },
    "pda-canonical-bump-missing": {
        "keywords": ["canonical-bump", "find-program-address", "create-program-address-unvalidated",
                     "bump-not-canonical"],
        "applies_to": "rust_only",
        "description": "Solana program uses create_program_address without binding to the canonical bump",
    },
    "cointype-wrap-unvalidated": {
        "keywords": ["cointype-wrap", "wrapped-cointype", "vaa-wrap-unvalidated",
                     "wrapped-asset-unchecked"],
        "applies_to": "rust_only",
        "description": "Wrapped-asset mint derivation from bridge VAA doesn't validate origin cointype",
    },
    "wormhole-guardian-quorum": {
        "keywords": ["guardian-quorum", "wormhole-guardian", "signature-threshold-bypass",
                     "guardian-set-stale"],
        "applies_to": "both",
        "description": "cross-chain bridge accepts VAA below guardian-quorum signature threshold",
    },
    "oracle-feed-id-mismatch": {
        "keywords": ["price-feed-id", "feed-id-mismatch", "oracle-id-mismatch",
                     "pyth-feed-id", "chainlink-feed-id"],
        "applies_to": "both",
        "description": "oracle consumer reads price from a feed-id that doesn't match the configured asset",
    },
    "account-size-miscalc": {
        "keywords": ["account-size", "size-calculation", "realloc-miscalc",
                     "account-layout-mismatch"],
        "applies_to": "rust_only",
        "description": "Solana account allocation size doesn't match the serialized struct",
    },
    # Cycle-13 ceiling raise (6 new classes from OtterSec Walrus/Mayan/Claynosaurz)
    "zero-share-first-deposit": {
        "keywords": ["zero-share", "zero-share-amount", "share-zero-withdraw",
                     "zero-share-first-deposit", "zero-share-mint"],
        "applies_to": "both",
        "description": "withdraw / mint / stake path accepts share_amount=0 — share-to-asset ratio manipulation",
    },
    "nft-collection-verified-bypass": {
        "keywords": ["verified-field", "nft-collection-verified", "collection-verified-missing",
                     "verified-unchecked", "metadata-verified"],
        "applies_to": "both",
        "description": "NFT integrity check reads collection.key but ignores collection.verified — spoofed collection passes",
    },
    "payload-hash-cross-contract-desync": {
        "keywords": ["payload-hash-mismatch", "hash-cross-contract", "hash-desync",
                     "payload-hash-desync", "hash-format-mismatch"],
        "applies_to": "both",
        "description": "Hash computed differently in two cooperating contracts — cross-contract desync on verification",
    },
    "vector-init-length-as-element": {
        "keywords": ["vector-init", "init-length-as-element", "vector-init-length",
                     "vec-init-length"],
        "applies_to": "both",  # Phase 29: Solidity sibling `vector-init-length-as-element.yaml` ships (new T[](1); arr[0]=len)
        "description": "Dynamic array initialised with capacity-1 then element[0]=len — author meant new T[](len) (rust vec![len] / solidity new uint256[](1))",
    },
    "oracle-confidence-negative-accept": {
        "keywords": ["negative-fluctuation", "confidence-interval-negative",
                     "oracle-confidence-accept", "pyth-confidence-negative",
                     "oracle-confidence-negative", "confidence-negative"],
        "applies_to": "both",
        "description": "Oracle consumer accepts negative deviations inside confidence interval when it should reject",
    },
    "stake-epoch-mismatch-reward-drift": {
        "keywords": ["activation-epoch", "stake-epoch-missing", "staked-activation-missing",
                     "reward-epoch-drift"],
        "applies_to": "both",
        "description": "Staking/reward math uses activation_epoch but join/merge doesn't enforce matching activation_epoch",
    },
    # Cycle-15 ceiling raise (5 new cross-chain/Move/Sui/CosmWasm classes)
    "move-capability-leak": {
        "keywords": ["capability-leak", "move-capability", "cap-leak",
                     "treasury-cap-leak", "admin-cap-exposed"],
        "applies_to": "rust_only",
        "description": "Move/Sui capability object passed into public function without scoping — caller obtains privileged power",
    },
    "cosmwasm-reply-handler-missing": {
        "keywords": ["reply-handler-missing", "submsg-reply-on",
                     "cosmwasm-reply", "reply-on-missing", "submsg-no-reply"],
        "applies_to": "rust_only",
        "description": "CosmWasm submessage has reply_on = ReplyOn::Always/Success but no reply handler processes result",
    },
    "layerzero-channel-mismatch": {
        "keywords": ["channel-id-mismatch", "oapp-channel", "lz-channel",
                     "layerzero-channel"],
        "applies_to": "both",
        "description": "LayerZero OApp receive path doesn't bind src-channel/message-channel id to expected peer",
    },
    "hyperlane-ism-bypass": {
        "keywords": ["ism-bypass", "hyperlane-ism", "interchain-security-module",
                     "ism-not-enforced"],
        "applies_to": "both",
        "description": "Hyperlane message handler doesn't enforce the configured ISM — inbound messages accepted without security verification",
    },
    "pyth-exponent-mismatch": {
        "keywords": ["price-exponent", "pyth-exponent", "exponent-mismatch",
                     "expo-not-scaled"],
        "applies_to": "both",
        "description": "Pyth price.expo ignored / mis-scaled when converting to fixed-decimal — off-by-10^n price",
    },
    # Cycle-18 ceiling raise (5 classes from Cairo/Starknet corpus)
    "perps-liquidation-state-flip": {
        "keywords": ["liquidation-flip", "long-to-short", "position-flip",
                     "liquidatable-forced-flip", "perps-liquidation-state-flip",
                     "liquidation-state-flip"],
        "applies_to": "both",
        "description": "Liquidation path doesn't enforce position-direction invariant — liquidatable long forced into short",
    },
    "state-mutation-before-check": {
        "keywords": ["apply-diff-before-check", "execute-before-validate",
                     "state-mutate-before-check", "state-mutation-before-check",
                     "wrong-order-operations"],
        "applies_to": "both",
        "description": "State is mutated with a diff before the validity check — check sees post-diff state and passes trivially",
    },
    "field-modulus-timestamp-overflow": {
        "keywords": ["timestamp-overflow", "modulus-overflow", "babybear-overflow",
                     "field-modulus", "prime-wraparound"],
        "applies_to": "rust_only",
        "description": "ZK-VM / prime-field timestamp or counter wraps past field modulus — invalid program paths verifiable",
    },
    "namespace-hash-inconsistency": {
        "keywords": ["namespace-hash", "caller-supplied-hash", "hash-vs-name-mismatch",
                     "namespace-spoof"],
        "applies_to": "both",
        "description": "Namespace/registry model accepts caller-supplied (name, hash) without cross-validating hash(name) == hash",
    },
    "hierarchy-permission-bypass": {
        "keywords": ["permission-hierarchy", "world-owner-bypass", "namespace-owner-bypass",
                     "hierarchical-permission", "hierarchy-permission-bypass",
                     "hierarchy-permission"],
        "applies_to": "both",
        "description": "Hierarchical access-control: lower-level role action doesn't consult upper-level owner",
    },
    # Cycle-20 ceiling raise (5 new canonical classes from Move/Sui/Aptos corpus)
    "reversed-comparison-operator": {
        "keywords": ["reversed-comparison", "wrong-comparison", "comparison-reversed",
                     "expired-when-active", "reversed-operator"],
        "applies_to": "both",
        "description": "Comparison operator (< / > / <= / >=) reversed in boundary check — state flips are inverted",
    },
    "bound-check-delta-only": {
        "keywords": ["max-expiration-bypass", "delta-only-bound", "cap-bypass-via-extend",
                     "sum-exceeds-bound", "extend-bypass-bound", "bound-check-delta-only",
                     "bound-check-delta"],
        "applies_to": "both",
        "description": "Extend/increment fn validates the DELTA against a cap but not the resulting sum — repeated calls bypass the cap",
    },
    "double-subtraction-accounting": {
        "keywords": ["double-subtraction", "subtract-twice", "deduct-twice",
                     "reserve-subtracted-twice"],
        "applies_to": "both",
        "description": "Accounting subtracts a value twice from a limit/cap comparison — understated used cap",
    },
    "cross-segment-limiter-netting": {
        "keywords": ["cross-segment-limiter", "segment-netting", "limiter-segment-drift",
                     "daily-cap-segment-grief"],
        "applies_to": "both",
        "description": "Per-segment daily cap doesn't net across segments — attacker zig-zags to bypass global cap",
    },
    "global-vs-per-group-trigger": {
        "keywords": ["global-vs-per-group", "global-debt-trigger", "adl-global-trigger",
                     "per-group-trigger-missing"],
        "applies_to": "both",
        "description": "Risk trigger checks a global aggregate (debt/utilization) when it should check a per-group local value",
    },
    # Cycle-22 ceiling raise (4 new classes from Go/Cosmos corpus)
    "stake-exit-slashing-lag": {
        "keywords": ["stake-exit-lag", "slashing-lag", "exit-before-slash",
                     "validator-set-non-atomic", "stake-exit-slashing-lag"],
        "applies_to": "both",
        "description": "Validator/operator can unstake before slashing enforcement kicks in — stake-exit slashing lag lets them act maliciously with no skin in the game",
    },
    "ibc-version-negotiation-bypass": {
        "keywords": ["ibc-version-bypass", "version-negotiation-bypass",
                     "onchanopeninit", "ibc-version-negotiation"],
        "applies_to": "rust_only",
        "description": "IBC channel version negotiation returns caller version instead of negotiated final version — middleware stack version drift",
    },
    "context-queue-not-drained": {
        "keywords": ["queue-not-drained", "queue-append-no-remove",
                     "context-queue-replay", "request-queue-stale",
                     "context-queue-not-drained"],
        "applies_to": "both",
        "description": "A queue / slice accumulates requests but is never drained after processing — replay / stale-state surface",
    },
    "missing-init-fallthrough": {
        "keywords": ["missing-init", "keeper-not-initialized", "resolver-not-init",
                     "init-fallthrough-default", "missing-init-fallthrough"],
        "applies_to": "both",
        "description": "Component expected to be init'd with a custom impl falls through to the framework's default — behavior-drift",
    },
    # Cycle-23 ceiling raise (3 new classes from remaining Go stubs)
    "storage-root-assignment-missing": {
        "keywords": ["storage-root-missing", "root-assignment-missing", "unassigned-root",
                     "tree-finalization-missing", "storage-root-assignment",
                     "storage-root-unassigned"],
        "applies_to": "both",
        "description": "Merkle/tree finalize fn returns a root variable that was never assigned — downstream (L1↔L2) sync breaks",
    },
    "bitcoin-sighash-confusion": {
        "keywords": ["sighash-confusion", "witness-hash-wrong", "sighash-wrong",
                     "bitcoin-sighash", "invalid-sighash"],
        "applies_to": "rust_only",
        "description": "Bitcoin transaction sighash computed with wrong witness commitment — signed tx rejected by BTC network",
    },
    "indexer-finalize-dos": {
        "keywords": ["indexer-finalize-dos", "listenfinalizeblock", "finalize-block-error",
                     "indexer-error-halt", "block-indexer-halt"],
        "applies_to": "both",
        "description": "Indexer's ListenFinalizeBlock / post-finalize hook can error on a crafted tx and prevent block indexing",
    },
    # Cycle-26 ceiling raise (4 HTLC / bridge classes from Hexens Train-Protocol)
    "htlc-timelock-delta-unenforced": {
        "keywords": ["htlc-timelock-delta", "timelock-delta-unenforced", "timelock-delta-missing",
                     "htlc-commit-no-delta", "htlc-add-lock-no-delta"],
        "applies_to": "both",
        "description": "HTLC commit/add_lock accepts timelock without enforcing a minimum delta — LP griefs solver",
    },
    "htlc-reward-overwrite": {
        "keywords": ["htlc-lock-reward-overwrite", "reward-overwrite", "lock-reward-overwrite",
                     "overwrites-previous-reward"],
        "applies_to": "both",
        "description": "HTLC lock_reward overwrites the existing locked reward — previous LP reward lost",
    },
    "htlc-refund-off-by-one": {
        "keywords": ["htlc-refund-off-by-one", "refund-off-by-one", "refund-timestamp-off",
                     "htlc-refund-timestamp"],
        "applies_to": "both",
        "description": "HTLC refund path uses strict `<` / `>` at boundary where `<=` / `>=` is correct — dust timing drift",
    },
    "htlc-zero-hashlock-accepted": {
        "keywords": ["htlc-zero-hashlock", "zero-hashlock-accepted", "hashlock-zero-missing-check",
                     "htlc-add-lock-no-hashlock-check"],
        "applies_to": "both",
        "description": "HTLC add_lock accepts hashlock == 0 — zero-hashlock collision unlocks by anyone",
    },
    # Cycle-29 ceiling raise (4 classes from TrailOfBits Rust corpus)
    "admin-rug-pull-token-removal": {
        "keywords": ["admin-rug-pull", "owner-can-rug", "token-removal-admin",
                     "basket-admin-removal", "folio-owner-rug"],
        "applies_to": "both",
        "description": "Admin/owner role has unilateral power to remove tokens/assets from a shared basket",
    },
    "dead-branch-wrong-constant": {
        "keywords": ["dead-branch", "unreachable-branch", "wrong-constant-comparison",
                     "never-executes", "divider-never-matches"],
        "applies_to": "both",
        "description": "Comparison against a constant the variable can never equal — guarded block is dead code",
    },
    "zk-expired-cert-accepted": {
        "keywords": ["zk-expired-cert", "risc0-expired", "sp1-expired",
                     "attestation-cert-expiry"],
        "applies_to": "rust_only",
        "description": "zkVM attestation accepts proofs generated against expired certificates / CRLs",
    },
    "merkle-proof-forgeable": {
        "keywords": ["merkle-proof-forgeable", "merk-forge", "fraudulent-merkle",
                     "merkle-inclusion-forge"],
        "applies_to": "both",
        "description": "Merkle proof algorithm accepts forged inclusion proofs — light-client / bridge fund theft",
    },
    # Cycle-32 ceiling raise (4 new classes from Vyper corpus)
    "per-user-baseline-not-initialized": {
        "keywords": ["baseline-not-initialized", "amount-claimed-not-init",
                     "per-user-baseline", "stale-global-accumulator-vs-baseline"],
        "applies_to": "both",
        "description": "Per-user baseline (amount_claimed) not initialized on deposit while a global accumulator is non-zero — yield misallocation",
    },
    "imbalanced-pool-proportional-deposit": {
        "keywords": ["imbalanced-pool", "proportional-deposit-imbalanced",
                     "curve-imbalanced", "pool-imbalanced-suboptimal"],
        "applies_to": "both",
        "description": "Vault performs proportional deposit into an imbalanced AMM/Curve pool — sub-optimal LP-token return",
    },
    "rebase-race-unstake": {
        "keywords": ["rebase-race", "unstake-before-rebase", "balance-rebase-race",
                     "stale-balance-pre-rebase"],
        "applies_to": "both",
        "description": "Staker can unstake before positive rebase is applied (balanceOf updated lazily) — escape dilution / exit at stale balance",
    },
    "curve-remove-liquidity-zero-min": {
        "keywords": ["curve-remove-liquidity", "zero-min-amounts", "remove-liquidity-zero-min",
                     "tokensIn-dropped-zero-min"],
        "applies_to": "both",
        "description": "Controller reading Curve remove_liquidity return drops tokens whose min_amount was set to 0 — accounting loses those tokens",
    },
    # Cycle-35 ceiling raise (4 classes from FunC/TON corpus)
    "ton-message-forge-via-notification": {
        "keywords": ["ton-message-forge", "vault-notification-forge", "notification-arbitrary-msg",
                     "arbitrary-message-bypass"],
        "applies_to": "rust_only",
        "description": "TON vault/pool notification lets caller inject arbitrary payload → downstream accepts as coming-from-contract",
    },
    "sender-address-not-validated-burn": {
        "keywords": ["sender-address-not-validated", "burn-notification-sender",
                     "burn-sender-spoof", "sender-not-jetton-master"],
        "applies_to": "both",
        "description": "Burn/mint notification handler updates supply without asserting sender == master — spoofed notification manipulates supply",
    },
    "execution-fee-underestimated": {
        "keywords": ["execution-fee-underestimated", "fee-not-covering-reserve",
                     "insufficient-execution-fee", "tx-fee-lock"],
        "applies_to": "rust_only",
        "description": "Fee validation checks msg_value against partial cost (fee) without including reserve/execution amount — tx aborts, state locks",
    },
    "admin-update-malformed-cell-brick": {
        "keywords": ["malformed-update-cell", "admin-update-brick", "update-code-cell-wrong",
                     "malformed-admin-update"],
        "applies_to": "rust_only",
        "description": "Admin-update helper writes a cell with wrong structure — if invoked, contract becomes permanently unusable",
    },
    # Cycle-36 ceiling raise (4 classes from Circom/ZK corpus)
    "curve-membership-missing-in-circuit": {
        "keywords": ["curve-membership-missing", "curve-validation-missing",
                     "babyjub-curve-check", "point-not-on-curve-circuit"],
        "applies_to": "rust_only",
        "description": "ZK circuit operates on curve points (BabyJubjub, etc.) without asserting point is on curve",
    },
    "constraint-inequality-when-equality": {
        "keywords": ["constraint-inequality-when-equality", "balancing-inequality",
                     "constraint-lt-when-eq", "inequality-instead-equality",
                     "constraint-le-not-eq"],
        "applies_to": "rust_only",
        "description": "ZK circuit uses `<=` constraint where `==` is required — unaccounted value slips through",
    },
    "ecrecover-malleability-no-check": {
        "keywords": ["ecrecover-malleability", "signature-malleability-ecrecover",
                     "s-value-not-bounded", "missing-s-malleability-check"],
        "applies_to": "both",
        "description": "recoverSigner uses ecrecover without s-value bound / malleability check — signature can be forged via (s, -s)",
    },
    "encrypted-output-not-in-hash": {
        "keywords": ["encrypted-output-not-hashed", "callDataHash-missing-outputs",
                     "output-swap-untraceable", "privacy-output-swap"],
        "applies_to": "rust_only",
        "description": "ZK-privacy proof's public inputs don't include encrypted outputs — attacker swaps outputs without invalidating proof",
    },
    # Cycle-37 ceiling raise (4 classes from Sway/Fuel corpus)
    "cross-timestamp-source-drift": {
        "keywords": ["cross-timestamp-drift", "pyth-vs-local-timestamp",
                     "oracle-vs-chain-time", "timestamp-source-mismatch",
                     "cross-timestamp-source-drift", "cross-timestamp-source"],
        "applies_to": "both",
        "description": "Oracle publish_time and local chain timestamp can drift — signed subtraction or staleness verdict is wrong",
    },
    "sorted-list-wrong-end-traversal": {
        "keywords": ["wrong-end-sorted", "sorted-list-reverse", "traverse-high-instead-low",
                     "trove-sort-order-wrong", "sorted-list-wrong-end-traversal",
                     "sorted-list-wrong-end"],
        "applies_to": "both",
        "description": "Iteration walks the wrong end of a sorted structure — worst-case elements aren't inspected",
    },
    "cancel-path-state-drift": {
        "keywords": ["cancel-state-drift", "cancel-partial-drift", "return-early-no-state-update",
                     "cancellation-drift", "cancel-path-state-drift", "cancel-path-state"],
        "applies_to": "both",
        "description": "Cancellation path returns early without updating dependent-state (stakes, sorted position, pending rewards)",
    },
    "update-price-fee-unvalidated": {
        "keywords": ["update-price-fee-unvalidated", "pyth-update-fee", "oracle-fee-drain",
                     "update-fee-from-market-balance"],
        "applies_to": "both",
        "description": "Oracle-update fn doesn't validate msg_amount matches update_fee — market's balance drained to pay oracle",
    },
    # Cycle-41 ceiling raise (5 oracle-class from Solodit tag=Oracle)
    "lp-price-via-manipulable-getrate": {
        "keywords": ["lp-price-getrate", "stable-bpt-manipulable", "lp-price-manipulable",
                     "getrate-oracle", "lp-price-via-manipulable-getrate",
                     "lp-price-via-manipulable"],
        "applies_to": "both",
        "description": "LP oracle reads pool.getRate() / virtual price — manipulable via flash-borrow of pool state",
    },
    "oracle-readonly-reentrancy": {
        "keywords": ["readonly-reentrancy", "balancer-reentrancy", "oracle-readonly-reentrancy",
                     "oracle-reentrancy-guard-missing"],
        "applies_to": "both",
        "description": "Oracle reads external pool state without checking pool's own reentrancy guard — inconsistent mid-trade values",
    },
    "oracle-heartbeat-no-fallback": {
        "keywords": ["oracle-heartbeat-missing", "update-gap-freezes-market", "chainlink-heartbeat",
                     "heartbeat-no-fallback"],
        "applies_to": "both",
        "description": "System depends on strictly-timed oracle roundId with no fallback path when heartbeat misses",
    },
    "oracle-version-expired-stale-return": {
        "keywords": ["expired-oracle-version", "stale-instead-of-invalid", "expired-return-prev",
                     "oracle-version-expired"],
        "applies_to": "both",
        "description": "Oracle versioning returns previous-price instead of INVALID when current-version commit times out",
    },
    "chainlink-feed-decimals-hardcoded": {
        "keywords": ["feed-decimals-hardcoded", "pricefeed-decimals-assumption",
                     "chainlink-8-decimals", "decimals-hardcoded"],
        "applies_to": "both",
        "description": "Price-feed decimals hardcoded to 8 (or other value) instead of reading pricefeed.decimals() — off by 10^N",
    },
    # Cycle-43 ceiling raise (4 reentrancy variant classes)
    "erc721-safe-transfer-reentrancy": {
        "keywords": ["erc721-safetransfer-reentrancy", "safeTransferFrom-reentrancy",
                     "onERC721Received-reentrancy", "erc721-safe-transfer-reentrancy",
                     "erc721-safe-transfer"],
        "applies_to": "both",
        "description": "ERC721 safeTransferFrom / safeMint receiver hook allows reentrancy before state commit",
    },
    "erc777-hook-reentrancy": {
        "keywords": ["erc777-hook-reentrancy", "tokensToSend-reentrancy",
                     "erc777-callback-reentrancy"],
        "applies_to": "both",
        "description": "ERC777 tokensToSend / tokensReceived hook lets sender reenter before state commit",
    },
    "liquidation-reentrancy-takeover": {
        "keywords": ["liquidation-reentrancy-takeover", "takeOverDebt-reentrancy",
                     "liquidation-transfer-race"],
        "applies_to": "both",
        "description": "Liquidation and debt-takeover race via reentrancy — position double-liquidated",
    },
    "post-exec-check-reentrancy-bypass": {
        "keywords": ["post-exec-check-reentrancy", "checkAfterExecution-bypass",
                     "module-add-reentrancy-bypass", "post-exec-check-reentrancy-bypass"],
        "applies_to": "both",
        "description": "checkAfterExecution / after-hook re-reads state that was mutated by the executed call — reentrancy bypasses the check",
    },
    # Cycle-45 ceiling raise (4 flash-loan variant classes)
    "flashloan-delegated-vote-bypass": {
        "keywords": ["flashloan-delegated-vote", "vote-flash-delegate-bypass",
                     "delegated-vote-flash", "vote-snapshot-flashloan"],
        "applies_to": "both",
        "description": "Flash-loan + delegated voting bypasses simple flash-mitigations that only block direct-vote paths",
    },
    "checkpoint-same-block-ambiguity": {
        "keywords": ["checkpoint-same-block", "getAtBlock-first-checkpoint",
                     "checkpoint-ordering-ambiguity", "stake-exit-same-block"],
        "applies_to": "both",
        "description": "Checkpoint.getAtBlock returns earliest value when multiple checkpoints exist in same block — flash stake-exit fakes stake value for later query",
    },
    "pmm-internal-price-manipulation": {
        "keywords": ["pmm-internal-price", "pmm-oracle-manipulation", "reserve-manipulation-pmm",
                     "single-sided-pool-drain"],
        "applies_to": "both",
        "description": "PMM oracle's internal price derived from on-pool reserves; flash-skew reserve → trade at bad price → pool drain",
    },
    "il-compensation-reserve-snapshot": {
        "keywords": ["il-compensation-flash", "impermanent-loss-compensation-manip",
                     "flash-reserve-snapshot-il", "il-compensation-reserve-snapshot",
                     "il-compensation-reserve"],
        "applies_to": "both",
        "description": "Impermanent-loss / slippage compensation computed from CURRENT reserves — flash-skewed reserves inflate the claim",
    },
    "reward-cliff-boundary-wrong-supply": {
        "keywords": ["reward-cliff-boundary", "cvx-cliff-boundary", "cliff-boundary-wrong-supply",
                     "reward-cliff-wrong-supply"],
        "applies_to": "both",
        "description": "Reward calculation at CVX/AURA-style cliff boundary uses wrong cliff-index (post-mint vs pre-mint supply) — last-cliff reward miscalculated",
    },
    "reward-cached-vs-current-index-drift": {
        "keywords": ["reward-cached-index", "reward-index-drift", "cached-vs-current-index",
                     "rewardpertoken-stale-cache"],
        "applies_to": "both",
        "description": "Reward accrual uses cached rewardPerTokenStored instead of current — users who stake between updates miss rewards / get over-credited",
    },
    "tax-refund-post-fee-amount": {
        "keywords": ["tax-refund-post-fee", "tax-refund-wrong-base", "fee-refund-post-fee",
                     "refund-uses-post-fee-amount"],
        "applies_to": "both",
        "description": "Tax/fee refund computed from POST-fee transfer amount instead of pre-fee input — refund double-subtracts, user gets less or math underflows",
    },
    "allowance-spend-cross-function-leak": {
        "keywords": ["allowance-cross-function-leak", "allowance-spend-leak",
                     "allowance-bypass-yield-drain", "cross-fn-allowance-spend",
                     "allowance-spend-cross-function", "allowance-spend-cross-function-leak"],
        "applies_to": "both",
        "description": "ERC20 allowance spent in one function (transfer) is not decremented before a sibling function (redeem/withdraw) uses the same allowance path — attacker drains via sibling call",
    },
    "draw-reward-wrong-denominator": {
        "keywords": ["draw-reward-wrong-denom", "prize-reward-wrong-denom",
                     "lottery-denominator-wrong", "draw-wrong-denominator"],
        "applies_to": "both",
        "description": "Prize/draw reward share uses wrong denominator (total supply vs eligible supply) — non-eligible holders dilute winners' prize or vice versa",
    },
    "withdraw-contribution-wrong-divisor": {
        "keywords": ["withdraw-contribution-divisor", "contribution-wrong-divisor",
                     "withdraw-wrong-divisor", "fractional-withdraw-divisor"],
        "applies_to": "both",
        "description": "withdrawContribution / refund divides by total or remaining supply using wrong base (includes fees, excludes redeemed shares) — overpays or underpays contributors",
    },
    "vault-add-reward-accepts-underlying": {
        "keywords": ["add-reward-accepts-underlying", "reward-token-accepts-underlying",
                     "vault-add-reward-accepts-underlying", "reward-equals-stake-token"],
        "applies_to": "both",
        "description": "Vault/staking addRewardToken accepts the underlying-stake asset as reward — attacker registers it, user stake counted as reward pool, drain 99%",
    },
    "bridge-generic-call-arbitrary-target": {
        "keywords": ["bridge-generic-call-arbitrary", "generic-bridge-arbitrary-target",
                     "bridge-arbitrary-call-user-allowance", "bridge-generic-call-arbitrary-target"],
        "applies_to": "both",
        "description": "Bridge/swap facet forwards user-supplied (target, calldata) with no target-allowlist — attacker calls token.transferFrom(victim, attacker, allowance) through the bridge",
    },
    "commitment-caller-not-collateral-owner": {
        "keywords": ["commitment-caller-not-owner", "validate-commitment-missing-owner",
                     "caller-not-collateral-owner", "commitment-caller-not-collateral-owner"],
        "applies_to": "both",
        "description": "Loan/commitment validation checks caller OR receiver OR signature but never binds caller == collateral owner — anyone mints a lien against someone else's NFT",
    },
    "withdraw-fee-no-claimed-flag": {
        "keywords": ["withdraw-fee-no-flag", "withdraw-fee-replay",
                     "fee-no-claimed-flag", "withdraw-fee-no-claimed-flag"],
        "applies_to": "both",
        "description": "withdrawFee / withdrawReward lacks a `feeWithdrawn` / `claimed` flag — caller invokes it N times and drains the fee pool",
    },
    "dual-admin-modifier-override": {
        "keywords": ["dual-admin-modifier", "onlyOwnerOrAdministrator",
                     "dual-role-override-config", "dual-admin-override"],
        "applies_to": "both",
        "description": "Single modifier allows EITHER owner OR admin to mutate shared config — either role overrides the other's work (price, allowlist, signer) with no consent check",
    },
    "governance-proposal-duplicate-action-queue-collision": {
        "keywords": ["proposal-duplicate-action", "queue-action-collision",
                     "governance-repeated-action-dos",
                     "governance-proposal-duplicate-action-queue-collision"],
        "applies_to": "both",
        "description": "Governor queue keyed by keccak(target,value,signature,data) — duplicate actions in one proposal collide, second queue() reverts, whole proposal DoS'd",
    },
    "governor-no-timelock-between-queue-and-execute": {
        "keywords": ["governor-no-timelock-queue-execute",
                     "queue-and-execute-same-block",
                     "flashloan-governance-takeover-no-timelock",
                     "governor-no-timelock-between-queue-and-execute"],
        "applies_to": "solidity_only",
        "tier": "A",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "description": "Governor execute() consumes a _queued[id] / queuedAt flag with no eta / TIMELOCK / GRACE_PERIOD / block.timestamp >= eta gate — flashloan-voting attacker queues and executes in the same transaction. Historical: Beanstalk 2022 ~$182M.",
    },
    "timelock-eth-stranded-no-refund": {
        "keywords": ["timelock-eth-stranded", "timelock-no-refund",
                     "timelock-eth-lock", "timelock-eth-stranded-no-refund"],
        "applies_to": "both",
        "description": "Timelock.execute accepts msg.value but never refunds unused ETH or tracks stranded ETH when execution fails — funds accumulate with no rescue path",
    },
    "veto-selector-check-wrapper-bypass": {
        "keywords": ["veto-selector-bypass", "veto-wrapper-bypass",
                     "veto-calldata-check-superficial", "veto-selector-check-wrapper-bypass"],
        "applies_to": "both",
        "description": "Council/guardian veto scans only outer selector; attacker wraps the forbidden call inside a multicall/proxy selector — veto misses it",
    },
    "vote-checkpoint-same-block-multiple-entries": {
        "keywords": ["vote-checkpoint-same-block", "vote-checkpoint-multiple-entries",
                     "erc721votes-same-block-checkpoint",
                     "vote-checkpoint-same-block-multiple-entries"],
        "applies_to": "both",
        "description": "_writeCheckpoint pushes a new entry per call, not per timestamp — _getPriorVotes binary-search returns stale entry for flash transfers in the same block",
    },
    "quorum-denominator-static-stale-total-power": {
        "keywords": ["quorum-denominator-static", "static-total-power",
                     "quorum-unreachable-static-denom",
                     "quorum-denominator-static-stale-total-power"],
        "applies_to": "both",
        "description": "Quorum denominator uses a cached totalPowerInTokens that isn't recomputed when NFTs transfer/burn — denominator inflates, quorum math becomes unreachable",
    },
    "delegation-overwrite-no-auth": {
        "keywords": ["delegation-overwrite-no-auth", "update-user-boost-no-auth",
                     "delegation-overwrite-dos", "delegate-overwrite-no-auth"],
        "applies_to": "both",
        "description": "Delegation/boost update fn lacks auth — anyone calls it with victim's address, zeroing delegation and DoS'ing victim's voting power",
    },
    "erc1271-replay-no-nonce": {
        "keywords": ["erc1271-replay-no-nonce", "erc1271-isvalidsignature-replay",
                     "isvalidsignature-no-nonce", "erc1271-replay"],
        "applies_to": "both",
        "description": "ERC1271 isValidSignature verifies sig hash without binding to a per-owner nonce — same signature replays across wallet-transition operations",
    },
    "merkle-leaf-no-used-flag": {
        "keywords": ["merkle-leaf-no-flag", "merkle-redeem-no-used-flag",
                     "merkle-proof-replay", "merkle-leaf-no-used-flag"],
        "applies_to": "both",
        "description": "Merkle-verified redemption/claim accepts proof but never marks `used[leaf]` — attacker replays identical parameters until pool drained",
    },
    "compact-sig-variant-allows-replay": {
        "keywords": ["compact-sig-replay", "eip2098-compact-variant",
                     "ecdsa-two-encodings", "compact-sig-variant-allows-replay"],
        "applies_to": "both",
        "description": "ECDSA.recover accepts both 65-byte and EIP-2098 compact formats — the same semantic sig is recoverable twice, bypassing nonce-keyed replay protection",
    },
    "signature-not-bound-to-target-consumer": {
        "keywords": ["sig-not-bound-to-consumer", "sig-not-bound-target",
                     "signature-replay-across-targets",
                     "signature-not-bound-to-target-consumer"],
        "applies_to": "both",
        "description": "Approve-by-signature hashes only call payload + signer but omits target contract — signature authorized for consumer A is reusable on consumer B",
    },
    "permit-swap-frontrun-zero-min-out": {
        "keywords": ["permit-swap-frontrun", "permit-min-out-zero",
                     "permit-sig-sandwich", "permit-swap-frontrun-zero-min-out"],
        "applies_to": "both",
        "description": "Swap fn bundles a user permit sig with caller-controlled amountOutMin — searcher extracts permit and submits at amountOutMin=0, sandwiching the victim",
    },
    "permit2-intent-binding-missing": {
        "keywords": ["permit2-intent-binding", "permit2-no-intent",
                     "permit2-recipient-unbound", "permit2-intent-binding-missing"],
        "applies_to": "both",
        "description": "Caller passes Permit2 sig to a proxy/target without binding the intended recipient / function — any contract with the sig can redirect the funds",
    },
    "vault-asset-injection-without-share-mint": {
        "keywords": ["vault-asset-injection", "rebase-without-mint",
                     "totalassets-inflate-no-share",
                     "vault-asset-injection-without-share-mint"],
        "applies_to": "both",
        "description": "Vault rebases by minting underlying directly to contract without minting matching shares — totalAssets inflates, depositors transfer value to prior holders",
    },
    "nested-erc4626-fee-not-accounted": {
        "keywords": ["nested-erc4626-fee", "underlying-vault-fee-ignored",
                     "nested-vault-preview-fee-miss",
                     "nested-erc4626-fee-not-accounted"],
        "applies_to": "both",
        "description": "Wrapper vault delegates to an underlying ERC4626 that charges deposit/withdraw fees — previewDeposit-based share math ignores the fee, wrapper issues too many/few shares",
    },
    "erc4626-rounding-direction-mixed": {
        "keywords": ["erc4626-rounding-mixed", "convert-preview-rounding-mismatch",
                     "erc4626-rounding-direction-mixed"],
        "applies_to": "both",
        "description": "convertToShares rounds DOWN while previewDeposit rounds UP (or vice versa) — arbitrage extracts free shares/assets on the rounding gap",
    },
    "erc4626-vault-strategy-decimal-mismatch": {
        "keywords": ["erc4626-decimal-mismatch", "vault-strategy-decimals",
                     "strategy-scaling-missing",
                     "erc4626-vault-strategy-decimal-mismatch"],
        "applies_to": "both",
        "description": "Vault (e.g. 18 dec) and strategy (e.g. 6 dec) use each other's raw values without a 10^N scale factor — share price wildly inflated or deflated",
    },
    "erc4626-first-deposit-mint-vs-deposit-asymmetry": {
        "keywords": ["erc4626-first-deposit-asymmetry", "mint-vs-deposit-first",
                     "erc4626-first-deposit-mint-vs-deposit-asymmetry"],
        "applies_to": "both",
        "description": "deposit() and mint() take different first-deposit paths (convertToShares 1:1 vs previewMint rounds-up) — first depositor gets different share count depending on entry point",
    },
    "erc4626-asset-diff-vs-preview-fee-drift": {
        "keywords": ["erc4626-asset-diff-fee", "assets-after-minus-before-fee",
                     "erc4626-asset-diff-vs-preview-fee-drift"],
        "applies_to": "both",
        "description": "Wrapper records `assetsAfter - assetsBefore` after calling underlying.deposit() which already deducted a fee; mismatch with previewDeposit causes accounting drift",
    },
    "bridge-destination-frontrun-after-approve": {
        "keywords": ["bridge-destination-frontrun", "bridge-nft-destination-frontrun",
                     "bridge-destination-frontrun-after-approve"],
        "applies_to": "both",
        "description": "Bridge fn takes destination address from caller AFTER owner approves the NFT/token — attacker frontruns with own destination, steals bridged asset",
    },
    "bridge-signal-hash-value-not-bound": {
        "keywords": ["bridge-signal-hash", "signal-hash-forge",
                     "bridge-signal-hash-value-not-bound"],
        "applies_to": "both",
        "description": "Bridge sendSignal stores hash(msg) as processed flag but message.value/fee aren't part of the hash key — attacker crafts same-hash message with different value",
    },
    "deposit-and-bridge-unlock-bypass": {
        "keywords": ["deposit-and-bridge-bypass", "bridge-unlock-bypass",
                     "share-unlock-bridge-exit",
                     "deposit-and-bridge-unlock-bypass"],
        "applies_to": "both",
        "description": "Mint+bridge-send in one fn skips the shareUnlockTime check that only direct withdraw enforces — lockup bypassed",
    },
    "ccip-receive-source-chain-not-validated": {
        "keywords": ["ccip-source-not-validated", "ccip-receive-source-chain",
                     "ccip-receive-source-chain-not-validated"],
        "applies_to": "both",
        "description": "_ccipReceive handles Any2EVMMessage without checking sourceChainSelector against an allowlist — attacker sends from cheap side-chain",
    },
    "bridge-retry-settlement-award-replay": {
        "keywords": ["bridge-retry-settlement-replay", "retry-settlement-replay",
                     "bridge-retry-settlement-award-replay"],
        "applies_to": "both",
        "description": "retrySettlement marks settlementId executed but reuses nonce space for fresh payouts; attacker retries after awards accrue",
    },
    "bridge-receive-message-conditional-auth-missing": {
        "keywords": ["bridge-receive-message-conditional", "receive-message-auth-conditional",
                     "bridge-receive-message-conditional-auth-missing"],
        "applies_to": "both",
        "description": "receiveMessage guards sender only on one branch (threshold == 1); other branches accept any external caller",
    },
    "fee-harvest-swap-zero-min-out": {
        "keywords": ["fee-harvest-zero-min-out", "harvest-swap-zero-slippage",
                     "charge-fees-swap-no-min-out", "fee-harvest-swap-zero-min-out"],
        "applies_to": "both",
        "description": "Protocol-fee harvest or sellProfits swap uses amountOutMinimum=0 — every harvest sandwiched, slice of fees drained",
    },
    "self-sandwich-caller-controlled-slippage-bad-debt": {
        "keywords": ["self-sandwich-controlled-slippage", "caller-slippage-bad-debt",
                     "self-sandwich-caller-controlled-slippage-bad-debt"],
        "applies_to": "both",
        "description": "Position-open/close internally swaps with caller-controlled slippage — attacker self-sandwiches to steal from vault and leaves bad debt",
    },
    "reserve-sell-no-slippage-min-out": {
        "keywords": ["reserve-sell-no-slippage", "protocol-reserve-sell-no-min-out",
                     "reserve-sell-no-slippage-min-out"],
        "applies_to": "both",
        "description": "Protocol reserve-sell / _sellDsReserve uses DEX swap with no amountOutMinimum — LP reserves sandwiched on every trigger",
    },
    "withdraw-amount-request-time-tvl-mev": {
        "keywords": ["withdraw-amount-request-time-tvl", "withdraw-queue-tvl-mev",
                     "request-time-tvl-sandwich",
                     "withdraw-amount-request-time-tvl-mev"],
        "applies_to": "both",
        "description": "Withdraw queue computes shares→assets at REQUEST time using live TVL / oracle — attacker sandwiches the request block to extract TVL delta",
    },
    "deadline-block-timestamp-passthrough": {
        "keywords": ["deadline-block-timestamp-passthrough", "deadline-always-pass",
                     "deadline-equal-block-timestamp",
                     "deadline-block-timestamp-passthrough"],
        "applies_to": "both",
        "description": "Caller passes block.timestamp (or now) as the deadline argument — validator-side deadline check always passes, stale pending txs execute",
    },
    "lsd-stake-internal-deposit-no-slippage": {
        "keywords": ["lsd-stake-internal-deposit", "stake-internal-deposit-no-slippage",
                     "internal-lst-deposit-sandwich",
                     "lsd-stake-internal-deposit-no-slippage"],
        "applies_to": "both",
        "description": "Stake/unstake/rebalance fn internally deposits into LST (rETH / stETH / etc.) without passing a min-out — stakers sandwiched",
    },
    "amm-rebalance-slot0-manipulation": {
        "keywords": ["amm-rebalance-slot0", "slot0-rebalance-manipulation",
                     "lp-reallocate-slot0", "amm-rebalance-slot0-manipulation"],
        "applies_to": "both",
        "description": "LP rebalance / reallocate decision reads slot0 current tick — flash swap within block manipulates slot0, attacker forces bad rebalance",
    },
    "v3-fee-growth-safemath-underflow-revert": {
        "keywords": ["v3-fee-growth-safemath", "fee-growth-underflow-revert",
                     "v3-fee-growth-safemath-underflow-revert"],
        "applies_to": "both",
        "description": "UniV3 position-value fee-growth math relies on intentional underflow; integrator uses checked arithmetic, operation panics and reverts",
    },
    "v3-seconds-per-liquidity-overflow-lock": {
        "keywords": ["seconds-per-liquidity-overflow", "v3-staker-overflow-lock",
                     "v3-seconds-per-liquidity-overflow-lock"],
        "applies_to": "both",
        "description": "UniV3Staker read of seconds_per_liquidity_inside overflows when liquidity is tiny and time elapsed is large — unstake uses checked sub, position locked",
    },
    "lp-shared-tick-range-accounting-theft": {
        "keywords": ["shared-tick-range-theft", "lp-shared-range-accounting",
                     "lp-shared-tick-range-accounting-theft"],
        "applies_to": "both",
        "description": "Protocol burns LP liquidity at a tick range without tracking which pair owns it — two pairs on same range commingle, one burns and steals the other's liquidity",
    },
    "cached-uniswap-liquidity-stale-collateral": {
        "keywords": ["cached-uniswap-liquidity", "stale-v3-collateral",
                     "cached-uniswap-liquidity-stale-collateral"],
        "applies_to": "both",
        "description": "Lending/collateral system caches Uniswap v3 position.liquidity() at deposit; borrower later decreases liquidity and collateral value becomes fake",
    },
    "erc6909-partial-unwrap-fee-theft": {
        "keywords": ["partial-unwrap-fee-theft", "erc6909-partial-unwrap",
                     "erc6909-partial-unwrap-fee-theft"],
        "applies_to": "both",
        "description": "Wrapper partial-unwrap returns the underlying NFT with accrued fees intact while wrapper supply tracks only partial — attacker partial-unwraps, claims fees, re-wraps",
    },
    "liquidation-ema-lag-seizes-solvent-borrower": {
        "keywords": ["liquidation-ema-lag", "ema-lag-liquidation",
                     "liquidation-ema-lag-seizes-solvent-borrower"],
        "applies_to": "both",
        "description": "Liquidation decision uses EMA/averaged price while borrower is solvent at spot — whitelisted bots seize collateral from still-solvent borrower during EMA-lag window",
    },
    "liquidation-bonus-strict-reverts-when-underfunded": {
        "keywords": ["liquidation-bonus-strict", "liquidation-bonus-reverts",
                     "liquidation-bonus-strict-reverts-when-underfunded"],
        "applies_to": "both",
        "description": "Liquidation fn strict-requires debt + bonus <= collateral; when position drops below bonus threshold liquidation reverts and bad debt accumulates",
    },
    "liquidation-rounding-up-collateral-down-debt": {
        "keywords": ["liquidation-rounding-up-collateral", "liquidation-rounding-up-down",
                     "liquidation-rounding-up-collateral-down-debt"],
        "applies_to": "both",
        "description": "Liquidation rounds up collateral transferred to liquidator while rounding down debt repayment — repeated calls drain the position",
    },
    "post-liquidation-borrow-no-health-check": {
        "keywords": ["post-liquidation-borrow-no-health", "utilize-no-health-check",
                     "post-liquidation-borrow-no-health-check"],
        "applies_to": "both",
        "description": "Borrow/utilize fn lacks a health-factor / is_liquidated gate — just-liquidated operator can immediately borrow again",
    },
    "max-liquidable-calc-inconsistent-scaling": {
        "keywords": ["max-liquidable-inconsistent-scaling", "max-liquidable-calc-mismatch",
                     "max-liquidable-calc-inconsistent-scaling"],
        "applies_to": "both",
        "description": "calculate_max_liquidation sizes max_liquidable_collateral and max_liquidable_debt using inconsistent scaling/oracle bounds — attacker pockets the delta",
    },
    "health-vs-slashable-collateral-discrepancy": {
        "keywords": ["health-vs-slashable-discrepancy", "slashable-collateral-discrepancy",
                     "health-vs-slashable-collateral-discrepancy"],
        "applies_to": "both",
        "description": "Agent health calc uses a different collateral model than slashable collateral — unhealthy agents slash insufficient amount, protocol absorbs bad debt",
    },
    "mint-based-on-pre-transfer-input-amount-fot": {
        "keywords": ["mint-pre-transfer-input-fot", "fot-mint-input-not-actual",
                     "mint-based-on-pre-transfer-input-amount-fot"],
        "applies_to": "both",
        "description": "fundWithToken / deposit mints credit from INPUT parameter but fee-on-transfer token delivers less — over-credits user, protocol insolvency",
    },
    "ledger-delta-unmeasured-fot-drift": {
        "keywords": ["ledger-delta-unmeasured", "balance-based-accounting-fot",
                     "ledger-delta-unmeasured-fot-drift"],
        "applies_to": "both",
        "description": "Lender / vault internal ledger uses `+= amount` without measuring balance delta post-transfer — FoT/rebasing drifts accounting until insolvency",
    },
    "erc20-transfer-return-unchecked": {
        "keywords": ["transfer-return-unchecked", "erc20-transfer-return-unchecked"],
        "applies_to": "both",
        "description": "Code calls token.transfer(...) / transferFrom(...) without checking boolean result — USDT-style tokens return false instead of reverting, silent failure",
    },
    "erc1155-amount-hardcoded-not-order-amount": {
        "keywords": ["erc1155-amount-hardcoded", "matching-amount-hardcoded",
                     "erc1155-amount-hardcoded-not-order-amount"],
        "applies_to": "both",
        "description": "Matching policy returns hardcoded `amount = 1` instead of `order.amount` — attacker lists N units and matcher fills only 1",
    },
    "token-transfer-orphans-accrued-rewards": {
        "keywords": ["transfer-orphans-rewards", "pool-token-transfer-no-settle",
                     "token-transfer-orphans-accrued-rewards"],
        "applies_to": "both",
        "description": "Pool/reward token transfer hook doesn't settle accrued rewards before updating balances — sender's lastRewardPerToken drifts, future accrual underflows or orphans",
    },
    "fee-config-intermediate-overflow-vault-drain": {
        "keywords": ["fee-config-overflow", "pnl-intermediate-overflow",
                     "fee-config-intermediate-overflow-vault-drain"],
        "applies_to": "both",
        "description": "PnL / fee math performs `position * price * fee_bps / 1e18 / 1e18` — intermediate multiplication overflows uint256, wraps to tiny value, attacker drains vault",
    },
    "funding-rate-maker-only-skew-applied-whole-market": {
        "keywords": ["funding-rate-maker-only-skew", "funding-rate-skew-whole-market",
                     "funding-rate-maker-only-skew-applied-whole-market"],
        "applies_to": "both",
        "description": "Funding rate derived only from oracle maker's skew but applied across all positions — attacker shakes maker skew at low cost and collects funding",
    },
    "nav-uses-spot-not-perp-mark": {
        "keywords": ["nav-uses-spot-not-perp", "vault-nav-spot-not-mark",
                     "nav-uses-spot-not-perp-mark"],
        "applies_to": "both",
        "description": "NAV / vault-value computes perp position value using oracle spot price, ignoring perp mark price — NAV drifts from true liquidation value",
    },
    "perp-value-uses-underlying-not-perp-price": {
        "keywords": ["perp-value-uses-underlying", "perp-mark-mismatch-underlying",
                     "perp-value-uses-underlying-not-perp-price"],
        "applies_to": "both",
        "description": "Perp position valuation reads underlying spot while trades execute at perp price — mark-to-market vs execution mismatch lets traders exit favorably",
    },
    "vault-admin-action-uses-mark-price": {
        "keywords": ["vault-admin-action-uses-mark-price", "admin-rake-mark-price",
                     "governance-sized-by-mark-price", "price-vault-mark"],
        "applies_to": "solidity_only",
        "description": "Admin-gated vault/strategy fn (onlyOwner/Governance/Keeper) sizes a value-transfer — fee rake, rebalance, treasury sweep — from the live perp mark-price with no TWAP / oracle-heartbeat / stale-price guard; admin (or any whale) moves markPrice for one block and the rake is computed at an inflated mark (Phase 33 novel-surfacer triangle price-vault-mark — sibling to nav-uses-spot-not-perp-mark and perp-value-uses-underlying-not-perp-price)",
    },
    "perp-open-price-rounds-down-drift": {
        "keywords": ["perp-open-price-rounds-down", "weighted-avg-open-price-drift",
                     "perp-open-price-rounds-down-drift"],
        "applies_to": "both",
        "description": "Weighted-average open_price on new fill rounds DOWN — attacker spams small crafted fills to drift open_price lower, then realises favorable PnL",
    },
    "perp-post-liquidation-market-state-not-reset": {
        "keywords": ["perp-post-liquidation-state-not-reset", "perp-open-interest-not-decremented",
                     "perp-post-liquidation-market-state-not-reset"],
        "applies_to": "both",
        "description": "Liquidation path doesn't decrement open_interest / position_count / imbalance — subsequent ops revert or produce wrong funding",
    },
    "liquidation-ltv-ignores-accrued-interest": {
        "keywords": ["liquidation-ltv-ignores-interest", "ltv-check-excludes-interest",
                     "liquidation-ltv-ignores-accrued-interest"],
        "applies_to": "both",
        "description": "Liquidation LTV / health check sees position_amount/position_size as pristine collateralization and excludes accrued interest — loan stays 'healthy' as debt grows, bad debt",
    },
    "staking-balance-overwrite-not-add": {
        "keywords": ["staking-balance-overwrite", "stake-overwrite-balance",
                     "staking-balance-overwrite-not-add"],
        "applies_to": "both",
        "description": "stake() writes `stakedBalance[user] = amount` instead of `+=` — second call overwrites, attacker keeps old-high balance on books",
    },
    "unstake-no-balance-deduction-drain": {
        "keywords": ["unstake-no-deduction", "unstake-missing-balance-deduction",
                     "unstake-no-balance-deduction-drain"],
        "applies_to": "both",
        "description": "Unstake fn transfers tokens out but doesn't decrement stakedBalance — user calls repeatedly, drains contract",
    },
    "reward-multiplier-reset-by-griefer": {
        "keywords": ["reward-multiplier-reset-griefer", "multiplier-reset-permissionless",
                     "reward-multiplier-reset-by-griefer"],
        "applies_to": "both",
        "description": "Permissionless reward-weight update can be called with 0 diff, resetting a user's multiplier to 1 — griefer keeps it pinned low",
    },
    "boost-mutation-without-settling-rewards": {
        "keywords": ["boost-mutation-no-settle", "setLockStatus-no-update-reward",
                     "boost-mutation-without-settling-rewards"],
        "applies_to": "both",
        "description": "setLockStatus / updateBoost changes boost factor without calling updateReward first — accrued rewards get retroactively multiplied",
    },
    "vrf-redraw-allowed-rig-outcome": {
        "keywords": ["vrf-redraw-rig", "draw-organizer-redraw-rig",
                     "vrf-redraw-allowed-rig-outcome"],
        "applies_to": "both",
        "description": "Draw/raffle host can requestRandomWords multiple times via redraw path — waits for favorable outcome, rigs results",
    },
    "gauge-reward-stake-withdraw-burst-game": {
        "keywords": ["gauge-reward-stake-withdraw-game", "gauge-burst-stake-withdraw",
                     "gauge-reward-stake-withdraw-burst-game"],
        "applies_to": "both",
        "description": "Gauge uses instantaneous balance as reward weight and settles on every stake/withdraw — user bursts large stake-withdraw pairs per block, captures rewards meant for long-term stakers",
    },
    "proxy-constructor-state-not-initialize": {
        "keywords": ["proxy-constructor-state", "constructor-sets-state-proxy",
                     "proxy-constructor-state-not-initialize"],
        "applies_to": "both",
        "description": "Implementation constructor sets state (owner/name/etc) — proxy delegatecall runs in proxy storage, so constructor values never land there; proxy sees uninit state",
    },
    "proxy-admin-wrong-address-blocks-upgrade": {
        "keywords": ["proxy-admin-wrong-address", "transparent-proxy-admin-collision",
                     "proxy-admin-wrong-address-blocks-upgrade"],
        "applies_to": "both",
        "description": "Transparent proxy admin set to a contract that delegates through to impl — admin calls always hit impl (no upgradeTo), proxy un-upgradeable",
    },
    "uups-implementation-takeover-destroy": {
        "keywords": ["uups-implementation-takeover", "uups-selfdestruct-dos",
                     "uups-implementation-takeover-destroy",
                     "implementation-init-not-called-constructor"],
        "applies_to": "both",
        "description": "UUPS implementation has no _disableInitializers() in constructor — attacker initializes impl, becomes owner, upgrades to malicious impl with selfdestruct, proxy breaks",
    },
    "ownable-non-upgradeable-in-proxy": {
        "keywords": ["ownable-non-upgradeable-proxy", "non-upgradeable-ownable",
                     "ownable-non-upgradeable-in-proxy"],
        "applies_to": "both",
        "description": "Upgradeable contract imports non-upgradeable Ownable (constructor-based) — proxy context doesn't run constructor, owner stays address(0), onlyOwner bypassable",
    },
    "storage-migration-missing-reinitializer": {
        "keywords": ["storage-migration-reinitializer", "upgrade-missing-reinitializer",
                     "storage-migration-missing-reinitializer"],
        "applies_to": "both",
        "description": "Upgrade migrates storage var across contracts but provides no reinitializer(N) to set the new var — variable stays at default forever",
    },
    "initialize-frontrun-ownership-steal": {
        "keywords": ["initialize-frontrun-ownership", "initializer-frontrun-steal",
                     "initialize-frontrun-ownership-steal"],
        "applies_to": "both",
        "description": "Proxy deployed then initialize() called in a follow-up tx — attacker mempool-frontruns with own params, claims ownership of the proxy",
    },
    "twap-fallback-to-spot-on-staleness": {
        "keywords": ["twap-fallback-spot", "oracle-fallback-spot-on-staleness",
                     "twap-fallback-to-spot-on-staleness"],
        "applies_to": "both",
        "description": "Oracle returns TWAP primary but falls back to SPOT when TWAP is stale — attacker manipulates spot and forces staleness to poison pricing",
    },
    "oracle-no-outlier-filter-single-feed": {
        "keywords": ["oracle-no-outlier-filter", "single-feed-no-bounds",
                     "oracle-no-outlier-filter-single-feed"],
        "applies_to": "both",
        "description": "Oracle consumer reads a single Chainlink/feed and passes value through with no bound / deviation sanity check — degraded aggregator corrupts callers",
    },
    "price-feed-force-update-simulated-swap": {
        "keywords": ["price-feed-force-update-swap", "force-update-price-simulated",
                     "price-feed-force-update-simulated-swap"],
        "applies_to": "both",
        "description": "Price update path lets caller pass `forceCurBlock=true` or equivalent and runs a simulated swap — attacker picks block to skew cached price",
    },
    "amm-getAmountsIn-used-as-oracle": {
        "keywords": ["amm-getamountsin-oracle", "getamountsin-payment-oracle",
                     "amm-getamountsin-used-as-oracle"],
        "applies_to": "both",
        "description": "Payment pricing uses `uniswapV2Router.getAmountsIn` (or equivalent) against a single pair — flash swap in same block skews result, attacker pays ~0",
    },
    "perp-underlying-px-from-orderbook-last-px": {
        "keywords": ["perp-underlying-px-orderbook", "orderbook-last-px-perp",
                     "perp-underlying-px-from-orderbook-last-px"],
        "applies_to": "both",
        "description": "Perp without oracle uses spot-market `last_px` as underlying price — attacker posts a small crossing order to move last_px and trigger unfair liquidation",
    },
    "chainlink-getTokenPrice-lookback-param-ignored": {
        "keywords": ["chainlink-lookback-ignored", "twap-lookback-param-ignored",
                     "chainlink-gettokenprice-lookback-param-ignored",
                     "gettokenprice-lookback-ignored"],
        "applies_to": "both",
        "description": "getTokenPrice takes a `lookback` seconds param but internally calls latestRoundData — caller believes they got TWAP, they get spot",
    },
    "vote-uses-current-balance-not-snapshot": {
        "keywords": ["vote-uses-current-balance", "castvote-current-balance-not-snapshot",
                     "vote-uses-current-balance-not-snapshot"],
        "applies_to": "both",
        "description": "castVote reads current balance instead of balance_at(proposal.snapshot) — user buys tokens after proposal, votes, sells; effectively double-spending voting power",
    },
    "votes-binary-search-duplicate-timestamp": {
        "keywords": ["votes-binary-search-duplicate", "binary-search-duplicate-ts",
                     "votes-binary-search-duplicate-timestamp"],
        "applies_to": "both",
        "description": "getPastVotes binary-search on checkpoints doesn't handle duplicate timestamps deterministically — attacker times writes so search returns stale entry",
    },
    "quorum-quadratic-vote-mismatch": {
        "keywords": ["quorum-quadratic-vote-mismatch", "quadratic-vote-linear-quorum",
                     "quorum-quadratic-vote-mismatch"],
        "applies_to": "both",
        "description": "Vote counting uses sqrt-weighted (quadratic) strategy but quorum numerator uses linear total supply — quorum unreachable or trivially reached",
    },
    "veto-skipped-single-host-majority": {
        "keywords": ["veto-skipped-single-host", "single-host-veto-skip",
                     "veto-skipped-single-host-majority"],
        "applies_to": "both",
        "description": "Veto delay skipped based on 'all-hosts-agree' flag computed from partial host-vote count — single host can flip the flag",
    },
    "snapshot-function-never-called": {
        "keywords": ["snapshot-function-never-called", "erc20snapshot-never-invoked",
                     "snapshot-never-called"],
        "applies_to": "both",
        "description": "ERC20Snapshot / snapshot-based voting inherits the snapshot module but never exposes or calls `_snapshot()` — balanceOfAt always reverts",
    },
    "state-mutation-between-read-and-write-delta": {
        "keywords": ["state-mutation-between-read-write", "delta-computed-post-mutation",
                     "state-mutation-between-read-and-write-delta"],
        "applies_to": "both",
        "description": "Delta value computed via `read_before()` / `read_after()` flanking a state mutation — state mutation lands BETWEEN read and write, delta is wrong",
    },
    "yt-interest-claim-blocked-by-donation": {
        "keywords": ["yt-interest-claim-blocked", "yield-token-donation-blocks-claim",
                     "yt-interest-claim-blocked-by-donation"],
        "applies_to": "both",
        "description": "Attacker donates tokens directly to PT/YT reserves, breaking accrual invariant; YT.claim_interest reverts on underflow",
    },
    "vault-donation-locks-ratio-permanent": {
        "keywords": ["vault-donation-locks-ratio", "donation-ratio-lock-permanent",
                     "vault-donation-locks-ratio-permanent"],
        "applies_to": "both",
        "description": "Attacker donates to empty vault; integer-division ratio locks at 1 permanently, all future deposits mint 1:1 regardless of accrued value",
    },
    "vault-allocate-rewards-timing-theft": {
        "keywords": ["vault-allocate-rewards-timing", "allocate-rewards-theft",
                     "vault-allocate-rewards-timing-theft"],
        "applies_to": "both",
        "description": "_allocate distributes undistributed rewards based on current-block shares — attacker deposits, triggers allocate, withdraws to skim accrued yield",
    },
    "yt-external-reward-distribution-formula-wrong": {
        "keywords": ["yt-external-reward-formula", "yt-rewards-formula-pro-rata-wrong",
                     "yt-external-reward-distribution-formula-wrong"],
        "applies_to": "both",
        "description": "YT external-reward distribution uses user_yt_balance / total_yt_supply as pro-rata weight, but YT balance grows with claimed YBT yield — rich YT holders get disproportionally more rewards",
    },
    "cross-chain-borrow-no-interest-accrual-on-subsequent": {
        "keywords": ["cross-chain-borrow-no-accrual", "subsequent-borrow-skip-accrual",
                     "cross-chain-borrow-no-interest-accrual-on-subsequent"],
        "applies_to": "both",
        "description": "Subsequent cross-chain borrow of same asset increments principal without accruing interest on existing balance — borrower enjoys interest-free extension",
    },
    "liquidate-uses-stored-outdated-liabilities": {
        "keywords": ["liquidate-uses-stored", "borrow-balance-stored-outdated",
                     "liquidate-uses-stored-outdated-liabilities"],
        "applies_to": "both",
        "description": "Liquidation / warn uses `borrowBalanceStored` (no interest accrual) so stored balance is outdated — user creates bad debt in one tx by timing",
    },
    "auction-stage-skip-via-hook-return-false": {
        "keywords": ["auction-stage-skip-hook", "hook-returns-false-skip-stage",
                     "auction-stage-skip-via-hook-return-false"],
        "applies_to": "both",
        "description": "Multi-stage auction flow skips current stage when a hook returns false without distinguishing error from completion — attacker forces hook failure to skip on-chain auction",
    },
    "dutch-auction-phantom-bid-escrow-lock": {
        "keywords": ["dutch-auction-phantom-bid", "phantom-bid-escrow-lock",
                     "dutch-auction-phantom-bid-escrow-lock"],
        "applies_to": "both",
        "description": "Dutch-auction bid fn stores bid-amount even though only one valid bid exists — phantom bids accumulate, escrow locked waiting for refund",
    },
    "liquidation-seaport-pair-wrong-collateral": {
        "keywords": ["liquidation-seaport-pair-wrong", "seaport-pair-fake-nft",
                     "liquidation-seaport-pair-wrong-collateral"],
        "applies_to": "both",
        "description": "Liquidation lists collateral via Seaport with a fake helper NFT in consideration — buyer manipulates pair to lock the collateral in the contract",
    },
    "nft-multiple-auctions-same-token-escrow-lock": {
        "keywords": ["nft-multiple-auctions-same", "multiple-auctions-same-token",
                     "nft-multiple-auctions-same-token-escrow-lock"],
        "applies_to": "both",
        "description": "createAuction fn doesn't lock NFT against a pre-existing auction — owner creates auction A then B, B wins escrow while A's bidders' funds stay locked",
    },
    "erc1155-escrow-check-dos-all-listings": {
        "keywords": ["erc1155-escrow-check-dos", "marketplace-balance-shared-dos",
                     "erc1155-escrow-check-dos-all-listings"],
        "applies_to": "both",
        "description": "Listing-validity check uses `balanceOf(marketplace, id) >= listing.amount` across ALL listings — single invalid listing cascades to make unrelated listings invalid (DOS)",
    },
    "nft-royalty-receiver-external-call-reentrancy": {
        "keywords": ["nft-royalty-receiver-reentrancy", "royalty-receiver-external-call",
                     "nft-royalty-receiver-external-call-reentrancy"],
        "applies_to": "both",
        "description": "Royalty fee transferred to attacker-controlled `royaltyReceiver` (ERC2981 of malicious NFT) via low-level call — attacker reenters pool via receiver hook and drains",
    },
    "eip712-domain-separator-immutable-forks-unsafe": {
        "keywords": ["eip712-domain-separator-immutable", "domain-separator-cached",
                     "eip712-domain-separator-immutable-forks-unsafe"],
        "applies_to": "both",
        "description": "DOMAIN_SEPARATOR cached at construction using block.chainid — fork / chainid change makes new-chain signatures replayable on old chain",
    },
    "ecrecover-high-s-value-not-rejected": {
        "keywords": ["ecrecover-high-s", "high-s-value-not-rejected",
                     "ecrecover-high-s-value-not-rejected"],
        "applies_to": "both",
        "description": "ecrecover-style recovery returns a valid address for high-s values instead of zero — attacker produces a second/third valid signature on the same message",
    },
    "multisig-threshold-signature-reuse-no-dedup": {
        "keywords": ["multisig-threshold-reuse", "threshold-counts-duplicate",
                     "multisig-threshold-signature-reuse-no-dedup"],
        "applies_to": "both",
        "description": "Multisig loop increments `acquired_threshold` for every recovered signer without deduping — N copies of one valid sig hit threshold",
    },
    "ecrecover-null-address-not-rejected": {
        "keywords": ["ecrecover-null-address", "ecrecover-zero-address-not-rejected",
                     "ecrecover-null-address-not-rejected"],
        "applies_to": "both",
        "description": "ecrecover used without require(signer != address(0)) — invalid sig returns 0; if authorized-signer set contains 0 by default, attacker passes zero-signature",
    },
    "multisig-accepts-duplicate-signer": {
        "keywords": ["multisig-accepts-duplicate-signer", "multisig-no-signer-dedup",
                     "multisig-accepts-duplicate-signer"],
        "applies_to": "both",
        "description": "validateMessage counts every sig in the attestor set without dedup-by-signer — repeated signatures from one attestor pass threshold",
    },
    "eip712-nested-array-incorrect-hashing": {
        "keywords": ["eip712-nested-array", "nested-array-incorrect-hashing",
                     "eip712-nested-array-incorrect-hashing"],
        "applies_to": "both",
        "description": "EIP-712 typed data hasher flattens nested arrays (e.g. uint256[2][]) instead of per-element recursive hashing — wallet and contract compute different typehash",
    },
    "callback-error-handler-revert-reason-brick": {
        "keywords": ["callback-error-handler-revert", "revert-reason-crafted-brick",
                     "callback-error-handler-revert-reason-brick"],
        "applies_to": "both",
        "description": "Callback.try/catch decodes user-controlled revert reason — attacker returns crafted oversized reason, error handler reverts too, entire flow bricked",
    },
    "revert-reason-faked-length-decode-overread": {
        "keywords": ["revert-reason-faked-length", "faked-length-decode-overread",
                     "revert-reason-faked-length-decode-overread"],
        "applies_to": "both",
        "description": "Callback decodes revert reason via `abi.decode(data,(string))` — attacker supplies length-prefix >> actual bytes, decoder overreads buffer",
    },
    "callback-63-64-gas-rule-bypass-stuck-withdraw": {
        "keywords": ["callback-63-64-gas-rule", "withdraw-high-gaslimit-63-64-bypass",
                     "callback-63-64-gas-rule-bypass-stuck-withdraw"],
        "applies_to": "both",
        "description": "Callback forwards caller-supplied `gasLimit` without reserving enough for post-call resumption — attacker picks limit that leaves insufficient gas, bricks finalize",
    },
    "bridge-recipient-non-20-byte-silent-burn": {
        "keywords": ["bridge-recipient-non-20-byte", "recipient-non-20-byte-silent-burn",
                     "bridge-recipient-non-20-byte-silent-burn"],
        "applies_to": "both",
        "description": "Bridge allows recipient bytes of ANY non-empty length; destination decodeAddress reads first 20 bytes — corrupt/partial recipient, funds silently burned",
    },
    "unsafe-cast-uint256-to-uint128-no-safecast": {
        "keywords": ["unsafe-cast-uint256-uint128", "cast-truncation-no-safecast",
                     "unsafe-cast-uint256-to-uint128-no-safecast"],
        "applies_to": "both",
        "description": "Code casts `uint256(x)` to `uint128` via direct cast instead of `SafeCast.toUint128` — truncates silently when x > 2^128-1",
    },
    "debt-erased-via-fee-offset-without-collateral-check": {
        "keywords": ["debt-erased-fee-offset", "fee-manager-erase-debt-no-collateral-check",
                     "debt-erased-via-fee-offset-without-collateral-check"],
        "applies_to": "both",
        "description": "FeeManager.offsetDebt updates user debt from fee pool without health / collateralization check — user times fee accrual, wipes debt for free",
    },
    "linear-curve-batch-price-sum-vs-product": {
        "keywords": ["linear-curve-batch-price", "bonding-curve-batch-product",
                     "linear-curve-batch-price-sum-vs-product"],
        "applies_to": "both",
        "description": "Linear bonding curve prices batch as `price(n) * n` instead of the arithmetic-series sum — attacker buys bulk at wrong (too low) total price",
    },
    "cpmm-pool-n-token-unsupported-broken": {
        "keywords": ["cpmm-n-token-unsupported", "multi-token-cpmm-broken",
                     "cpmm-pool-n-token-unsupported-broken"],
        "applies_to": "both",
        "description": "Pool factory allows >2-token pools with `ConstantProduct` type — invariant x*y=k only works for 2 tokens, 3+ produces undefined swap math",
    },
    "deposit-tick-range-not-validated-against-vault": {
        "keywords": ["deposit-tick-range-not-validated", "tick-range-unchecked-vs-vault",
                     "deposit-tick-range-not-validated-against-vault"],
        "applies_to": "both",
        "description": "Vault deposit accepts user tick_lower/tick_upper without matching vault's configured range — depositor places LP outside vault range, skips premium",
    },
    "tick-tracking-array-unbounded-brick-mint-burn": {
        "keywords": ["tick-tracking-array-unbounded", "tick-tracking-brick-mint-burn",
                     "tick-tracking-array-unbounded-brick-mint-burn"],
        "applies_to": "both",
        "description": "Liquidity mining tracks every in/out-of-range transition in an unbounded array — attacker dust-swaps to grow array until mint/burn runs out of gas",
    },
    "swap-amount-specified-not-updated-after-clamp": {
        "keywords": ["swap-amount-specified-not-updated", "amount-specified-clamp-mismatch",
                     "swap-amount-specified-not-updated-after-clamp"],
        "applies_to": "both",
        "description": "Swap fn clamps price bounds but doesn't update `amountSpecified` accordingly — user pays full while receiving only clamped-range portion, excess locked",
    },
    "stableswap-slippage-tolerance-wrong-reference-side": {
        "keywords": ["stableswap-slippage-wrong-ref", "slippage-tolerance-wrong-side",
                     "stableswap-slippage-tolerance-wrong-reference-side"],
        "applies_to": "both",
        "description": "assert_slippage_tolerance compares actual_deposit against pool's total balance instead of the user-requested nominal deposit — tolerance check misapplied",
    },
    "hook-bypasses-reentrancy-guard-cross-pool": {
        "keywords": ["hook-bypasses-reentrancy-guard", "cross-pool-reentrancy-via-hook",
                     "hook-bypasses-reentrancy-guard-cross-pool"],
        "applies_to": "both",
        "description": "Hook-enabled pool bypasses the primary contract's ReentrancyGuard by re-entering a DIFFERENT endpoint (e.g., UniswapV4 PoolManager) — guard flag only set on primary entry, cross-pool drain",
    },
    "erc777-balance-diff-reentrancy-spoof-amount": {
        "keywords": ["erc777-balance-diff-reentrancy", "balance-diff-reentrancy-spoof",
                     "erc777-balance-diff-reentrancy-spoof-amount"],
        "applies_to": "both",
        "description": "TokenManager/bridge sizes received amount via pre/post balance diff; ERC777 sender hook reenters to deposit more mid-check, balance-diff over-counts received",
    },
    "reward-update-at-end-reentrancy": {
        "keywords": ["reward-update-at-end-reentrancy", "updateaccountrewards-reentrancy",
                     "reward-update-at-end-reentrancy"],
        "applies_to": "both",
        "description": "Redeem / exit fn calls `_updateAccountRewards` at the END; if reward token has transfer hook (ERC777-like), hook re-enters redeem with stale state",
    },
    "clob-order-erc777-reentrancy": {
        "keywords": ["clob-order-erc777-reentrancy", "lob-place-cancel-reentrancy",
                     "clob-order-erc777-reentrancy"],
        "applies_to": "both",
        "description": "CLOB / LOB placeOrder / cancelOrder transfers tokens before state update; ERC777 sender hook re-enters to manipulate order book",
    },
    "pending-withdrawal-amount-reset-by-view": {
        "keywords": ["pending-withdrawal-amount-reset", "view-fn-mutates-pending-withdrawal",
                     "pending-withdrawal-amount-reset-by-view"],
        "applies_to": "both",
        "description": "A getter / view-named fn resets `_pendingWithdrawalAmount` (or similar bookkeeping) — anyone calling it wipes pending withdrawals",
    },
    "buy-erc777-reentrancy-stale-reserve-price": {
        "keywords": ["buy-erc777-reentrancy-stale-price", "pair-buy-erc777-discount",
                     "buy-erc777-reentrancy-stale-reserve-price"],
        "applies_to": "both",
        "description": "Pair.buy / swap transfers ERC20 first then updates reserves; ERC777 hook re-enters buy to purchase at stale (pre-update) reserve price",
    },
    "session-sig-digest-missing-space-nonce": {
        "keywords": ["session-sig-digest-missing", "session-sig-replay-partial",
                     "session-sig-digest-missing-space-nonce"],
        "applies_to": "both",
        "description": "Session-key digest built from (calls, session_id) but NOT (space, nonce) — session consumed mid-flight can be replayed on a different branch",
    },
    "meta-tx-nonce-not-bumped-on-revert": {
        "keywords": ["meta-tx-nonce-not-bumped", "nonce-not-bumped-on-revert",
                     "meta-tx-nonce-not-bumped-on-revert"],
        "applies_to": "both",
        "description": "EIP712 meta-tx executes inner call and reverts entire tx on failure — nonce stays unchanged, signer's tx replayable when conditions change",
    },
    "cosigner-nonce-not-invalidated-on-role-swap": {
        "keywords": ["cosigner-nonce-role-swap", "role-swap-sig-replay",
                     "cosigner-nonce-not-invalidated-on-role-swap"],
        "applies_to": "both",
        "description": "Co-signer nonce namespace isolated from primary signer; role swap doesn't invalidate old sigs — replay against new role",
    },
    "bridge-execute-calldata-missing-chainid-replay": {
        "keywords": ["bridge-execute-calldata-chainid", "xcall-replay-across-chains",
                     "bridge-execute-calldata-missing-chainid-replay"],
        "applies_to": "both",
        "description": "Bridge execute derives tx hash from (id, origin, dest) omitting chain-id — relayer replays calldata on a second chain to double-spend",
    },
    "deployer-privileged-access-not-revoked": {
        "keywords": ["deployer-privileged-access", "deployer-role-not-revoked",
                     "deployer-privileged-access-not-revoked"],
        "applies_to": "both",
        "description": "Constructor grants deployer DEFAULT_ADMIN_ROLE for setup but post-launch revocation never happens — deployer retains unilateral privileges",
    },
    "timelock-bypassable-governor-direct-call": {
        "keywords": ["timelock-bypassable-governor", "governor-direct-call-bypass",
                     "timelock-bypassable-governor-direct-call"],
        "applies_to": "both",
        "description": "Target contract accepts calls from governor directly (in addition to timelock) — governor-admin can mutate config without the timelock delay",
    },
    "order-cancel-no-owner-check": {
        "keywords": ["order-cancel-no-owner-check", "cancel-order-missing-owner",
                     "order-cancel-no-owner-check"],
        "applies_to": "both",
        "description": "Order-cancel fn doesn't verify caller owns the referenced orderId — attacker cancels arbitrary orders (especially with orderId reuse)",
    },
    "cancel-order-closed-record-skips-collateral-refund": {
        "keywords": ["cancel-order-closed-skip-refund", "cancel-order-no-collateral-reconcile",
                     "cancel-order-closed-record-skips-collateral-refund"],
        "applies_to": "both",
        "description": "Cancel-order branch for 'Closed' / completed record path skips reconciliation of collateral locked mid-match — user gets free debt token",
    },
    "self-liquidation-reward-harvest": {
        "keywords": ["self-liquidation-reward-harvest", "self-liquidate-bounty-game",
                     "self-liquidation-reward-harvest"],
        "applies_to": "both",
        "description": "Attacker decreases own collateral below threshold then calls liquidate(self) to collect liquidation bounty — self-profitable",
    },
    "exit-short-collateral-not-returned": {
        "keywords": ["exit-short-collateral-not-returned", "close-position-collateral-stuck",
                     "exit-short-collateral-not-returned"],
        "applies_to": "both",
        "description": "ExitShort / close-position fn transfers payout but forgets to return the SR's own collateral to the shorter — funds stuck",
    },
    "rental-stop-no-caller-verification": {
        "keywords": ["rental-stop-no-caller-verification", "nft-rental-stop-unauth",
                     "rental-stop-no-caller-verification"],
        "applies_to": "both",
        "description": "NFT rental `stopRental` / `cancel_rental` doesn't verify caller is renter or lender — attacker stops active rentals and reclaims NFT",
    },
    "nft-burn-stale-owner-mapping": {
        "keywords": ["nft-burn-stale-owner-mapping", "burn-stale-owner-storage",
                     "nft-burn-stale-owner-mapping"],
        "applies_to": "both",
        "description": "Burn fn reads a stale owner-mapping that wasn't updated on transfer — previous owner can burn NFT owned by new owner",
    },
    "kzg-weak-fiat-shamir-challenge": {
        "keywords": ["kzg-weak-fiat-shamir", "fiat-shamir-transcript-incomplete",
                     "kzg-weak-fiat-shamir-challenge"],
        "applies_to": "both",
        "description": "Fiat-Shamir challenge derived from incomplete transcript (missing cell count / index / domain sep) — attacker remixes cells into a different claim with same challenge",
    },
    "merkle-proof-depth-not-enforced-forgery": {
        "keywords": ["merkle-proof-depth-not-enforced", "merkle-proof-length-forgery",
                     "merkle-proof-depth-not-enforced-forgery"],
        "applies_to": "both",
        "description": "verifyMerkleBranch accepts proofs of ANY depth without requiring depth == tree.depth — attacker passes shorter proof reconstructing valid root",
    },
    "prover-ordering-fetches-extra-chips": {
        "keywords": ["prover-ordering-extra-chips", "prover-supplied-ordering",
                     "prover-ordering-fetches-extra-chips"],
        "applies_to": "both",
        "description": "zkVM verifier uses prover-supplied chip_ordering to enumerate chips; prover excludes chips to skip constraint evaluation",
    },
    "zkvm-timestamp-field-modulus-overflow": {
        "keywords": ["zkvm-timestamp-field-overflow", "babybear-timestamp-overflow",
                     "zkvm-timestamp-field-modulus-overflow"],
        "applies_to": "both",
        "description": "zkVM timestamp represented in prime field (BabyBear/Goldilocks); after field-size steps it wraps to 0, invalid paths prove valid",
    },
    "bls-point-doubling-edge-case-forgery": {
        "keywords": ["bls-point-doubling-edge-case", "bls-doubling-identity-edge",
                     "bls-point-doubling-edge-case-forgery"],
        "applies_to": "both",
        "description": "BLS point-doubling circuit / impl doesn't handle P == -P (identity) — attacker crafts sig hitting this edge-case to forge",
    },
    "modular-inverse-of-zero-defined-as-zero": {
        "keywords": ["modular-inverse-of-zero", "fermat-inverse-zero",
                     "modular-inverse-of-zero-defined-as-zero"],
        "applies_to": "solidity_only",
        "description": "Fermat-based modular inverse `a^(p-2) mod p` silently returns 0 for input 0, breaking `inv * x == 1` invariants in Plonk/KZG/BLS verifiers (Solodit #26821 Linea Plonk Verifier)",
    },
    "narrow-uint-param-for-unbounded-id": {
        "keywords": ["narrow-uint-param-for-unbounded-id", "uint8-tokenid-param",
                     "narrow-uint-tokenid-abi-truncation"],
        "applies_to": "solidity_only",
        "tier": "B",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "description": "Public function declares narrow uint8/uint16 parameter for a token/NFT id while the contract mints against an unbounded counter — once the id passes the param's max (256 / 65536) the ABI truncates and those holders are permanently locked out of the function (Solodit #32188 AI Arena FighterFarm::reRoll)",
    },
    "bls-rogue-key-attack-no-pop": {
        "keywords": ["bls-rogue-key-attack", "bls-no-proof-of-possession",
                     "bls-rogue-key-attack-no-pop"],
        "applies_to": "both",
        "description": "BLS aggregation accepts pubkeys without a proof-of-possession — attacker registers rogue pubkey that lets aggregated sig verify under any set",
    },
    "aa-limit-module-bypass-via-executor-entrypoint": {
        "keywords": ["aa-limit-module-bypass", "native-token-limit-module-bypass",
                     "aa-limit-module-bypass-via-executor-entrypoint"],
        "applies_to": "both",
        "description": "ERC-4337 spend/limit module tracks native-token usage only inside validateUserOp; ERC-6900 executeFromExecutor() path bypasses that hook, limit is never enforced",
    },
    "aa-validation-bypass-via-sig-validation-fallback": {
        "keywords": ["aa-validation-bypass-sig-fallback",
                     "aa-validation-bypass-via-sig-validation-fallback"],
        "applies_to": "both",
        "description": "When a validation module has both userOp validation and signature validation enabled, attacker triggers the signature-validation path to skip pre-validation hooks",
    },
    "ecdsa-recover-zero-address-validation-bypass": {
        "keywords": ["ecdsa-recover-zero-address", "ecdsa-recover-zero-bypass",
                     "ecdsa-recover-zero-address-validation-bypass"],
        "applies_to": "both",
        "description": "_validateSignature uses ECDSA.recover() which returns address(0) on malformed sigs; if owner slot can be zero, any bogus sig validates",
    },
    "aa-resource-lock-validator-missing-scope-bind": {
        "keywords": ["resource-lock-validator-missing-scope",
                     "aa-resource-lock-missing-scope",
                     "aa-resource-lock-validator-missing-scope-bind"],
        "applies_to": "both",
        "description": "ResourceLockValidator.validateUserOp does not bind the locked-resource scope to the target call, attacker drains the wallet with a userOp outside the locked scope",
    },
    "aa-userop-hash-missing-entrypoint-replay": {
        "keywords": ["userop-hash-missing-entrypoint", "aa-userop-replay-entrypoint",
                     "aa-userop-hash-missing-entrypoint-replay"],
        "applies_to": "both",
        "description": "EIP-4337 userOpHash omits entryPoint address (and/or chainId) — userOp replayable across EntryPoint deployments or across chains",
    },
    "paymaster-refund-excludes-pubdata-gas": {
        "keywords": ["paymaster-refund-pubdata-gas", "paymaster-spent-on-pubdata-ignored",
                     "paymaster-refund-excludes-pubdata-gas"],
        "applies_to": "both",
        "description": "paymaster.postTransaction receives _maxRefundedGas that does not subtract spentOnPubdata — paymaster over-refunds the user, drain vector",
    },
    "restaking-strategy-cap-zero-skips-shares-queue-sync": {
        "keywords": ["strategy-cap-zero-skips-shares-queue",
                     "restaking-strategy-cap-zero-skips-shares-queue-sync"],
        "applies_to": "both",
        "description": "Setting a restaking strategy cap to 0 doesn't decrement totalShares or update the withdrawal queue — subsequent rebalance lets withdrawals exceed allocated amount",
    },
    "restaking-operator-self-undelegate-lrt-rate-manipulation": {
        "keywords": ["operator-self-undelegate-lrt",
                     "restaking-operator-self-undelegate-lrt-rate-manipulation"],
        "applies_to": "both",
        "description": "Malicious restaking operator calls undelegate on themselves in the EL DelegationManager, collapsing the LRT exchange rate and stranding user withdrawals",
    },
    "restaking-node-operator-withdraw-credentials-overwrite": {
        "keywords": ["node-operator-withdraw-credentials-overwrite",
                     "restaking-node-operator-withdraw-credentials-overwrite"],
        "applies_to": "both",
        "description": "When staking into EigenLayer, a malicious node operator overwrites the validator's withdrawCredentials to their own address to steal ETH on withdrawal",
    },
    "restaking-operator-heap-removed-id-stale-divzero": {
        "keywords": ["operator-heap-removed-id-stale",
                     "restaking-operator-heap-removed-id-stale-divzero"],
        "applies_to": "both",
        "description": "Operator heap stores IDs of removed operators; deposit/withdraw flow iterates and hits divide-by-zero / stale utilization on the zombie entry",
    },
    "upgrade-moved-storage-uninitialised-post-upgrade": {
        "keywords": ["moved-storage-uninitialised-post-upgrade",
                     "upgrade-moved-storage-uninitialised-post-upgrade"],
        "applies_to": "both",
        "description": "Storage variable moved to a new contract during upgrade can only be set by initialize(), which is already marked done — variable remains 0/zero and the invariant it guarded is gone",
    },
    "restaking-withdraw-dos-erc20-buffer-overflow": {
        "keywords": ["withdraw-dos-erc20-buffer-overflow",
                     "restaking-withdraw-dos-erc20-buffer-overflow"],
        "applies_to": "both",
        "description": "`completeQueuedWithdrawal` deposits into an ERC20 withdrawal buffer; once buffer cap is hit, every subsequent completion reverts — permanent DOS on exits",
    },
    "hook-addliquidity-attacker-chosen-poolkey": {
        "keywords": ["hook-addliquidity-attacker-poolkey",
                     "hook-addliquidity-attacker-chosen-poolkey"],
        "applies_to": "both",
        "description": "Uniswap V4 hook addLiquidity fn accepts a caller-supplied PoolKey without asserting it matches the canonical target — attacker feeds a pool they control to earn hook points / rewards",
    },
    "hook-native-token-settle-erc20-path": {
        "keywords": ["hook-native-token-settle-erc20",
                     "hook-native-token-settle-erc20-path"],
        "applies_to": "both",
        "description": "Hook settle/take uses IERC20 transfer path for Currency.isAddressZero() native-token pools — ETH flow reverts or strands funds",
    },
    "jit-penalty-bypass-per-position-salt": {
        "keywords": ["jit-penalty-bypass-salt",
                     "jit-penalty-bypass-per-position-salt"],
        "applies_to": "both",
        "description": "JIT-liquidity penalty hook keys on position `salt`; attacker splits deposit across multiple salts so each is individually 'fresh' and no penalty is charged",
    },
    "incentivized-erc20-recursive-liquidity-reward-amplification": {
        "keywords": ["incentivized-erc20-recursive-reward",
                     "incentivized-erc20-recursive-liquidity-reward-amplification"],
        "applies_to": "both",
        "description": "Yield-bearing reward token used as LP collateral lets attacker recursively stack rewards on the same underlying — claim amplifies beyond issued emissions",
    },
    "reward-hook-duplicate-pool-listed-token-steal": {
        "keywords": ["reward-hook-duplicate-pool-steal",
                     "reward-hook-duplicate-pool-listed-token-steal"],
        "applies_to": "both",
        "description": "Reward hook keys on (token0, token1) only; attacker deploys a duplicate pool with different fee / tickSpacing on the same listed token pair and siphons rewards intended for the canonical pool",
    },
    "v4-donate-sandwich-in-single-tx": {
        "keywords": ["v4-donate-sandwich",
                     "v4-donate-sandwich-in-single-tx"],
        "applies_to": "both",
        "description": "Uniswap V4 pool.donate() distributes fees proportionally to current in-range liquidity — MEV searcher sandwiches donate() in one tx (enter, receive, exit) to extract value",
    },
    "layerzero-toaddress-oversized-payload-dos": {
        "keywords": ["layerzero-toaddress-oversized",
                     "layerzero-toaddress-oversized-payload-dos"],
        "applies_to": "both",
        "description": "OFT sendFrom packs a caller-supplied _toAddress into the LZ payload with no length cap — attacker sends a huge _toAddress that blows past the dst-gas budget and bricks the LZ channel",
    },
    "layerzero-remote-transfer-caller-supplied-from-unauth-pull": {
        "keywords": ["layerzero-remote-transfer-caller-supplied-from",
                     "layerzero-remote-transfer-caller-supplied-from-unauth-pull"],
        "applies_to": "both",
        "description": "Remote-transfer entry point reads the `from` address from a caller-controlled parameter instead of the LayerZero-attested payload — attacker passes another user's address and drains their balance",
    },
    "layerzero-replay-skips-access-control": {
        "keywords": ["layerzero-replay-skip-access-control",
                     "layerzero-replay-skips-access-control"],
        "applies_to": "both",
        "description": "LayerZero retry / replay path calls `_receiveMessage` directly without re-running the access-control modifier that normally guards the entry point — replay becomes a privilege-escalation vector",
    },
    "stargate-mtoft-native-rebalance-sgrecieve-missing": {
        "keywords": ["stargate-mtoft-native-rebalance",
                     "stargate-mtoft-native-rebalance-sgrecieve-missing"],
        "applies_to": "both",
        "description": "Native-ETH rebalancing on mTOFT / Stargate transfers ETH to destination without calling sgReceive; funds sit unowned and can be swept by any caller of a no-auth wrap/donate path",
    },
    "nonblocking-lzapp-channel-block-via-receive-precheck-revert": {
        "keywords": ["nonblocking-lzapp-channel-block",
                     "nonblocking-lzapp-channel-block-via-receive-precheck-revert"],
        "applies_to": "both",
        "description": "NonblockingLzApp's _blockingLzReceive can revert on a pre-try internal check (e.g. ONFT invariant), escaping the try-catch and bricking the LZ channel",
    },
    "layerzero-payload-save-gas-grief-channel-block": {
        "keywords": ["layerzero-payload-save-gas-grief",
                     "layerzero-payload-save-gas-grief-channel-block"],
        "applies_to": "both",
        "description": "lzReceive stores failed payload into a dynamic mapping whose SSTORE cost scales with payload size — attacker sends an oversized payload consuming all gas during failure-save, bricking the channel",
    },
    "quorum-denominator-uses-cast-votes-not-total-supply": {
        "keywords": ["quorum-denominator-cast-votes",
                     "quorum-denominator-uses-cast-votes-not-total-supply"],
        "applies_to": "both",
        "description": "quorumReached compares forVotes against (forVotes+againstVotes+abstainVotes) instead of totalSupply — proposals pass with a fraction of intended supply participation",
    },
    "quorum-denominator-total-supply-vs-quadratic-sqrt-mismatch": {
        "keywords": ["quorum-quadratic-sqrt-mismatch",
                     "quorum-denominator-total-supply-vs-quadratic-sqrt-mismatch"],
        "applies_to": "both",
        "description": "Quadratic-voting strategy returns sqrt(balance) but quorum is still computed from totalSupply — cast votes are dwarfed, quorum is unreachable",
    },
    "ve-total-voting-power-equals-total-supply-inflation": {
        "keywords": ["ve-total-voting-power-total-supply",
                     "ve-total-voting-power-equals-total-supply-inflation"],
        "applies_to": "both",
        "description": "veToken getTotalVotingPower() returns totalSupply rather than the sum of locked-weighted voting power — inflation / mint path bloats denominator and dilutes active voters",
    },
    "governance-only-state-fn-exposed-as-public": {
        "keywords": ["governance-only-fn-exposed-public",
                     "governance-only-state-fn-exposed-as-public"],
        "applies_to": "both",
        "description": "State-mutating fn labelled 'governance-only' in the whitepaper is declared external/public without any onlyGovernance / onlyOwner gate — any caller can drive the mutation directly",
    },
    "vote-checkpoint-same-block-overwrite-missing": {
        "keywords": ["vote-checkpoint-same-block-overwrite",
                     "vote-checkpoint-same-block-overwrite-missing"],
        "applies_to": "both",
        "description": "ERC721Votes / Votes appends a new checkpoint on every interaction; multiple interactions in the same block/timestamp overwrite instead of being coalesced, breaking past-voting-power lookups",
    },
    "checkpoint-getat-block-ambiguous-read": {
        "keywords": ["checkpoint-getat-block-ambiguous-read",
                     "getPastVotes-no-finality-guard",
                     "getVotesAt-current-block",
                     "entries-getatblock-block"],
        "applies_to": "solidity_only",
        "description": "ERC20Votes/ERC721Votes getAt-style accessor (getPastVotes / getVotesAt / balanceOfAt / votingPowerAt) binary-searches the checkpoints array without a block-finality gate — no require(block.number > blockNumber), no BLOCK_FINALIZED / _validateBlock — so a same-block query can return a value whose checkpoint list is still mutable (flash-mint → self-delegate → Governor reads inflated value → burn). READ-side sibling of vote-checkpoint-same-block-multiple-entries (WRITE-side ordering) and checkpoint-same-block-ambiguity (WRITE-resolution) — this one is read-resolution ambiguity (Phase 33 novel-surfacer triangle entries-getatblock-block)",
    },
    "quorum-counts-against-abstain-instead-of-for-abstain": {
        "keywords": ["quorum-against-abstain-wrong-numerator",
                     "quorum-counts-against-abstain-instead-of-for-abstain"],
        "applies_to": "both",
        "description": "_quorumReached sums againstVotes + abstainVotes against the quorum threshold — quorum only reaches when against/abstain exceeds, inverting intent",
    },
    "erc721-mint-transfer-skips-safe-callback": {
        "keywords": ["erc721-mint-transfer-skips-safe",
                     "erc721-mint-transfer-skips-safe-callback"],
        "applies_to": "both",
        "description": "Mint/transfer path uses plain ERC721 instead of safeMint/safeTransferFrom — recipient's onERC721Received is never invoked, contract recipients cannot refuse and tokens may end up stuck",
    },
    "erc721-recover-uses-transfer-not-safetransfer-locks": {
        "keywords": ["erc721-recover-transfer-locks",
                     "erc721-recover-uses-transfer-not-safetransfer-locks"],
        "applies_to": "both",
        "description": "Admin recoverERC721 helper invokes ERC721.transfer (or any non-safe variant) to a contract recipient — unsupported by OZ ERC721, tokens end up permanently locked",
    },
    "safe-fallback-handler-setter-missing-address-guard": {
        "keywords": ["safe-fallback-handler-missing-address-guard",
                     "safe-fallback-handler-setter-missing-address-guard"],
        "applies_to": "both",
        "description": "Guarded Gnosis Safe permits setFallbackHandler without validating the incoming address — attacker-borrower sets fallback to their contract and hijacks NFT / 1155 callbacks",
    },
    "bridge-nft-burn-missing-owner-check": {
        "keywords": ["bridge-nft-burn-missing-owner-check",
                     "bridge-nft-burn-caller-not-owner"],
        "applies_to": "both",
        "description": "Cross-chain bridge burns a caller-supplied NFT id on their behalf without asserting caller owns that NFT — attacker specifies another user's id and steals payout",
    },
    "royalty-distribution-rounding-dust-siphon": {
        "keywords": ["royalty-distribution-rounding-dust",
                     "royalty-distribution-rounding-dust-siphon"],
        "applies_to": "both",
        "description": "Royalty distribution rounds each recipient's share independently; accumulated truncation dust stays in the contract and the last caller siphons it on the next payout",
    },
    "onerc721received-reentrancy-collateral-shares-manipulation": {
        "keywords": ["onerc721received-reentrancy-collateral",
                     "onerc721received-reentrancy-collateral-shares-manipulation"],
        "applies_to": "both",
        "description": "Vault's onERC721Received mutates collateral config shares and then calls safeTransferFrom — nested ERC721 callback reenters before shares are committed, attacker inflates/deflates config",
    },
    "stableswap-disjoint-multihop-breaks-invariant": {
        "keywords": ["stableswap-disjoint-multihop",
                     "stableswap-disjoint-multihop-breaks-invariant"],
        "applies_to": "both",
        "description": "Stableswap helper performs A→B and B→C as two disjoint swaps on the same pool, recomputing D between them — each swap's own invariant passes but the aggregate multihop breaks the invariant and leaks value",
    },
    "stableswap-missing-rate-multipliers-decimal-normalization": {
        "keywords": ["stableswap-missing-rate-multipliers",
                     "stableswap-missing-rate-multiplier-decimals",
                     "stableswap-missing-rate-multipliers-decimal-normalization"],
        "applies_to": "both",
        "description": "Stableswap D/invariant uses raw token balances without Curve-style rate_multipliers — assets with different decimals get wrong share pricing / unfair swap rates",
    },
    "cpmm-pool-creation-allows-n-gt-2-tokens-broken-math": {
        "keywords": ["cpmm-pool-creation-n-gt-2",
                     "cpmm-pool-creation-allows-n-gt-2-tokens-broken-math"],
        "applies_to": "both",
        "description": "Pool factory accepts n≥3 tokens for a constant-product pool whose math only supports n=2 — LPs deposit into structurally broken tri-crypto CPMM and cannot exit cleanly",
    },
    "liquidation-partial-settlement-leaves-zombie-debt": {
        "keywords": ["liquidation-partial-zombie-debt",
                     "liquidation-partial-settlement-leaves-zombie-debt"],
        "applies_to": "both",
        "description": "Liquidate partially settles debt from stability-pool deposits but never zeroes borrower.debt when pool is insufficient — borrower retains zombie debt while collateral is seized",
    },
    "cdp-borrow-repay-cycle-rate-inflate-grief": {
        "keywords": ["cdp-borrow-repay-cycle-inflate",
                     "cdp-borrow-repay-cycle-rate-inflate-grief"],
        "applies_to": "both",
        "description": "CDPVault borrow/repay each recompute utilization × rate factor without smoothing — attacker cycles tiny amounts to inflate accumulated rate for every other borrower",
    },
    "liquidation-atoken-burn-reserve-illiquidity-dos": {
        "keywords": ["liquidation-atoken-burn-reserve-illiquidity",
                     "liquidation-atoken-burn-reserve-illiquidity-dos"],
        "applies_to": "both",
        "description": "Liquidation burns aTokens against the collateral reserve; if reserve lacks liquidity the burn reverts, so an unhealthy position can't be liquidated and insolvency grows",
    },
    "chainlink-feed-updatedat-not-checked": {
        "keywords": ["chainlink-feed-updatedat-not-checked",
                     "chainlink-stale-feed-updatedat"],
        "applies_to": "both",
        "description": "Oracle reads `latestRoundData()` and uses the answer without validating `updatedAt` is recent — stale/frozen prices are consumed as current",
    },
    "chainlink-round-id-zero-not-checked": {
        "keywords": ["chainlink-round-id-zero-not-checked",
                     "round-id-zero-not-checked",
                     "roundId zero not checked",
                     "roundId uninitialized aggregator",
                     "latestRoundData roundId zero",
                     "answeredInRound roundId stale",
                     "BitKeep stale roundId oracle",
                     "aggregator proxy migration zero roundId"],
        "applies_to": "solidity_only",
        "description": "Chainlink consumer destructures `latestRoundData` and uses the answer without `require(roundId != 0)` or `roundId >= answeredInRound` — a fresh/migrating aggregator proxy returns a zero roundId and the consumer accepts the uninitialized answer as live price (BitKeep $8M 2022 class)",
    },
    "chainlink-negative-price-not-rejected-signed-cast": {
        "keywords": ["chainlink-negative-price-not-rejected",
                     "chainlink-negative-price-not-rejected-signed-cast"],
        "applies_to": "both",
        "description": "Oracle reads `int256` answer from Chainlink and casts to uint without `require(answer > 0)` — a feed returning negative rolls over to a huge uint, breaking pricing",
    },
    "single-dex-spot-reserves-flashloan-manipulable-oracle": {
        "keywords": ["single-dex-spot-reserves-flashloan",
                     "single-dex-spot-reserves-flashloan-manipulable-oracle"],
        "applies_to": "both",
        "description": "Price provider reads instantaneous reserves of a single DEX pool and uses them as an oracle — attacker flashloans, skews reserves, reads manipulated price, restores",
    },
    "curve-lp-virtual-price-read-only-reentrancy-oracle": {
        "keywords": ["curve-virtual-price-read-only-reentrancy",
                     "curve-lp-virtual-price-read-only-reentrancy-oracle"],
        "applies_to": "both",
        "description": "Oracle reads Curve pool's `get_virtual_price()` without an external-reentrancy guard; during `remove_liquidity`/`add_liquidity` the read returns an inflated value, causing unwarranted liquidations",
    },
    "lp-value-sum-of-balances-priced-flashloan-manipulable": {
        "keywords": ["lp-value-sum-of-balances-flashloan",
                     "lp-value-sum-of-balances-priced-flashloan-manipulable"],
        "applies_to": "both",
        "description": "LP token priced as `priceA*balanceA + priceB*balanceB` with instantaneous pool balances — attacker flashloans and skews balances to tamper the intra-tx LP price",
    },
    "lp-token-claim-redemption-ratio-spot-reserves-manipulable": {
        "keywords": ["lp-token-claim-spot-reserves",
                     "lp-token-claim-redemption-ratio-spot-reserves-manipulable"],
        "applies_to": "both",
        "description": "LP token claim is computed from current totalSupply / spot reserves — a flashloan-moved reserve inflates the claim, attacker borrows beyond collateral",
    },
    "erc20-approve-nonzero-to-nonzero-race-condition": {
        "keywords": ["erc20-approve-nonzero-race",
                     "erc20-approve-nonzero-to-nonzero-race-condition"],
        "applies_to": "both",
        "description": "approve(spender, nonZero) called while an older non-zero allowance still exists — attacker front-runs the tx to spend the old allowance then accepts the new allowance, double-spending",
    },
    "usdt-non-standard-return-missing-safetransfer": {
        "keywords": ["usdt-non-standard-return",
                     "usdt-non-standard-return-missing-safetransfer"],
        "applies_to": "both",
        "description": "Contract calls `IERC20(token).transferFrom` expecting a bool, but USDT and similar tokens return void — Solidity decodes empty return data and reverts, breaking transfers with legit tokens",
    },
    "token-deposit-no-balance-delta-fot-rebasing-drift": {
        "keywords": ["token-deposit-no-balance-delta",
                     "token-deposit-no-balance-delta-fot-rebasing-drift"],
        "applies_to": "both",
        "description": "Deposit records user-supplied amount instead of the `balanceOf(this)` delta after transferFrom — fee-on-transfer / deflationary / rebasing tokens cause internal accounting to drift from real balance",
    },
    "vault-share-balance-of-self-rebasing-steal": {
        "keywords": ["vault-share-balance-of-self-rebasing",
                     "vault-share-balance-of-self-rebasing-steal"],
        "applies_to": "both",
        "description": "Vault computes user share off `balanceOf(self)` which rebases silently — attacker deposits just before a positive rebase and withdraws right after, siphoning from existing depositors",
    },
    "usdt-nonzero-to-nonzero-approve-dos-grief": {
        "keywords": ["usdt-nonzero-approve-dos",
                     "usdt-nonzero-to-nonzero-approve-dos-grief"],
        "applies_to": "both",
        "description": "USDT reverts `approve(spender, nonZero)` when current allowance is non-zero; attacker sets a 1-wei allowance via the vault's approval path to permanently DOS every swap",
    },
    "erc20-no-revert-on-failure-return-value-ignored-shares-mint": {
        "keywords": ["erc20-no-revert-on-failure-return",
                     "erc20-no-revert-on-failure-return-value-ignored-shares-mint"],
        "applies_to": "both",
        "description": "Lender calls `token.transferFrom` without checking the returned bool; BNB / ZRX style tokens return false instead of reverting, attacker deposits nothing and mints shares",
    },
    "rewards-update-after-external-transfer-reentrancy-steal": {
        "keywords": ["rewards-update-after-external-transfer-reentrancy",
                     "rewards-update-after-external-transfer-reentrancy-steal"],
        "applies_to": "both",
        "description": "Redeem transfers tokens to user then calls _updateAccountRewards at the end — receive-hook reenters to double-claim rewards using pre-update share balance",
    },
    "nft-packet-open-reentrancy-duplicate-card-mint": {
        "keywords": ["nft-packet-open-reentrancy-duplicate",
                     "nft-packet-open-reentrancy-duplicate-card-mint"],
        "applies_to": "both",
        "description": "Packet.open burns the packet then mints reward NFTs via an external callback before committing the burn state — attacker reenters to open the same packet twice, duplicating cards",
    },
    "balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check": {
        "keywords": ["balancer-oracle-read-only-reentrancy",
                     "balancer-pair-oracle-read-only-reentrancy-no-vault-guard-check"],
        "applies_to": "both",
        "description": "Oracle reads BalancerVault.getPoolTokens without first calling Vault.manageUserBalance / checking the Vault reentrancy lock — during joinPool callback the read returns a stale snapshot and attacker premature-liquidates",
    },
    "deposit-balance-delta-no-reentrancy-guard-erc777-inflate": {
        "keywords": ["deposit-balance-delta-no-reentrancy",
                     "deposit-balance-delta-no-reentrancy-guard-erc777-inflate"],
        "applies_to": "both",
        "description": "Deposit measures balanceBefore/balanceAfter then mints shares, but has no reentrancy guard — ERC777 tokensReceived hook re-enters deposit to double-count the delta and mint extra shares",
    },
    "transient-eth-balance-relied-on-as-accounting-reentrancy-steal": {
        "keywords": ["transient-eth-balance-accounting-reentrancy",
                     "transient-eth-balance-relied-on-as-accounting-reentrancy-steal"],
        "applies_to": "both",
        "description": "Order fulfillment holds ETH in the contract mid-tx and uses `address(this).balance` for refund accounting — attacker's callback reenters a second trade, stealing the transient ETH",
    },
    "redeem-burn-before-transfer-erc777-hook-reenter-drain": {
        "keywords": ["redeem-burn-before-transfer-erc777-hook",
                     "redeem-burn-before-transfer-erc777-hook-reenter-drain"],
        "applies_to": "both",
        "description": "_redeem burns the stablecoin first then transfers ERC777 collateral; the ERC777 collateral-send hook re-enters _redeem with the pre-updated state and drains extra collateral",
    },
    "dex-swap-amountoutmin-zero-no-slippage": {
        "keywords": ["dex-swap-amountoutmin-zero",
                     "dex-swap-amountoutmin-zero-no-slippage"],
        "applies_to": "both",
        "description": "DEX wrapper calls router.swapExactTokensForTokens / exactInputSingle with amountOutMin = 0 — sandwich MEV extracts full slippage",
    },
    "reserve-sale-missing-amount-out-min-mev-sandwich": {
        "keywords": ["reserve-sale-missing-amount-out-min",
                     "reserve-sale-missing-amount-out-min-mev-sandwich"],
        "applies_to": "both",
        "description": "Reserve / treasury sells assets via DEX without setting amountOutMin — sandwich MEV extracts value from protocol liquidity",
    },
    "slippage-memory-var-not-propagated-unlimited": {
        "keywords": ["slippage-memory-var-not-propagated",
                     "slippage-memory-var-not-propagated-unlimited"],
        "applies_to": "both",
        "description": "Swap helper reads a memory `slippage` / `amountOutMin` that is never initialized / written before being passed to the router — effective slippage is 0 (unlimited), sandwich extracts full value",
    },
    "uniswap-swap-slippage-deadline-not-set": {
        "keywords": ["uniswap-swap-slippage-deadline-not-set",
                     "uniswap-swap-no-slippage-no-deadline"],
        "applies_to": "both",
        "description": "Code calls Uniswap V2/V3 swap with amountOutMinimum = 0 AND deadline = type(uint256).max — sandwich MEV extracts full value and tx can lie in the mempool indefinitely",
    },
    "lp-join-asymmetric-min-ratio-sandwich-overpay": {
        "keywords": ["lp-join-asymmetric-min-ratio-sandwich",
                     "lp-join-asymmetric-min-ratio-sandwich-overpay"],
        "applies_to": "both",
        "description": "LP join computes amountLP = min(token0In*supply/reserve0, token1In*supply/reserve1) without a pre-join price check — attacker sandwiches to skew reserves so one side wildly overpays",
    },
    "wsteth-steth-1to1-peg-assumption-overvalue": {
        "keywords": ["wsteth-steth-1to1-peg-assumption",
                     "wsteth-steth-1to1-peg-assumption-overvalue"],
        "applies_to": "both",
        "description": "LSD derivative prices wstETH as `stEthPerToken()` ETH-equivalent assuming stETH pegs 1:1 to ETH — during depegs the derivative overvalues the LSD, borrow-against-LSD exceeds real collateral value",
    },
    "concentrated-liquidity-deposit-tick-range-not-validated-against-vault": {
        "keywords": ["concentrated-liquidity-deposit-tick-range",
                     "concentrated-liquidity-deposit-tick-range-not-validated-against-vault"],
        "applies_to": "both",
        "description": "deposit_fixed / addLiquidity accepts caller-supplied tick_lower/tick_upper without asserting they fall within the vault's own concentration range — attacker opens a position outside the premium zone and collects premium",
    },
    "funding-rate-derived-from-partial-skew-applied-globally": {
        "keywords": ["funding-rate-partial-skew-applied-global",
                     "funding-rate-derived-from-partial-skew-applied-globally"],
        "applies_to": "both",
        "description": "Perp funding-fee rate is derived from oracle-maker skew only but applied to every trader market-wide — attacker creates extreme skew on the oracle maker for little cost, every other trader pays funding",
    },
    "tick-tracking-array-unbounded-growth-brick-mint-burn": {
        "keywords": ["tick-tracking-array-unbounded-growth",
                     "tick-tracking-array-unbounded-growth-brick-mint-burn"],
        "applies_to": "both",
        "description": "tickTracking / tickMapping array grows on every mint/burn without bounds — attacker spams empty ops to inflate its length, iteration runs out of gas and bricks all liquidity operations",
    },
    "swap-amount-not-reduced-after-price-clamp-lock-funds": {
        "keywords": ["swap-amount-not-reduced-after-price-clamp",
                     "swap-amount-not-reduced-after-price-clamp-lock-funds"],
        "applies_to": "both",
        "description": "swap() clamps price but does not reduce amountSpecified — user pays the full amount even though only a fraction of the trade executed, extra tokens stay locked in the pool",
    },
    "perp-liquidation-market-totals-updated-after-settle-partial-state": {
        "keywords": ["perp-liquidation-market-totals-partial-state",
                     "perp-liquidation-market-totals-updated-after-settle-partial-state"],
        "applies_to": "both",
        "description": "Liquidation updates market totals (open_interest, skew) AFTER settling position; if settle reverts on stale price / oracle issues, partial state mutation leaves market totals off-by-position",
    },
    "perp-vault-nav-uses-spot-not-mark-price-divergence": {
        "keywords": ["perp-vault-nav-spot-not-mark",
                     "perp-vault-nav-uses-spot-not-mark-price-divergence"],
        "applies_to": "both",
        "description": "Vault NAV for perp positions reads the oracle SPOT price instead of the perp's MARK price — NAV diverges from actual settlement during funding windows, redemption at stale NAV",
    },
    "sig-verify-message-hash-missing-nonce-replay": {
        "keywords": ["sig-verify-message-hash-missing-nonce",
                     "sig-verify-message-hash-missing-nonce-replay"],
        "applies_to": "both",
        "description": "Signed-message hash = hash(domain, payload) with no nonce — anyone can re-submit the same signature to re-drive the same state transition",
    },
    "user-supplied-domain-separator-cross-chain-replay": {
        "keywords": ["user-supplied-domain-separator",
                     "user-supplied-domain-separator-cross-chain-replay"],
        "applies_to": "both",
        "description": "Forwarder / meta-tx recovers signer from a hash that includes a caller-supplied domainSeparator — attacker passes another chain's domain to replay a sig there",
    },
    "chainid-cached-at-deploy-fork-replay": {
        "keywords": ["chainid-cached-at-deploy",
                     "chainid-cached-at-deploy-fork-replay"],
        "applies_to": "both",
        "description": "EIP-712 domain separator caches `chainId` at deployment; after a hard-fork the live chainId changes but the stored value stays — sigs replay across fork",
    },
    "batch-claim-no-used-flag-params-replay": {
        "keywords": ["batch-claim-no-used-flag",
                     "batch-claim-no-used-flag-params-replay"],
        "applies_to": "both",
        "description": "Batch claim / redeem accepts a params bundle and doesn't record successfully-used bundles — same params can be re-redeemed indefinitely",
    },
    "ecdsa-high-s-malleability-not-rejected": {
        "keywords": ["ecdsa-high-s-malleability",
                     "ecdsa-high-s-malleability-not-rejected"],
        "applies_to": "both",
        "description": "Signature verifier accepts ECDSA signatures with S > n/2 — EIP-2 rejects high-S to prevent malleability; a high-S sig variant slips past used-sig trackers that only log the normalized form",
    },
    "vulnerable-ecdsa-library-eip2098-malleable-version": {
        "keywords": ["vulnerable-ecdsa-library-eip2098",
                     "vulnerable-ecdsa-library-eip2098-malleable-version"],
        "applies_to": "both",
        "description": "Project uses OpenZeppelin ECDSA < 4.7.3 (or equivalent unfixed lib) with known EIP-2098 compact-sig malleability — attacker forges a second valid sig variant and replays",
    },
    "lz-oft-single-dvn-configuration-quorum-bypass": {
        "keywords": ["lz-oft-single-dvn-configuration-quorum-bypass",
                     "layerzero-single-dvn-quorum-bypass"],
        "applies_to": "both",
        "description": "LayerZero OApp config sets requiredDVNCount=1 and optionalDVNCount=0 (no quorum); a single compromised/malicious DVN attests arbitrary packets. Source: Kelp rsETH $220M exploit (2026-04-18).",
    },
    "oft-adapter-lzreceive-no-source-burn-proof": {
        "keywords": ["oft-adapter-lzreceive-no-source-burn-proof",
                     "oft-lzreceive-no-source-chain-proof"],
        "applies_to": "both",
        "description": "OFT adapter's lzReceive releases inventory purely on DVN attestation, without independent proof that the source-chain burn/debit actually occurred (light-client proof, source-nonce echo, etc.). Source: Kelp rsETH exploit.",
    },
    "bridge-receive-library-quorum-single-signer-is-sole-gate": {
        "keywords": ["bridge-receive-library-quorum-single-signer",
                     "bridge-receive-library-quorum-single-signer-is-sole-gate"],
        "applies_to": "both",
        "description": "Receive library verify() accepts a packet once required-DVN quorum is met; with required-DVN-count=1 the entire quorum is a single signature, no defense-in-depth. Source: Kelp rsETH exploit.",
    },
    "cross-chain-destination-accepts-out-of-sequence-inbound-nonce": {
        "keywords": ["cross-chain-destination-out-of-sequence-nonce",
                     "cross-chain-destination-accepts-out-of-sequence-inbound-nonce"],
        "applies_to": "both",
        "description": "Destination contract processes inboundNonce without sanity-checking that source.outboundNonce has advanced past it — attacker-attested out-of-sequence nonce (dst 308 while src still 307) slips through. Source: Kelp rsETH exploit.",
    },
    "oft-adapter-release-no-post-release-min-supply-cap": {
        "keywords": ["oft-adapter-release-no-post-release-cap",
                     "oft-adapter-release-no-post-release-min-supply-cap"],
        "applies_to": "both",
        "description": "OFT adapter's lzReceive dispatches from `balanceOf(adapter)` with no post-release invariant check (reserve floor, max-per-message cap). Allowed 116,500 rsETH drain in one message. Source: Kelp rsETH exploit.",
    },
    "dvn-admin-execute-unilateral-no-multisig-no-timelock": {
        "keywords": ["dvn-admin-execute-unilateral-no-multisig",
                     "dvn-admin-execute-unilateral-no-multisig-no-timelock"],
        "applies_to": "both",
        "description": "DVN contract's execute(attestation) is callable by a single admin EOA (no multisig, no timelock, no DVN-signer quorum). Compromise of that EOA = full bridge compromise. Source: Kelp rsETH exploit.",
    },
    "dvn-admin-role-grant-no-timelock-delay": {
        "keywords": ["dvn-admin-role-grant-no-timelock",
                     "dvn-admin-role-grant-no-timelock-delay"],
        "applies_to": "both",
        "description": "DVN grantRole(ADMIN_ROLE) is callable instantly by current admins with no timelock / multisig — Kelp DVN admin granted ADMIN_ROLE to 10 new EOAs 10 days pre-exploit. Source: Kelp rsETH exploit.",
    },
    "lz-oapp-configured-executor-advisory-not-enforced": {
        "keywords": ["lz-oapp-configured-executor-advisory",
                     "lz-oapp-configured-executor-advisory-not-enforced"],
        "applies_to": "both",
        "description": "LayerZero EndpointV2.lzReceive accepts any caller as executor once a packet is committed — the OApp-configured executor address is informational only, not an auth gate. Source: Kelp rsETH exploit.",
    },
    "bridge-pause-only-tokens-not-attestation-layer": {
        "keywords": ["bridge-pause-only-tokens",
                     "bridge-pause-only-tokens-not-attestation-layer"],
        "applies_to": "both",
        "description": "Emergency pause / sweep blocks token-level transfers but does NOT pause the OApp's verify/commitVerification path — attacker can still commit further attestations post-freeze. Source: Kelp rsETH exploit.",
    },
    "oft-adapter-inventory-vs-source-supply-divergence-unchecked": {
        "keywords": ["oft-adapter-inventory-vs-source-supply",
                     "oft-adapter-inventory-vs-source-supply-divergence-unchecked"],
        "applies_to": "both",
        "description": "OFT adapter never asserts that adapter locked balance + destination-minted supply matches canonical source-chain locked + distributed supply — global invariant violation undetected. Source: Kelp rsETH exploit.",
    },
    "oapp-config-safe-dvn-threshold-not-enforced-on-setconfig": {
        "keywords": ["oapp-config-safe-dvn-threshold",
                     "oapp-config-safe-dvn-threshold-not-enforced-on-setconfig"],
        "applies_to": "both",
        "description": "setConfig accepts a UlnConfig with requiredDVNCount < safe threshold (≥2) without any revert or event alarm — protocol lets a mis-configured single-DVN path stand. Source: Kelp rsETH exploit.",
    },
    "bridge-destination-adapter-ignores-source-pause-state": {
        "keywords": ["bridge-destination-adapter-ignores-source-pause",
                     "bridge-destination-adapter-ignores-source-pause-state"],
        "applies_to": "both",
        "description": "Destination adapter has no mechanism to observe source-chain pause state — once source is paused (compromise indicator), destination still accepts attestations. Source: Kelp rsETH exploit.",
    },
    "vesting-share-instant-pool-balance-pro-rata-steal": {
        "keywords": ["vesting-share-instant-pool-balance",
                     "vesting-share-instant-pool-balance-pro-rata-steal"],
        "applies_to": "both",
        "description": "Vesting wallet computes user share as shares*pool_balance/totalShares where pool_balance reads instant balance at withdraw — attacker deposits just before withdraw and siphons accrued bonus tokens pro-rata",
    },
    "vesting-revoke-freezes-already-vested-unclaimed": {
        "keywords": ["vesting-revoke-freezes-already-vested",
                     "vesting-revoke-freezes-already-vested-unclaimed"],
        "applies_to": "both",
        "description": "Admin revokeGrant zeros remaining allocation AND already-vested-but-unclaimed tokens — beneficiary loses what they had earned",
    },
    "vesting-update-overwrites-unsnapshotted-accrued-vested": {
        "keywords": ["vesting-update-overwrites-unsnapshotted",
                     "vesting-update-overwrites-unsnapshotted-accrued-vested"],
        "applies_to": "both",
        "description": "Updating a vesting claim (change amount/schedule) overwrites released/withdrawn counters without snapshotting the already-vested delta — user loses historical accrual",
    },
    "vesting-transfer-releaserate-uses-stale-step-count": {
        "keywords": ["vesting-transfer-releaserate-stale-step",
                     "vesting-transfer-releaserate-uses-stale-step-count"],
        "applies_to": "both",
        "description": "transferVesting recomputes grantor.releaseRate = totalAmount/N using the original step count N (not residual) — after partial transfer the grantor can unlock more than original lock",
    },
    "linear-vesting-reserve-missing-concurrent-instant-claim-drain": {
        "keywords": ["linear-vesting-reserve-concurrent-drain",
                     "linear-vesting-reserve-missing-concurrent-instant-claim-drain"],
        "applies_to": "both",
        "description": "Linear vesting checks balanceOf(this) >= amount_in at entry but doesn't reserve the output for scheduled unlock — concurrent instant-transmute drains the pool before linear users claim",
    },
    "orphan-privileged-setter-no-caller-path": {
        "keywords": ["orphan-privileged-setter",
                     "orphan-privileged-setter-no-caller-path"],
        "applies_to": "solidity_only",
        "description": "Privileged rotation setter (changeDAO/setOwner/rotateAdmin) is gated by only<Role> but the authorized caller contract has no function that routes to it — setter is unreachable, admin rotation permanently bricked (Solodit #3906 Vader changeDAO); assisted-review flag, reviewer must confirm reachability",
    },
    # Phase 37b: Polymarket Draft 3 (UmaCtfAdapter ignore-branch resolve brick)
    "resolve-transfer-without-balance-check-bricks": {
        "keywords": ["resolve-transfer-no-balance-check",
                     "resolve-transfer-without-balance-check-bricks",
                     "resolve-brick-zero-balance",
                     "ignore-branch-resolve-brick"],
        "applies_to": "solidity_only",
        "description": "External resolve/finalize/settle entrypoint performs ERC20 transfer without prior balance/zero-amount guard — drained-balance revert rolls back the entire resolve() call, bricking on-chain market resolution (Polymarket Draft 3, UmaCtfAdapter._resolve ignore-price branch)",
    },
    # Phase 37c: Polymarket Draft 7 (NegRiskAdapter MarketData.incrementQuestionCount packed-lane overflow)
    # Phase 48b: promoted to `both` — Rust sibling
    # r94_loop_packed_lane_increment_no_overflow_guard covers Anchor/Solana/
    # Soroban packed-account layouts with the same lane-saturation primitive.
    "packed-lane-increment-no-overflow-guard": {
        "keywords": ["packed-lane-increment-no-overflow-guard",
                     "packed-lane-overflow",
                     "packed-counter-overflow",
                     "lane-increment-no-cap",
                     "increment-question-count-overflow"],
        "applies_to": "both",
        "description": "Packed-lane bitmap counter is incremented (`slot += INCREMENT`, `<<=`, `slot[i]++`) on a Packed/Bitmap/MarketData/Registry-style contract without a `< type(uintN).max` lane-cap guard — at lane saturation the next call panics 0x11 on solc>=0.8 or silently carries into a neighbouring packed field on pre-0.8/unchecked code, permanently bricking the entry-point (Polymarket Draft 7, NegRiskAdapter MarketDataLib.incrementQuestionCount overflows at 256th prepareQuestion)",
    },
    # Phase 37c: Polymarket Draft 5 (NegRiskOperator unflag race, DELAY_PERIOD = 0)
    "flag-unflag-race-delay-period-zero": {
        "keywords": ["flag-unflag-race-delay-period-zero",
                     "flag-unflag-race",
                     "delay-period-zero",
                     "unflag-race-zero-delay",
                     "admin-preempt-race-zero-delay"],
        "applies_to": "solidity_only",
        "description": "Permissionless resolve/settle/finalize on an Operator/Resolver/Adapter/Oracle/Dispute/Safety contract is gated by an `isFlagged` / `flagged[qid]` guard but the contract declares `DELAY_PERIOD = 0` and the function enforces no `block.timestamp >= flaggedAt + DELAY` cooldown — admin's `unflagQuestion` opens a one-shot mempool window in which an MEV bundle can preempt admin's `emergencyResolveQuestion` and lock in the oracle outcome (Polymarket Draft 5, NegRiskOperator.resolveQuestion vs emergencyResolveQuestion)",
    },
    # Phase 37c: Polymarket Draft 4 (UmaCtfAdapter tie-payout cross-contract brick)
    "construct-payouts-no-tie-revert-sentinel": {
        "keywords": ["construct-payouts-no-tie-revert-sentinel",
                     "construct-payouts-no-sum-check",
                     "payout-vector-no-invariant-check"],
        "applies_to": "solidity_only",
        "tier": "B",
        "description": "External/public payouts producer (constructPayouts/computePayouts/finalizeOutcome/settleOutcome) writes the payout array and returns it without any local tie/sum/equal-leg sanity check — downstream CTF/NegRisk consumer enforcing sum==1 reverts on tied vectors, bricking resolution (Polymarket Draft 4, UmaCtfAdapter._constructPayouts → NegRiskOperator.reportPayouts)",
    },
    # Phase 37c: Polymarket Draft 9 (CTFExchange POLY_1271 path — EIP-7702 delegated-EOA forged orders)
    "eip1271-isvalidsignature-call-accepts-any-eoa-delegate-order": {
        "keywords": ["eip1271-isvalidsignature-accepts-eoa-delegate",
                     "eip1271-isvalidsignature-call-accepts-any-eoa-delegate-order",
                     "ctfexchange-poly1271-7702-forged-order",
                     "exchange-1271-no-delegate-allowlist"],
        "applies_to": "solidity_only",
        "tier": "B",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "source": "polymarket-draft-9",
        "description": "Exchange/order-matching entrypoint (fillOrder/matchOrders/_verifyPoly1271Signature) routes maker authentication through IERC1271(maker).isValidSignature without a 7702-delegate guard or trusted-validator allowlist — attacker installs a permissive 1271 delegate on their EOA via EIP-7702 set-code tx and forges orders for arbitrary makers (Polymarket Draft 9, forward-looking)",
    },
    # Phase 37c: Polymarket Drafts 1+2 (UmaCtfAdapter multi-hop refund-flag desync)
    # Write-side: callback calls _reset(..., false, ...) without setting refund=true.
    "reset-function-called-with-refund-false-from-callback": {
        "keywords": ["reset-function-called-with-refund-false-from-callback",
                     "reset-refund-false-callback",
                     "callback-reset-no-refund-flag",
                     "pricedisputed-reset-refund-false"],
        "applies_to": "solidity_only",
        "tier": "B",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "source": "polymarket-drafts-1-2",
        "description": "Permissionless oracle/dispute callback (priceDisputed/onDispute/priceSettled/onCallback) invokes internal _reset(..., false, ...) without explicitly setting questionData.refund=true — the resetRefund=false branch never flips the flag, so the downstream resolve path's flag-gated refund is silently skipped (Polymarket Drafts 1+2, UmaCtfAdapter.priceDisputed write-side; heuristic / MEDIUM confidence)",
    },
    # Phase 37d + 48b: Polymarket Cantina #173/#174 — Adapter redeems
    # fixed amount then sweeps full contract balance. Rust sibling
    # ports to Solana/Soroban offramp adapters.
    "collateral-sweep-without-pre-post-delta-check": {
        "keywords": ["collateral-sweep-without-pre-post-delta-check",
                     "collateral-sweep-no-delta",
                     "adapter-sweep-full-balance",
                     "redeem-sweep-balance-of-this",
                     "offramp-full-balance-skim"],
        "applies_to": "both",
        "description": "Adapter/Collateral wrapper redeems or converts a fixed-amount position then sweeps the FULL contract balance (`token.balanceOf(address(this))`) to the caller without computing a pre/post-call delta. Any stranded underlying is harvested by the next caller (Polymarket Cantina #173/#174, CtfCollateralAdapter.redeemPositions / NegRiskCtfCollateralAdapter.convertPositions)",
    },
    "event-attribution-loss-self-routed-callee": {
        "keywords": ["event-attribution-loss-self-routed-callee",
                     "event-attribution-loss-via-self-routed-call",
                     "self-routed-callee-event-topic",
                     "event-indexed-to-misattributed"],
        "applies_to": "solidity_only",
        "tier": "B",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "source": "polymarket-cantina-49",
        "description": "A function on an Adapter/Proxy/Collateral contract calls an external contract and passes address(this) as the recipient/_to argument, but the callee's event has that field as an indexed topic — the topic carries the proxy/adapter address instead of the originating user. Off-chain TVL/attribution indexers that join on the recipient topic see the adapter address, not the user. Sibling functions that pass msg.sender are correct; bug is asymmetric to split() (Polymarket CtfCollateralAdapter.splitPosition → CollateralToken.unwrap(_to: address(this)), Unwrapped event indexed to = adapter)",
    },

    # Phase 37b/c + 48b: Polymarket Drafts 6+8 — CollateralToken wrapper
    # custodies pUSD but ships no recoverERC20/sweep. Rust sibling
    # covers Solana/Soroban wrapper programs with the same gap.
    "no-admin-sweep-for-stuck-erc20": {
        "keywords": ["no-admin-sweep-for-stuck-erc20",
                     "no-admin-sweep-for-stuck",
                     "no-recover-erc20",
                     "no-rescue-tokens",
                     "missing-admin-sweep",
                     "wrapper-no-emergency-withdraw"],
        "applies_to": "both",
        "description": "Token wrapper / collateral-holder / vault has user-facing wrap/unwrap/redeem/release endpoints that custody an ERC20/SPL underlying, but ships no admin-gated sweep / rescue / recoverERC20 / emergencyWithdraw path. Any token mistakenly sent to the contract is permanently stuck (Polymarket Drafts 6+8, CollateralToken pUSD wrapper)",
    },
    # Phase 37c: Polymarket Drafts 1+2 read-side complement.
    "resolve-gated-on-flag-that-callback-path-never-sets": {
        "keywords": ["resolve-gated-on-flag-that-callback-path-never-sets",
                     "resolve-flag-gate-no-local-write",
                     "resolvemanually-refund-flag-gate",
                     "finalize-flag-gate-not-set-locally"],
        "applies_to": "solidity_only",
        "tier": "B",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "source": "polymarket-drafts-1-2",
        "description": "External resolve/resolveManually/finalize/settle entrypoint gates a refund (or analogous remediation) on questionData.refund but never writes that flag locally — desync with any upstream callback path that fails to flip refund=true silently skips the refund (Polymarket Drafts 1+2, UmaCtfAdapter.resolveManually read-side; heuristic / MEDIUM confidence)",
    },
    # Phase 81: PR #85 patterns — SKILL_ISSUE #223 + gap-closing patterns
    "init-reinitializable": {
        "keywords": ["init-reinitializable", "unprotected-init", "initialize-no-guard",
                     "reinitialize-missing", "initializer-missing", "init-no-access-control"],
        "applies_to": "solidity_only",
        "tier": "D",
        "severity": "HIGH",
        "confidence": "HIGH",
        "source": "auditooor-SKILL-223",
        "description": "init()/initialize() is external/public with no initializer/reinitializer modifier and no already-initialized guard — anyone can re-initialize and steal funds or replace logic",
    },
    "forced-liquidation-via-withdrawal-queue": {
        "keywords": ["forced-liquidation", "withdrawal-queue-liquidation", "queue-manipulation-liquidation",
                     "requestwithdraw-liquidation", "withdrawal-queue-forced"],
        "applies_to": "solidity_only",
        "tier": "D",
        "severity": "HIGH",
        "confidence": "HIGH",
        "source": "auditooor-SKILL-223",
        "description": "Withdrawal queue manipulation (requestWithdraw/addToWithdrawalQueue without adequate balance check) enables forced liquidation of other users",
    },
    "yield-manager-valuation-manipulation": {
        "keywords": ["yield-manager-valuation", "valuation-manipulation", "totalassets-manipulation",
                     "share-price-oracle-manipulation", "yield-valuation"],
        "applies_to": "solidity_only",
        "tier": "D",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "source": "auditooor-SKILL-223",
        "description": "Yield manager backing asset valuation is manipulable via oracle timing or flash loans — totalAssets/convertToShares uses a manipulable price source",
    },
    "division-to-zero-solvency": {
        "keywords": ["division-to-zero", "division-by-zero-solvency", "zero-denominator-solvency",
                     "phantom-shares", "insolvency-division", "divide-zero-denominator"],
        "applies_to": "solidity_only",
        "tier": "D",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "source": "auditooor-SKILL-223",
        "description": "Division by a user-controlled or manipulable denominator (totalAssets/totalSupply) without zero guard causes revert lock or phantom share insolvency",
    },
    "missing-two-step-ownership-transfer": {
        "keywords": ["missing-two-step-ownership", "two-step-transfer-missing", "ownable-no-2step",
                     "single-step-ownership-transfer", "ownership-lockout", "no-accept-ownership"],
        "applies_to": "solidity_only",
        "tier": "D",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "source": "kiln-v1",
        "description": "Ownable contract uses single-step transferOwnership without Ownable2Step propose/accept pattern — wrong address causes permanent admin lockout",
    },
    "privileged-function-missing-onlyowner": {
        "keywords": ["privileged-function-missing-onlyowner", "emergencywithdraw-no-owner",
                     "admin-function-no-access-control", "privileged-missing-modifier",
                     "unguarded-admin-function", "missing-onlyowner"],
        "applies_to": "solidity_only",
        "tier": "E",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "source": "solodit-Zokyo-ArGo",
        "description": "Privileged administrative function (emergencyWithdraw, set*, update*, pause) lacks access-control modifier despite contract defining onlyOwner/onlyAdmin elsewhere",
    },
    "operator-management-missing-access-control": {
        "keywords": ["operator-management-missing-access-control", "addoperator-no-owner",
                     "removerole-no-guard", "operator-role-missing-modifier",
                     "grantrole-no-access", "role-management-unguarded"],
        "applies_to": "solidity_only",
        "tier": "E",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "source": "solodit-Zokyo-EqiFi",
        "description": "Operator/role management functions (addOperator, removeOperator, grantRole, revokeRole) lack access-control modifiers despite contract defining such modifiers",
    },
}


def classify(name: str) -> list[str]:
    """Return list of bug_class keys that this name/file matches."""
    name_low = name.lower().replace("_", "-")
    matches = []
    for cls, meta in BUG_CLASSES.items():
        for kw in meta["keywords"]:
            if kw in name_low:
                matches.append(cls)
                break
    return matches or ["unclassified"]


def load_solidity_patterns() -> list[tuple[str, Path]]:
    """Return (pattern-slug, path) for every active Solidity pattern."""
    out = []
    for p in sorted(SOL_PATTERNS.glob("*.yaml")):
        slug = p.stem
        out.append((slug, p))
    return out


def load_rust_detectors() -> list[tuple[str, Path]]:
    """Return (detector-slug, path) for every active Rust detector."""
    out = []
    for p in sorted(RUST_DETECTORS.glob("*.py")):
        if p.name.startswith("_"):
            continue  # skip _util.py
        slug = p.stem
        out.append((slug, p))
    return out


def build_parity_map() -> dict:
    sol = load_solidity_patterns()
    rust = load_rust_detectors()

    sol_by_class = defaultdict(list)
    rust_by_class = defaultdict(list)

    for slug, _ in sol:
        for cls in classify(slug):
            sol_by_class[cls].append(slug)
    for slug, _ in rust:
        for cls in classify(slug):
            rust_by_class[cls].append(slug)

    all_classes = sorted(set(sol_by_class) | set(rust_by_class) | set(BUG_CLASSES))

    rows = []
    for cls in all_classes:
        meta = BUG_CLASSES.get(cls, {})
        applies = meta.get("applies_to", "both")
        sol_count = len(sol_by_class.get(cls, []))
        rust_count = len(rust_by_class.get(cls, []))
        # Item-#6 burn-down: `deliberate` discriminator. For
        # `applies_to: both` rows the field is meaningless (always False —
        # any one-sided coverage is a real gap). For `solidity_only` /
        # `rust_only` rows the field defaults to `True` because the
        # platform-only declaration itself is an intentional design choice;
        # set `deliberate: False` explicitly only when a platform-only row
        # is suspect (e.g. mistakenly tagged single-platform when a sibling
        # detector should exist). `tools/detector-lint.py` Check 5 honours
        # this discriminator.
        if applies == "both":
            deliberate = False
        else:
            deliberate = bool(meta.get("deliberate", True))
        row = {
            "bug_class": cls,
            "applies_to": applies,
            "solidity_count": sol_count,
            "rust_count": rust_count,
            "deliberate": deliberate,
            "rationale": meta.get("rationale", ""),
            "description": meta.get("description", "(not in registry)"),
        }
        # Parity status
        if applies == "both":
            if sol_count > 0 and rust_count > 0:
                row["status"] = "COVERED_BOTH"
            elif sol_count > 0 and rust_count == 0:
                row["status"] = "GAP_RUST"  # port Solidity→Rust
            elif rust_count > 0 and sol_count == 0:
                row["status"] = "GAP_SOLIDITY"  # port Rust→Solidity
            else:
                row["status"] = "UNCOVERED_BOTH"
        elif applies == "solidity_only":
            row["status"] = "PLATFORM_ONLY_SOL" if sol_count > 0 else "PLATFORM_ONLY_SOL_UNCOVERED"
        elif applies == "rust_only":
            row["status"] = "PLATFORM_ONLY_RUST" if rust_count > 0 else "PLATFORM_ONLY_RUST_UNCOVERED"
        else:
            row["status"] = "UNKNOWN"
        rows.append(row)

    # Parity %:
    both_classes = [r for r in rows if r["applies_to"] == "both"]
    covered_both = [r for r in both_classes if r["status"] == "COVERED_BOTH"]
    parity_pct = (len(covered_both) / len(both_classes) * 100) if both_classes else 0.0

    # Item-#6 burn-down: split platform-only rows into deliberate vs suspect.
    platform_only_rows = [
        r for r in rows if r["status"].startswith("PLATFORM_ONLY")
    ]
    platform_only_deliberate = [r for r in platform_only_rows if r["deliberate"]]
    platform_only_suspect = [r for r in platform_only_rows if not r["deliberate"]]
    real_gap_rows = [
        r for r in rows if r["status"] in ("GAP_RUST", "GAP_SOLIDITY")
    ]

    return {
        "solidity_total": len(sol),
        "rust_total": len(rust),
        "bug_classes_registered": len(BUG_CLASSES),
        "bug_classes_applicable_to_both": len(both_classes),
        "bug_classes_covered_both": len(covered_both),
        "parity_pct_bidirectional": round(parity_pct, 2),
        # Item-#6 burn-down summary fields
        "platform_only_total": len(platform_only_rows),
        "platform_only_deliberate": len(platform_only_deliberate),
        "platform_only_suspect": len(platform_only_suspect),
        "real_gap_count": len(real_gap_rows),
        "rows": rows,
    }


def emit_markdown(report: dict) -> str:
    lines = []
    lines.append("# Solidity↔Rust parity report")
    lines.append("")
    lines.append(f"- **Solidity active patterns:** {report['solidity_total']}")
    lines.append(f"- **Rust active detectors:** {report['rust_total']}")
    lines.append(f"- **Bug classes registered:** {report['bug_classes_registered']}")
    lines.append(f"- **Classes applicable to both:** {report['bug_classes_applicable_to_both']}")
    lines.append(f"- **Classes covered on both sides:** {report['bug_classes_covered_both']}")
    lines.append(f"- **Bidirectional parity:** **{report['parity_pct_bidirectional']}%**")
    lines.append(f"- **Real gaps (forward/reverse port targets):** {report.get('real_gap_count', 0)}")
    lines.append(f"- **Platform-only (deliberate):** {report.get('platform_only_deliberate', 0)}")
    lines.append(f"- **Platform-only (suspect / un-rationalized):** {report.get('platform_only_suspect', 0)}")
    lines.append("")
    lines.append("## Bug-class coverage matrix")
    lines.append("")
    lines.append("| bug class | applies | Solidity | Rust | status |")
    lines.append("|---|---|---:|---:|---|")
    for r in report["rows"]:
        lines.append(f"| `{r['bug_class']}` | {r['applies_to']} | {r['solidity_count']} | {r['rust_count']} | {r['status']} |")
    lines.append("")
    lines.append("## Gaps (port targets)")
    lines.append("")
    lines.append("### GAP_RUST — Solidity has coverage, Rust doesn't (forward-port targets)")
    lines.append("")
    for r in report["rows"]:
        if r["status"] == "GAP_RUST":
            lines.append(f"- `{r['bug_class']}` — {r['description']} (Solidity: {r['solidity_count']})")
    lines.append("")
    lines.append("### GAP_SOLIDITY — Rust has coverage, Solidity doesn't (reverse-port targets)")
    lines.append("")
    for r in report["rows"]:
        if r["status"] == "GAP_SOLIDITY":
            lines.append(f"- `{r['bug_class']}` — {r['description']} (Rust: {r['rust_count']})")
    lines.append("")
    lines.append("### UNCOVERED_BOTH — no detector on either side")
    lines.append("")
    for r in report["rows"]:
        if r["status"] == "UNCOVERED_BOTH":
            lines.append(f"- `{r['bug_class']}` — {r['description']}")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", action="store_true", help="Emit JSON to stdout")
    ap.add_argument("--gap-only", action="store_true", help="Print only the gap list")
    ap.add_argument("--out", type=Path, help="Write markdown to path")
    args = ap.parse_args()

    report = build_parity_map()

    if args.json:
        print(json.dumps(report, indent=2))
        return 0
    if args.gap_only:
        for r in report["rows"]:
            if r["status"].startswith("GAP_"):
                print(f"{r['status']:15} {r['bug_class']:25} sol={r['solidity_count']:3} rust={r['rust_count']:3}")
        return 0

    md = emit_markdown(report)
    if args.out:
        args.out.write_text(md)
        print(f"[parity] wrote {args.out}")
    else:
        print(md)
    print(f"\n[parity] bidirectional={report['parity_pct_bidirectional']}%  "
          f"covered_both={report['bug_classes_covered_both']}/"
          f"{report['bug_classes_applicable_to_both']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
