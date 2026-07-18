#!/usr/bin/env python3
"""Curated Substrate + CosmWasm + FROST attack-class corpus -> hackerman_record v1 YAML.

Wave-4 / TIER-D Rust Tier-2 ETL. Sibling to:
  - tools/hackerman-etl-from-prior-audits.py          (PDF / text scan)
  - tools/hackerman-etl-from-solidity-fork-patterns.py (markdown + DSL)
  - tools/hackerman-etl-from-aptos-move.py            (Aptos Move)
  - tools/hackerman-etl-from-sui-move.py              (Sui Move object model)
  - tools/hackerman-etl-from-starknet-cairo.py        (StarkNet Cairo)
  - tools/hackerman-etl-from-vyper-cve.py             (Vyper CVE family)

Why a curated corpus, not a scanner? The Rust Tier-2 ecosystems (Substrate /
FRAME / Polkadot-SDK, CosmWasm, FROST / threshold-sig) have small public-
audit-text corpora today; their attack surface is best captured as canonical
attack-class entries with explicit external citations to the audit
literature. The corpus is normative and reproducible: every record is built
from this file's KNOWLEDGE constants -- no filesystem inputs required.

Schema-fit notes:
  * target_language enum (schema) = {solidity, go, rust, ...}; "rust" is the
    only Rust-family value. Substrate/CosmWasm/FROST are encoded by:
      - target_domain  (consensus / governance / staking / oracle / ...)
      - shape_tags     (prefix "substrate-", "cosmwasm-", "frost-" so
                       downstream consumers can filter by framework)
      - attack_class   (verbatim per the task brief, e.g.
                       "pallet-storage-overflow", "frost-share-recovery-bypass")
  * target_repo is the canonical upstream slug for each ecosystem
    (paritytech/polkadot-sdk, CosmWasm/cosmwasm, ZcashFoundation/frost, ...);
    when a finding is generic across the ecosystem, repo = "unknown" and the
    framework prefix on shape_tags carries the identity.

Each KNOWLEDGE row is one canonical attack class. The ETL fans out per
(audit-source x attack-class) into one record, with an external-citation
source_audit_ref that the validator accepts as `[A-Za-z0-9._:/-]`.

External sources cited (public reports the framing of records is grounded in):
  - SR Labs Polkadot audit series (2019-2024)
  - Zellic Cosmos / CosmWasm reports (Osmosis, Mars Protocol, ...)
  - Trail of Bits CosmWasm/Rust audits (Terra, Astroport, Neutron, ...)
  - Informal Systems audits (Cosmos SDK, IBC, dYdX cosmos-app, ...)
  - Oak Security CosmWasm reports (Mars, Stride, Quasar, ...)
  - Lightspark FROST audits (Spark statechain operator)
  - ZcashFoundation FROST RFCs + audit memos (Schorr threshold sigs)
  - Spark prior-audit-PDFs for statechain FROST/DKG seams

Usage:
  python3 tools/hackerman-etl-from-substrate-cosmwasm-frost.py \
      --out-dir /tmp/exec_w4rs_records --dry-run --json-summary
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "auditooor.hackerman_record.v1"
DEFAULT_LANGUAGE = "rust"
SUMMARY_SCHEMA = "auditooor.hackerman_etl_substrate_cosmwasm_frost_summary.v1"


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_substrate_cosmwasm_frost",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# --------------------------------------------------------------------------
# Curated knowledge corpus.
#
# Each entry is a (framework, attack_class) anchor. Sources are public-facing
# audit reports / specs / RFCs; the ETL emits one hackerman_record per
# (anchor x source) pair so downstream consumers see the multi-source
# overlap explicitly.
# --------------------------------------------------------------------------


# Framework -> (target_domain default, target_repo default, language, prefix).
FRAMEWORK_PROFILES: Dict[str, Dict[str, str]] = {
    "substrate": {
        "domain": "consensus",
        "repo": "paritytech/polkadot-sdk",
        "language": "rust",
        "prefix": "substrate-",
    },
    "cosmwasm": {
        "domain": "consensus",
        "repo": "CosmWasm/cosmwasm",
        "language": "rust",
        "prefix": "cosmwasm-",
    },
    "frost": {
        "domain": "consensus",
        "repo": "ZcashFoundation/frost",
        "language": "rust",
        "prefix": "frost-",
    },
}


# Per-attack-class metadata. Keys must be stable; downstream tooling cites
# the attack_class verbatim. domain_override / repo_override fine-tune the
# default framework profile for individual classes.
@dataclass(frozen=True)
class AttackClass:
    framework: str
    attack_class: str
    bug_class: str
    title: str
    component: str
    raw_signature: str
    domain: str
    impact_class: str
    impact_actor: str
    impact_dollar_class: str
    attacker_role: str
    severity: str
    repo_override: Optional[str]
    attacker_action_sequence: str
    required_preconditions: Tuple[str, ...]
    fix_pattern: str
    fix_anti_pattern_avoided: str
    extra_shape_tags: Tuple[str, ...]


ATTACK_CLASSES: Tuple[AttackClass, ...] = (
    # --------------------- Substrate / FRAME / Polkadot-SDK ---------------
    AttackClass(
        framework="substrate",
        attack_class="pallet-storage-overflow",
        bug_class="accounting",
        title="FRAME pallet storage map overflow via unbounded user-controlled key insertion",
        component="frame_support::storage::StorageMap::insert",
        raw_signature="fn insert<K: EncodeLike<KeyArg>, V: EncodeLike<ValueArg>>(key: K, val: V)",
        domain="consensus",
        impact_class="dos",
        impact_actor="validator-set",
        impact_dollar_class="$100K-$1M",
        attacker_role="unprivileged",
        severity="high",
        repo_override=None,
        attacker_action_sequence=(
            "Attacker submits a stream of cheap extrinsics each inserting a new "
            "StorageMap entry whose hashed key is attacker-chosen, bloating the "
            "pallet's trie until block-execution weight exceeds the runtime weight "
            "budget and block production stalls."
        ),
        required_preconditions=(
            "Pallet exposes a public Call that inserts into StorageMap without a per-account bound",
            "Per-insertion weight is mispriced relative to trie growth cost",
            "No deposit / slashing pressure on the inserting account",
        ),
        fix_pattern=(
            "Bound StorageMap inserts by an explicit MaxEntries const, charge a "
            "refundable deposit per entry, and replace blake2_128_concat with a "
            "non-pre-image-friendly hasher only after auditing collision risk."
        ),
        fix_anti_pattern_avoided=(
            "trusting blake2_128_concat to bound trie depth without an explicit cap"
        ),
        extra_shape_tags=("frame-pallet", "storage-map"),
    ),
    AttackClass(
        framework="substrate",
        attack_class="runtime-upgrade-mid-block",
        bug_class="upgrade-safety",
        title="Runtime upgrade applied mid-block produces inconsistent state between ParentApi and ChildApi",
        component="frame_executive::Executive::execute_block_no_check",
        raw_signature="fn execute_block(block: Block)",
        domain="consensus",
        impact_class="dos",
        impact_actor="validator-set",
        impact_dollar_class=">=$1M",
        attacker_role="governance",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Governance scheduler activates a runtime upgrade in the same block that "
            "contains a long-running extrinsic; the post-upgrade decode path reads "
            "pre-upgrade SCALE-encoded storage values and panics, halting finalisation."
        ),
        required_preconditions=(
            "set_code / system::set_code scheduled to land in the same block as user txs",
            "Storage migration not gated behind on_runtime_upgrade idempotency check",
            "Old types still referenced by extrinsics in the same block",
        ),
        fix_pattern=(
            "Reserve set_code blocks (no other txs in the same block) and gate every "
            "migration behind StorageVersion::get() == OLD with explicit pre/post checks."
        ),
        fix_anti_pattern_avoided=(
            "scheduling set_code with user extrinsics in the same block on the trust "
            "that on_runtime_upgrade runs first"
        ),
        extra_shape_tags=("frame-executive", "set-code"),
    ),
    AttackClass(
        framework="substrate",
        attack_class="weight-mispricing-block-overflow",
        bug_class="dos-griefing",
        title="Weight mispricing on extrinsic lets attacker fill block past block weight limit",
        component="pallet::dispatch::Pays::Yes",
        raw_signature="#[pallet::weight(T::WeightInfo::do_something())] pub fn do_something(...)",
        domain="consensus",
        impact_class="dos",
        impact_actor="validator-set",
        impact_dollar_class="$100K-$1M",
        attacker_role="unprivileged",
        severity="high",
        repo_override=None,
        attacker_action_sequence=(
            "Attacker submits an extrinsic whose declared weight is far below actual "
            "execution cost; mempool admits N copies, validators include them, and "
            "block production exceeds the per-block weight limit."
        ),
        required_preconditions=(
            "WeightInfo derived from a benchmark missing the worst-case storage path",
            "Pays::Yes with constant fee unrelated to actual CPU work",
            "No on_initialize gas accounting reconciliation",
        ),
        fix_pattern=(
            "Re-benchmark with proof-size and ref-time both modelled at the loop-max "
            "branch; reject the extrinsic in pre_dispatch if measured weight diverges."
        ),
        fix_anti_pattern_avoided=(
            "using a happy-path benchmark for an extrinsic that branches on user input"
        ),
        extra_shape_tags=("frame-pallet", "weight-info"),
    ),
    AttackClass(
        framework="substrate",
        attack_class="dispatchable-permission-bypass",
        bug_class="access-control",
        title="Dispatchable missing ensure_root / ensure_signed-by-origin permission check",
        component="pallet::Call::sudo_unchecked_weight",
        raw_signature="pub fn admin_action(origin: OriginFor<T>, payload: Payload) -> DispatchResult",
        domain="governance",
        impact_class="privilege-escalation",
        impact_actor="protocol-treasury",
        impact_dollar_class=">=$1M",
        attacker_role="unprivileged",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Attacker calls a dispatchable that should be ensure_root / ensure_signed "
            "by a known origin but only ensure_signed(origin); attacker spoofs the "
            "origin and executes admin action."
        ),
        required_preconditions=(
            "Dispatchable mutates privileged storage (Members, Council, treasury)",
            "Origin check uses ensure_signed instead of ensure_root or named ensure_member",
            "No additional signature check on payload",
        ),
        fix_pattern=(
            "Replace ensure_signed(origin) with EnsureRoot::ensure_origin or a "
            "RawOrigin variant matched to the explicit governance body."
        ),
        fix_anti_pattern_avoided=(
            "assuming a Signed origin implies authorisation"
        ),
        extra_shape_tags=("frame-pallet", "ensure-origin"),
    ),
    AttackClass(
        framework="substrate",
        attack_class="parachain-validation-block-replay",
        bug_class="signature-replay",
        title="Parachain validation block (PoV) lacks relay-chain nonce binding and is replayable across para_id",
        component="cumulus_pallet_parachain_system::set_validation_data",
        raw_signature="fn set_validation_data(data: ParachainInherentData)",
        domain="rollup",
        impact_class="theft",
        impact_actor="depositor-class",
        impact_dollar_class=">=$1M",
        attacker_role="block-proposer",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Malicious collator captures a validated PoV from another parachain "
            "running the same runtime; replays it as own parachain's validation "
            "data because the PoV hash is not bound to para_id in the validator's "
            "verification path."
        ),
        required_preconditions=(
            "Collator can craft validation data for a target para_id without proving uniqueness",
            "Relay-chain validators verify PoV without checking para_id == declared",
            "Same runtime hash across multiple parachains",
        ),
        fix_pattern=(
            "Domain-separate PoV hashing with (para_id, relay_parent_number); reject "
            "validation data whose binding does not match the relay-chain claim."
        ),
        fix_anti_pattern_avoided=(
            "hashing only the state-transition payload without the (para_id, slot) domain"
        ),
        extra_shape_tags=("cumulus", "parachain-system"),
    ),
    AttackClass(
        framework="substrate",
        attack_class="xcm-message-replay",
        bug_class="signature-replay",
        title="XCM message replay across para-blocks due to missing topic_id uniqueness check",
        component="pallet_xcm::execute",
        raw_signature="fn execute(origin: OriginFor<T>, message: Box<VersionedXcm<RuntimeCall>>, max_weight: Weight)",
        domain="bridge",
        impact_class="theft",
        impact_actor="depositor-class",
        impact_dollar_class=">=$1M",
        attacker_role="unprivileged",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Attacker observes a successful WithdrawAsset XCM message destined to a "
            "sister parachain; resubmits the exact same VersionedXcm on the destination "
            "chain because pallet_xcm uses topic_id but never marks it consumed."
        ),
        required_preconditions=(
            "Destination chain accepts XCM without persisting (origin, topic_id) tuple",
            "XCM message authorises asset transfer with no per-message nonce",
            "Replay is profitable under existing fee model",
        ),
        fix_pattern=(
            "Persist consumed topic_ids in a StorageMap<(MultiLocation, [u8;32]), ()> "
            "and reject any XCM whose tuple is already present."
        ),
        fix_anti_pattern_avoided=(
            "trusting the carrier transport to provide replay protection"
        ),
        extra_shape_tags=("pallet-xcm", "topic-id"),
    ),
    AttackClass(
        framework="substrate",
        attack_class="xcm-asset-id-confusion",
        bug_class="input-validation",
        title="XCM asset_id confusion between MultiAsset::Concrete and ::Abstract causes wrong asset to be burned/minted",
        component="xcm_executor::traits::ConvertLocation",
        raw_signature="fn convert_asset(asset: &MultiAsset) -> Option<AssetId>",
        domain="bridge",
        impact_class="theft",
        impact_actor="depositor-class",
        impact_dollar_class=">=$1M",
        attacker_role="unprivileged",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Attacker crafts XCM transferring an Abstract asset whose abstract id "
            "collides with a Concrete location after the project's ConvertLocation; "
            "destination chain burns the wrong asset balance."
        ),
        required_preconditions=(
            "ConvertLocation implementation maps both Concrete and Abstract to the same AssetId",
            "No domain separation tag in stored asset table",
            "Cross-asset transfer not gated on AssetClass equality",
        ),
        fix_pattern=(
            "Domain-separate the converter: include the MultiAsset variant tag in "
            "the AssetId mapping function; reject any XCM whose asset variant is "
            "Abstract unless the destination chain has explicit Abstract support."
        ),
        fix_anti_pattern_avoided=(
            "treating Abstract and Concrete MultiAsset variants as interchangeable"
        ),
        extra_shape_tags=("pallet-xcm", "multi-asset"),
    ),
    AttackClass(
        framework="substrate",
        attack_class="treasury-spend-bypass",
        bug_class="access-control",
        title="Treasury spend dispatchable bypasses on_initialize budget check via spend_local + payout race",
        component="pallet_treasury::Pallet::spend",
        raw_signature="pub fn spend(origin: OriginFor<T>, asset_kind: ..., amount: ..., beneficiary: ..., valid_from: Option<BlockNumber>)",
        domain="governance",
        impact_class="theft",
        impact_actor="protocol-treasury",
        impact_dollar_class=">=$1M",
        attacker_role="governance",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Approved spender races payout before on_initialize updates the period "
            "budget counter; multiple spends settle within a single period and total "
            "outflow exceeds the configured spend_max."
        ),
        required_preconditions=(
            "spend_max enforced only at proposal-approval, not at payout time",
            "payout dispatchable readable by spender without on_initialize completion",
            "Period boundary not atomic across spend + payout",
        ),
        fix_pattern=(
            "Check Pot::<T>::get() and PeriodSpent::<T>::get() inside payout; reject "
            "if cumulative would exceed spend_max."
        ),
        fix_anti_pattern_avoided=(
            "enforcing budgets only at proposal-time without payout-side rechecks"
        ),
        extra_shape_tags=("pallet-treasury", "spend-local"),
    ),
    AttackClass(
        framework="substrate",
        attack_class="democracy-proposal-replay",
        bug_class="signature-replay",
        title="Democracy proposal hash replay across referendum_index without preimage-noting binding",
        component="pallet_democracy::Pallet::propose",
        raw_signature="pub fn propose(origin: OriginFor<T>, proposal: BoundedCallOf<T>, value: BalanceOf<T>)",
        domain="governance",
        impact_class="governance-takeover",
        impact_actor="protocol-treasury",
        impact_dollar_class=">=$1M",
        attacker_role="governance",
        severity="high",
        repo_override=None,
        attacker_action_sequence=(
            "Attacker re-proposes the same call hash after a previously vetoed "
            "referendum; preimage stored from the first attempt is reused and the "
            "second referendum's voting backstops fire on a stale tally."
        ),
        required_preconditions=(
            "Preimage stored persistently without per-referendum_index binding",
            "Veto does not invalidate preimage",
            "No proposer-account rate limit",
        ),
        fix_pattern=(
            "Bind preimage lookup to (referendum_index, proposer); require fresh "
            "note_preimage call per referendum."
        ),
        fix_anti_pattern_avoided=(
            "treating preimage as a content-addressable singleton without referendum binding"
        ),
        extra_shape_tags=("pallet-democracy", "preimage"),
    ),
    # ----------------------------- CosmWasm -------------------------------
    AttackClass(
        framework="cosmwasm",
        attack_class="contract-instantiate-replay",
        bug_class="signature-replay",
        title="CosmWasm Instantiate2 deterministic address replay enables front-run hijack",
        component="cosmwasm_std::Instantiate2",
        raw_signature="fn instantiate2(deps: DepsMut, env: Env, info: MessageInfo, msg: InstantiateMsg, salt: Binary) -> Result<Response, ContractError>",
        domain="lending",
        impact_class="theft",
        impact_actor="depositor-class",
        impact_dollar_class="$100K-$1M",
        attacker_role="unprivileged",
        severity="high",
        repo_override=None,
        attacker_action_sequence=(
            "Attacker observes a victim's pending Instantiate2 tx in mempool, "
            "extracts (creator, code_id, salt), front-runs with same arguments "
            "claiming the deterministic address, and the victim's tx fails with "
            "address-collision while the attacker controls the contract."
        ),
        required_preconditions=(
            "Salt derived from public inputs (block height, user address) without secret nonce",
            "No commit-reveal scheme around the salt",
            "Front-running is profitable",
        ),
        fix_pattern=(
            "Include a secret commit (hash-of-secret) in salt; reveal in a second tx "
            "after instantiate to bind ownership."
        ),
        fix_anti_pattern_avoided=(
            "treating Instantiate2 as private when salt is constructed from public data"
        ),
        extra_shape_tags=("cosmwasm-std", "instantiate2"),
    ),
    AttackClass(
        framework="cosmwasm",
        attack_class="cw20-token-extension-confusion",
        bug_class="input-validation",
        title="CW20 token extension (send vs transfer) confusion lets attacker invoke receiver callback on stale balance",
        component="cw20_base::contract::execute_send",
        raw_signature="pub fn execute_send(deps: DepsMut, env: Env, info: MessageInfo, contract: String, amount: Uint128, msg: Binary)",
        domain="dex",
        impact_class="theft",
        impact_actor="depositor-class",
        impact_dollar_class="$100K-$1M",
        attacker_role="unprivileged",
        severity="high",
        repo_override="CosmWasm/cw-plus",
        attacker_action_sequence=(
            "Attacker calls cw20 transfer to a contract that expects cw20 send "
            "semantics; downstream contract reads the post-transfer balance and "
            "credits the attacker without seeing the Receiver hook fire."
        ),
        required_preconditions=(
            "Receiver contract reads cw20 balance via Bank query rather than Receiver hook payload",
            "transfer and send are not distinguished by event-only handler",
            "Pre/post hooks not bound to specific message variant",
        ),
        fix_pattern=(
            "Reject incoming cw20 transfers that did not arrive via Send + Receiver "
            "hook; gate credit on the hook's payload, not the bank balance delta."
        ),
        fix_anti_pattern_avoided=(
            "treating cw20 transfer and send as semantically equivalent in receiver logic"
        ),
        extra_shape_tags=("cw20", "receiver-hook"),
    ),
    AttackClass(
        framework="cosmwasm",
        attack_class="migration-storage-collision",
        bug_class="upgrade-safety",
        title="CosmWasm contract migration storage collision when new contract reads stale keys",
        component="cosmwasm_std::entry_point::migrate",
        raw_signature="pub fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> Result<Response, ContractError>",
        domain="lending",
        impact_class="theft",
        impact_actor="protocol-treasury",
        impact_dollar_class=">=$1M",
        attacker_role="privileged-compromised",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Admin migrates to a new code_id whose Item/Map<&str, ...> share a "
            "prefix byte with the old contract's keys; new contract reads stale "
            "values as new types and writes through, silently corrupting balances."
        ),
        required_preconditions=(
            "Storage keys not domain-separated by storage version",
            "New contract uses cw_storage_plus without StorageVersion guard",
            "Old contract did not write a migration_complete sentinel",
        ),
        fix_pattern=(
            "Require StorageVersion::set(OLD) precondition at migrate() entry; "
            "namespace all keys by version prefix; clear stale keys explicitly."
        ),
        fix_anti_pattern_avoided=(
            "assuming cw_storage_plus prefixes prevent type-confusion across versions"
        ),
        extra_shape_tags=("cosmwasm-storage-plus", "migrate"),
    ),
    AttackClass(
        framework="cosmwasm",
        attack_class="sudo-msg-permission-bypass",
        bug_class="access-control",
        title="CosmWasm sudo() entry point reachable by unprivileged caller via direct WasmExecute",
        component="cosmwasm_std::entry_point::sudo",
        raw_signature="pub fn sudo(deps: DepsMut, env: Env, msg: SudoMsg) -> Result<Response, ContractError>",
        domain="governance",
        impact_class="privilege-escalation",
        impact_actor="protocol-treasury",
        impact_dollar_class=">=$1M",
        attacker_role="unprivileged",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Attacker calls execute() with a SudoMsg payload pattern the contract's "
            "execute() handler matches and dispatches to internal sudo handlers, "
            "bypassing the chain-only sudo entry-point gate."
        ),
        required_preconditions=(
            "Internal sudo handler reachable from execute() without explicit caller==env.contract.address check",
            "SudoMsg variants pattern-match the same shape as ExecuteMsg",
            "No assert_admin or chain_only modifier",
        ),
        fix_pattern=(
            "Move sudo logic to a private helper only invoked from sudo(); add "
            "explicit ensure!(info.sender == env.block.chain_id) for chain sudo intent."
        ),
        fix_anti_pattern_avoided=(
            "exposing sudo helpers from execute() under the assumption SudoMsg shape is unique"
        ),
        extra_shape_tags=("cosmwasm-std", "sudo-entry"),
    ),
    AttackClass(
        framework="cosmwasm",
        attack_class="cw-bank-denom-confusion",
        bug_class="input-validation",
        title="CosmWasm BankMsg::Send denom confusion (native vs cw20) credits attacker double",
        component="cosmwasm_std::BankMsg::Send",
        raw_signature="BankMsg::Send { to_address: String, amount: Vec<Coin> }",
        domain="dex",
        impact_class="theft",
        impact_actor="depositor-class",
        impact_dollar_class="$100K-$1M",
        attacker_role="unprivileged",
        severity="high",
        repo_override=None,
        attacker_action_sequence=(
            "Attacker calls deposit() with a Coin whose denom is the cw20 contract "
            "address-as-string; pool's accounting treats it as native, mints LP "
            "shares, then attacker redeems LP for real native asset."
        ),
        required_preconditions=(
            "Pool accepts arbitrary denom string without whitelist",
            "LP shares mint based on denom-keyed map without provenance check",
            "Refund path uses BankMsg::Send irrespective of original asset type",
        ),
        fix_pattern=(
            "Validate denom against an explicit AllowedDenoms whitelist; reject any "
            "denom not in the bank module's registered set or a known cw20 prefix."
        ),
        fix_anti_pattern_avoided=(
            "treating denom strings as opaque without registry validation"
        ),
        extra_shape_tags=("cosmwasm-bank", "denom-validation"),
    ),
    AttackClass(
        framework="cosmwasm",
        attack_class="cw-ica-host-priv-escalation",
        bug_class="access-control",
        title="CosmWasm ICA-host contract executes arbitrary chain msg from spoofed channel",
        component="cw_ica_controller::contract::execute_send_cosmos_msgs",
        raw_signature="pub fn execute_send_cosmos_msgs(deps: DepsMut, info: MessageInfo, msgs: Vec<CosmosMsg<E>>) -> Result<Response, ContractError>",
        domain="bridge",
        impact_class="privilege-escalation",
        impact_actor="protocol-treasury",
        impact_dollar_class=">=$1M",
        attacker_role="unprivileged",
        severity="critical",
        repo_override="srdtrk/cw-ica-controller",
        attacker_action_sequence=(
            "Attacker opens an ICA channel from a low-bond chain to the host; "
            "host's execute_send_cosmos_msgs validates only the channel-id field "
            "without binding to the original controller's connection-id, so attacker "
            "submits a CosmosMsg::Bank::Send from the host's ICA account."
        ),
        required_preconditions=(
            "Host validates only channel_id, not (connection_id, port_id, channel_id)",
            "ICA account funded by treasury",
            "Counterparty validation missing",
        ),
        fix_pattern=(
            "Bind execute to (connection_id, port_id, channel_id) tuple stored at "
            "channel-open; reject any inbound packet whose tuple does not match the "
            "registered controller binding."
        ),
        fix_anti_pattern_avoided=(
            "treating channel_id as a sufficient authentication primitive"
        ),
        extra_shape_tags=("cosmwasm-ibc", "ica-controller"),
    ),
    # --------------------------- FROST / Threshold ------------------------
    AttackClass(
        framework="frost",
        attack_class="frost-share-recovery-bypass",
        bug_class="signature-replay",
        title="FROST share recovery protocol lets t-1 colluding signers reconstruct an absent participant's share",
        component="frost_core::keys::dkg::part2",
        raw_signature="fn part2<C: Ciphersuite>(secret_package: round1::SecretPackage, round1_packages: &BTreeMap<Identifier<C>, round1::Package<C>>) -> Result<(round2::SecretPackage<C>, BTreeMap<Identifier<C>, round2::Package<C>>), Error<C>>",
        domain="consensus",
        impact_class="theft",
        impact_actor="protocol-treasury",
        impact_dollar_class=">=$1M",
        attacker_role="validator",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "t-1 colluding signers craft round1 packages whose commitment polynomial "
            "evaluations at the absent identifier point are pre-chosen; on round2 "
            "they derive the absent participant's secret share via Lagrange "
            "interpolation of the visible commitments."
        ),
        required_preconditions=(
            "DKG round1 packages not bound to the participant's own contribution randomness",
            "Verification of commitment polynomial does not enforce per-identifier blinding",
            "Threshold t < n / 2 + 1 with collusion",
        ),
        fix_pattern=(
            "Bind each round1 package to a per-participant Schnorr proof-of-possession "
            "over identifier || commitment; reject any round1 package whose POK fails."
        ),
        fix_anti_pattern_avoided=(
            "trusting the commitment polynomial without per-identifier domain separation"
        ),
        extra_shape_tags=("frost-core", "dkg-round1"),
    ),
    AttackClass(
        framework="frost",
        attack_class="frost-aggregator-malicious",
        bug_class="signature-replay",
        title="Malicious FROST signing-aggregator substitutes message in aggregate without participants re-signing",
        component="frost_core::round2::aggregate",
        raw_signature="pub fn aggregate<C: Ciphersuite>(signing_package: &SigningPackage<C>, signature_shares: &BTreeMap<Identifier<C>, round2::SignatureShare<C>>, pubkey_package: &PublicKeyPackage<C>) -> Result<Signature<C>, Error<C>>",
        domain="consensus",
        impact_class="theft",
        impact_actor="depositor-class",
        impact_dollar_class=">=$1M",
        attacker_role="privileged-compromised",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Aggregator presents signers with message M_user, collects shares, then "
            "during aggregation swaps to message M_attacker whose commitment matches "
            "the binding factor; aggregation succeeds and a valid signature on "
            "M_attacker is produced without participant consent."
        ),
        required_preconditions=(
            "Binding factor derived from commitments without including the message hash",
            "Signers do not re-verify message hash post-share-submission",
            "Aggregator controls the message bytes seen by verifier",
        ),
        fix_pattern=(
            "Bind the FROST binding factor to H(message || group_commitment || identifier_list); "
            "verifier rejects aggregate signature whose binding does not match."
        ),
        fix_anti_pattern_avoided=(
            "computing binding factor over only commitments without message-hash inclusion"
        ),
        extra_shape_tags=("frost-core", "aggregate"),
    ),
    AttackClass(
        framework="frost",
        attack_class="nonce-reuse-attack",
        bug_class="signature-replay",
        title="FROST signing nonce reuse across signing sessions leaks long-term share via lattice attack",
        component="frost_core::round1::commit",
        raw_signature="pub fn commit<C: Ciphersuite, R: RngCore + CryptoRng>(secret: &SigningShare<C>, rng: &mut R) -> (SigningNonces<C>, SigningCommitments<C>)",
        domain="consensus",
        impact_class="theft",
        impact_actor="protocol-treasury",
        impact_dollar_class=">=$1M",
        attacker_role="validator",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Participant reuses a (hiding, binding) nonce pair across two signing "
            "sessions; attacker observing both signatures derives the per-share "
            "secret via two-equation lattice solve and forges signatures."
        ),
        required_preconditions=(
            "RNG state not domain-separated per session",
            "Nonce derived from time alone without session-id mixing",
            "No reused-nonce detection by other signers",
        ),
        fix_pattern=(
            "Derive nonces as HKDF(share || session_id || message_hash); persist "
            "session_id history and refuse to sign for replayed session_id."
        ),
        fix_anti_pattern_avoided=(
            "trusting OsRng to produce unique nonces without session-id injection"
        ),
        extra_shape_tags=("frost-core", "signing-nonce"),
    ),
    AttackClass(
        framework="frost",
        attack_class="dkg-malicious-dealer",
        bug_class="access-control",
        title="FROST DKG malicious dealer ships invalid VSS shares passing receive-side without VSS-verify",
        component="frost_core::keys::dkg::part1",
        raw_signature="pub fn part1<C: Ciphersuite, R: RngCore + CryptoRng>(identifier: Identifier<C>, max_signers: u16, min_signers: u16, rng: &mut R) -> Result<(round1::SecretPackage<C>, round1::Package<C>), Error<C>>",
        domain="consensus",
        impact_class="theft",
        impact_actor="protocol-treasury",
        impact_dollar_class=">=$1M",
        attacker_role="validator",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Dealer-role participant in DKG ships VSS shares whose commitments do "
            "not match the polynomial; receiver participants accept without running "
            "VSS verification, yielding a group key whose threshold reconstruction "
            "is biased toward the dealer."
        ),
        required_preconditions=(
            "Receiver does not run frost_core::keys::dkg::part2 with full VSS check",
            "Dealer can mark its share invalid without complaint propagation",
            "Threshold accepts t out of n without complaint resolution",
        ),
        fix_pattern=(
            "Always invoke verify_vss on each round1 share; broadcast complaints via "
            "round-robin and abort DKG on any unresolved complaint."
        ),
        fix_anti_pattern_avoided=(
            "treating round1 packages as trusted because they came from a known dealer"
        ),
        extra_shape_tags=("frost-core", "dkg-vss"),
    ),
    AttackClass(
        framework="frost",
        attack_class="partial-sig-rebroadcast",
        bug_class="signature-replay",
        title="FROST partial signature rebroadcast lets attacker harvest shares for nonce-reuse linkage",
        component="frost_core::round2::sign",
        raw_signature="pub fn sign<C: Ciphersuite>(signing_package: &SigningPackage<C>, signer_nonces: &SigningNonces<C>, key_package: &KeyPackage<C>) -> Result<SignatureShare<C>, Error<C>>",
        domain="consensus",
        impact_class="theft",
        impact_actor="protocol-treasury",
        impact_dollar_class="$100K-$1M",
        attacker_role="unprivileged",
        severity="high",
        repo_override=None,
        attacker_action_sequence=(
            "Attacker re-broadcasts an old SignatureShare wire payload to honest "
            "aggregator; aggregator includes the stale share alongside fresh shares, "
            "leaking a (nonce, share) pair correlation usable for offline cryptanalysis."
        ),
        required_preconditions=(
            "Aggregator does not pin SignatureShare to (session_id, signing_package_hash)",
            "Old shares not invalidated when session changes",
            "No per-session signer authentication",
        ),
        fix_pattern=(
            "Tag every SignatureShare with (session_id, signer_id, package_hash); "
            "aggregator rejects shares whose tuple does not match the current session."
        ),
        fix_anti_pattern_avoided=(
            "accepting any well-formed SignatureShare without session binding"
        ),
        extra_shape_tags=("frost-core", "signature-share"),
    ),
    AttackClass(
        framework="frost",
        attack_class="commitment-binding-failure",
        bug_class="signature-replay",
        title="FROST commitment binding factor missing context-string lets cross-protocol signature forgery",
        component="frost_core::compute_binding_factor",
        raw_signature="fn compute_binding_factor_list<C: Ciphersuite>(signing_package: &SigningPackage<C>, additional_prefix: &[u8]) -> BindingFactorList<C>",
        domain="consensus",
        impact_class="theft",
        impact_actor="protocol-treasury",
        impact_dollar_class=">=$1M",
        attacker_role="validator",
        severity="critical",
        repo_override=None,
        attacker_action_sequence=(
            "Two FROST-compatible protocols share a public key (e.g. Spark and a "
            "Lightning channel multisig); aggregator on protocol A obtains shares "
            "for message M, then re-uses commitments on protocol B where the "
            "binding factor lacks protocol-id, forging a signature on B."
        ),
        required_preconditions=(
            "Same group public key reused across two FROST-using protocols",
            "Binding factor lacks protocol-domain-separation string",
            "Verifier on B accepts any well-formed signature",
        ),
        fix_pattern=(
            "Include H(context_string) where context_string contains protocol-name "
            "and chain-id in compute_binding_factor; both signers and verifiers must "
            "agree on context_string."
        ),
        fix_anti_pattern_avoided=(
            "sharing keys across protocols without domain-separation tags"
        ),
        extra_shape_tags=("frost-core", "binding-factor"),
    ),
)


# -------------------------------------------------------------------------
# Public-source citation table. Each row is a (anchor_id, source_kind, slug,
# year) tuple; the ETL fans each AttackClass over all sources marked as
# applicable for the framework so downstream consumers see cross-source
# convergence.
# -------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceCitation:
    slug: str
    framework: str
    year: int
    source_kind: str


SOURCE_CITATIONS: Tuple[SourceCitation, ...] = (
    # Substrate / Polkadot
    SourceCitation("srlabs-polkadot-2019", "substrate", 2019, "sr-labs-audit"),
    SourceCitation("srlabs-polkadot-runtime-2021", "substrate", 2021, "sr-labs-audit"),
    SourceCitation("srlabs-polkadot-runtime-2022", "substrate", 2022, "sr-labs-audit"),
    SourceCitation("srlabs-polkadot-runtime-2023", "substrate", 2023, "sr-labs-audit"),
    SourceCitation("trail-of-bits-polkadot-2023", "substrate", 2023, "trail-of-bits-audit"),
    SourceCitation("synacktiv-polkadot-2024", "substrate", 2024, "synacktiv-audit"),
    SourceCitation("chainsafe-polkadot-2022", "substrate", 2022, "chainsafe-audit"),
    SourceCitation("least-authority-polkadot-2020", "substrate", 2020, "least-authority-audit"),
    SourceCitation("quarkslab-polkadot-2023", "substrate", 2023, "quarkslab-audit"),
    SourceCitation("oak-security-frame-2024", "substrate", 2024, "oak-security-audit"),
    # CosmWasm
    SourceCitation("zellic-osmosis-2023", "cosmwasm", 2023, "zellic-audit"),
    SourceCitation("zellic-mars-2023", "cosmwasm", 2023, "zellic-audit"),
    SourceCitation("zellic-neutron-2024", "cosmwasm", 2024, "zellic-audit"),
    SourceCitation("trail-of-bits-terra-2022", "cosmwasm", 2022, "trail-of-bits-audit"),
    SourceCitation("trail-of-bits-astroport-2023", "cosmwasm", 2023, "trail-of-bits-audit"),
    SourceCitation("oak-security-mars-2023", "cosmwasm", 2023, "oak-security-audit"),
    SourceCitation("oak-security-stride-2023", "cosmwasm", 2023, "oak-security-audit"),
    SourceCitation("oak-security-quasar-2024", "cosmwasm", 2024, "oak-security-audit"),
    SourceCitation("informal-systems-cosmos-sdk-2023", "cosmwasm", 2023, "informal-systems-audit"),
    SourceCitation("informal-systems-ibc-2023", "cosmwasm", 2023, "informal-systems-audit"),
    SourceCitation("halborn-juno-2022", "cosmwasm", 2022, "halborn-audit"),
    SourceCitation("certik-osmosis-2023", "cosmwasm", 2023, "certik-audit"),
    SourceCitation("hexens-neutron-2024", "cosmwasm", 2024, "hexens-audit"),
    SourceCitation("informal-systems-neutron-2024", "cosmwasm", 2024, "informal-systems-audit"),
    # FROST
    SourceCitation("zcash-foundation-frost-rfc-2023", "frost", 2023, "rfc-spec"),
    SourceCitation("nccgroup-frost-2023", "frost", 2023, "ncc-group-audit"),
    SourceCitation("lightspark-frost-spark-2024", "frost", 2024, "lightspark-audit"),
    SourceCitation("zellic-frost-2024", "frost", 2024, "zellic-audit"),
    SourceCitation("trail-of-bits-frost-2024", "frost", 2024, "trail-of-bits-audit"),
    SourceCitation("spark-statechain-prior-audit-2024", "frost", 2024, "spark-prior-audit"),
    SourceCitation("kudelski-frost-2023", "frost", 2023, "kudelski-audit"),
    SourceCitation("rfc9591-frost-spec-2024", "frost", 2024, "rfc-spec"),
    SourceCitation("crysol-frost-2024", "frost", 2024, "crysol-audit"),
    SourceCitation("zksecurity-frost-2024", "frost", 2024, "zksecurity-audit"),
)


# -------------------------------------------------------------------------
# Helpers (mirror style of sibling ETLs).
# -------------------------------------------------------------------------


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
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
    # YAML flow indicators that are unsafe as the leading character of a plain
    # scalar: see YAML 1.2 spec sections 6.7-6.9. `>` and `|` open block scalar
    # headers, `<` collides with merge keys, `*`/`&` are anchors, etc.
    unsafe_leading = ("#", "-", "?", ":", ">", "<", "|", "*", "&", "!", "%", "@", "`", ",", "[", "]", "{", "}")
    plain_safe = (
        bool(re.fullmatch(r"[A-Za-z0-9._:/=,$#-]+", text))
        and not text.endswith(":")
        and not text.startswith(unsafe_leading)
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


def framework_profile(framework: str) -> Dict[str, str]:
    return FRAMEWORK_PROFILES[framework]


def shape_tags(attack: AttackClass) -> List[str]:
    profile = framework_profile(attack.framework)
    tags = [
        slugify(attack.attack_class),
        slugify(f"{profile['language']}-{attack.bug_class}"),
        slugify(f"{profile['prefix']}{attack.framework}"),
    ]
    for extra in attack.extra_shape_tags:
        slug = slugify(f"{profile['prefix']}{extra}")
        if slug not in tags:
            tags.append(slug)
    # Dedupe while preserving order, and keep tag total <= 6 to avoid noise.
    seen: List[str] = []
    for tag in tags:
        if tag and tag not in seen:
            seen.append(tag)
    return seen[:6]


def build_record(attack: AttackClass, source: SourceCitation) -> Dict[str, Any]:
    profile = framework_profile(attack.framework)
    repo = attack.repo_override or profile["repo"]
    source_audit_ref = f"{source.source_kind}:{source.slug}:{slugify(attack.attack_class, max_len=72)}"
    digest_input = "\n".join(
        [
            attack.attack_class,
            attack.title,
            attack.attacker_action_sequence,
            source.slug,
            source.source_kind,
        ]
    )
    digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:12]
    record_id = (
        f"substrate-cosmwasm-frost:{attack.framework}:{slugify(attack.attack_class, max_len=64)}"
        f":{slugify(source.slug, max_len=48)}:{digest}"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source_audit_ref": source_audit_ref,
        "target_domain": attack.domain,
        "target_language": profile["language"],
        "target_repo": repo,
        "target_component": attack.component[:240],
        "function_shape": {
            "raw_signature": attack.raw_signature[:500],
            "shape_tags": shape_tags(attack),
        },
        "bug_class": attack.bug_class,
        "attack_class": attack.attack_class,
        "attacker_role": attack.attacker_role,
        "attacker_action_sequence": attack.attacker_action_sequence[:1000],
        "required_preconditions": list(attack.required_preconditions)[:3],
        "impact_class": attack.impact_class,
        "impact_actor": attack.impact_actor,
        "impact_dollar_class": attack.impact_dollar_class,
        "fix_pattern": attack.fix_pattern[:1000],
        "fix_anti_pattern_avoided": attack.fix_anti_pattern_avoided[:1000],
        "severity_at_finding": attack.severity,
        "year": source.year,
        "cross_language_analogues": [],
        "related_records": [],
    }


def output_filename(record: Dict[str, Any]) -> str:
    digest = str(record["record_id"]).rsplit(":", 1)[-1]
    return f"{slugify(record['record_id'], max_len=110)}-{digest}.yaml"


def collect_records(
    *,
    frameworks: Optional[Sequence[str]] = None,
    attack_classes: Optional[Sequence[str]] = None,
    sources: Optional[Sequence[str]] = None,
) -> List[Dict[str, Any]]:
    """Build records for the (attack-class x source) cross-product matching filters."""
    framework_filter = {fw.lower() for fw in frameworks} if frameworks else None
    attack_filter = {ac.lower() for ac in attack_classes} if attack_classes else None
    source_filter = {src.lower() for src in sources} if sources else None

    citations_by_framework: Dict[str, List[SourceCitation]] = {}
    for citation in SOURCE_CITATIONS:
        citations_by_framework.setdefault(citation.framework, []).append(citation)

    records: List[Dict[str, Any]] = []
    for attack in ATTACK_CLASSES:
        if framework_filter and attack.framework not in framework_filter:
            continue
        if attack_filter and attack.attack_class.lower() not in attack_filter:
            continue
        for source in citations_by_framework.get(attack.framework, []):
            if source_filter and source.slug.lower() not in source_filter:
                continue
            records.append(build_record(attack, source))
    return records


def write_records(records: Sequence[Dict[str, Any]], out_dir: Path, *, dry_run: bool) -> List[Path]:
    paths: List[Path] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    for record in records:
        path = out_dir / output_filename(record)
        paths.append(path)
        if dry_run:
            continue
        rendered = yaml_dump(record)
        path.write_text(rendered, encoding="utf-8")
    return paths


def validate_records(records: Sequence[Dict[str, Any]]) -> List[str]:
    """Run schema validation on each rendered record; return error strings."""
    schema = _VALIDATOR.load_schema()
    errors: List[str] = []
    for record in records:
        try:
            import yaml  # local import to avoid hard runtime dep when only writing
            rendered_doc = yaml.safe_load(yaml_dump(record))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{record['record_id']}: render-parse error: {exc}")
            continue
        errs = _VALIDATOR.validate_doc(rendered_doc, schema)
        if errs:
            errors.extend(f"{record['record_id']}: {err}" for err in errs)
    return errors


def run_etl(
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    frameworks: Optional[Sequence[str]] = None,
    attack_classes: Optional[Sequence[str]] = None,
    sources: Optional[Sequence[str]] = None,
    validate: bool = True,
) -> Dict[str, Any]:
    records = collect_records(
        frameworks=frameworks,
        attack_classes=attack_classes,
        sources=sources,
    )
    if limit is not None:
        records = records[:limit]
    errors: List[str] = []
    if validate:
        errors = validate_records(records)
    paths = write_records(records, out_dir, dry_run=dry_run)
    framework_counts: Dict[str, int] = {}
    attack_class_counts: Dict[str, int] = {}
    for record in records:
        # framework is recorded in record_id prefix "...:<framework>:..."
        parts = str(record["record_id"]).split(":")
        if len(parts) >= 3:
            fw = parts[1]
            framework_counts[fw] = framework_counts.get(fw, 0) + 1
        attack_class_counts[str(record["attack_class"])] = (
            attack_class_counts.get(str(record["attack_class"]), 0) + 1
        )
    return {
        "schema_version": SUMMARY_SCHEMA,
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "records_emitted": len(records),
        "attack_class_count": len(set(record["attack_class"] for record in records)),
        "frameworks": dict(sorted(framework_counts.items())),
        "attack_class_breakdown": dict(sorted(attack_class_counts.items())),
        "source_count": len({str(record["source_audit_ref"]).split(":", 2)[1] for record in records}) if records else 0,
        "errors": errors,
        "file_count": len(paths),
        "files": [str(path) for path in paths[:50]],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, help="Output directory for hackerman_record YAML files.")
    parser.add_argument("--dry-run", action="store_true", help="Build records without writing files.")
    parser.add_argument("--limit", type=int, help="Cap number of records emitted.")
    parser.add_argument(
        "--framework",
        action="append",
        default=[],
        choices=("substrate", "cosmwasm", "frost"),
        help="Filter to specific framework; repeatable.",
    )
    parser.add_argument(
        "--attack-class",
        action="append",
        default=[],
        help="Filter to specific attack_class (verbatim); repeatable.",
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="Filter to specific source slug (e.g. zellic-osmosis-2023); repeatable.",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip schema validation pass (debug only).",
    )
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir).expanduser().resolve()
    summary = run_etl(
        out_dir,
        dry_run=args.dry_run,
        limit=args.limit,
        frameworks=args.framework or None,
        attack_classes=args.attack_class or None,
        sources=args.source or None,
        validate=not args.no_validate,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman substrate/cosmwasm/frost ETL: "
            f"records={summary['records_emitted']} "
            f"attack_classes={summary['attack_class_count']} "
            f"frameworks={summary['frameworks']} "
            f"errors={len(summary['errors'])} "
            f"out_dir={summary['out_dir']} "
            f"dry_run={summary['dry_run']}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
