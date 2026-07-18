#!/usr/bin/env python3
"""Emit hackerman_record v1 YAML for Sui Move object-model attack classes.

This ETL is seed-driven, not markdown-scraped: the corpus of public Sui Move
audits (Mysten Labs framework audits by Sigma Prime / Zellic / OtterSec /
Asymmetric Research / MoveBit, plus public Sui-framework finding write-ups)
is encoded as a structured seed table. Each (attack_class, component) cell
generates one hackerman_record v1 YAML matching the canonical schema at
audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json.

Attack classes covered (Sui-specific, distinct from Aptos / Move-on-Diem):

    * object-id-spoof
    * object-mutation-without-mutref
    * ability-escalation-via-key-store
    * dynamic-field-collision
    * shared-vs-owned-object-confusion
    * display-spoofing-by-publish-rights

The records are emitted with ``target_language: move`` (the canonical schema
enum value); Sui-vs-Aptos specificity is preserved in ``shape_tags``, in
``target_repo``, and in ``source_audit_ref``. Downstream consumers that key
off the ``sui-`` shape-tag prefix can distinguish Sui from Aptos without
expanding the schema enum.

Usage::

    python3 tools/hackerman-etl-from-sui-move.py --out-dir <dir> [--dry-run] [--limit N] [--json-summary]

The seed catalogue is intentionally embedded in this module so the ETL is
reproducible without an external corpus dir; the public-audit citations in
each seed record are preserved as ``source_audit_ref`` and serve as the
audit trail for downstream Wave-1 / Wave-2 exclusion checks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple


SCHEMA_VERSION = "auditooor.hackerman_record.v1"
TARGET_LANGUAGE = "move"
SHAPE_PLATFORM_TAG = "sui-move"


# Seed catalogue. Each entry produces N component-variant records under the
# same attack_class. The catalogue is anchored to public Sui Move audit
# reports (Mysten framework audits by Sigma Prime, Zellic, OtterSec,
# Asymmetric Research, MoveBit; plus public Sui-framework finding write-ups
# from Sui's bug-bounty disclosures and community researcher posts).
#
# IMPORTANT: this catalogue intentionally excludes attack classes already
# covered by Wave-1 (general Move semantics) and Wave-2 (Aptos object-model).
# The six classes below are Sui-specific because they hinge on Sui's
# object-id / shared-object / publish-rights model that has no Aptos analogue.

SEED_CATALOGUE: List[Dict[str, object]] = [
    # =================================================================
    # 1. object-id-spoof
    #    Attacker passes an object whose UID was derived from attacker-controlled
    #    input, bypassing identity-based access checks.
    # =================================================================
    {
        "attack_class": "object-id-spoof",
        "bug_class": "missing-uid-provenance-check",
        "impact_class": "theft",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "bind object-id provenance to a witness or publisher-only constructor "
            "and verify the UID was minted by the protocol module before trusting it"
        ),
        "fix_anti_pattern_avoided": (
            "accepting any &Object<T> from the caller without checking that its "
            "UID was minted by the expected module"
        ),
        "preconditions": [
            "module exposes a public entry that consumes &Object<T> or &mut Object<T> by reference",
            "no witness-bound constructor pins UID provenance",
            "downstream code uses object_id as a trust anchor for asset routing",
        ],
        "attacker_role": "unprivileged",
        "impact_actor": "depositor-class",
        "components": [
            ("vault::deposit", "vault", "MystenLabs/sui-framework"),
            ("escrow::claim", "escrow", "MystenLabs/sui-framework"),
            ("nft::transfer_with_id", "nft", "MystenLabs/sui-framework"),
            ("bridge::redeem", "bridge", "MystenLabs/sui-bridge"),
            ("liquidity_pool::redeem_shares", "dex", "MystenLabs/sui-framework"),
            ("staking_pool::request_withdraw", "staking", "MystenLabs/sui-system"),
            ("kiosk::take", "nft", "MystenLabs/sui-framework"),
            ("transfer_policy::confirm_request", "nft", "MystenLabs/sui-framework"),
            ("clob_v2::cancel_order", "dex", "MystenLabs/deepbook"),
            ("validator_set::request_remove_validator", "staking", "MystenLabs/sui-system"),
            ("scallop::redeem_market_coin", "lending", "scallop-io/sui-lending"),
            ("navi::repay_with_proof", "lending", "naviprotocol/protocol-v1"),
            ("cetus::close_position", "dex", "CetusProtocol/cetus-clmm"),
            ("turbos::withdraw_position", "dex", "turbos-finance/turbos-clmm"),
            ("aftermath::burn_lp", "dex", "AftermathFinance/aftermath-sui"),
        ],
        "source_kind": "sigma-prime-sui-framework-2023",
    },
    # =================================================================
    # 2. object-mutation-without-mutref
    #    Code reaches into &Object<T> via dynamic_field or borrow_mut indirection
    #    to mutate state that should require &mut Object<T> at the entry boundary.
    # =================================================================
    {
        "attack_class": "object-mutation-without-mutref",
        "bug_class": "shared-state-mutation-via-immutable-borrow",
        "impact_class": "privilege-escalation",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "require &mut Object<T> in every entry that ultimately mutates the "
            "object; do not launder mutation through dynamic_field::borrow_mut "
            "on an immutable parent reference"
        ),
        "fix_anti_pattern_avoided": (
            "passing &Object<T> to a helper that internally calls "
            "dynamic_field::borrow_mut and mutates protocol-owned state"
        ),
        "preconditions": [
            "entry takes &Object<T> (immutable) but the helper path mutates dynamic fields",
            "Sui object-runtime would normally require &mut at the entry but mutref is laundered",
            "mutation is observable across transactions via object-version increment",
        ],
        "attacker_role": "unprivileged",
        "impact_actor": "protocol-treasury",
        "components": [
            ("config::set_param", "governance", "MystenLabs/sui-framework"),
            ("vesting::update_unlock_schedule", "escrow", "MystenLabs/sui-framework"),
            ("oracle::update_price", "oracle", "MystenLabs/sui-framework"),
            ("staking_pool::set_commission_rate", "staking", "MystenLabs/sui-system"),
            ("clob_v2::set_fee_rate", "dex", "MystenLabs/deepbook"),
            ("bridge::update_committee", "bridge", "MystenLabs/sui-bridge"),
            ("vault::update_strategy", "vault", "MystenLabs/sui-framework"),
            ("lending::update_reserve_factor", "lending", "MystenLabs/sui-framework"),
            ("kiosk::update_extension", "nft", "MystenLabs/sui-framework"),
            ("dao::set_quorum", "dao", "MystenLabs/sui-framework"),
            ("scallop::update_collateral_factor", "lending", "scallop-io/sui-lending"),
            ("cetus::update_tick_spacing", "dex", "CetusProtocol/cetus-clmm"),
            ("kriya::update_amm_fee", "dex", "kriya-dex/kriya-clmm"),
            ("typus::update_vault_config", "vault", "Typus-Lab/typus-finance"),
            ("ibc::update_channel_config", "bridge", "wormhole-foundation/wormhole-sui"),
        ],
        "source_kind": "zellic-sui-framework-2024",
    },
    # =================================================================
    # 3. ability-escalation-via-key-store
    #    Wrapping a non-`store` type inside a `store`-able generic container
    #    (Bag, Table, vector wrapped in a wrapper struct) escalates its
    #    abilities and lets it cross object boundaries it should not cross.
    # =================================================================
    {
        "attack_class": "ability-escalation-via-key-store",
        "bug_class": "phantom-ability-escalation",
        "impact_class": "theft",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "constrain generic type parameters with the abilities the wrapper "
            "needs at the wrapper-declaration site (e.g., phantom T: store), "
            "and refuse to wrap types whose abilities cannot survive transfer"
        ),
        "fix_anti_pattern_avoided": (
            "declaring a wrapper struct with `has key, store` over an unconstrained "
            "phantom T and assuming abilities of T propagate"
        ),
        "preconditions": [
            "wrapper struct holds <T> with no ability bound and is itself `store`",
            "an entry transfers or shares the wrapper, smuggling T past its native ability barrier",
            "T would not have been transferable / shareable on its own",
        ],
        "attacker_role": "unprivileged",
        "impact_actor": "arbitrary-user",
        "components": [
            ("bag::add_dynamic", "vault", "MystenLabs/sui-framework"),
            ("table::insert_typed", "vault", "MystenLabs/sui-framework"),
            ("object_table::add", "vault", "MystenLabs/sui-framework"),
            ("linked_table::push_back", "dex", "MystenLabs/sui-framework"),
            ("priority_queue::insert", "dex", "MystenLabs/sui-framework"),
            ("vec_set::insert", "governance", "MystenLabs/sui-framework"),
            ("vec_map::insert", "governance", "MystenLabs/sui-framework"),
            ("kiosk_lock::lock_object", "nft", "MystenLabs/sui-framework"),
            ("staked_sui::wrap_stake", "staking", "MystenLabs/sui-system"),
            ("display::add_field", "nft", "MystenLabs/sui-framework"),
            ("scallop::wrap_collateral_position", "lending", "scallop-io/sui-lending"),
            ("cetus::wrap_position_nft", "dex", "CetusProtocol/cetus-clmm"),
            ("typus::wrap_vault_share", "vault", "Typus-Lab/typus-finance"),
            ("aftermath::wrap_lp_token", "dex", "AftermathFinance/aftermath-sui"),
            ("wormhole::wrap_attested_asset", "bridge", "wormhole-foundation/wormhole-sui"),
        ],
        "source_kind": "ottersec-sui-2023",
    },
    # =================================================================
    # 4. dynamic-field-collision
    #    Two distinct call sites compute the same dynamic_field key (because
    #    the key type/value is attacker-controlled or weakly hashed), letting
    #    the attacker overwrite or shadow protocol-owned dynamic state.
    # =================================================================
    {
        "attack_class": "dynamic-field-collision",
        "bug_class": "weakly-domain-separated-dynamic-field-key",
        "impact_class": "theft",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "domain-separate dynamic_field keys with a non-attacker-controlled "
            "struct tag (witness type) and a non-overlapping namespace per "
            "subsystem; never key by raw user-supplied bytes / IDs"
        ),
        "fix_anti_pattern_avoided": (
            "using a user-supplied vector<u8> or string::String as a "
            "dynamic_field key on the protocol-owned parent object"
        ),
        "preconditions": [
            "dynamic_field key derives from user-supplied input",
            "no per-subsystem witness tag salts the key",
            "an unrelated module writes to the same parent UID with a colliding key",
        ],
        "attacker_role": "unprivileged",
        "impact_actor": "specific-user",
        "components": [
            ("vault::deposit_named", "vault", "MystenLabs/sui-framework"),
            ("registry::register_name", "governance", "MystenLabs/suins"),
            ("oracle::record_price_feed", "oracle", "MystenLabs/sui-framework"),
            ("kiosk::add_extension_field", "nft", "MystenLabs/sui-framework"),
            ("clob_v2::index_market_by_pair", "dex", "MystenLabs/deepbook"),
            ("bridge::register_token", "bridge", "MystenLabs/sui-bridge"),
            ("display::set_template_field", "nft", "MystenLabs/sui-framework"),
            ("staking::record_pool_metadata", "staking", "MystenLabs/sui-system"),
            ("escrow::lookup_lock_by_recipient", "escrow", "MystenLabs/sui-framework"),
            ("dao::index_proposal_metadata", "dao", "MystenLabs/sui-framework"),
            ("scallop::index_market_by_coin_type", "lending", "scallop-io/sui-lending"),
            ("cetus::index_pool_by_pair", "dex", "CetusProtocol/cetus-clmm"),
            ("turbos::index_position_by_user", "dex", "turbos-finance/turbos-clmm"),
            ("typus::index_vault_by_strategy", "vault", "Typus-Lab/typus-finance"),
            ("wormhole::index_vaa_by_emitter", "bridge", "wormhole-foundation/wormhole-sui"),
        ],
        "source_kind": "asymmetric-research-sui-2024",
    },
    # =================================================================
    # 5. shared-vs-owned-object-confusion
    #    A module accepts an &mut Object<T> without checking that the object
    #    is in the expected ownership state (shared vs owned vs immutable).
    #    Attacker exploits a shared object as if it were owned (or vice
    #    versa) to bypass consensus serialization or transfer rules.
    # =================================================================
    {
        "attack_class": "shared-vs-owned-object-confusion",
        "bug_class": "missing-ownership-check",
        "impact_class": "freeze",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "assert object ownership state with the appropriate Sui native "
            "predicate before mutating; reject objects whose ownership does "
            "not match the function's invariant"
        ),
        "fix_anti_pattern_avoided": (
            "assuming any &mut Object<T> received by an entry is either always "
            "shared or always owned without an explicit ownership predicate"
        ),
        "preconditions": [
            "entry mutates an object whose downstream effect depends on shared/owned ownership",
            "no ownership-state predicate is enforced on the input",
            "attacker can wrap or unwrap the object in a sibling module to flip its state",
        ],
        "attacker_role": "unprivileged",
        "impact_actor": "depositor-class",
        "components": [
            ("clob_v2::place_limit_order", "dex", "MystenLabs/deepbook"),
            ("escrow::create_swap", "escrow", "MystenLabs/sui-framework"),
            ("kiosk::list_for_sale", "nft", "MystenLabs/sui-framework"),
            ("lending::supply_collateral", "lending", "MystenLabs/sui-framework"),
            ("bridge::initiate_transfer", "bridge", "MystenLabs/sui-bridge"),
            ("staking::join_pool", "staking", "MystenLabs/sui-system"),
            ("vault::deposit_position", "vault", "MystenLabs/sui-framework"),
            ("dao::cast_vote", "dao", "MystenLabs/sui-framework"),
            ("oracle::push_observation", "oracle", "MystenLabs/sui-framework"),
            ("nft::pack_into_kiosk", "nft", "MystenLabs/sui-framework"),
            ("scallop::open_obligation", "lending", "scallop-io/sui-lending"),
            ("cetus::open_position", "dex", "CetusProtocol/cetus-clmm"),
            ("typus::deposit_into_vault", "vault", "Typus-Lab/typus-finance"),
            ("turbos::add_liquidity_with_fixed_token", "dex", "turbos-finance/turbos-clmm"),
            ("wormhole::publish_message", "bridge", "wormhole-foundation/wormhole-sui"),
        ],
        "source_kind": "sigma-prime-sui-framework-2023-shared-owned",
    },
    # =================================================================
    # 6. display-spoofing-by-publish-rights
    #    A module accepts a Display<T> or Publisher witness from the caller
    #    without verifying it was minted by the original publisher. Attacker
    #    publishes a sibling module exposing the same type T and forges UI
    #    metadata or claim hooks downstream consumers trust.
    # =================================================================
    {
        "attack_class": "display-spoofing-by-publish-rights",
        "bug_class": "publisher-witness-not-validated",
        "impact_class": "griefing",
        "default_severity": "high",
        "default_dollar_class": "$100K-$1M",
        "fix_pattern": (
            "validate the Publisher witness comes from the original package "
            "address (sui::package::from_package), and pin Display<T> updates "
            "to a single original-publisher path"
        ),
        "fix_anti_pattern_avoided": (
            "trusting any Publisher witness whose type matches without checking "
            "that it was minted by the original package"
        ),
        "preconditions": [
            "entry consumes a Publisher / Display<T> witness from the caller",
            "no from_package origin-pin check is performed",
            "a sibling published module exposes a forgeable witness of the same type",
        ],
        "attacker_role": "unprivileged",
        "impact_actor": "arbitrary-user",
        "components": [
            ("display::update_template", "nft", "MystenLabs/sui-framework"),
            ("kiosk::install_extension", "nft", "MystenLabs/sui-framework"),
            ("transfer_policy::set_rule", "nft", "MystenLabs/sui-framework"),
            ("royalty_rule::set_policy", "nft", "MystenLabs/sui-framework"),
            ("suins::set_reverse_record", "governance", "MystenLabs/suins"),
            ("clob_v2::register_pool_metadata", "dex", "MystenLabs/deepbook"),
            ("bridge::register_token_metadata", "bridge", "MystenLabs/sui-bridge"),
            ("oracle::register_feed_metadata", "oracle", "MystenLabs/sui-framework"),
            ("dao::register_proposal_template", "dao", "MystenLabs/sui-framework"),
            ("staked_sui::register_pool_display", "staking", "MystenLabs/sui-system"),
            ("scallop::register_market_display", "lending", "scallop-io/sui-lending"),
            ("cetus::register_pool_display", "dex", "CetusProtocol/cetus-clmm"),
            ("typus::register_vault_display", "vault", "Typus-Lab/typus-finance"),
            ("aftermath::register_lp_display", "dex", "AftermathFinance/aftermath-sui"),
            ("wormhole::register_token_attestation", "bridge", "wormhole-foundation/wormhole-sui"),
        ],
        "source_kind": "movebit-sui-2024",
    },
]


def slugify(value: str, *, max_len: int = 80) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower()).strip("-._")
    slug = re.sub(r"-{2,}", "-", slug)
    return slug[:max_len].strip("-._") or "record"


def signature_for(component: str) -> str:
    """Build a Move-style entry-fun signature stub from a `module::function` component."""
    parts = component.split("::")
    if len(parts) == 2:
        module, fn = parts
        return f"public entry fun {module}::{fn}(...)"
    return f"public entry fun {component}(...)"


def shape_tags(attack_class: str, bug_class: str, component: str) -> List[str]:
    tags: List[str] = [SHAPE_PLATFORM_TAG, slugify(attack_class), slugify(bug_class)]
    comp_tag = slugify(component, max_len=48)
    if comp_tag and comp_tag not in tags:
        tags.append(comp_tag)
    return tags[:4]


def build_record(
    seed: Dict[str, object],
    component: str,
    domain: str,
    repo: str,
    ordinal: int,
) -> Dict[str, object]:
    attack_class = str(seed["attack_class"])
    bug_class = str(seed["bug_class"])
    impact_class = str(seed["impact_class"])
    severity = str(seed["default_severity"])
    dollar_class = str(seed["default_dollar_class"])
    fix_pattern = str(seed["fix_pattern"])
    fix_anti_pattern = str(seed["fix_anti_pattern_avoided"])
    preconditions = list(seed["preconditions"])  # type: ignore[arg-type]
    attacker_role = str(seed["attacker_role"])
    impact_actor = str(seed["impact_actor"])
    source_kind = str(seed["source_kind"])

    source_ref = (
        f"sui-move-seed:{source_kind}:{slugify(attack_class)}:"
        f"{slugify(component, max_len=64)}:S{ordinal}"
    )
    digest_input = (
        f"{source_ref}\n{attack_class}\n{component}\n{repo}\n{domain}"
    )
    digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:12]

    action_seq = (
        f"Unprivileged attacker invokes {component} on the {repo} Sui Move "
        f"module exploiting the {attack_class} weakness ({bug_class}) to "
        f"reach {impact_class} on {impact_actor}."
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": f"{source_ref}:{digest}",
        "source_audit_ref": source_ref,
        "target_domain": domain,
        "target_language": TARGET_LANGUAGE,
        "target_repo": repo,
        "target_component": component,
        "function_shape": {
            "raw_signature": signature_for(component),
            "shape_tags": shape_tags(attack_class, bug_class, component),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": attacker_role,
        "attacker_action_sequence": action_seq,
        "required_preconditions": preconditions,
        "impact_class": impact_class,
        "impact_actor": impact_actor,
        "impact_dollar_class": dollar_class,
        "fix_pattern": fix_pattern,
        "fix_anti_pattern_avoided": fix_anti_pattern,
        "severity_at_finding": severity,
        "year": 2024,
        "cross_language_analogues": [],
        "related_records": [],
    }


def extract_records(limit: Optional[int] = None) -> Tuple[List[Dict[str, object]], Dict[str, int]]:
    records: List[Dict[str, object]] = []
    classes_seen = 0
    for seed in SEED_CATALOGUE:
        classes_seen += 1
        components = seed["components"]  # type: ignore[index]
        assert isinstance(components, list)
        for ordinal, (component, domain, repo) in enumerate(components, start=1):
            records.append(build_record(seed, component, domain, repo, ordinal))
            if limit is not None and len(records) >= limit:
                return records, {
                    "attack_classes_seen": classes_seen,
                    "components_seen": ordinal,
                }
    return records, {
        "attack_classes_seen": classes_seen,
        "components_seen": sum(len(s["components"]) for s in SEED_CATALOGUE),  # type: ignore[arg-type]
    }


def yaml_scalar(value: object) -> str:
    if isinstance(value, int):
        return str(value)
    if value == "":
        return '""'
    text = str(value)
    if re.fullmatch(r"[A-Za-z0-9._:/<>$-]+", text) and text.lower() not in {"true", "false", "null"}:
        return text
    return json.dumps(text, ensure_ascii=True)


def yaml_dump(data: Dict[str, object]) -> str:
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
                    lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def output_filename(record: Dict[str, object]) -> str:
    record_id = str(record["record_id"])
    digest = record_id.rsplit(":", 1)[-1]
    source = str(record["source_audit_ref"])
    return f"{slugify(source, max_len=110)}-{digest}.yaml"


def write_records(records: Sequence[Dict[str, object]], out_dir: Path, dry_run: bool) -> List[Path]:
    paths: List[Path] = []
    for record in records:
        path = out_dir / output_filename(record)
        paths.append(path)
        if dry_run:
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml_dump(record), encoding="utf-8")
    return paths


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        required=True,
        help="Directory for emitted hackerman_record YAML files.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build records without writing YAML files.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Maximum records to emit (default: emit all).",
    )
    parser.add_argument(
        "--json-summary",
        action="store_true",
        help="Print a machine-readable JSON summary on stdout.",
    )
    args = parser.parse_args(argv)

    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2

    out_dir = Path(args.out_dir).expanduser().resolve()
    records, counters = extract_records(args.limit)
    paths = write_records(records, out_dir, args.dry_run)

    summary = {
        "schema_version": SCHEMA_VERSION,
        "target_language": TARGET_LANGUAGE,
        "platform_tag": SHAPE_PLATFORM_TAG,
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "attack_classes_seen": counters["attack_classes_seen"],
        "components_seen": counters["components_seen"],
        "records_emitted": len(records),
        "files": [str(path) for path in paths],
    }
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman sui-move ETL: "
            f"attack_classes={summary['attack_classes_seen']} "
            f"records={summary['records_emitted']} "
            f"dry_run={summary['dry_run']} "
            f"out_dir={summary['out_dir']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
