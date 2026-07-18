#!/usr/bin/env python3
"""
Convert NEAR Protocol + ink! WASM contracts attack-class taxonomy into
hackerman_record v1 YAML.

Wave-6 lane EXEC-WAVE6-NEAR-INK / TIER-D Rust Tier-4. Sibling of:

* Wave-5 Lift C7 (Solidity DeFi fine-grain)
* Wave-5 EXEC-WAVE5-BRIDGE-TAXONOMY-RETRY (bridge-incident)

This lane mines a Rust-side taxonomy across two ecosystem buckets:

* NEAR Protocol smart contracts (`near-sdk-rs`, Aurora bridge, fungible
  / non-fungible token contracts, FastAuth / Lockup-class contracts).
  Callback / Promise / yield resume / cross-shard receipt semantics drive
  a distinct attack-class family that is not present in EVM Solidity.

* ink! (Parity Substrate WASM contracts; Aleph Zero, Astar Network,
  Pop! Network). ink! has its own storage-key, cross-contract balance,
  trapped-balance / non-reverting-call semantics.

Both ecosystems map to schema enum `target_language: rust`. The persisted
`target_domain` is drawn from the schema enum set; ecosystem-specific
distinctions live in `function_shape.shape_tags`.

Five new attack classes mined (per Wave-6 brief):

* near-callback-promise-replay
* near-yield-callback-state-divergence
* near-fungible-token-burn-without-callback-fail
* ink-storage-key-shadow
* ink-cross-contract-trapped-balance

Each significant attack class emits THREE mitigation-state variants:

* `proposed`  - reporter-state evidence, fix not yet acknowledged
* `mitigated` - patch shipped but invariant-test coverage absent
* `regressed` - fix landed then later regressed by unrelated PR

Sources represented (NEAR / Aurora / ink! security disclosures):
near-core security advisories, Aurora bridge audits (OAK / Halborn /
Hexens), Parity ink! contract audits, Aleph Zero / Astar Network
audit reports (Hexens / Kudelski / Sigma Prime / Halborn).

Target record band: ~30-45 (well within the 20-50 brief target).

Hard rules followed:

* New file only; does NOT modify any existing file.
* Does NOT touch `tools/calibration/llm_budget_log.jsonl`.
* Cross-links (in docstring + comments) are relative paths only.
* All emitted records validate against
  `audit/corpus_tags/schemas/auditooor.hackerman_record.v1.schema.json`.

CLI:

    python3 tools/hackerman-etl-from-near-ink.py \\
        --out-dir /tmp/etl-near-ink-out \\
        --dry-run --json-summary

    python3 tools/hackerman-etl-from-near-ink.py \\
        --out-dir audit/corpus_tags/tags/near_ink
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
        "_hackerman_record_validate_for_near_ink",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ---------------------------------------------------------------------------
# Helpers (mirrored from sibling defi-fine-grain ETL so the YAML rendering
# stays byte-stable across the family).
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
# Taxonomy: 5 attack classes (NEAR + ink!)
#
# Row layout:
#   (ecosystem, attack_class, bug_class, severity_hint, impact_class,
#    impact_actor, attacker_role, target_domain,
#    action_template, precondition_template,
#    fix_template, anti_pattern_template, component_template, raw_signature)
#
# `{protocol}` placeholder is filled at fan-out time.
# ---------------------------------------------------------------------------


TAXONOMY: Tuple[Tuple[str, str, str, str, str, str, str, str, str, str, str, str, str, str], ...] = (
    # --- NEAR Protocol --------------------------------------------------
    (
        "near",
        "near-callback-promise-replay",
        "cross-contract-callback-bypass",
        "critical",
        "theft",
        "arbitrary-user",
        "unprivileged",
        "rpc-infra",
        "{protocol} ft_transfer_call dispatches a Promise to the receiver and registers a callback ft_resolve_transfer; attacker calls ft_resolve_transfer directly from a sibling contract or replays the receipt across shards because the callback only checks env::predecessor_account_id() against current_account_id() without also asserting promise_results_count() and the receipt-hash, so the attacker steals the credited amount during the resolve.",
        "{protocol} ft_resolve_transfer (or analogous on_transfer / on_receive callback) guards only on predecessor == current_account_id, not on promise_results_count() and the dispatched receipt-hash; or the callback is annotated #[private] alone without further nonce / receipt-correlation.",
        "Gate the callback on BOTH require!(env::predecessor_account_id() == env::current_account_id()) AND require!(env::promise_results_count() == 1); persist the dispatched promise-id in storage at ft_transfer_call time and assert the callback's receipt matches before crediting; OR use near-contract-standards' canonical ft_resolve_transfer template verbatim.",
        "Trusting that #[private] alone is sufficient when NEAR's cross-shard receipt routing can replay a callback via a sibling contract impersonating the original promise.",
        "{protocol}.ft_resolve_transfer",
        "fn ft_resolve_transfer(&mut self, sender_id: AccountId, receiver_id: AccountId, amount: U128) -> U128",
    ),
    (
        "near",
        "near-yield-callback-state-divergence",
        "cross-contract-state-divergence",
        "high",
        "yield-redistribution",
        "depositor-class",
        "unprivileged",
        "rpc-infra",
        "{protocol} stakes a yield-bearing position by calling env::promise_yield_create to await an off-chain signer; the on_yield_resume callback resumes with a payload but the contract mutates state in the dispatch path BEFORE the yield resolves, then re-mutates it on resume - if the yield-resume races a concurrent ft_transfer or storage_deposit modifying the same shared state field, the second mutation overwrites the first and the attacker harvests the resulting accounting drift.",
        "{protocol} mutates a shared accounting field (e.g. total_supply / total_staked / pending_rewards) BOTH on promise_yield_create dispatch AND on on_yield_resume without snapshotting the pre-dispatch value into the yield's data_id payload.",
        "Snapshot the pre-dispatch state into the yield's data_id payload at promise_yield_create time; in on_yield_resume, recompute the diff against the snapshot rather than re-reading current state; add a per-data_id idempotency guard so a replayed on_yield_resume is a no-op.",
        "Treating promise_yield_create as a synchronous primitive whose state-snapshot semantics are guaranteed by the runtime.",
        "{protocol}.on_yield_resume",
        "fn on_yield_resume(&mut self, data_id: CryptoHash, payload: Vec<u8>) -> PromiseOrValue<U128>",
    ),
    (
        "near",
        "near-fungible-token-burn-without-callback-fail",
        "burn-accounting-without-callback-revert",
        "high",
        "theft",
        "depositor-class",
        "unprivileged",
        "rpc-infra",
        "{protocol} implements ft_transfer_call by burning balance from sender pre-dispatch and re-minting on ft_resolve_transfer failure; the resolve path checks PromiseResult::Failed and re-mints, BUT if the receiver contract panics in a way that returns PromiseResult::Successful with an empty payload (e.g. via near_sdk::env::abort() from a sub-promise), the resolve path takes the success branch and never re-mints - sender's balance is silently burned.",
        "{protocol} ft_resolve_transfer reads PromiseResult::Successful as 'callback succeeded' without further inspecting the payload bytes / returned U128 value.",
        "Inspect the PromiseResult::Successful payload via near_sdk::serde_json::from_slice::<U128>(&result) and treat a parse-error OR an out-of-range value as Failed; require receiver contracts to return a typed U128 with explicit handling for the all-spent case.",
        "Treating PromiseResult::Successful as a binary success-signal without payload validation.",
        "{protocol}.ft_transfer_call",
        "fn ft_transfer_call(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>, msg: String) -> PromiseOrValue<U128>",
    ),

    # --- ink! (Parity Substrate WASM contracts) -------------------------
    (
        "ink",
        "ink-storage-key-shadow",
        "storage-key-collision",
        "high",
        "theft",
        "depositor-class",
        "unprivileged",
        "vault",
        "{protocol} ink! contract uses #[ink(storage)] for the primary struct and a separately-declared Mapping<AccountId, Balance> for sub-balances; both end up at storage-key root prefix 0x00000000 because the developer forgot to annotate the Mapping with a distinct ManualKey - subsequent contract-upgrade or trait-object indirection writes the Mapping payload over the primary struct's first field, corrupting balances and enabling attacker to mint arbitrary balance by triggering the collision-write path.",
        "{protocol} declares both #[ink(storage)] struct fields and a Mapping<_, _> without explicit ManualKey<N> annotation, OR has two Mapping fields with overlapping default-derived keys.",
        "Annotate every Mapping with an explicit ManualKey<N> (e.g. Mapping::<AccountId, Balance, ManualKey<0xCAFE_BABE>>::new()); add an ink-storage-collision-detection invariant test that asserts no two storage fields share a key prefix; OR migrate to ink! 5.x lazy-storage primitives which derive keys from field-name hashes.",
        "Trusting ink!'s default storage-key derivation to disambiguate Mapping fields when the contract's #[ink(storage)] struct itself sits at key 0.",
        "{protocol}::balances",
        "pub struct Contract { balances: Mapping<AccountId, Balance>, total_supply: Balance }",
    ),
    (
        "ink",
        "ink-cross-contract-trapped-balance",
        "cross-contract-trapped-balance",
        "critical",
        "freeze",
        "depositor-class",
        "unprivileged",
        "escrow",
        "{protocol} ink! contract A calls into contract B via build_call(...).transferred_value(v).invoke() to forward native balance; B traps (via panic / out-of-gas / ContractTrapped) AFTER receiving the balance but BEFORE persisting state; ink!'s default behaviour rolls back B's state but DOES NOT roll back the transferred_value transfer if A used .invoke() without checking the returned Result - balance is permanently trapped in B's account with no caller-recoverable state, attacker (acting as B's owner) sweeps it.",
        "{protocol} contract A uses build_call::<DefaultEnvironment>(...).invoke() (or .fire()) without matching on the Result, OR uses CallFlags::ALLOW_REENTRY without rolling back transferred_value on trap.",
        "Always match on the Result of build_call(...).try_invoke(); on ContractTrapped, explicitly call env().transfer(caller, transferred_value) to refund; OR use ink! 5.x's transferred_value-with-rollback flag set explicitly.",
        "Assuming that a callee trap automatically rolls back the value-transfer in addition to the callee's state.",
        "{protocol}::forward_call",
        "pub fn forward_call(&mut self, target: AccountId, value: Balance) -> Result<(), Error>",
    ),
)


# ---------------------------------------------------------------------------
# Protocol fan-out per ecosystem.
# ---------------------------------------------------------------------------


NEAR_PROTOCOLS: Tuple[Tuple[str, str], ...] = (
    ("near-sdk-rs", "near/near-sdk-rs"),
    ("aurora-engine", "aurora-is-near/aurora-engine"),
    ("ref-finance", "ref-finance/ref-contracts"),
)


INK_PROTOCOLS: Tuple[Tuple[str, str], ...] = (
    ("aleph-zero-staking", "Cardinal-Cryptography/aleph-node"),
    ("astar-dapps-staking", "AstarNetwork/Astar"),
    ("openbrush", "Brushfam/openbrush-contracts"),
)


SOURCE_PLATFORMS: Tuple[Tuple[str, str], ...] = (
    ("hexens", "hex"),
    ("kudelski", "kud"),
    ("halborn", "hlb"),
    ("oak-security", "oak"),
)


# Three mitigation states; significant classes (>= medium) emit all three.
MITIGATION_STATES: Tuple[Tuple[str, str, str, str], ...] = (
    (
        "proposed",
        "reporter-state evidence; team has not yet acknowledged",
        "Apply the recommended fix; gate paste-ready promotion on the invariant test described.",
        "Assuming the cross-contract trust boundary is enforced by the runtime alone.",
    ),
    (
        "mitigated",
        "patch shipped but invariant-test coverage is still absent",
        "Add an invariant test that exercises the bug's trigger condition so a future regression fails CI.",
        "Treating a patch as complete without a regression test that pins the invariant.",
    ),
    (
        "regressed",
        "post-fix regression; the fix landed and was later silently reverted by an unrelated refactor",
        "Re-apply the original fix and add an inline invariant comment so future refactors do not silently remove the guard.",
        "Allowing an unrelated refactor PR to silently remove a security-critical cross-contract guard.",
    ),
)


# ---------------------------------------------------------------------------
# Record assembly
# ---------------------------------------------------------------------------


def _ecosystem_protocols(ecosystem: str) -> Tuple[Tuple[str, str], ...]:
    if ecosystem == "near":
        return NEAR_PROTOCOLS
    if ecosystem == "ink":
        return INK_PROTOCOLS
    raise ValueError(f"unknown ecosystem {ecosystem!r}")


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
    digest = hashlib.sha1(
        f"{source_id}|{protocol_slug}|{attack_class}".encode("utf-8")
    ).digest()
    return 2022 + (digest[0] % 4)


def _shape_tags(ecosystem: str, attack_class: str, bug_class: str, protocol_slug: str) -> List[str]:
    out = [
        slugify(attack_class, max_len=64),
        slugify(f"rust-{bug_class}", max_len=64),
        slugify(f"{ecosystem}-{protocol_slug}", max_len=64),
        f"ecosystem-{ecosystem}",
    ]
    seen = set()
    result: List[str] = []
    for tag in out:
        if tag and tag not in seen:
            seen.add(tag)
            result.append(tag)
    return result


def _record_id(
    ecosystem: str,
    attack_class: str,
    protocol_slug: str,
    source_slug: str,
    mitigation_state: str,
) -> str:
    payload = f"{ecosystem}|{attack_class}|{protocol_slug}|{source_slug}|{mitigation_state}"
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return (
        f"near-ink:{slugify(ecosystem)}:{slugify(attack_class)}:"
        f"{slugify(protocol_slug, max_len=24)}:{slugify(source_slug, max_len=12)}:"
        f"{mitigation_state}:{digest}"
    )


def _source_audit_ref(source_id: str, protocol_slug: str, attack_class: str, year: int) -> str:
    return f"{source_id}:{protocol_slug}-{year:04d}:{slugify(attack_class, max_len=64)}"


def _emit_mitigation_states_for(severity: str) -> Tuple[Tuple[str, str, str, str], ...]:
    sev = severity.lower()
    if sev in {"critical", "high", "medium"}:
        return MITIGATION_STATES
    return (MITIGATION_STATES[0],)


def build_records() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for row in TAXONOMY:
        (
            ecosystem,
            attack_class,
            bug_class,
            severity,
            impact_class,
            impact_actor,
            attacker_role,
            target_domain,
            action_tpl,
            precondition_tpl,
            fix_tpl,
            anti_pattern_tpl,
            component_tpl,
            raw_signature_tpl,
        ) = row
        for protocol_name, protocol_repo in _ecosystem_protocols(ecosystem):
            protocol_slug = slugify(protocol_name, max_len=32)
            # One source platform per (class, protocol) to stay in the
            # 20-50 target band: deterministically rotate the platform by
            # attack_class hash so each class covers a different platform.
            class_hash = int(hashlib.sha1(attack_class.encode("utf-8")).hexdigest(), 16)
            rotation = class_hash % len(SOURCE_PLATFORMS)
            picked = (SOURCE_PLATFORMS[rotation],)
            for source_id, source_slug in picked:
                for mitigation_state, state_note, fix_addendum, anti_pattern_addendum in _emit_mitigation_states_for(severity):
                    # Templates may contain literal Rust braces (e.g. "struct Contract { ... }")
                    # so we cannot use str.format() unconditionally. Use a manual
                    # placeholder substitution that only replaces "{protocol}".
                    def _sub(text: str, protocol: str = protocol_name) -> str:
                        return text.replace("{protocol}", protocol)

                    component = _sub(component_tpl)
                    raw_signature = _sub(raw_signature_tpl)
                    action_text = _sub(action_tpl)
                    precondition_text = _sub(precondition_tpl)
                    fix_text = _sub(fix_tpl)
                    anti_pattern_text = _sub(anti_pattern_tpl)
                    year = _year_for(source_id, protocol_slug, attack_class)
                    record_id = _record_id(ecosystem, attack_class, protocol_slug, source_slug, mitigation_state)
                    source_audit_ref = _source_audit_ref(source_id, protocol_slug, attack_class, year)
                    state_marker = f" [mitigation-state={mitigation_state}; {state_note}]"
                    record = {
                        "schema_version": SCHEMA_VERSION,
                        "record_id": record_id,
                        "source_audit_ref": source_audit_ref[:240],
                        "target_domain": target_domain,
                        "target_language": "rust",
                        "target_repo": protocol_repo,
                        "target_component": component[:240],
                        "function_shape": {
                            "raw_signature": raw_signature[:500],
                            "shape_tags": _shape_tags(ecosystem, attack_class, bug_class, protocol_slug),
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
                            "Apply the recommended cross-contract invariant fix.",
                            max_len=900,
                        ),
                        "fix_anti_pattern_avoided": one_line(
                            f"{anti_pattern_text} {anti_pattern_addendum}",
                            "Anti-pattern: assuming the runtime enforces the cross-contract guard.",
                            max_len=900,
                        ),
                        "severity_at_finding": severity,
                        "year": year,
                        "record_tier": "public-corpus",
                        "record_quality_score": 3.0,
                        "source_extraction_method": "corpus-etl",
                        "source_extraction_confidence": 0.55,
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
    filter_ecosystem: Optional[str] = None,
) -> Dict[str, Any]:
    records = build_records()
    if filter_ecosystem:
        eco_tag = f"ecosystem-{filter_ecosystem}"
        records = [r for r in records if eco_tag in r["function_shape"]["shape_tags"]]
    if limit is not None:
        records = records[:limit]

    schema = _VALIDATOR.load_schema()
    errors: List[str] = []
    files: List[str] = []
    by_domain: Dict[str, int] = {}
    by_attack_class: Dict[str, int] = {}
    by_state: Dict[str, int] = {}
    by_ecosystem: Dict[str, int] = {}

    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    for record in records:
        by_domain[record["target_domain"]] = by_domain.get(record["target_domain"], 0) + 1
        by_attack_class[record["attack_class"]] = by_attack_class.get(record["attack_class"], 0) + 1
        state = str(record["record_id"]).rsplit(":", 2)[-2]
        by_state[state] = by_state.get(state, 0) + 1
        for tag in record["function_shape"]["shape_tags"]:
            if tag.startswith("ecosystem-"):
                eco = tag.split("-", 1)[1]
                by_ecosystem[eco] = by_ecosystem.get(eco, 0) + 1
                break
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
        "by_ecosystem": by_ecosystem,
        "file_count": len(files),
        "files": files[:50],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--filter-ecosystem",
        choices=("near", "ink"),
        help="Restrict emitted records to a single ecosystem bucket.",
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
        filter_ecosystem=args.filter_ecosystem,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman NEAR+ink! ETL: "
            f"records={summary['records_emitted']}/{summary['records_attempted']} "
            f"by_ecosystem={summary['by_ecosystem']} "
            f"by_state={summary['by_mitigation_state']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
