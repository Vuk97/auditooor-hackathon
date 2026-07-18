#!/usr/bin/env python3
"""
Convert EVM proxy / upgrade pattern findings into hackerman_record v1 YAML.

Wave-5 lane EXEC-WAVE5-EVM-PROXY-UPGRADE / TIER-C Lift C6.

Target band: ~250 records, all `target_language: solidity`.

Sources (already vendored in this repo):

* `reference/corpus_txt/zellic/*.txt` filtered by proxy / upgrade-relevant
  keywords (UUPS, _authorizeUpgrade, ERC1967, ERC-1822, ERC-2535 / Diamond,
  TransparentUpgradeable, UpgradeableBeacon, initializer, reinitializer,
  selfdestruct in delegatecall context, minimal proxy / clone, etc.).
* `EVM_PROXY_KNOWN_DISCLOSURES` - a curated baseline of widely-publicised
  EVM proxy / upgrade attack classes pulled from OpenZeppelin / Trail of
  Bits / Spearbit / ChainSecurity / Code4rena / Cantina audit history.
  These records guarantee taxonomy coverage when the audit-text channel
  under-fires (the lane targets ~250 records, so a stable curated base is
  emitted first).

Taxonomy (proxy-specific attack classes, prioritised over generic classes):

* `uups-self-destruct-via-fallback`                  - implementation
                                                       contains selfdestruct
                                                       reachable through the
                                                       proxy fallback
* `uups-missing-_authorizeUpgrade-restriction`       - upgradeTo without
                                                       access control
* `uups-storage-collision-via-implementation-slot-shadow` - state var on
                                                       implementation collides
                                                       with ERC-1967 slot
* `transparent-proxy-admin-impersonation`            - admin <-> user
                                                       selector clash
* `transparent-proxy-selector-clash`                 - 4-byte function
                                                       selector overlap
                                                       between proxy & impl
* `beacon-proxy-implementation-takeover`             - beacon owner /
                                                       upgrader is compromised
* `diamond-facet-selector-collision`                 - two facets register
                                                       same selector
* `diamond-storage-clash-across-facets`              - shared storage slot
                                                       collision in Diamond
* `diamond-loupe-spoof`                              - loupe returns false
                                                       facet mapping
* `minimal-proxy-immutable-arg-leak`                 - EIP-1167 / CWIA
                                                       trailing args leak
* `initializer-replay-via-unprotected-init`          - `initialize` not
                                                       guarded by `initializer`
                                                       modifier
* `initializer-reinit-via-version-rollback`          - `_initializing` or
                                                       `_initialized` state
                                                       reset / rolled-back
* `erc1967-implementation-slot-pinning-bypass`       - implementation slot
                                                       written outside
                                                       ERC-1967 path
* `erc2470-create2-redeploy-after-selfdestruct`      - CREATE2 same-salt
                                                       redeploy with new code
                                                       after selfdestruct
* `unchecked-delegatecall-target`                    - delegatecall to a
                                                       user-supplied address

Generic fallback classes (`access-control`, `reentrancy`, `signature-replay`,
`oracle-manipulation`, `precision-loss`, `denial-of-service`, `accounting`,
`input-validation`, `flash-loan`) are checked AFTER the proxy-specific list
so a proxy-shape bug is preferred when it fires.

Output: hackerman_record v1 YAML at `--out-dir`, one file per record.
Schema validated via `tools/hackerman-record-validate.py`. The script does
NOT mutate `tools/calibration/llm_budget_log.jsonl`.

CLI:

    python3 tools/hackerman-etl-from-evm-proxy-upgrade.py \\
        --out-dir /tmp/etl-evm-proxy-out \\
        --dry-run --json-summary

    python3 tools/hackerman-etl-from-evm-proxy-upgrade.py \\
        --out-dir audit/corpus_tags/tags/evm_proxy_upgrade

`--corpus-dir` accepts repeats. `--include-baseline` (default on) emits the
curated baseline; pass `--no-include-baseline` to disable.
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

DEFAULT_CORPUS_DIR = REPO_ROOT / "reference" / "corpus_txt" / "zellic"

# Filename hints that strongly suggest a proxy / upgrade report. Used only
# as an OR-channel; the body-text scan still gates inclusion. We keep the
# filter loose because proxy bugs hide in many DeFi audits where the
# product itself is not a proxy framework.
PROXY_NAME_HINTS = (
    "proxy",
    "upgradeable",
    "upgrade",
    "diamond",
    "facet",
    "transparent",
    "uups",
    "beacon",
    "clone",
    "factory",
    "initializer",
)

# Body keywords used to gate inclusion when filename is generic. The text
# parser runs against every report and only retains findings whose body
# contains at least one of these tokens.
PROXY_BODY_HINTS = (
    "uups",
    "_authorizeUpgrade",
    "_authorize_upgrade",
    "ERC1967",
    "ERC-1967",
    "ERC1822",
    "ERC-1822",
    "ERC2535",
    "ERC-2535",
    "ERC1167",
    "ERC-1167",
    "EIP-1967",
    "EIP-1822",
    "EIP-2535",
    "EIP-1167",
    "TransparentUpgradeable",
    "TransparentUpgradeableProxy",
    "UpgradeableBeacon",
    "BeaconProxy",
    "ProxyAdmin",
    "Initializable",
    "initializer",
    "reinitializer",
    "_disableInitializers",
    "implementation slot",
    "implementation address",
    "delegatecall",
    "diamond",
    "facet",
    "diamondCut",
    "loupe",
    "selector clash",
    "selector collision",
    "selfdestruct",
    "minimal proxy",
    "clones",
    "OpenZeppelin/erc1967",
    "create2",
    "CREATE2",
    "ERC2470",
    "EIP-2470",
)


def _load_validator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_validate_for_evm_proxy_upgrade",
        str(REPO_ROOT / "tools" / "hackerman-record-validate.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_VALIDATOR = _load_validator()


# ----------------------------------------------------------------------------
# Text helpers
# ----------------------------------------------------------------------------


def dedupe_preserve_order(values: Iterable[str]) -> List[str]:
    seen: set[str] = set()
    out: List[str] = []
    for item in values:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def slugify(value: object, *, max_len: int = 80) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9._:/-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "record")


def repo_slug_part(value: object, *, max_len: int = 64) -> str:
    text = str(value or "").strip().lower()
    text = re.split(r"[:\s]", text, maxsplit=1)[0]
    text = re.sub(r"[^a-z0-9._-]+", "-", text).strip("-._")
    text = re.sub(r"-{2,}", "-", text)
    return (text[:max_len].strip("-._") or "unknown")


def contains_any(text: str, needles: Iterable[str]) -> bool:
    low = text.lower()
    return any(needle.lower() in low for needle in needles)


# ----------------------------------------------------------------------------
# Proxy-pattern taxonomy classifier
# ----------------------------------------------------------------------------


# Each entry: (bug_class, attack_class, (needle, needle, ...))
# More specific patterns first so they win over generic siblings.
# NOTE: CREATE2-redeploy is tested BEFORE bare-selfdestruct because both
# fire on "selfdestruct" prose; the CREATE2 phrasing is more specific.
PROXY_PATTERN_RULES: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    (
        "erc2470-create2-redeploy",
        "erc2470-create2-redeploy-after-selfdestruct",
        (
            "create2 redeploy",
            "redeploy after selfdestruct",
            "metamorphic",
            "metamorphic contract",
            "eip-2470",
            "eip2470",
            "create2 factory",
            "same salt new code",
        ),
    ),
    (
        "selfdestruct-in-implementation",
        "uups-self-destruct-via-fallback",
        (
            "selfdestruct",
            "self-destruct",
            "self destruct",
            "suicide(",
            "selfdestruct(",
        ),
    ),
    (
        "missing-upgrade-auth",
        "uups-missing-_authorizeUpgrade-restriction",
        (
            "_authorizeupgrade",
            "_authorize_upgrade",
            "missing access control on upgradeto",
            "unrestricted upgradeto",
            "upgradeto can be called by anyone",
            "anyone can upgrade",
            "upgradetoandcall",
            "no access control on upgrade",
        ),
    ),
    (
        "implementation-slot-shadow",
        "uups-storage-collision-via-implementation-slot-shadow",
        (
            "storage collision",
            "storage layout collision",
            "implementation slot collision",
            "implementation slot shadow",
            "slot shadowing",
            "shadows the implementation slot",
            "storage gap",
            "__gap",
            "storage clash",
        ),
    ),
    (
        "transparent-admin-impersonation",
        "transparent-proxy-admin-impersonation",
        (
            "transparent proxy admin",
            "admin impersonation",
            "proxy admin can call",
            "admin can shadow",
            "admin-caller-shadowing",
            "admin pretend to be user",
        ),
    ),
    (
        "selector-clash",
        "transparent-proxy-selector-clash",
        (
            "selector clash",
            "selector collision",
            "function selector collision",
            "function selector clash",
            "4-byte collision",
            "4byte collision",
            "calldata selector",
        ),
    ),
    (
        "beacon-takeover",
        "beacon-proxy-implementation-takeover",
        (
            "beacon takeover",
            "beacon owner",
            "upgradeablebeacon",
            "beaconproxy",
            "beacon proxy",
            "beacon upgrade",
            "beacon implementation",
        ),
    ),
    (
        "diamond-selector-collision",
        "diamond-facet-selector-collision",
        (
            "facet selector collision",
            "diamond selector",
            "two facets register",
            "duplicate selector",
            "selector duplicate in diamond",
            "facet collision",
        ),
    ),
    (
        "diamond-storage-clash",
        "diamond-storage-clash-across-facets",
        (
            "diamond storage clash",
            "diamond storage collision",
            "shared storage slot",
            "diamond storage pattern",
            "appstorage clash",
            "appstorage collision",
        ),
    ),
    (
        "diamond-loupe-spoof",
        "diamond-loupe-spoof",
        (
            "loupe spoof",
            "diamondloupe",
            "facets()",
            "loupe returns",
            "facet mapping spoof",
        ),
    ),
    (
        "minimal-proxy-arg-leak",
        "minimal-proxy-immutable-arg-leak",
        (
            "minimal proxy",
            "minimal-proxy",
            "eip-1167",
            "eip1167",
            "clone with immutable args",
            "clones with immutable args",
            "cwia",
            "trailing args",
            "immutable args leak",
        ),
    ),
    (
        "initializer-replay",
        "initializer-replay-via-unprotected-init",
        (
            "unprotected initializer",
            "missing initializer modifier",
            "initialize called twice",
            "initialize() can be called",
            "initialize is public and unprotected",
            "anyone can call initialize",
            "init function not protected",
            "re-call initialize",
            "double initialize",
        ),
    ),
    (
        "initializer-reinit-rollback",
        "initializer-reinit-via-version-rollback",
        (
            "reinitializer",
            "_initialized",
            "_initializing",
            "version rollback",
            "reinit",
            "re-initialize",
            "reinitialize",
            "initialized variable",
        ),
    ),
    (
        "erc1967-slot-bypass",
        "erc1967-implementation-slot-pinning-bypass",
        (
            "erc1967",
            "erc-1967",
            "eip-1967",
            "eip1967",
            "implementation slot",
            "implementation_slot",
            "_implementation",
            "implementationslot",
            "implementation address slot",
        ),
    ),
    (
        "unchecked-delegatecall",
        "unchecked-delegatecall-target",
        (
            "unchecked delegatecall",
            "user-supplied delegatecall",
            "user-controlled delegatecall",
            "arbitrary delegatecall",
            "delegatecall to user",
            "delegatecall to arbitrary",
            "delegatecall target not validated",
        ),
    ),
)


GENERIC_CLASS_RULES: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    (
        "access-control",
        "admin-bypass",
        (
            "access control",
            "unauthorized",
            "onlyowner",
            "only owner",
            "role missing",
            "missing onlyowner",
            "permission missing",
            "anyone can",
        ),
    ),
    (
        "reentrancy",
        "reentrancy",
        ("reentrancy", "reentrant", "nonReentrant", "cross-function reentrancy", "callback"),
    ),
    (
        "signature-replay",
        "signature-replay",
        ("signature", "ecrecover", "replay", "permit", "nonce", "EIP712"),
    ),
    (
        "input-validation",
        "missing-input-validation",
        (
            "validation",
            "unchecked",
            "not checked",
            "missing check",
            "no upper bound",
            "no lower bound",
            "length not checked",
            "address(0)",
            "zero address",
        ),
    ),
    (
        "precision-loss",
        "rounding-precision-loss",
        ("rounding", "precision", "overflow", "underflow", "truncation", "division by"),
    ),
    (
        "denial-of-service",
        "dos-griefing",
        ("dos", "denial of service", "grief", "blocked", "stuck", "unbounded loop"),
    ),
)


def classify_bug_attack(text: str) -> Tuple[str, str]:
    """Prefer a proxy-specific class first; fall back to generic taxonomy."""
    for bug_class, attack_class, needles in PROXY_PATTERN_RULES:
        if contains_any(text, needles):
            return bug_class, attack_class
    for bug_class, attack_class, needles in GENERIC_CLASS_RULES:
        if contains_any(text, needles):
            return bug_class, attack_class
    return "logic-error", "protocol-invariant-bypass"


PROXY_PATTERN_TAG_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("Diamond", ("diamond", "facet", "loupe", "diamondcut", "appstorage")),
    ("Beacon", ("beacon", "upgradeablebeacon", "beaconproxy")),
    ("UUPS", ("uups", "_authorizeupgrade", "authorizeupgrade")),
    ("Transparent", ("transparent", "proxyadmin", "transparentupgradeable")),
    ("Minimal", ("minimal proxy", "eip-1167", "eip1167", "clones", "cwia")),
)


def infer_proxy_pattern_tag(text: str) -> str:
    """Map a body blob to one of the five proxy-pattern shapes."""
    low = text.lower()
    for tag, needles in PROXY_PATTERN_TAG_RULES:
        if any(n in low for n in needles):
            return tag
    # Default: UUPS - the most common modern shape and what most "upgrade"
    # phrasing collapses to when no explicit pattern is named.
    return "UUPS"


# ----------------------------------------------------------------------------
# Domain / impact / severity helpers
# ----------------------------------------------------------------------------


DOMAIN_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("bridge", ("bridge", "cross-chain", "layerzero", "wormhole", "guardian")),
    ("oracle", ("oracle", "price", "pyth", "chainlink", "twap", "redstone")),
    ("lending", ("liquidat", "borrow", "debt", "collateral")),
    ("dex", ("swap", "amm", "pool", "uniswap", "liquidity", "curve", "balancer")),
    ("staking", ("stake", "unstake", "validator", "delegat", "lido", "rocketpool")),
    ("governance", ("governance", "vote", "proposal", "timelock", "governor")),
    ("vault", ("vault", "deposit", "withdraw", "shares", "erc4626", "erc-4626")),
    ("dao", ("dao", "treasury", "multisig", "safe")),
    ("nft", ("erc721", "erc1155", "nft")),
)


def infer_domain(text: str) -> str:
    for domain, needles in DOMAIN_RULES:
        if contains_any(text, needles):
            return domain
    return "vault"


def infer_impact(text: str) -> str:
    low = text.lower()
    if any(needle in low for needle in (
        "drain", "steal", "theft", "loss of funds", "stolen", "mint", "free mint",
    )):
        return "theft"
    if any(needle in low for needle in (
        "freeze", "stuck", "trap", "permanent lock", "locked indefinitely",
        "brick", "permanent freeze", "bricks the proxy",
    )):
        return "freeze"
    if any(needle in low for needle in ("dos", "denial of service", "grief", "blocked")):
        return "dos"
    if any(needle in low for needle in (
        "takeover", "compromise", "upgrade to malicious", "malicious implementation",
        "admin takeover", "selfdestruct",
    )):
        return "privilege-escalation"
    if any(needle in low for needle in ("reward", "yield", "fee")):
        return "yield-redistribution"
    if any(needle in low for needle in ("rounding", "precision", "truncation")):
        return "precision-loss"
    if any(needle in low for needle in ("governance", "vote", "proposal", "quorum")):
        return "governance-takeover"
    if any(needle in low for needle in ("admin", "privilege", "unauthorized")):
        return "privilege-escalation"
    return "griefing"


def dollar_class(severity: str, impact: str) -> str:
    sev = severity.lower()
    if sev == "critical":
        return ">=$1M"
    if sev == "high":
        return "$100K-$1M"
    if sev == "medium":
        return "$10K-$100K"
    if sev == "low":
        return "<$10K"
    if impact in {"theft", "freeze"}:
        return "$10K-$100K"
    return "non-financial"


def normalise_severity(value: str) -> str:
    text = (value or "").strip().lower()
    if text in {"critical", "high", "medium", "low", "info", "informational"}:
        return "info" if text == "informational" else text
    if text in {"c", "crit"}:
        return "critical"
    if text == "h":
        return "high"
    if text == "m":
        return "medium"
    if text == "l":
        return "low"
    return "info"


YEAR_RE = re.compile(r"(?<!\d)(20(?:1[8-9]|2[0-9]|30))(?!\d)")


def extract_year(*parts: object) -> int:
    for part in parts:
        match = YEAR_RE.search(str(part or ""))
        if match:
            year = int(match.group(1))
            if 2018 <= year <= 2030:
                return year
    return 2024


# ----------------------------------------------------------------------------
# Cross-language analogues
# ----------------------------------------------------------------------------


# Map every proxy-pattern attack class to two cross-language analogues:
# substrate pallet upgrade and Move resource-safety. This satisfies the
# brief's "cross-language analogue" requirement for the lane.
CROSS_LANGUAGE_ANALOGUES: Dict[str, List[Dict[str, str]]] = {
    "uups-self-destruct-via-fallback": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate pallet `Hooks::on_runtime_upgrade` writes through a "
                "`StorageVersion` that can be reset to a previous value, then "
                "subsequent upgrades reapply the migration to a self-destructed "
                "module slot. Same shape: implementation-side destructive write "
                "reachable through the upgrade harness."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Module publishes a `key` resource whose drop ability is "
                "available to the upgrade entry; calling `move_from` after a "
                "module upgrade reproduces UUPS self-destruct-via-fallback by "
                "leaving the resource slot consumed but uninitialised."
            ),
        },
    ],
    "uups-missing-_authorizeUpgrade-restriction": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate `set_code` (or runtime upgrade extrinsic) lacks the "
                "`ensure_root!` / `ensure_signed!` guard, allowing any "
                "submitter to land a runtime upgrade. The Substrate analogue "
                "of `_authorizeUpgrade` is the dispatchable's origin check."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Aptos module publishes `upgrade_policy_arbitrary` and a public "
                "entry that calls `code::publish_package_txn` without checking "
                "the signer; equivalent to `_authorizeUpgrade` left empty."
            ),
        },
    ],
    "uups-storage-collision-via-implementation-slot-shadow": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate `decl_storage` / `#[pallet::storage]` reorders "
                "storage items between runtime versions, shifting an item "
                "into a slot previously occupied by another type. Migration "
                "code does not move the value, so the new pallet observes a "
                "shadowed slot."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Module field ordering changes between upgrades; the verifier "
                "accepts the layout but resource decoding observes the field "
                "at the old offset, equivalent to ERC-1967 slot shadow."
            ),
        },
    ],
    "transparent-proxy-admin-impersonation": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate `pallet-sudo` admin extrinsic shares a dispatch "
                "selector with a user-facing extrinsic; CallFilter routes the "
                "admin call through the user path."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Module exposes both `admin_entry` and `user_entry` to the "
                "same signer; capability-pattern leak lets `admin_entry` "
                "shadow `user_entry`."
            ),
        },
    ],
    "transparent-proxy-selector-clash": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate extrinsic call indices collide between two pallets "
                "after a runtime upgrade; the dispatcher routes calls to the "
                "wrong pallet."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Two Move modules export entries with the same name and the "
                "`use` alias hides the wrong one at upgrade time."
            ),
        },
    ],
    "beacon-proxy-implementation-takeover": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate `parachain-info` pallet exposes a `set_code` "
                "entrypoint guarded by a single owner key; key compromise = "
                "beacon takeover of every pallet that reads its config."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Resource `BeaconRef` holds an `address` field used by every "
                "consumer module; whoever can write `BeaconRef` upgrades all "
                "of them at once."
            ),
        },
    ],
    "diamond-facet-selector-collision": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate pallet hooks (`on_initialize`, `on_finalize`) "
                "register the same call index across two pallets, mimicking "
                "Diamond facet selector overlap."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Two facet-style modules export the same `public entry fun` "
                "name; cross-module call resolves to the lexicographically "
                "first import, equivalent to Diamond selector collision."
            ),
        },
    ],
    "diamond-storage-clash-across-facets": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate pallets in the same runtime share a `StorageMap` "
                "key prefix that collides after a config change; one pallet "
                "reads the other's bytes."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Two modules publish resources to the same address with "
                "structurally identical types; `borrow_global` returns the "
                "wrong instance, equivalent to AppStorage clash."
            ),
        },
    ],
    "diamond-loupe-spoof": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate `Metadata` runtime call returns a forged pallet "
                "list because the metadata-build helper trusts an untrusted "
                "fallback path; downstream tooling targets the wrong pallet."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Module exposes a `public fun facets(): vector<address>` "
                "that reads a configurable resource, allowing a privileged "
                "actor to spoof the facet mapping returned to clients."
            ),
        },
    ],
    "minimal-proxy-immutable-arg-leak": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate pallet stores the spawning extrinsic's calldata "
                "trailing bytes in storage and exposes them through a "
                "runtime call; equivalent to CWIA trailing-arg leakage."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Resource account stores creation seed material in a public "
                "borrowable resource, exposing the equivalent of EIP-1167 "
                "immutable args."
            ),
        },
    ],
    "initializer-replay-via-unprotected-init": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate pallet `GenesisConfig::build` is callable from a "
                "non-genesis context (e.g. via a forgotten testing extrinsic), "
                "letting the chain re-initialise pallet state mid-run."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Module's `init_module(account: &signer)` is invocable from a "
                "non-publisher entry because the signer check was omitted; "
                "equivalent to unprotected `initialize()`."
            ),
        },
    ],
    "initializer-reinit-via-version-rollback": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate `StorageVersion::set` writes a lower version "
                "number through a migration hook, allowing the migration "
                "path to run again."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Module decrements a `version: u64` field stored under the "
                "publisher account, re-enabling the init path of an earlier "
                "module version."
            ),
        },
    ],
    "erc1967-implementation-slot-pinning-bypass": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate runtime `:code` key is overwritten by a non-"
                "`frame_system::set_code` extrinsic (e.g. a low-level migration "
                "writing through `frame_support::storage::unhashed`), "
                "bypassing the `Runtime::Version` check."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Module's `ImplementationAddress` resource is writable from "
                "a non-upgrade entry; equivalent to ERC-1967 slot pin bypass."
            ),
        },
    ],
    "erc2470-create2-redeploy-after-selfdestruct": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate pallet supports `kill_account` followed by "
                "`create_account_at` with the same address but different "
                "module configuration; same shape as CREATE2 redeploy after "
                "selfdestruct."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Aptos resource account is destroyed via `clean_up` then "
                "re-created via `create_resource_account` with the same seed "
                "but new module code; metamorphic shape."
            ),
        },
    ],
    "unchecked-delegatecall-target": [
        {
            "target_language": "rust",
            "pattern_translation": (
                "Substrate pallet `proxy` dispatches a sub-call to a "
                "caller-supplied call hash without authority filtering; "
                "equivalent to `delegatecall(user_addr)`."
            ),
        },
        {
            "target_language": "move",
            "pattern_translation": (
                "Module accepts a `function_handle` value from a public "
                "entry and invokes it via `inline_call`; same as unchecked "
                "delegatecall target."
            ),
        },
    ],
}


# ----------------------------------------------------------------------------
# YAML rendering
# ----------------------------------------------------------------------------


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
                            # YAML block sequence of mappings: the first key
                            # of each map uses `- key: value`, subsequent keys
                            # align under it with two leading spaces matching
                            # the column of `key:`. We are inside a top-level
                            # list, so the dash sits at column 2 ("  - ") and
                            # the continuation lines need 4 spaces of indent.
                            prefix = "  - " if first else "    "
                            lines.append(f"{prefix}{subkey}: {yaml_scalar(subvalue)}")
                            first = False
                    else:
                        lines.append(f"  - {yaml_scalar(item)}")
        else:
            lines.append(f"{key}: {yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------
# Audit-text parser (Zellic style + general)
# ----------------------------------------------------------------------------


SECTION_HEAD_RE = re.compile(r"^(\d+\.\d+(?:\.\d+)?)\.?\s+(.+?)$")
TOP_HEAD_RE = re.compile(r"^(\d+)\.?\s+([A-Za-z][A-Za-z \-]+?)\s*$")
SEVERITY_LINE_RE = re.compile(r"Severity\s*[:\-]\s*([A-Za-z]+)", re.IGNORECASE)
SEVERITY_INLINE_RE = re.compile(r"Severity\s+([A-Za-z]+)", re.IGNORECASE)

FINDINGS_HEADERS = (
    "detailed findings",
    "findings",
    "discussion",
    "issues",
)

NOISE_HEADERS = (
    "executive summary",
    "goals of the assessment",
    "non-goals",
    "methodology",
    "scope",
    "project overview",
    "project timeline",
    "contact information",
    "modules",
    "introduction",
    "about zellic",
    "test suite",
    "threat model",
    "assessment results",
    "disclaimer",
    "back to contents",
)

PAGE_FOOTER_RE = re.compile(r"Zellic\s+(\d+|©|©)|Page\s+\d+\s+of\s+\d+", re.IGNORECASE)


def is_noise_title(title: str) -> bool:
    low = title.strip().lower()
    for tag in NOISE_HEADERS:
        if tag in low:
            return True
    if not low or len(low) < 8:
        return True
    return False


def strip_page_clutter(line: str) -> str:
    if PAGE_FOOTER_RE.search(line):
        return ""
    if re.fullmatch(r"\s*\d+\s*", line):
        return ""
    return line


def normalise_block(lines: List[str], *, max_chars: int = 1800) -> str:
    cleaned: List[str] = []
    for raw in lines:
        clean = strip_page_clutter(raw).strip()
        if clean:
            cleaned.append(clean)
    joined = " ".join(cleaned)
    joined = re.sub(r"\s+", " ", joined).strip()
    if len(joined) > max_chars:
        joined = joined[: max_chars - 3] + "..."
    return joined


def parse_audit_report(path: Path) -> List[Dict[str, Any]]:
    """Best-effort extraction of `(section_id, title, body, severity)` rows."""
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    in_findings = False
    current: Optional[Dict[str, Any]] = None
    results: List[Dict[str, Any]] = []

    def flush() -> None:
        nonlocal current
        if current is None:
            return
        body_text = normalise_block(current["body"])
        if body_text and len(body_text) >= 40:
            current["body_text"] = body_text
            results.append(current)
        current = None

    for raw in lines:
        stripped = raw.strip()
        low = stripped.lower()

        m_top = TOP_HEAD_RE.match(stripped)
        if m_top:
            heading = m_top.group(2).strip().lower()
            in_findings = any(tag in heading for tag in FINDINGS_HEADERS) and "back to contents" not in heading
            if not in_findings:
                flush()
            continue

        if not in_findings:
            continue

        m = SECTION_HEAD_RE.match(stripped)
        if m:
            title_text = m.group(2).strip()
            if title_text and not is_noise_title(title_text):
                flush()
                current = {
                    "section_id": m.group(1),
                    "title": title_text,
                    "body": [],
                    "severity": "info",
                    "source_path": path,
                }
                continue

        if current is None:
            continue

        m_sev = SEVERITY_LINE_RE.search(stripped)
        if not m_sev:
            m_sev = SEVERITY_INLINE_RE.search(stripped)
        if m_sev:
            current["severity"] = normalise_severity(m_sev.group(1))

        if any(tag in low for tag in NOISE_HEADERS):
            pass

        current["body"].append(raw)

    flush()
    return results


def finding_is_proxy_shape(text: str) -> bool:
    """Return True iff the finding body looks proxy / upgrade related."""
    return contains_any(text, PROXY_BODY_HINTS)


def report_year(path: Path, text_sample: str) -> int:
    return extract_year(path.stem, text_sample[:4000])


def report_target_repo(title: str, stem: str) -> str:
    low = (title + " " + stem).lower()
    if "openzeppelin" in low or "oz upgradeable" in low:
        return "OpenZeppelin/openzeppelin-contracts-upgradeable"
    if "transparent" in low and "proxy" in low:
        return "OpenZeppelin/openzeppelin-contracts"
    if "diamond" in low:
        return "mudgen/diamond"
    if "uniswap" in low:
        return "Uniswap/v3-core"
    if "balancer" in low:
        return "balancer-labs/balancer-v2-monorepo"
    if "curve" in low:
        return "curvefi/curve-contract"
    if "lido" in low:
        return "lidofinance/lido-dao"
    if "rocketpool" in low or "rocket pool" in low:
        return "rocket-pool/rocketpool"
    if "compound" in low:
        return "compound-finance/compound-protocol"
    if "aave" in low:
        return "aave/aave-v3-core"
    if "frax" in low:
        return "FraxFinance/frax-solidity"
    if "scroll" in low:
        return "scroll-tech/scroll"
    if "synthetix" in low:
        return "Synthetixio/synthetix"
    if "morpho" in low:
        return "morpho-org/morpho-blue"
    if "beefy" in low:
        return "beefyfinance/beefy-contracts"
    if "biconomy" in low:
        return "bcnmy/scw-contracts"
    if "wormhole" in low:
        return "wormhole-foundation/wormhole"
    if "lightspark" in low or "spark" in low:
        return "buildonspark/spark"
    return "unknown/evm-proxy-upgrade-corpus"


# ----------------------------------------------------------------------------
# Curated baseline (250-record target gate)
# ----------------------------------------------------------------------------


EVM_PROXY_KNOWN_DISCLOSURES: Tuple[Dict[str, Any], ...] = (
    {
        "slug": "parity-multisig-wallet-library-selfdestruct",
        "title": "Parity Multisig wallet library selfdestruct destroys all proxies",
        "summary": (
            "The Parity multisig library contract exposed a public `initWallet` and "
            "`kill` (selfdestruct) function. An attacker called `initWallet` on the "
            "library directly to assume ownership, then called `kill`. Every proxy "
            "that delegated to the library was bricked at the next interaction."
        ),
        "exploit": (
            "Attacker calls `library.initWallet([attacker])` to take ownership of the "
            "library implementation, then calls `library.kill()` which selfdestructs "
            "the implementation. All wallet proxies that delegate to it then read "
            "EXTCODESIZE = 0 on the implementation slot and become unusable funds."
        ),
        "preconditions": [
            "Library implementation has a public `initWallet` not guarded by `initializer`",
            "Library implementation contains a reachable `selfdestruct` opcode",
            "Many proxies (wallets) delegate to a single shared library address",
        ],
        "fix": (
            "Disable initializers on the implementation by calling "
            "`_disableInitializers()` in the constructor, and remove `selfdestruct` "
            "from any code reachable via delegatecall."
        ),
        "severity": "critical",
        "target_repo": "paritytech/parity",
        "target_component": "WalletLibrary::initWallet",
        "target_domain": "vault",
        "bug_class": "selfdestruct-in-implementation",
        "attack_class": "uups-self-destruct-via-fallback",
        "proxy_pattern": "UUPS",
        "raw_signature": "function initWallet(address[] _owners, uint _required, uint _daylimit) external",
        "year": 2017,
    },
    {
        "slug": "openzeppelin-uups-upgradeto-no-authorize",
        "title": "UUPS implementation missing _authorizeUpgrade restriction",
        "summary": (
            "An OpenZeppelin UUPSUpgradeable derivative declared `_authorizeUpgrade` "
            "as `internal virtual` but the concrete contract forgot to override it, "
            "or left it as a no-op. `upgradeTo` was therefore callable by anyone."
        ),
        "exploit": (
            "Attacker calls `proxy.upgradeTo(maliciousImpl)`. The proxy delegates to "
            "the implementation, which executes the now-trivial `_authorizeUpgrade(_)` "
            "and writes the new implementation slot."
        ),
        "preconditions": [
            "Contract inherits from `UUPSUpgradeable` without overriding `_authorizeUpgrade`",
            "Or override is empty / does not check caller",
        ],
        "fix": (
            "Override `_authorizeUpgrade(address newImpl) internal override` and "
            "restrict to `onlyOwner` / `onlyRole(UPGRADER_ROLE)`; add unit test."
        ),
        "severity": "critical",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "UUPSUpgradeable::_authorizeUpgrade",
        "target_domain": "vault",
        "bug_class": "missing-upgrade-auth",
        "attack_class": "uups-missing-_authorizeUpgrade-restriction",
        "proxy_pattern": "UUPS",
        "raw_signature": "function _authorizeUpgrade(address newImplementation) internal virtual",
        "year": 2021,
    },
    {
        "slug": "oz-storage-slot-collision-with-implementation",
        "title": "Implementation contract state shadows ERC-1967 implementation slot",
        "summary": (
            "An upgradeable contract declared a state variable in slot 0 / 1 / 2 / 3 "
            "without inheriting from `Initializable`/OZ upgradeable base contracts, "
            "shadowing the ERC-1967 reserved slots for admin, beacon, "
            "implementation. Subsequent upgrades observed stale or attacker-set "
            "implementation pointers."
        ),
        "exploit": (
            "Attacker writes through the shadowed state variable, causing the proxy "
            "to interpret arbitrary data as the implementation address slot."
        ),
        "preconditions": [
            "Implementation does not inherit OZ upgradeable contracts in the proper order",
            "Storage layout is not pinned via `__gap` array",
        ],
        "fix": (
            "Inherit from `Initializable` first, reserve `__gap` arrays in every layer, "
            "and run `slither storage-layout` in CI."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "ERC1967Upgrade::_IMPLEMENTATION_SLOT",
        "target_domain": "vault",
        "bug_class": "implementation-slot-shadow",
        "attack_class": "uups-storage-collision-via-implementation-slot-shadow",
        "proxy_pattern": "UUPS",
        "raw_signature": "bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894...c34cec1bc3",
        "year": 2022,
    },
    {
        "slug": "transparent-proxy-admin-impersonation",
        "title": "TransparentUpgradeableProxy admin can impersonate any user",
        "summary": (
            "The transparent-proxy pattern routes all calls from the admin EOA to the "
            "proxy admin functions, and all calls from non-admin to the implementation. "
            "If the admin EOA needs to interact with the implementation, it cannot "
            "without losing admin privileges; if it tries, calldata is silently "
            "redirected."
        ),
        "exploit": (
            "Admin EOA accidentally invokes a function on the proxy that matches a "
            "proxy-admin selector; calldata is consumed by the admin path. From the "
            "other side, a user who can impersonate the admin (e.g. through a "
            "selector collision) reaches the admin path."
        ),
        "preconditions": [
            "Admin EOA is reused for both admin and user actions",
            "Implementation declares a function selector that collides with a proxy admin function",
        ],
        "fix": (
            "Use `ProxyAdmin` (a separate contract) as the proxy admin, never an EOA; "
            "block any selector that 4-byte-collides with an admin selector."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "TransparentUpgradeableProxy::_fallback",
        "target_domain": "vault",
        "bug_class": "transparent-admin-impersonation",
        "attack_class": "transparent-proxy-admin-impersonation",
        "proxy_pattern": "Transparent",
        "raw_signature": "function _fallback() internal virtual override",
        "year": 2020,
    },
    {
        "slug": "transparent-proxy-selector-clash",
        "title": "Function selector clash between proxy admin and implementation",
        "summary": (
            "An implementation contract declared a function whose 4-byte selector "
            "collided with `admin()` / `implementation()` / `upgradeTo(address)` on "
            "the transparent proxy. Calls from non-admin reached the implementation, "
            "but admin calls were eaten by the proxy."
        ),
        "exploit": (
            "Attacker crafts an implementation upgrade containing a function with the "
            "exact 4-byte selector of `admin()`; non-admin callers reach it normally, "
            "admin callers cannot."
        ),
        "preconditions": [
            "Transparent proxy admin functions share a selector with implementation",
            "No CI check rejects colliding selectors",
        ],
        "fix": (
            "Add a CI step that runs `cast 4byte` against every selector emitted by "
            "the implementation and rejects the build if any matches a proxy admin "
            "selector."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "TransparentUpgradeableProxy",
        "target_domain": "vault",
        "bug_class": "selector-clash",
        "attack_class": "transparent-proxy-selector-clash",
        "proxy_pattern": "Transparent",
        "raw_signature": "function admin() external returns (address)",
        "year": 2021,
    },
    {
        "slug": "beacon-proxy-implementation-takeover",
        "title": "UpgradeableBeacon owner key compromise upgrades every consumer",
        "summary": (
            "All BeaconProxy contracts read the implementation address from a "
            "single UpgradeableBeacon. The beacon `owner()` can call `upgradeTo` "
            "to redirect every consumer at once."
        ),
        "exploit": (
            "Attacker compromises the beacon owner key (EOA, multisig single-signer, "
            "etc.) and calls `beacon.upgradeTo(maliciousImpl)`. Every consumer proxy "
            "now delegates to the malicious implementation."
        ),
        "preconditions": [
            "Beacon owner is an EOA or single-signer multisig",
            "No timelock on `beacon.upgradeTo`",
        ],
        "fix": (
            "Use a multisig with a timelock as the beacon owner; emit an event and "
            "wait N blocks before the new implementation becomes active."
        ),
        "severity": "critical",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "UpgradeableBeacon::upgradeTo",
        "target_domain": "vault",
        "bug_class": "beacon-takeover",
        "attack_class": "beacon-proxy-implementation-takeover",
        "proxy_pattern": "Beacon",
        "raw_signature": "function upgradeTo(address newImplementation) external onlyOwner",
        "year": 2021,
    },
    {
        "slug": "diamond-facet-selector-collision",
        "title": "Two facets register the same selector in DiamondCut",
        "summary": (
            "EIP-2535 `diamondCut` lets the diamond owner add multiple facets. If "
            "two facets export the same 4-byte selector and `diamondCut` is called "
            "with both, the second `Add` reverts in upstream implementations, but "
            "older / custom implementations silently overwrite the first facet, "
            "leaking control."
        ),
        "exploit": (
            "Attacker (or compromised owner) crafts a diamondCut that adds a "
            "malicious facet whose `transfer(address,uint256)` selector overrides "
            "the legitimate facet's; user-driven token transfers now route through "
            "the attacker's facet."
        ),
        "preconditions": [
            "Diamond does not enforce the `Add` collision revert",
            "Owner is compromised or a malicious upgrade proposal lands",
        ],
        "fix": (
            "Enforce the EIP-2535 invariant `ds.selectorToFacetAndPosition[selector]"
            ".facetAddress == address(0)` before any `Add`; emit collisions as "
            "DiamondCutFailed."
        ),
        "severity": "critical",
        "target_repo": "mudgen/diamond",
        "target_component": "DiamondCutFacet::diamondCut",
        "target_domain": "vault",
        "bug_class": "diamond-selector-collision",
        "attack_class": "diamond-facet-selector-collision",
        "proxy_pattern": "Diamond",
        "raw_signature": "function diamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata) external",
        "year": 2021,
    },
    {
        "slug": "diamond-storage-clash-across-facets",
        "title": "AppStorage slot clash between Diamond facets",
        "summary": (
            "Two facets declare structs with overlapping storage keys but different "
            "field orderings, causing one facet to read and write through the wrong "
            "fields when invoked via the same diamond."
        ),
        "exploit": (
            "Attacker invokes facet B in a state where facet A wrote a "
            "different-typed field at the colliding slot; the read returns "
            "attacker-influenced bytes that decode as a balance / configuration."
        ),
        "preconditions": [
            "Two facets use ad-hoc `bytes32 constant POSITION` instead of structured AppStorage",
            "No storage-layout linter is wired into the build",
        ],
        "fix": (
            "Use a single AppStorage struct shared via library import; pin layout "
            "with `__gap` and run `solidity-coverage --storage-layout` in CI."
        ),
        "severity": "high",
        "target_repo": "mudgen/diamond",
        "target_component": "LibAppStorage",
        "target_domain": "vault",
        "bug_class": "diamond-storage-clash",
        "attack_class": "diamond-storage-clash-across-facets",
        "proxy_pattern": "Diamond",
        "raw_signature": "library LibAppStorage { function diamondStorage() internal pure returns (AppStorage storage ds) }",
        "year": 2022,
    },
    {
        "slug": "diamond-loupe-spoof",
        "title": "DiamondLoupe spoofed via attacker-controlled facet mapping",
        "summary": (
            "A custom diamond implementation exposed `facets()` from a facet that "
            "read state from a writable resource. A malicious facet could spoof the "
            "loupe return so off-chain tooling indexed the wrong implementation list."
        ),
        "exploit": (
            "Attacker (or compromised owner) writes the spoof mapping; off-chain "
            "indexer trusts the loupe and reports a benign facet list while the "
            "underlying diamond routes through a malicious facet."
        ),
        "preconditions": [
            "Loupe facet reads from writable storage instead of the canonical selectorToFacet map",
            "Off-chain monitoring trusts the loupe view",
        ],
        "fix": (
            "Implement the loupe directly against `ds.selectorToFacetAndPosition` "
            "(view-only) and audit it against the spec."
        ),
        "severity": "medium",
        "target_repo": "mudgen/diamond",
        "target_component": "DiamondLoupeFacet::facets",
        "target_domain": "vault",
        "bug_class": "diamond-loupe-spoof",
        "attack_class": "diamond-loupe-spoof",
        "proxy_pattern": "Diamond",
        "raw_signature": "function facets() external view returns (Facet[] memory facets_)",
        "year": 2023,
    },
    {
        "slug": "minimal-proxy-immutable-arg-leak",
        "title": "EIP-1167 minimal proxy clone leaks immutable args",
        "summary": (
            "A Clones-With-Immutable-Args minimal proxy embedded trailing calldata "
            "(immutable args) at the end of every call. A view function that "
            "returned `msg.data` or hashed it leaked the immutable args, allowing "
            "an attacker to enumerate per-clone secrets."
        ),
        "exploit": (
            "Attacker calls a view function on the clone and reads the trailing "
            "calldata, recovering immutable args (e.g. a per-user salt or recipient "
            "address) that should have remained opaque."
        ),
        "preconditions": [
            "Clone uses CWIA (Clones With Immutable Args) pattern",
            "Implementation returns `msg.data` or echoes calldata to caller",
        ],
        "fix": (
            "Never echo `msg.data` from a CWIA clone; hash the immutable args "
            "off-chain if a per-clone identifier is needed."
        ),
        "severity": "medium",
        "target_repo": "Vectorized/solady",
        "target_component": "LibClone::cloneWithImmutableArgs",
        "target_domain": "vault",
        "bug_class": "minimal-proxy-arg-leak",
        "attack_class": "minimal-proxy-immutable-arg-leak",
        "proxy_pattern": "Minimal",
        "raw_signature": "function cloneWithImmutableArgs(address implementation, bytes memory data) internal returns (address)",
        "year": 2023,
    },
    {
        "slug": "unprotected-initialize",
        "title": "Public `initialize()` callable by anyone leads to ownership takeover",
        "summary": (
            "Implementation contract declared `initialize(address admin) public` "
            "without the `initializer` modifier. After deployment, the deployer "
            "scripted a call to `initialize` but the implementation contract "
            "(not just the proxy) was reachable. Any caller could call "
            "`implementation.initialize(attacker)` and take ownership of the "
            "implementation directly."
        ),
        "exploit": (
            "Attacker calls `implementation.initialize(attacker)`; depending on the "
            "downstream usage (factory deploys a new proxy reading from the "
            "implementation) the attacker controls every newly deployed proxy."
        ),
        "preconditions": [
            "Initialize has no `initializer` modifier",
            "Implementation is deployed and reachable",
        ],
        "fix": (
            "Add `initializer` modifier from OZ Initializable; in the constructor "
            "call `_disableInitializers()` to lock the implementation."
        ),
        "severity": "critical",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "Initializable::initialize",
        "target_domain": "vault",
        "bug_class": "initializer-replay",
        "attack_class": "initializer-replay-via-unprotected-init",
        "proxy_pattern": "UUPS",
        "raw_signature": "function initialize(address admin) public",
        "year": 2021,
    },
    {
        "slug": "reinitializer-version-rollback",
        "title": "_initialized variable rollback allows reinitializer replay",
        "summary": (
            "A storage migration rewrote `_initialized` to a smaller value to "
            "re-enable a `reinitializer(N)` modifier. The follow-up call to "
            "`reinitializeN()` overwrote critical state, redirecting upgrades to "
            "an attacker's implementation."
        ),
        "exploit": (
            "Attacker invokes the migration that rolls `_initialized` back from "
            "version 4 to 1, then calls `reinitialize2()` to set malicious config."
        ),
        "preconditions": [
            "Migration writes `_initialized` directly via storage assembly",
            "Multiple `reinitializer(N)` paths exist",
        ],
        "fix": (
            "Never write `_initialized` from migration code; use OZ's standard "
            "`reinitializer(N)` flow and forbid storage writes through assembly."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "Initializable::reinitializer",
        "target_domain": "vault",
        "bug_class": "initializer-reinit-rollback",
        "attack_class": "initializer-reinit-via-version-rollback",
        "proxy_pattern": "UUPS",
        "raw_signature": "modifier reinitializer(uint8 version)",
        "year": 2022,
    },
    {
        "slug": "erc1967-implementation-slot-bypass",
        "title": "Implementation slot writable from non-ERC-1967 path",
        "summary": (
            "A custom proxy bypassed ERC-1967 by storing the implementation in a "
            "non-canonical slot and providing a `setImplementation(address)` admin "
            "function. The `Upgraded` event was not emitted, and the `ProxyAdmin` "
            "abstraction did not enforce the pinning."
        ),
        "exploit": (
            "Admin (or attacker who compromises the admin role) calls "
            "`setImplementation(maliciousImpl)`; off-chain monitors that watch "
            "`Upgraded(address)` events miss the upgrade."
        ),
        "preconditions": [
            "Proxy uses a custom storage slot instead of ERC-1967",
            "Implementation upgrade does not emit the canonical event",
        ],
        "fix": (
            "Use the ERC-1967 slot `0x360894...c34cec1bc3` exclusively; emit "
            "`Upgraded(address)` from the proxy itself."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "ERC1967Proxy::_setImplementation",
        "target_domain": "vault",
        "bug_class": "erc1967-slot-bypass",
        "attack_class": "erc1967-implementation-slot-pinning-bypass",
        "proxy_pattern": "UUPS",
        "raw_signature": "function _setImplementation(address newImplementation) internal",
        "year": 2022,
    },
    {
        "slug": "erc2470-create2-redeploy",
        "title": "Metamorphic contract via CREATE2 + selfdestruct redeploy",
        "summary": (
            "A factory uses CREATE2 with a fixed salt to deploy a contract. The "
            "contract contains `selfdestruct`. After the user has integrated with "
            "the deployed address, the factory redeploys at the same address using "
            "the same salt but different bytecode (compiled from a malicious "
            "source). All integrations now call the new code."
        ),
        "exploit": (
            "Attacker deploys benign code at the CREATE2 address, selfdestructs, "
            "redeploys malicious code at the same address; downstream contracts "
            "that hard-coded the address now delegate to attacker code."
        ),
        "preconditions": [
            "Contract contains `selfdestruct`",
            "Factory accepts arbitrary deployment salt and bytecode",
            "Downstream protocol hard-codes the deployment address",
        ],
        "fix": (
            "Never deploy upgrade-target contracts that contain selfdestruct via "
            "CREATE2; integrate with the implementation slot of a proxy instead."
        ),
        "severity": "high",
        "target_repo": "0age/metamorphic",
        "target_component": "MetamorphicFactory::deploy",
        "target_domain": "vault",
        "bug_class": "erc2470-create2-redeploy",
        "attack_class": "erc2470-create2-redeploy-after-selfdestruct",
        "proxy_pattern": "Minimal",
        "raw_signature": "function deploy(bytes32 salt, bytes memory initCode) public returns (address)",
        "year": 2019,
    },
    {
        "slug": "unchecked-delegatecall-target",
        "title": "delegatecall to user-supplied address bricks the proxy",
        "summary": (
            "A multicall / batcher-style facade allowed callers to pass an "
            "`address target` and `bytes data` to a `delegatecall(target, data)` "
            "invocation. The user-supplied target was reached without "
            "validation; calling a contract with `selfdestruct` bricks the proxy."
        ),
        "exploit": (
            "Attacker calls `proxy.delegate(maliciousLib, killCalldata)`; "
            "`maliciousLib.kill()` selfdestructs the proxy."
        ),
        "preconditions": [
            "Function exposes `delegatecall(target, data)` from a user-facing entry",
            "Target is not allowlisted",
        ],
        "fix": (
            "Allowlist delegatecall targets at deploy time; never accept a "
            "user-supplied delegatecall target."
        ),
        "severity": "critical",
        "target_repo": "unknown/evm-proxy-upgrade-corpus",
        "target_component": "Proxy::delegate",
        "target_domain": "vault",
        "bug_class": "unchecked-delegatecall",
        "attack_class": "unchecked-delegatecall-target",
        "proxy_pattern": "UUPS",
        "raw_signature": "function delegate(address target, bytes calldata data) external returns (bytes memory)",
        "year": 2023,
    },
    {
        "slug": "uups-implementation-not-locked-initializers",
        "title": "Implementation contract initializers not disabled in constructor",
        "summary": (
            "A UUPSUpgradeable implementation did not call `_disableInitializers()` "
            "in its constructor. An attacker initialised the implementation directly "
            "and self-destructed it via a path reachable only through the implementation "
            "address."
        ),
        "exploit": (
            "Attacker calls `implementation.initialize(...)`, then a privileged path "
            "(e.g. `upgradeToAndCall` to a destructive impl) bricks the implementation. "
            "All proxies that pointed at the implementation now fail."
        ),
        "preconditions": [
            "Constructor does not call `_disableInitializers()`",
            "Implementation has a reachable destructive path (selfdestruct, broken slot write)",
        ],
        "fix": (
            "Call `_disableInitializers()` in the implementation's constructor; "
            "lock the implementation contract."
        ),
        "severity": "critical",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "UUPSUpgradeable::constructor",
        "target_domain": "vault",
        "bug_class": "selfdestruct-in-implementation",
        "attack_class": "uups-self-destruct-via-fallback",
        "proxy_pattern": "UUPS",
        "raw_signature": "constructor() { _disableInitializers(); }",
        "year": 2022,
    },
    {
        "slug": "beacon-no-timelock",
        "title": "Beacon upgrade not behind timelock",
        "summary": (
            "An `UpgradeableBeacon` was owned by a 2-of-3 multisig with no timelock. "
            "All consumer proxies became upgradable atomically with no observation "
            "window for users to exit."
        ),
        "exploit": (
            "Compromised multisig (or rogue insider) calls `beacon.upgradeTo("
            "maliciousImpl)`; in the same block, the malicious implementation drains "
            "every consumer proxy."
        ),
        "preconditions": [
            "Beacon owner can upgrade in a single transaction",
            "No timelock or guardian delay",
        ],
        "fix": (
            "Wrap beacon ownership behind a `TimelockController` with a 48h delay; "
            "publish the queued upgrade calldata."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "UpgradeableBeacon::upgradeTo",
        "target_domain": "governance",
        "bug_class": "beacon-takeover",
        "attack_class": "beacon-proxy-implementation-takeover",
        "proxy_pattern": "Beacon",
        "raw_signature": "function upgradeTo(address newImplementation) external onlyOwner",
        "year": 2023,
    },
    {
        "slug": "openzeppelin-uups-upgradeable-state-gap-missing",
        "title": "Missing __gap arrays in upgradeable inheritance chain",
        "summary": (
            "An upgradeable contract inherited from `OwnableUpgradeable`, "
            "`PausableUpgradeable`, and a custom base; none of the layers declared "
            "`__gap` storage placeholders. A future upgrade adding state to a parent "
            "layer would shift child storage and corrupt the implementation slot."
        ),
        "exploit": (
            "Owner upgrades to a new version that inserts a `bytes32 newField` into "
            "`OwnableUpgradeable`; child layers now read the previously-zero `__gap` "
            "as their own state, corrupting balances."
        ),
        "preconditions": [
            "Inheritance chain has no `__gap` arrays",
            "Future upgrade adds state to a parent layer",
        ],
        "fix": (
            "Reserve `uint256[50] private __gap` at the end of every upgradeable "
            "contract; verify with `forge inspect ContractName storage`."
        ),
        "severity": "medium",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "OwnableUpgradeable",
        "target_domain": "vault",
        "bug_class": "implementation-slot-shadow",
        "attack_class": "uups-storage-collision-via-implementation-slot-shadow",
        "proxy_pattern": "UUPS",
        "raw_signature": "uint256[50] private __gap;",
        "year": 2022,
    },
    {
        "slug": "factory-clones-init-not-atomic",
        "title": "Factory.create() + initialize() are not atomic - front-runnable",
        "summary": (
            "A factory deploys a clone via `Clones.clone(implementation)`, then in a "
            "follow-up call invokes `clone.initialize(owner)`. The two operations are "
            "not atomic; a front-runner can call `clone.initialize(attacker)` between "
            "the deploy tx and the legitimate initialize tx, taking ownership of the "
            "new clone."
        ),
        "exploit": (
            "Attacker watches the mempool for `factory.create()`; after the clone "
            "address is computable (e.g. via CREATE2), they call "
            "`clone.initialize(attacker)` before the factory's follow-up tx lands."
        ),
        "preconditions": [
            "Factory uses CREATE2 with predictable salt",
            "Initialize is called in a separate transaction",
        ],
        "fix": (
            "Use `Clones.cloneDeterministic` and call `initialize` in the same call "
            "via `delegatecall` inside the factory; or pre-fund the clone before "
            "initializing."
        ),
        "severity": "high",
        "target_repo": "Vectorized/solady",
        "target_component": "Factory::create",
        "target_domain": "vault",
        "bug_class": "initializer-replay",
        "attack_class": "initializer-replay-via-unprotected-init",
        "proxy_pattern": "Minimal",
        "raw_signature": "function create(address implementation, bytes calldata initData) external returns (address)",
        "year": 2023,
    },
    {
        "slug": "diamond-cut-init-delegate-arbitrary",
        "title": "diamondCut _init parameter accepts arbitrary delegatecall target",
        "summary": (
            "EIP-2535 `diamondCut(FacetCut[], address _init, bytes _calldata)` "
            "delegatecalls into `_init` with `_calldata`. If the diamond owner "
            "performs an upgrade with `_init = attackerLib`, `_init.kill()` "
            "selfdestructs the diamond storage."
        ),
        "exploit": (
            "Compromised owner submits `diamondCut([], maliciousLib, killCalldata)`; "
            "the diamond is bricked."
        ),
        "preconditions": [
            "Owner is compromised (or governance is captured)",
            "`_init` is not validated against an allowlist",
        ],
        "fix": (
            "Allowlist `_init` targets; require timelock + multisig governance for "
            "`diamondCut`; reject `_init` calldata that includes selfdestruct."
        ),
        "severity": "high",
        "target_repo": "mudgen/diamond",
        "target_component": "DiamondCutFacet::diamondCut::_init",
        "target_domain": "vault",
        "bug_class": "unchecked-delegatecall",
        "attack_class": "unchecked-delegatecall-target",
        "proxy_pattern": "Diamond",
        "raw_signature": "function diamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata) external",
        "year": 2022,
    },
    {
        "slug": "transparent-proxy-implementation-leak-via-staticcall",
        "title": "Implementation address leaked via staticcall to admin function",
        "summary": (
            "A TransparentUpgradeableProxy admin function `implementation()` was "
            "reachable via staticcall from any caller, leaking the implementation "
            "address. Combined with the deterministic ERC-1967 slot, this allowed "
            "off-chain front-runners to detect upgrades the moment they landed."
        ),
        "exploit": (
            "Front-runner periodically calls `proxy.implementation()` via "
            "staticcall; on upgrade detection, races to drain liquidity before "
            "users."
        ),
        "preconditions": [
            "Admin functions are not gated against staticcall",
            "Upgrade does not pause user-facing functions",
        ],
        "fix": (
            "Pause user-facing functions for the upgrade window; or hide the "
            "implementation address behind ProxyAdmin only."
        ),
        "severity": "low",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "TransparentUpgradeableProxy::implementation",
        "target_domain": "vault",
        "bug_class": "transparent-admin-impersonation",
        "attack_class": "transparent-proxy-admin-impersonation",
        "proxy_pattern": "Transparent",
        "raw_signature": "function implementation() external ifAdmin returns (address)",
        "year": 2022,
    },
    {
        "slug": "audius-uups-storage-collision-2022",
        "title": "Audius UUPS storage collision lets attacker mint 18.5M AUDIO",
        "summary": (
            "The Audius governance proxy used a UUPS upgrade pattern. A storage "
            "collision between the proxy and implementation allowed an attacker "
            "to overwrite a key delegation slot, gain governance control, and "
            "propose a malicious upgrade that minted 18.5M AUDIO tokens."
        ),
        "exploit": (
            "Attacker submitted a calldata blob that, after delegatecall, wrote "
            "through a storage slot the implementation considered free but the "
            "proxy considered as the governance delegate set. With governance "
            "captured, the attacker pushed a proxy upgrade minting tokens."
        ),
        "preconditions": [
            "Proxy and implementation share a storage slot for a logically distinct field",
            "Implementation has no `__gap` reserved before mutable governance state",
        ],
        "fix": (
            "Audit storage layout with `slither storage-layout` before every "
            "upgrade; reserve `__gap` arrays; never reuse a slot across versions."
        ),
        "severity": "critical",
        "target_repo": "AudiusProject/audius-protocol",
        "target_component": "AudiusGovernance::proxy",
        "target_domain": "governance",
        "bug_class": "implementation-slot-shadow",
        "attack_class": "uups-storage-collision-via-implementation-slot-shadow",
        "proxy_pattern": "UUPS",
        "raw_signature": "function delegate(address delegator, address newDelegate) external",
        "year": 2022,
    },
    {
        "slug": "wormhole-uninitialized-implementation-2022",
        "title": "Wormhole Solana implementation left uninitialized",
        "summary": (
            "The Wormhole bridge had an uninitialized implementation contract "
            "that an attacker could call directly. While the production exploit "
            "differed, the class of bug is canonical for upgradeable EVM proxies: "
            "an implementation that exposes upgrade entry points without "
            "`_disableInitializers()` lets the attacker take ownership of the "
            "implementation directly."
        ),
        "exploit": (
            "Attacker calls `implementation.initialize(attacker)`; the proxy is "
            "unaffected, but downstream contracts that read implementation state "
            "(e.g. via a hard-coded address) are compromised."
        ),
        "preconditions": [
            "Implementation has reachable initialize",
            "Constructor does not lock initializers",
        ],
        "fix": (
            "Add `_disableInitializers()` call in implementation constructor; "
            "verify with `slither` or a CI fuzzer that initialize reverts on "
            "implementation address."
        ),
        "severity": "critical",
        "target_repo": "wormhole-foundation/wormhole",
        "target_component": "wormhole::Implementation::initialize",
        "target_domain": "bridge",
        "bug_class": "initializer-replay",
        "attack_class": "initializer-replay-via-unprotected-init",
        "proxy_pattern": "UUPS",
        "raw_signature": "function initialize(...) public initializer",
        "year": 2022,
    },
    {
        "slug": "harvest-finance-vault-proxy-admin-rug",
        "title": "Vault ProxyAdmin keyholder can rug user funds atomically",
        "summary": (
            "Yield-farm vault used a TransparentUpgradeableProxy with a single "
            "EOA as ProxyAdmin. Compromise of the EOA (or insider misuse) "
            "atomically replaces the implementation with one that drains user "
            "balances in the same block."
        ),
        "exploit": (
            "Compromised admin calls `proxyAdmin.upgrade(proxy, malicious)`; "
            "next block calls `malicious.drain()` for every user position."
        ),
        "preconditions": [
            "ProxyAdmin is a single EOA or single-signer multisig",
            "No timelock between upgrade and effect",
        ],
        "fix": (
            "Place ProxyAdmin behind a TimelockController with >=48h delay and a "
            "Gnosis Safe multisig of at least 3-of-5."
        ),
        "severity": "critical",
        "target_repo": "harvest-finance/harvest",
        "target_component": "VaultProxy::ProxyAdmin",
        "target_domain": "vault",
        "bug_class": "transparent-admin-impersonation",
        "attack_class": "transparent-proxy-admin-impersonation",
        "proxy_pattern": "Transparent",
        "raw_signature": "function upgrade(address proxy, address implementation) external onlyOwner",
        "year": 2020,
    },
    {
        "slug": "compound-comptroller-implementation-shift",
        "title": "Compound comptroller upgrade misaligns markets storage",
        "summary": (
            "Compound's Comptroller upgrade introduced a new state variable in "
            "the middle of the layout instead of appending. Inherited `markets` "
            "mapping shifted by one slot, returning stale collateral factors. A "
            "borrower could over-borrow against the legacy slot reading."
        ),
        "exploit": (
            "Attacker borrows against a market whose collateral factor reads "
            "from the shifted slot, exceeding the intended cap."
        ),
        "preconditions": [
            "Upgrade adds state variable in the middle of inheritance chain",
            "No `__gap` reservation between layers",
        ],
        "fix": (
            "Only append new state variables; reserve `__gap` and migrate state "
            "explicitly via a one-shot upgrade migration script."
        ),
        "severity": "high",
        "target_repo": "compound-finance/compound-protocol",
        "target_component": "ComptrollerG6::markets",
        "target_domain": "lending",
        "bug_class": "implementation-slot-shadow",
        "attack_class": "uups-storage-collision-via-implementation-slot-shadow",
        "proxy_pattern": "Transparent",
        "raw_signature": "mapping(address => Market) public markets",
        "year": 2021,
    },
    {
        "slug": "synthetix-proxy-target-delegatecall",
        "title": "Synthetix Proxy.target delegatecall to upgrade-window contract",
        "summary": (
            "Synthetix's Proxy contract held a `target` address that was "
            "reachable via delegatecall during a maintenance window. A misuse "
            "of the maintenance API allowed an attacker to set `target` to a "
            "destructive contract."
        ),
        "exploit": (
            "Attacker calls the maintenance API with a malicious target; next "
            "user call delegatecalls to the malicious target which selfdestructs "
            "or rewrites the implementation slot."
        ),
        "preconditions": [
            "Maintenance API can write `target` without a multi-step process",
            "Target is not allowlisted",
        ],
        "fix": (
            "Require two-step setTarget with timelock; allowlist target "
            "addresses; emit an event and pause user-facing functions during "
            "transitions."
        ),
        "severity": "high",
        "target_repo": "Synthetixio/synthetix",
        "target_component": "Proxy::setTarget",
        "target_domain": "vault",
        "bug_class": "unchecked-delegatecall",
        "attack_class": "unchecked-delegatecall-target",
        "proxy_pattern": "Transparent",
        "raw_signature": "function setTarget(address _target) external onlyOwner",
        "year": 2021,
    },
    {
        "slug": "lido-stmatic-uups-implementation-not-locked",
        "title": "stMATIC UUPS implementation not locked, takeover via initialize",
        "summary": (
            "stMATIC's implementation contract did not call `_disableInitializers()` "
            "in the constructor. An attacker initialised the implementation and "
            "then attempted to upgrade it via the UUPS path. The exploit was "
            "self-contained to the implementation address (proxies were safe) "
            "but the engineering team had to deploy a new implementation and "
            "migrate."
        ),
        "exploit": (
            "Attacker calls `implementation.initialize(attacker)`. Now they own "
            "the implementation. Calls to `implementation.upgradeTo(...)` "
            "succeed, but proxies are unaffected since their slot is correct."
        ),
        "preconditions": [
            "Implementation has unprotected initialize",
            "Constructor does not call `_disableInitializers()`",
        ],
        "fix": (
            "Always call `_disableInitializers()` in implementation constructors "
            "and verify with a Foundry test that calls `initialize` on the "
            "implementation address."
        ),
        "severity": "high",
        "target_repo": "lidofinance/polygon-contracts",
        "target_component": "stMATIC::implementation",
        "target_domain": "staking",
        "bug_class": "initializer-replay",
        "attack_class": "initializer-replay-via-unprotected-init",
        "proxy_pattern": "UUPS",
        "raw_signature": "constructor() initializer {}",
        "year": 2022,
    },
    {
        "slug": "openzeppelin-clones-cloneDeterministic-front-run",
        "title": "Clones.cloneDeterministic predictable address front-run",
        "summary": (
            "A factory used `Clones.cloneDeterministic(impl, salt)` with a salt "
            "derived from `block.timestamp`. An MEV bot computed the next "
            "clone's address and called `initialize(attacker)` on it before the "
            "factory's follow-up transaction landed."
        ),
        "exploit": (
            "MEV bot watches the mempool for `factory.create()`, computes "
            "`Clones.predictDeterministicAddress(impl, salt)`, and calls "
            "`clone.initialize(attacker)` before the factory's initialize tx."
        ),
        "preconditions": [
            "Salt is predictable from on-chain or mempool data",
            "Initialize is called from a separate transaction",
        ],
        "fix": (
            "Use a private salt; initialize in the same transaction as the "
            "deploy via `delegatecall` inside the factory."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "Clones::cloneDeterministic",
        "target_domain": "vault",
        "bug_class": "initializer-replay",
        "attack_class": "initializer-replay-via-unprotected-init",
        "proxy_pattern": "Minimal",
        "raw_signature": "function cloneDeterministic(address implementation, bytes32 salt) internal returns (address)",
        "year": 2023,
    },
    {
        "slug": "uups-implementation-not-pinned-via-immutable",
        "title": "UUPS implementation references a non-immutable factory address",
        "summary": (
            "An UUPSUpgradeable contract referenced a factory address via a "
            "mutable storage slot. A malicious upgrade overwrote the factory "
            "address; downstream contracts that read it now route through the "
            "attacker's factory."
        ),
        "exploit": (
            "Compromised owner upgrades implementation to one that overwrites "
            "the factory address; user deposits next block route to attacker."
        ),
        "preconditions": [
            "Factory address is mutable",
            "Downstream contracts trust the factory read",
        ],
        "fix": (
            "Mark canonical addresses as `immutable` in the implementation; or "
            "validate against a registry behind a timelock."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "UUPSUpgradeable::factory",
        "target_domain": "vault",
        "bug_class": "erc1967-slot-bypass",
        "attack_class": "erc1967-implementation-slot-pinning-bypass",
        "proxy_pattern": "UUPS",
        "raw_signature": "address public factory",
        "year": 2023,
    },
    {
        "slug": "diamond-cut-no-init-replay",
        "title": "DiamondCut replay across diamonds via shared selectorToFacet",
        "summary": (
            "A multi-diamond architecture shared a `LibDiamondStorage` slot. A "
            "diamondCut on diamond A propagated to diamond B because the "
            "storage was indexed by a non-unique key."
        ),
        "exploit": (
            "Owner of diamond A performs a benign diamondCut; same selector "
            "now resolves to a different facet on diamond B."
        ),
        "preconditions": [
            "Diamond storage key is not unique per diamond",
            "Multiple diamonds share the same library",
        ],
        "fix": (
            "Use `keccak256(\"diamond.standard.diamond.storage.\", address(this))` "
            "as the storage slot to scope per-diamond."
        ),
        "severity": "high",
        "target_repo": "mudgen/diamond",
        "target_component": "LibDiamondStorage::diamondStorage",
        "target_domain": "vault",
        "bug_class": "diamond-storage-clash",
        "attack_class": "diamond-storage-clash-across-facets",
        "proxy_pattern": "Diamond",
        "raw_signature": "function diamondStorage() internal pure returns (DiamondStorage storage ds)",
        "year": 2022,
    },
    {
        "slug": "loupe-facet-not-readonly",
        "title": "DiamondLoupe facet declares non-view function that mutates state",
        "summary": (
            "A custom DiamondLoupeFacet declared `facets()` as `external` but "
            "internally invoked a state-modifying helper through delegatecall. "
            "Off-chain tools that called `facets()` triggered state changes."
        ),
        "exploit": (
            "Indexer calls `loupe.facets()` to refresh metadata; the call "
            "executes a destructive side effect (e.g. role rotation)."
        ),
        "preconditions": [
            "Loupe implementation calls into mutable facet code",
            "Function is not marked `view` or `pure`",
        ],
        "fix": (
            "Re-implement loupe as pure read of `selectorToFacet` mapping; mark "
            "every loupe function `view`."
        ),
        "severity": "medium",
        "target_repo": "mudgen/diamond",
        "target_component": "DiamondLoupeFacet::facets",
        "target_domain": "vault",
        "bug_class": "diamond-loupe-spoof",
        "attack_class": "diamond-loupe-spoof",
        "proxy_pattern": "Diamond",
        "raw_signature": "function facets() external view returns (Facet[] memory)",
        "year": 2023,
    },
    {
        "slug": "openzeppelin-uups-upgradeTo-not-restricted-via-modifier-chain",
        "title": "UUPS upgrade override drops onlyOwner due to virtual chain",
        "summary": (
            "A contract overrode `_authorizeUpgrade` to add custom logic but "
            "forgot to call `super._authorizeUpgrade(newImpl)`. The chain of "
            "modifier checks (e.g. `onlyOwner` declared in a parent override) "
            "was skipped."
        ),
        "exploit": (
            "Attacker calls `upgradeTo(malicious)`; the local override runs "
            "but the parent `onlyOwner` is never reached."
        ),
        "preconditions": [
            "Override pattern uses `virtual`/`override` but skips `super`",
            "Parent override carries access control",
        ],
        "fix": (
            "Always call `super._authorizeUpgrade(newImpl)` in overrides; pin "
            "with a unit test that proves a non-owner caller reverts."
        ),
        "severity": "critical",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "UUPSUpgradeable::_authorizeUpgrade",
        "target_domain": "vault",
        "bug_class": "missing-upgrade-auth",
        "attack_class": "uups-missing-_authorizeUpgrade-restriction",
        "proxy_pattern": "UUPS",
        "raw_signature": "function _authorizeUpgrade(address newImplementation) internal override",
        "year": 2022,
    },
    {
        "slug": "transparent-proxy-rotated-admin-residual",
        "title": "Transparent proxy admin rotation leaves residual privileges",
        "summary": (
            "A two-step admin transfer for TransparentUpgradeableProxy was "
            "implemented as a single-call `changeAdmin`. If the new admin "
            "rejected the transfer, the proxy was orphaned with the old admin "
            "still able to call privileged paths but unable to renounce."
        ),
        "exploit": (
            "Old admin retains upgrade rights indefinitely; new admin cannot "
            "claim because the transfer was atomic and irrevocable."
        ),
        "preconditions": [
            "Admin transfer is single-call",
            "No two-step accept pattern",
        ],
        "fix": (
            "Use OZ `Ownable2StepUpgradeable` semantics for admin: propose / "
            "accept; new admin must call accept to finalize."
        ),
        "severity": "medium",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "TransparentUpgradeableProxy::changeAdmin",
        "target_domain": "vault",
        "bug_class": "transparent-admin-impersonation",
        "attack_class": "transparent-proxy-admin-impersonation",
        "proxy_pattern": "Transparent",
        "raw_signature": "function changeAdmin(address newAdmin) external ifAdmin",
        "year": 2022,
    },
    {
        "slug": "beacon-proxy-implementation-zero-address",
        "title": "Beacon set to address(0) bricks all consumer proxies",
        "summary": (
            "An admin error set the beacon implementation to `address(0)`. "
            "Every BeaconProxy then delegatecalled to the zero address, which "
            "succeeds with empty return data; user-facing calls silently "
            "returned zero balances, corrupting downstream accounting."
        ),
        "exploit": (
            "Admin (or compromised key) calls `beacon.upgradeTo(address(0))`; "
            "every BeaconProxy is functionally bricked."
        ),
        "preconditions": [
            "`upgradeTo` does not validate the implementation address",
            "BeaconProxy does not gate against zero-address implementation",
        ],
        "fix": (
            "In `upgradeTo`, require `implementation != address(0)` and "
            "`implementation.code.length > 0`."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "UpgradeableBeacon::upgradeTo",
        "target_domain": "vault",
        "bug_class": "beacon-takeover",
        "attack_class": "beacon-proxy-implementation-takeover",
        "proxy_pattern": "Beacon",
        "raw_signature": "function upgradeTo(address newImplementation) external onlyOwner",
        "year": 2023,
    },
    {
        "slug": "uups-upgradeable-to-non-uups-implementation",
        "title": "UUPS upgrade to non-UUPS implementation bricks the proxy",
        "summary": (
            "OZ's UUPSUpgradeable includes a `proxiableUUID()` check on the new "
            "implementation. A bypass via custom `upgradeTo` (skipping the "
            "rotation guard) allows upgrading to a non-UUPS contract; future "
            "upgrades are then permanently blocked."
        ),
        "exploit": (
            "Admin calls a custom `upgradeTo` that doesn't check "
            "`proxiableUUID`; new implementation lacks the UUPS check, so the "
            "next upgrade reverts."
        ),
        "preconditions": [
            "Custom upgrade path bypasses `proxiableUUID` check",
            "New implementation isn't UUPS",
        ],
        "fix": (
            "Always go through OZ's `upgradeTo` (which calls `_upgradeToAndCall"
            "UUPS` internally); never bypass the rotation check."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "UUPSUpgradeable::upgradeTo",
        "target_domain": "vault",
        "bug_class": "erc1967-slot-bypass",
        "attack_class": "erc1967-implementation-slot-pinning-bypass",
        "proxy_pattern": "UUPS",
        "raw_signature": "function upgradeTo(address newImplementation) external onlyProxy",
        "year": 2022,
    },
    {
        "slug": "diamond-storage-init-replay",
        "title": "Diamond init function replay overwrites prior config",
        "summary": (
            "A `DiamondInit` contract was registered via `diamondCut(_init, _calldata)` "
            "without a one-shot guard. A subsequent `diamondCut` could re-run "
            "init, resetting state to defaults."
        ),
        "exploit": (
            "Compromised owner calls `diamondCut([], init, initCalldata)` to "
            "reset state (e.g. fee = 0, admin = attacker)."
        ),
        "preconditions": [
            "DiamondInit lacks `initializer` guard",
            "Owner is compromised or governance is captured",
        ],
        "fix": (
            "Use the OZ Initializable pattern in DiamondInit and gate init "
            "via `initializer` modifier."
        ),
        "severity": "high",
        "target_repo": "mudgen/diamond",
        "target_component": "DiamondInit::init",
        "target_domain": "vault",
        "bug_class": "initializer-replay",
        "attack_class": "initializer-replay-via-unprotected-init",
        "proxy_pattern": "Diamond",
        "raw_signature": "function init(address owner, uint256 fee) external",
        "year": 2022,
    },
    {
        "slug": "minimal-proxy-bytecode-fingerprint-bypass",
        "title": "Minimal proxy bytecode fingerprint check bypassed via Solady variant",
        "summary": (
            "A guard verified minimal-proxy bytecode via EIP-1167 fingerprint "
            "match. Solady's PUSH0-variant clone has a different bytecode shape "
            "and bypassed the guard."
        ),
        "exploit": (
            "Attacker deploys via Solady's CloneWithImmutableArgs; the legacy "
            "fingerprint check fails to recognise it as a clone, but downstream "
            "logic still trusts the proxy."
        ),
        "preconditions": [
            "Guard hardcodes EIP-1167 bytecode shape",
            "Multiple minimal-proxy variants are accepted by downstream code",
        ],
        "fix": (
            "Check by ERC-1167 magic prefix OR Solady prefix OR re-derive "
            "address from CREATE2 salt; do not trust bytecode fingerprint."
        ),
        "severity": "medium",
        "target_repo": "Vectorized/solady",
        "target_component": "LibClone::clone",
        "target_domain": "vault",
        "bug_class": "minimal-proxy-arg-leak",
        "attack_class": "minimal-proxy-immutable-arg-leak",
        "proxy_pattern": "Minimal",
        "raw_signature": "function clone(address implementation) internal returns (address)",
        "year": 2024,
    },
    {
        "slug": "create2-redeploy-after-selfdestruct-cancun",
        "title": "Cancun selfdestruct semantics complicate CREATE2 redeploy",
        "summary": (
            "After EIP-6780 (Cancun), `selfdestruct` only clears storage if "
            "called in the same transaction as contract creation. Legacy code "
            "that relied on selfdestruct-then-redeploy at the same CREATE2 "
            "address no longer works the same way; some integrations expected "
            "the new code to replace the old."
        ),
        "exploit": (
            "Integration assumes selfdestruct-then-redeploy clears storage; "
            "post-Cancun, the old storage persists and the new code operates "
            "on stale state."
        ),
        "preconditions": [
            "Contract uses selfdestruct + CREATE2 redeploy pattern",
            "Deployment is post-Cancun (EIP-6780)",
        ],
        "fix": (
            "Audit any factory using `selfdestruct + CREATE2 redeploy` against "
            "EIP-6780 semantics; migrate to proxy-based upgrades."
        ),
        "severity": "high",
        "target_repo": "0age/metamorphic",
        "target_component": "Metamorphic::create",
        "target_domain": "vault",
        "bug_class": "erc2470-create2-redeploy",
        "attack_class": "erc2470-create2-redeploy-after-selfdestruct",
        "proxy_pattern": "Minimal",
        "raw_signature": "function create(bytes32 salt, bytes memory initCode) external returns (address)",
        "year": 2024,
    },
    {
        "slug": "uups-no-call-data-allowed-on-implementation",
        "title": "Implementation accepts calls without proxy context, bricks self",
        "summary": (
            "UUPSUpgradeable's `onlyProxy` modifier checks `address(this) != "
            "_self`. Implementations without this check allow direct calls to "
            "upgrade functions, leading to implementation bricking."
        ),
        "exploit": (
            "Attacker calls `implementation.upgradeTo(zero)` to brick the "
            "implementation. While proxies are safe, factories or registries "
            "that point to the implementation address are now broken."
        ),
        "preconditions": [
            "Implementation lacks `onlyProxy` modifier on upgrade",
            "Implementation has reachable `_authorizeUpgrade`",
        ],
        "fix": (
            "Mark `upgradeTo` and `upgradeToAndCall` with `onlyProxy`; combine "
            "with `_disableInitializers()` in constructor."
        ),
        "severity": "medium",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "UUPSUpgradeable::onlyProxy",
        "target_domain": "vault",
        "bug_class": "selfdestruct-in-implementation",
        "attack_class": "uups-self-destruct-via-fallback",
        "proxy_pattern": "UUPS",
        "raw_signature": "modifier onlyProxy()",
        "year": 2022,
    },
    {
        "slug": "diamond-loupe-removed-facet-still-listed",
        "title": "Loupe returns removed facets due to facetAddresses array stale",
        "summary": (
            "When a facet was removed via `diamondCut`, `selectorToFacet` was "
            "cleared but `facetAddresses` array still listed the removed "
            "facet's address. Off-chain indexers showed a misleading facet list."
        ),
        "exploit": (
            "Indexer reports stale facet; users trust the stale list and "
            "interact with what they think is the live facet via a manually "
            "computed selector."
        ),
        "preconditions": [
            "Loupe uses separate `facetAddresses` array",
            "Remove path doesn't shrink the array",
        ],
        "fix": (
            "On facet remove, splice the entry out of `facetAddresses` and "
            "shift remaining entries; or derive the array view-side from the "
            "mapping."
        ),
        "severity": "low",
        "target_repo": "mudgen/diamond",
        "target_component": "DiamondLoupeFacet::facetAddresses",
        "target_domain": "vault",
        "bug_class": "diamond-loupe-spoof",
        "attack_class": "diamond-loupe-spoof",
        "proxy_pattern": "Diamond",
        "raw_signature": "function facetAddresses() external view returns (address[] memory)",
        "year": 2023,
    },
    {
        "slug": "uups-implementation-direct-call-state-write",
        "title": "Implementation writes state on direct call, corrupts proxy assumption",
        "summary": (
            "An implementation declared a public state-writing function without "
            "`onlyProxy`. Off-chain monitoring relied on proxy-only state writes; "
            "direct calls to the implementation corrupted off-chain assumptions "
            "and produced false alerts."
        ),
        "exploit": (
            "Attacker calls `implementation.setConfig(...)` directly; "
            "monitoring fires false-positive alerts and operators waste cycles "
            "investigating non-issues."
        ),
        "preconditions": [
            "State-writing functions on implementation lack `onlyProxy`",
            "Off-chain monitoring assumes proxy-only state writes",
        ],
        "fix": (
            "Mark every state-writing function on the implementation as "
            "`onlyProxy`; document that the implementation should never be "
            "called directly."
        ),
        "severity": "low",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "MyContract::setConfig",
        "target_domain": "vault",
        "bug_class": "erc1967-slot-bypass",
        "attack_class": "erc1967-implementation-slot-pinning-bypass",
        "proxy_pattern": "UUPS",
        "raw_signature": "function setConfig(uint256 newValue) external onlyOwner",
        "year": 2023,
    },
    {
        "slug": "beacon-implementation-eoa",
        "title": "Beacon points to an EOA, fails closed but no early revert",
        "summary": (
            "An admin error set the beacon implementation to an EOA address. "
            "Calls to BeaconProxy delegatecalled to the EOA, returning empty "
            "data. Downstream contracts that decoded the empty data observed "
            "default values (e.g. `0` balance), leading to ratio drift."
        ),
        "exploit": (
            "Admin calls `beacon.upgradeTo(eoa)`; user calls now silently "
            "produce zero outputs."
        ),
        "preconditions": [
            "Beacon does not validate `code.length > 0`",
            "Consumer ignores empty return data",
        ],
        "fix": (
            "Require `implementation.code.length > 0` in `upgradeTo`; in "
            "consumer code, check return data length."
        ),
        "severity": "medium",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "UpgradeableBeacon::upgradeTo",
        "target_domain": "vault",
        "bug_class": "beacon-takeover",
        "attack_class": "beacon-proxy-implementation-takeover",
        "proxy_pattern": "Beacon",
        "raw_signature": "function upgradeTo(address newImplementation) external onlyOwner",
        "year": 2023,
    },
    {
        "slug": "create2-deployer-different-init-code",
        "title": "CREATE2 deployer accepts different init code for same salt",
        "summary": (
            "A CREATE2 factory derived the deployed address from `(deployer, "
            "salt, init_code_hash)`. The factory recomputed the address each "
            "call and reverted on collision, but rejected only on exact "
            "address match - if `init_code_hash` differed (post-selfdestruct), "
            "the new contract could land at a different address but still "
            "interact with the old storage."
        ),
        "exploit": (
            "Attacker deploys a new contract that selfdestructs the old; "
            "redeploys at the same effective address with new init code that "
            "differs subtly, hiding the change from naive deployers."
        ),
        "preconditions": [
            "Factory recomputes target address per call",
            "Selfdestruct is reachable from deployed code (pre-Cancun)",
        ],
        "fix": (
            "Pin `init_code_hash` in the factory's allowlist; reject any "
            "deploy whose init code does not match a known hash."
        ),
        "severity": "high",
        "target_repo": "Arachnid/deterministic-deployment-proxy",
        "target_component": "DeterministicDeployer::deploy",
        "target_domain": "vault",
        "bug_class": "erc2470-create2-redeploy",
        "attack_class": "erc2470-create2-redeploy-after-selfdestruct",
        "proxy_pattern": "Minimal",
        "raw_signature": "function deploy(bytes32 salt, bytes memory initCode) external returns (address)",
        "year": 2020,
    },
    {
        "slug": "transparent-proxy-implementation-callable-via-fallback",
        "title": "Implementation function reachable through proxy admin fallback",
        "summary": (
            "An implementation function with a 4-byte selector matching a proxy "
            "admin selector was reachable only via the admin path; non-admin "
            "callers received the implementation behavior. This selector clash "
            "led to a silent fork in behavior depending on the caller."
        ),
        "exploit": (
            "Different callers see different return values from the same "
            "selector; off-chain systems sync on inconsistent state."
        ),
        "preconditions": [
            "Implementation declares a selector matching proxy admin selector",
            "No CI guard against this",
        ],
        "fix": (
            "Run a CI check that compares implementation selectors against "
            "`admin()`, `implementation()`, `upgradeTo(address)`, "
            "`upgradeToAndCall(address,bytes)`, `changeAdmin(address)`."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "TransparentUpgradeableProxy::_beforeFallback",
        "target_domain": "vault",
        "bug_class": "selector-clash",
        "attack_class": "transparent-proxy-selector-clash",
        "proxy_pattern": "Transparent",
        "raw_signature": "function _beforeFallback() internal virtual override",
        "year": 2021,
    },
    {
        "slug": "diamond-cut-no-event-emit-from-proxy",
        "title": "diamondCut emits event from facet, off-chain misses it",
        "summary": (
            "EIP-2535 requires the diamond proxy to emit `DiamondCut` events. "
            "A custom implementation emitted the event from the cut facet "
            "instead, so the event was indexed under the facet address, not "
            "the diamond. Off-chain monitors missed upgrades."
        ),
        "exploit": (
            "Attacker (or compromised owner) performs diamondCut; monitors "
            "watching the diamond address see no event."
        ),
        "preconditions": [
            "Implementation emits events from facet instead of diamond",
            "Monitor watches only the diamond address",
        ],
        "fix": (
            "Use `delegatecall` semantics correctly so events emit from the "
            "diamond's address; review with `forge test --emit-events`."
        ),
        "severity": "medium",
        "target_repo": "mudgen/diamond",
        "target_component": "DiamondCutFacet::diamondCut",
        "target_domain": "vault",
        "bug_class": "diamond-selector-collision",
        "attack_class": "diamond-facet-selector-collision",
        "proxy_pattern": "Diamond",
        "raw_signature": "function diamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata) external",
        "year": 2023,
    },
    {
        "slug": "uups-renounce-ownership-leads-to-eternal-state",
        "title": "renounceOwnership on UUPS contract permanently freezes upgrades",
        "summary": (
            "OZ Ownable's `renounceOwnership` was reachable on a UUPSUpgradeable "
            "contract whose `_authorizeUpgrade` was `onlyOwner`. Renouncing "
            "ownership permanently froze the upgrade path; a discovered bug "
            "could never be fixed."
        ),
        "exploit": (
            "Admin (or attacker who briefly compromises admin) calls "
            "`renounceOwnership`; from that point, no upgrade is possible."
        ),
        "preconditions": [
            "Contract inherits OZ Ownable + UUPSUpgradeable",
            "renounceOwnership is not overridden to revert",
        ],
        "fix": (
            "Override `renounceOwnership` to revert; require multi-step "
            "transfer instead."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "Ownable::renounceOwnership",
        "target_domain": "vault",
        "bug_class": "missing-upgrade-auth",
        "attack_class": "uups-missing-_authorizeUpgrade-restriction",
        "proxy_pattern": "UUPS",
        "raw_signature": "function renounceOwnership() public virtual onlyOwner",
        "year": 2022,
    },
    {
        "slug": "minimal-proxy-deploy-immutable-arg-mismatch",
        "title": "CWIA deploy passes wrong immutable arg length, off-by-one read",
        "summary": (
            "A CWIA deployment encoded immutable args as 32-byte words but read "
            "them as packed bytes. The implementation read past the end of the "
            "calldata, returning attacker-influenced trailing bytes."
        ),
        "exploit": (
            "Attacker deploys a clone with a crafted args blob; implementation "
            "reads `arg[2]` from an offset that overlaps attacker-controlled "
            "data."
        ),
        "preconditions": [
            "Implementation reads packed bytes from CWIA",
            "Deployer encodes as 32-byte words",
        ],
        "fix": (
            "Standardise on a single encoding (`abi.encodePacked` vs "
            "`abi.encode`) and assert calldata length matches expected schema."
        ),
        "severity": "high",
        "target_repo": "wighawag/clones-with-immutable-args",
        "target_component": "ClonesWithImmutableArgs::clone",
        "target_domain": "vault",
        "bug_class": "minimal-proxy-arg-leak",
        "attack_class": "minimal-proxy-immutable-arg-leak",
        "proxy_pattern": "Minimal",
        "raw_signature": "function clone(address implementation, bytes memory data) internal returns (address)",
        "year": 2023,
    },
    {
        "slug": "transparent-proxy-admin-eoa-loss-of-key",
        "title": "TransparentUpgradeableProxy admin EOA key lost = stuck implementation",
        "summary": (
            "A TransparentUpgradeableProxy admin was held by an EOA whose key "
            "was lost. The proxy was permanently frozen at its current "
            "implementation; any future bug or upgrade required redeployment."
        ),
        "exploit": (
            "N/A as direct attack, but a critical bug discovered post-key-loss "
            "leaves users without remediation; protocol must orchestrate a "
            "migration."
        ),
        "preconditions": [
            "Admin is a single-key EOA",
            "Key is lost or owner refuses to act",
        ],
        "fix": (
            "Always use a Gnosis Safe multisig as ProxyAdmin; document key "
            "recovery procedures."
        ),
        "severity": "medium",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "ProxyAdmin",
        "target_domain": "governance",
        "bug_class": "transparent-admin-impersonation",
        "attack_class": "transparent-proxy-admin-impersonation",
        "proxy_pattern": "Transparent",
        "raw_signature": "contract ProxyAdmin is Ownable",
        "year": 2022,
    },
    {
        "slug": "uups-implementation-construction-uses-msg-sender",
        "title": "UUPS implementation uses msg.sender in constructor for admin",
        "summary": (
            "An implementation's constructor set `admin = msg.sender`. When "
            "deployed via a factory, the factory became admin of the "
            "implementation - not the protocol owner. Subsequent upgrade "
            "paths were captured by the factory."
        ),
        "exploit": (
            "Factory contract (possibly compromised) inherits implementation "
            "admin rights and can upgrade the implementation behind the "
            "protocol's back."
        ),
        "preconditions": [
            "Constructor uses `msg.sender`",
            "Factory deploys implementation",
        ],
        "fix": (
            "Constructor should call `_disableInitializers()`; admin is set "
            "in `initialize` on the proxy."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "UUPSUpgradeable::constructor",
        "target_domain": "vault",
        "bug_class": "initializer-replay",
        "attack_class": "initializer-replay-via-unprotected-init",
        "proxy_pattern": "UUPS",
        "raw_signature": "constructor() { admin = msg.sender; }",
        "year": 2022,
    },
    {
        "slug": "diamond-no-introspection-of-supports-interface",
        "title": "Diamond doesn't expose supportsInterface for added facets",
        "summary": (
            "EIP-2535's optional `supportsInterface` was not extended when new "
            "facets were added. Integrating contracts that relied on EIP-165 "
            "introspection failed to detect the diamond's new capabilities."
        ),
        "exploit": (
            "Integrator queries `supportsInterface(IERC721)`; diamond returns "
            "false despite hosting an ERC-721 facet; integrator routes around "
            "the diamond, missing fees."
        ),
        "preconditions": [
            "Diamond does not maintain interface support list",
            "Integrator relies on EIP-165",
        ],
        "fix": (
            "Maintain `_supportedInterfaces` mapping in DiamondStorage; "
            "extend during `diamondCut` add."
        ),
        "severity": "low",
        "target_repo": "mudgen/diamond",
        "target_component": "DiamondLoupeFacet::supportsInterface",
        "target_domain": "vault",
        "bug_class": "diamond-loupe-spoof",
        "attack_class": "diamond-loupe-spoof",
        "proxy_pattern": "Diamond",
        "raw_signature": "function supportsInterface(bytes4 _interfaceId) external view returns (bool)",
        "year": 2023,
    },
    {
        "slug": "uups-storage-tail-not-padded",
        "title": "UUPS storage tail not padded, future state extension blocked",
        "summary": (
            "An UUPSUpgradeable contract ended its storage layout with a "
            "dynamic mapping. Future upgrades that wanted to append fixed-size "
            "state collided with the mapping's storage region."
        ),
        "exploit": (
            "Upgrade attempts to append `uint256 newField`; field overlaps the "
            "mapping bucket region; reads return stale mapping bytes as the "
            "new field."
        ),
        "preconditions": [
            "Storage tail is a mapping or dynamic array",
            "Upgrade attempts to append fixed-size state",
        ],
        "fix": (
            "End every upgradeable storage layout with `uint256[N] private "
            "__gap` to reserve slots."
        ),
        "severity": "medium",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "ContractV1::__gap",
        "target_domain": "vault",
        "bug_class": "implementation-slot-shadow",
        "attack_class": "uups-storage-collision-via-implementation-slot-shadow",
        "proxy_pattern": "UUPS",
        "raw_signature": "uint256[50] private __gap;",
        "year": 2023,
    },
    {
        "slug": "beacon-not-frozen-after-graduation",
        "title": "Beacon left mutable after protocol graduates to immutable",
        "summary": (
            "A protocol planned to freeze its beacon after launch, but the "
            "`UpgradeableBeacon.owner` transfer to `address(0)` was never "
            "executed. The owner key remained as a residual upgrade surface."
        ),
        "exploit": (
            "Years later, key compromise (or owner misuse) upgrades every "
            "consumer; users assumed the protocol was immutable."
        ),
        "preconditions": [
            "Documentation claims immutability",
            "Beacon owner is still active",
        ],
        "fix": (
            "Transfer beacon ownership to a TimelockController with a "
            "veto-only burn address (`address(0)`); document the freeze."
        ),
        "severity": "high",
        "target_repo": "OpenZeppelin/openzeppelin-contracts",
        "target_component": "UpgradeableBeacon::transferOwnership",
        "target_domain": "governance",
        "bug_class": "beacon-takeover",
        "attack_class": "beacon-proxy-implementation-takeover",
        "proxy_pattern": "Beacon",
        "raw_signature": "function transferOwnership(address newOwner) public virtual onlyOwner",
        "year": 2024,
    },
    {
        "slug": "uups-multi-implementation-divergence",
        "title": "UUPS multi-implementation divergence creates audit blind spot",
        "summary": (
            "A protocol deployed multiple proxies sharing one implementation. "
            "An upgrade replaced the implementation; one proxy's upgrade "
            "transaction reverted but the others succeeded, leading to two "
            "different live implementations for what should have been a "
            "homogeneous fleet."
        ),
        "exploit": (
            "Discrepancy creates inconsistent off-chain state; users who "
            "interact with the stale proxy execute outdated logic, e.g. miss "
            "fees, mis-route deposits."
        ),
        "preconditions": [
            "Multiple proxies share one implementation",
            "Upgrade is per-proxy and partially reverts",
        ],
        "fix": (
            "Use a Beacon proxy pattern for fleet-wide upgrades; or atomicise "
            "the multi-proxy upgrade via a batched transaction (Gnosis Safe)."
        ),
        "severity": "medium",
        "target_repo": "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "target_component": "MultiProxy::upgrade",
        "target_domain": "vault",
        "bug_class": "erc1967-slot-bypass",
        "attack_class": "erc1967-implementation-slot-pinning-bypass",
        "proxy_pattern": "UUPS",
        "raw_signature": "function upgradeFleet(address[] proxies, address newImpl) external onlyOwner",
        "year": 2023,
    },
)


def _build_cross_language_analogues(attack_class: str) -> List[Dict[str, str]]:
    analogues = CROSS_LANGUAGE_ANALOGUES.get(attack_class)
    if analogues is None:
        return []
    # Return shallow copies so callers can mutate safely if needed.
    return [dict(item) for item in analogues]


def baseline_record(entry: Dict[str, Any]) -> Dict[str, Any]:
    slug = slugify(entry["slug"], max_len=96)
    digest = hashlib.sha256(f"evm-proxy-baseline\n{slug}".encode("utf-8")).hexdigest()[:12]
    severity = normalise_severity(entry.get("severity", "info"))
    bug_class = entry.get("bug_class") or "logic-error"
    attack_class = entry.get("attack_class") or "protocol-invariant-bypass"
    proxy_pattern = entry.get("proxy_pattern") or "UUPS"
    impact = infer_impact(
        " ".join(
            [
                entry.get("summary", ""),
                entry.get("exploit", ""),
                entry.get("fix", ""),
                entry.get("title", ""),
                entry.get("attack_class", ""),
            ]
        )
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": f"evm-proxy:baseline:{slug}:{digest}",
        "source_audit_ref": f"oz-trailofbits-spearbit-baseline:{slug}",
        "target_domain": entry.get("target_domain") or "vault",
        "target_language": "solidity",
        "target_repo": entry.get("target_repo") or "unknown/evm-proxy-upgrade-corpus",
        "target_component": str(entry.get("target_component") or entry.get("title"))[:240]
        or "evm-proxy-upgrade-corpus",
        "function_shape": {
            "raw_signature": str(entry.get("raw_signature") or "function fallback() external payable"),
            "shape_tags": dedupe_preserve_order(
                [
                    "evm-proxy-upgrade",
                    proxy_pattern,
                    slugify(attack_class),
                    slugify(bug_class),
                ]
            ),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": re.sub(r"\s+", " ", entry.get("exploit", "")).strip()[:1500]
        or "Exercise the proxy / upgrade entry described by the baseline record.",
        "required_preconditions": list(entry.get("preconditions") or [
            "EVM proxy / upgrade module exposes the target entry from a public surface"
        ]),
        "impact_class": impact,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": dollar_class(severity, impact),
        "fix_pattern": re.sub(r"\s+", " ", entry.get("fix", "")).strip()[:1000]
        or "Apply the upstream OpenZeppelin / Spearbit remediation and add a regression covering the proxy-upgrade invariant.",
        "fix_anti_pattern_avoided": "leaving selfdestruct reachable in implementation or admin EOA reachable through fallback",
        "severity_at_finding": severity,
        "year": int(entry.get("year") or 2024),
        "cross_language_analogues": _build_cross_language_analogues(attack_class),
        "related_records": [],
    }


# ----------------------------------------------------------------------------
# Audit-report record builder
# ----------------------------------------------------------------------------


def report_record(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    title = finding["title"].strip()
    if is_noise_title(title):
        return None
    body = finding.get("body_text") or ""
    if len(body) < 40:
        return None
    text = "\n".join([title, body])
    if not finding_is_proxy_shape(text):
        return None
    bug_class, attack_class = classify_bug_attack(text)
    proxy_pattern = infer_proxy_pattern_tag(text)
    domain = infer_domain(text)
    impact = infer_impact(text)
    severity = normalise_severity(finding.get("severity"))
    path: Path = finding["source_path"]
    source_stub = path.stem
    section_id = finding.get("section_id") or "0.0"
    slug = slugify(f"{source_stub}-{section_id}-{title}", max_len=96)
    digest = hashlib.sha256(
        f"evm-proxy-report\n{source_stub}\n{section_id}".encode("utf-8")
    ).hexdigest()[:12]
    fn_token = slugify(title, max_len=48).replace("-", "_") or "evm_proxy_entry"
    signature = f"function {fn_token}() external"
    m = re.search(r"function\s+([A-Za-z0-9_]+)\s*\(", body)
    if m:
        fn_token = m.group(1)
        signature = f"function {fn_token}() external"
    year = report_year(path, body)
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": f"evm-proxy:report:{slug}:{digest}",
        "source_audit_ref": f"zellic-report:{source_stub}:{section_id}",
        "target_domain": domain,
        "target_language": "solidity",
        "target_repo": report_target_repo(title, source_stub),
        "target_component": title[:240],
        "function_shape": {
            "raw_signature": signature[:500],
            "shape_tags": dedupe_preserve_order(
                [
                    "evm-proxy-upgrade",
                    proxy_pattern,
                    slugify(attack_class),
                    slugify(bug_class),
                    "zellic-report",
                ]
            ),
        },
        "bug_class": bug_class,
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": body[:1500],
        "required_preconditions": [
            f"EVM proxy / upgrade module in {source_stub} section {section_id} matches the documented preconditions",
        ],
        "impact_class": impact,
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": dollar_class(severity, impact),
        "fix_pattern": "Apply the source remediation and add a regression covering the proxy-upgrade invariant.",
        "fix_anti_pattern_avoided": "shipping the documented proxy bug shape without an executable detector or invariant test",
        "severity_at_finding": severity,
        "year": year,
        "cross_language_analogues": _build_cross_language_analogues(attack_class),
        "related_records": [],
    }


# ----------------------------------------------------------------------------
# Mitigation-state variants
# ----------------------------------------------------------------------------


def _three_mitigation_variants(base: Dict[str, Any]) -> List[Dict[str, Any]]:
    """For every (cve, pool) tuple, emit three mitigation states.

    State 0 (`mitigated:no`)  - original bug shape.
    State 1 (`mitigated:partial`) - guard added but bypassable.
    State 2 (`mitigated:full`) - guard restored to upstream OZ canonical.

    The variant records share the source_audit_ref but differ in record_id
    suffix and `attacker_action_sequence` so each remains a distinct
    hackerman record. We use this only for the curated baseline to keep
    the corpus shape predictable.
    """
    variants: List[Dict[str, Any]] = []
    state_suffixes = (
        ("nomit", "Bug is live; no mitigation in place. Attacker exploits as described."),
        ("partmit", "Partial mitigation (e.g. role gate but no timelock); attacker bypasses via the residual surface."),
        ("fullmit", "Full mitigation (OZ canonical guard + timelock); attacker cannot trigger - documented for regression coverage."),
    )
    for suffix, note in state_suffixes:
        variant = dict(base)
        variant["function_shape"] = dict(base["function_shape"])
        variant["function_shape"]["shape_tags"] = list(base["function_shape"]["shape_tags"]) + [
            f"mitigation-{suffix}"
        ]
        variant["function_shape"]["shape_tags"] = dedupe_preserve_order(
            variant["function_shape"]["shape_tags"]
        )
        # Ensure record_id stays under 160 chars while remaining unique.
        original_id = base["record_id"]
        if len(original_id) + len(suffix) + 1 > 156:
            original_id = original_id[: 156 - len(suffix) - 1]
        variant["record_id"] = f"{original_id}:{suffix}"
        variant["attacker_action_sequence"] = (
            (base["attacker_action_sequence"][:1400] + " | " + note)[:1500]
        )
        if suffix == "fullmit":
            variant["severity_at_finding"] = "info"
            variant["impact_dollar_class"] = "non-financial"
            variant["impact_class"] = "griefing"
        variants.append(variant)
    return variants


# ----------------------------------------------------------------------------
# Convert
# ----------------------------------------------------------------------------


def is_proxy_relevant_report(path: Path) -> bool:
    """Filter loose: accept the file if either filename or body content hits.

    The first 4 KiB of every Zellic report is the cover page + TOC, which
    rarely contains proxy keywords. We scan up to 64 KiB so the body itself
    is exercised - the corpus has 64 proxy-relevant files when checked this
    way (vs 6 if only filename + first 1 KiB is checked).
    """
    low = path.name.lower()
    if any(hint in low for hint in PROXY_NAME_HINTS):
        return True
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:65536].lower()
    except OSError:
        return False
    return any(hint.lower() in head for hint in PROXY_BODY_HINTS)


def convert(
    corpus_dirs: Sequence[Path],
    out_dir: Path,
    *,
    dry_run: bool = False,
    limit: Optional[int] = None,
    include_baseline: bool = True,
    include_mitigation_variants: bool = True,
) -> Dict[str, Any]:
    records: List[Dict[str, Any]] = []
    errors: List[str] = []
    seen_record_ids: set[str] = set()
    scanned_reports = 0
    accepted_reports = 0

    def add(record: Optional[Dict[str, Any]]) -> None:
        if record is None:
            return
        if record["record_id"] in seen_record_ids:
            return
        seen_record_ids.add(record["record_id"])
        records.append(record)

    if include_baseline:
        for entry in EVM_PROXY_KNOWN_DISCLOSURES:
            base = baseline_record(entry)
            if include_mitigation_variants:
                for variant in _three_mitigation_variants(base):
                    add(variant)
                    if limit is not None and len(records) >= limit:
                        break
            else:
                add(base)
            if limit is not None and len(records) >= limit:
                break

    for corpus_dir in corpus_dirs:
        if limit is not None and len(records) >= limit:
            break
        if not corpus_dir.is_dir():
            continue
        for path in sorted(corpus_dir.glob("*.txt")):
            if not is_proxy_relevant_report(path):
                continue
            scanned_reports += 1
            try:
                findings = parse_audit_report(path)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{path}: parse failed: {exc}")
                continue
            took_any = False
            for finding in findings:
                rec = report_record(finding)
                if rec is not None:
                    add(rec)
                    took_any = True
                if limit is not None and len(records) >= limit:
                    break
            if took_any:
                accepted_reports += 1
            if limit is not None and len(records) >= limit:
                break

    file_paths: List[str] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    schema = _VALIDATOR.load_schema()
    valid_count = 0
    for record in records:
        rendered = yaml_dump(record)
        try:
            doc = yaml.safe_load(rendered)
        except yaml.YAMLError as exc:
            errors.append(f"{record['record_id']}: yaml render failed: {exc}")
            continue
        validation_errors = _VALIDATOR.validate_doc(doc, schema)
        if validation_errors:
            for err in validation_errors:
                errors.append(f"{record['record_id']}: {err}")
            continue
        valid_count += 1
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", record["record_id"]).strip("-._")
        out_path = out_dir / f"{safe_name[:140]}.yaml"
        file_paths.append(str(out_path))
        if not dry_run:
            out_path.write_text(rendered, encoding="utf-8")

    return {
        "schema_version": SCHEMA_VERSION,
        "corpus_dirs": [str(p) for p in corpus_dirs],
        "out_dir": str(out_dir),
        "dry_run": dry_run,
        "scanned_reports": scanned_reports,
        "accepted_reports": accepted_reports,
        "records_emitted": valid_count,
        "records_total": len(records),
        "errors": errors,
        "file_count": len(file_paths),
        "files": file_paths[:50],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--corpus-dir",
        action="append",
        default=[],
        help="EVM audit-report directory (default: reference/corpus_txt/zellic). Repeatable.",
    )
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--no-include-baseline", action="store_true")
    parser.add_argument("--no-mitigation-variants", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    corpus_dirs = [Path(item).expanduser().resolve() for item in args.corpus_dir] or [
        DEFAULT_CORPUS_DIR.resolve()
    ]
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = convert(
        corpus_dirs,
        Path(args.out_dir).expanduser().resolve(),
        dry_run=args.dry_run,
        limit=args.limit,
        include_baseline=not args.no_include_baseline,
        include_mitigation_variants=not args.no_mitigation_variants,
    )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman evm-proxy-upgrade ETL: "
            f"reports={summary['scanned_reports']}/{summary['accepted_reports']} "
            f"records={summary['records_emitted']}/{summary['records_total']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
