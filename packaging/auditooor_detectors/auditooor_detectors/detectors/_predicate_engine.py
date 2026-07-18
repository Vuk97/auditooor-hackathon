"""
_predicate_engine.py - evaluate DSL pattern predicates against Slither IR.
Used by every detector emitted by tools/pattern-compile.py (Issue #85).

Public API:
    eval_preconditions(contract, preconds_list) -> bool
    eval_function_match(function, match_list)   -> bool

Predicate spec: see reference/PATTERN_DSL.md.
"""

import re
from typing import Any, List


_UNKNOWN_PREDICATE_WARNED = set()

_CONTRACT_PREDICATE_ALIASES = {
    "contract.has_func_matching": "contract.has_function_matching",
    "contract.has_func_body_matching": "contract.has_function_body_matching",
    "contract.has_func_body_matching_invert": "contract.has_no_function_body_matching",
    "contract.has_field_matching": "contract.has_state_var_matching",
    "contract.source_contains_regex": "contract.source_matches_regex",
    "repo.source_matches_regex": "contract.source_matches_regex",
}

_FUNCTION_PREDICATE_ALIASES = {
    "function.body_matches_regex": "function.body_contains_regex",
    "function.not_body_matches_regex": "function.body_not_contains_regex",
    "function.body_not_matches_regex": "function.body_not_contains_regex",
    "function.contract_has_source_matching": "function.contract.source_matches_regex",
    "function.not_calls_function_matching": "function.does_not_call_matching",
    "function.not_in_slither_synthetic": "function.not_slither_synthetic",
    "function.has_modifier_regex": "function.has_modifier_matching",
    "function.modifier_not_matches_regex": "function.not_modifiers_match",
    "function.modifiers_not_matching": "function.not_modifiers_match",
    "function.has_modifier_not": "function.not_modifiers_match",
    "function.parameter_named": "function.has_param_name_matching",
    "function.parameter_matches_regex": "function.parameters_include",
    "function.parameter_not_matches_regex": "function.parameters_not_include",
    "function.param_list_contains_regex": "function.parameters_include",
    "function.signature_matches_regex": "function.signature_regex",
    "function.writes_state_var_matches": "function.writes_state_var_matching_regex",
    "function.body_contains_regex_ordered": "function.body_ordered_regex",
}


# ---- Helpers ----

def _inherits_names(contract):
    names = {contract.name}
    try:
        for parent in getattr(contract, "inheritance", []) or []:
            names.add(parent.name)
    except Exception:
        pass
    return names


def _external_call_sites(function):
    """List of (internal_call_node) tuples for every external/highlevel call."""
    out = []
    try:
        for node in getattr(function, "nodes", []) or []:
            # HighLevelCall / LowLevelCall / Send / Transfer
            for ic in getattr(node, "high_level_calls", []) or []:
                out.append(node)
            for lc in getattr(node, "low_level_calls", []) or []:
                out.append(node)
    except Exception:
        pass
    return out


def _has_modifier(function, name):
    try:
        for m in getattr(function, "modifiers", []) or []:
            if getattr(m, "name", "") == name:
                return True
    except Exception:
        pass
    return False


def _modifier_names(function):
    names = []
    try:
        for m in getattr(function, "modifiers", []) or []:
            name = getattr(m, "name", None)
            if name:
                names.append(str(name))
            elif isinstance(m, str):
                names.append(m)
    except Exception:
        pass
    return names


def _function_kind(function):
    vis = getattr(function, "visibility", "") or ""
    return vis  # "external", "public", "internal", "private"


def _state_writes_in_nodes(nodes_list):
    """Count / identify state variable writes across the given Slither nodes."""
    count = 0
    for n in nodes_list:
        count += len(getattr(n, "state_variables_written", []) or [])
    return count


def _node_index(function):
    """Return list of (idx, node). Slither CFG traversal preserves order in .nodes."""
    return list(enumerate(getattr(function, "nodes", []) or []))


def _function_contract(function):
    for attr in ("contract_declarer", "contract"):
        contract = getattr(function, attr, None)
        if contract is not None:
            return contract
    return None


def _function_name_stem(name: str) -> str:
    match = re.match(r"^([a-z]+)(.*)$", name or "")
    if match is None:
        return name or ""
    stem = match.group(2)
    return stem if stem else (name or "")


def _source_without_comments_and_strings(source: str) -> str:
    """Remove comment and literal text so source-regex predicates cannot be faked."""
    token_re = re.compile(
        r'"(?:[^"\\]|\\.)*"|'
        r"'(?:[^'\\]|\\.)*'|"
        r"//[^\n\r]*|"
        r"/\*.*?\*/",
        re.DOTALL,
    )

    def replace_token(match):
        text = match.group(0)
        return "\n" * text.count("\n") if "\n" in text else " "

    return token_re.sub(replace_token, source)


def _source_content(obj) -> str:
    try:
        return obj.source_mapping.content or ""
    except Exception:
        return ""


def _function_source(function) -> str:
    try:
        return function.source_mapping.content or ""
    except Exception:
        return ""


def _source_contains_value(source: str, value: Any) -> bool:
    if isinstance(value, (list, tuple, set)):
        return all(str(item) in source for item in value)
    return str(value) in source


def _strip_comments(source: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", str(source or ""), flags=re.DOTALL)
    return re.sub(r"//[^\n\r]*", "", text)


def _contract_search_blob(contract) -> str:
    parts = [_source_without_comments_and_strings(_source_content(contract)), getattr(contract, "name", "") or ""]
    try:
        parts.extend(sorted(_inherits_names(contract)))
    except Exception:
        pass
    try:
        funcs = (
            getattr(contract, "functions_and_modifiers_declared", None)
            or getattr(contract, "functions", None)
            or []
        )
        for f in funcs:
            parts.append(getattr(f, "name", "") or "")
            parts.append(_source_without_comments_and_strings(_function_source(f)))
    except Exception:
        pass
    return "\n".join(str(part) for part in parts if part)


def _contract_matches_any(contract, patterns: List[str]) -> bool:
    blob = _contract_search_blob(contract)
    return any(re.search(pattern, blob, re.IGNORECASE | re.DOTALL) for pattern in patterns)


def _contract_has_all(contract, patterns: List[str]) -> bool:
    blob = _contract_search_blob(contract)
    return all(re.search(pattern, blob, re.IGNORECASE | re.DOTALL) for pattern in patterns)


def _parse_bang_predicate_string(predicate: str):
    """Parse legacy compiled strings like ``!function.body_contains_regex: 'rx'``."""
    text = predicate.strip()
    if not text.startswith("!") or ":" not in text:
        return None
    key, raw_value = text[1:].split(":", 1)
    key = key.strip()
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    elif value.lower() == "true":
        value = True
    elif value.lower() == "false":
        value = False
    return key, value


def _warn_unknown_predicate_once(context: str, key: str, previous_behavior: str = "silent True") -> None:
    marker = (context, key)
    if marker in _UNKNOWN_PREDICATE_WARNED:
        return
    _UNKNOWN_PREDICATE_WARNED.add(marker)
    import sys as _sys
    _sys.stderr.write(
        "[predicate_engine] UNKNOWN %s predicate key %r - "
        "returning False (was: %s). Fix the pattern YAML.\n" % (context, key, previous_behavior)
    )


# ---- Contract-level predicates ----

def _check_contract_pred(c, key, val):
    key = _CONTRACT_PREDICATE_ALIASES.get(key, key)
    if key == "chain.is_zk_circuit":
        # This Slither-backed engine only has Solidity contract context. A ZK
        # circuit domain gate cannot be proven here, so `true` must fail closed
        # instead of warning once per contract during broad external recall.
        return not bool(val)
    if key in {
        "chain.is_cosmos_sdk",
        "chain.is_btc_spv_verifier",
        "chain.is_l2_with_shadow_eth_erc20",
        "crate.source_matches_regex",
    }:
        # Domain gates that cannot be proven from a Solidity contract through
        # Slither. True fails closed, false passes, and no warning spam.
        return not bool(val)
    if key in {"contract.name_matches", "contract.name_matches_regex"}:
        return bool(re.search(val, getattr(c, "name", "") or "", re.IGNORECASE))
    if key == "contract.name_equals":
        return (getattr(c, "name", "") or "") == str(val)
    if key == "contract.implements_any_interface" or key == "contract.inherits_any":
        want = set(val or [])
        names = _inherits_names(c)
        return len(names & want) > 0
    if key == "contract.inherits_regex":
        rx = re.compile(val, re.IGNORECASE)
        return any(rx.search(name or "") for name in _inherits_names(c))
    if key == "contract.inherits":
        names = _inherits_names(c)
        if isinstance(val, (list, tuple, set)):
            return bool(names & {str(item) for item in val})
        return str(val) in names
    if key == "contract.has_state_var_matching":
        rx = re.compile(val, re.IGNORECASE)
        try:
            for sv in getattr(c, "state_variables", []) or []:
                if rx.search(sv.name or ""):
                    return True
        except Exception:
            pass
        return False
    if key == "contract.has_function_matching":
        rx = re.compile(val, re.IGNORECASE)
        try:
            for f in getattr(c, "functions", []) or []:
                if rx.search(f.name or ""):
                    return True
        except Exception:
            pass
        return False
    if key == "contract.has_function_body_matching":
        # Round 26: scan ANY function's body (including constructor) for a regex.
        # Used by uups-missing-disable-initializers to check for
        # `_disableInitializers` in the constructor.
        rx = re.compile(val, re.IGNORECASE)
        try:
            for f in getattr(c, "functions", []) or []:
                try:
                    src = f.source_mapping.content or ""
                except Exception:
                    src = ""
                if rx.search(src):
                    return True
        except Exception:
            pass
        return False
    if key == "contract.has_multiple_funcs_doing":
        rx = re.compile(str(val), re.IGNORECASE)
        count = 0
        try:
            funcs = getattr(c, "functions", None) or []
            for f in funcs:
                if rx.search(_function_source(f)):
                    count += 1
                    if count >= 2:
                        return True
        except Exception:
            pass
        return False
    if key == "contract.has_function_without_modifier":
        rx = re.compile(str(val), re.IGNORECASE)
        try:
            funcs = (
                getattr(c, "functions_and_modifiers_declared", None)
                or getattr(c, "functions", None)
                or []
            )
        except Exception:
            funcs = []
        for function in funcs:
            if getattr(function, "is_constructor", False):
                continue
            visibility = str(getattr(function, "visibility", "") or "").lower()
            if visibility and visibility not in {"external", "public"}:
                continue
            mutability = str(getattr(function, "state_mutability", "") or "").lower()
            if mutability in {"view", "pure"}:
                continue
            if any(rx.search(name) for name in _modifier_names(function)):
                continue
            return bool(val)
        return not bool(val)
    if key == "contract.has_no_function_body_matching":
        # Inverse of contract.has_function_body_matching. Returns True when
        # NO function body matches the regex. This is the form the
        # uups-missing-disable-initializers pattern actually needs.
        rx = re.compile(val, re.IGNORECASE)
        try:
            for f in getattr(c, "functions", []) or []:
                try:
                    src = f.source_mapping.content or ""
                except Exception:
                    src = ""
                if rx.search(src):
                    return False
        except Exception:
            pass
        return True
    # Round 32 engine v5: contract-level source regex (scans the CONTRACT's
    # full source text, not just function bodies). Catches contract-scope
    # state declarations like `uint256[50] __gap` that don't appear inside
    # any function body. Needed for proxy-storage-gap-missing and
    # pausable-inherits-but-no-exposure patterns.
    if key in {"contract.source_matches_regex", "function.contract.source_matches_regex"}:
        rx = re.compile(val, re.IGNORECASE)
        return bool(rx.search(_source_content(c)))
    if key == "contract.source_contains":
        return _source_contains_value(_source_content(c), val)
    if key == "contract.not_source_contains":
        return not _source_contains_value(_source_content(c), val)
    if key == "contract.source_contains_any":
        source = _source_content(c)
        return any(str(item) in source for item in (val or []))
    if key == "contract.source_contains_all":
        source = _source_content(c)
        return all(str(item) in source for item in (val or []))
    if key == "contract.body_contains_regex":
        rx = re.compile(val, re.IGNORECASE)
        return bool(rx.search(_source_content(c)))
    if key == "contract.source_not_contains_regex":
        rx = re.compile(val, re.IGNORECASE)
        return not bool(rx.search(_source_content(c)))
    if key == "contract.body_not_contains_regex":
        rx = re.compile(val, re.IGNORECASE)
        return not bool(rx.search(_source_content(c)))
    if key == "contract.constructor_not_calls_regex":
        rx = re.compile(str(val), re.IGNORECASE)
        try:
            funcs = (
                getattr(c, "functions_and_modifiers_declared", None)
                or getattr(c, "functions", None)
                or []
            )
            for f in funcs:
                is_ctor = bool(getattr(f, "is_constructor", False)) or (getattr(f, "name", "") == "constructor")
                if is_ctor and rx.search(_function_source(f)):
                    return False
        except Exception:
            pass
        return True
    if key in {"contract.not_source_matches_regex", "function.contract.not_source_matches_regex"}:
        rx = re.compile(val, re.IGNORECASE)
        return not bool(rx.search(_source_content(c)))
    # Round 32 engine v5: any-of list helper for contract-level check
    if key == "contract.inherits_none_of":
        # True if the contract does NOT inherit from any of the listed names
        want = set(val or [])
        names = _inherits_names(c)
        return len(names & want) == 0
    # Round 34 engine v7: contract-level state-declaration regex.
    # Scans ONLY the contract's own (non-inherited) state variable
    # declarations - unlike `has_state_var_matching` which matches names,
    # this matches the full source text of each declaration (including
    # type, visibility, and initializer). Catches things like
    # `uint256[50] __gap` that are declarations, not function bodies.
    if key == "contract.has_state_declaration_matching":
        rx = re.compile(val, re.IGNORECASE)
        try:
            # Get THIS contract's state vars (not inherited)
            for sv in getattr(c, "variables", []) or []:
                try:
                    decl_src = sv.source_mapping.content or ""
                except Exception:
                    decl_src = ""
                if rx.search(decl_src):
                    return True
                # Fall back to reconstructing from type+name
                try:
                    synthetic = f"{sv.type} {sv.name}"
                    if rx.search(synthetic):
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False
    if key == "contract.has_no_state_declaration_matching":
        rx = re.compile(val, re.IGNORECASE)
        try:
            for sv in getattr(c, "variables", []) or []:
                try:
                    decl_src = sv.source_mapping.content or ""
                except Exception:
                    decl_src = ""
                if rx.search(decl_src):
                    return False
                try:
                    synthetic = f"{sv.type} {sv.name}"
                    if rx.search(synthetic):
                        return False
                except Exception:
                    pass
        except Exception:
            pass
        return True
    # ──────────────────────────────────────────────────────────────────
    # R75 GAP CLOSURE - contract-level AST predicates.
    # ──────────────────────────────────────────────────────────────────

    # R75 Gap 2 (contract side) - any function in this contract calls the given
    # target (contract.function or just function-name regex).
    #   contract.has_external_call_to: ContractName.fnName
    if key == "contract.has_external_call_to":
        target = val if isinstance(val, str) else ""
        if "." in target:
            tgt_contract, tgt_fn = target.split(".", 1)
        else:
            tgt_contract, tgt_fn = "", target
        fn_rx = re.compile(tgt_fn, re.IGNORECASE)
        try:
            for f in getattr(c, "functions", []) or []:
                for n in getattr(f, "nodes", []) or []:
                    for call in getattr(n, "high_level_calls", []) or []:
                        dest = call[0] if isinstance(call, (list, tuple)) and len(call) >= 2 else None
                        dest_fn = call[1] if isinstance(call, (list, tuple)) and len(call) >= 2 else call
                        dest_name = getattr(dest, "name", "") if dest else ""
                        fn_name = getattr(dest_fn, "name", "") if dest_fn else ""
                        if (not tgt_contract or tgt_contract == dest_name) and fn_rx.search(fn_name):
                            return True
        except Exception:
            pass
        return False

    # R75 Gap 3 (contract side) - does this contract declare a mapping field
    # with the given key/value types?
    #   contract.has_mapping: {key: address, value: uint256}
    if key == "contract.has_mapping":
        spec = val if isinstance(val, dict) else {}
        want_key = (spec.get("key") or "").lower()
        want_val = (spec.get("value") or "").lower()
        try:
            for sv in getattr(c, "state_variables", []) or []:
                t = str(getattr(sv, "type", "")).lower()
                if "mapping" in t and want_key in t and want_val in t:
                    return True
        except Exception:
            pass
        return False

    # R75 - convenience: does this contract inherit from an ERC token standard?
    #   contract.is_erc20 / contract.is_erc4626 / contract.is_erc721 / contract.is_erc1155
    if key in ("contract.is_erc20", "contract.is_erc4626", "contract.is_erc721", "contract.is_erc1155"):
        std = key.split(".")[1].replace("is_", "").upper()
        names = _inherits_names(c)
        candidates = {f"I{std}", std, f"{std}Upgradeable", f"I{std}Upgradeable"}
        return bool(names & candidates)

    if key == "contract.is_upgradeable_impl":
        names = _inherits_names(c)
        source = _source_content(c)
        upgrade_names = {
            "Initializable",
            "UUPSUpgradeable",
            "ERC1967Upgrade",
            "ERC1967UpgradeUpgradeable",
            "BeaconProxy",
            "UpgradeableBeacon",
        }
        has_upgrade_parent = bool(names & upgrade_names)
        has_upgrade_source = bool(
            re.search(
                r"(?i)\b(_authorizeUpgrade|upgradeTo|upgradeToAndCall|proxiableUUID|"
                r"_upgradeTo|_upgradeToAndCall|__\w+_init|initializer|onlyInitializing)\b",
                source,
            )
        )
        result = has_upgrade_parent or has_upgrade_source
        return result == bool(val)

    if key == "contract.is_upgradeable_or_proxy":
        names = _inherits_names(c)
        proxy_names = {
            "Initializable",
            "UUPSUpgradeable",
            "ERC1967Proxy",
            "ERC1967Upgrade",
            "TransparentUpgradeableProxy",
            "BeaconProxy",
            "Proxy",
        }
        result = bool(names & proxy_names) or _contract_matches_any(
            c,
            [
                r"\b(initializer|reinitializer|onlyInitializing|_disableInitializers)\b",
                r"\b(upgradeTo|upgradeToAndCall|_authorizeUpgrade|proxiableUUID)\b",
                r"\b(ERC1967|UUPS|TransparentUpgradeableProxy|BeaconProxy)\b",
            ],
        )
        return result == bool(val)

    if key == "contract.is_balancer_linear_pool":
        result = _contract_matches_any(c, [r"\b(ERC4626LinearPool|LinearPool|Balancer|BPT)\b"]) and (
            _contract_matches_any(c, [r"\b(mainBalance|_mainBalance|wrappedSupply|_wrappedSupply)\b"])
            or _contract_matches_any(c, [r"\b(swapGivenOut|onSwap|_calcInGivenOut)\b"])
        )
        return result == bool(val)

    if key == "contract.has_pool_registry":
        result = _contract_matches_any(c, [r"\b(wellRegistry|poolRegistry|registeredPools?)\b"]) or (
            _contract_matches_any(c, [r"\b(wells|pools)\s*\["])
            and _contract_matches_any(c, [r"\b(isWhitelisted|isValidWell|isPool|isWell)\s*\("])
        )
        return result == bool(val)

    if key == "contract.is_price_feed_adapter":
        result = (
            _contract_matches_any(c, [r"\b(PriceFeed|PriceOracle|OracleAdapter)\b"])
            and _contract_matches_any(c, [r"\b(pricePerShare|tokenPrice|getUnderlyingAmount|getRate|getNAV|calcUnderlying|exchangeRateStored)\b"])
        )
        return result == bool(val)

    if key == "contract.inherits_gsn_or_access_base":
        names = _inherits_names(c)
        gsn_names = {
            "BasePaymaster",
            "RelayRecipient",
            "GSNRecipient",
            "ERC2771Context",
            "BaseRelayRecipient",
        }
        result = bool(names & gsn_names) or _contract_matches_any(
            c,
            [
                r"\b(isTrustedForwarder|trustedForwarder|_trustedForwarder)\b",
                r"\b(preRelayedCall|acceptRelayedCall|relayCall|_msgSender)\b",
                r"\b(ERC2771Context|BasePaymaster|RelayRecipient|GSN)\b",
            ],
        )
        return result == bool(val)

    if key == "contract.has_buy_reward_or_sell_penalty":
        result = _contract_matches_any(c, [r"\b(buyReward|sellPenalty|applyPenalty|isPenaltyApplied)\b"]) or (
            _contract_matches_any(c, [r"\b(peg|penalty)\b"])
            and _contract_matches_any(c, [r"\b(getReserves|IUniswapV2Pair|swap)\b"])
        )
        return result == bool(val)

    if key == "contract.is_lending_or_collateral_manager":
        result = _contract_matches_any(c, [r"\b(activeCurrencies|bitmapCurrency|freeCollateral|accountContext)\b"]) or (
            _contract_matches_any(c, [r"\b(collateral|borrow|debt|liquidat|healthFactor)\b"])
            and _contract_matches_any(c, [r"\b(Lending|Collateral|Notional|Market)\b"])
        )
        return result == bool(val)

    if key == "contract.is_lending_market":
        result = _contract_matches_any(c, [r"\b(totalBorrows|totalBorrow|totalDeposits|totalDeposit)\b"]) and (
            _contract_matches_any(c, [r"\b(utilization|accrueInterest|borrowShares|depositShares)\b"])
            or _contract_matches_any(c, [r"\b(Silo|Lending|Market)\b"])
        )
        return result == bool(val)

    if key == "contract.is_yield_strategy_or_vault":
        names = _inherits_names(c)
        result = bool(names & {"ERC4626", "IERC4626"}) or (
            _contract_matches_any(c, [r"\b(ERC4626|Vault|Strategy|totalAssets|poolCached|cachedBalance)\b"])
            and _contract_matches_any(c, [r"\b(redeem|withdraw|burn|previewRedeem|convertToAssets)\b|\bbalanceOf\s*\(\s*address\s*\(\s*this\s*\)"])
        )
        return result == bool(val)

    if key == "contract.not_in_skip_list":
        # Detector templates already apply vendored/test filtering before
        # predicate evaluation. Keep legacy generated specs from spamming here.
        return True

    if key.startswith("function."):
        # Compatibility for a small set of legacy/generated YAMLs that placed
        # function predicates in `preconditions`. Interpret them as "any
        # declared function satisfies this predicate" rather than warning once
        # per broad scoreboard run.
        try:
            funcs = (
                getattr(c, "functions_and_modifiers_declared", None)
                or getattr(c, "functions", None)
                or []
            )
            return any(_check_function_pred(f, key, val) for f in funcs)
        except Exception:
            return False

    # R65 SKILL_ISSUES #165: previously "Unknown = conservative pass" silently
    # accepted typo'd predicate keys (e.g. function.has_param_matching instead of
    # function.has_param_name_matching), letting 3 ec-* patterns fire uncontrolled
    # on Centrifuge with 71% FP rate. Now fail-LOUD: warn to stderr + return False
    # so the detector SKIPS instead of firing on everything.
    _warn_unknown_predicate_once("contract", key)
    return False


def eval_preconditions(contract, preconds: List[Any]) -> bool:
    """AND of all preconditions."""
    if not preconds:
        return True
    for p in preconds:
        if isinstance(p, dict):
            for k, v in p.items():
                if not _check_contract_pred(contract, k, v):
                    return False
        elif isinstance(p, str):
            # Bare "contract.something: true" handled by caller
            pass
    return True


# ---- Function-level predicates ----

def _check_function_pred(function, key, val):
    key = _FUNCTION_PREDICATE_ALIASES.get(key, key)
    if key.startswith("contract.") or key.startswith("function.contract."):
        contract = _function_contract(function)
        if contract is None:
            return False
        return _check_contract_pred(contract, key, val)

    # ──────────────────────────────────────────────────────────────────
    # R94-D / R74-D - AST-level top-20 dispatch.
    # Keys of the form:
    #   function.ast: <label>       → True iff AST helper `label` matches.
    #   function.not_ast: <label>   → True iff AST helper `label` does NOT match.
    # Helper labels are defined in tools/slither_predicates.py. This block is
    # the only wiring the compiled detectors need - they keep their existing
    # regex predicates as AND-siblings (graceful degrade when tools/ is missing).
    # ──────────────────────────────────────────────────────────────────
    if key in ("function.ast", "function.not_ast"):
        try:
            import sys as _sys
            from pathlib import Path as _P
            _here = _P(__file__).resolve().parent.parent
            if str(_here) not in _sys.path:
                _sys.path.insert(0, str(_here))
            from tools.slither_predicates import check as _ast_check  # noqa: E402
            hit = bool(_ast_check(function, val))
            return hit if key == "function.ast" else (not hit)
        except Exception:
            # Slither-predicates module missing or IR unavailable.
            # Conservative pass: don't block the match on this key.
            # The detector's other (regex) predicates remain authoritative.
            return True

    if key == "function.kind":
        vis = _function_kind(function)
        if val == "external_or_public":
            return vis in ("external", "public")
        if val == "any":
            return True
        # PR #140 Part 3 (Codex decision point 1): honor any composite formed
        # by joining 2+ of {external, public, internal, private} with `_or_`
        # separators (e.g. `external_or_public_or_internal`,
        # `internal_or_external`, `internal_or_private`). Also normalize the
        # legacy pipe typo `internal|external_or_public` by splitting on `|`
        # first. Tokens must be PURE Solidity visibility keywords - anything
        # else (state-mutability `view`, non-Solidity markers like
        # `rust_fn_runtime`) falls through to the atomic-equality branch and
        # is caught by the detector-lint Check 7 fail-loud. Decision points
        # 2 + 3: state-mutability hybrids and domain markers stay fail-loud.
        _VIS_TOKENS = {"external", "public", "internal", "private"}
        if isinstance(val, str) and ("_or_" in val or "|" in val):
            tokens = []
            ok = True
            for piece in val.split("|"):
                for tok in piece.split("_or_"):
                    tok = tok.strip()
                    if tok in _VIS_TOKENS:
                        tokens.append(tok)
                    else:
                        ok = False
                        break
                if not ok:
                    break
            if ok and len(tokens) >= 2:
                return vis in set(tokens)
        return vis == val

    # Round 27 engine v3: is_payable (flagged by 4 agents as high-value)
    if key == "function.is_payable":
        payable = getattr(function, "payable", False)
        return payable == bool(val)

    # Round 27 engine v3: state_mutability (flagged by 2 agents)
    if key == "function.state_mutability":
        # val can be "view", "pure", "nonpayable", "payable"
        view = getattr(function, "view", False)
        pure = getattr(function, "pure", False)
        payable = getattr(function, "payable", False)
        if val == "view":
            return view and not pure
        if val == "pure":
            return pure
        if val == "payable":
            return payable
        if val == "nonpayable":
            return not (view or pure or payable)
        return False

    # Round 27 engine v3: has_param_of_type (flagged by 2 agents)
    if key == "function.has_param_of_type":
        # val can be "address", "uint256", etc.
        wanted = str(val)
        try:
            for p in getattr(function, "parameters", []) or []:
                t = str(getattr(p, "type", "") or "")
                if wanted in t:
                    return True
        except Exception:
            pass
        return False

    if key == "function.has_address_parameter":
        has_address = _check_function_pred(function, "function.has_param_of_type", "address")
        return has_address == bool(val)

    if key == "function.has_param_name_matching":
        rx = re.compile(str(val), re.IGNORECASE)
        try:
            for p in getattr(function, "parameters", []) or []:
                if rx.search(getattr(p, "name", "") or ""):
                    return True
        except Exception:
            pass
        return False

    # Back-compat alias used by legacy/generated YAMLs:
    #   function.parameters_include: '<regex>'
    # Match against "<type> <name>" per parameter declaration.
    if key == "function.parameters_include":
        rx = re.compile(str(val), re.IGNORECASE)
        try:
            for p in getattr(function, "parameters", []) or []:
                p_type = str(getattr(p, "type", "") or "")
                p_name = str(getattr(p, "name", "") or "")
                candidate = f"{p_type} {p_name}".strip()
                if rx.search(candidate):
                    return True
        except Exception:
            pass
        return False

    if key == "function.parameters_not_include":
        return not _check_function_pred(function, "function.parameters_include", val)

    if key == "function.parameter_names_match":
        rx = re.compile(str(val), re.IGNORECASE)
        try:
            names = ",".join(getattr(p, "name", "") or "" for p in (getattr(function, "parameters", []) or []))
        except Exception:
            names = ""
        return bool(rx.search(names))

    # Round 29 engine v4 gap fix #1: Slither synthetic-function filter.
    # Drop hits from slitherConstructorConstantVariables / slitherConstructorVariables
    # that compiler synthesizes for contracts with non-reassignable constants.
    if key == "function.not_slither_synthetic":
        name = function.name or ""
        is_synth = name.startswith("slither") or name == "constructor"
        return (not is_synth) if bool(val) else True

    # Round 29 engine v4 gap fix #2: skip pure/view/library functions for
    # reentrancy patterns (addresses the 7/8 FPs callback-reentrancy-no-guard
    # produced on morpho-blue's pure helpers).
    if key == "function.is_mutating":
        view = getattr(function, "view", False)
        pure = getattr(function, "pure", False)
        mutating = not (view or pure)
        return mutating == bool(val)

    # Round 29 engine v4 gap fix #3: abi.encodePacked collision precision -
    # only flag when at least 2 DYNAMIC-type args are present (string/bytes/array).
    # This is a body-regex shortcut; a proper AST check is future work.
    if key == "function.body_has_multi_dynamic_encodepacked":
        try:
            src = function.source_mapping.content or ""
        except Exception:
            src = ""
        # Match abi.encodePacked( ... ) and look for 2+ of string/bytes/array-like tokens
        pattern = re.compile(
            r"abi\.encodePacked\s*\(([^)]+)\)", re.DOTALL
        )
        for m in pattern.finditer(src):
            body = m.group(1)
            dynamic_count = sum([
                1 if re.search(r"\bstring\b|\bbytes\b(?!\d)|\[\]", body) else 0,
                len(re.findall(r"\bmsg\.data\b|\.name\s*\(|\.symbol\s*\(", body)),
            ])
            # Also check comma-separated arg count with dynamic types
            args = [a.strip() for a in body.split(",")]
            dynamic_args = sum(1 for a in args
                               if re.search(r"string|bytes(?!\d)|\[\]|\.name\(|\.symbol\(", a))
            if dynamic_args >= 2:
                return bool(val)
        return not bool(val)

    # Round 29 engine v4 gap fix #4: constructor-body check - for uups pattern,
    # we want to assert the constructor body DOES/DOES NOT contain a regex.
    if key == "function.is_constructor":
        is_ctor = getattr(function, "is_constructor", False)
        return is_ctor == bool(val)

    if key == "function.is_override":
        result = bool(getattr(function, "is_override", False))
        if not result:
            for attr in ("overrides", "overridden", "functions_overridden"):
                try:
                    if getattr(function, attr, None):
                        result = True
                        break
                except Exception:
                    pass
        if not result:
            src = _source_without_comments_and_strings(_function_source(function))
            head = re.split(r"[{;]", src, maxsplit=1)[0]
            result = bool(re.search(r"\boverride\b", head, re.IGNORECASE))
        return result == bool(val)

    # Round 29 engine v4 gap fix #5: bytes.concat EIP-712 recognition. Not a
    # predicate per se; callers should broaden their body_contains_regex to
    # include `bytes\.concat\s*\(\s*["\']\\\\x19\\\\x01` as an EIP-712 indicator.
    # Documented here so pattern authors know the v4 engine considers it valid.

    # Round 29 engine v4 gap fix #6: hit aggregation is at the detector runtime
    # level, not predicate level. Handled separately in run_custom.py.

    if key == "function.name":
        return (function.name or "") == str(val)

    if key in {"function.name_matches", "function.name_matches_regex"}:
        return bool(re.search(val, function.name or "", re.IGNORECASE))

    if key == "function.signature_regex":
        try:
            params = []
            for p in getattr(function, "parameters", []) or []:
                p_type = str(getattr(p, "type", "") or "")
                p_name = str(getattr(p, "name", "") or "")
                params.append(f"{p_type} {p_name}".strip())
            signature = f"{function.name or ''}({', '.join(params)})"
        except Exception:
            signature = function.name or ""
        return bool(re.search(str(val), signature, re.IGNORECASE))

    if key == "function.has_external_call":
        has = len(_external_call_sites(function)) > 0
        return has == bool(val)

    if key == "function.external_call_count_gte":
        return len(_external_call_sites(function)) >= int(val)

    if key == "function.post_external_call_mutates_state":
        # Find the first external-call node index, check if any state write appears after
        nodes = getattr(function, "nodes", []) or []
        first_ext = None
        for i, n in enumerate(nodes):
            if (getattr(n, "high_level_calls", None) or
                getattr(n, "low_level_calls", None)):
                first_ext = i
                break
        if first_ext is None:
            return not bool(val)  # no external call → not CEI-violating
        post_writes = _state_writes_in_nodes(nodes[first_ext + 1:])
        return (post_writes > 0) == bool(val)

    if key == "function.pre_external_call_mutates_state":
        nodes = getattr(function, "nodes", []) or []
        first_ext = None
        for i, n in enumerate(nodes):
            if (getattr(n, "high_level_calls", None) or
                getattr(n, "low_level_calls", None)):
                first_ext = i
                break
        if first_ext is None:
            return not bool(val)
        pre_writes = _state_writes_in_nodes(nodes[:first_ext])
        return (pre_writes > 0) == bool(val)

    if key == "function.has_modifier":
        # { includes: [list], negate: bool }
        if isinstance(val, dict):
            includes = val.get("includes", []) or []
            negate = bool(val.get("negate", False))
            present = any(_has_modifier(function, m) for m in includes)
            return (not present) if negate else present
        if isinstance(val, str):
            rx = re.compile(val, re.IGNORECASE)
            return any(rx.search(name) for name in _modifier_names(function))
        # Bare: list of modifier names, all required
        return all(_has_modifier(function, m) for m in (val or []))

    if key == "function.has_modifier_matching":
        rx = re.compile(str(val), re.IGNORECASE)
        return any(rx.search(name) for name in _modifier_names(function))

    if key == "function.not_modifiers_match":
        rx = re.compile(str(val), re.IGNORECASE)
        return not any(rx.search(name) for name in _modifier_names(function))

    if key == "function.body_ordered_regex":
        # Dict shape:
        #   {first: "regex A", second: "regex B", ignore_comments_and_strings: true}
        # Legacy YAMLs emitted a compact list shape:
        #   [ "regex A", "regex B" ]
        #
        # This is intentionally source-regex based because it is used for
        # sequence bugs where the order of two assignments matters. The
        # optional comment/string stripping keeps bait comments from creating
        # fake ordered hits.
        if isinstance(val, (list, tuple)) and len(val) >= 2:
            spec = {"first": val[0], "second": val[1]}
        else:
            spec = val if isinstance(val, dict) else {}
        first = spec.get("first") or ""
        second = spec.get("second") or ""
        negate = bool(spec.get("negate", False))
        if not first or not second:
            return False if not negate else True
        try:
            src = function.source_mapping.content or ""
        except Exception:
            src = ""
        if spec.get("ignore_comments_and_strings") or spec.get("strip_comments_and_strings"):
            src = _source_without_comments_and_strings(src)
        flags = re.IGNORECASE | re.DOTALL
        first_match = re.search(first, src, flags)
        found = False
        if first_match is not None:
            found = bool(re.search(second, src[first_match.end():], flags))
        return (not found) if negate else found

    if key == "function.body_contains_regex":
        # Accepts either a raw regex string or a dict {regex: "...", negate: bool}.
        # Round 26: added negate support so absence-of-guard patterns don't need
        # regex-gymnastics workarounds.
        pattern = val
        negate = False
        if isinstance(val, dict):
            pattern = val.get("regex") or val.get("pattern", "")
            negate = bool(val.get("negate", False))
        try:
            src = function.source_mapping.content or ""
        except Exception:
            src = ""
        found = bool(re.search(pattern, src, re.IGNORECASE))
        return (not found) if negate else found

    if key in {"function.body_not_contains_regex", "function.not_body_contains_regex"}:
        # Convenience inverse of body_contains_regex. Returns True when the
        # function body does NOT match the regex. Accepts either a raw regex
        # string or a dict {regex: "...", flags: "..."} matching the shape
        # used by body_contains_regex above. (Some YAMLs emitted by the
        # auto-migrator wrap the regex in a dict; passing the dict to
        # re.search raises TypeError, the upstream eval_function_match catches
        # it as "predicate failed", and the detector goes silent.)
        pattern = val
        if isinstance(val, dict):
            pattern = val.get("regex") or val.get("pattern", "")
        try:
            src = function.source_mapping.content or ""
        except Exception:
            src = ""
        return not bool(re.search(pattern, src, re.IGNORECASE))

    # Phase 82c: function-level source regex predicates (used by 1,600+ patterns)
    if key == "function.source_matches_regex":
        try:
            src = function.source_mapping.content or ""
        except Exception:
            src = ""
        return bool(re.search(val, src, re.IGNORECASE))

    if key == "function.source_contains":
        try:
            src = function.source_mapping.content or ""
        except Exception:
            src = ""
        return _source_contains_value(src, val)

    if key == "function.source_not_contains":
        try:
            src = function.source_mapping.content or ""
        except Exception:
            src = ""
        return not _source_contains_value(src, val)

    if key == "function.source_contains_all":
        try:
            src = function.source_mapping.content or ""
        except Exception:
            src = ""
        return all(str(item) in src for item in (val or []))

    if key == "function.not_source_matches_regex":
        try:
            src = function.source_mapping.content or ""
        except Exception:
            src = ""
        return not bool(re.search(val, src, re.IGNORECASE))

    if key == "function.body_contains_external_call_to_user_supplied_addr":
        src = _function_source(function)
        param_names = []
        try:
            for p in getattr(function, "parameters", []) or []:
                p_type = str(getattr(p, "type", "") or "")
                p_name = str(getattr(p, "name", "") or "")
                if "address" in p_type.lower() and p_name:
                    param_names.append(re.escape(p_name))
        except Exception:
            pass
        if not param_names:
            return False if bool(val) else True
        joined = "|".join(param_names)
        call_rx = re.compile(
            rf"(?is)"
            rf"(?:\b(?:{joined})\b\s*\.\s*(?:call|delegatecall|staticcall)\s*\()"
            rf"|(?:I[A-Za-z0-9_]*\s*\(\s*(?:{joined})\s*\)\s*\.)"
            rf"|(?:\b(?:{joined})\b\s*\.\s*[A-Za-z_]\w*\s*\()"
        )
        result = bool(call_rx.search(src))
        return result == bool(val)

    if key == "function.parent_contains_regex":
        contract = _function_contract(function)
        if contract is None:
            return False if bool(val) else True
        result = bool(re.search(str(val), _contract_search_blob(contract), re.IGNORECASE | re.DOTALL))
        return result == bool(val)

    if key == "function.body_lacks_recipient_code_guard_or_tier_update":
        src = _function_source(function)
        guard_or_tier_update = re.compile(
            r"(?is)"
            r"(?:codes|accountCodes|codeByAccount|codeOf|referralCodeOf|userCode|referrerCode)"
            r"\s*\[\s*(?:_newAccount|newAccount|newOwner|recipient|to)\s*\]\s*"
            r"(?:==|!=)\s*(?:bytes32\s*\(\s*0\s*\)|0x0?|\"\"|'')"
            r"|(?:require|if)\s*\([^;{}]{0,180}"
            r"(?:_newAccount|newAccount|newOwner|recipient|to)[^;{}]{0,180}"
            r"(?:code|referr)"
            r"|(?:referrerTiers|feeTiers|tiers|accountTiers|userTiers)\s*\["
            r"[^;\]]*(?:_newAccount|newAccount|newOwner|recipient|to)",
        )
        lacks = not bool(guard_or_tier_update.search(src))
        return lacks == bool(val)

    if key in {
        "function.internal_calling_regex",
        "function.not_internal_calling_regex",
    }:
        rx = re.compile(val, re.IGNORECASE)
        negate = key.startswith("function.not_")
        found = False
        for c in (getattr(function, "internal_calls", []) or []):
            nm = getattr(c, "name", "") or str(c)
            if rx.search(nm):
                found = True
                break
        if not found:
            for n in getattr(function, "nodes", []) or []:
                for c in (getattr(n, "internal_calls", []) or []):
                    nm = getattr(c, "name", "") or str(c)
                    if rx.search(nm):
                        found = True
                        break
                if found:
                    break
        return (not found) if negate else found

    if key in {
        "function.high_level_calling_regex",
        "function.not_high_level_calling_regex",
    }:
        rx = re.compile(val, re.IGNORECASE)
        negate = key.startswith("function.not_")
        found = False
        for hc_tuple in (getattr(function, "high_level_calls", []) or []):
            hc = hc_tuple[1] if isinstance(hc_tuple, tuple) else hc_tuple
            callee = getattr(hc, "function", hc)
            nm = getattr(callee, "name", "") or str(callee)
            if rx.search(nm):
                found = True
                break
        if not found:
            for n in getattr(function, "nodes", []) or []:
                for hc_tuple in (getattr(n, "high_level_calls", []) or []):
                    hc = hc_tuple[1] if isinstance(hc_tuple, tuple) else hc_tuple
                    callee = getattr(hc, "function", hc)
                    nm = getattr(callee, "name", "") or str(callee)
                    if rx.search(nm):
                        found = True
                        break
                if found:
                    break
        return (not found) if negate else found

    if key in {
        "function.calls_function_matching",
        "function.calls_function_matching_regex",
        "function.does_not_call_matching",
        "function.does_not_call_matching_regex",
    }:
        # Round 26: add negate support here too (for reward-distribution pattern).
        pattern = val
        negate = key in {"function.does_not_call_matching", "function.does_not_call_matching_regex"}
        if isinstance(val, dict):
            pattern = val.get("regex") or val.get("pattern", "")
            negate = negate ^ bool(val.get("negate", False))
        rx = re.compile(pattern, re.IGNORECASE)
        found = False
        for c in (getattr(function, "internal_calls", []) or []):
            nm = getattr(c, "name", "") or ""
            if rx.search(nm):
                found = True
                break
        if not found:
            for hc_tuple in (getattr(function, "high_level_calls", []) or []):
                hc = hc_tuple[1] if isinstance(hc_tuple, tuple) else hc_tuple
                callee = getattr(hc, "function", hc)
                nm = getattr(callee, "name", "") or ""
                if rx.search(nm):
                    found = True
                    break
        for n in getattr(function, "nodes", []) or []:
            if found:
                break
            for c in (getattr(n, "internal_calls", []) or []):
                nm = getattr(c, "name", "") or ""
                if rx.search(nm):
                    found = True
                    break
            if found:
                break
            for hc_tuple in (getattr(n, "high_level_calls", []) or []):
                hc = hc_tuple[1] if isinstance(hc_tuple, tuple) else hc_tuple
                callee = getattr(hc, "function", hc)
                nm = getattr(callee, "name", "") or ""
                if rx.search(nm):
                    found = True
                    break
            if found:
                break
        if not found:
            try:
                src = function.source_mapping.content or ""
            except Exception:
                src = ""
            if src and rx.search(src):
                found = True
        return (not found) if negate else found

    if key in {
        "function.reads_storage_matching",
        "function.reads_state_var_matching",
        "function.reads_state_var_matching_regex",
    }:
        rx = re.compile(val, re.IGNORECASE)
        for sv in getattr(function, "state_variables_read", []) or []:
            if rx.search(sv.name or ""):
                return True
        return False

    if key in {
        "function.writes_storage_matching",
        "function.writes_state_var_matching_regex",
        "function.does_not_write_state_var_matching_regex",
    }:
        rx = re.compile(val, re.IGNORECASE)
        negate = key == "function.does_not_write_state_var_matching_regex"
        for sv in getattr(function, "state_variables_written", []) or []:
            if rx.search(sv.name or ""):
                return not negate
        return negate

    if key == "function.not_writes_state_var_matching":
        rx = re.compile(val, re.IGNORECASE)
        for sv in getattr(function, "state_variables_written", []) or []:
            if rx.search(sv.name or ""):
                return False
        return True

    if key == "function.has_paired_function":
        spec = val if isinstance(val, dict) else {"partner_regex": val}
        partner_regex = str(spec.get("partner_regex") or "")
        if not partner_regex:
            return False
        stem = _function_name_stem(function.name or "")
        resolved_regex = re.sub(r"\\([1-9])", stem, partner_regex)
        partner_writes = str(spec.get("partner_writes_state_var_matching") or "")
        negate = bool(spec.get("negate", False))
        contract = _function_contract(function)
        if contract is None:
            return False if not negate else True
        found = False
        for candidate in getattr(contract, "functions_and_modifiers_declared", []) or []:
            if candidate is function:
                continue
            if not re.search(resolved_regex, candidate.name or "", re.IGNORECASE):
                continue
            if partner_writes:
                write_rx = re.compile(partner_writes, re.IGNORECASE)
                if not any(write_rx.search(sv.name or "") for sv in getattr(candidate, "state_variables_written", []) or []):
                    continue
            found = True
            break
        return (not found) if negate else found

    if key == "function.not_in_skip_list":
        # Handled by detector-level is_vendored_or_test_contract - treat as always true here.
        return True

    if key == "function.not_leaf_helper":
        # Handled by detector-level is_leaf_helper.
        return True

    # Round 34 engine v7: assembly block regex. Scans ONLY inline assembly
    # regions (between `assembly { ... }`). Existing body_contains_regex
    # matches anywhere in the function source, including comments and
    # Solidity-level code. This predicate isolates to the assembly block
    # so patterns like storage-packing can check `shl`/`shr`/`mul` without
    # colliding with Solidity keywords.
    if key == "function.assembly_block_matches":
        try:
            src = function.source_mapping.content or ""
        except Exception:
            return False
        asm_re = re.compile(r"assembly\s*(?:\"[^\"]*\")?\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}",
                            re.DOTALL)
        target = re.compile(val, re.IGNORECASE)
        for m in asm_re.finditer(src):
            if target.search(m.group(1)):
                return True
        return False
    if key == "function.assembly_block_not_matches":
        try:
            src = function.source_mapping.content or ""
        except Exception:
            return True
        asm_re = re.compile(r"assembly\s*(?:\"[^\"]*\")?\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}",
                            re.DOTALL)
        target = re.compile(val, re.IGNORECASE)
        for m in asm_re.finditer(src):
            if target.search(m.group(1)):
                return False
        return True

    # Round 34 engine v7: param name pattern match. Useful for
    # "function has a parameter named X" without requiring a type check
    # (differs from has_param_of_type which is type-based).
    if key == "function.has_param_name_matching":
        rx = re.compile(val, re.IGNORECASE)
        try:
            for p in getattr(function, "parameters", []) or []:
                if rx.search(getattr(p, "name", "") or ""):
                    return True
        except Exception:
            pass
        return False

    # Round 34 engine v7: require N writes after external call.
    # Differentiates "1 CEI violation write" from "3+ CEI violations"
    # - higher severity pattern can require multiple.
    if key == "function.post_external_call_writes_gte":
        nodes = getattr(function, "nodes", []) or []
        first_ext = None
        for i, n in enumerate(nodes):
            if (getattr(n, "high_level_calls", None) or
                getattr(n, "low_level_calls", None)):
                first_ext = i
                break
        if first_ext is None:
            return int(val) == 0
        post_writes = _state_writes_in_nodes(nodes[first_ext + 1:])
        return post_writes >= int(val)

    # ──────────────────────────────────────────────────────────────────
    # R75 GAP CLOSURE - AST-level predicates (replaces top-20 regex).
    # See reference/AST_EXPLAINED.md and reference/R74_MASTER_ROADMAP.md.
    # ──────────────────────────────────────────────────────────────────

    # R75 Gap 1 - Taint-flow: does a function parameter flow to a specific call
    # argument without an intervening require/bound check?
    # R76 extension: follow the call graph (depth 3) so taint propagates through
    # internal helpers. Set `depth: N` in spec to bound traversal.
    #   function.taints_param_to: {from: amount, to: transferFrom, guard: require, depth: 3}
    if key == "function.taints_param_to":
        try:
            spec = val if isinstance(val, dict) else {}
            param_rx = re.compile(spec.get("from", ".*"), re.IGNORECASE)
            target_rx = re.compile(spec.get("to", ".*"), re.IGNORECASE)
            guard_rx = re.compile(spec.get("guard", "require|assert"), re.IGNORECASE)
            max_depth = int(spec.get("depth", 3))
            param_names = {p.name for p in (getattr(function, "parameters", []) or []) if getattr(p, "name", None)}
            tainted = {n for n in param_names if param_rx.search(n)}
            if not tainted:
                return False

            # Inner procedure: walk one function's CFG. Returns (hit_target, became_guarded)
            def walk_fn(fn, tainted_set, seen_fns):
                nodes = getattr(fn, "nodes", []) or []
                guarded_local = False
                for n in nodes:
                    src_str = str(getattr(n, "expression", "") or "")
                    if guard_rx.search(src_str) and any(t in src_str for t in tainted_set):
                        guarded_local = True
                    # Check for target call on this node
                    for c in (getattr(n, "high_level_calls", []) or []) + (getattr(n, "low_level_calls", []) or []):
                        fn_obj = c[1] if isinstance(c, (list, tuple)) and len(c) >= 2 else c
                        nm = getattr(fn_obj, "name", None) or getattr(c, "name", "") or ""
                        if target_rx.search(nm) and any(t in src_str for t in tainted_set) and not guarded_local:
                            return True, guarded_local
                # Not found here - follow internal calls with forwarded tainted names
                if len(seen_fns) >= max_depth:
                    return False, guarded_local
                for n in nodes:
                    for ic in (getattr(n, "internal_calls", []) or []):
                        callee = ic
                        if not hasattr(callee, "parameters"):
                            continue
                        if callee in seen_fns:
                            continue
                        # Forward taint: if any tainted var appears in the call expression,
                        # treat the callee's params as tainted (approximation).
                        callee_params = {p.name for p in (getattr(callee, "parameters", []) or []) if getattr(p, "name", None)}
                        call_expr = str(getattr(n, "expression", "") or "")
                        if any(t in call_expr for t in tainted_set) and callee_params:
                            hit, _ = walk_fn(callee, callee_params, seen_fns | {callee})
                            if hit:
                                return True, guarded_local
                return False, guarded_local

            hit, _ = walk_fn(function, tainted, {function})
            return hit
        except Exception:
            return False

    # R75 Gap 2 - Inter-contract call-graph query: does any function in this
    # contract reach a target (contract.function) via an external call?
    #   function.reaches_external: ContractX.functionY
    #   contract.has_external_call_to: ContractX.functionY  (handled at contract level)
    if key == "function.reaches_external":
        target = val if isinstance(val, str) else ""
        if "." in target:
            tgt_contract, tgt_fn = target.split(".", 1)
        else:
            tgt_contract, tgt_fn = "", target
        try:
            for n in getattr(function, "nodes", []) or []:
                for c in getattr(n, "high_level_calls", []) or []:
                    dest = c[0] if isinstance(c, (list, tuple)) and len(c) >= 2 else None
                    dest_fn = c[1] if isinstance(c, (list, tuple)) and len(c) >= 2 else c
                    dest_name = getattr(dest, "name", "") if dest else ""
                    fn_name = getattr(dest_fn, "name", "") if dest_fn else ""
                    if (not tgt_contract or tgt_contract == dest_name) and re.search(tgt_fn, fn_name, re.IGNORECASE):
                        return True
        except Exception:
            pass
        return False

    # R75 Gap 3 - Type propagation: does function accept a mapping of given shape?
    #   function.has_param_mapping: {key: address, value: uint256}
    # Also exposes function.has_param_struct_named: Name.
    if key == "function.has_param_mapping":
        spec = val if isinstance(val, dict) else {}
        want_key = (spec.get("key") or "").lower()
        want_val = (spec.get("value") or "").lower()
        for p in getattr(function, "parameters", []) or []:
            t = str(getattr(p, "type", "")).lower()
            if "mapping" in t and want_key in t and want_val in t:
                return True
        return False

    if key == "function.has_param_struct_named":
        want = val if isinstance(val, str) else ""
        for p in getattr(function, "parameters", []) or []:
            t = str(getattr(p, "type", ""))
            if want and want in t:
                return True
        return False

    # R75 common replacements for top-6 regex shapes.

    # Replaces body_contains_regex for "\.safeTransfer\s*\(" / "\.transfer\s*\("
    #   function.has_high_level_call_named: safeTransfer|safeApprove
    if key == "function.has_high_level_call_named":
        rx = re.compile(val, re.IGNORECASE)
        for n in getattr(function, "nodes", []) or []:
            for c in getattr(n, "high_level_calls", []) or []:
                fn = c[1] if isinstance(c, (list, tuple)) and len(c) >= 2 else c
                nm = (
                    getattr(fn, "name", "")
                    or getattr(fn, "function_name", "")
                    or getattr(fn, "function", "")
                    or ""
                )
                if not isinstance(nm, str):
                    nm = getattr(nm, "name", "") or str(nm)
                if rx.search(nm):
                    return True
        return False

    # Replaces body_contains_regex for low-level .call{}/.send/.transfer
    #   function.has_low_level_call: true|{op: transfer|send|call}
    if key == "function.has_low_level_call":
        want_op = None
        if isinstance(val, dict):
            want_op = (val.get("op") or "").lower() or None
        for n in getattr(function, "nodes", []) or []:
            for lc in getattr(n, "low_level_calls", []) or []:
                if not want_op:
                    return True
                try:
                    opstr = str(lc).lower()
                    if want_op in opstr:
                        return True
                except Exception:
                    return True
        return False

    # Replaces body_contains_regex for "msg\.sender" / "tx\.origin"
    #   function.reads_msg_sender: true
    #   function.reads_tx_origin: true
    if key == "function.reads_msg_sender" or key == "function.reads_tx_origin":
        target = "msg.sender" if key.endswith("msg_sender") else "tx.origin"
        for n in getattr(function, "nodes", []) or []:
            expr = str(getattr(n, "expression", "") or "")
            if target in expr:
                return True
        return False

    # Replaces body_contains_regex for block.timestamp / block.number
    #   function.reads_block_timestamp: true
    #   function.reads_block_number: true
    if key == "function.reads_block_timestamp" or key == "function.reads_block_number":
        target = "block.timestamp" if key.endswith("timestamp") else "block.number"
        for n in getattr(function, "nodes", []) or []:
            expr = str(getattr(n, "expression", "") or "")
            if target in expr:
                return True
        return False

    # Replaces body_contains_regex for emit Event(...)
    #   function.emits_event_matching: RoleGranted|Withdraw
    if key == "function.emits_event_matching":
        rx = re.compile(val, re.IGNORECASE)
        try:
            for ev in getattr(function, "events_emitted", []) or []:
                nm = getattr(ev, "name", "") or ""
                if rx.search(nm):
                    return True
        except Exception:
            pass
        # Fallback: scan nodes for EMIT expression
        for n in getattr(function, "nodes", []) or []:
            expr = str(getattr(n, "expression", "") or "")
            if "emit " in expr and rx.search(expr):
                return True
        return False

    # Replaces body_contains_regex for require(...) shapes
    #   function.has_require_mentioning: <regex>
    # True if ANY require / assert / revert arg matches the regex.
    if key == "function.has_require_mentioning":
        rx = re.compile(val, re.IGNORECASE)
        for n in getattr(function, "nodes", []) or []:
            expr = str(getattr(n, "expression", "") or "")
            if (expr.startswith("require(") or expr.startswith("assert(") or "revert " in expr):
                if rx.search(expr):
                    return True
        return False

    # Replaces body_contains_regex for "keccak256(abi.encode*)"
    #   function.computes_keccak: true
    if key == "function.computes_keccak":
        for n in getattr(function, "nodes", []) or []:
            expr = str(getattr(n, "expression", "") or "")
            if "keccak256" in expr:
                return bool(val)  # allow "false" to invert
        return not bool(val)

    # R75 Gap 5 support - "has NO guard before external call" for post_external_call_mutates_state siblings.
    #   function.has_external_call_without_guard: <modifier-or-call-regex>
    if key == "function.has_external_call_without_guard":
        rx = re.compile(val, re.IGNORECASE)
        # Any modifier match satisfies guard
        for m in getattr(function, "modifiers", []) or []:
            nm = getattr(m, "name", "") or ""
            if rx.search(nm):
                return False
        # Must have an external call
        if not _external_call_sites(function):
            return False
        return True

    # PR #121 B5 - "self-scoped mapping write" carve-out for unauthenticated-
    # state-write detectors. True iff EVERY mapping/state write in the function
    # body indexes a mapping by `msg.sender` (so the function only mutates the
    # caller's own slot - e.g. `pauseMyself()`/`unpauseMyself()` patterns), AND
    # there is at least 1 such write. Designed as a NEGATIVE PRECONDITION:
    # detectors that flag "any external function writes state without auth"
    # use `function.is_self_scoped_mapping_write: false` to suppress the
    # legitimate self-action carve-out (POLY UserPausable shape).
    #
    # Detection is regex-based on the function source body (same approach as
    # body_contains_regex; AST-IR is heavier and not always available in all
    # engine paths). We:
    #   1. Strip comments + string literals so they can't fake matches.
    #   2. Count ALL mapping-style writes:  <ident>[<expr>] = ...,
    #                                       <ident>[<expr>].<field> = ...,
    #                                       delete <ident>[<expr>],
    #                                       <ident>[<expr>] += / -= / *= / /=
    #   3. Count the subset whose key expression is exactly `msg.sender`
    #      (or `msg . sender` with whitespace).
    #   4. Also reject if the body contains ANY non-mapping state assignment
    #      (e.g. `counter += 1;`, `owner = ...;`) - we only carve out the
    #      strict "self-only mapping mutation" shape.
    # Returns True iff total_writes == self_scoped_writes >= 1 AND there are
    # no scalar (non-mapping) writes.
    #   match:
    #     - function.is_self_scoped_mapping_write: false   # suppress carve-outs
    if key == "function.is_self_scoped_mapping_write":
        try:
            src = function.source_mapping.content or ""
        except Exception:
            src = ""
        # Strip the function signature line - we only care about the BODY.
        # Heuristic: drop everything up to and including the first `{`.
        body = src
        brace = src.find("{")
        if brace != -1:
            body = src[brace + 1:]
            # Drop the trailing `}` if present.
            last = body.rfind("}")
            if last != -1:
                body = body[:last]
        # Strip line + block comments (so `// foo[u] = 1` doesn't count).
        body_no_comments = re.sub(r"//[^\n]*", "", body)
        body_no_comments = re.sub(r"/\*.*?\*/", "", body_no_comments, flags=re.DOTALL)
        # Strip string literals so `"foo[u]="` doesn't count.
        body_no_comments = re.sub(r'"(?:[^"\\]|\\.)*"', '""', body_no_comments)
        body_no_comments = re.sub(r"'(?:[^'\\]|\\.)*'", "''", body_no_comments)

        # All mapping writes:
        #   <ident>[<key-expr>] (=|+=|-=|*=|/=|%=|&=|\|=|\^=)   → assignment
        #   <ident>[<key-expr>].<field> ... =                   → struct field write
        #   delete <ident>[<key-expr>]                          → delete write
        # We DO NOT match nested `m[a][b] = ...` here for v1 (rare for the
        # carve-out - a self-pausable doesn't double-index). Falls under
        # "non-self mapping write" → predicate returns False, conservative.
        write_assign_re = re.compile(
            r"(\w+)\s*\[\s*([^\[\]]+?)\s*\]\s*(?:\.\s*\w+\s*)?\s*(?:=(?!=)|[+\-*/%&|^]=)",
        )
        delete_re = re.compile(r"delete\s+(\w+)\s*\[\s*([^\[\]]+?)\s*\]")
        # Self-scope check: key expression is exactly msg.sender (with optional
        # whitespace). Any other form (variable, address, expression) is NOT
        # self-scoped.
        msg_sender_re = re.compile(r"^\s*msg\s*\.\s*sender\s*$")

        total_mapping_writes = 0
        self_scoped_writes = 0
        for ident, key_expr in write_assign_re.findall(body_no_comments):
            total_mapping_writes += 1
            if msg_sender_re.match(key_expr):
                self_scoped_writes += 1
        for ident, key_expr in delete_re.findall(body_no_comments):
            total_mapping_writes += 1
            if msg_sender_re.match(key_expr):
                self_scoped_writes += 1

        if total_mapping_writes == 0:
            return False  # empty / no-write function - not a self-action carve-out
        if total_mapping_writes != self_scoped_writes:
            return False  # at least one write touches another user's slot

        # Also reject if there are scalar (non-mapping) state writes mixed in
        # (e.g. `counter += 1;`, `counter++;`, `--counter;`). We approximate
        # this by looking for top-level assignments and ++/-- mutations that
        # aren't mapping-indexed.
        # Scalar-write heuristic: lines like `<ident> (=|+=|...) <expr>;`,
        # `<ident>++;`, `<ident>--;`, `++<ident>;`, `--<ident>;` where the
        # mutated name does NOT come from a mapping index (`map[k]++` is
        # stripped first). Skip lines that are local-var declarations (start
        # with a known type keyword) - those are stack writes, not state.
        # Conservative: any unrecognized non-mapping mutation fails the
        # predicate.
        TYPE_KEYWORDS = (
            "uint", "int", "bool", "address", "bytes", "string",
            "mapping", "var", "memory", "storage", "calldata",
        )
        # Strip mapping writes themselves so we don't double-count.
        residual = write_assign_re.sub("", body_no_comments)
        residual = delete_re.sub("", residual)
        # Strip mapping ++/-- forms (post + pre) so `m[k]++` isn't flagged as
        # a scalar mutation. Per spec, `map[msg.sender]++` is still allowed
        # as a self-scoped write - but for v1 we don't *count* it as a
        # mapping write either; we just remove it from residual so it
        # doesn't trip the scalar check. Detectors today only require the
        # presence of an `=`-style msg.sender mapping write, which the
        # carve-out function is expected to have.
        mapping_incdec_post_re = re.compile(
            r"(\w+)\s*\[\s*[^\[\]]+?\s*\]\s*(?:\+\+|--)"
        )
        mapping_incdec_pre_re = re.compile(
            r"(?:\+\+|--)\s*(\w+)\s*\[\s*[^\[\]]+?\s*\]"
        )
        residual = mapping_incdec_post_re.sub("", residual)
        residual = mapping_incdec_pre_re.sub("", residual)
        scalar_assign_re = re.compile(
            r"(?:^|;|\{)\s*([A-Za-z_]\w*)\s*(?:=(?!=)|[+\-*/%&|^]=)",
            re.MULTILINE,
        )
        for lhs in scalar_assign_re.findall(residual):
            if lhs in TYPE_KEYWORDS:
                continue  # local var decl
            # `return = ...` etc. shouldn't happen in valid Solidity; treat as
            # a state write to be conservative.
            return False
        # Scalar ++/-- mutations: `counter++`, `counter--`, `++counter`,
        # `--counter`. Mapping forms have already been stripped above, so a
        # remaining `\w++` is necessarily a scalar (state or local) mutation.
        # Conservative: any such mutation fails the predicate (we can't
        # cheaply distinguish state-var from local-var without IR, and the
        # carve-out is only meant for the strict self-only mapping shape).
        scalar_post_incdec_re = re.compile(
            r"(?:^|[^\w\]])([A-Za-z_]\w*)\s*(?:\+\+|--)"
        )
        scalar_pre_incdec_re = re.compile(
            r"(?:\+\+|--)\s*([A-Za-z_]\w*)\b"
        )
        if scalar_post_incdec_re.search(residual):
            return False
        if scalar_pre_incdec_re.search(residual):
            return False
        return True

    # R65 SKILL_ISSUES #165: fail-LOUD on unknown function-level predicate keys.
    # Previously this was "conservative pass True" which silently accepted typo'd
    # keys. Changed to False + stderr warn so pattern authors see the bug immediately.
    _warn_unknown_predicate_once("function", key)
    return False


def eval_function_match(function, matches: List[Any]) -> bool:
    """AND of all function-level match predicates."""
    if not matches:
        return False  # empty match set = match nothing (safer than match-all)
    for p in matches:
        if isinstance(p, dict):
            for k, v in p.items():
                try:
                    if not _check_function_pred(function, k, v):
                        return False
                except Exception:
                    return False
        elif isinstance(p, str):
            parsed = _parse_bang_predicate_string(p)
            if parsed is not None:
                key, value = parsed
                if _check_function_pred(function, key, value):
                    return False
                continue
            # Bare key with implicit true
            if not _check_function_pred(function, p, True):
                return False
    return True
