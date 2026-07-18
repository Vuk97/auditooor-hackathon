#!/usr/bin/env python3
"""
pattern-compile.py - compile a DSL pattern YAML into a Slither detector (Issue #85)

The DSL is specified in reference/PATTERN_DSL.md. This compiler reads one YAML
pattern and emits a runnable Slither detector to detectors/waveN/<name>.py.

Usage:
    python3 tools/pattern-compile.py <pattern.yaml>
    python3 tools/pattern-compile.py --all              # compile every .yaml in patterns.dsl/
    python3 tools/pattern-compile.py --wave 17 <pat>   # emit into wave17/ (default: wave17)

Emits detectors that reference lib.predicates from detectors/_template_utils.py
(extended in this round) for actual predicate evaluation.
"""

import argparse
import re
import sys
from pathlib import Path

AUDITOOOR_DIR = Path(__file__).resolve().parent.parent
DSL_DIR = AUDITOOOR_DIR / "reference" / "patterns.dsl"
DETECTORS_DIR = AUDITOOOR_DIR / "detectors"


SEVERITY_MAP = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFO": "INFORMATIONAL",
                "INFORMATIONAL": "INFORMATIONAL"}
CONFIDENCE_MAP = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
SLITHER_DSL_BACKENDS = {
    "solidity",
    "slither",
    "slither_source_shape",
    "evm",
    "vyper",
}


# ---------------------------------------------------------------------
# SUPPORTED PREDICATE KEYS - burn-down item #12.
#
# Canonical inventory of every predicate key honored by
# `detectors/_predicate_engine.py`. Keep this constant in sync with that
# module: any new `if key == "..."` branch in the engine MUST be added
# here (and documented in `reference/PATTERN_DSL.md`) so opt-in
# `--strict-unsupported-keys` validation does not reject it.
#
# Historically, unsupported keys silently compiled into a detector and
# then the predicate engine emitted a stderr warning at scan time and
# returned False - meaning the YAML "compiled" but the matcher was a
# silent no-op. The optional strict guard catches this at compile time
# instead, pointing the operator at the offending YAML/key.
# ---------------------------------------------------------------------
SUPPORTED_DOMAIN_PRECONDITION_KEYS = frozenset({
    "chain.is_zk_circuit",
    "chain.is_cosmos_sdk",
    "chain.is_btc_spv_verifier",
    "chain.is_l2_with_shadow_eth_erc20",
    "crate.source_matches_regex",
    "repo.source_matches_regex",
})

SUPPORTED_PRECONDITION_KEYS = frozenset({
    # Inheritance / interface
    "contract.name_matches",
    "contract.name_matches_regex",
    "contract.name_equals",
    "contract.implements_any_interface",
    "contract.inherits_any",
    "contract.inherits",
    "contract.inherits_regex",
    "contract.inherits_none_of",
    "contract.is_erc20",
    "contract.is_erc721",
    "contract.is_erc1155",
    "contract.is_erc4626",
    # Name/regex matchers
    "contract.has_state_var_matching",
    "contract.has_field_matching",
    "contract.has_func_matching",
    "contract.has_function_matching",
    "contract.has_func_body_matching",
    "contract.has_func_body_matching_invert",
    "contract.has_function_body_matching",
    "contract.has_no_function_body_matching",
    "contract.has_multiple_funcs_doing",
    "contract.has_function_without_modifier",
    "contract.has_state_declaration_matching",
    "contract.has_no_state_declaration_matching",
    # Source-text regex
    "contract.source_matches_regex",
    "contract.source_contains_regex",
    "contract.source_contains",
    "contract.not_source_contains",
    "contract.source_contains_any",
    "contract.source_contains_all",
    "contract.body_contains_regex",
    "contract.source_not_contains_regex",
    "contract.body_not_contains_regex",
    "contract.not_source_matches_regex",
    # Call-graph / shape
    "contract.has_external_call_to",
    "contract.has_mapping",
    "contract.constructor_not_calls_regex",
    "contract.is_upgradeable_impl",
    "contract.is_upgradeable_or_proxy",
    "contract.is_balancer_linear_pool",
    "contract.has_pool_registry",
    "contract.is_price_feed_adapter",
    "contract.inherits_gsn_or_access_base",
    "contract.has_buy_reward_or_sell_penalty",
    "contract.is_lending_or_collateral_manager",
    "contract.is_lending_market",
    "contract.is_yield_strategy_or_vault",
    "contract.not_in_skip_list",
})

SUPPORTED_FUNCTION_KEYS = frozenset({
    # AST dispatch (R94-D / R74-D)
    "function.ast",
    "function.not_ast",
    # Visibility / mutability / shape
    "function.kind",
    "function.is_payable",
    "function.state_mutability",
    "function.is_mutating",
    "function.is_constructor",
    "function.is_override",
    "function.not_in_slither_synthetic",
    "function.not_slither_synthetic",
    "function.not_in_skip_list",
    "function.not_leaf_helper",
    # Name / params
    "function.name",
    "function.name_matches",
    "function.name_matches_regex",
    "function.has_param_of_type",
    "function.parameters_include",
    "function.parameters_not_include",
    "function.has_param_name_matching",
    "function.parameter_named",
    "function.parameter_matches_regex",
    "function.parameter_not_matches_regex",
    "function.param_list_contains_regex",
    "function.parameter_names_match",
    "function.has_address_parameter",
    "function.has_param_mapping",
    "function.has_param_struct_named",
    "function.signature_regex",
    "function.signature_matches_regex",
    # Calls
    "function.has_external_call",
    "function.external_call_count_gte",
    "function.has_high_level_call_named",
    "function.has_low_level_call",
    "function.internal_calling_regex",
    "function.not_internal_calling_regex",
    "function.high_level_calling_regex",
    "function.not_high_level_calling_regex",
    "function.calls_function_matching",
    "function.calls_function_matching_regex",
    "function.not_calls_function_matching",
    "function.does_not_call_matching",
    "function.does_not_call_matching_regex",
    "function.reaches_external",
    "function.body_contains_external_call_to_user_supplied_addr",
    "function.has_external_call_without_guard",
    # State-write ordering (CEI / inverse-CEI)
    "function.post_external_call_mutates_state",
    "function.pre_external_call_mutates_state",
    "function.post_external_call_writes_gte",
    "function.is_self_scoped_mapping_write",
    # Body / source regex
    "function.body_matches_regex",
    "function.body_contains_regex",
    "function.body_ordered_regex",
    "function.body_contains_regex_ordered",
    "function.not_body_matches_regex",
    "function.body_not_matches_regex",
    "function.body_not_contains_regex",
    "function.not_body_contains_regex",
    "function.source_matches_regex",
    "function.source_contains",
    "function.source_not_contains",
    "function.source_contains_all",
    "function.not_source_matches_regex",
    "function.parent_contains_regex",
    "function.body_lacks_recipient_code_guard_or_tier_update",
    # Storage reads/writes
    "function.reads_storage_matching",
    "function.reads_state_var_matching",
    "function.reads_state_var_matching_regex",
    "function.writes_storage_matching",
    "function.writes_state_var_matching_regex",
    "function.writes_state_var_matches",
    "function.does_not_write_state_var_matching_regex",
    "function.not_writes_state_var_matching",
    # Modifiers
    "function.has_modifier",
    "function.has_modifier_matching",
    "function.has_modifier_regex",
    "function.has_modifier_not",
    "function.modifier_not_matches_regex",
    "function.modifiers_not_matching",
    "function.not_modifiers_match",
    # Assembly
    "function.assembly_block_matches",
    "function.assembly_block_not_matches",
    # Cross-context regex (function-context predicate against parent contract)
    "function.contract_has_source_matching",
    "function.contract.source_matches_regex",
    "function.contract.not_source_matches_regex",
    # Misc shapes
    "function.body_has_multi_dynamic_encodepacked",
    "function.taints_param_to",
    "function.has_paired_function",
    "function.has_require_mentioning",
    "function.computes_keccak",
    "function.emits_event_matching",
    "function.reads_msg_sender",
    "function.reads_tx_origin",
    "function.reads_block_timestamp",
    "function.reads_block_number",
})

SUPPORTED_KEYS_BY_FIELD = {
    # `preconditions:` is evaluated against the contract via
    # `eval_preconditions` -> `_check_contract_pred`. That engine also has a
    # compatibility branch for function.* predicates, interpreted as "any
    # declared function satisfies this predicate".
    "preconditions": (
        SUPPORTED_DOMAIN_PRECONDITION_KEYS
        | SUPPORTED_PRECONDITION_KEYS
        | SUPPORTED_FUNCTION_KEYS
    ),
    # `match:` is evaluated against each function via
    # `eval_function_match` -> `_check_function_pred`. Contract-level
    # `contract.*` keys are routed through the function-context parent
    # contract helper by the runtime engine.
    "match": SUPPORTED_FUNCTION_KEYS | {
        k for k in SUPPORTED_PRECONDITION_KEYS if k.startswith(("contract.", "function.contract."))
    },
}


class PatternCompileError(ValueError):
    """Raised when a compileable YAML would emit an unsafe detector."""


def classname(pattern_id):
    return "".join(p.capitalize() for p in re.split(r"[-_]", pattern_id) if p)


def _canonical_dsl_backend(spec: dict) -> str:
    for key in ("backend", "engine", "language"):
        value = str(spec.get(key, "")).strip().lower()
        if not value:
            continue
        parts = [part for part in re.split(r"[^a-z0-9_]+", value) if part]
        return parts[0] if parts else value
    return ""


def _predicate_shape_errors(yaml_path: Path, field: str, value, *, required: bool) -> list[str]:
    """Return suspicious YAML predicate-shape problems without mutating legacy specs."""
    errors: list[str] = []
    if value is None:
        value = []
    if not isinstance(value, list):
        return [
            f"{yaml_path.name}: `{field}` must be a YAML list of single-key predicate maps "
            "(did a matcher line lose its leading `-` or quote a `key: value` scalar?)"
        ]
    if required and not value:
        errors.append(
            f"{yaml_path.name}: `match` must contain at least one predicate; "
            "empty matcher emission is refused"
        )
    for idx, item in enumerate(value, start=1):
        if not isinstance(item, dict):
            hint = " suspicious `key: value` scalar" if isinstance(item, str) and ":" in item else ""
            errors.append(
                f"{yaml_path.name}: `{field}` item {idx} must be a single-key predicate map; "
                f"got {type(item).__name__}{hint}"
            )
            continue
        if len(item) != 1:
            errors.append(
                f"{yaml_path.name}: `{field}` item {idx} must contain exactly one predicate key"
            )
            continue
        key, pred_value = next(iter(item.items()))
        if not isinstance(key, str) or not key.strip():
            errors.append(
                f"{yaml_path.name}: `{field}` item {idx} has an empty/non-string predicate key"
            )
        if pred_value is None or pred_value == "":
            errors.append(
                f"{yaml_path.name}: `{field}` item {idx} (`{key}`) has an empty value; "
                "quote regexes/text that contain `:` so YAML does not erase the matcher"
            )
    return errors


def _unsupported_key_errors(yaml_path: Path, field: str, value) -> list[str]:
    """Return errors for any predicate key not in the field's supported set.

    Burn-down item #12: historically, a typo'd or made-up key (e.g.
    `function.totally_made_up`) silently compiled - the predicate engine
    then warned to stderr and returned False at scan time, meaning the
    detector ran against zero matches. The optional strict guard surfaces
    this at compile time and points at the offending YAML so authors
    cannot ship silently no-op detectors.
    """
    errors: list[str] = []
    supported = SUPPORTED_KEYS_BY_FIELD.get(field, set())
    if not supported:
        return errors
    items = value
    if items is None:
        return errors
    if not isinstance(items, list):
        # Shape errors are reported by `_predicate_shape_errors`; key-set
        # validation requires a list-of-maps and falls through otherwise.
        return errors
    for idx, item in enumerate(items, start=1):
        if not isinstance(item, dict) or len(item) != 1:
            continue
        key = next(iter(item.keys()))
        if not isinstance(key, str) or not key.strip():
            continue
        if key in supported:
            continue
        # `function.contract.*` cross-context predicates ARE handled by
        # `_check_contract_pred` (the engine special-cases them). Keep
        # them in SUPPORTED_FUNCTION_KEYS instead of carving here.
        errors.append(
            f"{yaml_path.name}: `{field}` item {idx} uses unsupported "
            f"predicate key `{key}` - not handled by "
            f"detectors/_predicate_engine.py. Supported keys are listed "
            f"in reference/PATTERN_DSL.md and tools/pattern-compile.py "
            f"(SUPPORTED_KEYS_BY_FIELD)."
        )
    return errors


def _validate_predicate_list(
    yaml_path: Path,
    field: str,
    value,
    *,
    required: bool,
    strict_yaml_shapes: bool,
    strict_unsupported_keys: bool = False,
):
    """Warn by default, fail loud in strict mode, and preserve legacy compile output."""
    errors = _predicate_shape_errors(yaml_path, field, value, required=required)
    if errors and strict_yaml_shapes:
        raise PatternCompileError("; ".join(errors))
    for err in errors:
        print(f"[warn] {err}", file=sys.stderr)
    # Burn-down item #12: opt-in unsupported-key validation. Off by
    # default so the 1,400+ legacy YAMLs still compile silently; on
    # under `--strict-unsupported-keys` (or the convenience
    # `--strict-all`) the validator fails loud and points at the
    # offending key. We do NOT print warnings on the default path -
    # historically those YAMLs compile and the engine emits its own
    # stderr warning at scan time, so a default-path duplicate would
    # double-warn for every legacy pattern (>= 1,400 lines of noise).
    if strict_unsupported_keys:
        key_errors = _unsupported_key_errors(yaml_path, field, value)
        if key_errors:
            raise PatternCompileError("; ".join(key_errors))
    if value is None:
        return []
    return value


def compile_pattern(
    yaml_path: Path,
    wave_dir: Path,
    *,
    strict_yaml_shapes: bool = False,
    strict_unsupported_keys: bool = False,
):
    try:
        import yaml
    except ImportError:
        print("[error] PyYAML required", file=sys.stderr)
        sys.exit(1)

    spec = yaml.safe_load(yaml_path.read_text())
    if not spec or "pattern" not in spec:
        print(f"[skip] {yaml_path.name} has no 'pattern:' field", file=sys.stderr)
        return False

    # PR #121 A2 (Codex unblock #133): YAMLs flagged `status: documentation-only`
    # are companion descriptors for hand-written canonical detectors (e.g. wave18
    # custom Python). Skip them so --all doesn't accidentally compile a duplicate
    # into wave17/ that contradicts the canonical implementation.
    if str(spec.get("status", "")).strip().lower() == "documentation-only":
        print(f"[skip] {yaml_path.name} status: documentation-only", file=sys.stderr)
        return False
    # Some live detectors are intentionally hand-tuned while keeping their YAML
    # as the wiki/provenance record. Unlike documentation-only rows, these
    # detectors must still run through detectors/run_custom.py; only the compiler
    # should skip them.
    if bool(spec.get("manual_detector")):
        print(f"[skip] {yaml_path.name} manual_detector: true", file=sys.stderr)
        return False
    backend = _canonical_dsl_backend(spec)
    if backend and backend not in SLITHER_DSL_BACKENDS:
        print(
            f"[skip] {yaml_path.name} backend: {backend} is not a Slither backend",
            file=sys.stderr,
        )
        return False

    pat_id = spec["pattern"]
    cls = classname(pat_id)
    severity = SEVERITY_MAP.get(str(spec.get("severity", "MEDIUM")).upper(), "MEDIUM")
    confidence = CONFIDENCE_MAP.get(str(spec.get("confidence", "MEDIUM")).upper(), "MEDIUM")
    help_text = spec.get("help", pat_id)
    wiki_title = spec.get("wiki_title", help_text)
    wiki_desc = spec.get("wiki_description", help_text)
    wiki_exploit = spec.get("wiki_exploit_scenario", help_text)
    wiki_rec = spec.get("wiki_recommendation", "See audit report.")
    source = spec.get("source", "auditooor")
    preconds = _validate_predicate_list(
        yaml_path,
        "preconditions",
        spec.get("preconditions", []),
        required=False,
        strict_yaml_shapes=strict_yaml_shapes,
        strict_unsupported_keys=strict_unsupported_keys,
    )
    matches = _validate_predicate_list(
        yaml_path,
        "match",
        spec.get("match", []),
        required=True,
        strict_yaml_shapes=strict_yaml_shapes,
        strict_unsupported_keys=strict_unsupported_keys,
    )
    # R32: patterns that target view/pure functions (e.g., cross-contract-reentrancy-view-exposed)
    # need to opt out of the leaf-helper skip filter.
    include_leaf_helpers = bool(spec.get("include_leaf_helpers", False))
    # SKILL_ISSUES #102: reentrancy-class patterns flag themselves with `inverse_cei: true`.
    # run_custom.py --inverse-cei-workspace <ws> then skips them on workspaces whose
    # `<ws>/.skill_state.yaml:inverse_cei_architecture: true` marks them as inverse-CEI
    # by design (e.g., Morpho Blue optimistic-state). The DSL flag passes through as a
    # class-level `_INVERSE_CEI` constant the runner introspects.
    inverse_cei = bool(spec.get("inverse_cei", False))

    # Serialize predicates as Python literals (repr -> Python-parseable).
    # json.dumps would emit true/false/null which Python cannot import.
    preconds_lit = repr(preconds)
    matches_lit = repr(matches)

    # Clean strings for embedding in generated code.
    # R67f: must also escape newlines / CRs / tabs, otherwise multi-line
    # wiki_recommendation fields in the YAML compile to Python source
    # that has a literal newline inside a single-quoted string literal,
    # breaking the emitted module with SyntaxError.
    def _q(s):
        return (
            str(s)
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
        )

    out = f'''"""
{pat_id} - generated from reference/patterns.dsl/{yaml_path.name}
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py {yaml_path.name}
Source: {source}
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class {cls}(AbstractDetector):
    ARGUMENT = "{pat_id}"
    HELP = "{_q(help_text)[:300]}"
    IMPACT = DetectorClassification.{severity}
    CONFIDENCE = DetectorClassification.{confidence}
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/{yaml_path.name}"
    WIKI_TITLE = "{_q(wiki_title)[:200]}"
    WIKI_DESCRIPTION = "{_q(wiki_desc)}"
    WIKI_EXPLOIT_SCENARIO = "{_q(wiki_exploit)}"
    WIKI_RECOMMENDATION = "{_q(wiki_rec)}"

    _PRECONDITIONS = {preconds_lit}
    _MATCH = {matches_lit}

    _INCLUDE_LEAF_HELPERS = {include_leaf_helpers}
    _INVERSE_CEI = {inverse_cei}

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" - {pat_id}: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
'''

    wave_dir.mkdir(parents=True, exist_ok=True)
    out_path = wave_dir / f"{pat_id.replace('-', '_')}.py"
    out_path.write_text(out)
    print(f"[ok] compiled {yaml_path.name} -> {out_path.relative_to(AUDITOOOR_DIR)}")
    return True


def _parallel_worker(yf_wave_strict):
    """R73 C5: module-scope worker so multiprocessing can pickle it."""
    # Backward-compatible unpack: accept the legacy 3-tuple
    # `(yf, wave_dir, strict_yaml_shapes)` plus the burn-down 4-tuple
    # `(yf, wave_dir, strict_yaml_shapes, strict_unsupported_keys)`.
    if len(yf_wave_strict) == 3:
        yf, wave_dir, strict_yaml_shapes = yf_wave_strict
        strict_unsupported_keys = False
    else:
        yf, wave_dir, strict_yaml_shapes, strict_unsupported_keys = yf_wave_strict
    try:
        return 1 if compile_pattern(
            yf,
            wave_dir,
            strict_yaml_shapes=strict_yaml_shapes,
            strict_unsupported_keys=strict_unsupported_keys,
        ) else 0
    except Exception as _e:
        import sys as _sys
        _sys.stderr.write(f"[err] {yf.name}: {_e}\n")
        return -1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pattern", nargs="?", help="path to pattern.yaml (or --all)")
    ap.add_argument("--all", action="store_true", help="compile every .yaml in patterns.dsl/")
    ap.add_argument("--wave", default="17", help="emit into waveN/ (default 17)")
    ap.add_argument("--serial", action="store_true", help="disable multiprocessing parallelism (R73 C5)")
    ap.add_argument(
        "--strict-yaml-shapes",
        action="store_true",
        help="fail on malformed predicate YAML shapes instead of warning (burn-down check mode)",
    )
    # Burn-down item #12: opt-in unsupported-key validation.
    ap.add_argument(
        "--strict-unsupported-keys",
        action="store_true",
        help=(
            "fail when a YAML uses a predicate key not handled by "
            "detectors/_predicate_engine.py (burn-down check mode; off by "
            "default to keep ~1,400 legacy YAMLs compiling)"
        ),
    )
    ap.add_argument(
        "--strict-all",
        action="store_true",
        help="convenience: enable both --strict-yaml-shapes and --strict-unsupported-keys",
    )
    args = ap.parse_args()
    if args.strict_all:
        args.strict_yaml_shapes = True
        args.strict_unsupported_keys = True

    wave_dir = DETECTORS_DIR / f"wave{args.wave}"

    if args.all:
        if not DSL_DIR.exists():
            print(f"[error] {DSL_DIR} missing - create it and drop .yaml patterns there",
                  file=sys.stderr)
            sys.exit(1)
        # Skip DRAFT-*.yaml - parity-gap-closer emits these for operator
        # review before they're ready to ship (see tools/parity-gap-closer.py
        # + docs/archive/PARITY_GAP_DRAFTS.md). DRAFTs are not registered in
        # BUG_CLASSES and must not compile into wave17/ until promoted.
        yaml_files = sorted(
            yf for yf in DSL_DIR.glob("*.yaml")
            if not yf.name.startswith("DRAFT-")
        )
        # R73 C5: parallelize compile via multiprocessing. Each pattern is
        # independent (reads one YAML, emits one .py). ~8x speedup on large
        # libraries. Fall back to single-process on --serial or if only a
        # handful of patterns (overhead not worth it).
        errors = 0
        if args.serial or len(yaml_files) < 8:
            ok = 0
            for yf in yaml_files:
                try:
                    ok += 1 if compile_pattern(
                        yf,
                        wave_dir,
                        strict_yaml_shapes=args.strict_yaml_shapes,
                        strict_unsupported_keys=args.strict_unsupported_keys,
                    ) else 0
                except Exception as e:
                    print(f"[err] {yf.name}: {e}", file=sys.stderr)
                    errors += 1
        else:
            import multiprocessing as _mp
            with _mp.Pool(processes=min(_mp.cpu_count(), 8)) as pool:
                results = pool.map(
                    _parallel_worker,
                    [
                        (
                            yf,
                            wave_dir,
                            args.strict_yaml_shapes,
                            args.strict_unsupported_keys,
                        )
                        for yf in yaml_files
                    ],
                )
            ok = sum(1 for r in results if r > 0)
            errors = sum(1 for r in results if r < 0)
        print(f"\n[done] compiled {ok} patterns into {wave_dir}/")
        if errors:
            print(f"[error] refused {errors} malformed pattern YAML(s)", file=sys.stderr)
            sys.exit(1)
        return

    if not args.pattern:
        ap.print_help()
        sys.exit(1)

    p = Path(args.pattern)
    if not p.exists():
        # Try relative to DSL_DIR
        alt = DSL_DIR / p.name
        if alt.exists():
            p = alt
        else:
            print(f"[error] {p} not found", file=sys.stderr)
            sys.exit(1)
    try:
        compile_pattern(
            p,
            wave_dir,
            strict_yaml_shapes=args.strict_yaml_shapes,
            strict_unsupported_keys=args.strict_unsupported_keys,
        )
    except Exception as e:
        print(f"[err] {p.name}: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
