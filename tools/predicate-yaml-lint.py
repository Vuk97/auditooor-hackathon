#!/usr/bin/env python3
"""Lint YAML predicate shapes that make the predicate engine warn at runtime.

This tool intentionally does not import or modify detectors/_predicate_engine.py.
It mirrors the predicate keys the engine currently accepts and reports malformed
YAML with path + predicate location + key. By default it is advisory; strict
mode exits nonzero when warnings are found.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import os
import re
import sys
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

try:
    import yaml  # type: ignore
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


REPO = Path(__file__).resolve().parents[1]

CONTRACT_KEYS = frozenset(
    {
        "chain.is_zk_circuit",
        "chain.is_cosmos_sdk",
        "chain.is_btc_spv_verifier",
        "chain.is_l2_with_shadow_eth_erc20",
        "contract.name_matches",
        "contract.name_matches_regex",
        "contract.name_equals",
        "contract.implements_any_interface",
        "contract.inherits_any",
        "contract.inherits",
        "contract.inherits_regex",
        "contract.has_state_var_matching",
        "contract.has_field_matching",
        "contract.has_func_matching",
        "contract.has_function_matching",
        "contract.has_func_body_matching",
        "contract.has_func_body_matching_invert",
        "contract.has_function_body_matching",
        "contract.has_multiple_funcs_doing",
        "contract.has_function_without_modifier",
        "contract.has_no_function_body_matching",
        "contract.source_matches_regex",
        "contract.source_contains_regex",
        "repo.source_matches_regex",
        "contract.source_contains",
        "contract.not_source_contains",
        "contract.source_contains_any",
        "contract.source_contains_all",
        "function.contract.source_matches_regex",
        "contract.body_contains_regex",
        "contract.source_not_contains_regex",
        "contract.body_not_contains_regex",
        "contract.not_source_matches_regex",
        "function.contract.not_source_matches_regex",
        "contract.inherits_none_of",
        "contract.has_state_declaration_matching",
        "contract.has_no_state_declaration_matching",
        "contract.has_external_call_to",
        "contract.has_mapping",
        "contract.constructor_not_calls_regex",
        "contract.is_erc20",
        "contract.is_erc4626",
        "contract.is_erc721",
        "contract.is_erc1155",
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
    }
)

FUNCTION_KEYS = frozenset(
    {
        "function.ast",
        "function.not_ast",
        "function.kind",
        "function.is_payable",
        "function.state_mutability",
        "function.has_param_of_type",
        "function.parameters_include",
        "function.not_in_slither_synthetic",
        "function.not_slither_synthetic",
        "function.is_mutating",
        "function.body_has_multi_dynamic_encodepacked",
        "function.is_constructor",
        "function.is_override",
        "function.name",
        "function.name_matches",
        "function.name_matches_regex",
        "function.has_external_call",
        "function.external_call_count_gte",
        "function.post_external_call_mutates_state",
        "function.pre_external_call_mutates_state",
        "function.has_modifier",
        "function.has_modifier_matching",
        "function.has_modifier_regex",
        "function.has_modifier_not",
        "function.modifier_not_matches_regex",
        "function.modifiers_not_matching",
        "function.not_modifiers_match",
        "function.body_ordered_regex",
        "function.body_contains_regex_ordered",
        "function.body_matches_regex",
        "function.body_contains_regex",
        "function.not_body_matches_regex",
        "function.body_not_matches_regex",
        "function.body_not_contains_regex",
        "function.not_body_contains_regex",
        "function.source_matches_regex",
        "function.source_contains",
        "function.source_not_contains",
        "function.source_contains_all",
        "function.not_source_matches_regex",
        "function.body_contains_external_call_to_user_supplied_addr",
        "function.parent_contains_regex",
        "function.body_lacks_recipient_code_guard_or_tier_update",
        "function.internal_calling_regex",
        "function.not_internal_calling_regex",
        "function.high_level_calling_regex",
        "function.not_high_level_calling_regex",
        "function.calls_function_matching",
        "function.calls_function_matching_regex",
        "function.not_calls_function_matching",
        "function.does_not_call_matching",
        "function.does_not_call_matching_regex",
        "function.reads_storage_matching",
        "function.reads_state_var_matching",
        "function.reads_state_var_matching_regex",
        "function.writes_storage_matching",
        "function.writes_state_var_matching_regex",
        "function.writes_state_var_matches",
        "function.does_not_write_state_var_matching_regex",
        "function.not_writes_state_var_matching",
        "function.has_paired_function",
        "function.not_in_skip_list",
        "function.not_leaf_helper",
        "function.assembly_block_matches",
        "function.assembly_block_not_matches",
        "function.has_param_name_matching",
        "function.has_address_parameter",
        "function.parameter_named",
        "function.parameter_matches_regex",
        "function.parameter_not_matches_regex",
        "function.param_list_contains_regex",
        "function.parameters_not_include",
        "function.parameter_names_match",
        "function.signature_regex",
        "function.signature_matches_regex",
        "function.contract_has_source_matching",
        "function.post_external_call_writes_gte",
        "function.taints_param_to",
        "function.reaches_external",
        "function.has_param_mapping",
        "function.has_param_struct_named",
        "function.has_high_level_call_named",
        "function.has_low_level_call",
        "function.reads_msg_sender",
        "function.reads_tx_origin",
        "function.reads_block_timestamp",
        "function.reads_block_number",
        "function.emits_event_matching",
        "function.has_require_mentioning",
        "function.computes_keccak",
        "function.has_external_call_without_guard",
        "function.is_self_scoped_mapping_write",
    }
)

PREDICATE_BLOCKS = ("preconditions", "match")
STRINGIFIED_MARKERS = (":", "{", "}")
SLITHER_DSL_BACKENDS = {
    "",
    "solidity",
    "slither",
    "slither_dsl",
    "slither_source_shape",
    "source_shape",
    "evm",
    "vyper",
}


@dataclasses.dataclass(frozen=True)
class Finding:
    yaml_path: str
    predicate: str
    key: str
    warning_class: str
    message: str

    def line(self) -> str:
        return (
            f"{self.yaml_path}: {self.warning_class}: "
            f"predicate={self.predicate} key={self.key} - {self.message}"
        )


def _display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return str(path)


def _looks_stringified_predicate(value: str) -> bool:
    text = value.strip()
    if not text:
        return False
    if not any(marker in text for marker in STRINGIFIED_MARKERS):
        return False
    prefixes = (
        "contract.",
        "function.",
        "chain.",
        "context.",
        "- contract.",
        "- function.",
        "- chain.",
        "- context.",
    )
    return text.startswith(prefixes) or text.startswith("{")


def _canonical_dsl_backend(doc: dict[str, Any]) -> str:
    for key in ("backend", "engine", "language"):
        value = str(doc.get(key, "")).strip().lower()
        if not value:
            continue
        parts = [part for part in re.split(r"[^a-z0-9_]+", value) if part]
        return parts[0] if parts else value
    return ""


def _should_skip_doc(doc: dict[str, Any]) -> bool:
    if str(doc.get("status", "")).strip().lower() == "documentation-only":
        return True
    if bool(doc.get("manual_detector")):
        return True
    backend = _canonical_dsl_backend(doc)
    return backend not in SLITHER_DSL_BACKENDS


def _allowed_for_block(block_name: str) -> set[str]:
    if block_name == "preconditions":
        # The runtime engine intentionally accepts function predicates in
        # preconditions as "any declared function satisfies this predicate"
        # via _check_contract_pred's function.* compatibility branch.
        return set(CONTRACT_KEYS) | set(FUNCTION_KEYS)
    if block_name == "match":
        return set(FUNCTION_KEYS) | {
            k for k in CONTRACT_KEYS if k.startswith(("contract.", "function.contract."))
        }
    return set()


def _unsupported_class(key: str) -> str:
    if key.startswith("context.") or key == "context":
        return "unsupported_context_use"
    if key.startswith("contract.") or key.startswith("function.contract."):
        return "unsupported_contract_key"
    if key.startswith("function."):
        return "unsupported_function_key"
    if key.startswith("chain."):
        return "unsupported_chain_key"
    return "unsupported_predicate_key"


def _iter_predicate_entries(block_name: str, block: Any) -> Iterator[tuple[str, str, Any]]:
    if block is None:
        return
    if isinstance(block, list):
        for idx, entry in enumerate(block):
            predicate = f"{block_name}[{idx}]"
            if isinstance(entry, dict):
                for key, value in entry.items():
                    yield predicate, str(key), value
            elif isinstance(entry, str):
                yield predicate, "__stringified__", entry
            else:
                yield predicate, "__non_mapping__", entry
        return
    if isinstance(block, dict):
        for key, value in block.items():
            yield block_name, str(key), value
        return
    yield block_name, "__non_sequence__", block


def lint_doc(path: Path, doc: Any) -> list[Finding]:
    shown = _display_path(path)
    findings: list[Finding] = []
    if not isinstance(doc, dict):
        return [
            Finding(
                shown,
                "<document>",
                "__document__",
                "non_mapping_yaml",
                "YAML document is not a mapping; predicate blocks cannot be inspected",
            )
        ]
    if _should_skip_doc(doc):
        return []

    for block_name in PREDICATE_BLOCKS:
        allowed = _allowed_for_block(block_name)
        for predicate, key, value in _iter_predicate_entries(block_name, doc.get(block_name)):
            if key == "__stringified__":
                if _looks_stringified_predicate(str(value)):
                    findings.append(
                        Finding(
                            shown,
                            predicate,
                            key,
                            "stringified_predicate_entry",
                            "predicate entry is a string; use a YAML mapping such as "
                            "`- function.name_matches: withdraw`",
                        )
                    )
                continue
            if key.startswith("__"):
                findings.append(
                    Finding(
                        shown,
                        predicate,
                        key,
                        "invalid_predicate_shape",
                        "predicate entry must be a mapping, not a scalar or sequence",
                    )
                )
                continue
            if key.startswith("context.") or key == "context":
                findings.append(
                    Finding(
                        shown,
                        predicate,
                        key,
                        "unsupported_context_use",
                        "predicate engine has no context.* predicate namespace",
                    )
                )
                continue
            if key not in allowed:
                findings.append(
                    Finding(
                        shown,
                        predicate,
                        key,
                        _unsupported_class(key),
                        f"{key!r} is not supported in {block_name}",
                    )
                )
    return findings


def lint_path(path: Path) -> list[Finding]:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [
            Finding(
                _display_path(path),
                "<document>",
                "__yaml_load__",
                "yaml_load_error",
                str(exc),
            )
        ]
    return lint_doc(path, doc)


def collect_paths(paths: Sequence[str], dirs: Sequence[str]) -> list[Path]:
    out: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            out.extend(sorted(path.rglob("*.yaml")))
            out.extend(sorted(path.rglob("*.yml")))
        else:
            out.append(path)
    for dirname in dirs:
        out.extend(sorted(Path(dirname).rglob("*.yaml")))
        out.extend(sorted(Path(dirname).rglob("*.yml")))
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in out:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def _strict_from_env() -> bool:
    value = os.environ.get("PREDICATE_YAML_LINT_STRICT", os.environ.get("STRICT", ""))
    return value.lower() in {"1", "true", "yes", "on"}


def write_markdown_report(report_path: Path, findings: Sequence[Finding], checked: int, strict: bool) -> None:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.warning_class] = counts.get(finding.warning_class, 0) + 1
    lines = [
        "# Predicate YAML Lint Phase B",
        "",
        f"- Date: {_dt.date.today().isoformat()}",
        f"- Checked YAMLs: {checked}",
        f"- Findings: {len(findings)}",
        f"- Strict mode: {strict}",
        "",
        "## Implemented Checks",
        "",
        "- `stringified_predicate_entry`: list entries such as `\"function.name_matches: foo\"`",
        "- `unsupported_contract_key`: unknown `contract.*` or `function.contract.*` predicates",
        "- `unsupported_function_key`: unknown `function.*` predicates or function keys in `preconditions`",
        "- `unsupported_chain_key`: unknown `chain.*` predicates or chain predicates outside contract preconditions",
        "- `unsupported_context_use`: `context.*` predicates, which the engine does not support",
        "- `invalid_predicate_shape`: scalar or sequence entries in predicate blocks",
        "",
        "## Warning Classes",
        "",
    ]
    if counts:
        lines.extend(f"- `{name}`: {count}" for name, count in sorted(counts.items()))
    else:
        lines.append("- none")
    lines.extend(["", "## Findings", ""])
    if findings:
        lines.extend(f"- `{finding.line()}`" for finding in findings)
    else:
        lines.append("- No predicate YAML shape warnings found.")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", help="YAML files to lint")
    parser.add_argument("--dir", action="append", default=[], help="directory to scan recursively")
    parser.add_argument("--strict", action="store_true", help="exit 1 when warnings are found")
    parser.add_argument(
        "--report",
        default="reports/predicate_yaml_lint_phase_b_2026-05-17.md",
        help="markdown report path",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    strict = bool(args.strict or _strict_from_env())
    paths = collect_paths(args.paths, args.dir)
    if not paths:
        print("[predicate-yaml-lint] no YAML paths supplied", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    for path in paths:
        if not path.exists():
            findings.append(
                Finding(
                    _display_path(path),
                    "<document>",
                    "__missing_file__",
                    "missing_file",
                    "path does not exist",
                )
            )
            continue
        findings.extend(lint_path(path))

    for finding in findings:
        print(finding.line())
    print(
        f"[predicate-yaml-lint] checked={len(paths)} warnings={len(findings)} strict={strict}",
        file=sys.stderr,
    )
    write_markdown_report(Path(args.report), findings, len(paths), strict)
    return 1 if strict and findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
