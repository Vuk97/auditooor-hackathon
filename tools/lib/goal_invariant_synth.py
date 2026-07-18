#!/usr/bin/env python3
"""goal_invariant_synth.py - adversary-GOAL invariant synthesis (FIX-3 increment).

The shape-keyed synthesizer in tools/invariant-auto-synth.py answers "this fn
takes a uint amount -> assert amount > 0". It enumerates over function SHAPE,
never over adversary GOAL. This LIBRARY adds the missing axis: it routes a
function through its matched impact_id(s) (reusing the SAME classify +
admit logic as tools/hacker_question_renderer.render_impact_methodology_questions)
and, for each matched impact, emits the GOAL-oriented invariant templates from
audit/corpus_tags/goal_invariant_templates.yaml - binding each template's roles
against the function source. A template whose required roles do NOT all bind is
returned UNBOUND (status goal-unbound, is_goal_template False) and is never
credited; a missing/corrupt corpus degrades to {} (zero false credit).

This is a LIBRARY, not a CLI: both tools/invariant-auto-synth.py and
tools/per-function-invariant-gen.py import it so the goal axis is additive on
top of their existing shape path.

Schemas:
  goal_invariant_templates.yaml -> auditooor.goal_invariant_templates.v1
  each returned record           -> auditooor.goal_invariant.v1
"""
from __future__ import annotations

import importlib.util as _ilu
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

GOAL_RECORD_SCHEMA = "auditooor.goal_invariant.v1"

# tools/lib/goal_invariant_synth.py -> repo root is parents[2].
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_TOOLS_DIR = Path(__file__).resolve().parent.parent
GOAL_TEMPLATES_PATH = (
    _REPO_ROOT / "audit" / "corpus_tags" / "goal_invariant_templates.yaml"
)


# ---------------------------------------------------------------------------
# Import-by-path of the sibling tools (the package layout has no namespace
# package; hyphenated filenames are not importable as modules). Mirrors
# per-function-invariant-gen.py:44-56 (_load_sentinel_predicate).
# ---------------------------------------------------------------------------
def _load_module_by_path(name: str, rel_path: Path):
    if not rel_path.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location(name, str(rel_path))
        mod = _ilu.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception:  # noqa: BLE001
        return None


_HQR = _load_module_by_path(
    "hacker_question_renderer", _TOOLS_DIR / "hacker_question_renderer.py"
)
# invariant-auto-synth carries _sol_fn_has_modifier (the per-fn modifier check
# we reuse for the caller_auth_guard role). The hyphenated filename forces an
# import-by-path with a sanitized module name.
_IAS = _load_module_by_path(
    "invariant_auto_synth", _TOOLS_DIR / "invariant-auto-synth.py"
)


# ---------------------------------------------------------------------------
# Corpus loader (mirrors load_impact_playbooks: graceful-empty on any failure).
# ---------------------------------------------------------------------------
def load_goal_templates(path: Optional[Path] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Load the goal-invariant template corpus, indexed by impact_id.

    Returns ``{impact_id: [template, ...]}``. Degrades to ``{}`` when the file
    is missing, unreadable, not valid YAML, or the YAML parser is unavailable -
    so a caller adds ZERO false credit when the corpus is absent (never raises).
    """
    target = path or GOAL_TEMPLATES_PATH
    by_impact: Dict[str, List[Dict[str, Any]]] = {}
    try:
        import yaml  # type: ignore

        with open(target, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except Exception:  # noqa: BLE001 - missing/corrupt/no-parser -> empty
        return {}
    if not isinstance(data, dict):
        return {}
    for block in data.get("templates", []) or []:
        if not isinstance(block, dict):
            continue
        impact_id = str(block.get("impact_id") or "").strip()
        if not impact_id:
            continue
        templates = [t for t in (block.get("templates") or []) if isinstance(t, dict)]
        if templates:
            by_impact.setdefault(impact_id, []).extend(templates)
    return by_impact


# ---------------------------------------------------------------------------
# Role -> source resolvers. Each returns the matched token (str) or "" (UNBOUND).
# The resolvers are small, source-grounded regex probes over the function body.
# ---------------------------------------------------------------------------
_ACCRUAL_ACCUM_RE = re.compile(
    r"\b(\w*(?:acc|reward|index|accrued)\w*)\s*\[", re.IGNORECASE
)
_ACCRUAL_ACCUM_SCALAR_RE = re.compile(
    # `=(?!=)` excludes a `==` comparator (e.g. `if (blockIndex == 3)`) while still
    # matching plain/compound assignment (`index =`, `index +=`); a comparator is
    # not an accrual write.
    r"\b(\w*(?:acc|reward|index|accrued)\w*)\s*[+\-*/]?=(?!=)", re.IGNORECASE
)
_CLAIMED_MARKER_RE = re.compile(
    r"\b(rewardDebt|claimed\w*|lastClaim\w*|nullifier\w*)\b", re.IGNORECASE
)
_BALANCE_STATE_RE = re.compile(
    r"\b(balanceOf|_balances|shares?\w*)\b", re.IGNORECASE
)
_AUTH_FALLBACK_RE = re.compile(
    r"onlyOwner|onlyRole|require\s*\([^)]*msg\.sender", re.IGNORECASE
)
_WITHDRAW_ENTRY_RE = re.compile(
    r"\b(withdraw\w*|redeem\w*|unstake\w*|exit\w*)\b", re.IGNORECASE
)
_HEALTH_READ_RE = re.compile(
    r"\b(healthFactor\w*|isHealthy\w*)\b|collateral[\s\S]{0,80}?debt", re.IGNORECASE
)
_LIQUIDATE_ENTRY_RE = re.compile(r"\bliquidat\w*\b", re.IGNORECASE)


def _first_token(match: Optional[re.Match]) -> str:
    if not match:
        return ""
    if match.groups():
        for g in match.groups():
            if g:
                return str(g)
    return match.group(0)


def _curated_match(
    patterns: List[str],
    match_in: str,
    *,
    function_name: str,
    source_body: str,
) -> str:
    """Test a template's curated ``match_any`` patterns against the selected
    text (name|body|both). Returns the FIRST matched token, or "" when none
    match (or the pattern list is empty). A malformed regex is skipped (never
    raises), so a single bad curated pattern cannot crash binding.
    """
    if not patterns:
        return ""
    mode = (match_in or "body").strip().lower()
    targets: List[str] = []
    if mode in ("name", "both"):
        targets.append(function_name or "")
    if mode in ("body", "both") or mode not in ("name", "body", "both"):
        # default / unknown mode -> body (matches the documented default).
        targets.append(source_body or "")
    for pat in patterns:
        if not isinstance(pat, str) or not pat:
            continue
        try:
            rx = re.compile(pat, re.IGNORECASE)
        except re.error:
            continue
        for text in targets:
            tok = _first_token(rx.search(text))
            if tok:
                return tok
    return ""


def _resolve_role(
    role: str,
    *,
    function_name: str,
    function_signature: str,
    source_body: str,
    auth_sig_tail: str = "",
    match_any: Optional[List[str]] = None,
    match_in: str = "body",
) -> str:
    """Resolve one bind role to a source token, or "" when UNBOUND.

    A role is resolved by FIRST trying the template-supplied curated
    ``match_any`` patterns (respecting ``match_in`` name|body|both). When the
    template supplies none (or none match), it FALLS BACK to the built-in
    default regex for the role. A role with neither a curated nor a default
    match stays UNBOUND (never-false-pass).

    The ``caller_auth_guard`` role is special-cased: its curated patterns and
    its built-in signature-modifier probe BOTH count, but the auth_sig_tail
    false-bind guard (no param-type credit) is preserved unchanged.
    """
    body = source_body or ""
    # Curated patterns win first (data-driven, per-goal). Auth is handled in its
    # own branch below so the signature-modifier probe is not lost.
    if role != "caller_auth_guard":
        curated = _curated_match(
            match_any or [],
            match_in,
            function_name=function_name,
            source_body=body,
        )
        if curated:
            return curated
    # The per-fn modifier check expects a SIGNATURE TAIL (visibility + mutability
    # + applied modifiers ONLY), NOT the param list - a param identifier like
    # `amount`/`uint256` would otherwise look like a modifier token (false bind).
    # The caller passes `auth_sig_tail` (the attrs string) for the auth role;
    # when blank we fall back to the body probe only (no signature-modifier
    # credit) so we never over-bind from param types.
    sig_tail = auth_sig_tail or ""
    if role == "accrual_accumulator":
        return _first_token(_ACCRUAL_ACCUM_RE.search(body)) or _first_token(
            _ACCRUAL_ACCUM_SCALAR_RE.search(body)
        )
    if role == "claimed_marker":
        return _first_token(_CLAIMED_MARKER_RE.search(body))
    if role == "balance_state":
        return _first_token(_BALANCE_STATE_RE.search(body))
    if role == "caller_auth_guard":
        # Curated patterns (if any) take precedence, tested over the SELECTED
        # text only (name/body) - NEVER the signature param list, so the
        # auth_sig_tail false-bind guard (no param-type credit) is preserved.
        curated_auth = _curated_match(
            match_any or [],
            match_in,
            function_name=function_name,
            source_body=body,
        )
        if curated_auth:
            return curated_auth
        # Reuse the per-function modifier check from invariant-auto-synth when
        # importable (it answers "does THIS fn's signature carry a modifier"),
        # else fall back to an in-body onlyOwner/onlyRole/require(msg.sender)
        # probe. Either match BINDS the role.
        if _IAS is not None and hasattr(_IAS, "_sol_fn_has_modifier"):
            try:
                if _IAS._sol_fn_has_modifier(sig_tail):
                    return "modifier"
            except Exception:  # noqa: BLE001
                pass
        m = _AUTH_FALLBACK_RE.search(body)
        return _first_token(m) if m else ""
    if role == "withdraw_entrypoint":
        # Prefer the function NAME (the entrypoint itself), else a body call.
        if _WITHDRAW_ENTRY_RE.search(function_name or ""):
            return function_name
        return _first_token(_WITHDRAW_ENTRY_RE.search(body))
    if role == "terminal_revert_absent":
        # BOUND (the relation is checkable) iff the value-return path does NOT
        # carry an unconditional `revert(...)`/`require(false ...)` terminal.
        if re.search(r"\brevert\s*\(", body) or re.search(
            r"\brequire\s*\(\s*false\b", body
        ):
            return ""
        return "no-terminal-revert"
    if role == "health_factor_read":
        return _first_token(_HEALTH_READ_RE.search(body))
    if role == "liquidate_entrypoint":
        if _LIQUIDATE_ENTRY_RE.search(function_name or ""):
            return function_name
        return _first_token(_LIQUIDATE_ENTRY_RE.search(body))
    return ""


def _matched_impact_ids(
    function_name: str,
    function_signature: str,
    *,
    language: str,
    contract_kind: str,
    scope_text: str,
) -> List[str]:
    """Resolve the set of matched impact_ids using the SAME classify + admit
    logic as render_impact_methodology_questions (shape/kind/language intersect
    with family normalization + kind-only rescue). Returns [] when the renderer
    is unavailable (graceful)."""
    if _HQR is None:
        return []
    try:
        target = _HQR.classify_impact_target(
            function_name,
            function_signature,
            language=language,
            contract_kind=contract_kind,
            scope_text=scope_text,
        )
    except Exception:  # noqa: BLE001
        return []
    classes = {_HQR.shape_family(c) for c in target.get("shape_classes", [])}
    tgt_language = _HQR.language_alias(target.get("language", ""))
    tgt_kind = (target.get("contract_kind") or "").strip().lower()
    tgt_family = _HQR.kind_family(tgt_kind)
    try:
        books = _HQR.load_impact_playbooks()
    except Exception:  # noqa: BLE001
        books = []
    matched: List[str] = []
    seen: set = set()
    for playbook in books or []:
        applies_shape = playbook.get("applies_to_shape_classes") or []
        if not isinstance(applies_shape, list):
            continue
        if not _HQR._impact_filter_admits(
            playbook.get("applies_to_languages"), tgt_language
        ):
            continue
        shape_match = bool(
            classes.intersection(
                _HQR.shape_family(c) for c in applies_shape if str(c).strip()
            )
        )
        applies_kind_families = {
            _HQR.kind_family(k)
            for k in (playbook.get("applies_to_contract_kinds") or [])
            if str(k).strip()
        }
        kind_match = bool(tgt_family) and tgt_family in applies_kind_families
        kind_rescue = (
            kind_match
            and not classes
            and _HQR._function_is_value_moving_ish(function_name, function_signature)
        )
        if not (shape_match or kind_rescue):
            continue
        impact_id = str(playbook.get("impact_id") or "").strip()
        if impact_id and impact_id not in seen:
            seen.add(impact_id)
            matched.append(impact_id)
    # Liquidation routing rescue (no fork of classify_impact_target): a function
    # NAMED liquidate* is, by definition, a liquidation entrypoint, but the
    # liquidation-abuse playbook's applies_to_shape_classes does not include the
    # `collateral-liquidation-fn` shape the classifier emits - so a bare
    # `liquidate(...)` with no lending contract_kind misses the playbook above.
    # Admit liquidation-abuse here when (a) the name is a liquidate entrypoint and
    # (b) the playbook actually exists in the corpus. The goal template's role
    # binding still gates credit downstream (never-false-pass).
    if "liquidation-abuse" not in seen and _LIQUIDATE_ENTRY_RE.search(
        function_name or ""
    ):
        if any(
            str((pb or {}).get("impact_id") or "").strip() == "liquidation-abuse"
            for pb in (books or [])
        ):
            seen.add("liquidation-abuse")
            matched.append("liquidation-abuse")
    return matched


def goal_invariants_for(
    function_name: str,
    function_signature: str,
    *,
    language: str,
    contract_kind: str = "",
    scope_text: str = "",
    source_body: str = "",
    templates: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    file_line: str = "",
    auth_sig_tail: str = "",
) -> List[Dict[str, Any]]:
    """Emit GOAL-oriented invariant records for a single function.

    a) Resolve the matched impact_id set via the renderer's classify + admit
       logic (shape/kind/language).
    b) For each matched impact_id, look up its goal templates.
    c) Bind each template's required roles against ``source_body``; a role with
       NO source match is UNBOUND.

    Each returned dict (schema auditooor.goal_invariant.v1) carries
    status="goal-bound" iff ALL required roles bound, else "goal-unbound";
    is_goal_template is True only when goal-bound. Returns [] when the corpus is
    empty (graceful-empty) or no impact matches the function (no spray).
    """
    tmpl = templates if templates is not None else load_goal_templates()
    if not tmpl:
        return []
    impact_ids = _matched_impact_ids(
        function_name,
        function_signature,
        language=language,
        contract_kind=contract_kind,
        scope_text=scope_text,
    )
    if not impact_ids:
        return []
    out: List[Dict[str, Any]] = []
    for impact_id in impact_ids:
        for template in tmpl.get(impact_id, []) or []:
            binds = template.get("binds") or []
            bound_symbols: Dict[str, str] = {}
            unbound_roles: List[str] = []
            for b in binds:
                role = str((b or {}).get("role") or "").strip()
                if not role:
                    continue
                # Curated, data-driven patterns supplied by the template (optional).
                raw_any = (b or {}).get("match_any") or []
                match_any = [str(p) for p in raw_any if isinstance(p, str) and p]
                match_in = str((b or {}).get("match_in") or "body").strip().lower()
                if match_in not in ("name", "body", "both"):
                    match_in = "body"
                token = _resolve_role(
                    role,
                    function_name=function_name,
                    function_signature=function_signature,
                    source_body=source_body,
                    auth_sig_tail=auth_sig_tail,
                    match_any=match_any,
                    match_in=match_in,
                )
                if token:
                    bound_symbols[role] = token
                else:
                    unbound_roles.append(role)
            all_bound = bool(binds) and not unbound_roles
            status = "goal-bound" if all_bound else "goal-unbound"
            out.append(
                {
                    "schema_version": GOAL_RECORD_SCHEMA,
                    "impact_id": impact_id,
                    "goal_template_id": str(template.get("id") or ""),
                    "goal_statement": str(template.get("goal_statement") or ""),
                    "language": (language or "").strip().lower(),
                    "function": function_name,
                    "file_line": file_line,
                    "bound_symbols": bound_symbols,
                    "unbound_roles": unbound_roles,
                    "relational_form": str(template.get("relational_form") or ""),
                    "named_invariant_xref": list(
                        template.get("named_invariant_xref") or []
                    ),
                    "severity_axis": str(template.get("severity_axis") or ""),
                    "status": status,
                    # NEVER-FALSE-PASS: an unbound goal is NOT a usable template.
                    "is_goal_template": all_bound,
                }
            )
    return out
