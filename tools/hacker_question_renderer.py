#!/usr/bin/env python3
"""Shared Hackerman question renderer.

This module converts ranked attack-class rows into bounded attacker questions
with proof obligations and kill conditions.  It is intentionally light-weight:
callers provide the ranked rows and any target metadata they already know.

W5-F1: the renderer also draws from a hand-authored curated question library
(`audit/corpus_tags/hacker_question_library.yaml`, schema
`auditooor.hacker_question_template.v1`).  A function signature is classified
into one or more shape classes; the library's reusable probing questions for
those classes are emitted alongside the attack-class-derived questions.  This
turns the renderer from a taxonomy-label projector into a reasoning library.

W5-F3: the renderer also draws from a hand-authored economic-attack-primitive
corpus (`audit/corpus_tags/economic_attack_primitives.yaml`, schema
`auditooor.economic_attack_primitive.v1`).  Each primitive (donation/inflation
attack, sandwich MEV, oracle-manipulation arbitrage, fee-rounding skim,
liquidation cascade, JIT liquidity, vote-bribery, interest-rate manipulation,
share-price dilution) declares the shape classes it applies to.  When a
function classifies into one of those classes, the primitive's economic
probing questions are emitted with `question_source: economic-primitive`,
carrying the primitive's profit-source and real-incident anchor as rationale.
This wires economic-attack reasoning - previously a disconnected IR silo
(econ-simulator, economic-risk-card, economic-hypotheses-ir) - directly into
the hacker-question flow so DeFi-shaped functions get economic questions.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any


HACKER_QUESTION_SCHEMA = "auditooor.hacker_question.v1"
HACKER_QUESTION_TEMPLATE_SCHEMA = "auditooor.hacker_question_template.v1"
ECONOMIC_PRIMITIVE_SCHEMA = "auditooor.economic_attack_primitive.v1"
# Per-impact hunting-methodology corpus schema (sibling of the economic
# primitive corpus; consolidates the authored IMPACT_*/methodology playbooks).
IMPACT_PLAYBOOK_SCHEMA = "auditooor.impact_hunting_methodology.v1"

# Curated library lives next to the corpus tags it complements.
_LIBRARY_PATH = (
    Path(__file__).resolve().parent.parent
    / "audit"
    / "corpus_tags"
    / "hacker_question_library.yaml"
)

# W5-F3: economic-attack-primitive corpus, same directory.
_ECONOMIC_PRIMITIVES_PATH = (
    Path(__file__).resolve().parent.parent
    / "audit"
    / "corpus_tags"
    / "economic_attack_primitives.yaml"
)

# Per-impact hunting-methodology corpus, same directory.
_IMPACT_PLAYBOOKS_PATH = (
    Path(__file__).resolve().parent.parent
    / "audit"
    / "corpus_tags"
    / "impact_hunting_methodology.yaml"
)

_LIBRARY_CACHE: dict[str, Any] | None = None
_ECONOMIC_PRIMITIVES_CACHE: list[dict[str, Any]] | None = None
_IMPACT_PLAYBOOKS_CACHE: list[dict[str, Any]] | None = None

PROOF_DOMAIN_ALWAYS_TERMS = {
    "attestation",
    "nullifier",
    "verifier",
}
PROOF_DOMAIN_ROUTE_TERMS = {"bridge", "crosschain", "portal"}
PROOF_DOMAIN_CONTEXT_TERMS = PROOF_DOMAIN_ROUTE_TERMS | {"quorum"}
ZERO_OUTPUT_LESSON_CLASSES = {
    "first-depositor-inflation",
    "share-price-manipulation",
    "rounding-direction-attack",
    "mint-burn-asymmetry",
}
TAIL_HEALTH_LESSON_CLASSES = {
    "liquidation-trigger-poison",
}
SIBLING_SAFE_CALLSITE_LESSON_CLASSES = {
    "fix-not-applied-to-sibling",
    "reverted-guard-still-live",
    "sibling-fix-not-applied",
}


def _normalized_attack_class(attack_class: str) -> str:
    return attack_class.lower().replace("_", "-").strip()


def _attack_class_matches(attack_class: str, candidate: str) -> bool:
    attack_class_norm = f"-{_normalized_attack_class(attack_class)}-"
    candidate_norm = f"-{candidate.lower().replace('_', '-').strip()}-"
    return candidate_norm in attack_class_norm


def _attack_class_matches_any(attack_class: str, candidates: set[str]) -> bool:
    return any(_attack_class_matches(attack_class, candidate) for candidate in candidates)


def _evidence_id(evidence: dict[str, Any]) -> str:
    for key in (
        "record_id",
        "verdict_id",
        "outcome_id",
        "tag_file",
        "source_ref",
        "rule_id",
        "path",
    ):
        value = evidence.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _first_evidence(row: dict[str, Any]) -> dict[str, Any]:
    for key in ("evidence", "evidence_refs", "analogue_refs"):
        items = row.get(key)
        if not isinstance(items, list):
            continue
        first = next((item for item in items if isinstance(item, dict)), None)
        if first is not None:
            return first
    return {}


def _cross_language_analogues(evidence: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
    raw = evidence.get("cross_language_analogues")
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        language = str(item.get("target_language") or "").strip()
        translation = str(item.get("pattern_translation") or "").strip()
        if not language or not translation:
            continue
        cleaned = {
            "target_language": language,
            "pattern_translation": translation,
        }
        for field in ("analogue_record_id", "confidence", "reason", "attack_class"):
            if item.get(field) not in (None, ""):
                cleaned[field] = item[field]
        out.append(cleaned)
        if len(out) >= limit:
            break
    return out


def _canonical_hackerman_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    if not evidence:
        return {}
    if not (
        evidence.get("match_kind")
        or evidence.get("match_weight") not in (None, "")
        or evidence.get("record_tier")
        or evidence.get("record_quality_score") not in (None, "")
    ):
        return {}
    out: dict[str, Any] = {}
    source_record_id = _evidence_id(evidence)
    if source_record_id:
        out["source_record_id"] = source_record_id
    for field in (
        "match_kind",
        "match_weight",
        "record_tier",
        "record_quality_score",
        "target_language",
        "target_repo",
        "target_component",
    ):
        value = evidence.get(field)
        if value not in (None, ""):
            out[field] = value
    return out


def attack_question_text(attack_class: str, function_name: str = "", detector_slug: str = "") -> str:
    pretty = attack_class.replace("-", " ").replace("_", " ").strip() or "this attack class"
    target = function_name or detector_slug or "this target"
    if _is_proof_domain_class(attack_class):
        return (
            f"Can an attacker supply or replay proof/attestation material that {target}'s "
            "production verifier accepts for a release, withdrawal, or finalization path?"
        )
    if _attack_class_matches_any(attack_class, ZERO_OUTPUT_LESSON_CLASSES):
        return (
            f"Can a pre-curated, reserve-inflated setup force {target}'s first measured output "
            "to floor to zero and hand the attacker value from the same accounting path?"
        )
    if _attack_class_matches_any(attack_class, TAIL_HEALTH_LESSON_CLASSES):
        return (
            f"Is the sorted-list tail only a nominal proxy while {target} can still leave a live "
            "ICR or health check below threshold?"
        )
    if _attack_class_matches_any(attack_class, SIBLING_SAFE_CALLSITE_LESSON_CLASSES):
        return (
            f"Where does a nearby safe callsite already repair the same invariant, and why does "
            f"{target} still skip that guard?"
        )
    templates = {
        "admin-bypass": f"Can {target} be reached with an authority, signer, role, or owner check missing or checked against the wrong actor?",
        "authorization-bypass": f"Can {target} be reached with authorization checked on a nearby object but not on the state transition that matters?",
        "accounting-drift": f"Can {target} move accounting balances before a later invariant, slippage, or state update can fail?",
        "invariant-bypass": f"Can {target} break a state invariant under an adjacent but valid ordering of calls?",
        "reentrancy": f"Can {target} make an external call before all accounting and permission state is finalized?",
        "oracle-manipulation": f"Can {target} consume stale, attacker-influenced, or domain-mismatched pricing data?",
    }
    for key, question in templates.items():
        if key in attack_class:
            return question
    return f"How would an attacker turn {target}'s {pretty} shape into a concrete state transition, fund flow, or liveness failure?"


def _is_proof_domain_class(attack_class: str) -> bool:
    lowered = attack_class.lower().replace("cross-chain", "crosschain").replace("cross_chain", "crosschain")
    tokens = {token for token in lowered.replace("_", "-").split("-") if token}
    if tokens & PROOF_DOMAIN_ALWAYS_TERMS:
        return True
    if "proof" in tokens and bool(tokens & PROOF_DOMAIN_CONTEXT_TERMS):
        return True
    return bool(tokens & PROOF_DOMAIN_ROUTE_TERMS) and bool(tokens & (PROOF_DOMAIN_ALWAYS_TERMS | {"proof", "quorum"}))


def proof_gate(attack_class: str) -> str:
    if _is_proof_domain_class(attack_class):
        return "production_reachability_required"
    return "source_confirmed"


def claim_boundary(attack_class: str) -> str:
    if _is_proof_domain_class(attack_class):
        return (
            "Bridge/proof-domain question only; not accepted-proof, release, finalization, "
            "duplicate/OOS, severity, or submission-readiness evidence."
        )
    return (
        "Advisory hacker question only; not exploitability, production reachability, "
        "duplicate/OOS, severity, or submission-readiness evidence."
    )


def shape_question_proof_obligation(shape_class: str = "", reasoning_axis: str = "") -> str:
    axis = str(reasoning_axis or "").strip()
    shape = str(shape_class or "").strip()
    suffix = f" for `{shape}`" if shape else ""
    if axis:
        return (
            f"Answer the `{axis}` hacker question{suffix} against the real source path; "
            "show attacker control, production reachability, affected state, and a negative control."
        )
    return (
        f"Answer the shape-class hacker question{suffix} against the real source path; "
        "show attacker control, production reachability, affected state, and a negative control."
    )


def shape_question_kill_condition(shape_class: str = "", reasoning_axis: str = "") -> str:
    axis = str(reasoning_axis or "").strip()
    if axis:
        return (
            f"Kill if the `{axis}` condition is not reachable on the production path, "
            "has no attacker-controlled transition, or collapses under the adjacent control case."
        )
    return (
        "Kill if the question is answered only by test-only setup, trusted-actor behavior, "
        "or a state transition that has no non-self impact."
    )


def economic_question_proof_obligation(primitive_id: str = "", category: str = "") -> str:
    primitive = str(primitive_id or "").strip()
    suffix = f" for `{primitive}`" if primitive else ""
    category_bits = f" in the `{category}` category" if category else ""
    return (
        f"Prove the economic preconditions{suffix}{category_bits}: attacker capital/control, "
        "profit or victim/protocol loss, production reachability, repeatability bounds, and a no-profit control."
    )


def economic_question_kill_condition(primitive_id: str = "") -> str:
    primitive = str(primitive_id or "").strip()
    prefix = f"Kill `{primitive}` if" if primitive else "Kill if"
    return (
        f"{prefix} the profit source is absent, losses are self-inflicted, "
        "the path depends on excluded MEV-only behavior, or production parameters make the trade uneconomic."
    )


def impact_question_proof_obligation(impact_id: str = "") -> str:
    suffix = f" for `{impact_id}`" if impact_id else ""
    return (
        f"Prove the impact preconditions{suffix}: attacker-reachable entry "
        "on the production path, the affected non-self state/funds, the "
        "realized impact magnitude, and a negative control where the impact "
        "does not occur."
    )


def impact_question_kill_condition(impact_id: str = "") -> str:
    prefix = f"Kill `{impact_id}` if" if impact_id else "Kill if"
    return (
        f"{prefix} the impact is self-inflicted, only reachable by a trusted "
        "actor, recoverable by an in-protocol path, or only reproduced in a "
        "test-only / single-process / injected-fault setup."
    )


def proof_obligation(attack_class: str) -> str:
    if _is_proof_domain_class(attack_class):
        return (
            "Prove verifier acceptance on the production entry point, response-path or "
            "release-proof evidence, finalization-window status, attacker-controlled "
            "destination delta, and an honest/corrupted proof negative control."
        )
    if _attack_class_matches_any(attack_class, ZERO_OUTPUT_LESSON_CLASSES):
        return (
            "Prove the pre-curated or reserve-inflated state forces zero output on the same path, "
            "and include one realistic control case plus one negative control that stays above the floor."
        )
    if _attack_class_matches_any(attack_class, TAIL_HEALTH_LESSON_CLASSES):
        return (
            "Prove a non-tail position is unhealthy while the sorted-list tail still looks healthy, "
            "and show the live ICR or health check that diverges from the tail proxy."
        )
    if _attack_class_matches_any(attack_class, SIBLING_SAFE_CALLSITE_LESSON_CLASSES):
        return (
            "Prove the nearby safe callsite repairs the same invariant, then show why the target path "
            "does not inherit that guard."
        )
    if "admin" in attack_class or "author" in attack_class:
        return "Prove the attacker-controlled actor reaches the sensitive state transition without the required authority."
    if "account" in attack_class or "fund" in attack_class or "yield" in attack_class:
        return "Prove the before/after balances for attacker, victim, and protocol accounts under the real execution path."
    if "reentr" in attack_class:
        return "Prove an external callback can re-enter before the relevant state is finalized."
    if "oracle" in attack_class:
        return "Prove the consumed price/input can be stale, manipulated, or from the wrong domain in production configuration."
    if "liveness" in attack_class or "halt" in attack_class:
        return "Prove the failure in a production-path harness and rule out teardown or single-process artifacts."
    return "Prove reachability, non-self impact, and the smallest production-path state transition that realizes the attack class."


def kill_condition(attack_class: str) -> str:
    if _is_proof_domain_class(attack_class):
        return (
            "Kill if exploitability requires signing-key compromise, unavailable live "
            "attestation, unreachable finalization, or no destination release/withdrawal."
        )
    if _attack_class_matches_any(attack_class, ZERO_OUTPUT_LESSON_CLASSES):
        return (
            "Kill if the same workload still produces nonzero output under realistic parameters, "
            "or if the claim depends on an artificial pre-curated setup."
        )
    if _attack_class_matches_any(attack_class, TAIL_HEALTH_LESSON_CLASSES):
        return (
            "Kill if the sorted-list tail and live health check agree under the same workload, "
            "or if the tail is not actually used as the proxy."
        )
    if _attack_class_matches_any(attack_class, SIBLING_SAFE_CALLSITE_LESSON_CLASSES):
        return (
            "Kill if the same guard is already applied on the target path or the sibling site is not a real safe control."
        )
    if "admin" in attack_class or "author" in attack_class:
        return "Kill if the production path requires the correct privileged actor before the state transition."
    if "account" in attack_class or "fund" in attack_class or "yield" in attack_class:
        return "Kill if all affected balances stay conserved for non-attacker-owned assets or the movement is fully reversible by design."
    if "reentr" in attack_class:
        return "Kill if the external call is absent, post-state, or guarded by a production reentrancy lock."
    if "oracle" in attack_class:
        return "Kill if production configuration pins a trusted, fresh, domain-correct input with no attacker influence."
    if "round" in attack_class or "first" in attack_class:
        return "Kill if the adjacent control case and the alleged bug case produce equivalent accounting."
    if "liveness" in attack_class or "halt" in attack_class:
        return "Kill if the failure only appears in keeper-direct, teardown, injected-fault, or single-process-only evidence."
    return "Kill if the hypothesis cannot be reached by an unprivileged actor on the real production path."


def load_question_library(path: Path | None = None) -> dict[str, Any]:
    """Load and cache the curated hacker-question library.

    Returns a dict keyed by shape-class id.  Degrades gracefully to an empty
    library if the file or a YAML parser is unavailable - the renderer still
    emits attack-class-derived questions in that case.
    """
    global _LIBRARY_CACHE
    if path is None and _LIBRARY_CACHE is not None:
        return _LIBRARY_CACHE
    target = path or _LIBRARY_PATH
    library: dict[str, Any] = {}
    try:
        import yaml  # type: ignore

        with open(target, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        for shape_class in data.get("shape_classes", []) or []:
            if not isinstance(shape_class, dict):
                continue
            class_id = str(shape_class.get("id") or "").strip()
            if not class_id:
                continue
            library[class_id] = shape_class
    except Exception:
        library = {}
    if path is None:
        _LIBRARY_CACHE = library
    return library


def load_economic_primitives(path: Path | None = None) -> list[dict[str, Any]]:
    """Load and cache the economic-attack-primitive corpus (W5-F3).

    Returns a list of primitive dicts.  Degrades gracefully to an empty list
    if the file or a YAML parser is unavailable - the renderer still emits
    structural and corpus-derived questions in that case.
    """
    global _ECONOMIC_PRIMITIVES_CACHE
    if path is None and _ECONOMIC_PRIMITIVES_CACHE is not None:
        return _ECONOMIC_PRIMITIVES_CACHE
    target = path or _ECONOMIC_PRIMITIVES_PATH
    primitives: list[dict[str, Any]] = []
    try:
        import yaml  # type: ignore

        with open(target, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        for primitive in data.get("primitives", []) or []:
            if not isinstance(primitive, dict):
                continue
            if not str(primitive.get("id") or "").strip():
                continue
            primitives.append(primitive)
    except Exception:
        primitives = []
    if path is None:
        _ECONOMIC_PRIMITIVES_CACHE = primitives
    return primitives


def load_impact_playbooks(path: Path | None = None) -> list[dict[str, Any]]:
    """Load and cache the per-impact hunting-methodology corpus.

    Returns a list of playbook dicts, one per impact class (impact_id).
    Mirrors `load_economic_primitives`: degrades gracefully to an empty list if
    the file or a YAML parser is unavailable, and requires a non-empty
    `impact_id` on each row - the renderer must never raise on a missing or
    corrupt corpus, it simply emits no impact-methodology questions.
    """
    global _IMPACT_PLAYBOOKS_CACHE
    if path is None and _IMPACT_PLAYBOOKS_CACHE is not None:
        return _IMPACT_PLAYBOOKS_CACHE
    target = path or _IMPACT_PLAYBOOKS_PATH
    playbooks: list[dict[str, Any]] = []
    try:
        import yaml  # type: ignore

        with open(target, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        for playbook in data.get("playbooks", []) or []:
            if not isinstance(playbook, dict):
                continue
            if not str(playbook.get("impact_id") or "").strip():
                continue
            playbooks.append(playbook)
    except Exception:
        playbooks = []
    if path is None:
        _IMPACT_PLAYBOOKS_CACHE = playbooks
    return playbooks


def render_economic_primitive_questions(
    function_name: str = "",
    function_signature: str = "",
    *,
    shape_hash: str = "",
    file_path: str = "",
    context_pack_id: str = "",
    detector_slug: str = "",
    library: dict[str, Any] | None = None,
    primitives: list[dict[str, Any]] | None = None,
    max_questions: int = 0,
) -> list[dict[str, Any]]:
    """Render economic-attack-primitive questions for a function's shape (W5-F3).

    Classifies the function into structural shape classes, then attaches every
    economic primitive whose `applies_to_shape_classes` intersects those
    classes.  Emits `auditooor.hacker_question.v1` rows tagged with
    `question_source: economic-primitive`, the originating `economic_primitive`
    id, its `economic_category`, and the primitive's profit-source plus
    real-incident anchor folded into the rationale.
    """
    prims = primitives if primitives is not None else load_economic_primitives()
    if not prims:
        return []
    lib = library if library is not None else load_question_library()
    classes = set(classify_function_shape(function_name, function_signature, library=lib))
    if not classes:
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for primitive in prims:
        applies = primitive.get("applies_to_shape_classes") or []
        if not isinstance(applies, list):
            continue
        if not classes.intersection(str(c) for c in applies):
            continue
        primitive_id = str(primitive.get("id") or "").strip()
        category = str(primitive.get("category") or "").strip()
        profit_source = str(primitive.get("profit_source") or "").strip()
        incident = str(primitive.get("incident_anchor") or "").strip()
        for entry in primitive.get("questions", []) or []:
            if not isinstance(entry, dict):
                continue
            text = str(entry.get("q") or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            rationale_bits = [b for b in (str(entry.get("why") or "").strip(),
                                          profit_source) if b]
            row = {
                "schema": HACKER_QUESTION_SCHEMA,
                "question": text,
                "question_source": "economic-primitive",
                "economic_primitive": primitive_id,
                "economic_category": category,
                "reasoning_axis": str(entry.get("axis") or "economic"),
                "rationale": " Profit source: ".join(rationale_bits) if rationale_bits else "",
                "profit_source": profit_source,
                "incident_anchor": incident,
                "function_shape": shape_hash,
                "proof_gate": "source_confirmed",
                "claim_boundary": claim_boundary(""),
                "proof_obligation": economic_question_proof_obligation(primitive_id, category),
                "kill_condition": economic_question_kill_condition(primitive_id),
                "target_file": file_path,
                "mcp_context_pack_id": context_pack_id,
            }
            if detector_slug:
                row["detector_slug"] = detector_slug
            out.append(row)
            if max_questions and len(out) >= max_questions:
                return out
    return out


# Shape-class classification rules.  Each entry: (class_id, name_regex,
# signature_keyword_regex).  A class matches when EITHER the function name OR
# the full signature matches.  A function commonly matches several classes -
# they are not mutually exclusive (a withdrawal is also a transfer path).
_SHAPE_CLASS_RULES: list[tuple[str, str, str]] = [
    ("withdrawal-redemption-fn",
     r"withdraw|redeem|claim|unstake|exit|cashout|cash_out|payout",
     r"\bwithdraw|\bredeem|\bclaim"),
    ("token-transfer-path",
     r"transfer|send|payout|sweep|disburse|remit",
     r"\btransfer\(|\bsafeTransfer|IERC20|\.send\("),
    ("reward-fee-distribution-fn",
     r"distribut|reward|harvest|accrue|payfee|collectfee|notifyreward",
     r"reward|feeIndex|perShare|accumulat"),
    ("collateral-liquidation-fn",
     r"liquidat|seize|collateral|healthfactor|repay|borrow",
     r"collateral|healthFactor|liquidat"),
    ("oracle-read-fn",
     r"price|oracle|quote|getrate|exchangerate|peek|latestanswer",
     r"oracle|latestRoundData|getPrice|priceFeed"),
    ("signature-nonce-fn",
     r"permit|sign|verify|recover|nonce|delegatebysig|votebysig",
     r"ecrecover|ECDSA|isValidSignature|EIP712|nonce"),
    ("upgrade-init-fn",
     r"^init|initialize|setup|upgrade|migrate|^constructor",
     r"initializer|onlyProxy|_disableInitializers"),
    ("delegatecall-proxy-fn",
     r"delegate|fallback|dispatch|proxy|implementation",
     r"delegatecall|\.delegatecall"),
    ("governance-voting-fn",
     r"vote|propos|govern|queue|execute|delegate|castvote",
     r"proposal|votingPower|quorum|timelock"),
    ("pausable-emergency-fn",
     r"pause|unpause|freeze|halt|emergency|circuitbreak|shutdown",
     r"whenNotPaused|_pause\(|Pausable"),
    ("cross-chain-message-fn",
     r"receivemessage|onmessage|handlemessage|relay|crosschain|lzreceive|ccipreceive|bridge",
     r"sourceChain|srcChainId|origin|messageId|relayer"),
    ("loop-batch-fn",
     r"batch|multicall|bulk|forall|processall|sweepall",
     r"for\s*\(|\.length|\brange\b"),
    ("accounting-math-fn",
     r"convert|calc|compute|shares|assets|preview|mint|burn|exchangerate",
     r"mulDiv|/\s*total|totalSupply|totalShares|FullMath"),
    ("cosmos-msg-handler-fn",
     r"^msg|handlemsg|^handle.*msg",
     r"sdk\.Context|sdk\.Msg|ctx sdk|MsgServer"),
    ("state-machine-transition-fn",
     r"finaliz|settle|activate|cancel|close|open|advance|transition|complete",
     r"status|state|phase|lifecycle"),
    ("deadline-time-dependent-fn",
     r"deadline|expire|timeout|elapsed",
     r"block\.timestamp|block\.number|deadline|ctx\.BlockTime"),
    ("access-controlled-setter",
     r"^set|^update|^config|^change|register|grant|revoke",
     r"onlyOwner|onlyRole|onlyAdmin|require\(msg\.sender|hasRole"),
]

# --------------------------------------------------------------------------
# token-transfer-path precision guard.
#
# The generic (name_re, sig_re) rule for `token-transfer-path` keys on the
# substring "transfer", so it false-matches the OWNERSHIP / ROLE / ADMIN
# transfer family (transferOwnership / transferAdmin / transferRole / accept*)
# - none of which move a VALUE token, yet they picked up token-transfer-path
# and, via shape_match, the value-impact playbooks (direct-theft-funds). A
# token transfer moves an AMOUNT of a token; an ownership/role/admin transfer
# hands over a privilege. Distinguish them structurally, not per-name:
#   token-transfer-path is a VALUE transfer when it carries an amount-ish
#   param (uint / uint256 / amount / value / shares / assets) in the signature,
#   OR its name is NOT in the ownership/role/admin/operator family.
# So `transfer(address,uint256)` / `transferFrom(...)` / `safeTransferFrom(...)`
# / `send(address,uint256)` KEEP token-transfer-path (amount-ish param present),
# while `transferOwnership(address)` / `acceptOwnership()` / `transferAdmin(
# address)` / `transferRole(bytes32,address)` are EXCLUDED (ownership family,
# no amount-ish param).
_OWNERSHIP_ROLE_ADMIN_NAME_RE = re.compile(
    r"(ownership|admin|role|operator)$|^accept", re.IGNORECASE
)
_AMOUNT_ISH_PARAM_RE = re.compile(
    r"\buint\d*\b|\bamount\b|\bvalue\b|\bshares\b|\bassets\b", re.IGNORECASE
)


def _token_transfer_path_is_value_transfer(name: str, sig: str) -> bool:
    """True when a `token-transfer-path` name/sig match is a genuine VALUE
    token transfer (transfer/transferFrom/safeTransfer(From)/send of an amount)
    and NOT an ownership/role/admin/operator transfer.

    A value transfer either carries an amount-ish param (uint/uint256/amount/
    value/shares/assets) OR is not in the ownership/role/admin/operator/accept*
    family. transferOwnership(address) / acceptOwnership() / transferAdmin(
    address) / transferRole(bytes32,address) fail both arms -> excluded.
    """
    if _AMOUNT_ISH_PARAM_RE.search(sig or ""):
        return True
    return not _OWNERSHIP_ROLE_ADMIN_NAME_RE.search(name or "")


# These two classes are emitted as a structural baseline: every mutator gets
# the external-state-mutating set, every public read gets the view-getter set.
# They are advisory defaults applied only when no sharper class matched.
_DEFAULT_MUTATOR_CLASS = "external-state-mutating-fn"
_DEFAULT_VIEW_CLASS = "view-getter-fn"

# GENERIC / structural-baseline shapes: the shapes the classifier assigns to a
# function it could NOT specialize into a value-mover role. These carry no
# impact-routing signal of their own (every playbook that would match them lists
# a SHARPER value shape too), so a function tagged ONLY with generic shapes is
# effectively shape-less for attach purposes. The contract-kind UNION rescue must
# treat "only generic shapes" the same as "no shape at all" - else a value-moving
# `deposit(uint256,address)` (classified cross-contract-call/external-state-
# mutating-fn purely because of its address param) loses EVERY contract-kind-
# listed impact (direct-theft-funds/insolvency/permanent-freeze/... - measured
# 93 dropped (impact,kind) pairs across vault/lending/amm/bridge/gov/cosmos).
# A function with a SPECIFIC value shape (token-transfer-path / withdrawal-
# redemption-fn / accounting-math-fn / access-controlled-setter / ...) is NOT
# generic-only, so its real shape still governs (no kind spray onto e.g.
# registerValidator, which carries access-controlled-setter).
_GENERIC_ONLY_SHAPES = frozenset({_DEFAULT_MUTATOR_CLASS, _DEFAULT_VIEW_CLASS, "cross-contract-call"})

# VALUE-CONDUCTING sharp shapes: shapes through which FUNDS/VALUE demonstrably flow
# (a withdrawal/redemption, cross-chain message, collateral liquidation, reward/fee
# distribution, cosmos value handler, accounting mutation, or value batch loop). A
# value-mover whose sharp shape(s) are ALL in this set is a genuine value path for
# its contract-kind's value-impacts (direct-theft / drain / freeze / inflation /
# unauthorized-mint), EVEN when a specific impact's applies_to_shape_classes omits
# that exact sharp shape - e.g. a bridge `relayMessage` (cross-chain-message-fn) IS
# the drain surface. Deliberately EXCLUDES: (a) admin/config/ownership/upgrade/
# governance/view/oracle/pause shapes (access-controlled-setter, upgrade-init-fn,
# delegatecall-proxy-fn, governance-voting-fn, view-getter-fn, oracle-read-fn,
# pausable-emergency-fn, signature-nonce-fn, state-machine-transition-fn,
# deadline-time-dependent-fn) so the anti-spray guard holds; (b) the
# classifier-IMPRECISE `token-transfer-path` (it false-matches `transferOwnership`)
# - legit token transfers already carry token-transfer-path in the impacts' own
# shape-lists, so they attach via shape_match and lose nothing by its exclusion here.
_VALUE_CONDUCTING_SHARP_SHAPES = frozenset({
    "withdrawal-redemption-fn", "reward-fee-distribution-fn", "collateral-liquidation-fn",
    "cross-chain-message-fn", "accounting-math-fn", "cosmos-msg-handler-fn", "loop-batch-fn",
})


def classify_function_shape(
    function_name: str = "",
    function_signature: str = "",
    *,
    library: dict[str, Any] | None = None,
) -> list[str]:
    """Classify a function into curated shape-class ids.

    Heuristic name/keyword matching - advisory only.  Returns an ordered,
    de-duplicated list of class ids that exist in the library.  Always returns
    at least one class so a brief is never empty.
    """
    lib = library if library is not None else load_question_library()
    name = (function_name or "").strip().lower()
    sig = (function_signature or "").strip()
    sig_lower = sig.lower()
    matched: list[str] = []
    for class_id, name_re, sig_re in _SHAPE_CLASS_RULES:
        if class_id not in lib:
            continue
        if class_id in matched:
            continue
        name_hit = bool(name and re.search(name_re, name))
        sig_hit = bool(sig and re.search(sig_re, sig, re.IGNORECASE))
        if not (name_hit or sig_hit):
            continue
        # Precision guard: `token-transfer-path` keys on the "transfer"
        # substring, which false-matches the ownership/role/admin transfer
        # family. Only a genuine VALUE token transfer (amount-ish param, or a
        # name outside the ownership/role/admin/operator/accept* family) keeps
        # this sharp shape.
        if class_id == "token-transfer-path" and not _token_transfer_path_is_value_transfer(name, sig):
            continue
        matched.append(class_id)

    # External-call shape is signature-only (no clean name signal).
    if ("cross-contract-call" in lib
            and "cross-contract-call" not in matched
            and re.search(r"\.call\(|external|interface|\bcall\b", sig_lower)):
        matched.append("cross-contract-call")

    is_view = bool(re.search(r"\bview\b|\bpure\b|^get|^is|^has|^total|^balance", name)
                   or re.search(r"\bview\b|\bpure\b", sig_lower))
    if not matched:
        fallback = _DEFAULT_VIEW_CLASS if is_view else _DEFAULT_MUTATOR_CLASS
        if fallback in lib:
            matched.append(fallback)
    elif not is_view and _DEFAULT_MUTATOR_CLASS in lib:
        # A mutator that matched a sharp class still benefits from the generic
        # state-mutating questions; append them last as a baseline.
        if _DEFAULT_MUTATOR_CLASS not in matched:
            matched.append(_DEFAULT_MUTATOR_CLASS)
    return matched


# --------------------------------------------------------------------------
# Kind-family reconciliation.
#
# The impact-hunting-methodology corpus
# (audit/corpus_tags/impact_hunting_methodology.yaml) uses a FINE
# `applies_to_contract_kinds` vocabulary (129 kinds: lending-market,
# perp-margin, cdp-vault, oracle-adapter, proxy-admin, mpc-tss, bank-keeper,
# rpc-handler, ...). The classifier (`_CONTRACT_KIND_RULES`) only ever EMITS a
# small coarse set. Without reconciliation, ~119 fine kinds are never produced,
# so 8 impacts whose every fine kind sits outside the coarse set were
# kind-unreachable (they could only ever attach by shape, never by kind):
# liquidation-abuse, oracle-manipulation, signature-replay-forgery,
# unauthorized-upgrade-impl-swap, crypto-key-recovery-leak,
# bc-direct-loss-of-funds, bc-node-resource-exhaustion, bc-rpc-api-crash.
#
# `_KIND_FAMILY` normalizes BOTH a target kind and a playbook's
# applies_to_contract_kinds to a canonical FAMILY; attach then becomes a
# family-intersection. This is FAIL-CLOSED: it does NOT collapse the partition
# (a vault stays vault, a consensus target stays consensus, a pure token target
# does NOT acquire a perp/consensus family). Every fine kind maps to exactly one
# family; an unknown kind passes through unchanged (so a never-before-seen kind
# can still match its own literal, never the whole world).
#
# Families that are CLASSIFIER-EMITTABLE (a real target can infer them via
# `_CONTRACT_KIND_RULES`): the original 10 (amm, bridge, consensus,
# cosmos-module, governance, lending, staking, token, vault, zk-circuit) plus
# the 6 NEW families taught below: oracle, proxy, perp, distributor,
# crypto-signer, dex.
_KIND_FAMILY: dict[str, str] = {
    # --- vault family (share-accounting custody of fungible deposits) ---
    "vault": "vault",
    "erc4626-vault": "vault",
    "defi-vault": "vault",
    "escrow": "vault",
    "insurance-fund": "vault",
    "vesting": "vault",
    "intent-settlement": "vault",
    "settlement": "vault",
    # --- lending family (collateralized debt / CDP / liquidation venues) ---
    "lending": "lending",
    "lending-market": "lending",
    "cdp-vault": "lending",
    "stability-pool": "lending",
    "auction-liquidation": "lending",
    "auction": "lending",
    # --- perp family (perpetuals / margin / funding) ---
    "perp": "perp",
    "perps": "perp",
    "perp-margin": "perp",
    "perp-funding": "perp",
    "perpetuals-exchange": "perp",
    # --- amm family (constant-function pools) ---
    "amm": "amm",
    "amm-pool": "amm",
    "amm-dex": "amm",
    # --- dex family (orderbook / matching / marketplace / routing) ---
    "dex": "dex",
    "dex-orderbook": "dex",
    "matching-engine": "dex",
    "nft-marketplace": "dex",
    "router": "dex",
    # --- staking family ---
    "staking": "staking",
    "staking-rewards": "staking",
    "lst-lrt-staking": "staking",
    # --- distributor family (reward/fee/emission/gauge/merkle distribution) ---
    "distributor": "distributor",
    "merkle-claim": "distributor",
    "gauge": "distributor",
    "gauge-voter": "distributor",
    "gauge-emissions": "distributor",
    "emission-minter": "distributor",
    "fee-collector": "distributor",
    "feemarket": "distributor",
    "gas-service": "distributor",
    "paymaster": "distributor",
    # --- governance family ---
    "governance": "governance",
    # --- token family (plain fungible/non-fungible token + permit) ---
    "token": "token",
    "permit-erc2612": "token",
    # --- oracle family (price feeds) ---
    "oracle": "oracle",
    "oracle-adapter": "oracle",
    # --- randomness-beacon family (VRF / RANDAO / seed beacons) ---
    # Kept DISTINCT from `oracle`. A randomness beacon is cross-cutting: the
    # corpus authors put it ONLY in `crypto-key-recovery-leak.applies_to_
    # contract_kinds` (the seed/signing-key recovery concern), NOT in
    # `oracle-manipulation` (which lists `oracle-adapter`). Folding it into the
    # `oracle` family made every plain price-feed oracle wrongly inherit
    # crypto-key-recovery-leak. A self-mapping family lets a real randomness
    # beacon still reach key-recovery while a price oracle does not.
    "randomness-beacon": "randomness-beacon",
    # --- proxy family (upgradeability / admin / registry / dispute games) ---
    "proxy": "proxy",
    "proxy-admin": "proxy",
    "upgradeable-proxy": "proxy",
    "upgrade-handler": "proxy",
    "registry": "proxy",
    "dispute-game": "proxy",
    "dispute-game-factory": "proxy",
    "anchor-state-registry": "proxy",
    # --- bridge family (cross-chain message / portal / relay / IBC / L2) ---
    "bridge": "bridge",
    "bridge-adapter": "bridge",
    "bridge-messaging": "bridge",
    "bridge-attestation": "bridge",
    "cross-chain-message": "bridge",
    "cross-domain-messenger": "bridge",
    "xcm-handler": "bridge",
    "relayer": "bridge",
    "portal": "bridge",
    "meta-tx-forwarder": "bridge",
    "ibc": "bridge",
    "ibc-module": "bridge",
    "ibc-transfer-module": "bridge",
    "statechain": "bridge",
    "rollup": "bridge",
    "l1-protocol": "bridge",
    "l2-system-contract": "bridge",
    # --- crypto-signer family (key custody / signature schemes / MPC-TSS) ---
    "signer": "crypto-signer",
    "keystore": "crypto-signer",
    "hd-wallet": "crypto-signer",
    "mpc-tss": "crypto-signer",
    "mpc-signer": "crypto-signer",
    "prf-kdf": "crypto-signer",
    "signature-scheme": "crypto-signer",
    "signature-verifier": "crypto-signer",
    "hardware-wallet-app": "crypto-signer",
    "ring-signature": "crypto-signer",
    "tss-frost-schnorr": "crypto-signer",
    "hash-based-signature": "crypto-signer",
    "multisig-threshold": "crypto-signer",
    "eip712-typed-data": "crypto-signer",
    "eip1271-smart-account": "crypto-signer",
    "account-abstraction": "crypto-signer",
    "crypto-gadget": "crypto-signer",
    "consensus-crypto": "crypto-signer",
    # --- zk-circuit family (proof systems / verifiers / light-clients) ---
    "zk-circuit": "zk-circuit",
    "zk-verifier": "zk-circuit",
    "zk-value-circuit": "zk-circuit",
    "verifier": "zk-circuit",
    "proof-verifier": "zk-circuit",
    "proof-aggregator": "zk-circuit",
    "state-proof": "zk-circuit",
    "fraud-proof-emulator": "zk-circuit",
    "light-client": "zk-circuit",
    # --- consensus family (block production / ABCI / node-level / VM / p2p) ---
    "consensus": "consensus",
    "abci-app": "consensus",
    "consensus-state-transition": "consensus",
    "consensus-vote-extension": "consensus",
    "proposal-handler": "consensus",
    "blocksync": "consensus",
    "chunk-production": "consensus",
    "state-sync": "consensus",
    "state-machine": "consensus",
    "state-tree": "consensus",
    "el-client": "consensus",
    "vm-runtime": "consensus",
    "state-store": "consensus",
    "codec": "consensus",
    "node-daemon": "consensus",
    "node-resource": "consensus",
    "p2p": "consensus",
    "mempool": "consensus",
    # RPC/query node surfaces are a node-level (consensus) concern: a target
    # that is an RPC/query/mempool endpoint normalizes to consensus, which is
    # where the bc-rpc-api-crash methodology lives. (Folded per the brief's
    # "all the bc-/.../rpc/mempool kinds -> consensus or cosmos-module".)
    "rpc-api": "consensus",
    "rpc-handler": "consensus",
    "query-server": "consensus",
    "api-gateway": "consensus",
    "mempool-rpc": "consensus",
    # --- cosmos-module family (keeper / ante / bank / msg-handler) ---
    "cosmos-module": "cosmos-module",
    "cosmos-msg-handler": "cosmos-module",
    "cosmos-ante-handler": "cosmos-module",
    "bank-keeper": "cosmos-module",
    "state-machine-keeper": "cosmos-module",
    "module-account-handler": "cosmos-module",
    "node-client-derivation": "cosmos-module",
    "cron-scheduler": "cosmos-module",
}

# Families the classifier can EMIT (sanity-checked by the reconcile test).
_EMITTABLE_KIND_FAMILIES = frozenset({
    "amm", "bridge", "consensus", "cosmos-module", "governance", "lending",
    "staking", "token", "vault", "zk-circuit",
    # seven new families taught to _CONTRACT_KIND_RULES below
    "oracle", "proxy", "perp", "distributor", "crypto-signer", "dex",
    "randomness-beacon",
})


def kind_family(kind: str) -> str:
    """Normalize a fine contract-kind to its canonical family.

    Lower-cased, hyphen-normalized lookup in `_KIND_FAMILY`. An unknown kind
    passes through as itself (so a never-seen fine kind still matches its own
    literal in an intersection - it never silently widens to match everything).
    Empty input -> "".
    """
    k = str(kind or "").strip().lower().replace("_", "-")
    if not k:
        return ""
    return _KIND_FAMILY.get(k, k)


# --------------------------------------------------------------------------
# Shape-family reconciliation (the SHAPE-axis twin of _KIND_FAMILY).
#
# The impact-hunting-methodology corpus authors `applies_to_shape_classes`
# against a FINE shape vocabulary (51 distinct classes), but
# `classify_function_shape` can only EMIT 20 classes (the `_SHAPE_CLASS_RULES`
# ids present in the library, the three specials, and the two defaults). 37
# corpus shape-classes are NEVER emitted, so the renderer's shape attach arm
# (`classes.intersection(applies_to_shape_classes)`) could never fire on them -
# the exact same dead-arm failure mode as the kind-vocab gap, on the shape axis.
# Several dead classes are plain synonyms of an emittable one the author wrote
# by hand (liquidation-fn vs collateral-liquidation-fn; initializer-fn /
# upgrade-setter-fn vs upgrade-init-fn; reward-accrual-fn / distribution-fn vs
# reward-fee-distribution-fn; signature-verify-fn / crypto-verify-fn vs
# signature-nonce-fn; cross-chain-message-handler-fn vs cross-chain-message-fn).
#
# `_SHAPE_FAMILY` normalizes a corpus shape-class to a canonical EMITTABLE
# family; `shape_family` is applied to BOTH the target's emitted shape classes
# (each emittable class is a self-mapping key, so it normalizes to itself) and a
# playbook's applies_to_shape_classes, and attach becomes a family-intersection.
# FAIL-CLOSED: every family value is itself emittable (so a corpus class can
# only ever map onto a shape the classifier really produces), an unknown shape
# passes through as itself (matching only its own literal, never widening to the
# whole world), and language stays the partition guard (a go-only bc-* playbook
# still excludes a solidity target even after its dead shape is re-homed).
_SHAPE_FAMILY: dict[str, str] = {
    # access-control / role / admin setters -> access-controlled-setter
    "admin-config-setter-fn": "access-controlled-setter",
    "admin-setter-fn": "access-controlled-setter",
    "role-grant-fn": "access-controlled-setter",
    # upgrade / initializer -> upgrade-init-fn
    "initializer-fn": "upgrade-init-fn",
    "upgrade-setter-fn": "upgrade-init-fn",
    # delegatecall implementation target -> delegatecall-proxy-fn
    "delegatecall-target-fn": "delegatecall-proxy-fn",
    # liquidation -> collateral-liquidation-fn
    "liquidation-fn": "collateral-liquidation-fn",
    # reward / fee accrual / distribution / skim -> reward-fee-distribution-fn
    "distribution-fn": "reward-fee-distribution-fn",
    "reward-accrual-fn": "reward-fee-distribution-fn",
    "fee-skim-fn": "reward-fee-distribution-fn",
    # claim / reward-claim / settlement-redemption -> withdrawal-redemption-fn
    "claim-fn": "withdrawal-redemption-fn",
    "reward-claim-fn": "withdrawal-redemption-fn",
    "settlement-redemption-fn": "withdrawal-redemption-fn",
    # signature / crypto / merkle / hash verification -> signature-nonce-fn
    "signature-verify-fn": "signature-nonce-fn",
    "crypto-verify-fn": "signature-nonce-fn",
    "merkle-proof-fn": "signature-nonce-fn",
    "hash-commitment-fn": "signature-nonce-fn",
    # arithmetic / interest / rate / range / field / zk-constraint math
    # -> accounting-math-fn
    "field-arithmetic-fn": "accounting-math-fn",
    "interest-accrual-fn": "accounting-math-fn",
    "rate-model-fn": "accounting-math-fn",
    "range-check-fn": "accounting-math-fn",
    "zk-constraint-region-fn": "accounting-math-fn",
    # cross-chain message handling -> cross-chain-message-fn
    "cross-chain-message-handler-fn": "cross-chain-message-fn",
    # pause guard -> pausable-emergency-fn
    "pause-guard-fn": "pausable-emergency-fn",
    # iteration over an unbounded user set -> loop-batch-fn
    "loop-over-userset-fn": "loop-batch-fn",
    # external-call / callback hooks -> cross-contract-call
    "external-call-fn": "cross-contract-call",
    "callback-hook-fn": "cross-contract-call",
    # lifecycle / state-tree / serialization state-writes
    # -> state-machine-transition-fn
    "abci-lifecycle-fn": "state-machine-transition-fn",
    "merkle-store-write-fn": "state-machine-transition-fn",
    # cosmos / wasm / api / codec message + deserialization handlers
    # -> cosmos-msg-handler-fn (the emittable Go/cosmos message surface)
    "api-deserialization-fn": "cosmos-msg-handler-fn",
    "parser-decoder-fn": "cosmos-msg-handler-fn",
    "serialization-codec-fn": "cosmos-msg-handler-fn",
    "wasm-host-fn": "cosmos-msg-handler-fn",
    # RPC / gRPC / json-rpc / light-client query surfaces -> view-getter-fn
    # (the emittable read surface; bc-rpc-api-crash stays language-gated to
    # go/rust, so a solidity view-getter never inherits it).
    "grpc-query-service-fn": "view-getter-fn",
    "json-rpc-method-fn": "view-getter-fn",
    "light-client-query-fn": "view-getter-fn",
    "rpc-query-handler-fn": "view-getter-fn",
}

# Shape families the classifier can EMIT (the 20 ids classify_function_shape
# produces). _SHAPE_FAMILY values must all be members; the reconcile test
# asserts this so a corpus shape can only re-home onto a real emittable shape.
_EMITTABLE_SHAPE_FAMILIES = frozenset({
    "withdrawal-redemption-fn", "token-transfer-path",
    "reward-fee-distribution-fn", "collateral-liquidation-fn",
    "oracle-read-fn", "signature-nonce-fn", "upgrade-init-fn",
    "delegatecall-proxy-fn", "governance-voting-fn", "pausable-emergency-fn",
    "cross-chain-message-fn", "loop-batch-fn", "accounting-math-fn",
    "cosmos-msg-handler-fn", "state-machine-transition-fn",
    "deadline-time-dependent-fn", "access-controlled-setter",
    "cross-contract-call", "external-state-mutating-fn", "view-getter-fn",
})


def shape_family(shape_class: str) -> str:
    """Normalize a corpus shape-class to its canonical EMITTABLE family.

    Lower-cased, hyphen-normalized lookup in `_SHAPE_FAMILY`. An emittable class
    is a self-mapping key (normalizes to itself); a dead corpus synonym maps to
    its emittable twin; an unknown shape passes through as itself (so it matches
    only its own literal in an intersection, never widening to everything).
    Empty input -> "".
    """
    s = str(shape_class or "").strip().lower().replace("_", "-")
    if not s:
        return ""
    if s in _EMITTABLE_SHAPE_FAMILIES:
        return s
    return _SHAPE_FAMILY.get(s, s)


# --------------------------------------------------------------------------
# Language-alias reconciliation.
#
# The impact corpus authors `applies_to_languages` with a fixed vocabulary
# (solidity, go, rust, vyper, cairo, move, zk, c, cpp, circom, noir, leo, nim,
# java, ...). Callers, however, derive a target language from a file extension
# via the `_DEFENSE_SOURCE_EXTS` path documented in `classify_impact_target`,
# and that path emits `evm` for `.sol`/`.vy` - a token NO corpus playbook lists.
# Wired as documented, `language="evm"` would silently ZERO all 23 solidity + 14
# vyper playbooks (the language guard excludes a known-but-unlisted value),
# while `.rs`/`.go` survived. `_LANGUAGE_ALIAS` maps the ext-derived / shorthand
# tokens onto the corpus vocabulary so a real solidity/vyper/cairo/move/zk
# target attaches instead of being silently dropped.
#
# Language remains a pure EXCLUSION guard (see `_impact_filter_admits`): an
# EMPTY target language still admits every playbook; only a known, normalized
# language that a playbook does NOT list excludes that playbook.
_LANGUAGE_ALIAS: dict[str, str] = {
    # the _DEFENSE_SOURCE_EXTS collapse: .sol and .vy both map to "evm"
    "evm": "solidity",
    # solidity shorthands / ext stems
    "sol": "solidity",
    ".sol": "solidity",
    # vyper
    "vy": "vyper",
    ".vy": "vyper",
    # rust
    "rs": "rust",
    ".rs": "rust",
    # go
    "golang": "go",
    ".go": "go",
    # cairo / starknet
    "starknet": "cairo",
    ".cairo": "cairo",
    # move / aptos / sui
    "aptos": "move",
    "sui": "move",
    ".move": "move",
    # zk / circuit dialects fold to the corpus `zk` bucket; the corpus also
    # carries the explicit dialect tokens (circom/noir/leo) which pass through
    # unchanged via the self-mapping below.
    "zk-circuit": "zk",
    "zkcircuit": "zk",
    "zksnark": "zk",
    "circom": "circom",
    "noir": "noir",
    ".nr": "noir",
    "leo": "leo",
    ".leo": "leo",
    # c / c++
    ".c": "c",
    "c++": "cpp",
    ".cpp": "cpp",
    # nim
    "nim": "nim",
    ".nim": "nim",
}


def language_alias(language: str) -> str:
    """Normalize a caller-supplied / ext-derived language to the corpus token.

    Lower-cased, stripped lookup in `_LANGUAGE_ALIAS`; an unaliased token passes
    through unchanged (so a corpus-correct token like "solidity"/"rust"/"go" or
    an unknown one is preserved - normalization only rewrites known aliases).
    Empty input -> "" (which `_impact_filter_admits` treats as admit-all).
    """
    raw = str(language or "").strip().lower()
    if not raw:
        return ""
    return _LANGUAGE_ALIAS.get(raw, raw)


# Maps SCOPE/source signals to a contract_kind used by impact playbooks.
# First match wins; "" if none. The classifier emits FAMILY values directly
# (each family is also a self-mapping key in `_KIND_FAMILY`). The order is
# specificity-descending so a sharper concept (perp/oracle/proxy/crypto-signer/
# distributor/dex) wins over a generic one (vault/token) it would otherwise be
# swallowed by. Kept conservative + first-match: a plain token or vault must NOT
# be mis-routed into one of the new families.
_CONTRACT_KIND_RULES: list[tuple[str, str]] = [
    ("consensus",
     r"consensus|tendermint|cometbft|abci|baseapp|begin\s*block|end\s*block|finalize\s*block|finalize\s*commit|fork[\- ]?choice|block production"),
    # crypto-signer BEFORE bridge/zk so a keystore/MPC/TSS signer routes to its
    # own family rather than being read as a generic verifier or bridge signer.
    ("crypto-signer",
     r"keystore|\bhd[\- ]?wallet\b|mnemonic|seed\s*phrase|\bmpc\b|\btss\b|threshold\s*signature|frost|schnorr|ring\s*signature|secp256k1|ed25519|private\s*key|signing\s*key|key\s*derivation|\bkdf\b|ecdsa"),
    # proxy/upgrade BEFORE bridge (portal/dispute games are proxy-shaped) and
    # BEFORE vault so a proxy-admin is not swallowed by a generic vault match.
    # NOTE: the bare adjective "upgradeable" is boilerplate in nearly every
    # Immunefi SEVERITY.md/scope text, so it must NOT win on its own - an
    # ERC-4626 DeFi vault that merely says "upgradeable" is a vault, not a
    # proxy shell. Require a genuine proxy/UUPS/delegatecall-pattern signal
    # (an actual proxy noun, an upgradeable-PROXY phrase, an impl slot, etc.).
    ("proxy",
     r"\bproxy\b|upgradeable\s*proxy|upgradeableproxy|implementation\s*slot|erc1967|uups|delegatecall|proxy[\- ]?admin|dispute\s*game|anchor[\- ]?state[\- ]?registry|upgrade\s*handler"),
    ("bridge",
     r"bridge|cross[\- ]?chain|lzreceive|ccipreceive|relayer|message\s*id|portal|\bism\b|\bibc\b|xcm"),
    # perp BEFORE lending/amm: a perpetuals/margin/funding venue is its own
    # family even though it shares liquidation + swap vocabulary.
    ("perp",
     r"\bperp\b|\bperps\b|perpetual|funding\s*rate|margin\s*account|isolated\s*margin|cross\s*margin|open\s*interest"),
    # randomness-beacon BEFORE oracle: a VRF/RANDAO/seed beacon is its OWN
    # family, not a price oracle. Kept distinct so a real beacon reaches
    # crypto-key-recovery-leak (its seed/signing-key concern) while a plain
    # price-feed oracle does NOT inherit it.
    ("randomness-beacon",
     r"randomness\s*beacon|\bvrf\b|\brandao\b|\bdrand\b|beacon\s*randomness|verifiable\s*random"),
    # oracle BEFORE lending/amm/vault: a price/feed adapter is its own family.
    ("oracle",
     r"\boracle\b|price\s*feed|pricefeed|latestrounddata|latestanswer|chainlink|\btwap\b|\bvwap\b|aggregatorv3"),
    ("amm",
     r"\bamm\b|swap|liquidity pool|x\*y=k|uniswap|curve|balancer|constant product"),
    # dex AFTER amm (constant-product pools route to amm first); an orderbook /
    # matching engine / marketplace / router routes to dex.
    ("dex",
     r"order\s*book|orderbook|matching\s*engine|\bdex\b|marketplace|nft\s*market|\brouter\b|fill\s*order|limit\s*order"),
    ("lending",
     r"lending|borrow|collateral|liquidat|health factor|aave|compound|morpho|cdp\b|stability\s*pool"),
    # distributor BEFORE vault/staking: reward/fee/emission/gauge/merkle payout.
    ("distributor",
     r"distributor|merkle\s*claim|merkleclaim|\bgauge\b|emission|fee\s*collector|feecollector|paymaster|gas\s*service|reward\s*distribut"),
    ("vault",
     r"erc[\- ]?4626|\bvault\b|converttoshares|totalassets|previewdeposit|previewwithdraw"),
    ("governance",
     r"govern|proposal|voting\s*power|timelock|quorum|castvote"),
    ("staking",
     r"\bstak|validator|delegat|operator|\bcluster\b|slashing|restak"),
    ("zk-circuit",
     r"verifier|nullifier|groth16|plonk|attestation|\bproof\b|circuit"),
    ("cosmos-module",
     r"sdk\.context|sdk\.msg|msgserver|keeper|\bkv\s*store\b|cosmos"),
    ("token",
     r"erc[\- ]?20|erc[\- ]?721|\bmint\b|\bburn\b|totalsupply|balanceof"),
]


def classify_impact_target(
    function_name: str = "",
    function_signature: str = "",
    *,
    language: str = "",
    contract_kind: str = "",
    scope_text: str = "",
    library: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve (shape_classes, language, contract_kind) for impact attach.

    This is the NET-NEW classifier the economic renderer lacks: it carries
    `language` and `contract_kind` so a per-impact playbook can gate on the
    lane language / target kind in addition to function shape.

    language: caller may pass it explicitly ("solidity"/"rust"/"go"/"zk"/...);
    when blank it stays "" - the renderer itself does NOT scan files (kept
    side-effect free). The dispatch caller derives it from the source tree via
    the existing _DEFENSE_SOURCE_EXTS path and passes it in.
    contract_kind: caller may pass it; when blank, infer from scope_text +
    signature + name via _CONTRACT_KIND_RULES (first match wins, "" if none).
    """
    shape_classes = classify_function_shape(
        function_name, function_signature, library=library
    )
    kind = (contract_kind or "").strip().lower()
    if not kind:
        blob = f"{scope_text}\n{function_signature}\n{function_name}".lower()
        for k, pat in _CONTRACT_KIND_RULES:
            if re.search(pat, blob):
                kind = k
                break
    return {
        "shape_classes": shape_classes,
        "language": (language or "").strip().lower(),
        "contract_kind": kind,
    }


def _impact_filter_admits(
    applies: Any,
    target_value: str,
) -> bool:
    """An OPTIONAL list filter on a playbook.

    Returns True (admits) when: the filter is absent/empty (never excludes), OR
    the target value is "" (unknown -> do not filter), OR the target value is a
    member of the filter list. Returns False only when the filter is a non-empty
    list, the target value is known, and the value is NOT in the list.
    """
    if not isinstance(applies, list) or not applies:
        return True
    if not target_value:
        return True
    wanted = {str(v).strip().lower() for v in applies if str(v).strip()}
    return target_value.strip().lower() in wanted


# Severity tier words, ranked HIGHEST -> lowest. When a playbook stores its
# severity as a mapping of conditions -> tiers, the hint reports the CEILING
# (worst plausible grade) so the hunter is not anchored on a benign branch.
_SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
}
_SEVERITY_WORD_RE = re.compile(
    r"\b(critical|high|medium|low|informational|info)\b", re.IGNORECASE
)

# All field names the 32-playbook corpus uses to carry severity. The corpus was
# merged from heterogeneous source files, so the SAME concept lives under seven
# different keys. Reading only `severity_hint`/`severity_source` rendered an
# EMPTY hint for 26 of 32 playbooks (measured). First present (in this order)
# wins; values may be a scalar string, a list, or a nested dict.
_SEVERITY_FIELD_NAMES: tuple[str, ...] = (
    "severity_hint",
    "severity_ceiling",
    "typical_severity",
    "max_severity",
    "impact_severity",
    "sev",
    "severity",
    "severity_source",
    "severity_mapping",
    "severity_rows_verbatim",
    "severity_rubric_anchors",
    "severity_by_program",
)


def _severity_words_in(value: Any) -> list[str]:
    """Recursively collect every severity tier word in a scalar/list/dict.

    Dict values typically hold the tier (e.g. {'condition': 'critical'} or
    {'condition': {'verdict': 'high', ...}}); list/string values hold rubric
    prose. We scan the stringified leaves so any storage shape is covered.
    """
    out: list[str] = []
    if isinstance(value, dict):
        for v in value.values():
            out.extend(_severity_words_in(v))
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            out.extend(_severity_words_in(v))
    else:
        for m in _SEVERITY_WORD_RE.finditer(str(value or "")):
            out.append(m.group(1).lower())
    return out


def _impact_severity_hint(playbook: dict[str, Any]) -> str:
    """Best-effort severity hint from the playbook.

    Reads ALL field-name variants the corpus uses (the same concept is stored
    under seven different keys across the 32 merged playbooks). Returns the
    first field that carries a recognizable severity tier; when that field is a
    mapping/list of multiple tiers it reports the CEILING (the worst grade), so
    the hint never anchors the hunter on a benign branch. An explicit string
    `severity_hint`/`severity_ceiling`/`typical_severity` is honored verbatim
    when it is itself a clean tier word.
    """
    for field in _SEVERITY_FIELD_NAMES:
        if field not in playbook:
            continue
        value = playbook.get(field)
        words = _severity_words_in(value)
        if not words:
            continue
        ceiling = max(words, key=lambda w: _SEVERITY_RANK.get(w, 0))
        if ceiling == "info":
            ceiling = "informational"
        return ceiling.capitalize()
    return ""


def _impact_incident_anchor(playbook: dict[str, Any]) -> str:
    """Best-effort incident anchor.

    Prefers a scalar `incident_anchor`; falls back to the first entry of the
    real corpus's `incident_anchors` list.
    """
    scalar = str(playbook.get("incident_anchor") or "").strip()
    if scalar:
        return scalar
    anchors = playbook.get("incident_anchors")
    if isinstance(anchors, list):
        for item in anchors:
            text = str(item or "").strip()
            if text:
                return text
    return ""


def _impact_rubric_row_hint(playbook: dict[str, Any]) -> str:
    """Reconciliation hint to Check #31: which SEVERITY.md row family this
    impact usually grounds in. Prefers explicit `rubric_row_hint`, else the
    playbook title (a human phrase eyeballable against a real SEVERITY.md row).
    """
    explicit = str(playbook.get("rubric_row_hint") or "").strip()
    if explicit:
        return explicit
    return str(playbook.get("title") or "").strip()


_VALUE_MOVING_VERB_RE = re.compile(
    r"(withdraw|redeem|claim|transfer|send|deposit|mint|burn|liquidat|"
    r"stake|unstake|payout|collect|sweep|rescue|settle|distribut|refund|"
    r"borrow|repay|swap|flashloan|migrat|harvest|skim|donate)",
    re.IGNORECASE,
)
_VALUE_PARAM_RE = re.compile(
    r"\b(amount|amounts|value|shares|assets|wad|qty|sum|principal)\b", re.IGNORECASE
)


def _function_is_value_moving_ish(function_name: str, function_signature: str) -> bool:
    """Heuristic: does this function plausibly move value (so a contract-kind-only
    impact playbook is worth attaching when the shape classifier produced NOTHING)?

    True when the name carries a value-moving verb, OR the signature is `payable`,
    OR it takes an amount/value/shares-style parameter. Used ONLY for the kind-only
    rescue arm, and ONLY when the shape classifier returned no shape at all - so a
    genuinely non-value function (e.g. a view/config setter the classifier also
    missed) does not get sprayed with fund-theft questions.
    """
    # Anchor the verb at the START of the name (after any leading underscore):
    # value-movers LEAD with the verb (withdraw/liquidate/mint), while a getter
    # like `getBurnRate` merely CONTAINS "burn" mid-word and must not match.
    name = re.sub(r"^[^A-Za-z]+", "", function_name or "")
    sig = function_signature or ""
    # Ownership/role/admin transfer family (transferOwnership / transferAdmin /
    # transferRole / accept*) LEADS with the value-moving verb "transfer" but
    # hands over a PRIVILEGE, not a VALUE token - it must not be treated as
    # value-moving (else the kind_rescue arm sprays direct-theft-funds onto
    # transferOwnership). It is only value-moving if it also carries an
    # amount-ish param (uint/uint256/amount/value/shares/assets).
    if (_OWNERSHIP_ROLE_ADMIN_NAME_RE.search(name)
            and not _AMOUNT_ISH_PARAM_RE.search(sig)):
        return False
    if _VALUE_MOVING_VERB_RE.match(name):
        return True
    if re.search(r"\bpayable\b", sig, re.IGNORECASE):
        return True
    return bool(_VALUE_PARAM_RE.search(sig))


# --------------------------------------------------------------------------
# IMPACT-FIRST availability / infrastructure kind-attach (Blockchain/DLT gap).
#
# THE GAP (SEI 2026-07-04): a Blockchain/DLT program's DOMINANT impact surface
# is AVAILABILITY/CONSENSUS (chain halt / chain split / RPC-node crash / block
# delay / consensus liveness), not fund theft. Those attack surfaces live on
# functions whose IMPACT is triggered by their POSITION on the block-production /
# node / p2p / mempool / rpc path (ABCI++ Prepare/Process/FinalizeBlock,
# Begin/EndBlocker, consensus vote/timeout, CheckTx, evmrpc/gRPC handlers, p2p
# Receive, OCC/executor) - NOT by a value-moving verb. The classifier gives many
# of these a benign shape (`external-state-mutating-fn`) and NO value-moving verb,
# so the shape arm misses them AND the DeFi-oriented `kind_rescue` arm (which
# requires `not classes AND value_moving_ish`) suppresses them. Result: consensus
# units were handed FUND-THEFT methodology (direct-theft/access-control) or a
# generic fallback, and the chain-halt/chain-split/consensus-transient/
# node-resource playbooks attached to ZERO consensus units - the impact-first-
# not-symbol-first miss.
#
# GENERIC, LANGUAGE-AGNOSTIC FIX: attach an INFRASTRUCTURE playbook (one that
# lists an infra contract-kind family in its OWN applies_to_contract_kinds -
# derived from the library, never hardcoded per-impact) via the kind arm
# regardless of shape / value-moving, WHEN the target's contract-kind family is
# that same infra family. The playbook's language filter still excludes (a go/rust
# bc-* playbook never attaches to a solidity target), and a DeFi playbook (which
# does NOT list an infra kind) / a DeFi target (kind vault/lending/...) is never
# touched - so the SSV custody-spray and solidity-view regressions stay green.
#
# The infra families are exactly the two node-level kind families the
# `_KIND_FAMILY` table already collapses every consensus/abci/p2p/mempool/rpc/
# vm-runtime/state-tree/cosmos-keeper kind into (see the "consensus family" and
# "cosmos-module family" blocks above). Impact-first, library-driven, generic.
# --------------------------------------------------------------------------
_INFRA_KIND_FAMILIES: frozenset[str] = frozenset({"consensus", "cosmos-module"})

# The infra kind-attach arm fires ONLY for NODE-LANGUAGE targets. Availability /
# consensus impact (chain halt / split / RPC crash / consensus liveness / block
# stuffing) is a node-implementation concern - it lives in the go/rust/c/cpp/nim/
# java daemon that runs consensus, NOT in an on-chain EVM/Move contract (a
# solidity/vyper contract cannot halt the chain by itself). Excluding the EVM
# contract languages keeps a PURE SMART-CONTRACT workspace (all solidity/vyper)
# completely unaffected by this arm, and stops a contract file that merely sits
# in a chain repo (whose SEVERITY.md mentions "block production" -> the scope-
# derived kind becomes `consensus` for every unit) from inheriting availability
# methodology it cannot realize. The playbook's own language filter still applies
# on top (a go-only bc-* never reaches a rust target and vice-versa).
_INFRA_ATTACH_LANGUAGES: frozenset[str] = frozenset(
    {"go", "rust", "c", "cpp", "nim", "java", "zig", "ocaml"}
)


def _impact_is_infrastructure_playbook(applies_kind_families: set[str]) -> bool:
    """True when a playbook targets a node-level / consensus INFRASTRUCTURE kind
    family (derived from the playbook's OWN applies_to_contract_kinds families).

    Used to decide whether the kind arm may attach an AVAILABILITY/CONSENSUS
    impact playbook to an infra function irrespective of its shape or a value-
    moving verb (availability impact is triggered by the function's position on
    the block-production / node / rpc / p2p path, not by moving value). A DeFi
    playbook does not list an infra kind family, so it never qualifies."""
    return bool(applies_kind_families & _INFRA_KIND_FAMILIES)


def _impact_is_availability_primary(impact_id: str) -> bool:
    """True for the AVAILABILITY-PRIMARY Blockchain/DLT impacts (chain halt /
    chain split / consensus-transient / node-resource-exhaustion / RPC crash /
    block-stuffing / hardfork-freeze) - the DOMINANT impact surface a
    Blockchain/DLT SEVERITY.md prices (>=1/3-validator halt, chain split, RPC
    crash, block-delay, block stuffing).

    The impact-hunting-methodology corpus names these under a deliberate
    Blockchain/DLT availability NAMESPACE: `chain-*`, `bc-*`, and
    `griefing-dos-blockstuffing`. This is used ONLY to ORDER playbook iteration
    on an infra target so the per-function question cap does not starve the
    availability surface in favour of an incidentally-consensus-listed fund-theft
    playbook (e.g. `unauthorized-mint` / `signature-replay-forgery`, which list
    `consensus` but are NOT availability-primary). It NEVER changes WHICH
    playbooks attach (the attach predicate is unchanged) - only their order."""
    iid = (impact_id or "").strip().lower()
    return (
        iid.startswith("chain-")
        or iid.startswith("bc-")
        or iid == "griefing-dos-blockstuffing"
    )


def _bind_question_to_fn(text: str, function_name: str) -> str:
    """Anchor a generic per-impact question to the specific function under test.

    The 32-playbook corpus stores impact questions as generic prose (no function
    binding), so without this the SAME text is emitted for every function in a
    contract - indistinguishable, and the hunter is not pointed at the unit. We
    (a) honor an explicit `{fn}`/`{function}` placeholder when a playbook uses one,
    else (b) prefix `On \\`<fn>\\`: ` so the emitted question names the function.
    Returns text unchanged when no function name is available.
    """
    fn = (function_name or "").strip()
    if not fn:
        return text
    if "{fn}" in text or "{function}" in text:
        try:
            return text.format(fn=fn, function=fn)
        except (KeyError, IndexError, ValueError):
            return text
    return f"On `{fn}`: {text}"


def render_impact_questions(
    function_name: str = "",
    function_signature: str = "",
    *,
    shape_hash: str = "",
    file_path: str = "",
    context_pack_id: str = "",
    detector_slug: str = "",
    language: str = "",
    contract_kind: str = "",
    scope_text: str = "",
    library: dict[str, Any] | None = None,
    playbooks: list[dict[str, Any]] | None = None,
    max_questions: int = 0,
) -> list[dict[str, Any]]:
    """Render per-impact hunting-methodology questions for a function.

    Mirrors `render_economic_primitive_questions` but with a NET-NEW attach
    predicate: a playbook attaches when its `applies_to_shape_classes`
    intersects the target's shape classes (REQUIRED, same as economic) AND its
    OPTIONAL `applies_to_languages` / `applies_to_contract_kinds` filters admit
    the target (absent/empty optional filters never exclude; an unknown target
    language/kind never excludes). This lets the EVM/DeFi playbooks attach on
    shape alone while the Go/cosmos consensus playbooks additionally gate on
    `contract_kinds: [consensus, ...]`.

    Emits `auditooor.hacker_question.v1` rows tagged
    `question_source: impact-methodology`, carrying the originating `impact_id`,
    its severity hint, reasoning axis, per-impact proof obligation +
    kill condition, incident anchor, and rubric-row hint (the Check #31
    reconciliation hook).
    """
    books = playbooks if playbooks is not None else load_impact_playbooks()
    if not books:
        return []
    lib = library if library is not None else load_question_library()
    target = classify_impact_target(
        function_name,
        function_signature,
        language=language,
        contract_kind=contract_kind,
        scope_text=scope_text,
        library=lib,
    )
    # Normalize the emitted shape classes to their canonical FAMILY so a corpus
    # playbook authored against a FINE/synonym shape (e.g. `liquidation-fn`,
    # `initializer-fn`, `signature-verify-fn`) matches a family-equivalent shape
    # the classifier really emits. Without this, 37 corpus shape-classes were
    # never emittable, so their shape attach arm was dead. See `_SHAPE_FAMILY`.
    classes = {shape_family(c) for c in target["shape_classes"]}
    # Language is normalized through the alias table so an ext-derived `evm`
    # (the _DEFENSE_SOURCE_EXTS collapse) or a shorthand (`sol`/`rs`/`golang`)
    # attaches instead of silently zeroing every solidity/vyper playbook.
    tgt_language = language_alias(target["language"])
    tgt_kind = (target["contract_kind"] or "").strip().lower()
    # Normalize the target kind to its canonical FAMILY so a coarse classifier
    # value (e.g. `lending`) matches a corpus playbook authored against a FINE
    # kind (e.g. `lending-market` / `cdp-vault` / `perp-margin`). Without this
    # reconciliation 8 impacts whose every fine kind sits outside the coarse
    # vocabulary were kind-unreachable. See `_KIND_FAMILY`.
    tgt_family = kind_family(tgt_kind)
    # UNION attach: a playbook attaches when its shape-classes intersect the
    # target shape OR the (known) target contract-kind FAMILY intersects the
    # playbook's applies_to_contract_kinds families. Language stays an EXCLUSION
    # guard. Do NOT abort on empty shape - a value-moving fn the shape
    # classifier missed (e.g. a plain `deposit`) must still attach via its
    # contract-kind (the DeFi half; a shape-only gate required the classifier to
    # tag every verb, which it does not, so DeFi playbooks silently never
    # attached).
    # AVAILABILITY-FIRST iteration order on an INFRASTRUCTURE target: a per-
    # function question cap (max_questions) truncates to the first-emitted rows,
    # so on a Blockchain/DLT target the availability-primary playbooks (chain-*/
    # bc-*/griefing) must be VISITED FIRST or an incidentally-consensus-listed
    # fund-theft playbook (unauthorized-mint / signature-replay-forgery) fills the
    # cap and the DOMINANT availability surface never reaches the hunter. This is
    # a STABLE partition applied ONLY when the target is a NODE-LANGUAGE infra
    # target (same guard as the infra attach arm): availability-primary playbooks
    # keep their relative order and move ahead of the rest, which also keep their
    # relative order. A non-infra (DeFi) target - and every EVM/solidity target,
    # so a pure Smart-Contract ws is untouched - keeps the exact original `books`
    # order (byte-identical), and the attach predicate below is UNCHANGED - this
    # reorders visitation, it does not add or drop any playbook.
    _iter_books = books
    _infra_target = (
        tgt_language in _INFRA_ATTACH_LANGUAGES
        and tgt_family in _INFRA_KIND_FAMILIES
    )
    if _infra_target:
        _iter_books = sorted(
            books,
            key=lambda b: 0 if _impact_is_availability_primary(
                str(b.get("impact_id") or "")
            ) else 1,
        )
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for playbook in _iter_books:
        applies_shape = playbook.get("applies_to_shape_classes") or []
        if not isinstance(applies_shape, list):
            continue
        if not _impact_filter_admits(
            playbook.get("applies_to_languages"), tgt_language
        ):
            continue
        shape_match = bool(
            classes.intersection(shape_family(c) for c in applies_shape if str(c).strip())
        )
        applies_kind_families = {
            kind_family(k)
            for k in (playbook.get("applies_to_contract_kinds") or [])
            if str(k).strip()
        }
        kind_match = bool(tgt_family) and tgt_family in applies_kind_families
        # Attach precedence (specialization fix, corrected 2026-07-04):
        #  - shape_match: the function's OWN shape is relevant -> attach.
        #  - kind-only (UNION) RESCUE: attach a contract-kind-matched playbook when
        #    the classifier produced NO SHARP shape - i.e. only the generic /
        #    structural fallbacks (_GENERIC_ONLY_SHAPES: external-state-mutating-fn
        #    / view-getter-fn / cross-contract-call) - AND the function looks value-
        #    moving. The gate is `not (classes - _GENERIC_ONLY_SHAPES)`, NOT `not
        #    classes`: the earlier `not classes` form disabled the whole kind arm
        #    the instant the classifier assigned ANY (even generic) shape, so a
        #    value-mover the classifier tagged only generically - e.g. `deposit(
        #    uint256,address)` -> {cross-contract-call, external-state-mutating-fn}
        #    - lost EVERY kind-listed impact (measured 93 dropped (impact,kind)
        #    pairs incl. direct-theft-funds/insolvency/permanent-freeze across
        #    vault/lending/amm/bridge/gov/cosmos - a systematic coverage loss). A
        #    function the classifier gave a SHARP shape (token-transfer-path /
        #    access-controlled-setter / withdrawal-redemption-fn / ...) is NOT
        #    rescued - its real shape governs (so registerValidator, shaped
        #    access-controlled-setter, is NOT sprayed with custody/theft), and the
        #    value-moving gate keeps pure views/no-ops clean.
        #    RESIDUAL (2026-07-04): a fn whose SHARP shape is value-conducting (funds
        #    flow through it) but is NOT in a kind-listed impact's own shape-list was
        #    still dropped - e.g. a bridge `relayMessage` (cross-chain-message-fn, no
        #    value verb) did not attach direct-theft-funds/bridge-cross-chain-drain,
        #    a lending `borrow` (collateral-liquidation-fn) dropped its theft/freeze
        #    impacts. Fix: a 2nd rescue arm fires when the fn's sharp shapes are ALL
        #    value-CONDUCTING (the shape itself is the value signal, so value_moving_ish
        #    is not additionally required). Admin/config/ownership/upgrade/view shapes
        #    are NOT value-conducting, so anti-spray holds.
        _sharp_shapes = classes - _GENERIC_ONLY_SHAPES
        kind_rescue = kind_match and (
            # (i) generic-only shape -> needs an explicit value SIGNAL (verb/payable/
            #     amount) to tell a value-mover (deposit) from a no-op/view.
            (not _sharp_shapes
             and _function_is_value_moving_ish(function_name, function_signature))
            # (ii) value-conducting sharp shape(s) only -> the shape establishes
            #     value-conduction (bridge relayMessage / lending borrow / vault
            #     withdraw). A mixed sharp set including an admin/upgrade/oracle shape
            #     (access-controlled-setter / upgrade-init-fn / oracle-read-fn / ...)
            #     or the classifier-imprecise token-transfer-path (matches
            #     transferOwnership) is NOT a subset, so it does not fire.
            or (bool(_sharp_shapes)
                and _sharp_shapes <= _VALUE_CONDUCTING_SHARP_SHAPES)
        )
        #  - INFRA-KIND (availability-first) attach: for an AVAILABILITY-PRIMARY
        #    Blockchain/DLT playbook (chain-*/bc-*/griefing - the halt/split/RPC-
        #    crash/consensus-transient/node-resource/block-delay surface) that
        #    lists an infra contract-kind family, attach when the TARGET's kind is
        #    that infra family, REGARDLESS of shape or a value-moving verb. An
        #    availability impact is triggered by the function's POSITION on the
        #    block-production / node / p2p / mempool / rpc path, not by moving
        #    value - so gating it on `value_moving_ish` (the DeFi rescue gate)
        #    wrongly suppressed it on EndBlocker/BeginBlock/CheckTx/proposal/
        #    p2p-Receive units that carry a benign `external-state-mutating-fn`
        #    shape. GATED to availability-primary impacts (NOT every playbook that
        #    merely lists `cosmos-module`, e.g. direct-theft-funds / access-control-
        #    bypass, which are fund-theft, not availability) so a solidity/cosmos
        #    DeFi target (kind lending/vault/cosmos-module) never inherits fund-
        #    theft via this arm - that stays governed by shape / value-moving
        #    rescue. Language still excludes (a go/rust bc-* playbook never reaches
        #    a solidity target). Impact-first, library-driven; keeps the SSV
        #    custody-spray + solidity-view regressions green.
        infra_kind_attach = (
            kind_match
            and tgt_language in _INFRA_ATTACH_LANGUAGES
            and tgt_family in _INFRA_KIND_FAMILIES
            and _impact_is_infrastructure_playbook(applies_kind_families)
            and _impact_is_availability_primary(str(playbook.get("impact_id") or ""))
        )
        if not (shape_match or kind_rescue or infra_kind_attach):
            continue
        impact_id = str(playbook.get("impact_id") or "").strip()
        severity_hint = _impact_severity_hint(playbook)
        incident = _impact_incident_anchor(playbook)
        rubric_row_hint = _impact_rubric_row_hint(playbook)
        # BREADTH-FIRST availability diversity: on an infra target the per-fn
        # question cap (max_questions) is small (often 3), and one playbook holds
        # 8-9 questions - so draining a single availability playbook (e.g.
        # bc-consensus-transient-failure) would fill the whole cap and the hunter
        # would never SEE the distinct chain-halt / chain-split / rpc-crash /
        # node-resource frames. When a cap is in force on an infra target, emit at
        # most ONE question per availability-primary playbook so the first N rows
        # span N DISTINCT availability impacts (the impact-first diversity the
        # Blockchain/DLT SEVERITY.md prices). Non-infra targets and the uncapped
        # path are byte-identical (this cap is 0 = unlimited there).
        _per_pb_cap = (
            1
            if (_infra_target and max_questions
                and _impact_is_availability_primary(impact_id))
            else 0
        )
        _emitted_this_pb = 0
        for entry in playbook.get("hacker_questions", []) or []:
            if not isinstance(entry, dict):
                continue
            if _per_pb_cap and _emitted_this_pb >= _per_pb_cap:
                break
            raw_text = str(entry.get("q") or "").strip()
            if not raw_text:
                continue
            # Bind the generic per-impact question to THIS function so the emitted
            # text is function-specialized (not identical corpus prose across every
            # unit) and the hunter is pointed at the unit under test.
            text = _bind_question_to_fn(raw_text, function_name)
            if text in seen:
                continue
            seen.add(text)
            entry_proof = str(entry.get("proof_obligation") or "").strip()
            entry_kill = str(entry.get("kill_condition") or "").strip()
            rationale = str(entry.get("why") or "").strip()
            row = {
                "schema": HACKER_QUESTION_SCHEMA,
                "question": text,
                "question_source": "impact-methodology",
                "impact_id": impact_id,
                "impact_severity_hint": severity_hint,
                "reasoning_axis": str(entry.get("axis") or "impact"),
                "rationale": rationale,
                "function_shape": shape_hash,
                "proof_gate": "source_confirmed",
                "claim_boundary": claim_boundary(""),
                "proof_obligation": entry_proof
                or impact_question_proof_obligation(impact_id),
                "kill_condition": entry_kill
                or impact_question_kill_condition(impact_id),
                "incident_anchor": incident,
                "rubric_row_hint": rubric_row_hint,
                "target_file": file_path,
                "mcp_context_pack_id": context_pack_id,
            }
            if detector_slug:
                row["detector_slug"] = detector_slug
            out.append(row)
            _emitted_this_pb += 1
            if max_questions and len(out) >= max_questions:
                return out
    return out


def render_library_questions(
    function_name: str = "",
    function_signature: str = "",
    *,
    shape_hash: str = "",
    file_path: str = "",
    context_pack_id: str = "",
    detector_slug: str = "",
    library: dict[str, Any] | None = None,
    max_questions: int = 0,
) -> list[dict[str, Any]]:
    """Render curated-library questions for a function's shape class(es).

    Emits `auditooor.hacker_question.v1` rows whose `question` text comes from
    the hand-authored reasoning library, tagged with `question_source:
    curated-library`, the originating `shape_class`, and the reasoning `axis`.
    """
    lib = library if library is not None else load_question_library()
    if not lib:
        return []
    classes = classify_function_shape(function_name, function_signature, library=lib)
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for class_id in classes:
        shape_class = lib.get(class_id) or {}
        for entry in shape_class.get("questions", []) or []:
            if not isinstance(entry, dict):
                continue
            text = str(entry.get("q") or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            row = {
                "schema": HACKER_QUESTION_SCHEMA,
                "question": text,
                "question_source": "curated-library",
                "shape_class": class_id,
                "reasoning_axis": str(entry.get("axis") or ""),
                "rationale": str(entry.get("why") or ""),
                "function_shape": shape_hash,
                "proof_gate": "source_confirmed",
                "claim_boundary": claim_boundary(""),
                "proof_obligation": shape_question_proof_obligation(
                    class_id,
                    str(entry.get("axis") or ""),
                ),
                "kill_condition": shape_question_kill_condition(
                    class_id,
                    str(entry.get("axis") or ""),
                ),
                "target_file": file_path,
                "mcp_context_pack_id": context_pack_id,
            }
            if detector_slug:
                row["detector_slug"] = detector_slug
            out.append(row)
            if max_questions and len(out) >= max_questions:
                return out
    return out


def render_hacker_questions(
    *,
    ranked: list[dict[str, Any]],
    function_name: str = "",
    function_signature: str = "",
    shape_hash: str = "",
    shape_hash_fine: str = "",
    file_path: str = "",
    context_pack_id: str = "",
    detector_slug: str = "",
    include_library: bool = True,
    include_economic: bool = True,
    include_impact: bool = True,
    max_library_questions: int = 0,
    max_economic_questions: int = 0,
    max_impact_questions: int = 0,
    language: str = "",
    contract_kind: str = "",
    scope_text: str = "",
) -> list[dict[str, Any]]:
    questions: list[dict[str, Any]] = []
    for row in ranked:
        attack_class = str(row.get("attack_class") or row.get("class_id") or "").strip()
        if not attack_class:
            continue
        evidence = _first_evidence(row)
        question = {
            "schema": HACKER_QUESTION_SCHEMA,
            "question": attack_question_text(attack_class, function_name, detector_slug),
            "question_source": "corpus-derived",
            "attack_class": attack_class,
            "function_shape": shape_hash,
            "function_shape_fine": shape_hash_fine,
            "target_file": file_path,
            "source_record_id": _evidence_id(evidence),
            "record_tier": str(evidence.get("record_tier") or evidence.get("tier") or ""),
            "record_quality_score": evidence.get("record_quality_score", ""),
            "proof_gate": proof_gate(attack_class),
            "claim_boundary": claim_boundary(attack_class),
            "proof_obligation": proof_obligation(attack_class),
            "kill_condition": kill_condition(attack_class),
            "mcp_context_pack_id": context_pack_id,
        }
        if detector_slug:
            question["detector_slug"] = detector_slug
        analogues = _cross_language_analogues(evidence)
        if analogues:
            question["cross_language_analogues"] = analogues
        canonical_evidence = _canonical_hackerman_evidence(evidence)
        if canonical_evidence:
            question["canonical_hackerman_evidence"] = canonical_evidence
        questions.append(question)

    # W5-F1: intersect the corpus-derived questions with the curated
    # shape-class reasoning library.  The library carries the actual probing
    # questions a top auditor asks; corpus rows carry the evidence anchors.
    if include_library:
        questions.extend(
            render_library_questions(
                function_name,
                function_signature,
                shape_hash=shape_hash,
                file_path=file_path,
                context_pack_id=context_pack_id,
                detector_slug=detector_slug,
                max_questions=max_library_questions,
            )
        )

    # W5-F3: attach economic-attack-primitive questions when the function's
    # shape matches an economic primitive's applicable shape classes.  This
    # makes DeFi-shaped functions (AMM / lending / vault / oracle / governance)
    # receive profit-motivated economic questions, not just structural ones.
    if include_economic:
        questions.extend(
            render_economic_primitive_questions(
                function_name,
                function_signature,
                shape_hash=shape_hash,
                file_path=file_path,
                context_pack_id=context_pack_id,
                detector_slug=detector_slug,
                max_questions=max_economic_questions,
            )
        )

    # Per-impact hunting methodology: attach the playbook(s) for the impact
    # class this function's shape + language + contract-kind maps to. Hands the
    # hunter the "how exploits in this impact class were actually found" axis
    # (chain-halt for a Go/cosmos consensus fn, fund-theft / inflation for a
    # DeFi vault fn). Additive: every existing caller keeps working, the new
    # rows are tagged question_source: impact-methodology and easy to filter.
    if include_impact:
        questions.extend(
            render_impact_questions(
                function_name,
                function_signature,
                shape_hash=shape_hash,
                file_path=file_path,
                context_pack_id=context_pack_id,
                detector_slug=detector_slug,
                language=language,
                contract_kind=contract_kind,
                scope_text=scope_text,
                max_questions=max_impact_questions,
            )
        )
    return questions
