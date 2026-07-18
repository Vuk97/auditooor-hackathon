# r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY registered in .auditooor/agent_pathspec.json (tools/agent-pathspec-register.py)
"""Per-function / per-contract target-pattern derivation library (LIFT-28).

LIFT-28 (2026-05-26): operator-flagged gap. Chain template match, hacker
questions, and brain prime all currently work at WORKSPACE level. Real
audit work happens at CONTRACT + FUNCTION level. This library carries
the deterministic auto-derivation logic that:

1. Maps a hacker-question record's `grep_patterns` (e.g. `executeRaw`,
   `isArbitraryCall`) onto `target_function_patterns` (regex matching
   the function names a worker would grep for in code), and onto
   `target_contract_patterns` (regex matching the contract names the
   patterns are typically defined in).

2. Maps a global-chain-template's `member_invariant_ids` /
   `member_categories` onto `applicable_contract_kinds`
   (bridge / lending / dex / rollup / oracle / governance / ...) and
   `applicable_function_role_patterns` (dispatcher / proposer / settler
   / minter / burner / liquidator / ...).

3. Provides per-target filtering helpers used by `vault_hacker_questions`,
   `vault_global_chain_template_match`, `vault_chained_attack_plan_context`,
   and the new `vault_per_function_hunter_brief` callable.

Backward-compat: this library only produces ADDITIVE fields. Existing
JSONL records that lack the new fields continue to behave at workspace-
level granularity; callable kwargs default to existing behavior when the
new contract/function arguments are absent.

Pure: no I/O at module level, no network, no filesystem writes.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# --- Scope specificity vocabulary ------------------------------------------------
SCOPE_WORKSPACE = "workspace"
SCOPE_CONTRACT = "contract"
SCOPE_FUNCTION = "function"
SCOPE_LINE = "line"
SCOPE_VALUES = (SCOPE_WORKSPACE, SCOPE_CONTRACT, SCOPE_FUNCTION, SCOPE_LINE)

# --- Contract-kind taxonomy ------------------------------------------------------
# Auto-derived from member_invariant_ids prefixes and member_categories names.
# Order matters: more specific kinds first so the FIRST match wins.
CONTRACT_KIND_BY_INVARIANT_PREFIX: Tuple[Tuple[str, str], ...] = (
    ("INV-BRIDGE-", "bridge"),
    ("INV-FRE-",   "oracle"),       # freshness family commonly an oracle/feed
    ("INV-CUS-",   "custody"),
    ("INV-RP-",    "rollup-prover"),
    ("INV-DEX-",   "dex"),
    ("INV-LEND-",  "lending"),
    ("INV-LIQ-",   "liquidation"),
    ("INV-GOV-",   "governance"),
    ("INV-VAULT-", "vault"),
    ("INV-AMM-",   "dex"),
    ("INV-AUC-",   "auction"),
    ("INV-MINT-",  "minter"),
    ("INV-BURN-",  "burner"),
    ("INV-STAK-",  "staking"),
)

CONTRACT_KIND_BY_CATEGORY: Dict[str, str] = {
    "bridge": "bridge",
    "cross-chain": "bridge",
    "freshness": "oracle",
    "staleness": "oracle",
    "oracle": "oracle",
    "price": "oracle",
    "custody": "custody",
    "vault": "vault",
    "lending": "lending",
    "borrow": "lending",
    "collateral": "lending",
    "liquidation": "liquidation",
    "dex": "dex",
    "swap": "dex",
    "amm": "dex",
    "governance": "governance",
    "voting": "governance",
    "auction": "auction",
    "staking": "staking",
    "mint": "minter",
    "minter": "minter",
    "burn": "burner",
    "burner": "burner",
    "rollup": "rollup",
    "proposer": "rollup",
    "settler": "settler",
    "dispatcher": "bridge",
    "router": "bridge",
}

# --- Function-role taxonomy ------------------------------------------------------
# Auto-derived from grep_patterns + question text. Each row is
# (function_role, regex_patterns_that_imply_role). The regex tries to
# match function-name fragments (case-insensitive).
FUNCTION_ROLE_RULES: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("dispatcher", (
        r"(?i)dispatch", r"(?i)executeRaw", r"(?i)forwardCall",
        r"(?i)processBridgeMessage", r"(?i)onAccept", r"(?i)onMessage",
        r"(?i)handleMessage", r"(?i)callBytes", r"(?i)relay",
    )),
    ("settler", (
        r"(?i)settle", r"(?i)finalize", r"(?i)payout",
        r"(?i)claim", r"(?i)redeem", r"(?i)withdraw",
    )),
    ("proposer", (
        r"(?i)propose", r"(?i)submitState", r"(?i)submitProof",
        r"(?i)submitRoot", r"(?i)assertBatch",
    )),
    ("verifier", (
        r"(?i)verifyProof", r"(?i)verify", r"(?i)checkProof",
        r"(?i)validateProof", r"(?i)_verifyAgainstStateRoot",
    )),
    ("minter", (
        r"(?i)\bmint\b", r"(?i)_mint\(",
    )),
    ("burner", (
        r"(?i)\bburn\b", r"(?i)_burn\(",
    )),
    ("liquidator", (
        r"(?i)liquidat",
    )),
    ("approver", (
        r"(?i)approve\(", r"(?i)permit\(", r"(?i)increaseAllowance",
        r"(?i)allowance\(",
    )),
    ("transferer", (
        r"(?i)transferFrom", r"(?i)transfer\(", r"(?i)safeTransfer",
    )),
    ("oracle-reader", (
        r"(?i)getPrice", r"(?i)latestAnswer", r"(?i)fetchPrice",
        r"(?i)oracle", r"(?i)staleness",
    )),
    ("voter", (
        r"(?i)\bvote\b", r"(?i)castVote", r"(?i)tally",
    )),
    ("governance-exec", (
        r"(?i)execute", r"(?i)queue", r"(?i)scheduleProposal",
    )),
    ("entry-point", (
        r"(?i)entryPoint", r"(?i)fallback\(", r"(?i)receive\(",
    )),
)


# --- Contract-name regex auto-derivation -----------------------------------------
# Maps detected function roles back to contract-name regex fragments.
CONTRACT_NAME_RE_BY_ROLE: Dict[str, str] = {
    "dispatcher": r"(?i)(bridge|dispatcher|router|gateway|relay|messenger|callDispatcher)",
    "settler":    r"(?i)(settle|settler|finalizer|claim|payout|vault|escrow)",
    "proposer":   r"(?i)(proposer|sequencer|batcher|outputOracle|l2Output)",
    "verifier":   r"(?i)(verifier|prover|fraudProof|disputeGame|stateRoot)",
    "minter":     r"(?i)(minter|token|erc20|erc721|erc1155|coin)",
    "burner":     r"(?i)(burner|token|coin)",
    "liquidator": r"(?i)(liquidator|liquidation|borrow|lend)",
    "approver":   r"(?i)(token|erc20|erc721|approval|permit)",
    "transferer": r"(?i)(token|erc20|treasury|vault|escrow)",
    "oracle-reader": r"(?i)(oracle|price|aggregator|feed|chainlink|pyth)",
    "voter":      r"(?i)(governance|voting|gauge|dao)",
    "governance-exec": r"(?i)(governance|timelock|executor|dao)",
    "entry-point": r"(?i)(entryPoint|account|proxy|wallet)",
}

# --- Modifier patterns -----------------------------------------------------------
DEFAULT_MODIFIER_PATTERNS: Tuple[str, ...] = (
    r"(?i)onlyOwner",
    r"(?i)onlyHost",
    r"(?i)onlyAdmin",
    r"(?i)onlyAuthorized",
    r"(?i)onlyRole\(",
    r"(?i)nonReentrant",
    r"(?i)whenNotPaused",
    r"(?i)onlyGovernance",
)


# --- Routing-integrity: native target-language derivation (B2) -------------------
# ROOT CAUSE this fixes: hacker-question records mined out of Go/Rust/Move/Cairo/ZK
# incidents (e.g. Wormhole guardian consensus, Cosmos NonceVoter, Substrate pallets,
# Zebra consensus-divergence) were stamped `target_languages: ["solidity"]` - the
# fail-to-solidity default in the ETL (`hackerman-etl-from-incident-corpora.py:228`)
# and the DSL-harvested rows that carry no `target_language` at all. A Go/Rust
# workspace lane that filters `vault_hacker_questions(target_language="go")` then
# drops the very consensus/memory-safety questions that live on its own surface,
# silently amputating whole attack classes from the non-Solidity fleet.
#
# FIX: derive a class's NATIVE language(s) from its attack-class taxonomy anchor
# (+ source-shape evidence in the question text). Fail OPEN: if we cannot decide a
# native language we keep whatever the record already declared (never silently drop
# a language). We never OVER-correct: a genuinely Solidity-only class (allowance
# residue, unlimited-approve, ERC-20 misuse, delegatecall/sstore/yul) resolves to
# ("solidity",) and gains no go/rust.

VALID_TARGET_LANGUAGES: Tuple[str, ...] = (
    "solidity", "vyper", "rust", "go", "move", "cairo",
    "circom", "typescript", "javascript",
)

# Ordered attack-class -> native-language rules. Keys are matched with word
# boundaries (case-insensitive substring on the anchor). Every rule whose key
# matches contributes its languages (union preserves the taxonomy relationship
# that, e.g., cosmos consensus lives in BOTH Go and Rust reference stacks).
NATIVE_LANGUAGES_BY_ATTACK_CLASS: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    # --- Go / Cosmos / consensus-machine native ---
    ("cosmos", ("go", "rust")),
    ("ibc", ("go", "rust")),
    ("cosmwasm", ("rust",)),
    ("tendermint", ("go",)),
    ("cometbft", ("go",)),
    ("consensus", ("go", "rust")),
    ("nonce-voter", ("go",)),
    ("observer", ("go",)),
    ("guardian", ("go",)),
    ("validator", ("go", "rust")),
    ("geth", ("go",)),
    ("go-l1", ("go",)),
    ("go-cosmos", ("go",)),
    ("l1-client", ("go", "rust")),
    ("goroutine", ("go",)),
    # --- Rust native ---
    ("substrate", ("rust",)),
    ("frame-pallet", ("rust",)),
    ("xcm", ("rust",)),
    ("polkadot", ("rust",)),
    ("zebra", ("rust",)),
    ("zcash", ("rust",)),
    ("reth", ("rust",)),
    ("solana", ("rust",)),
    ("svm", ("rust",)),
    ("anchor-lang", ("rust",)),
    # --- Memory-safety family (systems languages) ---
    ("memory-safety", ("rust", "go")),
    ("use-after-free", ("rust", "go")),
    ("buffer-overflow", ("rust", "go")),
    ("data-race", ("go", "rust")),
    # --- Move native ---
    ("move", ("move",)),
    ("aptos", ("move",)),
    ("sui", ("move",)),
    # --- Cairo / Starknet native ---
    ("cairo", ("cairo",)),
    ("starknet", ("cairo",)),
    ("felt252", ("cairo",)),
    # --- ZK circuit native (specific tokens only; bare "circuit"/"zk" omitted
    # because "circuit-breaker" is a Solidity pause pattern) ---
    ("circom", ("circom",)),
    ("groth16", ("circom",)),
    ("plonk", ("circom",)),
    # --- Compiler families: multi-language (specific first) ---
    ("vyper-compiler", ("vyper",)),
    ("solc-compiler", ("solidity",)),
    # --- Explicitly Solidity-native families (keep solidity; add nothing) ---
    ("allowance-residue", ("solidity",)),
    ("unlimited-approve", ("solidity",)),
    ("erc20", ("solidity",)),
    ("erc721", ("solidity",)),
    ("erc1155", ("solidity",)),
    ("erc4626", ("solidity",)),
    ("erc4337", ("solidity",)),
    ("delegatecall", ("solidity",)),
    ("sstore", ("solidity",)),
    ("yul", ("solidity",)),
    ("selector-deny", ("solidity",)),
    ("sqrtprice", ("solidity",)),
    ("uniswap", ("solidity",)),
)

# Source-shape evidence: (language, case-SENSITIVE regex over question_text).
# These recover the native language when the anchor is generic but the prose
# quotes real source (e.g. `NonceVoter(ctx, MsgNonceVoter)`, `pub fn`, `.move`).
# Evidence tokens are deliberately GO/RUST/MOVE/CAIRO-SYNTAX-SPECIFIC so they
# cannot fire on Solidity prose. NOTE: generic role words that ALSO exist in
# Solidity (Keeper, ctx, Msg*) are intentionally EXCLUDED - GMX-style Solidity
# perp DEXes use `Keeper`/`ctx` heavily and would be wrongly routed to Go.
_LANGUAGE_EVIDENCE_RULES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("go", re.compile(
        r"\bfunc\s+\w*\s*\([^)]*\)\s*\w|\bfunc\s*\([^)]*\)\s*[\w*(]|"
        r"sdk\.Context|sdk\.Msg|\.Keeper\b|keeper\.|zetacored|goroutine|"
        r"\.go\b|MsgServer|SetChainNonces")),
    ("rust", re.compile(
        r"\bpub\s+fn\b|\bfn\s+\w+\s*\([^)]*\)\s*->|\.rs\b|\bimpl\s+\w+\s+for\b|"
        r"\bSubstrate\b|\bpallet\b|\bZebra\b|\bzcash\b|\.unwrap\(\)|panic!\(")),
    ("move", re.compile(
        r"\.move\b|\bmodule\s+\w+::|\bpublic\s+(?:entry\s+)?fun\b|\bAptos\b|\bSui::")),
    ("cairo", re.compile(
        r"\.cairo\b|\bStarknet\b|felt252|#\[starknet")),
    ("vyper", re.compile(
        r"\.vy\b|@external\s*\ndef|@payable\s*\ndef|\bVyper\b")),
)


def _match_class_key(key: str, hay_lower: str) -> bool:
    """Word-boundary substring match so 'move' does not match 'remove'."""
    try:
        return re.search(r"\b" + re.escape(key) + r"\b", hay_lower) is not None
    except re.error:
        return key in hay_lower


def derive_native_target_languages(
    attack_class_anchor: str,
    question_text: str = "",
) -> List[str]:
    """Return the NATIVE target language(s) implied by a record's attack-class
    anchor plus source-shape evidence in the question text.

    Returns an ordered, de-duplicated list restricted to VALID_TARGET_LANGUAGES.
    Empty when nothing decides a native language (the caller then fails open to
    the record's declared languages). This is the authoritative signal the
    routing-integrity gate checks against a record's stored target_languages.
    """
    # Class-key matching runs against the ANCHOR ONLY. The attack-class anchor
    # is a controlled taxonomy string; the free-text question is NOT (English
    # words like "move", "circuit-breaker", "felt" would false-match). The
    # question text is consulted only by the code-syntax evidence rules below.
    anchor = _safe_str(attack_class_anchor)
    qtext = _safe_str(question_text)
    anchor_lower = anchor.lower()
    out: List[str] = []
    seen: Set[str] = set()

    def _add(langs: Iterable[str]) -> None:
        for lang in langs:
            lg = lang.lower().strip()
            if lg in VALID_TARGET_LANGUAGES and lg not in seen:
                seen.add(lg)
                out.append(lg)

    matched_specific_compiler = False
    for key, langs in NATIVE_LANGUAGES_BY_ATTACK_CLASS:
        if _match_class_key(key, anchor_lower):
            _add(langs)
            if key in ("solc-compiler", "vyper-compiler"):
                matched_specific_compiler = True

    # Generic compiler bug-class (no specific solc/vyper marker): a compiler
    # defect surfaces across the languages the toolchain compiles.
    if (not matched_specific_compiler
            and _match_class_key("compiler", anchor_lower)):
        _add(("solidity", "vyper", "rust", "go"))

    # Source-shape evidence (recovers native lang for generic anchors).
    for lang, rx in _LANGUAGE_EVIDENCE_RULES:
        if rx.search(qtext):
            _add((lang,))

    return out[:8]


def resolve_target_languages(
    attack_class_anchor: str,
    question_text: str,
    existing: Iterable[str],
) -> Tuple[List[str], List[str], str]:
    """Resolve a record's routed target_languages.

    Returns ``(resolved, native, source)`` where:
      - ``native``   = the native languages derived from the class/evidence
        (empty if undecidable).
      - ``resolved`` = the languages the record SHOULD carry: native UNIONed
        with its declared languages (never drops a declared language), or the
        fail-open fallback when no native language is derivable.
      - ``source``   = provenance tag ('native-derived' / 'fail-open-existing'
        / 'fail-open-default').
    """
    existing_valid: List[str] = []
    seen: Set[str] = set()
    for e in _safe_list(existing):
        lg = e.lower().strip()
        if lg in VALID_TARGET_LANGUAGES and lg not in seen:
            seen.add(lg)
            existing_valid.append(lg)

    native = derive_native_target_languages(attack_class_anchor, question_text)
    if native:
        resolved: List[str] = []
        rseen: Set[str] = set()
        for lg in list(native) + existing_valid:
            if lg not in rseen:
                rseen.add(lg)
                resolved.append(lg)
        return resolved[:8], native, "native-derived"
    if existing_valid:
        return existing_valid[:8], [], "fail-open-existing"
    return ["solidity"], [], "fail-open-default"


def _safe_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()


def _safe_list(v: Any) -> List[str]:
    if isinstance(v, list):
        return [_safe_str(x) for x in v if _safe_str(x)]
    if isinstance(v, str) and v.strip():
        return [v.strip()]
    return []


def _norm_lower(values: Iterable[str]) -> List[str]:
    return [v.lower() for v in values]


# === Public API ===================================================================


def derive_target_function_patterns(grep_patterns: Iterable[str]) -> List[str]:
    """Derive `target_function_patterns` regex list from a hacker-question
    record's grep_patterns.

    The grep_patterns frequently ARE function-name fragments
    (e.g. `executeRaw`, `transferFrom`, `permit(`). We keep them as
    case-insensitive regexes after escaping the regex metachars except
    for `\\b` word-boundary and parens which we preserve as written.

    Returns a deduplicated list capped at 24.
    """
    out: List[str] = []
    seen: Set[str] = set()
    for raw in grep_patterns or []:
        s = _safe_str(raw)
        if not s:
            continue
        # If the pattern already contains regex metachars (\\ ( ) [ ] | etc.)
        # the corpus has already written it as a regex; keep verbatim and
        # add case-insensitivity hint by prefixing `(?i)` if absent.
        if any(ch in s for ch in r"\\^$.*+?[](){}|"):
            candidate = s if s.startswith("(?i)") else f"(?i){s}"
        else:
            # Plain identifier; escape sensibly + ensure case-insensitive.
            candidate = f"(?i){re.escape(s)}"
        # Cheap regex-compile check to drop obviously bad records.
        try:
            re.compile(candidate)
        except re.error:
            continue
        key = candidate.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(candidate)
        if len(out) >= 24:
            break
    return out


def derive_function_roles(
    grep_patterns: Iterable[str],
    question_text: str = "",
) -> List[str]:
    """Return the function roles a hacker-question or chain-template
    record matches (e.g. ['dispatcher', 'verifier'])."""
    haystack_parts: List[str] = []
    for g in grep_patterns or []:
        haystack_parts.append(_safe_str(g))
    if question_text:
        haystack_parts.append(_safe_str(question_text))
    haystack = " || ".join(haystack_parts)
    if not haystack:
        return []
    matched: List[str] = []
    for role, patterns in FUNCTION_ROLE_RULES:
        for pat in patterns:
            try:
                if re.search(pat, haystack):
                    matched.append(role)
                    break
            except re.error:
                continue
    # Stable dedupe preserving first-occurrence order.
    seen: Set[str] = set()
    out: List[str] = []
    for role in matched:
        if role not in seen:
            seen.add(role)
            out.append(role)
    return out


def derive_target_contract_patterns(roles: Iterable[str]) -> List[str]:
    """Map function roles back to contract-name regex fragments."""
    out: List[str] = []
    seen: Set[str] = set()
    for role in roles or []:
        regex = CONTRACT_NAME_RE_BY_ROLE.get(role.lower().strip())
        if not regex:
            continue
        if regex in seen:
            continue
        seen.add(regex)
        out.append(regex)
        if len(out) >= 16:
            break
    return out


def derive_modifier_patterns() -> List[str]:
    """Return the canonical modifier-name regex list. (Static for now.)"""
    return list(DEFAULT_MODIFIER_PATTERNS)


def derive_scope_specificity(
    grep_patterns: Iterable[str],
    target_function_patterns: Iterable[str],
    target_contract_patterns: Iterable[str],
) -> str:
    """Return one of workspace / contract / function / line.

    Heuristic: line > function > contract > workspace.
    """
    has_fn = any(_safe_str(p) for p in target_function_patterns or [])
    has_ct = any(_safe_str(p) for p in target_contract_patterns or [])
    if not has_fn and not has_ct:
        return SCOPE_WORKSPACE
    if has_fn and not has_ct:
        return SCOPE_FUNCTION
    if has_ct and not has_fn:
        return SCOPE_CONTRACT
    return SCOPE_FUNCTION


def derive_applicable_contract_kinds(
    member_invariant_ids: Iterable[str],
    member_categories: Iterable[str] = (),
) -> List[str]:
    """Map a global-chain-template's member invariants + categories onto
    applicable contract kinds (bridge / lending / dex / oracle / ...).
    """
    kinds: List[str] = []
    seen: Set[str] = set()
    inv_ids = list(member_invariant_ids or [])
    for inv in inv_ids:
        inv_str = _safe_str(inv).upper()
        if not inv_str:
            continue
        for prefix, kind in CONTRACT_KIND_BY_INVARIANT_PREFIX:
            if inv_str.startswith(prefix):
                if kind not in seen:
                    seen.add(kind)
                    kinds.append(kind)
                break
    for cat in member_categories or []:
        key = _safe_str(cat).lower()
        if not key:
            continue
        kind = CONTRACT_KIND_BY_CATEGORY.get(key)
        if kind and kind not in seen:
            seen.add(kind)
            kinds.append(kind)
    return kinds[:8]


def derive_applicable_function_role_patterns(
    member_invariant_ids: Iterable[str],
    member_categories: Iterable[str] = (),
) -> List[str]:
    """Map invariants + categories onto canonical function roles.

    Uses a heuristic: bridge -> dispatcher; oracle -> oracle-reader;
    lending -> liquidator/transferer; dex -> transferer; rollup ->
    proposer/verifier; etc.
    """
    role_map: Dict[str, Tuple[str, ...]] = {
        "bridge": ("dispatcher", "verifier", "transferer"),
        "oracle": ("oracle-reader",),
        "custody": ("transferer", "settler"),
        "lending": ("liquidator", "transferer", "oracle-reader"),
        "liquidation": ("liquidator",),
        "dex": ("transferer",),
        "vault": ("settler", "transferer"),
        "governance": ("voter", "governance-exec"),
        "rollup": ("proposer", "verifier"),
        "rollup-prover": ("proposer", "verifier"),
        "auction": ("settler",),
        "staking": ("settler", "transferer"),
        "minter": ("minter",),
        "burner": ("burner",),
        "settler": ("settler",),
    }
    kinds = derive_applicable_contract_kinds(
        member_invariant_ids, member_categories
    )
    out: List[str] = []
    seen: Set[str] = set()
    for kind in kinds:
        for role in role_map.get(kind, ()):
            if role not in seen:
                seen.add(role)
                out.append(role)
    return out[:12]


# A2a: a META/rule row has no function target by nature (codified rubric rule,
# postmortem rule, or a generic firm-finding-other shell). Such rows must NOT be
# back-derived a function pattern (that would mislabel them); they route to a
# rubric/postmortem lane via non_targetable_meta instead of the per-fn proof queue.
# STRUCTURAL meta only: a codified rubric rule or a postmortem rule has no function
# target by nature. We deliberately do NOT flag by harvest-source (lift-13-mega-harvest)
# or a generic anchor (unspecified): those rows DO carry role signal in their
# attack_class_anchor + question_text and recover ~2727 matchable patterns. Over-flagging
# by source would route real attack-class rows to a rubric lane and lose the recovery.
_META_ANCHOR_RE = re.compile(r"(?i)^(rule-\d+|postmortem-rule)$")
_ROLE_PATTERNS_BY_NAME = {role: pats for role, pats in FUNCTION_ROLE_RULES}


def _is_meta_rule_row(anchor: str, source_incident: str) -> bool:
    a = _safe_str(anchor).strip()
    s = _safe_str(source_incident).strip().lower()
    if a and _META_ANCHOR_RE.match(a):
        return True
    return s.startswith("codified-rule")


def _function_patterns_for_roles(roles: Iterable[str], cap: int = 24) -> List[str]:
    """The FUNCTION_ROLE_RULES patterns ARE function-name regexes; reuse them as
    target_function_patterns for a grep-less row whose role we inferred."""
    out: List[str] = []
    seen: Set[str] = set()
    for role in roles or []:
        for pat in _ROLE_PATTERNS_BY_NAME.get(_safe_str(role).lower().strip(), ()):
            cand = pat if pat.startswith("(?i)") else f"(?i){pat}"
            key = cand.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(cand)
            if len(out) >= cap:
                return out
    return out


def enrich_hacker_question_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Return a NEW dict equal to ``rec`` plus the LIFT-28 per-function
    fields. Backward-compat: ``rec`` is never mutated; existing fields
    are preserved verbatim.

    A2a: for a GREP-LESS row (no grep payload) that is NOT a meta/rule row,
    back-derive target_function_patterns from the roles inferred off
    attack_class_anchor + question_text, so the row becomes matchable by
    corpus-driven-hunt (which drops empty-needle rows) instead of dying silently.
    Meta/rule rows are flagged non_targetable_meta and routed to a rubric lane.
    """
    if not isinstance(rec, dict):
        return rec  # degenerate input passthrough
    grep_patterns = _safe_list(rec.get("grep_patterns"))
    question_text = _safe_str(rec.get("question_text"))
    anchor = _safe_str(rec.get("attack_class_anchor"))
    source_incident = _safe_str(rec.get("source_incident_id"))
    fn_pats = derive_target_function_patterns(grep_patterns)
    # role inference now also reads the attack_class_anchor for grep-less rows.
    roles = derive_function_roles(
        grep_patterns, " ".join(p for p in (question_text, anchor) if p)
    )
    ct_pats = derive_target_contract_patterns(roles)
    mod_pats = derive_modifier_patterns()
    out = dict(rec)
    non_targetable = False
    if not fn_pats:
        if _is_meta_rule_row(anchor, source_incident):
            non_targetable = True
        elif roles:
            fn_pats = _function_patterns_for_roles(roles)
    scope = derive_scope_specificity(grep_patterns, fn_pats, ct_pats)
    out["target_function_patterns"] = fn_pats
    out["target_function_roles"] = roles
    out["target_contract_patterns"] = ct_pats
    out["target_modifier_patterns"] = mod_pats
    out["scope_specificity"] = SCOPE_WORKSPACE if non_targetable else scope
    if non_targetable:
        out["non_targetable_meta"] = True
    # B2 routing-integrity: route target_languages to the class's NATIVE
    # language(s) instead of the fail-to-solidity default. Fail-open: a record
    # with no derivable native language keeps its declared languages verbatim.
    resolved_langs, native_langs, lang_source = resolve_target_languages(
        anchor, question_text, rec.get("target_languages")
    )
    out["target_languages"] = resolved_langs
    out["native_target_languages"] = native_langs
    out["target_languages_routing_source"] = lang_source
    return out


def enrich_global_chain_template_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Return a NEW dict equal to ``rec`` plus the LIFT-28 per-function
    fields. Adds:

    - ``applicable_contract_kinds``: list of canonical contract kinds.
    - ``applicable_function_role_patterns``: list of canonical roles.
    - ``min_member_invariants_matching``: int (default ceil(tuple_size/2),
      minimum 1).
    """
    if not isinstance(rec, dict):
        return rec
    members = _safe_list(rec.get("member_invariant_ids"))
    categories = _safe_list(rec.get("member_categories"))
    kinds = derive_applicable_contract_kinds(members, categories)
    roles = derive_applicable_function_role_patterns(members, categories)
    tuple_size_raw = rec.get("tuple_size")
    try:
        tuple_size = int(tuple_size_raw) if tuple_size_raw is not None else len(members)
    except (TypeError, ValueError):
        tuple_size = len(members) or 1
    min_match = max(1, (tuple_size + 1) // 2)
    out = dict(rec)
    out["applicable_contract_kinds"] = kinds
    out["applicable_function_role_patterns"] = roles
    out["min_member_invariants_matching"] = min_match
    return out


# === Filtering helpers ===========================================================


def _compile_patterns_safe(patterns: Iterable[str]) -> List[re.Pattern[str]]:
    out: List[re.Pattern[str]] = []
    for p in patterns or []:
        try:
            out.append(re.compile(p))
        except re.error:
            continue
    return out


def _any_match(text: str, patterns: Sequence[re.Pattern[str]]) -> bool:
    if not text or not patterns:
        return False
    for pat in patterns:
        if pat.search(text):
            return True
    return False


def question_matches_target(
    question: Dict[str, Any],
    *,
    target_contract_path: str = "",
    target_function_name: str = "",
    contract_kind_hint: str = "",
) -> bool:
    """Return True iff a hacker_questions record applies to the target.

    Decision rules:
    - If target_contract_path is provided, match against
      ``target_contract_patterns`` (any pattern hit = True). Records that
      lack the field (legacy) match by default at contract level.
    - If target_function_name is provided, match against
      ``target_function_patterns``. Records with no field match by
      default at function level (workspace-wide fall-through).
    - contract_kind_hint matches the question's question_text +
      grep_patterns.
    """
    if not isinstance(question, dict):
        return False
    # Function-name filter
    if target_function_name:
        fn_pats = _compile_patterns_safe(
            _safe_list(question.get("target_function_patterns"))
        )
        if fn_pats and not _any_match(target_function_name, fn_pats):
            # The record explicitly declares its function patterns and the
            # target function doesn't match any; reject it.
            return False
        if not fn_pats:
            # Legacy record without per-function patterns: fall through to
            # grep_patterns + question_text substring check.
            haystack_grep = " || ".join(_safe_list(question.get("grep_patterns")))
            haystack_text = _safe_str(question.get("question_text"))
            if haystack_grep or haystack_text:
                combined = (haystack_grep + " " + haystack_text).lower()
                if target_function_name.lower() not in combined:
                    # Soft-fail to keep workspace-level questions surfacing.
                    pass
    # Contract-path filter
    if target_contract_path:
        ct_pats = _compile_patterns_safe(
            _safe_list(question.get("target_contract_patterns"))
        )
        if ct_pats and not _any_match(target_contract_path, ct_pats):
            return False
    # Contract-kind hint
    if contract_kind_hint:
        haystack = (
            " ".join(_safe_list(question.get("grep_patterns")))
            + " "
            + _safe_str(question.get("question_text"))
            + " "
            + _safe_str(question.get("attack_class_anchor"))
        ).lower()
        if contract_kind_hint.lower() not in haystack:
            # Soft-fail; if the record was workspace-level we keep it.
            pass
    return True


# r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY pathspec registered.
def template_matches_target(
    template: Dict[str, Any],
    *,
    target_contract_path: str = "",
    target_function_name: str = "",
    contract_kind_hint: str = "",
) -> bool:
    """Return True iff a global_chain_template record applies to the target.

    Strictness model (LIFT-28 default - lenient pass-through):
    - Only HARD-reject when contract_kind_hint is explicitly provided
      AND the template's applicable_contract_kinds list is non-empty AND
      the hint does not intersect the list. This preserves the maximum
      number of candidate templates so the score-based ranking in the
      caller chooses the best matches.
    - target_contract_path and target_function_name remain SOFT signals:
      they boost rank in the caller, do not gate.
    """
    if not isinstance(template, dict):
        return False
    kinds = [k.lower() for k in _safe_list(template.get("applicable_contract_kinds"))]
    if contract_kind_hint and kinds:
        if contract_kind_hint.lower() not in kinds:
            return False
    return True


def score_template_match(
    template: Dict[str, Any],
    *,
    target_contract_path: str = "",
    target_function_name: str = "",
    contract_kind_hint: str = "",
) -> int:
    """LIFT-28 scoring helper: how strongly does this template apply to
    the named contract:function target? Higher == better.

    The score is composed deterministically:
      +20 if applicable_contract_kinds intersects target_contract_path
      +15 if applicable_contract_kinds intersects contract_kind_hint
      +10 if applicable_function_role_patterns has a regex that matches
          target_function_name
      +5  if template has applicable_contract_kinds (was enriched)
      +1  baseline.
    """
    if not isinstance(template, dict):
        return 0
    score = 1
    kinds = [k.lower() for k in _safe_list(template.get("applicable_contract_kinds"))]
    roles = [r.lower() for r in _safe_list(template.get("applicable_function_role_patterns"))]
    if kinds:
        score += 5
    if target_contract_path and kinds:
        cp = target_contract_path.lower()
        if any(k in cp for k in kinds):
            score += 20
    if contract_kind_hint and kinds:
        if contract_kind_hint.lower() in kinds:
            score += 15
    if target_function_name and roles:
        tfn = target_function_name.lower()
        for role in roles:
            role_hit = False
            for declared_role, patterns in FUNCTION_ROLE_RULES:
                if declared_role.lower() != role:
                    continue
                for rgx in patterns:
                    try:
                        if re.search(rgx, tfn):
                            role_hit = True
                            break
                    except re.error:
                        continue
                if role_hit:
                    break
            if role_hit:
                score += 10
                break
    return score


__all__ = [
    "SCOPE_WORKSPACE",
    "SCOPE_CONTRACT",
    "SCOPE_FUNCTION",
    "SCOPE_LINE",
    "SCOPE_VALUES",
    "derive_target_function_patterns",
    "derive_target_contract_patterns",
    "derive_function_roles",
    "derive_modifier_patterns",
    "derive_scope_specificity",
    "derive_native_target_languages",
    "resolve_target_languages",
    "VALID_TARGET_LANGUAGES",
    "NATIVE_LANGUAGES_BY_ATTACK_CLASS",
    "derive_applicable_contract_kinds",
    "derive_applicable_function_role_patterns",
    "enrich_hacker_question_record",
    "enrich_global_chain_template_record",
    "question_matches_target",
    "template_matches_target",
    # r36-rebuttal: lane LIFT-28-PER-FUNCTION-CAPABILITY pathspec registered.
    "score_template_match",
]
