#!/usr/bin/env python3
"""zk-hacker-questions.py - per-function ZK soundness/completeness hacker questions.

ZK analog of vault_hacker_questions (the per-Solidity-function adversarial
question generator). Given a verifier / circuit source FILE (or directory of
them), split it into functions and, for each function, emit the targeted
soundness / completeness questions a ZK auditor asks:

  - "Is every public input constrained?"
  - "Can the prover choose this challenge (Fiat-Shamir freedom)?"
  - "Is this field op constrained mod P?"
  - "Is the transcript bound to all proof elements (no domain-separation gap)?"
  - "Are databus / lookup constraints present?"
  - "Can a malformed proof skip this check?"

RELATED TOOLS:
  - tools/zk-verifier-bugclass-checklist.py : Stage-2 workspace consumer that
    reads <ws>/.auditooor/zk_surface.json and writes a zk_hunt_queue.jsonl.
    DIFFERENT INPUT/OUTPUT: that tool is a workspace-wide queue writer keyed
    off a pre-computed surface file; THIS tool is a per-FILE / per-FUNCTION
    question generator that takes a `<file-or-dir>` positional arg and prints
    questions (vault_hacker_questions parity). This tool reuses the 8
    verifier-side bug-class predicates from the checklist as its question
    seed library and ADDS circuit-side classes (public-input-constraint,
    field-op-mod-p, lookup-databus-constraint, malformed-proof-skip).
  - tools/per-function-hacker-questions.py : generic (non-ZK) per-function
    hacker-question generator that consumes invariants.jsonl. THIS tool is
    the ZK-specific sibling that reads source directly and keys questions off
    ZK soundness bug classes rather than generic invariant candidates.
  - tools/zk-function-mindset.py / tools/function-mindset.py : per-function
    hunt orchestrators (circuit body extractors); this tool emits the
    question set those orchestrators ask.

CLI:
    python3 tools/zk-hacker-questions.py <file-or-dir> [--json]

Exit codes:
    0  >=1 function emitted at least one question
    1  no ZK function matched any question class
    2  argument error (path not found)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.zk_hacker_questions.v1"

# --- halo2-constraint-completeness predicate (advisory soundness-margin axis) --
#
# NET-NEW ABSENCE/ordering predicate (NOT keyword-presence like QUESTION_LIBRARY
# above - the A1 trap). It parses each `meta.create_gate(..)` closure, collects
# the advice/witness columns queried inside it, and diffs them against the
# columns actually referenced by the returned `Constraints::` expressions. A
# column queried but referenced in NO returned constraint expr is a dropped /
# unconstrained witness -> one hypothesis per gate/dropped-col.
#
# Advisory-first: emission is OFF unless HALO2_CC_ENV is truthy. Verdict is
# always 'needs-fuzz' (NO-AUTO-CREDIT). FP-guard: lookup / enable_equality /
# permutation constraints live OUTSIDE create_gate, so a gate whose closure
# returns no `Constraints::` block is skipped (not flagged).
HALO2_CC_SCHEMA = "auditooor.zk_constraint_completeness.v1"
HALO2_CC_ENV = "ZK_HALO2_CONSTRAINT_COMPLETENESS"
HALO2_CC_FILENAME = "zk_constraint_completeness_hypotheses.jsonl"
HALO2_CC_PREDICATE = "halo2-constraint-completeness"

# --- PASS 2: halo2 witness-underdetermination (residual-freedom) ----------------
#
# DISTINCT from pass 1 (dropped-col) AND from E4 (checks which gates EXIST).
# Pass 1 / E4 answer "does a constraint touch this advice at all?". This pass
# answers the HALF they miss: the gate IS present and DOES reference the advice,
# but leaves RESIDUAL FREEDOM - the advice can take >1 value that still satisfies
# every returned constraint, so a false statement obtains a valid proof via a
# prover-chosen alternate assignment. Invariant: INV-ZK-WITNESS-UNIQUE (every
# advice cell is a pure function of committed inputs - exactly one witness).
#
# Non-vacuous, low-FP scope: we only judge advice used in a role that PROVABLY
# requires a uniqueness pin:
#   - mux/condition role: used as the selector arg of ternary/select/mux(..).
#     Requires a boolean pin (bool_check(col) or col*(1-col) / col*col-col).
#   - hint role: var name is an inverse/isZero/quotient hint. Requires an
#     inverse pin (col in a product that subtracts one: col * x - 1).
# If the role is present in the ENFORCED (returned) expression closure but the
# matching pin is NOT, we emit one residual-freedom hypothesis.
#
# FP-guard: pin/role detection runs over the RETURNED region only (cblock plus
# the transitive let-closure reaching it) - a bool_check COMPUTED but never
# placed in Constraints is not a real pin and correctly does not suppress. Advice
# with a pin present is benign and never fires. Lookup / permutation /
# enable_equality live outside create_gate and are out of this pass by scope.
HALO2_WU_SCHEMA = "auditooor.zk_witness_underdetermination.v1"
HALO2_WU_PREDICATE = "halo2-witness-underdetermination"
HALO2_WU_INVARIANT = "INV-ZK-WITNESS-UNIQUE"

_MUX_COND_TMPL = (
    r"(?:ternary|select|mux|cond_select|conditional[_a-z]*select|conditionally_select)"
    r"\s*\(\s*{col}\b")
# inverse/quotient hint advice (the classic under-determined witness: `a_inv` is
# free when a==0). The isZero OUTPUT flag is a boolean pinned by an equality, a
# different idiom, so it is intentionally NOT in this inverse-hint name set.
_HINT_NAME_RE = re.compile(r"(?:^|_)(?:inv|inverse|quotient|hint)",
                           re.IGNORECASE)
_ONE = r"(?:1|one|F::one\(\)|Expression::Constant\(F::one\(\)\))"
_LET_RE = re.compile(r"\blet\s+(?P<v>\w+)\s*=\s*(?P<expr>[^;]*);", re.DOTALL)

_CREATE_GATE_RE = re.compile(
    r"\.create_gate\s*\(\s*(?P<gate>\"[^\"]*\"|\w+)\s*,\s*\|[^|]*\|\s*\{")
_QUERY_ADVICE_RE = re.compile(
    r"let\s+(?P<var>\w+)\s*=\s*meta\.query_advice\s*\(")
_CONSTRAINTS_RE = re.compile(r"Constraints::(?:with_selector|without_selector)\s*\(")


def _match_delim(text: str, open_idx: int, opener: str, closer: str) -> int:
    """Return index just past the delimiter that matches text[open_idx]==opener."""
    depth = 0
    for i in range(open_idx, len(text)):
        c = text[i]
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i + 1
    return len(text)


def _constraints_block(body: str) -> str | None:
    """Return the `Constraints::with/without_selector( ... )` arg text, or None.

    None => this create_gate closure returns no Constraints block (FP-guard:
    skip lookup / permutation / equality gates whose logic lives elsewhere)."""
    m = _CONSTRAINTS_RE.search(body)
    if not m:
        return None
    paren = body.find("(", m.end() - 1)
    if paren < 0:
        return None
    return body[paren:_match_delim(body, paren, "(", ")")]


def _referenced_outside_binding(body: str, var: str, bind_off: int) -> bool:
    """True if `var` appears anywhere in the closure body other than its own
    `let var = meta.query_advice(..)` binding line.

    Broad referenced-region (whole body minus the binding line) is the
    deliberately conservative / low-FP direction: any downstream use - direct
    in a constraint expr OR via an intermediate `let` - counts as referenced,
    so the predicate only fires on a column used NOWHERE but its binding."""
    line_start = body.rfind("\n", 0, bind_off) + 1
    line_end = body.find("\n", bind_off)
    if line_end == -1:
        line_end = len(body)
    rest = body[:line_start] + body[line_end:]
    return re.search(r"\b" + re.escape(var) + r"\b", rest) is not None


def _returned_region(body: str, cblock: str) -> str:
    """cblock plus the transitive let-closure that reaches it.

    Only expressions that actually flow into the returned Constraints block are
    'enforced'. Expanding the let-graph (bounded fixpoint) means a bool_check
    computed but never referenced in Constraints is NOT counted as a pin."""
    lets = {m.group("v"): m.group("expr") for m in _LET_RE.finditer(body)}
    region = cblock
    pending = [v for v in lets if re.search(r"\b" + re.escape(v) + r"\b", region)]
    seen: set[str] = set()
    while pending:
        v = pending.pop()
        if v in seen:
            continue
        seen.add(v)
        expr = lets[v]
        region += "\n" + expr
        for w in lets:
            if w not in seen and re.search(r"\b" + re.escape(w) + r"\b", expr):
                pending.append(w)
    return region


def _used_as_mux_condition(region: str, col: str) -> bool:
    return re.search(_MUX_COND_TMPL.format(col=re.escape(col)), region) is not None


def _has_boolean_pin(region: str, col: str) -> bool:
    c = re.escape(col)
    pats = [
        r"bool_check\s*\(\s*" + c + r"\b",                       # helper
        c + r"\b[\w.'()\s]*\*[\w.'()\s]*\(\s*" + _ONE + r"\s*-\s*" + c + r"\b",   # col*(1-col)
        r"\(\s*" + _ONE + r"\s*-\s*" + c + r"\b[^)]*\)[\w.'()\s]*\*[\w.'()\s]*" + c + r"\b",  # (1-col)*col
        c + r"\b[\w.'()\s]*\*[\w.'()\s]*" + c + r"\b[^;\n]*-\s*" + c + r"\b",      # col*col - col
    ]
    return any(re.search(p, region) for p in pats)


def _has_inverse_pin(region: str, col: str) -> bool:
    c = re.escape(col)
    pats = [
        c + r"\b[^;\n]{0,40}\*[^;\n]{0,120}-\s*" + _ONE,      # col * x ... - 1
        r"\*[^;\n]{0,40}" + c + r"\b[^;\n]{0,120}-\s*" + _ONE,  # x * col ... - 1
        r"-\s*" + _ONE + r"[^;\n]{0,120}\*[^;\n]{0,40}" + c + r"\b",  # ... - 1 = x*col
    ]
    return any(re.search(p, region) for p in pats)


def _halo2_witness_underdetermination(path: Path, text: str) -> list[dict[str, Any]]:
    """PASS 2: advice referenced by a gate but left under-determined (INV-ZK-WITNESS-UNIQUE)."""
    hyps: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for m in _CREATE_GATE_RE.finditer(text):
        open_brace = text.index("{", m.end() - 1)
        body = text[open_brace:_match_delim(text, open_brace, "{", "}")]
        gate = m.group("gate").strip('"')
        cblock = _constraints_block(body)
        if cblock is None:
            continue  # FP-guard: lookup/permutation/equality gate -> not judged here
        region = _returned_region(body, cblock)
        cols: dict[str, int] = {}
        for qm in _QUERY_ADVICE_RE.finditer(body):
            cols.setdefault(qm.group("var"), qm.start())
        gate_line = text.count("\n", 0, m.start()) + 1
        for var in cols:
            # only advice actually referenced in the enforced region (else it is
            # pass-1's dropped-col locus, not residual freedom - DEDUP)
            if not re.search(r"\b" + re.escape(var) + r"\b", region):
                continue
            role = None
            if _used_as_mux_condition(region, var):
                role = "mux-condition"
                pinned = _has_boolean_pin(region, var)
            elif _HINT_NAME_RE.search(var):
                role = "inverse-hint"
                pinned = _has_inverse_pin(region, var)
            else:
                continue  # no uniqueness-requiring role -> out of low-FP scope
            if pinned:
                continue  # benign: advice is pinned to one value
            key = (str(path), gate, var)
            if key in seen:
                continue
            seen.add(key)
            hyps.append({
                "schema": HALO2_WU_SCHEMA,
                "predicate": HALO2_WU_PREDICATE,
                "axis": "witness-uniqueness",
                "invariant": HALO2_WU_INVARIANT,
                "advisory": True,
                "verdict": "needs-fuzz",       # NO-AUTO-CREDIT
                "file": str(path),
                "line": gate_line,
                "gate": gate,
                "advice_col": var,
                "role": role,
                # DEDUP: pass-1 / E4 flag advice with NO constraint; this locus is
                # advice WITH a constraint but no uniqueness pin -> not re-derived.
                "covered_by": None,
                "note": ("advice used as %s inside a returned Constraints expr but no "
                         "uniqueness pin (boolean/inverse) constrains it to one value; "
                         "admits multiple satisfying witnesses -> false statement can "
                         "prove valid" % role),
            })
    return hyps


def halo2_constraint_completeness(path: Path, text: str) -> list[dict[str, Any]]:
    """Emit one dropped-constraint hypothesis per (gate, unreferenced advice col)."""
    hyps: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()  # dedup identical (file,gate,col)
    line_starts = [0]
    for ch in text:
        line_starts.append(line_starts[-1] + 1)
    for m in _CREATE_GATE_RE.finditer(text):
        open_brace = text.index("{", m.end() - 1)
        body = text[open_brace:_match_delim(text, open_brace, "{", "}")]
        gate = m.group("gate").strip('"')
        cblock = _constraints_block(body)
        if cblock is None:
            continue  # FP-guard: no returned Constraints -> not a gate we judge
        cols: dict[str, int] = {}
        for qm in _QUERY_ADVICE_RE.finditer(body):
            cols.setdefault(qm.group("var"), qm.start())
        if not cols:
            continue
        gate_line = text.count("\n", 0, m.start()) + 1
        for var, bind_off in cols.items():
            if _referenced_outside_binding(body, var, bind_off):
                continue
            key = (str(path), gate, var)
            if key in seen:
                continue
            seen.add(key)
            hyps.append({
                "schema": HALO2_CC_SCHEMA,
                "predicate": HALO2_CC_PREDICATE,
                "axis": "soundness-margin",
                "advisory": True,
                "verdict": "needs-fuzz",       # NO-AUTO-CREDIT
                "file": str(path),
                "line": gate_line,
                "gate": gate,
                "dropped_col": var,
                # DEDUP (A1): net-new column-level ABSENCE class; the
                # keyword-presence QUESTION_LIBRARY never emits a dropped_col
                # locus, so covered_by is null by construction (not re-derived).
                "covered_by": None,
                "note": ("advice col queried in create_gate but referenced in no "
                         "returned Constraints expr (unconstrained witness)"),
            })
    # PASS 2: residual-freedom (advice constrained but not pinned to one value).
    hyps.extend(_halo2_witness_underdetermination(path, text))
    return hyps


def halo2_cc_enabled() -> bool:
    return os.environ.get(HALO2_CC_ENV, "").strip().lower() in {"1", "true", "yes", "on"}


def run_halo2_cc(target: Path) -> list[dict[str, Any]]:
    hyps: list[dict[str, Any]] = []
    for f in _iter_source_files(target):
        if f.suffix.lower() != ".rs":
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if ".create_gate" not in text:
            continue
        hyps.extend(halo2_constraint_completeness(f, text))
    return hyps

# Files worth scanning: solidity verifiers, circom/halo2/noir/gnark circuit
# sources, and rust verifier ports.
SOURCE_SUFFIXES = {".sol", ".circom", ".rs", ".nr", ".go", ".cairo"}

SKIP_DIRS = {".git", "target", "node_modules", "__pycache__", ".venv", "build", "dist"}

# Function-definition patterns across the ZK source languages we care about.
# Each entry: (compiled regex with a `name` group, language label).
FUNCTION_DEF_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bfunction\s+(?P<name>\w+)\s*\("), "solidity"),
    (re.compile(r"\btemplate\s+(?P<name>\w+)\s*\("), "circom"),
    (re.compile(r"\bcomponent\s+(?P<name>\w+)\s*="), "circom"),
    (re.compile(r"\bfn\s+(?P<name>\w+)\s*[(<]"), "rust"),
    (re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?(?P<name>\w+)\s*\("), "go"),
]

# Seed question library. The first 8 classes mirror the verifier-side
# bug classes from zk-verifier-bugclass-checklist.py; the remaining classes
# add the generic ZK soundness/completeness questions the operator listed.
#
# Each predicate:
#   bug_class       : canonical class label
#   keywords        : substrings that, if present in the fn name OR the fn
#                     body, attach the question to that function
#   question        : the adversarial question (the thing the hacker asks)
#   oracle_check    : the source-level check that answers the question
#   severity_hint   : HIGH/MEDIUM rough severity if the answer is "no"
QUESTION_LIBRARY: list[dict[str, Any]] = [
    {
        "bug_class": "transcript-absorb-completeness",
        "keywords": ["absorb", "squeeze", "getchallenge", "squeezechallenge",
                     "transcript", "append", "hash_to_transcript"],
        "question": ("Is the transcript bound to ALL proof elements - are every public "
                     "input, commitment, and vkHash absorbed BEFORE any challenge is "
                     "squeezed? A missing absorption lets a prover substitute a vk or "
                     "proof element the challenge never committed to."),
        "oracle_check": ("Every transcript.absorb(public_inputs / commitments / vkHash) "
                         "precedes every transcript.get_challenge() / squeeze call."),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "fs-challenge-domain-separation",
        "keywords": ["splitchallenge", "getchallenge", "squeezechallenge",
                     "challenge", "fiatshamir", "fiat_shamir", "domain_sep",
                     "domainseparator"],
        "question": ("Can the prover CHOOSE this Fiat-Shamir challenge - does each "
                     "challenge domain use a unique label so challenges cannot collide "
                     "across domains (e.g. sumcheck vs KZG vs lookup)?"),
        "oracle_check": ("Each get_challenge(label) call site uses a distinct, "
                         "non-reused domain-separation label string."),
        "severity_hint": "MEDIUM",
    },
    {
        "bug_class": "curve-membership-check",
        "keywords": ["batchmul", "batchverify", "pairing", "staticcall", "ecadd",
                     "ecmul", "msm", "multiscalar", "g1", "g2", "point"],
        "question": ("Is curve membership + point-at-infinity rejection enforced on ALL "
                     "proof-element points before accumulation (not only the final "
                     "pairing)? A single un-checked point breaks soundness."),
        "oracle_check": ("rejectPointAtInfinity() / is_on_curve() is called on EVERY "
                         "input G1/G2 point individually before the accumulation loop."),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "field-op-mod-p",
        "keywords": ["invert", "modinverse", "inverse", "divmod", "mulmod", "addmod",
                     "submod", "expmod", "field", "fr", "fq", "montgomery"],
        "question": ("Is this field op constrained mod P - is the input to every "
                     ".invert()/modular-inverse checked != 0, and is every add/mul/sub "
                     "reduced mod the field prime so no value silently exceeds P?"),
        "oracle_check": ("Inverse inputs assert != 0 (return optional / revert), and "
                         "all field arithmetic uses addmod/mulmod (or reduces) mod P."),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "public-input-constraint",
        "keywords": ["publicinput", "public_input", "publicinputdelta", "verifyproof",
                     "verify", "instance", "pi_", "publicinputs"],
        "question": ("Is EVERY public input constrained - is each public input both "
                     "(a) range/field checked and (b) bound into the Fiat-Shamir "
                     "transcript BEFORE the first challenge? An unconstrained or "
                     "late-absorbed public input lets the prover forge the statement."),
        "oracle_check": ("Each public input is validated (< field modulus) and absorbed "
                         "into the transcript before any squeeze; count of constrained "
                         "PIs == count of declared PIs."),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "sumcheck-round-count-enforcement",
        "keywords": ["verifysumcheck", "sumcheck", "sumcheckround", "logn", "numrounds",
                     "round", "univariate"],
        "question": ("Can a malformed proof skip rounds - is the number of sumcheck "
                     "rounds asserted == log2(circuit_size)? A reduced round count skips "
                     "polynomial relations and admits false proofs."),
        "oracle_check": ("Round loop asserts round_idx bound == log2(N) / "
                         "CONST_PROOF_SIZE_LOG_N; no early-exit shortens the loop."),
        "severity_hint": "MEDIUM",
    },
    {
        "bug_class": "recursion-aggregation-object-skip",
        "keywords": ["verifyzkproof", "verifyrecursive", "verifyaggregation",
                     "basezkhonkverifier", "basehonkverifier", "aggregation",
                     "accumulator", "ipa", "recursion"],
        "question": ("Can a malformed proof skip this check - does a non-ZK / "
                     "non-recursive path skip aggregation-object or pairing-accumulator "
                     "processing that the ZK / recursive path includes? Asymmetric guards "
                     "create a soundness bypass."),
        "oracle_check": ("Diff the ZK vs non-ZK verifier path for any "
                         "aggregation_object / IPA accumulation block present in one but "
                         "absent in the other; confirm the asymmetry is intentional."),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "shplemini-opening-proof-binding",
        "keywords": ["verifyshplemini", "verifyopeningproof", "kzg", "shplemini",
                     "evaluation_challenge", "opening", "commitmentscheme", "gemini"],
        "question": ("Can the prover choose the evaluation point - is `r` committed into "
                     "the Fiat-Shamir transcript BEFORE the opening query is constructed? "
                     "A free `r` lets the prover pick a convenient evaluation point."),
        "oracle_check": ("evaluation_challenge_r is squeezed from the transcript BEFORE "
                         "the opening polynomial / query is constructed."),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "lookup-databus-constraint",
        "keywords": ["lookup", "databus", "plookup", "logderivative", "log_derivative",
                     "permutation", "grandproduct", "grand_product", "table", "calldata_bus",
                     "return_bus"],
        "question": ("Are databus / lookup constraints present and complete - is every "
                     "looked-up value actually constrained to appear in the table, and is "
                     "the log-derivative / grand-product accumulator checked to equal its "
                     "expected boundary value? A missing accumulator check admits "
                     "out-of-table values."),
        "oracle_check": ("Lookup / permutation accumulator opens to the expected boundary "
                         "(1 or the claimed product) and every bus column is range/membership "
                         "constrained; no lookup column is left unconstrained."),
        "severity_hint": "HIGH",
    },
    {
        "bug_class": "malformed-proof-skip",
        "keywords": ["verify", "verifyproof", "checkproof", "require", "assert", "revert",
                     "if", "guard", "validate"],
        "question": ("Can a malformed proof skip this check - if any required relation, "
                     "length check, or boundary assertion is gated behind an attacker-"
                     "controllable branch (proof-supplied flag, length, or selector), can a "
                     "crafted proof take the path that omits the constraint?"),
        "oracle_check": ("Every soundness-critical assertion is reached unconditionally "
                         "for all proof shapes; no proof-supplied value selects a "
                         "constraint-skipping branch."),
        "severity_hint": "HIGH",
    },
]


def _iter_source_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    found: list[Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        try:
            if p.stat().st_size > 4 * 1024 * 1024:
                continue
        except OSError:
            continue
        found.append(p)
    return found


def _extract_functions(text: str) -> list[dict[str, Any]]:
    """Return [{name, line, language, body}] for each function-like def.

    Body of function i runs from its def line to the next function's def line
    (a cheap, language-agnostic slice; sufficient for keyword matching).
    """
    lines = text.splitlines()
    hits: list[tuple[int, str, str]] = []  # (line_idx_0based, name, language)
    for idx, line in enumerate(lines):
        for pat, lang in FUNCTION_DEF_PATTERNS:
            m = pat.search(line)
            if m:
                hits.append((idx, m.group("name"), lang))
                break
    funcs: list[dict[str, Any]] = []
    for i, (line_idx, name, lang) in enumerate(hits):
        end_idx = hits[i + 1][0] if i + 1 < len(hits) else len(lines)
        body = "\n".join(lines[line_idx:end_idx])
        funcs.append({
            "name": name,
            "line": line_idx + 1,
            "language": lang,
            "body": body,
        })
    return funcs


def _match_questions(fn_name: str, fn_body: str) -> list[dict[str, Any]]:
    name_l = fn_name.lower()
    body_l = fn_body.lower()
    matched: list[dict[str, Any]] = []
    for pred in QUESTION_LIBRARY:
        for kw in pred["keywords"]:
            if kw in name_l or kw in body_l:
                matched.append(pred)
                break
    return matched


def analyze_file(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for fn in _extract_functions(text):
        preds = _match_questions(fn["name"], fn["body"])
        if not preds:
            continue
        questions = [
            {
                "bug_class": p["bug_class"],
                "question": p["question"],
                "oracle_check": p["oracle_check"],
                "severity_hint": p["severity_hint"],
            }
            for p in preds
        ]
        out.append({
            "function": fn["name"],
            "file_line": f"{path}:{fn['line']}",
            "language": fn["language"],
            "questions": questions,
        })
    return out


def analyze(target: Path) -> dict[str, Any]:
    files = _iter_source_files(target)
    records: list[dict[str, Any]] = []
    for f in files:
        records.extend(analyze_file(f))
    total_q = sum(len(r["questions"]) for r in records)
    bug_classes = sorted({q["bug_class"] for r in records for q in r["questions"]})
    return {
        "schema": SCHEMA,
        "target": str(target),
        "files_scanned": len(files),
        "functions_with_questions": len(records),
        "total_questions": total_q,
        "bug_classes": bug_classes,
        "records": records,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Per-function ZK soundness/completeness hacker questions "
                    "(vault_hacker_questions ZK analog)")
    ap.add_argument("target", help="Verifier/circuit source file or directory")
    ap.add_argument("--json", action="store_true", help="Emit JSON to stdout")
    ap.add_argument("--halo2-out", default=".",
                    help=("dir to write %s (only when %s is truthy; advisory-first, "
                          "OFF by default)" % (HALO2_CC_FILENAME, HALO2_CC_ENV)))
    args = ap.parse_args(argv)

    target = Path(args.target).resolve()
    if not target.exists():
        sys.stderr.write(f"error: path not found: {target}\n")
        return 2

    if halo2_cc_enabled():
        hyps = run_halo2_cc(target)
        out = Path(args.halo2_out).resolve() / HALO2_CC_FILENAME
        with out.open("w", encoding="utf-8") as fh:
            for h in hyps:
                fh.write(json.dumps(h) + "\n")
        sys.stderr.write(f"[zk-hq] halo2-cc: {len(hyps)} hypothesis(es) -> {out}\n")

    result = analyze(target)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if not result["records"]:
            print(f"[zk-hq] no ZK functions matched any question class in {target}")
        for rec in result["records"]:
            print(f"\n{rec['file_line']}  ({rec['language']})  fn {rec['function']}")
            for q in rec["questions"]:
                print(f"  [{q['severity_hint']:6s}] {q['bug_class']}")
                print(f"          Q: {q['question']}")
                print(f"          oracle: {q['oracle_check']}")
        print(f"\n[zk-hq] {result['functions_with_questions']} fn(s), "
              f"{result['total_questions']} question(s), "
              f"classes: {', '.join(result['bug_classes']) or '(none)'}")

    return 0 if result["total_questions"] > 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
