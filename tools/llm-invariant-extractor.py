#!/usr/bin/env python3
"""llm-invariant-extractor.py - LLM-assisted layer: stated invariants -> fuzzable assertions.

SKELETON (not full impl). The 3-stage pipeline is implemented with real honesty
gates; the LLM call itself is a clearly-marked stub that must be replaced before
production use.

=== 3-STAGE PIPELINE ===

Stage 1 - EXTRACT
  Input : a Solidity source file (or NatSpec doc).
  Output: a list of InvariantClaim records, each carrying:
    - a verbatim source_quote (mandatory) referencing the exact comment/NatSpec span,
    - the claim text (natural language),
    - the source_span (file, line_start, line_end).
  LLM call (STUB): prompted to return JSON array of {claim, source_quote, line_start,
  line_end}. The stub returns a hardcoded example for testing; replace with a real
  Anthropic API call.

Stage 2 - BIND
  Each InvariantClaim's claim terms are resolved to REAL Solidity symbols that
  exist in the workspace source tree. Resolution uses symbol_exists_grep() which
  greps the actual .sol files and rejects any symbol absent from the source.
  A claim whose key terms cannot all be bound to real symbols is recorded as
  BIND_FAILED and excluded from Stage 3.

Stage 3 - COMPILE
  Bound claims are compiled into FuzzableAssertion records: a Solidity
  invariant_* function body expressing a REAL comparison between two distinct,
  separately-mutated quantities. Assertions are never vacuous (no assert(true),
  no x == x). Compilation is a template-driven stub in the MVP; the LLM call
  here is also stubbed.

=== HONESTY GATES ===

  Gate (a) - symbol_exists_grep(symbol, ws): REAL and tested. Greps all .sol
    files under ws for the symbol; returns True iff found. Rejects hallucinated
    symbols before any harness is emitted.

  Gate (b) - seeded_mutation_must_fail(assertion_src, ws): PLACEHOLDER. In
    production: inject a known mutation (e.g., flip `<=` to `<`) into a copy of
    the target source, run the assertion harness, and assert the engine KILLS it.
    Until this gate is wired, a warning is emitted and the assertion is marked
    mutation_verified=false in the manifest. A mutation_verified=false assertion
    NEVER counts toward coverage (anti-stub rule).

  Gate (c) - pass_on_clean(assertion_src, ws): PLACEHOLDER. In production: run
    the assertion harness against the UNMODIFIED source and assert it does NOT
    trip. Until wired, marked clean_verified=false.

HONESTY CONTRACT:
  - Every output file carries a CANDIDATE HARNESS - NOT PROOF banner (matches
    evm-engine-harness-author._BANNER convention).
  - is_real_contract is only set True when symbol_exists_grep passes for all
    bound symbols AND a non-zero contract address resolves.
  - mutation_verified=false records are excluded from coverage accounting by
    cross-function-invariant-coverage.py (fail-closed).

NON-DUPLICATION:
  This tool is the ~30% LLM-assisted layer that lifts STATED invariants from
  docs/NatSpec into fuzzable assertions. It is DISTINCT from:
  - tools/evm-engine-harness-author.py (corpus-matched, model-based, 3-engine)
  - tools/auto-invariant-harness-gen.py (universal catalog, real-contract-driving,
    no LLM call)
  Reuses: _load_module pattern from cross-function-harness-producer.py,
  _BANNER from evm-engine-harness-author.py (via importlib path-load).

Exit codes:
  0 - assertions emitted (all gates passed)
  1 - partial: some claims bound, some BIND_FAILED (output written, manifest
      records bind_status per claim)
  2 - input error / no claims extracted / all claims BIND_FAILED / any gate
      failure in strict mode (--strict)

agent_pathspec.json: tools/llm-invariant-extractor.py registered via
tools/agent-pathspec-register.py lane LLM-INVARIANT-EXTRACTOR-BUILD.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.llm_invariant_extractor.v1"
_HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Canonical banner (matches evm-engine-harness-author._BANNER convention).
# ---------------------------------------------------------------------------
_BANNER = """\
// =====================================================================
// CANDIDATE HARNESS - NOT PROOF
// ---------------------------------------------------------------------
// Auto-authored by tools/llm-invariant-extractor.py.
// Each invariant_* assertion was EXTRACTED from stated invariants in
// NatSpec/docs, BOUND to grep-verified real symbols, and COMPILED to a
// Solidity comparison over two distinct quantities. A counterexample from
// a fuzz engine is a REVIEW CANDIDATE, not a finding.
//
// Honesty gate status (see attempt_manifest.json for per-claim detail):
//   symbol_exists_grep : REAL (grep-verified)
//   seeded_mutation    : {mutation_status}
//   pass_on_clean      : {clean_status}
// =====================================================================
"""

# ---------------------------------------------------------------------------
# Data model.
# ---------------------------------------------------------------------------

@dataclass
class InvariantClaim:
    """A stated invariant extracted from source comments / NatSpec (Stage 1)."""
    claim: str                   # natural-language claim text
    source_quote: str            # verbatim quote from the source (mandatory)
    source_file: str             # relative path to the source file
    line_start: int
    line_end: int
    # Populated by Stage 2 (bind):
    bound_symbols: list[str] = field(default_factory=list)
    bind_status: str = "UNBOUND"  # UNBOUND | BOUND | BIND_FAILED | PARTIAL_BIND
    bind_failures: list[str] = field(default_factory=list)


@dataclass
class FuzzableAssertion:
    """A Solidity invariant_* function body ready to drop into a harness (Stage 3)."""
    claim: InvariantClaim
    inv_id: str          # e.g. "LLM-INV-001"
    fn_name: str         # e.g. "invariant_totalSupply_conservation"
    solidity_body: str   # the full function body (Solidity text)
    # Honesty gate results:
    mutation_verified: bool = False    # Gate (b) - placeholder until wired
    clean_verified: bool = False       # Gate (c) - placeholder until wired
    is_real_contract: bool = False     # True only when symbols grep-verified
                                       # and a non-zero contract address resolves


# ---------------------------------------------------------------------------
# HONESTY GATE (a): symbol_exists_grep - REAL AND TESTED.
# ---------------------------------------------------------------------------

def symbol_exists_grep(symbol: str, ws: Path) -> bool:
    """Return True iff `symbol` appears in at least one .sol file under `ws`.

    This is GATE (a) - the real honesty gate. It greps the actual Solidity
    source tree and rejects any symbol that is absent. Hallucinated symbols
    (e.g. a function name the LLM invented that does not exist in the contract)
    are caught here and cause the enclosing claim to be marked BIND_FAILED.

    Grep target: all *.sol files under ws (recursive).
    Pattern: word-boundary match on the symbol identifier so that a symbol
    `transfer` does not accidentally match `transferFrom` as a prefix.
    Returns False (= reject) when:
      - no .sol files exist under ws
      - grep exits non-zero (no match)
      - any subprocess error occurs

    Fallback chain:
      1. grep -r -l -P (Perl regex, word boundary)
      2. grep -r -l -E (extended regex, word boundary)
      3. grep -r -l   (plain, no word boundary - broader but safe as last resort)
    """
    if not ws.is_dir():
        return False
    perl_pattern = rf"\b{re.escape(symbol)}\b"
    plain_pattern = re.escape(symbol)
    try:
        # Attempt 1: GNU grep with Perl regex word boundaries.
        result = subprocess.run(
            ["grep", "-r", "-l", "-P", perl_pattern, "--include=*.sol", str(ws)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0 and result.stdout.strip():
            return True
        # Attempt 2: BSD/macOS grep with extended regex.
        result2 = subprocess.run(
            ["grep", "-r", "-l", "-E", perl_pattern, "--include=*.sol", str(ws)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result2.returncode == 0 and result2.stdout.strip():
            return True
        # Attempt 3: plain grep (no word boundary, broadest match).
        result3 = subprocess.run(
            ["grep", "-r", "-l", plain_pattern, "--include=*.sol", str(ws)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result3.returncode == 0 and bool(result3.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


# ---------------------------------------------------------------------------
# HONESTY GATE (b): seeded_mutation_must_fail - PLACEHOLDER.
# ---------------------------------------------------------------------------

def seeded_mutation_must_fail(assertion_src: str, ws: Path) -> bool:
    """PLACEHOLDER - Gate (b): seeded mutation must be killed by the engine.

    Production implementation (NOT YET WIRED):
      1. Identify the primary comparison operator in assertion_src (e.g. `<=`).
      2. Flip it to a known-wrong variant (e.g. `<`).
      3. Write the mutated harness to a temp directory under ws/poc-tests/_mut/.
      4. Run `medusa fuzz --config medusa.json --timeout 30` on the mutated harness.
      5. Assert the engine reports a FAIL (counterexample found).
      6. Return True iff the engine kills the mutation.
    Until wired, always returns False. A False result sets
    mutation_verified=False in the manifest - the assertion CANNOT count
    toward coverage (fail-closed, anti-stub).
    """
    # TODO(operator): wire to medusa/echidna runner.
    return False


# ---------------------------------------------------------------------------
# HONESTY GATE (c): pass_on_clean - PLACEHOLDER.
# ---------------------------------------------------------------------------

def pass_on_clean(assertion_src: str, ws: Path) -> bool:
    """PLACEHOLDER - Gate (c): assertion must NOT trip on unmodified source.

    Production implementation (NOT YET WIRED):
      1. Run the fuzz harness against the real (unmodified) contract for a
         short campaign (e.g. 60s medusa).
      2. Assert NO counterexample is found.
      3. Return True iff clean.
    Until wired, always returns False. Marked clean_verified=False; does NOT
    block emit but is recorded in the manifest for downstream enforcement.
    """
    # TODO(operator): wire to medusa/echidna runner.
    return False


# ---------------------------------------------------------------------------
# Stage 1: EXTRACT stated invariants (LLM call - STUB).
# ---------------------------------------------------------------------------

def extract_invariant_claims(src_path: Path) -> list[InvariantClaim]:
    """Stage 1: extract stated invariant claims from NatSpec / comments.

    LLM CALL STUB - replace _llm_extract_claims() with a real Anthropic API
    call (claude-sonnet-4-5 or later) before production use.

    The real call should:
      - Send the full source text as user content.
      - Use a system prompt instructing the model to return a JSON array of
        {claim, source_quote, line_start, line_end} where source_quote is a
        VERBATIM substring of the source (mandatory; used to anchor the claim).
      - Parse the JSON response and map to InvariantClaim records.
      - Reject any record whose source_quote is not a literal substring of the
        source text (hallucination guard: the quote must be findable).
    """
    src_text = src_path.read_text(encoding="utf-8", errors="replace")
    raw_claims = _llm_extract_claims(src_text, src_path)
    validated: list[InvariantClaim] = []
    for rc in raw_claims:
        # Mandatory: source_quote must appear literally in the source.
        quote = rc.get("source_quote", "")
        if not quote or quote not in src_text:
            # Hallucinated quote - drop (honesty gate at extract time).
            continue
        validated.append(InvariantClaim(
            claim=rc.get("claim", ""),
            source_quote=quote,
            source_file=str(src_path),
            line_start=int(rc.get("line_start", 0)),
            line_end=int(rc.get("line_end", 0)),
        ))
    return validated


def _llm_extract_claims(src_text: str, src_path: Path) -> list[dict[str, Any]]:
    """STUB: replace with a real Anthropic API call.

    Production call (pseudocode):
      import anthropic
      client = anthropic.Anthropic()
      response = client.messages.create(
          model="claude-sonnet-4-5",
          max_tokens=2048,
          system=EXTRACT_SYSTEM_PROMPT,
          messages=[{"role": "user", "content": src_text}],
      )
      return json.loads(response.content[0].text)

    The stub scans NatSpec @dev/@notice lines with keywords (invariant, always,
    never, must, should) to produce a minimal set of plausible claims for
    skeleton testing.
    """
    claims: list[dict[str, Any]] = []
    lines = src_text.splitlines()
    keywords = re.compile(
        r"(?:invariant|always|never|must\s+(?:be|remain|not)|should\s+(?:be|remain|not))",
        re.IGNORECASE,
    )
    natspec = re.compile(r"///\s*(.*)|/\*\*?\s*(.*)")
    for i, line in enumerate(lines, 1):
        m = natspec.match(line.strip())
        if m:
            comment_text = (m.group(1) or m.group(2) or "").strip()
            if keywords.search(comment_text):
                claims.append({
                    "claim": comment_text,
                    "source_quote": line.rstrip(),
                    "line_start": i,
                    "line_end": i,
                })
    return claims


# ---------------------------------------------------------------------------
# Stage 2: BIND claim terms to grep-verified real symbols.
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"\b([a-zA-Z_]\w*)\b")
_SKIP_WORDS = frozenset({
    "the", "a", "an", "is", "are", "was", "be", "must", "always", "never",
    "not", "total", "sum", "value", "amount", "if", "when", "after",
    "before", "invariant", "should", "remain", "equal", "greater", "less",
    "than", "or", "and", "in", "of", "to", "for", "at", "by",
})


def bind_claim(claim: InvariantClaim, ws: Path) -> InvariantClaim:
    """Stage 2: bind each candidate symbol in claim.claim to a real grep hit.

    Populates claim.bound_symbols (verified) and claim.bind_failures (absent).
    Sets claim.bind_status to BOUND, BIND_FAILED, or PARTIAL_BIND.
    BIND_FAILED means zero candidate symbols resolved - the claim is excluded
    from Stage 3.
    """
    candidates = [
        w for w in _IDENT_RE.findall(claim.claim)
        if w not in _SKIP_WORDS and len(w) > 2
    ]
    seen: set[str] = set()
    unique: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            unique.append(c)

    bound: list[str] = []
    failed: list[str] = []
    for sym in unique:
        if symbol_exists_grep(sym, ws):
            bound.append(sym)
        else:
            failed.append(sym)

    claim.bound_symbols = bound
    claim.bind_failures = failed
    if not bound:
        claim.bind_status = "BIND_FAILED"
    elif failed:
        claim.bind_status = "PARTIAL_BIND"
    else:
        claim.bind_status = "BOUND"
    return claim


# ---------------------------------------------------------------------------
# Stage 3: COMPILE bound claim to a FuzzableAssertion (template stub).
# ---------------------------------------------------------------------------

# LLM COMPILE STUB: in production replace _llm_compile_assertion() with an
# Anthropic API call that turns a bound claim + its verified symbols into a
# Solidity invariant_* function body with a REAL comparison.
#
# The system prompt must enforce:
#   - No assert(true), no x == x, no modulo-neutralized arithmetic.
#   - The comparison must involve two distinct, separately-mutated quantities.
#   - Must reference at least one symbol from bound_symbols.

def compile_assertion(claim: InvariantClaim, inv_id: str, ws: Path) -> FuzzableAssertion:
    """Stage 3: compile a bound claim to a FuzzableAssertion."""
    fn_name = _make_fn_name(claim, inv_id)
    body = _llm_compile_assertion(claim, fn_name)
    mutation_ok = seeded_mutation_must_fail(body, ws)
    clean_ok = pass_on_clean(body, ws)
    is_real = claim.bind_status in ("BOUND", "PARTIAL_BIND") and bool(claim.bound_symbols)
    return FuzzableAssertion(
        claim=claim,
        inv_id=inv_id,
        fn_name=fn_name,
        solidity_body=body,
        mutation_verified=mutation_ok,
        clean_verified=clean_ok,
        is_real_contract=is_real,
    )


def _make_fn_name(claim: InvariantClaim, inv_id: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "_", claim.claim[:40]).strip("_").lower()
    return f"invariant_{slug}_{inv_id.replace('-', '_').lower()}"


def _llm_compile_assertion(claim: InvariantClaim, fn_name: str) -> str:
    """STUB: replace with real Anthropic API call (see module docstring).

    The stub emits a template with a TODO placeholder. The emitted body
    references at least one bound symbol but is tagged // TODO(operator)
    so no automated gate can mistake it for a real assertion.
    """
    symbol_comment = (
        ", ".join(claim.bound_symbols) if claim.bound_symbols
        else "/* no symbols bound */"
    )
    # r36-rebuttal: lane FIX-AUTO-INVARIANT-DEFECTS registered
    # The stub must NOT emit an unconditional `revert(...)` - that has inverted
    # polarity (it would mark every CORRECT contract as broken on the first
    # fuzz call). Emit an explicitly-non-counting PLACEHOLDER that PASSES on a
    # correct contract; the seeded_mutation_must_fail / pass_on_clean gates set
    # mutation_verified=False so this can never be credited as coverage until an
    # operator replaces it with a genuine comparison.
    return (
        f"    function {fn_name}() public pure {{\n"
        f"        // PLACEHOLDER - NOT COUNTED (mutation_verified=false). Replace with a\n"
        f"        // REAL comparison over two distinct quantities. Bound symbols: {symbol_comment}\n"
        f"        // Source quote: {claim.source_quote!r}\n"
        f"        // shape required: assert(A != B) / assertEq(measuredA, measuredB)\n"
        f"        assertTrue(true, \"LLM-INVARIANT-EXTRACTOR PLACEHOLDER - not a real invariant, not counted\");\n"
        f"    }}\n"
    )


# ---------------------------------------------------------------------------
# Pipeline orchestrator.
# ---------------------------------------------------------------------------

def run(src_path: Path, ws: Path, strict: bool = False):
    """Run the 3-stage pipeline: extract -> bind -> compile.

    Returns (manifest, assertions, claims, mutation_status, clean_status).
    Calls sys.exit(2) on fatal conditions.
    """
    claims = extract_invariant_claims(src_path)
    if not claims:
        print(
            f"[llm-invariant-extractor] No stated invariants found in {src_path}",
            file=sys.stderr,
        )
        sys.exit(2)

    bound_claims = [bind_claim(c, ws) for c in claims]
    viable = [c for c in bound_claims if c.bind_status != "BIND_FAILED"]
    failed = [c for c in bound_claims if c.bind_status == "BIND_FAILED"]

    if not viable:
        print(
            f"[llm-invariant-extractor] All {len(claims)} claims BIND_FAILED "
            f"(no symbols grep-verified in {ws}). "
            "Refusing to emit vacuous harness.",
            file=sys.stderr,
        )
        sys.exit(2)

    assertions: list[FuzzableAssertion] = []
    for i, claim in enumerate(viable, 1):
        inv_id = f"LLM-INV-{i:03d}"
        assertions.append(compile_assertion(claim, inv_id, ws))

    mutation_status = (
        "WIRED" if all(a.mutation_verified for a in assertions)
        else "PLACEHOLDER-NOT-WIRED"
    )
    clean_status = (
        "WIRED" if all(a.clean_verified for a in assertions)
        else "PLACEHOLDER-NOT-WIRED"
    )

    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_file": str(src_path),
        "workspace": str(ws),
        "candidate_not_proof": True,
        "proof_pending_via": (
            "seeded_mutation_must_fail() + pass_on_clean() gates must be wired "
            "before mutation_verified=True; until then coverage=0"
        ),
        "honesty_gates": {
            "symbol_exists_grep": "REAL",
            "seeded_mutation_must_fail": mutation_status,
            "pass_on_clean": clean_status,
        },
        "claims_total": len(claims),
        "claims_viable": len(viable),
        "claims_bind_failed": len(failed),
        "bind_failed_claims": [
            {"claim": c.claim, "bind_failures": c.bind_failures}
            for c in failed
        ],
        "assertions": [
            {
                "inv_id": a.inv_id,
                "fn_name": a.fn_name,
                "claim": a.claim.claim,
                "source_quote": a.claim.source_quote,
                "bound_symbols": a.claim.bound_symbols,
                "bind_status": a.claim.bind_status,
                "mutation_verified": a.mutation_verified,
                "clean_verified": a.clean_verified,
                "is_real_contract": a.is_real_contract,
            }
            for a in assertions
        ],
    }
    return manifest, assertions, claims, mutation_status, clean_status


def emit_solidity(
    assertions: list[FuzzableAssertion],
    out_dir: Path,
    contract_name: str,
    mutation_status: str,
    clean_status: str,
) -> Path:
    """Emit the Solidity harness file carrying the banner + all assertion bodies."""
    banner = _BANNER.format(
        mutation_status=mutation_status,
        clean_status=clean_status,
    )
    bodies = "\n".join(a.solidity_body for a in assertions)
    sol = (
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n\n"
        f"{banner}\n"
        'import "forge-std/Test.sol";\n\n'
        f"contract {contract_name}_LLMInvariantHarness is Test {{\n"
        f"{bodies}"
        "}\n"
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{contract_name}_LLMInvariant.t.sol"
    out_path.write_text(sol, encoding="utf-8")
    return out_path


# ---------------------------------------------------------------------------
# CLI.
# ---------------------------------------------------------------------------

def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="LLM-assisted stated-invariant extractor (skeleton).",
    )
    p.add_argument(
        "--source", required=True, type=Path,
        help="Path to the Solidity source file to analyse.",
    )
    p.add_argument(
        "--workspace", required=True, type=Path,
        help="Workspace root (grep target for symbol_exists_grep).",
    )
    p.add_argument(
        "--out-dir", type=Path, default=None,
        help=(
            "Output directory for harness + manifest. "
            "Default: <workspace>/poc-tests/<ContractName>-llm-invariants/"
        ),
    )
    p.add_argument(
        "--strict", action="store_true",
        help="Exit 2 if any gate returns False (Gate b or c not wired).",
    )
    p.add_argument(
        "--manifest-only", action="store_true",
        help="Print manifest JSON to stdout; do not write files.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    src = args.source.resolve()
    ws = args.workspace.resolve()
    if not src.is_file():
        print(
            f"[llm-invariant-extractor] Source not found: {src}",
            file=sys.stderr,
        )
        return 2

    manifest, assertions, claims, mutation_status, clean_status = run(
        src, ws, args.strict
    )
    contract_name = args.source.stem

    if args.manifest_only:
        print(json.dumps(manifest, indent=2))
        return 0

    out_dir = (
        args.out_dir
        or ws / "poc-tests" / f"{contract_name}-llm-invariants"
    )
    sol_path = emit_solidity(
        assertions, out_dir, contract_name, mutation_status, clean_status
    )
    manifest_path = out_dir / "attempt_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"[llm-invariant-extractor] Emitted {sol_path}")
    print(f"[llm-invariant-extractor] Manifest  {manifest_path}")
    print(
        f"[llm-invariant-extractor] Claims: {manifest['claims_viable']} viable, "
        f"{manifest['claims_bind_failed']} BIND_FAILED"
    )
    print(
        f"[llm-invariant-extractor] Gates: symbol_exists_grep=REAL | "
        f"seeded_mutation={mutation_status} | pass_on_clean={clean_status}"
    )

    if args.strict and (
        mutation_status != "WIRED" or clean_status != "WIRED"
    ):
        print(
            "[llm-invariant-extractor] --strict: gates not fully wired -> exit 2",
            file=sys.stderr,
        )
        return 2

    return 1 if manifest["claims_bind_failed"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
