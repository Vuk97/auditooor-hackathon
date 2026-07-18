#!/usr/bin/env python3
"""realfn_token_guard.py - shared anti-fabrication guard for the auto-converters.

THE FABRICATION THIS GUARD KILLS
================================
A 0-day auto-converter (engine-auto-convert.py / anchor-0day-proof.py) is allowed
to emit a `proof-backed` (a.k.a. "proven" / "converted" / "real-fn-convert")
verdict ONLY when it actually compiled + ran a harness that DRIVES THE REAL
function it cites. GRSWEEP-2 (Securitize RWA) caught a converter emitting
`proof-backed` with a real `cargo run` transcript (rc 101) on a NAMED REAL
TARGET, while the lifted `src/lib.rs` it compiled contained ZERO tokens from the
real handler - the tool had authored a SYNTHETIC GENERIC template
(`handler_buggy(acct, exp) { Ok(()) }`) and proved THAT, not the real function.

The run "passed", the cited target was real, the toolchain was real - but the
proof was of a stub, not of the target. That is a fabricated proof: the single
worst failure mode (#1 rule: never fabricate a proof).

WHAT THE GUARD DOES
===================
At the moment a converter is about to emit a proof-backed-equivalent verdict FOR
A RUN THAT CARRIES A CITED REAL (external / cloned-repo) SOURCE, this guard:

  1. Extracts the real function body from the cited source (the fn span the tool
     already located).
  2. Derives a token set: the real fn NAME plus the distinct identifiers/keywords
     in the real fn body (locals, called fns, account/field/struct names), with
     language boilerplate stripped.
  3. Reads the AUTHORED HARNESS/LIFTED file(s) the tool generated + compiled +
     ran (the lib.rs / target.go / .sol it drove).
  4. Requires the authored source to contain the real fn NAME AND >= 3 distinct
     real-fn-body tokens. Fewer than 3 (or 0) body tokens => the authored source
     is a SYNTHETIC TEMPLATE, not a real-fn drive.
  5. On failure: do NOT emit proof-backed. Downgrade the verdict to
     blocked-with-obligation with the reason
       "template-proof: authored harness does not embed real-fn source tokens
        (synthetic template, not a real-fn convert)"
     and record the token-overlap count in the result so it is auditable.

FIXTURE-EXEMPTION (preserved, conservative)
===========================================
A registered self-contained fixture IS the real program - there is no external
source to lift FROM, so the token check does not apply and proof-backed is still
emitted. A run is treated as a self-contained fixture (exempt) when ANY of:
  * the cited target_file lives under a `tools/tests/fixtures/**` path or a
    converter-bundled `tools/exploit-*-fixtures/**` path (the tool's OWN in-repo
    fixture corpus), OR
  * the run carries a fixture role via an INDEX.json `fixture_role` / `role`
    marker in the target's directory tree, OR
  * the run carries NO external cited source at all (no target_file / no fn).
EVERYTHING ELSE - any run that cites a real external/cloned source file + a real
function name - gets the token check. When it is unclear whether a run is a
real-target lift, the guard APPLIES (false-block is safe; false-pass is the
fabrication we are killing).

This module is shared by both converters so the guard logic is identical and
single-sourced. It is import-only (no side effects, no CLI).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

# The verdict strings the converters use for a real, run-backed PASS. Any of
# these, when about to be emitted on a cited-real-source run, triggers the guard.
PROOF_BACKED_EQUIVALENTS = frozenset({
    "proof-backed", "proven", "converted", "real-fn-convert",
})

# The downgrade target + reason (verbatim, auditable).
DOWNGRADE_VERDICT = "blocked-with-obligation"
DOWNGRADE_REASON = (
    "template-proof: authored harness does not embed real-fn source tokens "
    "(synthetic template, not a real-fn convert)"
)

# Minimum distinct real-fn-body tokens the authored source must embed (in
# addition to the fn name) for the lift to count as a real-fn drive.
MIN_BODY_TOKENS = 3

# Language boilerplate keywords stripped from the derived token set so a stub
# that merely shares `let`/`return`/`Ok` with the real fn cannot pass. This is a
# generic (target-agnostic) keyword set covering Rust / Go / Solidity surfaces.
_BOILERPLATE = frozenset({
    # control flow / decls common across rust/go/sol
    "let", "mut", "fn", "func", "return", "if", "else", "for", "while", "loop",
    "match", "case", "switch", "break", "continue", "in", "as", "is", "be",
    "pub", "const", "static", "var", "type", "struct", "enum", "impl", "trait",
    "use", "mod", "package", "import", "self", "Self", "super", "crate", "this",
    "public", "private", "internal", "external", "view", "pure", "payable",
    "memory", "storage", "calldata", "function", "contract", "library",
    # ubiquitous result/option/err idioms
    "Ok", "Err", "Result", "Some", "None", "Option", "nil", "err", "error",
    "true", "false", "bool", "unwrap", "into", "from", "to_string", "clone",
    "new", "default", "Default", "panic", "require", "assert", "emit", "revert",
    # primitive types (rust/go/sol)
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64",
    "i128", "isize", "f32", "f64", "string", "byte", "rune", "int", "uint",
    "uint256", "uint128", "uint64", "uint32", "uint8", "int256", "address",
    "bytes", "bytes32", "Vec", "Box", "Rc", "Arc", "RefCell", "RefMut", "Ref",
    "HashMap", "BTreeMap", "Pubkey", "AccountInfo", "Account", "Context",
    "Signer", "msg", "sender",
})

# What an identifier/keyword token looks like (>= 2 chars to avoid single-letter
# noise; alnum + underscore). We additionally keep the real fn name regardless of
# length.
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]+")

# Authored / lifted source file extensions the guard scans inside the workdir.
_SOURCE_GLOBS = ("*.rs", "*.go", "*.sol")

# Path markers that flag a registered, in-repo self-contained fixture (exempt).
# These are the converter's OWN bundled fixture corpora - the fixture IS the real
# program, there is no external source being lifted FROM. An EXTERNAL cloned-repo
# target (the fabrication surface) matches NONE of these.
#   * tools/tests/fixtures/**        - the shared test-fixture tree
#   * tools/exploit-*-fixtures/**    - the converters' bundled exploit fixtures
#                                      (e.g. tools/exploit-anchor-fixtures/)
#   * a path component literally named `fixtures` / `exploit-anchor-fixtures` etc.
_FIXTURE_PATH_RE = re.compile(
    r"(?:^|/)tools/tests/fixtures/|"
    r"(?:^|/)tools/exploit-[A-Za-z0-9_-]*fixtures/|"
    r"(?:^|/)exploit-anchor-fixtures/")


# ---------------------------------------------------------------------------
# Fixture-exemption decision.
# ---------------------------------------------------------------------------

def _has_index_fixture_role(target_file: Optional[Path]) -> bool:
    """True iff an INDEX.json carrying a fixture role marker sits at or above the
    cited target's directory (a registered self-contained fixture kit)."""
    if target_file is None:
        return False
    try:
        cur = target_file.resolve().parent
    except OSError:
        return False
    # Walk up a bounded number of directories looking for a sibling INDEX.json
    # that declares this tree as a fixture kit.
    for _ in range(8):
        idx = cur / "INDEX.json"
        if idx.is_file():
            try:
                d = json.loads(idx.read_text(encoding="utf-8", errors="replace"))
            except (json.JSONDecodeError, OSError):
                d = {}
            if isinstance(d, dict):
                schema = str(d.get("schema", ""))
                if "fixture" in schema.lower():
                    return True
                if d.get("fixture_role") or d.get("role"):
                    return True
            # an INDEX.json that lives under the fixtures tree is itself a marker
            if _FIXTURE_PATH_RE.search(str(idx).replace("\\", "/")):
                return True
        if cur.parent == cur:
            break
        cur = cur.parent
    return False


def is_self_contained_fixture(target_file: Optional[Path], fn: Optional[str]) -> bool:
    """Conservative fixture-exemption test. Returns True ONLY for runs that are
    genuinely self-contained (the fixture IS the real program, or there is no
    external cited source). Everything else returns False so the token check
    applies (false-block is safe; false-pass is the fabrication we kill)."""
    # No external cited source at all -> nothing was lifted FROM -> exempt.
    if target_file is None or not str(fn or "").strip():
        return True
    p_str = str(target_file).replace("\\", "/")
    if _FIXTURE_PATH_RE.search(p_str):
        return True
    if _has_index_fixture_role(target_file):
        return True
    return False


# ---------------------------------------------------------------------------
# Token extraction.
# ---------------------------------------------------------------------------

def _fn_body(fn_src: str) -> str:
    """Return the brace body of the located fn span (everything between the first
    `{` and the matching close). If no body is found, fall back to the whole span
    so we still derive a (weaker) token set rather than silently passing."""
    i = fn_src.find("{")
    if i < 0:
        return fn_src
    depth = 0
    for j in range(i, len(fn_src)):
        c = fn_src[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return fn_src[i + 1:j]
    return fn_src[i + 1:]


def derive_realfn_tokens(fn: str, fn_src: str) -> Set[str]:
    """Derive the distinct, non-boilerplate identifier/keyword tokens that appear
    in the real fn body (locals, called fns, account/field/struct names). The fn
    name itself is tracked separately by the caller."""
    body = _fn_body(fn_src)
    toks: Set[str] = set()
    for m in _IDENT_RE.finditer(body):
        t = m.group(0)
        if t in _BOILERPLATE:
            continue
        if t == fn:
            # the fn name is checked separately as a hard requirement
            continue
        toks.add(t)
    return toks


# ---------------------------------------------------------------------------
# Authored-source collection.
# ---------------------------------------------------------------------------

def _read_authored_sources(workdir: Optional[Path],
                           explicit: Optional[Sequence[Path]]) -> str:
    """Concatenate every authored / lifted source file the converter compiled.
    Prefers an explicit list; otherwise scans the workdir for .rs/.go/.sol files.
    Test (`tests/`) harness files are INCLUDED - the real fn may be referenced
    there by name (engine-auto-convert) and the lifted body lives in lib.rs /
    target.go which the same scan picks up."""
    blobs: List[str] = []
    seen: Set[str] = set()

    def _add(p: Path) -> None:
        rp = str(p)
        if rp in seen:
            return
        seen.add(rp)
        try:
            blobs.append(p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass

    if explicit:
        for p in explicit:
            pp = Path(p)
            if pp.is_file():
                _add(pp)
    if workdir is not None and Path(workdir).is_dir():
        for glob in _SOURCE_GLOBS:
            for p in sorted(Path(workdir).rglob(glob)):
                if p.is_file():
                    _add(p)
    return "\n".join(blobs)


def count_token_overlap(authored_src: str, fn: str,
                        realfn_tokens: Iterable[str]) -> Dict[str, Any]:
    """Return overlap metrics between the authored source and the real fn tokens:
      fn_name_present : the real fn name appears verbatim in the authored source
      body_token_hits : how many distinct real-fn-body tokens appear
      matched_tokens  : the (sorted, capped) list of matched body tokens
    """
    # Word-boundary membership for the fn name + each token.
    present_idents = set(_IDENT_RE.findall(authored_src))
    fn_present = fn in present_idents
    matched = sorted(t for t in set(realfn_tokens) if t in present_idents)
    return {
        "fn_name_present": fn_present,
        "body_token_hits": len(matched),
        "matched_tokens": matched[:25],
    }


# ---------------------------------------------------------------------------
# The guard.
# ---------------------------------------------------------------------------

def verify_realfn_tokens_or_downgrade(
    result: Dict[str, Any],
    *,
    target_file: Optional[Path],
    fn: Optional[str],
    fn_src: Optional[str],
    workdir: Optional[Path] = None,
    authored_sources: Optional[Sequence[Path]] = None,
    min_body_tokens: int = MIN_BODY_TOKENS,
) -> Dict[str, Any]:
    """Mutate + return `result`.

    If `result['verdict']` is a proof-backed-equivalent AND the run cites a real
    external source (NOT a registered self-contained fixture), require the
    authored harness/lifted source to embed the real fn NAME and >= min_body_tokens
    distinct real-fn-body tokens. On failure, downgrade to
    blocked-with-obligation and record the overlap metrics. Otherwise leave the
    verdict untouched.

    The guard records `realfn_token_guard` on every cited-real-source run it
    inspects (pass or fail) so the decision is always auditable; on exempt runs
    it records the exemption reason.
    """
    verdict = result.get("verdict")
    if verdict not in PROOF_BACKED_EQUIVALENTS:
        # Only guards a proof-backed-equivalent emission.
        return result

    tf = Path(target_file) if target_file is not None else None

    # Fixture-exemption: a self-contained fixture IS the real program.
    if is_self_contained_fixture(tf, fn):
        result["realfn_token_guard"] = {
            "applied": False,
            "exempt": True,
            "exempt_reason": (
                "self-contained-fixture-or-no-external-source: the fixture IS the "
                "real program; no external source was lifted from"),
        }
        return result

    # Cited-real-source run -> apply the token check. If the tool did not hand us
    # the located fn span, we cannot derive tokens; that is itself suspicious for
    # a proof-backed-equivalent claim, so we fail closed (downgrade).
    real_tokens: Set[str] = set()
    if fn_src:
        real_tokens = derive_realfn_tokens(fn or "", fn_src)

    authored = _read_authored_sources(
        Path(workdir) if workdir is not None else None, authored_sources)

    overlap = count_token_overlap(authored, fn or "", real_tokens)
    n_real = len(real_tokens)
    overlap["real_fn_token_count"] = n_real
    # A genuine lift embeds the WHOLE real fn body, so body_token_hits ==
    # real_fn_token_count. A small real fn may legitimately have < min_body_tokens
    # distinct non-boilerplate tokens; for such fns we require the authored source
    # to embed ALL of them (and >= 1). A larger real fn must clear the floor of
    # min_body_tokens. The fabrication signature (large real fn, ZERO/near-zero
    # hits) fails either way.
    required = min(min_body_tokens, n_real) if n_real > 0 else 1
    overlap["min_body_tokens_required"] = required
    overlap["min_body_tokens_floor"] = min_body_tokens

    passed = bool(overlap["fn_name_present"]) and (
        overlap["body_token_hits"] >= required)

    overlap["applied"] = True
    overlap["exempt"] = False
    overlap["passed"] = passed
    result["realfn_token_guard"] = overlap

    if not passed:
        # Preserve the original (now-rejected) verdict + reason for the audit
        # trail, then downgrade.
        result["pre_guard_verdict"] = verdict
        result["pre_guard_reason"] = result.get("reason")
        result["verdict"] = DOWNGRADE_VERDICT
        result["reason"] = DOWNGRADE_REASON
        result["obligation"] = (
            DOWNGRADE_REASON +
            f"; observed fn_name_present={overlap['fn_name_present']} "
            f"body_token_hits={overlap['body_token_hits']} "
            f"(need >= {min_body_tokens}). Obligation: author a harness that "
            f"drives the REAL `{fn}` from {tf.name if tf else 'the cited source'} "
            "(embed its real source span), not a synthetic generic template.")
    return result
