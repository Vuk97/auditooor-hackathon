#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-CORE-COVERAGE-GATE registered via agent-pathspec-register.py -->
"""core-coverage-completeness.py - the CORE-CONTRACT invariant-coverage gate.

WHY THIS EXISTS (the periphery-only false-green it closes)
----------------------------------------------------------
``audit-complete`` can today pass STRICT while EVERY mutation-verified stateful
invariant harness targets a PERIPHERY contract (a logging helper, a view
adapter, a config/registry shim) and NOT one of the in-scope value-moving CORE
contracts. The sibling axes do not catch this:

  - ``invariant-fuzz`` (signal) asks "was each BUILT harness multi-invariant +
    mutation-verified + actually fuzzed?" - it never asks WHICH contract the
    harness's CUT is. A periphery-only harness that is broad + non-vacuous +
    fuzzed PASSES invariant-fuzz.
  - ``cross-function-coverage`` asks "is every sibling-pair / state-machine
    COMPOSITION requirement covered?" - on a workspace whose CORE composition
    requirements happen to be expressed only in periphery modules, or where the
    core pairs are rebutted, it can pass while core value-movement is untested.
  - ``function-coverage`` / ``depth-certificate`` are per-FUNCTION / per-GUARD
    axes; neither requires a *stateful invariant harness* whose CUT is a CORE
    value-moving contract.

This gate adds the missing axis: **if the workspace flags in-scope value-moving
CORE contracts, REQUIRE >=1 mutation-verified stateful invariant harness whose
CUT (contract-under-test source file) is one of those core contracts.** A
periphery-only harness set fails closed.

WHAT IS A "CORE" CONTRACT (no per-workspace hardcoding)
-------------------------------------------------------
The core set is the set of distinct source files that contain >=1 VALUE-MOVING
function, as enumerated by the canonical producer
``tools/value-moving-functions.py`` -> ``<ws>/.auditooor/value_moving_functions.json``
(schema ``functions[].file``). This is the SAME authoritative "value-moving"
signal the honesty gate (``audit-honesty-check.py`` PATH 2) already consumes, so
there is one source of truth for "core" across the funnel. If the artifact is
absent this tool AUTO-RUNS the producer (mirroring the honesty gate), so the
gate is self-sufficient. A coverage-map override list
(``<ws>/.auditooor/core_contracts.json`` -> ``{"core_contracts": ["rel/path", ...]}``)
is UNIONED in when present, so an operator / coverage-map producer can flag
additional core contracts the value-moving heuristic missed (it can only ADD
core contracts - it can never SHRINK the set, so it is false-green-safe).

WHAT COUNTS AS A "HARNESS WHOSE CUT IS A CORE CONTRACT"
------------------------------------------------------
A mutation-verified record (from the cached
``<ws>/.auditooor/mutation_verify_coverage.json`` /
``mutation-verify-coverage.json`` artifact the sibling gates already read -
NEVER re-run here, per the tool-duplication charter) counts when BOTH hold:
  (i)  its verdict is a KILL (``non-vacuous`` / ``killed`` / ``mutation_verified
       == True``) - a vacuous / no-mutant / no-baseline record is NOT credit; and
  (ii) its ``source_file`` (CUT) normalizes to one of the core contract files.

The CUT match is path-suffix tolerant (workspace-relative tail or basename),
because mutation records store absolute or ws-relative paths while
value_moving_functions stores ws-relative paths.

SUBSTITUTION / THIN-WRAPPER / EQUIVALENT-MUTANT CLAIMS MUST BE PROVEN
--------------------------------------------------------------------
A record may instead CLAIM a core CUT is covered via substitution / equivalent-
mutant / thin-wrapper - i.e. "no behaviour-changing mutant can exist, so a
genuine kill is impossible" (the SSV updateNetworkFee pure-setter shape). That
claim is the dangerous false-green vector: "we gave up / it is a thin wrapper"
must NOT count as coverage on its own. Such records (verdict
``equivalent-mutant-only`` / ``substituted`` / ``thin-wrapper`` / ``zero-mutable``,
or a boolean ``substituted`` / ``thin_wrapper`` / ``equivalent_mutant_only`` /
``zero_mutable``, or a ``zero_mutability_proof`` object) are routed EXCLUSIVELY
through ``_zero_mutability_proven`` - they are NEVER credited through the ordinary
kill path, so a spurious ``mutants_killed`` counter cannot smuggle credit. A
substituted slot is credited ONLY when it carries a machine-checkable
0-mutability proof: an attempted mutation campaign (``mutants_attempted >= 1``)
that produced ONLY equivalent-mutant verdicts (every detail row classified
equivalent-mutant via ``tools/lib/mutation_kill.classify_kill_kind``),
``behavior_changing_kills == 0``, ``survived == 0``, and a cited per-function
``reason``. Absent that proof, the substituted slot is NOT credited (gate stays
red / reason states the missing proof).

VERDICT VOCABULARY
------------------
- ``pass-core-covered``             >=1 core contract has a mutation-verified
                                    CUT harness.
- ``pass-no-core-contracts``        the workspace flags NO value-moving core
                                    contracts (nothing to require). Not every
                                    workspace has a value-moving core surface.
- ``pass-no-source``                no in-scope source found.
- ``fail-core-coverage-periphery-only``  core contracts exist but NO
                                    mutation-verified harness targets any of
                                    them (periphery-only / no-harness).
- ``error``                         unreadable workspace / internal error.

GRACEFUL DEGRADATION (mirrors depth-certificate / cross-function / invariant-fuzz)
---------------------------------------------------------------------------------
- value-moving producer unavailable / unimportable / raises   -> the L37 signal
  wrapper WARN-passes (tooling-absence never hard-fails).
- mutation-verify artifact ABSENT (no mutation backend has run yet)  -> verdict
  ``pass-core-mutation-evidence-absent`` (this gate does not own mutation
  execution; the invariant-fuzz / cross-function gates own "you must actually
  fuzz". This gate only enforces the CUT-IS-CORE direction once mutation
  evidence exists, so it never double-penalizes a workspace for the absence the
  sibling gates already fail on).

OVERRIDE (honest-walk-back-compatible)
--------------------------------------
The L37 signal key is ``core-coverage``; the standard
``<ws>/.auditooor/audit_completeness_rebuttal.txt`` line
``core-coverage: <reason>`` (or ``all: <reason>``) flips the fail to
``ok-rebuttal`` via ``evaluate()`` in audit-completeness-check.py - the exact
same operator l37-rebuttal path every other signal inherits. No self-greening:
the rebuttal is an explicit operator-authored line, never written by this tool.

Dependency-free: stdlib only, offline-safe, never executes target code.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.core_coverage_completeness.v1"
GATE = "CORE-COVERAGE-COMPLETENESS"


# --------------------------------------------------------------------------
# Reuse the canonical equivalent-mutant classifier (single source of truth)
# from tools/lib/mutation_kill.py rather than reinventing it. If the leaf
# module is unimportable we fall back to a conservative local recogniser that
# only ever recognises FEWER tails as equivalent (never-false-pass: a tail we
# cannot classify is NOT accepted as a proven equivalent-mutant).
# --------------------------------------------------------------------------
def _load_mutation_kill_mod():
    leaf = Path(__file__).resolve().parent / "lib" / "mutation_kill.py"
    if not leaf.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_cc_mutation_kill", str(leaf))
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_cc_mutation_kill"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


_MK = _load_mutation_kill_mod()


def _tail_is_equivalent_mutant(tail) -> bool:
    """True iff ``tail`` is a genuine EVM-enforced equivalent-mutant (a mutant that
    only panics / would be 'killed' by any assertion, so it is NOT behaviour-
    changing). Reuses mutation_kill.classify_kill_kind when available. Fail-closed:
    if the classifier is unavailable OR the tail is not recognisably an equivalent
    mutant, returns False (so an unproven 'equivalent' claim does NOT count)."""
    if not isinstance(tail, str) or not tail.strip():
        return False
    if _MK is not None and hasattr(_MK, "classify_kill_kind"):
        try:
            return _MK.classify_kill_kind(tail) == "equivalent-mutant"
        except Exception:
            return False
    return False

# A mutation record counts as a genuine KILL (non-vacuous) when its verdict is
# one of these (mirrors cross-function-invariant-coverage._MUT_KILL_VERDICTS so
# there is one definition of "non-vacuous" across the funnel).
_MUT_KILL_VERDICTS = {"killed", "non-vacuous", "nonvacuous", "real", "mutation-killed"}

_VMF_REL = (".auditooor", "value_moving_functions.json")
_CORE_OVERRIDE_REL = (".auditooor", "core_contracts.json")
_MUT_RELS = (
    (".auditooor", "mutation_verify_coverage.json"),
    (".auditooor", "mutation-verify-coverage.json"),
)
_MUT_SIDECAR_DIR = (".auditooor", "cross-function-coverage")

# Source language extensions we treat as in-scope source for the no-source guard.
_SRC_EXTS = (".sol", ".vy", ".rs", ".go", ".move", ".cairo")
# Dirs never treated as in-scope source (mirrors the sibling gates' prune sets).
_SKIP_DIRS = {
    ".git", "node_modules", "lib", "out", "artifacts", "cache", "target",
    "vendor", "third_party", ".audit_logs", ".auditooor", "submissions",
    "prior_audits", "reports", "docs", "test", "tests", "mocks",
}


def _read_json(p: Path):
    try:
        if not (p.is_file() and p.stat().st_size > 0):
            return None
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _has_in_scope_source(ws: Path) -> bool:
    try:
        for p in ws.rglob("*"):
            if not p.is_file() or p.suffix not in _SRC_EXTS:
                continue
            if set(p.parts) & _SKIP_DIRS:
                continue
            return True
    except OSError:
        return False
    return False


# --------------------------------------------------------------------------
# Core-contract set (value-moving producer + optional override union).
# --------------------------------------------------------------------------
def _load_vmf_module():
    """Load tools/value-moving-functions.py by path (dashed filename); else None."""
    tool = Path(__file__).resolve().with_name("value-moving-functions.py")
    if not tool.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_cc_vmf", str(tool))
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules["_cc_vmf"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _norm_path_keys(rel: str) -> set:
    """Return the set of normalized match-keys for a source path: the basename
    and the full posix-normalized relative path (lower-cased). Used so a
    mutation record's ``source_file`` (absolute or ws-relative) joins to a
    value-moving ``file`` (ws-relative) by path-suffix / basename."""
    if not rel:
        return set()
    rel = rel.replace("\\", "/").strip()
    keys = {rel.lower()}
    base = rel.rsplit("/", 1)[-1]
    if base:
        keys.add(base.lower())
    return keys


# This gate enforces a MEDUSA (Solidity) mutation-verified stateful-invariant
# harness. Medusa can only harness Solidity/Vyper. Go/Rust value-moving "core"
# files therefore CANNOT have a medusa harness - their invariant coverage is owned
# by the go-engine / rust native-test axes (separate audit-complete gates). Counting
# them in THIS gate's denominator is a category error (e.g. optimism op-dispute-mon
# monitoring .go files showed up as "uncovered core" that medusa can never cover).
# We scope the medusa core set to Solidity and SURFACE the deferred Go/Rust count
# (no silent cap). This never weakens the Solidity requirement.
_MEDUSA_CORE_EXTS = (".sol", ".vy")


def _core_contract_files(ws: Path):
    """Return (core_files: set[str ws-rel Solidity], tool_available, vmf_count,
    deferred_non_medusa: sorted list of Go/Rust/other core files deferred to their
    own engine axes).

    core_files is the union of (a) every distinct ``file`` carrying a
    value-moving function per value_moving_functions.json (auto-generated via
    value-moving-functions.py if absent) and (b) an optional operator/coverage-
    map override list (can only ADD). tool_available is False ONLY when the
    value-moving producer is unimportable AND no cached artifact exists - that
    is the tooling-absence the L37 wrapper degrades to WARN-pass on."""
    core: set = set()
    tool_available = True
    vmf_count = 0

    vmf_path = ws / _VMF_REL[0] / _VMF_REL[1]
    payload = _read_json(vmf_path)
    if payload is None:
        # Auto-run the canonical producer (mirrors audit-honesty-check PATH 2).
        mod = _load_vmf_module()
        if mod is None:
            tool_available = False
        else:
            try:
                mod.run(ws)
            except Exception:
                tool_available = False
            payload = _read_json(vmf_path)

    if isinstance(payload, dict):
        for rec in payload.get("functions", []) or []:
            if isinstance(rec, dict):
                f = rec.get("file")
                if isinstance(f, str) and f.strip():
                    core.add(f.strip())
                    vmf_count += 1

    # Optional override union (can only ADD core contracts; never shrinks).
    ov = _read_json(ws / _CORE_OVERRIDE_REL[0] / _CORE_OVERRIDE_REL[1])
    if isinstance(ov, dict):
        for f in ov.get("core_contracts", []) or []:
            if isinstance(f, str) and f.strip():
                core.add(f.strip())

    # Language scope: keep only Solidity/Vyper (what medusa can harness). Go/Rust
    # value-moving core defer to their own engine coverage axes - surface them so
    # the deferral is explicit, never silent.
    medusa_core = {f for f in core if f.lower().endswith(_MEDUSA_CORE_EXTS)}
    deferred = sorted(core - medusa_core)
    return medusa_core, tool_available, vmf_count, deferred


# --------------------------------------------------------------------------
# Mutation-verified CUT set (cached artifact only - never re-run).
# --------------------------------------------------------------------------
def _records_from_payload(payload) -> list:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("results", "verdicts", "harnesses", "functions", "mutations", "records"):
        v = payload.get(key)
        if isinstance(v, list):
            return [r for r in v if isinstance(r, dict)]
    if payload.get("verdict") is not None and payload.get("source_file") is not None:
        return [payload]
    if payload.get("verdict") is not None and payload.get("function") is not None:
        return [payload]
    # Durable mvc_sidecar / cross-function cluster schema: a single dict that
    # records a whole harness campaign (cluster-level: harness_path + invariants[]
    # + mutation_detail[] + mutants_killed) rather than a list of per-function
    # rows. Recognize it so genuine >=1M-call core harnesses are credited - else
    # core-coverage silently ignores the very durable sidecars it is documented to
    # read (the LiquidRestaking/CashSolvency etherfi sidecars hit exactly this:
    # real DebtManagerCore/LiquidityPool CUTs, 0 credit). _record_is_kill gates it
    # downstream, so a vacuous (0-kill) cluster still cannot false-green.
    if any(k in payload for k in ("mutation_verified", "mutants_killed", "mutation_detail")):
        return [payload]
    return []


def _record_is_kill(rec: dict) -> bool:
    """True iff the record is a genuine mutation KILL (non-vacuous). False-green
    safe: a bare ``mutation_verified`` flag is NOT enough on its own unless the
    verdict is also a kill - a record can be ``mutation_verified: true`` while
    its verdict is ``vacuous`` (the producer flags it ran the verifier but the
    harness killed nothing). We require an actual kill verdict OR an explicit
    ``killed``/``non_vacuous`` boolean."""
    for key in ("mutation_verdict", "verdict", "status", "disposition"):
        v = rec.get(key)
        if isinstance(v, str) and v.strip().lower() in _MUT_KILL_VERDICTS:
            return True
    for key in ("killed", "mutation_killed", "non_vacuous"):
        if rec.get(key) is True:
            return True
    # Cluster-level mvc_sidecar: a genuine kill is recorded as mutants_killed>=1
    # (a vacuous harness records 0), or any mutation_detail row whose mutant was
    # CAUGHT by a property (mutant_result/result == FAIL == mutant killed).
    mk = rec.get("mutants_killed")
    if isinstance(mk, int) and mk >= 1:
        return True
    md = rec.get("mutation_detail")
    if isinstance(md, list):
        for m in md:
            if isinstance(m, dict):
                r = m.get("mutant_result") or m.get("result") or ""
                if isinstance(r, str) and r.strip().lower() in ("fail", "failed", "killed", "broken", "caught"):
                    return True
    return False


# A record is a SUBSTITUTION / equivalent-mutant / thin-wrapper claim when it
# asserts the core CUT needs no genuine behaviour-changing kill because the
# contract is (allegedly) 0-mutable - a pure pass-through / thin wrapper (e.g.
# the SSV updateNetworkFee setter). Such a claim is the dangerous false-green
# vector: "we gave up / it is a thin wrapper" must NOT pass as coverage on its
# own. It is credited ONLY when it carries a machine-checkable 0-mutability proof
# (see _zero_mutability_proven). These markers are matched verdict-exact / boolean
# to avoid catching a genuine non-vacuous record.
_SUBSTITUTION_VERDICTS = {
    "equivalent-mutant-only", "equivalent-mutant", "equivalentmutantonly",
    "substituted", "thin-wrapper", "thin_wrapper", "zero-mutable", "zero_mutable",
}
_SUBSTITUTION_BOOL_KEYS = (
    "substituted", "thin_wrapper", "equivalent_mutant_only",
    "equivalent_mutant", "zero_mutable",
)


def _record_is_substitution(rec: dict) -> bool:
    """True iff the record CLAIMS the core CUT is covered via substitution /
    equivalent-mutant / thin-wrapper (0-mutability) rather than a genuine
    behaviour-changing kill. Such a record is routed to the proof gate and is
    NEVER credited through the ordinary _record_is_kill path - so a substitution
    claim cannot smuggle credit via a spurious mutants_killed counter."""
    if not isinstance(rec, dict):
        return False
    for key in ("mutation_verdict", "verdict", "status", "disposition"):
        v = rec.get(key)
        if isinstance(v, str) and v.strip().lower() in _SUBSTITUTION_VERDICTS:
            return True
    for key in _SUBSTITUTION_BOOL_KEYS:
        if rec.get(key) is True:
            return True
    # An explicit zero-mutability proof object present at all is, by intent, a
    # substitution claim (it exists precisely to credit a 0-mutable contract).
    if isinstance(rec.get("zero_mutability_proof"), dict):
        return True
    return False


def _zero_mutability_proven(rec: dict) -> bool:
    """True iff the record carries a MACHINE-CHECKABLE 0-mutability proof: an
    attempted mutation campaign that produced ONLY equivalent-mutant verdicts
    (i.e. NO behaviour-changing mutant can exist), with a cited per-function
    reason. This is the only path by which a substitution / thin-wrapper slot is
    credited. NEVER-FALSE-PASS - ALL of the following must hold:

      - the proof lives under ``zero_mutability_proof`` (a dict) OR the record's
        own top-level fields carry the same evidence;
      - ``mutants_attempted`` (a.k.a. attempted / mutants_total) is an int >= 1
        (a campaign with zero attempted mutants proves nothing);
      - ``behavior_changing_kills`` == 0 (a single behaviour-changing kill means
        the contract IS mutable, so this is not a thin wrapper - it must be
        covered by a real harness, not substituted);
      - ``survived`` (a.k.a. survived_count) == 0 (a surviving mutant means the
        harness did NOT detect a real mutation, i.e. vacuity, not 0-mutability);
      - every attempted mutant is classified an equivalent-mutant: the detail
        list is non-empty and EVERY row is a genuine equivalent-mutant (verdict
        token or a tail that mutation_kill.classify_kill_kind judges equivalent);
      - a non-empty ``reason`` string is present (the cited per-function rationale).

    Any missing / failing element -> False (slot NOT credited)."""
    proof = rec.get("zero_mutability_proof")
    src = proof if isinstance(proof, dict) else rec

    def _int(*keys):
        for k in keys:
            v = src.get(k)
            if isinstance(v, bool):
                continue
            if isinstance(v, int):
                return v
        return None

    attempted = _int("mutants_attempted", "attempted", "mutants_total", "total")
    bck = _int("behavior_changing_kills", "behavior_changing_kill_count")
    survived = _int("survived", "survived_count")

    if not (isinstance(attempted, int) and attempted >= 1):
        return False
    if bck != 0:
        return False
    if survived != 0:
        return False

    reason = src.get("reason")
    if not (isinstance(reason, str) and reason.strip()):
        return False

    # Every attempted mutant must be a genuine equivalent-mutant. We accept a row
    # that is EITHER (a) explicitly verdict-tagged equivalent-mutant, OR (b)
    # carries an output_tail the canonical classifier judges equivalent-mutant.
    # The detail list must be non-empty and account for >= attempted rows, so a
    # claim of "5 attempted, ONLY equivalent" cannot be made with 0 evidenced rows.
    rows = None
    for k in ("mutant_results", "mutation_detail", "mutants", "equivalent_mutants"):
        v = src.get(k)
        if isinstance(v, list):
            rows = v
            break
    if not rows:
        return False
    equivalent_rows = 0
    for m in rows:
        if not isinstance(m, dict):
            return False
        verdict = (m.get("kill_kind") or m.get("verdict") or m.get("mutant_result")
                   or m.get("result") or "")
        is_equiv = (isinstance(verdict, str)
                    and verdict.strip().lower() in ("equivalent-mutant", "equivalent_mutant",
                                                    "equivalent-mutant-only"))
        if not is_equiv:
            is_equiv = _tail_is_equivalent_mutant(m.get("output_tail"))
        # A row that is a genuine behaviour-changing kill or a surviving mutant
        # contradicts 0-mutability -> proof invalid.
        if not is_equiv:
            return False
        equivalent_rows += 1
    if equivalent_rows < attempted:
        return False
    return True


def _record_cut_paths(rec: dict) -> set:
    """The CUT (contract-under-test) source path(s) a mutation record names."""
    out: set = set()
    for key in ("source_file", "cut", "contract_file", "target_file", "file"):
        v = rec.get(key)
        if isinstance(v, str) and v.strip():
            out |= _norm_path_keys(v.strip())
    # Durable mvc_sidecar cluster schema: explicit CUT contract list.
    cc = rec.get("cut_contracts")
    if isinstance(cc, list):
        for v in cc:
            if isinstance(v, str) and v.strip():
                out |= _norm_path_keys(v.strip())
    # Mutant descriptions name the mutated contract as the leading identifier,
    # e.g. "DebtManagerCore supply 2x shares" / "WeETH.wrap over-mint +1" /
    # "LiquidityPool._sharesForDepositAmount +5% over-credit". The mutated
    # contract IS a CUT, so extract its CamelCase name -> <name>.sol basename
    # key. Joins to the core set by basename only (_norm_path_keys), so it can
    # only credit a contract that is ALREADY in the value-moving core set - it
    # cannot false-green a non-core contract.
    md = rec.get("mutation_detail")
    if isinstance(md, list):
        for m in md:
            if not isinstance(m, dict):
                continue
            mut = m.get("mutant") or m.get("description") or ""
            if isinstance(mut, str):
                mobj = re.match(r"\s*([A-Z][A-Za-z0-9_]+)", mut)
                if mobj:
                    out.add(mobj.group(1).lower() + ".sol")
    return out


def _mutation_killed_cut_keys(ws: Path):
    """Return (cut_keys: set[str], available: bool). cut_keys is the union of
    normalized path-keys of every CUT with >=1 genuine mutation KILL, read ONLY
    from the cached artifact (offline; never re-runs mutation testing)."""
    cut_keys: set = set()
    available = False
    candidates = [ws / a / b for a, b in _MUT_RELS]
    # Read the DURABLE per-record sidecars (cross-function-coverage + mvc_sidecar).
    # mutation_verify_coverage.json above is CLOBBERED by a fresh audit-deep-solidity
    # run (it rewrites it from the auto-scaffold harnesses, wiping hand-recorded
    # premade-mutant records), so core-coverage must also read the durable sidecars -
    # else a deep re-run silently regresses recorded core coverage (6/31 -> 2/31).
    # Glob *.json (records are operator-named, e.g. liqctl_mint_premade_mutant.json),
    # not just mutation*.json; _record_is_kill gates each so this cannot false-green.
    for _sd in ("cross-function-coverage", "mvc_sidecar"):
        sidecar = ws / ".auditooor" / _sd
        if sidecar.is_dir():
            try:
                candidates.extend(sorted(sidecar.glob("*.json")))
            except OSError:
                pass
    for cand in candidates:
        payload = _read_json(cand)
        if payload is None:
            continue
        available = True
        for rec in _records_from_payload(payload):
            # SUBSTITUTION / equivalent-mutant / thin-wrapper claims are routed
            # EXCLUSIVELY through the 0-mutability proof gate - they are NEVER
            # credited via the ordinary kill path, so a "we gave up / it is a thin
            # wrapper" record cannot smuggle credit via a spurious mutants_killed
            # counter or a kill verdict. Credited ONLY with a machine-checkable
            # proof (attempted >= 1 mutants, ALL equivalent, 0 behaviour-changing,
            # 0 survived, cited reason). Absent the proof: no credit (gate stays red).
            if _record_is_substitution(rec):
                if _zero_mutability_proven(rec):
                    cut_keys |= _record_cut_paths(rec)
                continue
            if _record_is_kill(rec):
                cut_keys |= _record_cut_paths(rec)
    return cut_keys, available


def _core_keys(core_files: set) -> dict:
    """Map each core contract file -> its normalized match-key set."""
    return {f: _norm_path_keys(f) for f in core_files}


# --------------------------------------------------------------------------
# Evaluate
# --------------------------------------------------------------------------
def evaluate(ws) -> dict:
    ws = Path(ws)
    base = {"schema": SCHEMA, "gate": GATE}
    if not ws.is_dir():
        return {**base, "verdict": "error", "reason": f"workspace not found: {ws}",
                "core_contracts": [], "covered_core": [], "core_count": 0,
                "covered_core_count": 0}

    core_files, tool_available, vmf_count, deferred_non_medusa = _core_contract_files(ws)
    base = {**base, "deferred_non_medusa_core": deferred_non_medusa,
            "deferred_non_medusa_core_count": len(deferred_non_medusa)}

    if not tool_available:
        # Tooling absence: let the L37 wrapper degrade to WARN-pass. Surface a
        # distinct verdict so the wrapper can recognise it explicitly.
        return {**base, "verdict": "pass-tooling-absent",
                "reason": "value-moving-functions producer unavailable; "
                          "core-coverage degraded (tooling-absence)",
                "core_contracts": [], "covered_core": [], "core_count": 0,
                "covered_core_count": 0, "tool_available": False}

    if not core_files:
        if not _has_in_scope_source(ws):
            return {**base, "verdict": "pass-no-source",
                    "reason": "no in-scope source found",
                    "core_contracts": [], "covered_core": [], "core_count": 0,
                    "covered_core_count": 0}
        return {**base, "verdict": "pass-no-core-contracts",
                "reason": "no in-scope value-moving CORE contract flagged "
                          "(value_moving_functions.json empty); nothing to require",
                "core_contracts": [], "covered_core": [], "core_count": 0,
                "covered_core_count": 0, "vmf_function_count": vmf_count}

    cut_keys, mut_available = _mutation_killed_cut_keys(ws)

    if not mut_available:
        # No mutation evidence on disk at all. This gate does NOT own "you must
        # fuzz" (invariant-fuzz / cross-function own that). It only enforces
        # CUT-IS-CORE once evidence exists. So when there is NO mutation
        # artifact, do not double-penalize - PASS with a distinct, loud verdict.
        return {**base, "verdict": "pass-core-mutation-evidence-absent",
                "reason": f"{len(core_files)} value-moving core contract(s) "
                          "flagged but NO mutation-verify artifact on disk yet; "
                          "core-CUT requirement deferred to invariant-fuzz / "
                          "cross-function (which own 'must actually fuzz')",
                "core_contracts": sorted(core_files), "covered_core": [],
                "core_count": len(core_files), "covered_core_count": 0,
                "mutation_evidence_available": False}

    keys_by_core = _core_keys(core_files)
    covered = sorted(
        c for c, ks in keys_by_core.items() if ks & cut_keys
    )

    core_count = len(core_files)
    if covered:
        return {**base, "verdict": "pass-core-covered",
                "reason": f"{len(covered)}/{core_count} value-moving core "
                          f"contract(s) have a mutation-verified CUT harness "
                          f"(e.g. {covered[0]})",
                "core_contracts": sorted(core_files), "covered_core": covered,
                "core_count": core_count, "covered_core_count": len(covered),
                "mutation_evidence_available": True}

    sample = sorted(core_files)[:8]
    return {**base, "verdict": "fail-core-coverage-periphery-only",
            "reason": f"0/{core_count} value-moving CORE contract(s) have a "
                      f"mutation-verified stateful invariant harness whose CUT "
                      f"is the core contract - every mutation-verified harness "
                      f"targets PERIPHERY. Uncovered core: "
                      f"{', '.join(sample)}{' ...' if core_count > 8 else ''}",
            "core_contracts": sorted(core_files), "covered_core": [],
            "core_count": core_count, "covered_core_count": 0,
            "uncovered_core": sorted(core_files),
            "mutation_evidence_available": True}


def check(ws) -> dict:
    """Alias mirroring the sibling gates' check()/evaluate() pair + a worklist."""
    res = evaluate(ws)
    if res.get("verdict") == "fail-core-coverage-periphery-only":
        res["worklist"] = [
            {
                "core_contract": c,
                "action": "author a stateful invariant harness whose CUT is "
                          f"{c}, then run mutation-verify-coverage.py over it",
            }
            for c in res.get("uncovered_core", [])
        ]
    return res


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Core-contract invariant-coverage gate.")
    ap.add_argument("--workspace", "-w", required=True)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 on fail-core-coverage-periphery-only")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    res = check(Path(args.workspace))
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[{GATE}] verdict={res['verdict']} "
              f"covered_core={res.get('covered_core_count', 0)}/"
              f"{res.get('core_count', 0)} -- {res['reason']}")
        for row in res.get("worklist", []):
            print(f"  UNCOVERED CORE: {row['core_contract']}")

    if res["verdict"] == "error":
        return 2
    if args.check and res["verdict"] == "fail-core-coverage-periphery-only":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
