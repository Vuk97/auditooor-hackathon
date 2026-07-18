#!/usr/bin/env python3
"""Shared mutation-KILL genuineness predicates (single source of truth).

PRINCIPLE (taxonomy modes 9, 12, 16)
------------------------------------
A mutant "kill" is only genuine evidence that a harness CATCHES a behaviour
change if the failing output names a real invariant/property assertion frame -
NOT merely a setUp()/compile/cast revert that broke the harness scaffold, and
NOT merely an EVM-enforced Panic (0x11 underflow / 0x01 overflow) that ANY
assertion (even `assert(true)`) after the revert would "kill".

Historically `_is_genuine_invariant_kill` lived ONCE at
`invariant-fuzz-completeness.py:~252` and only ONE consumer applied it, while the
PRODUCER (`mutation-verify-coverage.py`) and two other consumers
(`engine-harness-proof-check.py`, `audit-honesty-check.py`) keyed on a bare
`status == "fail"` / `killed` bool. That asymmetry let a disk artifact record
`non-vacuous` for kills that never ran the property (near-intents finTransfer 6/6
`[FAIL] setUp()`, mode 12) and credited panic-only equivalent mutants as genuine
(ssv deposit `+=`->`-=`, mode 9). This module promotes the predicate to a single
shared home so the producer and every consumer agree.

This is a pure-stdlib leaf module (no imports of sibling hyphenated tools), safe
to load via `importlib` from any tool that needs the predicate.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

# Frames that mark a GENUINE invariant/property assertion failure (the harness's
# own property fired). A kill whose only failing frame is one of these is real.
_ASSERTION_TOKENS = ("invariant_", "property_", "echidna_", "check_")

# EVM-enforced panic codes / tokens: a mutant that only triggers one of these is
# an equivalent-mutant - the revert is enforced by the VM, not by the harness's
# property, so it proves nothing about the harness's catching power (mode 9).
_PANIC_RE = re.compile(
    r"panic\(uint256\)|panic:\s*0x(?:11|01)\b|\b0x11\b|\b0x01\b|"
    r"arithmetic\s+(?:over|under)flow|division\s+or\s+modulo\s+by\s+zero",
    re.I,
)

# A mutant output is a KILL when it carries ANY failure signal the producer's
# verdict classifier (mutation-verify-coverage.py::_classify -> _FAIL_TOKENS /
# the medusa/echidna FAIL regexes) treats as a harness FAILURE. The previous
# `"fail" not in low and "panic" not in low` guard here was NARROWER than that
# producer set: a real Halmos/symbolic counterexample prints just
# `Counterexample:` (no "fail"/"panic" substring) and echidna prints `: falsified`
# / `: failing` - the producer classified those as a genuine FAIL, but
# classify_kill_kind then returned `not-a-kill`, so a real silent-baseline harness
# that FLIPPED to a counterexample on a mutant collapsed to no-property-discovered
# (the beanstalk/mezo/morpho-midnight symptom). This regex re-aligns the kill
# marker with the producer's fail set. It stays FAIL-CLOSED: a tail with NONE of
# these signals (a silent stub that kills nothing) is still `not-a-kill`.
#
# OVER-MATCH HAZARD (fixed): the fail markers below are substring/word patterns
# that ALSO appear inside NEGATED / PASSING phrases - "No counterexample found",
# "no failing sequence", "0 failing tests", "counterexample search exhausted", and
# the standard forge summary "5 passed; 0 failed" all contain a fail token even
# though the run PASSED. Crediting those as a kill is a FAIL-OPEN over-credit (a
# passing baseline would be read as a behaviour-changing kill). To stay aligned
# with the producer - whose _classify checks the medusa/echidna PASS regexes and
# _PASS_TOKENS BEFORE the generic fail-token scan - _has_kill_marker first applies
# a PASS-OVERRIDE: if the tail is authoritatively a PASS, it is NOT a kill, no
# matter which fail substring also appears. A genuine medusa/forge FAIL summary
# ("1 test(s) failed", "5 passed; 1 failed") is NOT a pass and is unaffected.
_KILL_MARKER_RE = re.compile(
    r"\bfail\b|\bfailed\b|\bfailing\b|\bpanic\b|counterexample|falsified|"
    r"assertion\s+(?:failed|violated)|failing\s+assertion|\[fail\]|"
    r":\s*failed!|--- fail:|test\s+result:\s+failed|test\(s\)\s+failed",
    re.I,
)

# PASS-OVERRIDE: authoritative pass signals that win over a co-occurring fail
# substring (mirrors the producer's pass-first precedence in _classify). Each
# alternative is anchored so it cannot itself be a disguised failure:
#   - medusa pass summary "N test(s) passed, 0 test(s) failed"
#   - forge pass summary "test result: ok. N passed; 0 failed" / "N passed; 0 failed"
#   - echidna per-property "<name>: passing"
#   - halmos / symbolic "no counterexample" / "counterexample search exhausted" /
#     "property holds" / "no failing sequence" / "0 failing"
# The medusa/forge "0 failed" tail is required so a mixed "5 passed; 1 failed" run
# is NOT swallowed (that is a genuine kill).
_PASS_OVERRIDE_RE = re.compile(
    r"\d+\s+test\(s\)\s+passed,\s*0\s+test\(s\)\s+failed|"          # medusa pass
    r"test\s+result:\s*ok\b|"                                        # forge ok
    r"\b\d+\s+passed;\s*0\s+failed\b|"                               # forge "N passed; 0 failed"
    r"\b\d+\s+passed,\s*0\s+failed\b|"                               # forge variant w/ comma
    r":\s*passing\b|"                                                # echidna passing
    r"no\s+counterexample|counterexample\s+search\s+exhausted|"      # halmos no-CEX
    r"property\s+holds|no\s+failing\s+sequence|"                     # medusa/halmos pass prose
    r"\b0\s+failing\b|\bno\s+failing\s+tests?\b",                    # "0 failing" / "no failing tests"
    re.I,
)


# A genuine engine FAIL summary that must WIN over any pass-override (mirrors the
# producer's _MEDUSA_FAIL_RE / _ECHIDNA_FAIL_RE being checked BEFORE the pass
# regexes). A medusa "M>0 test(s) failed", a forge "N failed" with N>=1, an
# echidna ": failed!"/": falsified", or a raw counterexample are real kills even
# if the same multi-test tail also prints a per-test "ok"/"passing" line.
_FAIL_SUMMARY_RE = re.compile(
    r"[1-9]\d*\s+test\(s\)\s+failed|"          # medusa M>0 failed
    r"[1-9]\d*\s+failed\b|"                     # forge "N failed" N>=1 (incl. "1 failed")
    r":\s*failed!|:\s*falsified|"              # echidna fail verdict
    r"^\s*counterexample:|\ncounterexample:",  # explicit counterexample frame
    re.I | re.M,
)


def _is_pass_override(tail: str) -> bool:
    """True iff the tail carries an authoritative PASS signal that must win over a
    co-occurring fail substring (negated phrase / passing summary), AND carries no
    genuine engine FAIL summary. Mirrors the producer's pass-first precedence (with
    medusa/echidna FAIL checked first) so a passing baseline is never read as a kill
    while a real mixed-run failure is still a kill."""
    t = tail or ""
    if _FAIL_SUMMARY_RE.search(t):
        return False
    return bool(_PASS_OVERRIDE_RE.search(t))


def _has_kill_marker(tail: str) -> bool:
    """True iff the mutant output_tail carries a recognized harness-FAILURE signal
    (the same fail set the producer's _classify uses) AND is not authoritatively a
    PASS. Used as the kill-vs-no-kill discriminator in classify_kill_kind.
    Fail-closed: no marker -> no kill; a PASS-override tail -> no kill (never
    over-credit a passing/negated run as a behaviour-changing kill)."""
    t = tail or ""
    if _is_pass_override(t):
        return False
    return bool(_KILL_MARKER_RE.search(t))


def _is_genuine_invariant_kill(tail: str) -> bool:
    """True iff the failing mutant output shows an actual invariant/property
    assertion failing - NOT merely a setUp()/compile/cast revert that broke the
    harness scaffold (which proves nothing about the invariant's catching power).

    Promoted VERBATIM from invariant-fuzz-completeness.py:252 (mode 12). A kill
    whose ONLY failing frame is setUp()/compile/cast is reclassified
    harness-broken-by-mutant by the callers."""
    t = tail or ""
    low = t.lower()
    if "fail" not in low:
        return False
    has_assertion = any(tok in t for tok in ("invariant_", "property_", "echidna_"))
    if not has_assertion:
        return False
    # If the ONLY failing frame is setUp() (no invariant_/property_ on a FAIL line),
    # it is a scaffold-revert kill. Require an assertion token to co-occur with a
    # failing-test marker that is not exclusively the setUp frame.
    if "setUp()" in t and not re.search(
            r"(?:invariant_|property_|echidna_)\w*\s*\(\)[^\n]*(?:fail|FAIL)", t):
        # the failing line names setUp, not an invariant -> scaffold revert
        if re.search(r"\bsetUp\(\)\b[^\n]*(?:fail|FAIL)", t):
            return False
    return True


def classify_kill_kind(tail: str) -> str:
    """Classify a mutant's failing output_tail into a kill_kind.

    Returns one of:
      "harness-broken-by-mutant" - the failing frame is ONLY setUp()/compile/
            cast (mode 12). NOT a genuine kill: the property never executed.
      "equivalent-mutant"        - the only failing signal is an EVM-enforced
            panic (0x11/0x01 over/underflow, div-by-zero) with no
            invariant_/property_/echidna_/check_ assertion frame (mode 9). Any
            assertion would "kill" this, so it is not behaviour-changing.
      "behavior-changing"        - a real invariant/property/echidna/check_
            assertion frame fired (the genuine, credited kill).
      "not-a-kill"               - no failure marker at all.

    Only "behavior-changing" should count toward verdict=non-vacuous (P1-a)."""
    t = tail or ""
    low = t.lower()
    # Kill-vs-no-kill uses the SAME fail set as the producer's _classify (a real
    # Halmos counterexample / echidna `: falsified` is a FAIL there but carries no
    # "fail"/"panic" substring). A tail with no recognized failure signal is not a
    # kill. Fail-closed: a silent stub (no marker) stays not-a-kill.
    if not _has_kill_marker(t):
        return "not-a-kill"
    has_assertion = any(tok in t for tok in _ASSERTION_TOKENS)
    # SCAFFOLD-BREAK signal (mode 12): the failure is a setUp()/compile/cast revert
    # that broke the harness's own scaffold, NOT the property firing. Reclassify
    # harness-broken-by-mutant. The genuine-kill predicate already rejects a
    # setUp()-only failing frame; we additionally catch compile/cast scaffold breaks.
    _scaffold = (
        ("setup()" in low and not _has_assertion_fail_frame(t))
        or (("compilation failed" in low or "compile error" in low
             or "could not compile" in low) and not has_assertion)
    )
    if _scaffold:
        return "harness-broken-by-mutant"
    # EQUIVALENT-MUTANT (mode 9): the ONLY failure signal is an EVM-enforced panic
    # (0x11/0x01 over/underflow, div-by-zero) - any assertion would "kill" it. This
    # holds whether or not an assertion frame is named, as long as there is no
    # NON-panic behaviour-changing assertion failure.
    if _PANIC_RE.search(t) and not _has_nonpanic_assertion_failure(t):
        return "equivalent-mutant"
    # Otherwise a genuine behaviour-changing kill: a counterexample / falsified /
    # assertion-violated / relational failure that the harness's property caught
    # (with or without a named invariant_/property_ frame in the truncated tail).
    return "behavior-changing"


def _has_assertion_fail_frame(tail: str) -> bool:
    """True iff a named invariant_/property_/echidna_/check_ frame appears on a
    FAIL line (so the failure is the property, not only setUp)."""
    t = tail or ""
    return bool(re.search(
        r"(?:invariant_|property_|echidna_|check_)\w*\s*\(\)[^\n]*(?:fail|FAIL)", t)) \
        or bool(re.search(
            r"(?:invariant_|property_|echidna_|check_)\w*[^\n]*(?:failed!|falsified|"
            r"assertion\s+(?:failed|violated))", t, re.I))


def _has_nonpanic_assertion_failure(tail: str) -> bool:
    """True iff the output shows an invariant/property/echidna/check_ assertion
    failure that is NOT solely an EVM panic (i.e. a behaviour-changing kill -
    assertion-violated / counterexample / falsified / require failure that the
    harness's own property caught, distinct from a VM-enforced over/underflow)."""
    t = tail or ""
    # An assertion-failure frame plus a NON-panic failure verb is behaviour-changing.
    nonpanic_fail = re.search(
        r"(assertion\s+failed|assertion\s+violated|counterexample|falsified|"
        r"failing\s+assertion|require|invariant\s+violated|: failed!)",
        t, re.I,
    )
    has_assertion_frame = any(tok in t for tok in _ASSERTION_TOKENS)
    return bool(has_assertion_frame and nonpanic_fail)


def is_behavior_changing_kill(tail: str) -> bool:
    """Convenience: True iff classify_kill_kind == 'behavior-changing'."""
    return classify_kill_kind(tail) == "behavior-changing"


# ---------------------------------------------------------------------------
# CANONICAL mvc_sidecar credit predicate (caveat A: schema normalization).
#
# TWO sidecar schemas exist for the SAME ground truth (a harness proven non-vacuous
# by a real mutant kill):
#   (1) auto-producer (mutation-verify-coverage.py::_persist_durable_sidecar):
#       keys verdict=='non-vacuous', killed_count, behavior_changing_kill_count,
#       genuine_coverage, mutant_results[] - and NO `mutation_verified` key.
#   (2) manual-registration (register_manual_mvc): keys verdict=='non-vacuous',
#       mutation_verified=True, mutants_killed, mutant_results[] - and NO
#       `genuine_coverage` key.
#   (3) durable cluster: mutation_verified=True + mutants_killed / mutation_detail[]
#       / mutation_verify[] (KILLED rows) - often NO verdict key.
#
# A reader that keyed on `mutation_verified` MISSED schema (1); a reader that keyed
# on `genuine_coverage` MISSED schema (2) - the classic serving-join: genuine
# evidence sits in a field the reader does not look at. This predicate is the
# SINGLE canonical answer all readers share so producer and every consumer agree.
#
# FAIL-CLOSED (never weaken a guard, never over-credit):
#   credited IFF (verdict=='non-vacuous' AND >=1 real kill)
#            OR  (mutation_verified is True AND >=1 real kill)   [cluster, no verdict]
# A record with verdict!='non-vacuous' AND mutation_verified!=True is NOT credited.
# A record with ZERO real kills is NOT credited, in EITHER schema. "Real kill" is
# the un-fakeable ground truth: a positive kill counter, OR a mutant_results row
# that is killed + (genuine behaviour-changing tail OR no tail/kill_kind to judge),
# OR a cluster mutation_detail/mutation_verify FAIL/KILLED row.
# ---------------------------------------------------------------------------
_CLUSTER_KILL_TOKENS = ("fail", "failed", "killed", "broken", "caught")

# ---------------------------------------------------------------------------
# E2 (2026-07-03): reject a cluster mutation_verify/mutation_detail KILLED row
# that carries NO run evidence - a `verdict=='killed'` STRING alone is not proof
# the mutant was ever executed. CONFIRMED SSV fabrication: ssv_eb_accounting.json
# mutation_verify[] lists 3 rows each `verdict=='KILLED'` with output_tail=None,
# evidence_logs=None, mutant=None, and NO property-name hit anywhere in the run
# logs - the mutants were never run (the workspace's own NEXT_TICK_INVARIANT_FUZZ
# admits this). The claimed kill_sequence / calls_to_kill / property_killed fields
# are typed CLAIMS, not run evidence - anyone can type them into the JSON - so they
# do NOT satisfy the evidence bar. Real run evidence is ONE of: a non-empty
# output_tail; a non-empty evidence_logs / kill_log / log_path pointer; a
# mutants_run/calls counter >= 1; or an explicit engine result string.
#
# ADVISORY-FIRST + NEVER-RETRO-RED: the stricter predicate is applied ONLY when the
# named default-OFF env AUDITOOOR_MUTATION_KILL_RUN_EVIDENCE_STRICT is set. When the
# env is unset the behaviour is BYTE-IDENTICAL to before (a token-string KILLED row
# still counts) so no prior audit is retroactively re-failed. NEVER-FALSE-PASS: a
# row WITH genuine run evidence still credits under strict.
# ---------------------------------------------------------------------------
_RUN_EVIDENCE_STRICT_ENV = "AUDITOOOR_MUTATION_KILL_RUN_EVIDENCE_STRICT"


def _run_evidence_strict() -> bool:
    """Uniform gate-strict semantics (2026-07-03 graduate-to-default-ON, operator
    decision overriding the prior default-OFF posture): require per-KILL run evidence
    for a cluster mutation_verify/mutation_detail row when the gate is enforced.
      - explicit opt-out  AUDITOOOR_MUTATION_KILL_RUN_EVIDENCE_STRICT in {0,false,no,off}
        -> DISABLED (legacy token-string credit preserved, escape hatch);
      - explicit opt-in   any other truthy value -> ENFORCED;
      - unset (new default): ENFORCED iff AUDITOOOR_L37_STRICT is truthy (the strict
        audit umbrella `make audit-complete STRICT=1` always sets it), else advisory
        so a bare non-strict / library caller keeps the legacy credit exactly.
    NEVER-FALSE-PASS is unchanged: a KILLED row WITH real run evidence still credits
    under strict; only the WHEN of the stricter predicate changes, not its logic."""
    v = os.environ.get(_RUN_EVIDENCE_STRICT_ENV, "").strip().lower()
    if v in ("0", "false", "no", "off"):
        return False                      # explicit opt-out (escape hatch)
    if v:                                  # any other explicit value
        return True                        # explicit opt-in
    # unset -> default-ON only under the L37 strict umbrella
    return os.environ.get("AUDITOOOR_L37_STRICT", "").strip().lower() not in (
        "", "0", "false", "no")


def _cluster_row_has_run_evidence(m: dict) -> bool:
    """True iff a cluster mutation_verify/mutation_detail row carries evidence the
    mutant was ACTUALLY RUN (not merely a typed `verdict=='killed'` claim).

    Real run evidence is ANY of:
      - a non-empty output_tail (the engine's failing output was captured);
      - a non-empty evidence_logs / kill_log / log_path / log pointer;
      - a mutants_run / calls / calls_to_kill / kill_calls counter that is an int
        >= 1 (the engine executed at least one call against the mutant);
      - an explicit engine execution status string (mutant_result / result / status
        that is a recognized engine outcome token, distinct from the bare
        `verdict` claim key).

    Fail-closed: a row whose ONLY signal is `verdict=='killed'` (with a null tail,
    null logs, and no counter) has NO run evidence and returns False. NOTE the
    caller only consults this under the strict env; a bare `calls_to_kill` claim
    with no other corroboration is intentionally NOT accepted as evidence here (it
    is a typed claim like verdict), matching the E2 fabrication shape - a counter is
    only honored when it lives in a run-counter field (mutants_run/calls/kill_calls)
    that a runner writes, not the authored calls_to_kill claim field."""
    if not isinstance(m, dict):
        return False
    # (i) captured engine output.
    tail = m.get("output_tail")
    if isinstance(tail, str) and tail.strip():
        return True
    # (ii) a log-pointer field with a non-empty value (str or non-empty list).
    for lk in ("evidence_logs", "kill_log", "log_path", "log", "logs",
               "evidence_log", "run_log"):
        v = m.get(lk)
        if isinstance(v, str) and v.strip():
            return True
        if isinstance(v, (list, tuple)) and any(
                isinstance(x, str) and x.strip() for x in v):
            return True
    # (iii) a RUN counter written by an actual engine run (>=1). Only genuine
    # run-counter fields count - NOT the authored `calls_to_kill` claim (that is a
    # typed assertion, present in the SSV fabrication with no run behind it).
    for ck in ("mutants_run", "calls", "kill_calls", "total_calls", "executed_calls"):
        v = m.get(ck)
        if isinstance(v, bool):
            continue
        if isinstance(v, int) and v >= 1:
            return True
        if isinstance(v, str):
            try:
                if int(v.replace(",", "").strip()) >= 1:
                    return True
            except ValueError:
                pass
    return False


def _sidecar_has_real_kill(d: dict) -> bool:
    """True iff the sidecar record evidences >=1 genuine mutant kill, across every
    schema variant. Fail-closed: returns False when no kill counter / killed row /
    cluster FAIL row is present. A killed mutant_results row whose tail is a
    panic-only equivalent-mutant or a setUp-crash false-kill does NOT count."""
    if not isinstance(d, dict):
        return False
    # (a) positive kill counters (auto-producer behavior_changing_kill_count /
    #     killed_count; manual/cluster mutants_killed). >=1 required.
    for key in ("behavior_changing_kill_count", "killed_count", "mutants_killed"):
        v = d.get(key)
        if isinstance(v, bool):
            continue
        if isinstance(v, int) and v >= 1:
            return True
    # (b) a genuine behaviour-changing mutant_results row. A row with a tail is
    #     judged by classify_kill_kind (rejects panic-only / setUp-crash false
    #     kills); a row with no tail/kill_kind keeps the legacy `killed` truth so a
    #     pre-tail manual/cluster record is not retroactively dropped.
    for m in (d.get("mutant_results") or []):
        if not isinstance(m, dict) or not m.get("killed"):
            continue
        kk = m.get("kill_kind")
        tail = m.get("output_tail")
        if kk == "behavior-changing":
            return True
        if kk in (None, "") and not tail:
            return True
        if tail and is_behavior_changing_kill(str(tail)):
            return True
    # (c) cluster mutation_detail[] / mutation_verify[] FAIL/KILLED rows.
    # E2 (2026-07-03): a `verdict=='killed'` STRING alone is not proof the mutant
    # ran. Under AUDITOOOR_MUTATION_KILL_RUN_EVIDENCE_STRICT (default OFF -> legacy
    # behaviour, no retroactive re-fail) a cluster KILLED row must ALSO carry run
    # evidence (output_tail / evidence_logs / a run counter) - a bare token-string
    # claim with no run behind it (the confirmed SSV ssv_eb_accounting fabrication)
    # is NOT credited. NEVER-FALSE-PASS: a KILLED row WITH run evidence still counts.
    strict = _run_evidence_strict()
    for arr_key in ("mutation_detail", "mutation_verify"):
        arr = d.get(arr_key)
        if not isinstance(arr, list):
            continue
        for m in arr:
            if not isinstance(m, dict):
                continue
            rr = m.get("verdict") or m.get("mutant_result") or m.get("result") or ""
            if isinstance(rr, str) and rr.strip().lower() in _CLUSTER_KILL_TOKENS:
                if strict and not _cluster_row_has_run_evidence(m):
                    # token-string KILLED with zero run evidence: skip under strict.
                    continue
                return True
    return False


def sidecar_is_genuine(d: dict) -> bool:
    """CANONICAL credit predicate for an mvc_sidecar record (caveat A).

    True IFF the record is a non-vacuous mutation-verified proof with >=1 real kill,
    honoring EITHER schema (verdict=='non-vacuous' OR cluster mutation_verified) so a
    reader can never miss a genuine sidecar because it lives in the other schema's
    field. Fail-closed: a record with verdict!='non-vacuous' AND
    mutation_verified!=True is NOT credited, and ZERO real kills is NOT credited in
    either schema. Use this in EVERY reader (invariant-fuzz-completeness,
    engine-harness-proof-check, audit-honesty-check) so producer + consumers agree."""
    if not isinstance(d, dict):
        return False
    verdict_ok = str(d.get("verdict") or "").strip().lower() in (
        "non-vacuous", "nonvacuous")
    cluster_ok = d.get("mutation_verified") is True
    # 3rd schema (auditooor.mvc_sidecar.cluster.v1): genuineness is carried
    # STRUCTURALLY by a non-empty mutation_verify[] campaign list (+ a baseline_run),
    # not a top-level verdict/mutation_verified flag. Without recognising it here, a
    # genuine cluster harness whose mutants were all KILLED is skipped purely on the
    # missing flag - the same serving-join class as corecov_cluster_sidecar_credit_fix,
    # hitting invariant-fuzz-completeness as a 4th blind-spot gate. NEVER-FALSE-PASS:
    # _sidecar_has_real_kill below still requires >=1 genuine KILLED row in that list,
    # so a SURVIVED-only / empty campaign credits nothing.
    mutation_verify_list_ok = (
        isinstance(d.get("mutation_verify"), list) and len(d.get("mutation_verify")) > 0
    )
    if not (verdict_ok or cluster_ok or mutation_verify_list_ok):
        return False
    return _sidecar_has_real_kill(d)


def _resolve_ws_path(raw: str, ws) -> Path:
    """Resolve a (possibly ws-relative) path string against the workspace root."""
    p = Path(str(raw))
    if not p.is_absolute() and ws is not None:
        p = Path(ws) / p
    return p


def sidecar_harness_drifted(rec: dict, ws) -> bool:
    """True iff the sidecar's recorded harness_source_sha256 NO LONGER matches the
    on-disk harness content (mode 13 - the harness was edited/clobbered AFTER its
    mutation-kill was banked, so the recorded kill no longer attests the current
    harness). A consumer MUST NOT credit such a stale sidecar.

    Canonical single-source home so every reader (audit-honesty-check,
    engine-harness-proof-check, ...) agrees. Mirrors the producer's stale-guard in
    mutation-verify-coverage.py::sidecar_harness_drifted.

    Conservative FALSE (no drift asserted) when: the record has no recorded hash
    (pre-P1-b sidecars are not retroactively rejected here - a separate
    absent-attestation policy handles those), the record names no harness file, or
    the harness file is missing (a vanished-harness on-disk check handles that).
    Fail-closed TRUE only on a concrete hash mismatch."""
    if not isinstance(rec, dict):
        return False
    recorded = rec.get("harness_source_sha256")
    if not isinstance(recorded, str) or not recorded:
        return False
    hp = rec.get("harness_path")
    if not hp:
        return False
    p = _resolve_ws_path(hp, ws)
    try:
        if not p.is_file():
            return False
        current = hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return False
    return current != recorded


def sidecar_manual_attested(rec: dict, ws) -> bool:
    """True iff a MANUALLY-registered sidecar carries the minimum runner attestation
    required to credit the STRICT gate: a non-empty ``source_file`` that EXISTS on
    disk AND a captured baseline runner result (``baseline_result`` non-None) AND a
    captured baseline output tail (``baseline_output_tail`` non-None).

    A manual record (mode='manual-mutant-harness' / manual_registration=true) whose
    only anti-fake check at registration is "harness_path exists" can otherwise set
    mutation_verified=true / verdict='non-vacuous' with agent-authored, unverifiable
    output strings and NO real baseline run captured. Such records are ADVISORY only
    (uncredited) until a genuine baseline run is captured.

    Non-manual records return True (this predicate does not gate them)."""
    if not isinstance(rec, dict):
        return False
    is_manual = (
        rec.get("manual_registration") is True
        or str(rec.get("mode") or "").strip().lower() == "manual-mutant-harness"
    )
    if not is_manual:
        return True
    src = rec.get("source_file")
    if not isinstance(src, str) or not src.strip():
        return False
    if not _resolve_ws_path(src, ws).is_file():
        return False
    if rec.get("baseline_result") is None:
        return False
    if rec.get("baseline_output_tail") is None:
        return False
    return True


def sidecar_uncredited_reason(rec: dict, ws):
    """Return a human-readable reason string iff a mutation-verified sidecar must NOT
    credit the strict gate (drift or unattested-manual), else None. Generic across
    workspaces/languages - no workspace literals. Callers treat a non-None reason as
    'downgrade to advisory / uncredited' and may surface the reason."""
    if sidecar_harness_drifted(rec, ws):
        return ("mvc sha-drift: harness edited after mutation-verify, re-run required "
                "(recorded harness_source_sha256 != current on-disk sha)")
    if not sidecar_manual_attested(rec, ws):
        return ("mvc manual-unattested: manual_registration record lacks an on-disk "
                "source_file + captured baseline_result/baseline_output_tail runner "
                "output; advisory only until a real baseline run is captured")
    return None
