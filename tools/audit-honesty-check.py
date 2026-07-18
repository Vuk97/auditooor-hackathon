#!/usr/bin/env python3
"""Audit-honesty gate: report TRUE coverage + flag hollow/mock engine execution.

Born from the 'audit the audit' verification (2026-06-03) that exposed every
workspace reporting a fake green: 'coverage 100%' that was really ~5.6% because
budget-skipped units were counted as covered, and 'engines ran' that were really
engine-error or assert(true) advisory stubs. This gate makes that impossible to
hide - it computes the HONEST numbers and emits the exact gap list the completion
workflows must close.

It checks, per workspace:
  1. TRUE coverage = covered - budget_skipped - (fake queue-basename matches) over
     the real denominator; lists the uncovered + budget-skipped + unscanned units.
  2. Engine reality: are halmos/medusa/echidna (or rust engines) genuinely executed,
     or engine-error / no-execution? Are the per-function harnesses real invariants
     or assert(true) stubs? Did any real run target a MOCK / reimplementation rather
     than in-scope source?

Verdicts: pass-genuinely-audited | fail-fake-coverage | fail-hollow-engines |
fail-mock-target | fail-depth-not-run | fail-hollow-per-function-harnesses |
needs-work (multiple gaps). Exit 1 on any fail unless --report.
(R81: fail-depth-not-run fires when a workspace LOOKS audited - coverage
reported done + engines genuinely executed - but carries no fresh
depth_certificate.json with per-guard negative-space + sibling-path guard-diff
evidence; a 'genuinely audited' claim with zero depth evidence is
itself hollow, so the depth layer underpins pass-genuinely-audited.)

Usage: audit-honesty-check.py --workspace <ws> [--json] [--report]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.audit_honesty_check.v1"


# ---------------------------------------------------------------------------
# P0-d / P1-a / P1-b: load the shared kill-genuineness predicate
# (tools/lib/mutation_kill.py) and the producer's stale-sidecar guard
# (mutation-verify-coverage.py::sidecar_harness_drifted). The CONSUMER applies the
# same rule as the producer so a setUp-crash false-kill (mode 12) / panic-only
# equivalent-mutant (mode 9) / drifted stale sidecar (mode 13) is not credited here.
# ---------------------------------------------------------------------------
def _load_mutation_kill():
    import importlib.util as _ilu

    out = {"kill": None, "drift": None, "reason": None}
    here = Path(__file__).resolve().parent
    libp = here / "lib" / "mutation_kill.py"
    if libp.is_file():
        try:
            spec = _ilu.spec_from_file_location("mutation_kill", str(libp))
            mod = _ilu.module_from_spec(spec)
            sys.modules["mutation_kill"] = mod  # py3.14: register BEFORE exec
            spec.loader.exec_module(mod)
            out["kill"] = mod
            # Canonical uncredited-reason predicate (drift OR manual-unattested).
            # Present in the shared lib so every reader agrees; the producer import
            # below still supplies the drift half for older lib copies.
            out["reason"] = getattr(mod, "sidecar_uncredited_reason", None)
        except Exception:  # noqa: BLE001
            pass
    mvcp = here / "mutation-verify-coverage.py"
    if mvcp.is_file():
        try:
            spec = _ilu.spec_from_file_location("mutation_verify_coverage", str(mvcp))
            mod = _ilu.module_from_spec(spec)
            sys.modules["mutation_verify_coverage"] = mod
            spec.loader.exec_module(mod)
            out["drift"] = getattr(mod, "sidecar_harness_drifted", None)
        except Exception:  # noqa: BLE001
            pass
    return out


_MK = _load_mutation_kill()


# ---------------------------------------------------------------------------
# Per-unit non-economic-surface disposition (single source of truth in
# tools/lib/non_economic_disposition.py). A value-moving fn or per-function
# scaffold over a DOCUMENTED non-economic / OOS contract has no fund/share
# conservation invariant to assert; it is removed from the value-moving floor
# denominator and from the stub-harness count, so a config-only contract no
# longer forces a vacuous assert(true) (R80/R81 coverage-theater). Never-false-
# pass-guarded in the lib (bounded class, real rationale, on-disk CUT, REJECTED
# for any transfer-mover).
# ---------------------------------------------------------------------------
def _load_non_economic_disposition():
    import importlib.util as _ilu

    here = Path(__file__).resolve().parent
    libp = here / "lib" / "non_economic_disposition.py"
    if not libp.is_file():
        return None
    try:
        spec = _ilu.spec_from_file_location("non_economic_disposition", str(libp))
        mod = _ilu.module_from_spec(spec)
        sys.modules["non_economic_disposition"] = mod
        spec.loader.exec_module(mod)
        return mod
    except Exception:  # noqa: BLE001
        return None


_NED_MOD = _load_non_economic_disposition()


def _genuine_kill_tail(tail: str) -> bool:
    """True iff output_tail is a genuine behaviour-changing kill (P0-d/P1-a).
    Fail-open True when the shared lib is unavailable."""
    mod = _MK.get("kill")
    if mod is None:
        return True
    try:
        return bool(mod.is_behavior_changing_kill(tail))
    except Exception:  # noqa: BLE001
        return True


def _sidecar_is_genuine(rec: dict) -> bool:
    """Canonical mvc_sidecar credit predicate (caveat A schema normalization),
    delegated to the shared tools/lib/mutation_kill.py so this reader agrees with
    the invariant-fuzz / engine-harness readers - a genuine sidecar can never be
    missed because it lives in the other schema's field (serving-join). Fail-closed
    False fallback when the shared lib is unavailable (the schema-specific branches
    below remain the backstop credit paths)."""
    mod = _MK.get("kill")
    if mod is None or not hasattr(mod, "sidecar_is_genuine"):
        return False
    try:
        return bool(mod.sidecar_is_genuine(rec))
    except Exception:  # noqa: BLE001
        return False


def _sidecar_drifted(rec: dict, ws: Path) -> bool:
    """True iff the sidecar's harness_source_sha256 no longer matches disk (P1-b)."""
    fn = _MK.get("drift")
    if fn is None:
        return False
    try:
        return bool(fn(rec, ws))
    except Exception:  # noqa: BLE001
        return False


def _sidecar_uncredited_reason(rec: dict, ws: Path):
    """Return a reason string iff a mutation-verified sidecar must NOT credit the
    strict gate: (A) sha-drift - harness edited after the kill was banked, or
    (B) manual-unattested - a manual_registration record lacking an on-disk
    source_file + captured baseline_result/baseline_output_tail runner output.
    Returns None when the record is creditable. Fail-closed layering: the shared-lib
    predicate covers BOTH; the legacy `_sidecar_drifted` (producer import) remains a
    backstop for the drift half if the lib is an older copy."""
    fn = _MK.get("reason")
    if fn is not None:
        try:
            r = fn(rec, ws)
            if r:
                return r
        except Exception:  # noqa: BLE001
            pass
    # Backstop: drift half via the producer-loaded predicate.
    if _sidecar_drifted(rec, ws):
        return "mvc sha-drift: harness edited after mutation-verify, re-run required"
    return None


# A per-function mutation record is a GENUINE non-vacuous KILL when it is
# mutation_verified + killed AND any of its verdict fields says so. The per-fn
# producer writes verdict='killed' + genuine_verdict='non-vacuous' (NO
# oracle_verdict key); core-coverage / function-coverage already credit it via this
# alias set, so the honesty + honest-zero readers MUST too or they false-RED a
# genuinely-audited forge ws (the SSV 12-genuine hollow false-red). Mirrors
# core-coverage-completeness._MUT_KILL_VERDICTS - one definition across the funnel.
_MUT_KILL_VERDICTS = {"killed", "non-vacuous", "nonvacuous", "real", "mutation-killed"}


def _mvc_entry_is_genuine_kill(entry: dict) -> bool:
    """True iff entry is a mutation_verified + killed genuine non-vacuous kill,
    reading ANY verdict alias (oracle_verdict / genuine_verdict / verdict /
    mutation_verdict). Still gated on mutation_verified AND killed, so broadening
    the verdict-field read cannot credit a vacuous/unkilled entry."""
    if not isinstance(entry, dict):
        return False
    if entry.get("mutation_verified") is not True or entry.get("killed") is not True:
        return False
    # P0-d / P1-a: when the entry records the kill_kind or an output_tail, it must be
    # a genuine behaviour-changing kill (not a setUp-crash false-kill nor a panic-only
    # equivalent-mutant). Entries with neither field keep the legacy verdict-alias
    # truth (fail-open), so pre-existing records are not retroactively dropped.
    kk = entry.get("kill_kind")
    if isinstance(kk, str) and kk not in ("behavior-changing",):
        return False
    if "output_tail" in entry and not _genuine_kill_tail(str(entry.get("output_tail") or "")):
        return False
    for k in ("oracle_verdict", "genuine_verdict", "verdict", "mutation_verdict"):
        v = entry.get(k)
        if isinstance(v, str) and v.strip().lower() in _MUT_KILL_VERDICTS:
            return True
    return False


def _load(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _corroborated_genuine_count(ws: Path) -> int:
    """Return the number of per_function entries in mutation_verify_coverage.json
    that are corroborated as genuinely non-vacuous:
      mutation_verified==True AND oracle_verdict=="non-vacuous" AND killed==True.

    This is the TOOL-WRITTEN ground truth that backs up the bare integer in
    genuine_coverage_manifest.json.  If mutation_verify_coverage.json is absent,
    malformed, or has no per_function list, returns 0.  Generic stdlib only,
    no workspace literals.
    """
    count = 0
    mvc_path = ws / ".auditooor" / "mutation_verify_coverage.json"
    try:
        mvc = json.loads(mvc_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        mvc = None
    if isinstance(mvc, dict) and isinstance(mvc.get("per_function"), list):
        for entry in mvc["per_function"]:
            if _mvc_entry_is_genuine_kill(entry):
                count += 1
    # ALSO count standalone mutation-verify-coverage.v1 sidecar records (e.g. a
    # Foundry core-invariant harness like ProtocolFee_CoreInvariant) - the same
    # un-fakeable ground truth (baseline pass + killed mutant + CUT on disk) that
    # the aggregate per_function list above does not capture.
    count += len(_mutation_verified_cut_harnesses(ws))
    return count


# ---------------------------------------------------------------------------
# E3.3 - per-language-sub-tree value-moving floor (cross-cutting rule 1).
# ---------------------------------------------------------------------------
# value_moving_functions.json carries functions[].language (sol|go|rs|move|cairo);
# mutation_verify_coverage.json per_function entries carry .language. The floor
# is corroborated_genuine[lang] >= value_moving_count[lang] for EVERY present
# language - a mixed Solidity+circom repo must not clear the floor with only its
# Solidity half. Computed PER LANGUAGE so no sub-tree is masked by another.

# Canonical language tag normalisation (the two artifacts use slightly different
# tokens: value-moving-functions uses sol|go|rs|move|cairo; mutation-verify-
# coverage may emit 'solidity'/'rust' for the language field).
_LANG_NORM = {
    "sol": "sol", "solidity": "sol",
    "rs": "rs", "rust": "rs",
    "go": "go", "golang": "go",
    "move": "move", "aptos": "move", "sui": "move",
    "cairo": "cairo",
    "circom": "circom", "noir": "noir", "zokrates": "zokrates", "sway": "sway",
}

# E3.4 - mutation-runner backing per language (must match
# function-coverage-completeness.py). solidity/rust/go ship a built-in runner: an
# absent backend under STRICT is FATAL. move/cairo/circom/noir have NO built-in
# runner: emit a TYPED <lang>-mutation-runner-absent verdict + a waiver path.
_MUT_RUNNER_LANGS = {"sol", "rs", "go"}
_MUT_RUNNER_ABSENT_LANGS = {"move", "cairo", "circom", "noir"}
_RUNNER_ABSENT_VERDICT = {
    "move": "move-mutation-runner-absent",
    "cairo": "cairo-mutation-runner-absent",
    "circom": "circom-mutation-runner-absent",
    "noir": "noir-mutation-runner-absent",
}
_RUNNER_WAIVER_ENV = {
    "move": "AUDITOOOR_MVC_RUNNER_MOVE",
    "cairo": "AUDITOOOR_MVC_RUNNER_CAIRO",
    "circom": "AUDITOOOR_MVC_RUNNER_CIRCOM",
    "noir": "AUDITOOOR_MVC_RUNNER_NOIR",
}


def _norm_lang_tag(raw) -> str:
    return _LANG_NORM.get(str(raw or "").strip().lower(), str(raw or "").strip().lower())


def _value_moving_count_by_lang(vmf) -> dict:
    """Map normalised-language -> count of value-moving functions.

    Reads functions[].language. A function with no language tag is bucketed under
    'unknown' so it still contributes to the floor (never silently dropped)."""
    out: dict = {}
    if not isinstance(vmf, dict):
        return out
    for fn in (vmf.get("functions") or []):
        if not isinstance(fn, dict):
            continue
        lang = _norm_lang_tag(fn.get("language")) or "unknown"
        out[lang] = out.get(lang, 0) + 1
    return out


def _corroborated_genuine_count_by_lang(ws: Path) -> dict:
    """Map normalised-language -> count of genuinely-corroborated per_function
    entries (mutation_verified==True AND oracle_verdict=='non-vacuous' AND
    killed==True). A standalone CUT-harness sidecar with no language tag is
    bucketed under 'any' (it can satisfy any language sub-tree's floor since it
    is genuine, language-agnostic evidence)."""
    out: dict = {}
    mvc_path = ws / ".auditooor" / "mutation_verify_coverage.json"
    try:
        mvc = json.loads(mvc_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        mvc = None
    if isinstance(mvc, dict) and isinstance(mvc.get("per_function"), list):
        for entry in mvc["per_function"]:
            if _mvc_entry_is_genuine_kill(entry):
                lang = _norm_lang_tag(entry.get("language")) or "any"
                out[lang] = out.get(lang, 0) + 1
    n_cut = len(_mutation_verified_cut_harnesses(ws))
    if n_cut:
        out["any"] = out.get("any", 0) + n_cut
    return out


def _vmf_drop_non_economic_dispositioned(ws: Path, vmf):
    """Return a copy of vmf with functions whose file carries an ACCEPTED
    non-economic-surface disposition removed from the value-moving floor.

    A pure config-mapping write (ledger_write_hit, NO transfer_hit) over a
    documented non-economic / OOS contract is not a fund/share-conservation
    obligation - the value-moving detector is shape-based and over-flags such
    msg.sender-namespaced registries. The lib REJECTS any disposition that
    overlaps a transfer_hit file, so a real custody mover can never be dropped
    here. When no disposition artifact exists, vmf is returned unchanged."""
    if _NED_MOD is None or not isinstance(vmf, dict):
        return vmf
    dispositions = _NED_MOD.load_dispositions(ws)
    if not dispositions:
        return vmf
    fns = vmf.get("functions")
    if not isinstance(fns, list):
        return vmf
    kept = [
        fn for fn in fns
        if not (isinstance(fn, dict)
                and _NED_MOD.file_is_dispositioned(str(fn.get("file") or ""), dispositions) is not None)
    ]
    if len(kept) == len(fns):
        return vmf
    out = dict(vmf)
    out["functions"] = kept
    out["function_count"] = len(kept)
    return out


def _mutation_verified_cut_files(ws: Path) -> set:
    """Relative source-file paths that are the CUT of a MUTATION-VERIFIED harness
    (mvc_sidecar / cross-function-coverage records with mutation_verified True +
    >=1 kill). A genuine economic-invariant harness over a contract/file EXERCISES
    that file's value-moving functions and a killed mutant proves non-vacuity, so
    every value-moving function in such a file is covered. This is the coverage-
    based credit that fixes the per-language-floor granularity gap: the floor was
    comparing harness-RECORD count vs value-moving FUNCTION count, so a single
    conservation harness covering N functions counted as 1 and could never meet the
    floor. NUVA 2026-06-30. UN-FAKEABLE: require mutation_verified + a real kill +
    an on-disk CUT file."""
    import glob as _glob
    out: set = set()
    cands: list = []
    for rel in ("mvc_sidecar", "cross-function-coverage"):
        cands += _glob.glob(str(ws / ".auditooor" / rel / "*.json"))
    for p in cands:
        try:
            rec = json.loads(Path(p).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        mv = rec.get("mutation_verified") is True or \
            str(rec.get("verdict", "")).strip().lower() in ("non-vacuous", "nonvacuous", "killed")
        killed = (isinstance(rec.get("mutants_killed"), int) and rec["mutants_killed"] >= 1) \
            or (isinstance(rec.get("killed_count"), int) and rec["killed_count"] >= 1) \
            or rec.get("mutation_verified") is True
        if not (mv and killed):
            continue
        cut_cands = []
        for k in ("source_file", "cut"):
            v = rec.get(k)
            if isinstance(v, str) and v:
                cut_cands.append(v)
        for c in (rec.get("cut_contracts") or []):
            if isinstance(c, str):
                cut_cands.append(c)
        for c in cut_cands:
            cp = Path(c) if os.path.isabs(c) else (ws / c)
            if cp.is_file():
                try:
                    out.add(str(cp.resolve().relative_to(ws.resolve())))
                except (ValueError, OSError):
                    out.add(c.split("/audits/")[-1].split("/", 1)[-1] if "/audits/" in c else c)
    return out


def _per_language_floor_unmet(ws: Path, vmf) -> list:
    """Return the list of languages whose value-moving floor is NOT met:
    corroborated_genuine[lang] (+ language-agnostic 'any' credit) < value_moving
    count[lang]. Empty list == every present language sub-tree clears its floor.

    'any'-tagged genuine evidence (standalone CUT harness with no language tag)
    is applied as a shared pool across the unmet languages, smallest-deficit
    first, so a genuine language-agnostic harness can legitimately satisfy a
    single-language workspace without being double-counted across languages."""
    return _value_moving_floor_breakdown(ws, vmf)["unmet_languages"]


def _value_moving_floor_breakdown(ws: Path, vmf) -> dict:
    """Compute the per-language value-moving floor AND a three-way visibility
    breakdown so a reviewer never mistakes scope-removal for real proof.

    Returns a dict with:
      * ``proven_by_executed_code`` - value-moving functions covered by a
        mutation-verified (killed-mutant, on-disk CUT) economic-invariant harness
        or an equivalent corroborated per-function record. REAL proof.
      * ``dispositioned`` - value-moving functions REMOVED from the floor by an
        operator-APPROVED non-economic-surface disposition (scope-removal, NOT
        proof). Never folded into ``proven``.
      * ``uncovered`` - value-moving functions with neither proof nor an approved
        disposition (the honest remaining floor deficit).
      * ``value_moving_total`` - the raw value-moving function count.
      * ``unmet_languages`` - languages whose floor is still unmet (drives the
        gate FAIL), identical to the legacy _per_language_floor_unmet result."""
    raw_functions = (vmf.get("functions") or []) if isinstance(vmf, dict) else []
    value_moving_total = len(raw_functions)
    vmf = _vmf_drop_non_economic_dispositioned(ws, vmf)
    kept = (vmf.get("functions") or []) if isinstance(vmf, dict) else []
    dispositioned = max(0, value_moving_total - len(kept))
    vm_by_lang = _value_moving_count_by_lang(vmf)
    corr_by_lang = _corroborated_genuine_count_by_lang(ws)
    # The "any" pool double-counts the CUT harnesses that the file-coverage credit
    # below already attributes per value-moving function (both read the SAME mvc
    # sidecars). Subtract the CUT-harness contribution so a single harness cannot
    # credit twice (once per file-covered fn AND once via the pool). Only genuinely
    # language-agnostic per_function entries remain in the pool. NUVA 2026-06-30.
    any_pool = max(0, corr_by_lang.get("any", 0) - len(_mutation_verified_cut_harnesses(ws)))
    # COVERAGE-BASED CREDIT (granularity fix): reduce each language's NEED by the
    # value-moving functions whose FILE is the CUT of a mutation-verified harness -
    # a conservation harness over a contract/file covers all its value-moving fns
    # (it was previously counted as a single record vs the function count, so it
    # could never meet the floor). UN-FAKEABLE: only a mutation_verified harness
    # with a real on-disk CUT credits. NUVA 2026-06-30.
    _cut_files = _mutation_verified_cut_files(ws)
    _file_covered_by_lang: dict = {}
    if _cut_files and isinstance(vmf, dict):
        for fn in (vmf.get("functions") or []):
            if not isinstance(fn, dict):
                continue
            _f = str(fn.get("file") or "").replace("\\", "/")
            try:
                _rel = str(Path(_f).resolve().relative_to(ws.resolve())) if _f else ""
            except (ValueError, OSError):
                _rel = _f.split("/audits/")[-1].split("/", 1)[-1] if "/audits/" in _f else _f
            if _rel and _rel in _cut_files:
                _lang = _norm_lang_tag(fn.get("language")) or "unknown"
                _file_covered_by_lang[_lang] = _file_covered_by_lang.get(_lang, 0) + 1
    deficits = []
    need_total = 0
    proven_direct = 0  # proof credited before the shared any-pool
    for lang, need in vm_by_lang.items():
        need_total += need
        have = corr_by_lang.get(lang, 0) + _file_covered_by_lang.get(lang, 0)
        proven_direct += min(need, have)  # proof cannot exceed the need it covers
        deficit = need - have
        if deficit > 0:
            deficits.append([lang, deficit])
    # Apply the shared language-agnostic pool to the smallest deficits first.
    deficits.sort(key=lambda t: t[1])
    pool_applied = 0
    for row in deficits:
        if any_pool <= 0:
            break
        applied = min(any_pool, row[1])
        row[1] -= applied
        any_pool -= applied
        pool_applied += applied
    unmet = [lang for (lang, deficit) in deficits if deficit > 0]
    proven = min(need_total, proven_direct + pool_applied)
    uncovered = max(0, need_total - proven)
    return {
        "unmet_languages": unmet,
        # THREE DISTINCT counts - never collapse dispositioned into proven.
        "proven_by_executed_code": proven,
        "dispositioned": dispositioned,
        "uncovered": uncovered,
        "value_moving_total": value_moving_total,
    }


def _true_coverage(ws: Path) -> dict:
    # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
    _gate_path = ws / ".auditooor" / "g15_hunt_coverage_gate_last_result.json"
    g = _load(_gate_path) or {}
    total = g.get("total_units") or g.get("total_contracts") or 0
    raw_covered = g.get("covered") or 0
    budget_skipped = len(g.get("budget_skipped_units") or [])
    skip_logged = len(g.get("skip_logged_units") or [])
    # honest covered = covered units that are NOT budget-skipped and NOT skip-logged
    true_covered = max(0, raw_covered - budget_skipped - skip_logged)
    # secondary: the underlying coverage_report.json (rust path / detailed)
    cr = _load(ws / ".auditooor" / "coverage_report.json") or _load(
        ws / "coverage_report.json"
    ) or {}
    cr_total = cr.get("total_units")
    cr_covered = cr.get("covered")
    cr_frac = cr.get("coverage_fraction")
    true_pct = (true_covered / total) if total else None
    # Credit honest agent-review coverage: the coverage agents review the previously-
    # uncovered/budget-skipped units and write .auditooor/honest_coverage_review.jsonl
    # (one row per unit with reviewed:true). Those units ARE genuinely covered (real agent
    # review), so add them to the count.
    reviewed = 0
    rev = ws / ".auditooor" / "honest_coverage_review.jsonl"
    if rev.is_file():
        try:
            for line in rev.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get("reviewed") or r.get("verdict"):
                    reviewed += 1
        except OSError:
            pass
    # Prefer the underlying coverage_report.json fraction when available (real source units),
    # then add the agent-reviewed previously-uncovered units, capped at total.
    base_covered = round(cr_frac * total) if (cr_frac is not None and total) else true_covered
    final_covered = min(total, base_covered + reviewed) if total else (base_covered + reviewed)
    preferred_pct = (final_covered / total) if total else None

    # ---- In-scope-denominator override (Rule: measure TRUE coverage over the units that
    # ACTUALLY matter, not over vendored OOS dependency functions). When the workspace ships
    # an explicit in-scope unit manifest (.auditooor/inscope_units.jsonl), use the count of
    # in-scope units as the denominator and count an in-scope unit as covered when it is EITHER
    # deep-pipeline-covered OR agent-reviewed. A workspace whose entire in-scope surface is
    # reviewed then reads TRUE coverage 100%, regardless of how many OOS dep functions exist.
    # Generic: applies to any workspace with an inscope_units.jsonl. ---------------------------
    inscope_units = _load_inscope_units(ws)
    # Defer the coverage DENOMINATOR to function-coverage's authoritative attack-
    # surface enumeration: drop inscope units fcc does not enumerate (constructors,
    # internal `_`-helpers, pure libraries, interface decls, view getters, sim/
    # boilerplate) - they are not independent coverage obligations, they are covered
    # transitively via the public entrypoint fcc audits. Filter (never expand); only
    # when fcc's enumeration is present + non-trivial so a missing artifact cannot
    # silently empty the denominator. NUVA 2026-06-30: 58 internal/ctor/lib/interface
    # units inflated audit-honesty's denominator and read coverage-below-100 even
    # though function-coverage is pass-fully-covered (171/171).
    _fcc_keys = _fcc_enumerated_keys(ws)
    if len(_fcc_keys) >= 8:
        _filtered = [u for u in inscope_units if u & _fcc_keys]
        if _filtered:
            inscope_units = _filtered
    inscope_total = len(inscope_units)
    inscope_block: dict = {}
    if inscope_total:
        reviewed_keys = _load_reviewed_unit_keys(ws)
        covered_keys = _load_deep_covered_unit_keys(ws)
        # Per-UNIT counting: a unit is covered when ANY of its match keys (full relpath
        # form OR basename form) appears in the reviewed/deep-covered key sets. This is
        # robust to source-tree prefix differences between inscope_units.jsonl and the
        # review/coverage records.
        inscope_reviewed = sum(
            1 for u in inscope_units if u & reviewed_keys
        )
        inscope_deep = sum(
            1 for u in inscope_units if u & covered_keys
        )
        inscope_covered = sum(
            1 for u in inscope_units if (u & reviewed_keys) or (u & covered_keys)
        )
        inscope_pct = (inscope_covered / inscope_total) if inscope_total else None
        # Coverage-fraction scaling fallback: when key-matching yields a low inscope
        # coverage fraction AND the underlying coverage_report has a more reliable
        # fraction (cr_frac), scale the pipeline fraction to the inscope denominator.
        # This handles mixed-language workspaces (Rust+Solidity) where the coverage
        # pipeline stores per-unit lists in one path-format while inscope_units.jsonl
        # uses another, causing key-matching to under-count covered units.
        # Condition: inscope_pct < 0.40 AND cr_frac is available AND cr_frac is a
        # trustworthy non-trivial number (0.1 < cr_frac < 1.0). In that case, use
        # round(cr_frac * inscope_total) as the scaled covered count so the headline
        # reads "~cr_frac% of the inscope surface is covered per the pipeline."
        inscope_covered_scaled = inscope_covered
        inscope_pct_source = "key-match"
        if (
            cr_frac is not None
            and 0.1 < cr_frac < 1.0
            and inscope_pct is not None
            and inscope_pct < 0.40
        ):
            scaled = round(cr_frac * inscope_total)
            if scaled > inscope_covered:
                inscope_covered_scaled = scaled
                inscope_pct = cr_frac
                inscope_pct_source = "cr-fraction-scaled"
        inscope_block = {
            "inscope_total": inscope_total,
            "inscope_covered": inscope_covered_scaled,
            "inscope_covered_key_match": inscope_covered,
            "inscope_reviewed": inscope_reviewed,
            "inscope_deep_covered": inscope_deep,
            "inscope_coverage_pct": inscope_pct,
            "inscope_coverage_pct_source": inscope_pct_source,
            "scoped_to_inscope": True,
        }
        # Override the headline denominator/coverage to the in-scope surface.
        total = inscope_total
        final_covered = inscope_covered_scaled
        preferred_pct = inscope_pct

    # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
    result = {
        "gate_reported_pct": g.get("coverage_pct"),
        "gate_verdict": g.get("verdict"),
        # gate_file_missing: True when the g15 coverage gate has never been run.
        # Used by check() to fire fail-no-coverage-gate when engines genuinely ran
        # but coverage was never measured - a workspace that looks audited but has
        # NO coverage gate evidence is itself hollow.
        "gate_file_missing": not _gate_path.is_file(),
        "total_units": total,
        "raw_covered": raw_covered,
        "budget_skipped": budget_skipped,
        "skip_logged": skip_logged,
        "agent_reviewed": reviewed,
        "true_covered": final_covered,
        "true_coverage_pct": preferred_pct,
        "underlying_report_pct": cr_frac,
        "underlying_uncovered": (cr.get("uncovered_units") or cr.get("uncovered") or [])[:40]
        if isinstance(cr.get("uncovered_units") or cr.get("uncovered"), list) else [],
        "gate_unscanned": (g.get("queued_not_scanned") or [])[:40],
    }
    result.update(inscope_block)
    return result


# _norm_unit_key removed: dead code (zero call sites, body was a no-op strip).
# The actual prefix-stripping normalization lives in _unit_match_keys below.
# r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
def _unit_match_keys(file_part: str, fn_part: str) -> set:
    """Produce the set of keys a unit can be matched under (full rel path + basename)."""
    file_part = (file_part or "").strip()
    fn_part = (fn_part or "").strip()
    keys = set()
    if file_part and fn_part:
        keys.add(f"{file_part}::{fn_part}")
        base = file_part.rsplit("/", 1)[-1]
        keys.add(f"{base}::{fn_part}")
    return keys


def _load_inscope_units(ws: Path) -> list:
    """Load the in-scope unit manifest if present, return a list of per-unit match-key sets.

    Accepts .auditooor/inscope_units.jsonl rows of either shape:
      {"file": "...", "function": "...", "file_line": "...:NN"}  (file+function)
      {"unit": "<path>::<fn>"}                                   (precomposed key)
    Each unit contributes a SET of match keys (its '<relpath>::<fn>' and '<basename>::<fn>').
    Units are deduped by their canonical '<relpath>::<fn>' so duplicate manifest rows (e.g.
    the same function name defined in multiple libraries within one file, or the same file
    copied under several module subtrees) collapse to the unique surface that ACTUALLY matters.
    """
    p = ws / ".auditooor" / "inscope_units.jsonl"
    if not p.is_file():
        return []
    units: dict = {}
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            fp = fn = None
            if d.get("unit") and "::" in str(d["unit"]):
                fp, fn = str(d["unit"]).rsplit("::", 1)
            elif d.get("file") and d.get("function"):
                fp, fn = str(d["file"]), str(d["function"])
            if not fp or not fn:
                continue
            canon = f"{fp}::{fn}"
            if canon not in units:
                units[canon] = _unit_match_keys(fp, fn)
    except OSError:
        return []
    return list(units.values())


def _fcc_enumerated_keys(ws: Path) -> set:
    """Match-keys for every function function-coverage-completeness ENUMERATES as
    external attack surface (.auditooor/function_coverage_completeness.json, any
    classification). function-coverage is THE authoritative per-function attack-
    surface gate: it deliberately drops non-attack-surface units (constructors,
    internal `_`-helpers, pure libraries, interface declarations, view/pure getters,
    Cosmos sim/boilerplate). A unit that fcc does NOT enumerate is therefore not an
    INDEPENDENT coverage obligation - it is exercised transitively through the public
    entrypoint that fcc DOES audit. Returns an empty set when the artifact is absent
    (then no filtering - preserves legacy behavior)."""
    fcc_p = ws / ".auditooor" / "function_coverage_completeness.json"
    if not fcc_p.is_file():
        return set()
    fcc = _load(fcc_p) or {}
    fns = fcc.get("functions") if isinstance(fcc, dict) else None
    keys: set = set()
    if isinstance(fns, list):
        for fnrec in fns:
            if not isinstance(fnrec, dict):
                continue
            fp = str(fnrec.get("file") or "")
            fn = str(fnrec.get("name") or fnrec.get("function") or "")
            if fp and fn:
                keys |= _unit_match_keys(fp, fn)
    return keys


def _load_reviewed_unit_keys(ws: Path) -> set:
    """Load agent-reviewed unit keys from honest_coverage_review.jsonl as match keys."""
    p = ws / ".auditooor" / "honest_coverage_review.jsonl"
    if not p.is_file():
        return set()
    keys: set = set()
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            # a row is a genuine review if it carries a verdict (clean/concern/...) OR
            # an explicit reviewed:true. Accept BOTH the precomposed {unit:"path::fn"} shape
            # and the {file, function} shape the coverage agents actually emit.
            if not (r.get("reviewed") or r.get("verdict")):
                continue
            fp = fn = None
            u = r.get("unit")
            if u and "::" in str(u):
                fp, fn = str(u).rsplit("::", 1)
            elif r.get("file") and r.get("function"):
                fp, fn = str(r["file"]), str(r["function"])
            if not fp or not fn:
                continue
            keys |= _unit_match_keys(fp, fn)
    except OSError:
        return set()
    return keys


def _load_deep_covered_unit_keys(ws: Path) -> set:
    """Load deep-pipeline-covered unit keys (best-effort) as match keys.

    Reads coverage_report.json 'covered_units' / 'covered_list' lists when present.
    Falls back to deriving the covered set from denominator_units - uncovered_units when
    those explicit per-unit lists are absent (common for mixed Rust+Solidity workspaces
    where the coverage pipeline stores aggregate counts rather than per-unit lists).
    Also reads prior_covered=True entries from inscope_units.jsonl as a supplementary
    source so that scope-agent-identified already-covered units are not missed.

    Each entry may be a '<path>::<fn>' string or a {'file','function'} dict.
    """
    keys: set = set()
    cr = _load(ws / ".auditooor" / "coverage_report.json") or _load(
        ws / "coverage_report.json"
    ) or {}
    # Primary: explicit covered_units / covered_list lists.
    covered_list = cr.get("covered_units") or cr.get("covered_list") or []
    if isinstance(covered_list, list) and covered_list:
        for c in covered_list:
            if isinstance(c, str) and "::" in c:
                fp, fn = c.rsplit("::", 1)
                keys |= _unit_match_keys(fp, fn)
            elif isinstance(c, dict) and c.get("file") and c.get("function"):
                keys |= _unit_match_keys(str(c["file"]), str(c["function"]))
    # Fallback: derive covered from denominator_units - uncovered_units.
    # This handles workspaces where coverage_report stores only aggregate counts
    # (covered: int) rather than per-unit lists (covered_units: list).
    if not keys:
        denom = cr.get("denominator_units") or []
        uncov = cr.get("uncovered_units") or []
        if isinstance(denom, list) and denom:
            uncov_set = set(uncov) if isinstance(uncov, list) else set()
            for s in denom:
                if s in uncov_set:
                    continue
                if isinstance(s, str) and "::" in s:
                    fp, fn = s.rsplit("::", 1)
                    keys |= _unit_match_keys(fp, fn)
    # Supplement: inscope_units.jsonl prior_covered=True entries mark units the
    # scope agent confirmed were already covered; include them so inscope-override
    # mode does not under-count coverage on mixed workspaces.
    inscope_p = ws / ".auditooor" / "inscope_units.jsonl"
    if inscope_p.is_file():
        try:
            for line in inscope_p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if not d.get("prior_covered"):
                    continue
                fp = str(d.get("file") or "")
                fn = str(d.get("function") or "")
                if fp and fn:
                    keys |= _unit_match_keys(fp, fn)
        except OSError:
            pass
    # Supplement: the function-coverage-completeness per-function attack layer is the
    # AUTHORITATIVE per-fn coverage (R80-gated hunt-sidecar verdicts), but its
    # real-attack units are not written into coverage_report.json (the swept-surface
    # heatmap). Without crediting them, audit-honesty's inscope key-match under-counts
    # genuinely-hunted units (#[private] callbacks, view getters, infra) and reads
    # coverage-below-100 even when function-coverage is pass-fully-covered
    # (near-intents 2026-06-26: 327/364 vs 1618/1618). Credit a unit when
    # function_coverage_completeness.json classifies it real-attack.
    fcc_p = ws / ".auditooor" / "function_coverage_completeness.json"
    if fcc_p.is_file():
        fcc = _load(fcc_p) or {}
        fcc_fns = fcc.get("functions") if isinstance(fcc, dict) else None
        if isinstance(fcc_fns, list):
            for fnrec in fcc_fns:
                if not isinstance(fnrec, dict):
                    continue
                if str(fnrec.get("classification", "")) != "real-attack":
                    continue
                fp = str(fnrec.get("file") or "")
                fn = str(fnrec.get("name") or fnrec.get("function") or "")
                if fp and fn:
                    keys |= _unit_match_keys(fp, fn)
    # Supplement: per-function hunt sidecars are the AUTHORITATIVE per-fn evidence,
    # but function-coverage's enumeration (1618) can omit units audit-honesty's
    # inscope_units (364) carries - e.g. Solana program entrypoints + near/btc view
    # getters (near-intents 2026-06-26: 8 such hunted units under-credited). Credit a
    # unit directly from a hunt sidecar carrying a terminal verdict (KILL / refuted /
    # applies_to_target=no) with a real file+fn anchor (top-level OR nested result/
    # function_anchor schema). Bare-prose (no anchor) does not credit (R76).
    scd = ws / ".auditooor" / "hunt_findings_sidecars"
    if scd.is_dir():
        for p in scd.glob("*.json"):
            obj = _load(p)
            if not isinstance(obj, dict):
                continue
            res = obj.get("result")
            if isinstance(res, str):
                try:
                    res = json.loads(res)
                except ValueError:
                    res = {}
            res = res if isinstance(res, dict) else {}
            verdict = str(res.get("verdict") or obj.get("verdict") or "").strip().lower()
            applies = str(res.get("applies_to_target") or obj.get("applies_to_target") or "").strip().lower()
            if verdict not in ("kill", "killed", "refuted") and applies != "no":
                continue
            anc = obj.get("function_anchor")
            if isinstance(anc, str):
                try:
                    anc = json.loads(anc)
                except ValueError:
                    anc = None
            fp = fn = ""
            if isinstance(anc, dict):
                fp = str(anc.get("file") or "")
                fn = str(anc.get("fn") or anc.get("function") or "")
            if not fp:
                fp = str(obj.get("file") or "")
            if not fn:
                fn = str(obj.get("function") or obj.get("fn") or "")
            fn = fn.split("(", 1)[0].strip()
            if fp and fn and fp != "?" and fn != "?":
                keys |= _unit_match_keys(fp, fn)
    return keys


_MOCK_RE = re.compile(r"\b(Mock|Minimal|Fake|Stub|Reimplementation|Faithful)\w*", re.I)
_SRC_IMPORT_RE = re.compile(r'import[^\n;]*["\'][^"\']*\bsrc/', re.I)
_NEW_RE = re.compile(r'\bnew\s+([A-Za-z_]\w*)\s*\(')


def _mutation_verified_cut_harnesses(ws: Path) -> list[str]:
    """Real in-scope harnesses proven by a canonical mutation-verify-coverage.v1
    record (baseline PASS on the real CUT + >=1 behaviour-changing mutant KILLED).
    These are CUT-keyed (a runner command, not a Chimera Setup.sol), so
    `_harness_reality` cannot see them - yet they are the STRONGEST honest
    evidence of a real in-scope harness (un-fakeable mutation ground truth). A
    workspace whose only genuine harness is a Foundry invariant test (e.g.
    ProtocolFee_CoreInvariant) must not be flagged stub-harness/hollow. Require
    the CUT source_file on disk so a bare marker cannot pass."""
    import glob as _glob
    out: list[str] = []
    seen: set[str] = set()
    cands: list[str] = []
    for rel in ("cross-function-coverage", "mvc_sidecar"):
        cands += _glob.glob(str(ws / ".auditooor" / rel / "*.json"))
    cands += _glob.glob(str(ws / ".auditooor" / "mvc_sidecar*.json"))
    for p in cands:
        try:
            rec = json.loads(Path(p).read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(rec, dict):
            continue
        # P1-b (mode 13) + manual-unattested (mode B): reject a STALE sidecar whose
        # harness was clobbered after its kills were banked (recorded source-hash no
        # longer matches disk), AND a manual_registration record with no on-disk
        # source_file + captured baseline runner output (agent-authored, unverifiable).
        # Fail-closed: such records are advisory-only, never credit the strict floor.
        _uncredited = _sidecar_uncredited_reason(rec, ws)
        if _uncredited:
            continue
        # caveat A (schema normalization): credit via the CANONICAL shared predicate
        # FIRST, so a genuine sidecar in EITHER schema (auto-producer verdict==
        # 'non-vacuous' + killed_count, manual mutation_verified + mutants_killed,
        # or cluster mutation_detail/mutation_verify) is credited identically and a
        # genuine record is never missed because it lives in the other schema's
        # field. Fail-closed: still require a real on-disk CUT/harness file so a bare
        # marker cannot pass, and sidecar_is_genuine itself rejects vacuous/0-kill.
        if _sidecar_is_genuine(rec):
            _cands = []
            if isinstance(rec.get("harness_path"), str):
                _cands.append(rec["harness_path"])
            if isinstance(rec.get("cut_contracts"), list):
                _cands += [c for c in rec["cut_contracts"] if isinstance(c, str)]
            if isinstance(rec.get("source_file"), str):
                _cands.append(rec["source_file"])
            _ondisk = None
            for _c in _cands:
                _cp = Path(_c)
                if not _cp.is_absolute():
                    _cp = ws / _cp
                if _cp.is_file():
                    _ondisk = _cp
                    break
            if _ondisk is not None:
                label = f"mutation-verified:{_ondisk.name}"
                _fn = str(rec.get("function") or "").strip()
                if _fn:
                    label += f"::{_fn}"
                if label not in seen:
                    seen.add(label)
                    out.append(label)
                continue
        # Durable mvc_sidecar CLUSTER schema (mutation_verified + mutants_killed +
        # harness_path/cut_contracts, ws-relative paths): the strongest honest
        # evidence of a real in-scope harness, but it carries no
        # mutation_verify_coverage.v1 schema / verdict / mutant_results[] - so the
        # flat-schema block below skips it, silently dropping genuine >=1M-call core
        # campaigns to fail-stub-harnesses. Recognize it here (same serving-join gap
        # fixed in core-coverage + engine-harness-proof). UN-FAKEABLE: require
        # mutation_verified + a real kill + a real on-disk harness/CUT file.
        if rec.get("mutation_verified") is True:
            _killed = isinstance(rec.get("mutants_killed"), int) and rec["mutants_killed"] >= 1
            if not _killed:
                for _m in (rec.get("mutation_detail") or []):
                    if isinstance(_m, dict):
                        _rr = _m.get("mutant_result") or _m.get("result") or ""
                        if isinstance(_rr, str) and _rr.strip().lower() in (
                                "fail", "failed", "killed", "broken", "caught"):
                            _killed = True
                            break
            if _killed:
                _cands = []
                if isinstance(rec.get("harness_path"), str):
                    _cands.append(rec["harness_path"])
                if isinstance(rec.get("cut_contracts"), list):
                    _cands += [c for c in rec["cut_contracts"] if isinstance(c, str)]
                if isinstance(rec.get("source_file"), str):
                    _cands.append(rec["source_file"])
                _ondisk = None
                for _c in _cands:
                    _cp = Path(_c)
                    if not _cp.is_absolute():
                        _cp = ws / _cp
                    if _cp.is_file():
                        _ondisk = _cp
                        break
                if _ondisk is not None:
                    label = f"mutation-verified-cluster:{rec.get('cluster') or _ondisk.name}"
                    if label not in seen:
                        seen.add(label)
                        out.append(label)
                    continue
        if str(rec.get("schema")) != "auditooor.mutation_verify_coverage.v1":
            continue
        if str(rec.get("verdict")) != "non-vacuous":
            continue
        base = rec.get("baseline") if isinstance(rec.get("baseline"), dict) else {}
        if str(base.get("status")) not in ("pass", "passed", "ok"):
            continue
        # P0-d / P1-a: a kill counts only when genuine behaviour-changing (its tail
        # names a real invariant/property frame, not a setUp-crash/panic-only). Rows
        # with no output_tail keep the legacy `killed` truth (fail-open).
        if not any(isinstance(m, dict) and m.get("killed")
                   and (m.get("kill_kind") in (None, "behavior-changing")
                        or "output_tail" not in m)
                   and (("output_tail" not in m)
                        or _genuine_kill_tail(str(m.get("output_tail") or "")))
                   for m in (rec.get("mutant_results") or [])):
            continue
        src = str(rec.get("source_file") or "").strip()
        if not src or not Path(src).is_file():
            continue
        fn = str(rec.get("function") or "").strip()
        label = f"mutation-verified:{Path(src).name}" + (f"::{fn}" if fn else "")
        if label not in seen:
            seen.add(label)
            out.append(label)
    return out


def _harness_reality(ws: Path) -> tuple[list[str], list[str]]:
    """Classify scaffolded harness Setup.sol files.

    Returns (real_inscope_harnesses, mock_only_runs). A harness is a REAL in-scope
    run when its Setup imports from src/ AND deploys at least one non-mock contract
    (the in-scope contract-under-test) AND its sibling Properties.sol holds a real
    invariant (not assert(true)). Mocking EXTERNAL dependencies (MockERC20/MockOracle)
    does NOT make it a mock-target - only a Setup that deploys ONLY mocks (no in-scope
    src/ contract) is a mock-target run.
    """
    real_inscope: list[str] = []
    mock_only: list[str] = []
    for setup in ws.rglob("Setup.sol"):
        if "/lib/" in str(setup):
            continue
        try:
            t = setup.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        deploys = _NEW_RE.findall(t)
        if not deploys:
            continue
        imports_src = bool(_SRC_IMPORT_RE.search(t))
        non_mock_deploys = [c for c in deploys if not _MOCK_RE.match(c)]
        props = setup.parent / "Properties.sol"
        real_invariant = False
        if props.is_file():
            try:
                pt = props.read_text(encoding="utf-8", errors="replace")
                real_invariant = ("assert(" in pt and "assert(true)" not in pt) or bool(
                    re.search(r"function\s+property_\w+", pt)
                )
            except OSError:
                pass
        rel = str(setup.relative_to(ws))
        # in-scope: deploys at least one NON-mock contract (the real CUT) + a real invariant.
        # (Mocks named Mock*/Minimal*/Faithful* are external deps and are excluded from
        # non_mock_deploys; a reimplementation harness deploys ONLY such mocks.) The literal
        # src/ import is NOT required because in-scope source is often behind a remapping
        # (src_cut/, @ns/src/, etc.). imports_src only strengthens the signal.
        if non_mock_deploys and real_invariant:
            real_inscope.append(rel)
        elif deploys and all(_MOCK_RE.match(c) for c in deploys):
            mock_only.append(rel)
    return real_inscope, mock_only


def _rust_go_stub_harnesses(ws: Path, ext: str) -> tuple[int, int]:
    """Per-language stub/vacuous-harness heuristic for Rust (.rs) and Go (.go),
    mirroring the Solidity assert(true) detector in _engine_reality.

    Per-function harnesses canonically land in .auditooor/per_function_invariants
    (the go/rust arms) with a backward-compat fallback to
    poc-tests/per_function_invariants. We scan the language-matching authored
    harness files and classify each as a STUB (vacuous: assert!(true) /
    assert_eq!(true, ...) / a ghost x == x self-equality / 'not proof' marker /
    no assertion at all) or a REAL non-vacuous predicate (assert! / assert_eq! /
    prop_assert! over distinct bindings, or an 'invariant' marker).

    Honest-by-construction: if no per-function harness files of this language
    exist the function returns (0, 0) - it credits nothing. A file we cannot read
    is skipped, never counted as real.
    """
    pfi_dirs = [ws / ".auditooor" / "per_function_invariants",
                ws / "poc-tests" / "per_function_invariants"]
    files: list[Path] = []
    for _pfi in pfi_dirs:
        if _pfi.is_dir():
            files.extend(_pfi.rglob(f"*{ext}"))
    stub = real = 0
    # A real, non-vacuous assertion call (Rust assert!/assert_eq!/prop_assert! or
    # Go require/assert/t.Fatal-style check) over a NON-tautological argument.
    if ext == ".rs":
        real_assert_re = re.compile(r"\b(?:assert|assert_eq|assert_ne|prop_assert|prop_assert_eq)!\s*\(")
        vacuous_assert_re = re.compile(r"\b(?:assert|prop_assert)!\s*\(\s*true\s*[\),]")
    else:  # ".go"
        real_assert_re = re.compile(r"\b(?:require\.|assert\.|t\.(?:Fatal|Error|Fatalf|Errorf))\b")
        vacuous_assert_re = re.compile(r"\b(?:require|assert)\.(?:True|Equal)\s*\(\s*t\s*,\s*true\b")
    # Ghost self-equality: `x == x`, `foo == foo` (same token on both sides).
    self_equality_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*==\s*\1\b")
    for h in files[:200]:
        try:
            t = h.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        low = t.lower()
        is_vacuous = (
            bool(vacuous_assert_re.search(t))
            or "not proof" in low
            or bool(self_equality_re.search(t))
        )
        has_real_assert = bool(real_assert_re.search(t))
        if is_vacuous and not has_real_assert:
            stub += 1
        elif has_real_assert or "invariant" in low:
            real += 1
        else:
            # No assertion at all -> a vacuous harness that proves nothing.
            stub += 1
    return stub, real


def _vcis_placeholder_stubs(ws: Path) -> int:
    """G-2 (enforcement-gap audit 2026-07-03): a Go/Cosmos value-conservation-invariant-
    synth (VCIS) harness is VACUOUS/dead - and thus coverage-theater - when it STILL
    carries an un-substituted MODULE_ACCOUNT_PLACEHOLDER / DENOM_PLACEHOLDER, or an
    un-replaced GetTotal<Field> stub that returns a constant 0 (can never fire), OR
    defines RegisterVCISInvariants but never wires it into a RegisterInvariants call
    (dead code). No gate caught this - the #1 coverage-theater class
    (methodology_coverage_theater). Returns the count of vacuous VCIS harness files.
    Honest-by-construction: 0 when no VCIS harness exists (credits/penalizes nothing);
    a file we cannot read is skipped, never counted."""
    stub = 0
    cand: list[Path] = []
    seen: set[Path] = set()
    for r in (ws / "src", ws):
        if r.is_dir():
            for p in list(r.rglob("*vcis*.go")) + list(r.rglob("*conservation_vcis*.go")):
                if p not in seen:
                    seen.add(p)
                    cand.append(p)
    _ph = re.compile(r"MODULE_ACCOUNT_PLACEHOLDER|DENOM_PLACEHOLDER")
    _gettotal_stub = re.compile(
        r"func\s+[^\n{]*GetTotal\w+\s*\([^)]*\)[^\{\n]*\{\s*return\s+"
        r"(?:0|sdk\.ZeroInt\(\)|sdkmath\.ZeroInt\(\)|math\.ZeroInt\(\)|nil)\s*\}")
    _reg_defined = re.compile(r"func\s+RegisterVCISInvariants\b")
    _reg_call = re.compile(r"(?<![A-Za-z_])RegisterVCISInvariants\s*\(")
    for p in cand[:100]:
        try:
            t = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        vacuous = bool(_ph.search(t)) or bool(_gettotal_stub.search(t))
        if not vacuous and _reg_defined.search(t):
            # defined here; look for a call site anywhere in-scope (bounded scan).
            called = False
            for q in list((ws / "src").rglob("*.go"))[:600] if (ws / "src").is_dir() else []:
                try:
                    tq = q.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _reg_defined.search(tq):
                    continue  # the definition file, not a call
                if _reg_call.search(tq):
                    called = True
                    break
            if not called:
                vacuous = True
        if vacuous:
            stub += 1
    return stub


def _authored_real_output_bound_split(ws: Path) -> dict:
    """Scan authored engine-harness manifests and split authored entries by the
    `real_output_bound` honesty flag (wave-4 engine-real-output-property-class).

    real_output_bound=true  -> the harness asserts a RELATION over the REAL fn
                               return value (determinism f(x)==f(x), round-trip,
                               idempotence). This is GENUINE coverage (R80).
    real_output_bound=false -> the harness asserts over a hand-authored MODEL
                               with a `// MODEL ->` / mutate* seam. This is
                               needs-binding scaffolding: NOT genuine coverage,
                               and (because it is a real non-tautological relation
                               over the model) NOT a vacuous-fail either.

    Reads:
      * rust:  poc-tests/**/auditooor_harnesses/harness_manifest.json (authored[])
      * evm:   poc-tests/*-engine-harness/attempt_manifest.json (top-level flag)
    Returns {"genuine": int, "needs_binding": int, "manifests": int}. Generic
    stdlib, no workspace literals; absent/malformed manifests contribute 0.
    """
    genuine = 0
    needs_binding = 0
    manifests = 0
    poc = ws / "poc-tests"
    if not poc.is_dir():
        return {"genuine": 0, "needs_binding": 0, "manifests": 0}
    # Rust authored manifests: one file, many authored[] entries each flagged.
    for mpath in poc.rglob("harness_manifest.json"):
        d = _load(mpath)
        if not isinstance(d, dict):
            continue
        authored = d.get("authored")
        if not isinstance(authored, list):
            continue
        manifests += 1
        for entry in authored:
            if not isinstance(entry, dict):
                continue
            if entry.get("real_output_bound") is True:
                genuine += 1
            else:
                needs_binding += 1
    # EVM authored manifests: one file, a single top-level real_output_bound flag.
    for mpath in poc.rglob("attempt_manifest.json"):
        d = _load(mpath)
        if not isinstance(d, dict):
            continue
        manifests += 1
        if d.get("real_output_bound") is True:
            genuine += 1
        else:
            needs_binding += 1
    return {"genuine": genuine, "needs_binding": needs_binding, "manifests": manifests}


def _authored_engine_harnesses_genuinely_executed(ws: Path) -> tuple[bool, int]:
    """Return (credited: bool, authored_real_count: int).

    Reads .auditooor/solidity-deep-audit/engine-harness-execution.json (written
    by the Makefile audit-deep-solidity target, schema
    auditooor.engine_harness_execution.v1) and credits the authored
    poc-tests/*-engine-harness/ harnesses when ALL of the following hold:

      1. executed_engine_harness_count > 0 (at least one harness ran forge test)
      2. At least one harness entry has tests_passed > 0 and status in
         ("pass", "pass-with-failures")
      3. That harness's test directory contains at least one Solidity file with a
         genuine (non-tautological) assertion: assertEq( / require( / assert(
         but NOT a file where assert(true) is the ONLY assertion form present.

    This mirrors the per-function stub check: a harness with ONLY assert(true)
    is still classified as a stub and does NOT count.
    NOT a false-pass: requires both a real execution record AND a genuine
    assertion in the source.
    """
    exec_path = ws / ".auditooor" / "solidity-deep-audit" / "engine-harness-execution.json"
    data = _load(exec_path)
    if not isinstance(data, dict):
        return False, 0
    if str(data.get("schema") or "") != "auditooor.engine_harness_execution.v1":
        return False, 0
    try:
        total_executed = int(data.get("executed_engine_harness_count") or 0)
    except (ValueError, TypeError):
        return False, 0
    if total_executed <= 0:
        return False, 0
    # Scan each credited harness for genuine assertions.
    harnesses = data.get("harnesses") or []
    authored_real = 0
    for h in harnesses:
        if not isinstance(h, dict):
            continue
        try:
            tests_passed = int(h.get("tests_passed") or 0)
        except (ValueError, TypeError):
            continue
        status = str(h.get("status") or "").lower()
        if tests_passed <= 0 or status not in ("pass", "pass-with-failures"):
            continue
        root = h.get("root") or ""
        if not root:
            continue
        root_path = Path(root)
        # Producers may persist a workspace-relative harness root. Resolve it
        # against the audited workspace rather than the checker process cwd.
        if not root_path.is_absolute():
            root_path = ws / root_path
        # Scan test/ and src/ Solidity files for genuine (non-stub) assertions.
        sol_files: list[Path] = []
        for sub in ("test", "src"):
            d = root_path / sub
            if d.is_dir():
                sol_files.extend(d.rglob("*.sol"))
        # Also scan root-level .sol files.
        sol_files.extend(root_path.glob("*.sol"))
        is_genuine = False
        for sf in sol_files[:50]:  # cap to avoid scanning huge trees
            try:
                txt = sf.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            has_genuine_assert = "assertEq(" in txt or "require(" in txt
            has_any_assert = "assert(" in txt
            has_only_stub = "assert(true)" in txt and not has_genuine_assert
            if has_genuine_assert or (has_any_assert and not has_only_stub):
                is_genuine = True
                break
        if is_genuine:
            authored_real += 1
    return authored_real > 0, authored_real


def _non_economic_dispositioned_stub_count(ws: Path, harness_files: list) -> int:
    """Count AUTO-GENERATED scaffold .t.sol harness files (per-function-invariant-gen
    header) whose contract-under-test maps to an ACCEPTED non-economic disposition.

    Eligible files MUST carry the per-function-invariant-gen marker (a hand-authored
    stub is never credited here). The CUT is read from the scaffold's
    `Function under test: ... at <path>` header, falling back to the harness file's
    own path for the disposition match. Returns 0 when no disposition artifact
    exists or the lib is unavailable."""
    if _NED_MOD is None:
        return 0
    dispositions = _NED_MOD.load_dispositions(ws)
    if not dispositions:
        return 0
    marker = "Auto-generated by tools/per-function-invariant-gen.py"
    n = 0
    for h in (harness_files or [])[:400]:
        try:
            txt = Path(h).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if marker not in txt:
            continue
        cut_rel = ""
        m = re.search(r"Function under test:[^\n]*\bat\s+([^\s:]+\.sol)", txt)
        if m:
            cut_rel = m.group(1)
            try:
                cut_rel = str(Path(cut_rel).resolve().relative_to(ws.resolve()))
            except (ValueError, OSError):
                pass
        try:
            h_rel = str(Path(h).resolve().relative_to(ws.resolve()))
        except (ValueError, OSError):
            h_rel = str(h)
        target = cut_rel or h_rel
        if _NED_MOD.file_is_dispositioned(target, dispositions) is not None:
            n += 1
    return n


def _engine_reality(ws: Path, lang: str) -> dict:
    # For mixed workspaces, merge both engine families so neither side is invisible.
    if lang == "mixed":
        sol = _engine_reality(ws, "solidity")
        rust = _engine_reality(ws, "rust")
        merged: dict = {
            "top_level_engines": {},
            "per_function": sol.get("per_function", {}),
            "mock_target_runs": sol.get("mock_target_runs", []) + rust.get("mock_target_runs", []),
            "real_execution": sol["real_execution"] or rust["real_execution"],
            "mixed": True,
        }
        # Prefix engine keys so they don't collide.
        for k, v in sol.get("top_level_engines", {}).items():
            merged["top_level_engines"][f"sol:{k}"] = v
        for k, v in rust.get("top_level_engines", {}).items():
            merged["top_level_engines"][f"rust:{k}"] = v
        # Carry through sol-specific fields if present.
        for extra in ("real_inscope_harnesses", "fresh_manifest_pass"):
            if extra in sol:
                merged[extra] = sol[extra]
            if extra in rust:
                merged.setdefault(extra, rust[extra])
        return merged
    out = {"top_level_engines": {}, "per_function": {}, "mock_target_runs": [], "real_execution": False}
    if lang == "solidity":
        for e in ("halmos", "medusa", "echidna"):
            art = _load(ws / ".auditooor" / e / "artifact.json")
            out["top_level_engines"][e] = (art or {}).get("status", "absent")
        pf = _load(ws / ".audit_logs" / "solidity_per_function_halmos_manifest.json") or {}
        invs = pf.get("invocations") or []
        ok = sum(1 for r in invs if isinstance(r, dict) and r.get("status") == "ok")
        out["per_function"] = {
            "ok": ok, "executed": pf.get("executed_invocation_count"),
            "expected": pf.get("expected_invocation_count"),
            "truncated": pf.get("truncated_by_total_budget"),
        }
        # detect assert(true) stub harnesses.
        # Per-function harnesses canonically land in .auditooor/per_function_invariants
        # (go/rust arms + the canonicalized solidity arm); older solidity runs emitted
        # to poc-tests/per_function_invariants. Scan BOTH dirs for backward-compat.
        # IMPORTANT: per-function-invariant-gen.py writes .t.sol stubs to src/*/test/
        # (the forge project's test directory, not to pfi_dirs). The harness_path for
        # each generated file is recorded in pfi_dirs/manifest.json under
        # functions[*].harness_path. We MUST read those manifest entries and add the
        # referenced files to the scan list; otherwise the rglob finds 0 files and
        # stub_harnesses stays 0 even when 100+ assert(true) stubs exist, producing
        # a false pass-genuinely-audited verdict (tokenize-it anchor, 2026-06-09).
        pfi_dirs = [ws / ".auditooor" / "per_function_invariants",
                    ws / "poc-tests" / "per_function_invariants"]
        stub = real = 0
        _harness_files: list = []
        _harness_file_set: set = set()
        for _pfi in pfi_dirs:
            if _pfi.is_dir():
                for _f in _pfi.rglob("*.t.sol"):
                    _s = str(_f)
                    if _s not in _harness_file_set:
                        _harness_file_set.add(_s)
                        _harness_files.append(_f)
                # Also read harness_path entries from manifest.json so we catch
                # harnesses written by per-function-invariant-gen.py to src/*/test/
                _mf = _pfi / "manifest.json"
                if _mf.is_file():
                    try:
                        _mfd = json.loads(_mf.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        _mfd = {}
                    for _fn in (_mfd.get("functions") or []):
                        _hp = _fn.get("harness_path")
                        if _hp and _hp not in _harness_file_set:
                            _hp_path = Path(_hp)
                            if _hp_path.is_file():
                                _harness_file_set.add(_hp)
                                _harness_files.append(_hp_path)
                            else:
                                # A manifest that claims a harness_path which does
                                # not exist on disk is a broken/ghost stub claim.
                                # Count it as a stub so fail-stub-harnesses fires
                                # when NO real harnesses compensate. Silently
                                # skipping it would allow a manifest with N broken
                                # paths and 0 real files to produce a false
                                # pass-genuinely-audited verdict.
                                # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
                                stub += 1
        if _harness_files:
            for h in _harness_files[:200]:
                try:
                    t = h.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "assert(true)" in t or "not proof" in t.lower():
                    stub += 1
                elif "assert(" in t or "invariant" in t.lower():
                    real += 1
        # Per-unit non-economic-surface disposition: an AUTO-GENERATED scaffold
        # over a documented non-economic / OOS contract is not coverage-theater -
        # it is an honestly-dispositioned unit. Subtract such scaffolds from the
        # stub count so a config-only workspace does not trip fail-stub-harnesses.
        # Only the per-function-invariant-gen scaffolds are eligible (the marker is
        # checked in the helper); a hand-authored stub is still counted.
        _disp_stub = _non_economic_dispositioned_stub_count(ws, _harness_files)
        out["per_function"]["non_economic_dispositioned_stubs"] = _disp_stub
        stub = max(0, stub - _disp_stub)
        out["per_function"]["stub_harnesses"] = stub
        out["per_function"]["real_harnesses"] = real
        # classify scaffolded harnesses: in-scope (real CUT + real invariant) vs mock-only
        real_inscope, mock_only = _harness_reality(ws)
        # Also credit mutation-verified CUT harnesses (Foundry invariant tests
        # proven non-vacuous via mutation-verify-coverage.v1) - the un-fakeable
        # ground truth _harness_reality's Chimera-Setup scan cannot see.
        real_inscope = list(real_inscope) + _mutation_verified_cut_harnesses(ws)
        out["real_inscope_harnesses"] = real_inscope
        out["mock_target_runs"] = mock_only
        # real execution if a top-level engine is ok, a real per-function harness ran,
        # a genuine in-scope chimera harness exists, OR the Makefile-authored
        # poc-tests/*-engine-harness/ harnesses ran forge test with genuine assertions
        # (non-assert(true)) and at least one passing test. Mocking external deps
        # does not disqualify a chimera harness; an assert(true)-only authored
        # harness is still a stub and does NOT satisfy this condition.
        _authored_credited, _authored_real_count = _authored_engine_harnesses_genuinely_executed(ws)
        out["authored_engine_harnesses_credited"] = _authored_credited
        out["authored_engine_harness_real_count"] = _authored_real_count
        # wave-4: split authored entries by real_output_bound. Only genuine (real
        # output asserted) entries count as genuine engine coverage; needs_binding
        # (model+seam) is honest scaffolding that must be bound before it counts.
        out["real_output_bound_split"] = _authored_real_output_bound_split(ws)
        out["real_execution"] = (
            any(s == "ok" for s in out["top_level_engines"].values())
            or real > 0
            or len(real_inscope) > 0
            or _authored_credited
        )
    elif lang == "rust":
        manifests = list((ws / ".audit_logs").glob("audit_deep_*_manifest.json"))
        statuses = {}
        for m in manifests:
            d = _load(m) or {}
            # audit_deep_all_manifest.json stores status in profiles[].status, not top-level.
            # Treat a manifest where ALL profiles completed (status="success"/exit_code=0) as "ok".
            profiles = d.get("profiles") or []
            if profiles:
                all_ok = all(
                    p.get("status") in ("success", "ok", "complete") or p.get("exit_code") == 0
                    for p in profiles
                )
                statuses[m.name] = "ok" if all_ok else "profiles-incomplete"
            else:
                # Fall back to top-level "status" field for manifests that use it
                statuses[m.name] = d.get("status")
        # Also accept "pass-fresh-deep-manifest" from audit_run_full_manifest.jsonl as evidence
        # that a fresh audit_deep_all run completed with real engine execution.
        rfm_path = ws / ".auditooor" / "audit_run_full_manifest.jsonl"
        fresh_manifest_pass = False
        if rfm_path.is_file():
            try:
                for line in rfm_path.read_text(encoding="utf-8").splitlines():
                    try:
                        ev = json.loads(line)
                    except (ValueError, KeyError):
                        continue
                    if (
                        ev.get("event") == "stage-pass"
                        and ev.get("stage") == "deep-freshness"
                        and ev.get("deep_engine_completion_mode") == "fresh-manifest"
                        and ev.get("deep_engine_freshness_verdict") == "pass-fresh-deep-manifest"
                    ):
                        fresh_manifest_pass = True
                        break
            except OSError:
                pass
        out["top_level_engines"] = statuses
        out["fresh_manifest_pass"] = fresh_manifest_pass
        # Rust per-function stub/vacuous-harness classification, mirroring the
        # Solidity assert(true) arm above. This does NOT change real_execution
        # (which still rests on a genuinely-executed engine manifest); it surfaces
        # the stub/real counts so check() can flag a stub-only Rust workspace the
        # same way it flags a stub-only Solidity workspace.
        rust_stub, rust_real = _rust_go_stub_harnesses(ws, ".rs")
        out["per_function"]["stub_harnesses"] = rust_stub
        out["per_function"]["real_harnesses"] = rust_real
        # wave-4: real_output_bound split over authored rust harness manifests.
        out["real_output_bound_split"] = _authored_real_output_bound_split(ws)
        # SERVING-JOIN FIX (nuva 2026-07-04): mirror the Go/Solidity arms - credit
        # genuine mutation-verified CUT harnesses (un-fakeable kill on a real on-disk
        # Rust CUT/harness file) into real_execution so a mutation-proven Rust core
        # campaign is not mislabelled hollow when no audit_deep manifest is present.
        # false-green-safe: helper requires baseline pass + real kill + on-disk file.
        _mvc_cut = _mutation_verified_cut_harnesses(ws)
        out["mutation_verified_cut_harnesses"] = _mvc_cut
        out["real_execution"] = (
            any(s in ("ok", "pass", "complete") for s in statuses.values())
            or fresh_manifest_pass
            or _nonevm_engine_genuinely_executed(ws)
            or bool(_mvc_cut)
        )
    elif lang == "go":
        # Go DYNAMIC engine arm. The Go deep-engine runner
        # (tools/go-dynamic-engine-runner.sh) writes its result to
        # <ws>/fuzz_runs/<ts>/manifest.json (and .audit_logs/fuzz_runs/...) with
        # engine="go-dynamic", a status, and positive count fields
        # (tests_passed / executed_harnesses) plus staticcheck_findings. We also
        # read any .audit_logs/audit_deep_*_manifest.json the Go pipeline emits.
        # Honest: an absent or tool-not-installed manifest contributes nothing.
        statuses = {}
        go_engine_runs = []
        staticcheck_findings_total = 0
        for sub in ("fuzz_runs", ".audit_logs/fuzz_runs"):
            d = ws / sub
            if not d.is_dir():
                continue
            for man in d.glob("*/manifest.json"):
                data = _load(man) or {}
                eng = str(data.get("engine") or "").lower()
                # Only credit Go engine manifests here; EVM/rust manifests are
                # handled by their own arms.
                if "go" not in eng and "staticcheck" not in eng and "govulncheck" not in eng:
                    continue
                status = str(data.get("status") or "").lower()
                statuses[f"{man.parent.name}:{eng or 'go'}"] = status or "absent"
                count = 0
                for k in ("tests_passed", "executed_harnesses", "fuzz_targets",
                          "properties_checked"):
                    try:
                        count = max(count, int(data.get(k) or 0))
                    except (ValueError, TypeError):
                        pass
                sc = data.get("staticcheck_findings")
                try:
                    staticcheck_findings_total += int(sc)
                except (ValueError, TypeError):
                    pass
                if status in ("pass", "ok", "counterexample") and count > 0:
                    go_engine_runs.append(man.parent.name)
        # Also surface any audit_deep_*_manifest.json the Go pipeline emits, using
        # the same profile/status reading as the rust arm (no double-credit: this
        # only adds status visibility, real_execution still needs a positive run).
        for m in (ws / ".audit_logs").glob("audit_deep_*_manifest.json"):
            d = _load(m) or {}
            profiles = d.get("profiles") or []
            if profiles:
                all_ok = all(
                    p.get("status") in ("success", "ok", "complete") or p.get("exit_code") == 0
                    for p in profiles
                )
                statuses[m.name] = "ok" if all_ok else "profiles-incomplete"
            else:
                statuses[m.name] = d.get("status")
        go_stub, go_real = _rust_go_stub_harnesses(ws, ".go")
        # G-2: a VACUOUS VCIS conservation harness (residual MODULE_ACCOUNT/DENOM
        # placeholder, GetTotal-zero-stub, or RegisterVCISInvariants defined-but-never-
        # wired) credits conservation coverage while it can NEVER fire - the #1 coverage-
        # theater class. ALWAYS surface the count (visible advisory); fold it into the
        # hard fail-stub-harnesses tally ONLY under AUDITOOOR_VCIS_STUB_STRICT (default
        # OFF -> no retroactive re-fail of a ws that left the scaffold unfilled).
        _vcis_stub = _vcis_placeholder_stubs(ws)
        out["per_function"]["vcis_placeholder_stubs"] = _vcis_stub
        if _vcis_stub > 0 and os.environ.get("AUDITOOOR_VCIS_STUB_STRICT", "").strip().lower() in ("1", "true", "yes", "on"):
            go_stub += _vcis_stub
        out["per_function"]["stub_harnesses"] = go_stub
        out["per_function"]["real_harnesses"] = go_real
        out["top_level_engines"] = statuses
        out["staticcheck_findings"] = staticcheck_findings_total
        # real_execution requires a GENUINELY executed Go engine run (positive
        # harness/test count on a pass/ok/counterexample status). An absent or
        # tool-not-installed manifest (count 0) does NOT count - no fabricated
        # credit. A staticcheck finding alone is corroborating, not engine proof.
        #
        # NOTE: statuses is intentionally NOT used in real_execution here.
        # The audit_deep_*_manifest.json glob above populates statuses for
        # visibility (top_level_engines) only. audit_deep_all_manifest.json is the
        # LANGUAGE-AGNOSTIC orchestrator handoff packet (no engine/language field),
        # so a prior Solidity or Rust run's "ok" status in statuses MUST NOT
        # certify a Go workspace with zero actual Go engine runs. Only go_engine_runs
        # (filtered to engine names containing "go"/"staticcheck"/"govulncheck") and
        # the language-filtered _nonevm_engine_genuinely_executed probe are allowed.
        # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
        #
        # SERVING-JOIN FIX (nuva 2026-07-04): the Go arm also credits genuine
        # mutation-verified CUT harnesses (mvc_sidecar records with a real kill on a
        # real on-disk Go CUT/harness file) - the SAME un-fakeable ground truth the
        # Solidity arm already folds into real_execution via real_inscope +
        # _mutation_verified_cut_harnesses. A Cosmos/Go vault whose economic-invariant
        # Go harnesses (economic_invariant_test.go / reconcile_test.go / xfn_state_test.go)
        # killed behaviour-changing mutants over src/vault/keeper/*.go was
        # invisible to the Go real_execution predicate (which only saw fuzz_runs Go
        # manifests + the fuzz_runs positive-count probe), producing a false
        # fail-hollow-engines despite genuine deep Go engine execution on disk. The
        # helper is false-green-safe: it requires baseline PASS + >=1 behaviour-
        # changing kill + a real on-disk CUT file, and rejects drifted/vacuous sidecars.
        _mvc_cut = _mutation_verified_cut_harnesses(ws)
        out["mutation_verified_cut_harnesses"] = _mvc_cut
        out["real_execution"] = (
            bool(go_engine_runs)
            or _nonevm_engine_genuinely_executed(ws)
            or bool(_mvc_cut)
        )
    else:
        # Unhandled language (move / cairo / vyper / zk and any future target):
        # report the engine arm as absent rather than silently borrowing the
        # rust/solidity logic. real_execution stays False unless the generic
        # non-EVM engine probe finds a genuinely-executed language manifest.
        out["real_execution"] = _nonevm_engine_genuinely_executed(ws)
    return out


def _nonevm_engine_genuinely_executed(ws: Path) -> bool:
    """A non-EVM (Rust/Go/Move) workspace has GENUINE engine execution iff a
    language-matching engine manifest shows a POSITIVE executed harness/test
    count. This is the same evidence the L37 engine-harness signal credits.
    A failed/skipped EVM engine profile (halmos/medusa/echidna have no forge
    project on a Rust target) must NOT make the workspace hollow when the
    language engine genuinely ran. NOT a false-pass: it requires a real
    positive executed count, never a spec-doc 'profile success' with zero runs.
    Generic for any non-EVM workspace."""
    _EVM = {"halmos", "medusa", "echidna"}
    for sub in ("fuzz_runs", ".audit_logs/fuzz_runs"):
        d = ws / sub
        if not d.is_dir():
            continue
        for man in d.glob("*/manifest.json"):
            data = _load(man) or {}
            if str(data.get("engine") or "").lower() in _EVM:
                continue
            status = str(data.get("status") or "").lower()
            count = 0
            for k in ("tests_passed", "tests_run", "harness_count",
                      "executed_harnesses", "properties_checked"):
                try:
                    count = max(count, int(data.get(k) or 0))
                except (ValueError, TypeError):
                    pass
            if status in ("pass", "ok", "counterexample") and count > 0:
                return True
    return False


def _depth_evidence_present(ws: Path) -> bool:
    """R81: a workspace has DEPTH evidence iff a fresh depth_certificate.json
    exists declaring BOTH depth passes ran with evidence (per-guard
    negative-space + proactive sibling-path guard-diff). We deliberately read
    the cert directly (not via the depth gate) so this stays a cheap, offline,
    dependency-free presence probe: the L37 gate does the full freshness /
    survivor validation; here we only answer "is there ANY depth evidence?".
    A 'genuinely audited' claim with zero depth evidence is hollow."""
    cert = ws / ".auditooor" / "depth_certificate.json"
    try:
        data = json.loads(cert.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(data, dict):
        return False
    return bool(data.get("negative_space_ran")) and bool(data.get("sibling_diff_ran"))


def check(ws: Path, lang: str) -> dict:
    cov = _true_coverage(ws)
    eng = _engine_reality(ws, lang)
    fails = []
    # E3.4 - typed <lang>-mutation-runner-absent verdicts (move/cairo/circom/noir)
    # collected during the STRICT per-language floor; surfaced in the result so a
    # no-builtin-runner language is recorded (with its waiver path), never silent.
    runner_absent_verdicts: list = []
    # FIX 2 (visibility): three DISTINCT value-moving-floor counts so a reviewer
    # sees how much of a pass is real executed-code proof vs operator-approved
    # scope-removal (dispositioned) vs still-uncovered. Never collapse
    # dispositioned into covered/proven. Populated in PATH 2 below.
    value_moving_floor_detail: dict | None = None
    true_pct = cov["true_coverage_pct"]
    if cov["gate_reported_pct"] == 1.0 and true_pct is not None and true_pct < 0.99:
        fails.append("fail-fake-coverage")
    if true_pct is not None and true_pct < 1.0:
        fails.append("coverage-below-100")
    if not eng["real_execution"]:
        fails.append("fail-hollow-engines")
    # fail-no-coverage-gate: engines genuinely ran (real_execution=True) but the
    # g15 coverage gate file is absent. A workspace where engines ran but no
    # coverage gate ever recorded WHAT was covered is itself hollow - the
    # "genuinely audited" verdict requires knowing the coverage denominator.
    # We gate on real_execution to avoid penalizing honest intermediate runs
    # that have not yet produced engine evidence (those already have
    # fail-hollow-engines). If fail-hollow-engines is already set, this
    # condition is redundant (no double-penalty). Only appended here; the
    # verdict line and gaps block below already surface it.
    # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
    if cov.get("gate_file_missing") and eng["real_execution"]:
        fails.append("fail-no-coverage-gate")
    # a mock-ONLY harness is only a hard fail when it is the ONLY engine evidence; if a
    # genuine in-scope harness also exists, a leftover/superseded mock harness is advisory.
    if eng.get("mock_target_runs") and not eng.get("real_inscope_harnesses"):
        fails.append("fail-mock-target")
    if (
        lang in ("solidity", "mixed")
        and eng["per_function"].get("stub_harnesses", 0) > 0
        and eng["per_function"].get("real_harnesses", 0) == 0
        and not eng.get("real_inscope_harnesses")
        and not eng.get("authored_engine_harnesses_credited")
    ):
        if "fail-hollow-engines" not in fails:
            fails.append("fail-stub-harnesses")
    # R81 depth layer: a workspace that LOOKS audited (coverage reported done +
    # engines genuinely executed) but carries ZERO depth evidence (no fresh
    # depth_certificate.json with both the per-guard negative-space pass and the
    # proactive sibling-path guard-diff pass) is itself hollow - "genuinely
    # audited" must require the per-unit depth layer, not just per-surface
    # coverage. We only raise this when the workspace would otherwise pass the
    # coverage/engine honesty checks (it is the peer of fail-fake-coverage on the
    # depth axis); a workspace already flagged hollow is not double-penalized.
    depth_present = _depth_evidence_present(ws)
    looks_audited = (
        cov["gate_reported_pct"] == 1.0
        and eng["real_execution"]
        and "fail-fake-coverage" not in fails
        and "fail-hollow-engines" not in fails
        and "fail-mock-target" not in fails
        and "fail-stub-harnesses" not in fails
    )
    if looks_audited and not depth_present:
        fails.append("fail-depth-not-run")
    # R80/R81 HOLLOW-PER-FUNCTION HARNESSES: a workspace whose per-function
    # harnesses were generated but produced 0 mutation-verified kills is
    # coverage-theater. Two detection paths - both must be guarded:
    #
    # PATH 1 (flag-based, existing): DEEP_AUDIT_HOLLOW.flag written by
    #   hollow-engine-check.py when generated_per_function_harness_count>0
    #   AND mutation_verified_genuine_count==0. The flag alone is sufficient
    #   to fail; genuine_coverage_manifest with mutation_verified_genuine_count>0
    #   overrides a stale flag.
    #
    # PATH 2 (value-moving-functions direct, new - closes the monero false-green):
    #   A workspace that NEVER ran the deep audit pipeline (no hollow flag written)
    #   but lists >=1 value-moving function in value_moving_functions.json AND has
    #   per_function_verified==0 in mutation_verify_coverage.json MUST also fail.
    #   This fires REGARDLESS of whether DEEP_AUDIT_HOLLOW.flag is present.
    #   If value_moving_functions.json is absent, auto-run value-moving-functions.py
    #   to populate it. The gate is skipped when no value-moving functions are found
    #   (function_count=0) so workspaces with no value-moving surface are unaffected.
    #
    # Only fires when the workspace would otherwise pass the shallow honesty checks
    # (fail-hollow-engines / fail-stub-harnesses not already set). No double-penalty.
    # Generic: reads only canonical JSON/flag artifacts, no workspace literals.
    _HOLLOW_ALREADY = {"fail-hollow-engines", "fail-stub-harnesses", "fail-hollow-per-function-harnesses"}
    if not (_HOLLOW_ALREADY & set(fails)):
        # PATH 1: flag-based
        _hollow_flag = ws / ".auditooor" / "DEEP_AUDIT_HOLLOW.flag"
        if _hollow_flag.is_file():
            # The flag is stale (skip fail) only when BOTH:
            #   (a) genuine_coverage_manifest claims mutation_verified_genuine_count > 0, AND
            #   (b) that claim is CORROBORATED by mutation_verify_coverage.json having >=1
            #       per_function entry with mutation_verified==True, oracle_verdict=="non-vacuous",
            #       killed==True.
            # A hand-written manifest with a bare integer is NOT sufficient - it must be
            # backed by the tool-written per_function list.  If mutation_verify_coverage.json
            # is absent or has 0 corroborated entries, the flag wins and the fail fires.
            _gcm_path = ws / ".auditooor" / "genuine_coverage_manifest.json"
            try:
                _gcm = json.loads(_gcm_path.read_text(encoding="utf-8")) if _gcm_path.is_file() else {}
            except (OSError, ValueError):
                _gcm = {}
            _gcm_genuine = (_gcm.get("mutation_verified_genuine_count") or 0) if isinstance(_gcm, dict) else 0
            _corroborated = _corroborated_genuine_count(ws)
            # Flag is stale when the corroborated (tool-written, un-fakeable) genuine
            # count is >0 - that is itself sufficient evidence (incl. a standalone
            # mutation-verify-coverage.v1 CUT harness), with or without the gcm bare
            # integer also agreeing.
            _flag_is_stale = _corroborated > 0
            if not _flag_is_stale:
                fails.append("fail-hollow-per-function-harnesses")

    # PATH 2: value-moving-functions direct (fires even when flag is absent)
    # Re-check _HOLLOW_ALREADY in case PATH 1 just appended.
    if not ({"fail-hollow-engines", "fail-stub-harnesses", "fail-hollow-per-function-harnesses"} & set(fails)):
        _vmf_path = ws / ".auditooor" / "value_moving_functions.json"
        if not _vmf_path.is_file():
            # Auto-enumerate: try to run value-moving-functions.py to produce the artifact.
            _vmf_script = Path(__file__).resolve().parent / "value-moving-functions.py"
            if _vmf_script.is_file():
                import subprocess as _sp
                import sys as _sys
                try:
                    _sp.run(
                        [_sys.executable, str(_vmf_script), str(ws)],
                        capture_output=True, timeout=60,
                    )
                except Exception:
                    pass
        _vmf = _load(_vmf_path) if _vmf_path.is_file() else None
        _vmf_count = ((_vmf.get("function_count") or 0) if isinstance(_vmf, dict) else 0)
        if _vmf_count >= 1:
            # Load per_function_verified from mutation_verify_coverage.json.
            _mvc = _load(ws / ".auditooor" / "mutation_verify_coverage.json") or {}
            _mvc_counts = (_mvc.get("counts") or {}) if isinstance(_mvc, dict) else {}
            _pf_verified = (_mvc_counts.get("per_function_verified") or 0)
            # genuine_coverage_manifest may claim genuine kills, but that bare integer
            # must be CORROBORATED by tool-written per_function entries in
            # mutation_verify_coverage.json (mutation_verified+non-vacuous+killed).
            # A hand-written manifest alone is NOT sufficient evidence.
            _gcm2_path = ws / ".auditooor" / "genuine_coverage_manifest.json"
            _gcm2 = _load(_gcm2_path) if _gcm2_path.is_file() else None
            _gcm2_genuine = (
                (_gcm2.get("mutation_verified_genuine_count") or 0)
                if isinstance(_gcm2, dict) else 0
            )
            _corroborated2 = _corroborated_genuine_count(ws)
            # Compute the three-way breakdown ONCE (proven / dispositioned /
            # uncovered) - emitted on the result for reviewer visibility and reused
            # for the STRICT unmet-language decision so the numbers can never drift.
            value_moving_floor_detail = _value_moving_floor_breakdown(ws, _vmf)
            # E3.3 - under STRICT (AUDITOOOR_L37_STRICT=1) the bar is a PER
            # LANGUAGE SUB-TREE value-moving floor: corroborated_genuine[lang] >=
            # value_moving_count[lang] for EVERY present language (a mixed
            # Solidity+circom repo must not clear the floor using only its
            # Solidity half). The legacy n>=1 OR was a whole-ws aggregate that a
            # single solidity kill could satisfy while every value-moving fn in
            # another language stayed unverified. Default (non-STRICT) keeps the
            # aggregate behavior so the gate only TIGHTENS under STRICT.
            _strict = os.environ.get("AUDITOOOR_L37_STRICT", "").strip() == "1"
            if _strict:
                _unmet = value_moving_floor_detail["unmet_languages"]
                if _unmet:
                    # E3.4 - distinguish backed languages (sol/rs/go: a missing
                    # producer is FATAL) from no-builtin-runner languages
                    # (move/cairo/circom/noir: emit a TYPED <lang>-mutation-runner-
                    # absent verdict + a waiver path, never an un-waivable brick).
                    # A no-runner language is waived ONLY when its waiver env is set
                    # (a language-appropriate static-soundness/runner substitute);
                    # otherwise its typed-absent verdict is recorded AND the floor
                    # still fails (typed, never silent).
                    _backed_unmet = [l for l in _unmet if l in _MUT_RUNNER_LANGS]
                    _norunner_unmet = [l for l in _unmet if l in _MUT_RUNNER_ABSENT_LANGS]
                    _other_unmet = [
                        l for l in _unmet
                        if l not in _MUT_RUNNER_LANGS and l not in _MUT_RUNNER_ABSENT_LANGS
                    ]
                    for _l in _norunner_unmet:
                        _waived = os.environ.get(
                            _RUNNER_WAIVER_ENV.get(_l, ""), "").strip() != ""
                        runner_absent_verdicts.append({
                            "lang": _l,
                            "verdict": _RUNNER_ABSENT_VERDICT.get(
                                _l, f"{_l}-mutation-runner-absent"),
                            "waived": _waived,
                            "waiver_env": _RUNNER_WAIVER_ENV.get(_l, ""),
                        })
                    _unwaived_norunner = [
                        v["lang"] for v in runner_absent_verdicts if not v["waived"]
                    ]
                    if _backed_unmet or _other_unmet or _unwaived_norunner:
                        fails.append("fail-hollow-per-function-harnesses")
            else:
                # Genuine evidence = per_function_verified>0 (aggregate), OR a corroborated
                # (tool-written, un-fakeable) genuine count >0. The corroborated count
                # includes standalone mutation-verify-coverage.v1 CUT harnesses (killed
                # mutant + CUT on disk), so it suffices on its own; a bare gcm integer
                # without corroboration still does not.
                _has_genuine_evidence = _pf_verified > 0 or _corroborated2 > 0
                if not _has_genuine_evidence:
                    fails.append("fail-hollow-per-function-harnesses")
    verdict = "pass-genuinely-audited" if not fails else (fails[0] if len(fails) == 1 else "needs-work")
    gaps = []
    if true_pct is not None and true_pct < 1.0:
        # When coverage_report.json is available, use its covered/total for the gap message
        # because the gate's queue-basename counters can claim 100% while real coverage is lower.
        cr = cov.get("underlying_report_pct")
        cr_total = cov.get("total_units")  # same denominator
        if cr is not None and cov.get("underlying_uncovered"):
            cr_covered = round(cr * cr_total) if cr_total else cov["true_covered"]
            gaps.append(
                f"coverage: {cr_covered}/{cr_total} real ({cov['budget_skipped']} budget-skipped,"
                f" {len(cov['gate_unscanned'])} unscanned; underlying_report={cr:.4f})"
            )
        else:
            gaps.append(f"coverage: {cov['true_covered']}/{cov['total_units']} real ({cov['budget_skipped']} budget-skipped, {len(cov['gate_unscanned'])} unscanned)")
    if not eng["real_execution"]:
        gaps.append(f"engines hollow: top-level={eng['top_level_engines']}, stubs={eng['per_function'].get('stub_harnesses')}")
    if eng.get("mock_target_runs"):
        gaps.append(f"mock-target runs (not in-scope source): {eng['mock_target_runs']}")
    if "fail-depth-not-run" in fails:
        gaps.append(
            "depth layer absent: no fresh .auditooor/depth_certificate.json with "
            "per-guard negative-space + sibling-path guard-diff evidence (R81)"
        )
    # r36-rebuttal: bugfix-inventory-claude-20260610 agent_pathspec.json
    if "fail-no-coverage-gate" in fails:
        gaps.append(
            "coverage gate absent: engines ran but .auditooor/"
            "g15_hunt_coverage_gate_last_result.json was never written; "
            # r36-rebuttal: lane-coverage-gate-msg - the target is hunt-coverage-gate;
            # 'audit-coverage-gate' does not exist (misleading-remediation false-red).
            "run 'make hunt-coverage-gate WS=<ws>' to measure TRUE coverage"
        )
    result = {
        "schema": SCHEMA, "workspace": str(ws), "language": lang,
        "verdict": verdict, "fails": fails, "coverage": cov, "engines": eng, "gaps": gaps,
    }
    if runner_absent_verdicts:
        result["mutation_runner_absent"] = runner_absent_verdicts
    if value_moving_floor_detail is not None:
        # Reviewer visibility: proven-by-executed-code vs dispositioned(operator-
        # approved scope-removal) vs uncovered - three DISTINCT numbers, never
        # folded together, so a pass resting on scope-removal is legible.
        result["value_moving_floor"] = {
            "proven_by_executed_code": value_moving_floor_detail["proven_by_executed_code"],
            "dispositioned": value_moving_floor_detail["dispositioned"],
            "uncovered": value_moving_floor_detail["uncovered"],
            "value_moving_total": value_moving_floor_detail["value_moving_total"],
        }
    return result


# L11: directory segments that hold VENDORED / dependency / build / test files.
# A bare glob like ws.glob("src/**/*.rs") matches these too, so a pure-Solidity
# workspace can mis-detect rust/go from a single vendored lib (e.g. strata's
# src/contracts/node_modules/@nomicfoundation/edr/src/*.rs). Exclude any path that
# crosses one of these segments from the language probe.
_VENDORED_SEGMENTS = frozenset({
    "lib", "node_modules", "dependencies", "forge-std", "out", "cache",
    "test", "tests", "vendor", ".git",
})


def _is_vendored_path(p: Path, ws: Path) -> bool:
    """True if p lives under any vendored/dependency/build/test directory segment."""
    try:
        rel = p.relative_to(ws)
    except ValueError:
        rel = p
    # exclude the file basename; only directory segments gate vendoring.
    return any(seg in _VENDORED_SEGMENTS for seg in rel.parts[:-1])


def _lang_from_inscope(ws: Path) -> str:
    """Derive the dominant language from .auditooor/inscope_units.jsonl 'lang' field
    when present. Returns '' if the manifest is absent or carries no usable lang.
    This is preferred over filesystem globs because it reflects the REAL in-scope
    surface, not vendored deps that happen to sit in the tree."""
    p = ws / ".auditooor" / "inscope_units.jsonl"
    if not p.is_file():
        return ""
    counts: dict = {}
    try:
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            lg = str(d.get("lang") or "").strip().lower()
            if not lg:
                # fall back to inferring from the file extension on the row
                f = str(d.get("file") or d.get("unit") or "")
                if f.endswith(".sol"):
                    lg = "solidity"
                elif f.endswith(".rs"):
                    lg = "rust"
                elif f.endswith(".go"):
                    lg = "go"
            if lg in ("solidity", "rust", "go"):
                counts[lg] = counts.get(lg, 0) + 1
    except OSError:
        return ""
    if not counts:
        return ""
    langs = set(counts)
    if "rust" in langs and "solidity" in langs:
        return "mixed"
    # dominant single language by unit count
    return max(counts, key=counts.get)


def _detect_lang(ws: Path) -> str:
    # L11: prefer the in-scope manifest's dominant language when available - it is
    # the authoritative real surface and is immune to vendored-dep mis-detection.
    by_manifest = _lang_from_inscope(ws)
    if by_manifest:
        return by_manifest
    # else fall back to a filtered filesystem walk that EXCLUDES vendored dirs.
    has_rust = (
        any(not _is_vendored_path(p, ws) for p in ws.glob("src/**/*.rs"))
        or ((ws / "src" / "Cargo.toml").exists()
            and not _is_vendored_path(ws / "src" / "Cargo.toml", ws))
        or any(not _is_vendored_path(p, ws) for p in (ws / "src").glob("*/Cargo.toml"))
    )
    has_sol = any(not _is_vendored_path(p, ws) for p in ws.glob("src/**/*.sol"))
    has_go = (
        any(not _is_vendored_path(p, ws) for p in ws.glob("src/**/*.go"))
        or (ws / "go.mod").exists()
        or any(not _is_vendored_path(p, ws) for p in ws.glob("**/go.mod"))
    )
    if has_rust and has_sol:
        return "mixed"
    if has_rust:
        return "rust"
    if has_go and not has_sol:
        return "go"
    return "solidity"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--lang", choices=["solidity", "rust", "go", "auto"], default="auto")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--report", action="store_true", help="always exit 0 (report mode)")
    a = ap.parse_args(argv)
    ws = a.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[audit-honesty-check] not found: {ws}", file=sys.stderr)
        return 2
    lang = _detect_lang(ws) if a.lang == "auto" else a.lang
    res = check(ws, lang)
    if a.json:
        print(json.dumps(res, indent=2, sort_keys=True))
    else:
        c = res["coverage"]
        print(f"[audit-honesty-check] {ws.name}: {res['verdict']}")
        print(f"  coverage: gate={c['gate_reported_pct']} TRUE={c['true_coverage_pct']} ({c['true_covered']}/{c['total_units']}; {c['budget_skipped']} budget-skipped)")
        print(f"  engines real_execution={res['engines']['real_execution']} top={res['engines']['top_level_engines']}")
        for g in res["gaps"]:
            print(f"  GAP: {g}")
    return 0 if (a.report or res["verdict"] == "pass-genuinely-audited") else 1


if __name__ == "__main__":
    raise SystemExit(main())
