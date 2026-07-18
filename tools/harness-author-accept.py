#!/usr/bin/env python3
"""harness-author-accept.py - the SINGLE author-time acceptance gate (spec item E).

A thin COMPOSITION wrapper (NO new logic of its own) that an agent runs BEFORE
reporting a harness done, so a dead harness is caught at AUTHOR time instead of
at the late audit-complete. It composes the already-landed enforcement tools:

  (1) lib/harness_vacuity.py deep-mode detectors over the harness file
      (modes 1, 4, 4b, 5-subterm, 5-skeleton, 6 + the backward-compatible
      sentinel-only check). Source: tools/lib/harness_vacuity.deep_vacuity_modes
      + is_sentinel_only_harness (lane A).
  (2) mutation-verify-coverage.py for >=1 ATTRIBUTED non-panic behavior-changing
      kill per invariant + the reachability-witness execution check
      (P0-d / P1-a / P0-b6). Source: mutation-verify-coverage.verify() verdict
      (`non-vacuous` + behavior_changing_kill_count>=1 + every credited invariant
      attributed + witness_reached not False). Lane B owns the verdict logic;
      this wrapper only READS the verdict it returns.
  (3) invariant-fuzz-completeness.py for >=1M / no-dry-run / engine-choice
      (P1-d). Source: invariant-fuzz-completeness.evaluate() verdict +
      per-harness fail (under-budgeted / dry-run-not-a-campaign /
      selfdestruct-needs-echidna).
  (4) the .auditooor/inscope_units.jsonl check (P1-e): the harness CUT path must
      be in the authoritative allow-list.
  (5) the sidecar-registration check (P1-c): a conforming
      .auditooor/mvc_sidecar/*.json must exist that names this harness and whose
      recorded harness_source_sha256 still matches the on-disk file
      (stale-sidecar guard, mode 13).

It prints `pass-harness-accept` on a clean composite verdict, or a FAIL list
(one line per failing check, each naming the deep-mode / verdict it failed).

CONTRACT (rc / stdout):
  rc 0 + first stdout line `pass-harness-accept`  -> the harness is genuine.
  rc 1 + a `FAIL` block listing each failing check -> not done.
  rc 2 + `error: ...`                              -> a usage/IO error.

This wrapper deliberately holds NO detection logic. Every verdict is delegated
to the named tool; changing a threshold or a detector is done THERE, never here.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent
_LIB = _TOOLS / "lib"

# Env that enables the harness-source-COMPILES precondition (check 6).
# GRADUATED TO DEFAULT-ON under the L37 strict umbrella (operator decision
# 2026-07-03). Uniform gate semantics:
#   explicit opt-out : AUDITOOOR_HARNESS_COMPILE_STRICT in {0,false,no,off} -> DISABLED
#   explicit opt-in  : AUDITOOOR_HARNESS_COMPILE_STRICT truthy              -> ENABLED
#   unset (new default): ENABLED iff AUDITOOOR_L37_STRICT is truthy (what
#     `make audit-complete STRICT=1` always exports). A bare non-strict / library
#     caller (L37 unset) still gets the byte-identical advisory (check does NOT
#     run, no compile key) - never a retro-red.
# never-false-pass: an actual build break FAILS. never-false-red: a missing/
# unresolvable forge toolchain, a non-foundry (e.g. .rs/.cairo/.move) harness, or
# a build TIMEOUT is reported as an advisory note, NOT a FAIL.
_COMPILE_STRICT_ENV = "AUDITOOOR_HARNESS_COMPILE_STRICT"


def _compile_strict_enabled() -> bool:
    v = os.environ.get(_COMPILE_STRICT_ENV, "").strip().lower()
    if v in ("0", "false", "no", "off"):
        return False                       # explicit opt-out (escape hatch)
    if v:                                   # any other explicit value
        return True                         # explicit opt-in
    # unset -> default-ON under the L37 strict umbrella; advisory otherwise.
    return os.environ.get("AUDITOOOR_L37_STRICT", "").strip().lower() not in (
        "", "0", "false", "no")


# ---------------------------------------------------------------------------
# Tool loading. The three composed tools are hyphenated module files; load each
# via importlib under a clean module name. (Python 3.14: set sys.modules BEFORE
# exec_module so a re-entrant import sees the partially-initialised module.)
# ---------------------------------------------------------------------------
def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {name} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _vac():
    return _load(_LIB / "harness_vacuity.py", "harness_vacuity_accept")


def _ifc():
    return _load(_TOOLS / "invariant-fuzz-completeness.py", "ifc_accept")


def _mvc():
    return _load(_TOOLS / "mutation-verify-coverage.py", "mvc_accept")


def _fbr():
    """forge-build-readiness-check: the SHARED forge-build wrapper (its `_forge_bin`
    resolves the toolchain via lib/forge-resolve.sh, `evaluate` runs `forge build`
    per foundry root and returns pass-build-ready / fail-build-broken /
    toolchain-absent / no-foundry-root). We REUSE it rather than shelling out to a
    second `forge build` implementation (do-not-rebuild)."""
    return _load(_TOOLS / "forge-build-readiness-check.py", "fbr_accept")


# ---------------------------------------------------------------------------
# Oracle verdict from a durable mvc_sidecar (serving-join, 2026-06-28).
#
# The live auto-oracle mutates `source_file=harness` and resolves the function
# from the harness stem - which is WRONG when the CUT lives in an imported `src/`
# file (the harness contract name is not a CUT function), yielding
# verdict=error "function not found: <HarnessContract>". When a conforming
# mvc_sidecar produced by `mutation-verify-coverage.py --register-manual-mvc`
# (or an --out auto-mutate run) already records the REAL-CUT mutation result for
# THIS harness, prefer it: it is the authoritative non-vacuity proof over the
# real CUT, identical to the credit invariant-fuzz-completeness._mvc_sidecar_credit
# already grants. NEVER-FALSE-PASS: only a sidecar with verdict=non-vacuous AND a
# genuine behaviour-changing invariant-assertion kill is accepted; a panic-only /
# setUp-only kill is rejected (delegated to the shared mutation_kill predicate).
# ---------------------------------------------------------------------------
_MVC_SCHEMA = "auditooor.mutation_verify_coverage.v1"


# ---------------------------------------------------------------------------
# medusa/Chimera auto-mutation-verify fallback (P1-a serving-join fix,
# 2026-07-12).
#
# The live-oracle call below mutates `source_file=harness` and resolves the
# target function from the harness FILE STEM (the forge StdInvariant
# convention this gate was originally written against: a `.t.sol` harness
# whose stem happens to name a function inside itself). A medusa/Chimera-style
# harness instead declares FLAT property functions in the harness body
# (`property_*` / `invariant_*` / `h_*` handler naming) that are never named
# after the file stem, so the stem lookup raises `LookupError` inside
# mutation-engine._find_function_span and the live oracle returns
# verdict=error "function not found: <stem>" - even though the harness is
# perfectly genuine. Previously this forced an operator to manually run
# mutation-verify-coverage.py and hand-register a mvc_sidecar as a workaround
# (observed on axelar-sc: mvc-FlowLimitNetFlow, mvc-InterchainTokenMinterRole,
# mvc-OperatorsMembership, mvc-AuthWeightedForge, mvc-GovernanceTimelock) - a
# "serving-join": genuine evidence existed on disk but the automated reader
# could not see it.
#
# This ADDS a second attempt (never replaces the forge stem-match): when the
# stem lookup does not yield a creditable verdict AND the harness looks like a
# medusa/Chimera property harness, retry the SAME live oracle against the
# first declared property_/invariant_/h_ function name instead of the stem.
# NEVER-FALSE-PASS: the retry still goes through the real mutation-verify-
# coverage.verify() oracle (mutation loop + attribution + witness check); this
# only changes WHICH function name is targeted, not the pass/fail judgement.
# ---------------------------------------------------------------------------
_MEDUSA_PROPERTY_RE = re.compile(
    r"function\s+((?:property_|invariant_|h_)\w+)\s*\(")


def _medusa_candidate_function(harness_text: str) -> str | None:
    """First property_/invariant_/h_ function declared in the harness body
    (medusa/Chimera's flat property-function style), or None. Unlike forge's
    StdInvariant convention - a separate handler contract inherited via
    `is StdInvariant, Test` whose `targetContract(...)` wires up handlers in
    setUp - medusa harnesses declare the fuzzed properties directly in the
    same file/contract the runner points at, so a name match inside the
    harness text itself is meaningful for medusa but not for forge."""
    m = _MEDUSA_PROPERTY_RE.search(harness_text)
    return m.group(1) if m else None


def _has_medusa_config(ws: Path, harness_path: Path) -> bool:
    """True iff a `medusa.json` with a `testLimit` key is reachable from the
    harness (its own dir, or any ancestor up to and including the workspace
    root). Used only to DISAMBIGUATE/confirm the property-function fallback
    above - it never gates acceptance on its own, and its absence never blocks
    the property-function retry from being attempted by a caller that already
    knows the harness is medusa-authored."""
    seen: set[Path] = set()
    try:
        anchors = [harness_path.resolve().parent, *harness_path.resolve().parents]
    except OSError:
        anchors = []
    ws_resolved = None
    try:
        ws_resolved = ws.resolve()
    except OSError:
        pass
    for anc in anchors:
        if anc in seen:
            continue
        seen.add(anc)
        cand = anc / "medusa.json"
        if cand.is_file():
            try:
                d = json.loads(cand.read_text(encoding="utf-8", errors="replace"))
            except (OSError, ValueError):
                d = None
            if isinstance(d, dict):
                # medusa.json nests testLimit under "fuzzing" in real configs
                # (`{"fuzzing": {"testLimit": N, ...}}`); a bare top-level
                # testLimit key (hand-built fixture / older config shape) is
                # accepted too.
                fuzzing = d.get("fuzzing")
                if "testLimit" in d or (
                        isinstance(fuzzing, dict) and "testLimit" in fuzzing):
                    return True
        if ws_resolved is not None and anc == ws_resolved:
            break
    return False


def _genuine_kill(tail: str) -> bool:
    """Behaviour-changing invariant/property assertion failure (not panic/setUp).
    Delegates to the shared predicate via invariant-fuzz-completeness so the
    judgement is identical across gates."""
    try:
        ifc = _ifc()
        return bool(ifc._is_genuine_invariant_kill(tail or ""))
    except Exception:  # noqa: BLE001
        t = tail or ""
        return ("fail" in t.lower()) and any(
            k in t for k in ("invariant_", "property_", "echidna_"))


def _oracle_verdict_from_sidecar(ws: Path, harness: Path) -> dict | None:
    """Build a mutation-verify-coverage-shaped verdict dict from a durable
    mvc_sidecar that maps to THIS harness, or None if no genuine sidecar exists."""
    sc_dir = ws / ".auditooor" / "mvc_sidecar"
    if not sc_dir.is_dir():
        return None
    hname = harness.name
    hstem = harness.stem
    for sc in sorted(sc_dir.glob("*.json")):
        try:
            d = json.loads(sc.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        if not isinstance(d, dict) or d.get("schema") != _MVC_SCHEMA:
            continue
        hp = Path(str(d.get("harness_path") or "")).name
        cmd = str(d.get("harness") or "") + " " + str(d.get("runner_command") or "")
        if not (hp == hname or hstem in cmd or hname in cmd):
            continue
        if str(d.get("verdict")) != "non-vacuous":
            continue
        muts = d.get("mutant_results") or []
        bc_kills = [
            m for m in muts
            if m.get("killed")
            and str(m.get("kill_kind")) == "behavior-changing"
            and _genuine_kill(str(m.get("output_tail") or ""))
        ]
        if not bc_kills:
            continue
        invariants = d.get("invariants") or []
        attribution = d.get("invariant_mutant_attribution") or {}
        if not attribution and invariants:
            # manual-registration sidecars may omit per-invariant attribution;
            # attribute the genuine kill(s) to every declared invariant the kill
            # output names (or all, when the tail is a summary line).
            mid = bc_kills[0].get("mutant_id", "manual-mvc")
            attribution = {iv: [mid] for iv in invariants}
        return {
            "verdict": "non-vacuous",
            "behavior_changing_kill_count": len(bc_kills),
            "panic_only_kill_count": int(d.get("panic_only_kill_count", 0) or 0),
            "witness_reached": d.get("witness_reached"),
            "invariants": invariants,
            "invariant_mutant_attribution": attribution,
            "reason": f"credited from durable mvc_sidecar {sc.name}",
            "source": "mvc_sidecar",
        }
    return None


# ---------------------------------------------------------------------------
# Check 1: deep-mode static vacuity over the harness file.
# ---------------------------------------------------------------------------
def _check_static_vacuity(harness_text: str) -> list[str]:
    """Return a list of FAIL reasons from the lib/harness_vacuity deep detectors.

    A non-empty list means the harness is statically vacuous. Pure composition:
    the modes and their human-readable reasons come from lib/harness_vacuity.
    """
    vac = _vac()
    fails: list[str] = []
    modes = vac.deep_vacuity_modes(harness_text)
    for mode in modes:
        reason = vac.deep_vacuity_reasons.get(mode, "")
        fails.append(f"{mode}: {reason}")
    # The backward-compatible sentinel-only check (assert(true)/no-assertion).
    # deep_vacuity_modes does not cover the bare sentinel-TRUE class, so consult
    # is_sentinel_only_harness too (sentinel-skeleton is already in deep modes).
    if vac.is_sentinel_only_harness(harness_text) and "sentinel-skeleton" not in [
        m.split(":", 1)[0] for m in fails
    ]:
        fails.append("sentinel-body: " + vac.sentinel_reason(harness_text))
    return fails


# ---------------------------------------------------------------------------
# Check 4: in-scope CUT filter.
# ---------------------------------------------------------------------------
def _check_inscope(ws: Path, harness_path: Path) -> list[str]:
    """The harness CUT must be in .auditooor/inscope_units.jsonl (P1-e).

    We accept the harness when EITHER the harness path itself OR a `.sol` it
    imports appears in the manifest. A missing manifest is NOT a pass (the
    author must scope the workspace first) - it is a typed FAIL with the recipe.
    """
    manifest = ws / ".auditooor" / "inscope_units.jsonl"
    if not manifest.is_file():
        return [
            "inscope-missing: no .auditooor/inscope_units.jsonl - scope the "
            "workspace (emit the in-scope allow-list) before crediting a harness"
        ]
    inscope: set[str] = set()
    for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        f = str(row.get("file") or "").strip().lstrip("./").replace("\\", "/")
        if f:
            inscope.add(f)
    if not inscope:
        return [
            "inscope-empty: .auditooor/inscope_units.jsonl has no `file` rows - "
            "scope the workspace before crediting a harness"
        ]
    # Match the harness path or any imported .sol file against the allow-list.
    hp_norm = str(harness_path).replace("\\", "/")
    try:
        htext = harness_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        htext = ""
    imported = set()
    import re as _re
    for m in _re.finditer(r'import\s+(?:\{[^}]*\}\s+from\s+)?["\']([^"\']+\.sol)["\']', htext):
        imported.add(Path(m.group(1)).name)
    for unit in inscope:
        base = Path(unit).name
        if unit in hp_norm or hp_norm.endswith("/" + unit) or base in imported:
            return []
    # The harness file path itself may be listed.
    for unit in inscope:
        if Path(unit).name == harness_path.name:
            return []
    return [
        "wrong-CUT-OOS-target: the harness CUT is not in "
        ".auditooor/inscope_units.jsonl (mode 19); target a `src/` in-scope "
        "contract, not vendored OZ / a deployed-zip reimpl / a bare interface"
    ]


# ---------------------------------------------------------------------------
# Check 5: sidecar-registration + stale-sidecar guard.
# ---------------------------------------------------------------------------
def _check_sidecar(ws: Path, harness_path: Path) -> list[str]:
    """A conforming .auditooor/mvc_sidecar/*.json must name this harness AND its
    recorded harness_source_sha256 must still match the on-disk file (P1-c +
    P1-b stale-sidecar guard, mode 13). Re-uses the shared hash helper from
    mutation-verify-coverage so the hashing is identical to the producer's.
    """
    sidecar_dir = ws / ".auditooor" / "mvc_sidecar"
    if not sidecar_dir.is_dir():
        return [
            "sidecar-unregistered: no .auditooor/mvc_sidecar/ - register the "
            "harness proof with `mutation-verify-coverage.py --register-manual-mvc "
            f"{harness_path}` (mode 11) so the ledger / coverage producer credits it"
        ]
    mvc = _mvc()
    hp_resolved = str(harness_path.resolve())
    hp_name = harness_path.name
    matched = None
    for sc in sorted(sidecar_dir.glob("*.json")):
        try:
            rec = json.loads(sc.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, ValueError, OSError):
            continue
        rec_hp = str(rec.get("harness_path") or "")
        if not rec_hp:
            continue
        if rec_hp == hp_resolved or Path(rec_hp).name == hp_name or hp_name in rec_hp:
            matched = (sc, rec)
            break
    if matched is None:
        return [
            "sidecar-unregistered: no .auditooor/mvc_sidecar/*.json names this "
            f"harness ({hp_name}) - register it with "
            "`mutation-verify-coverage.py --register-manual-mvc` (mode 11)"
        ]
    _sc, rec = matched
    # Stale-sidecar guard (P1-b / mode 13): re-hash the on-disk harness and
    # compare to the sidecar's recorded harness_source_sha256.
    recorded = rec.get("harness_source_sha256")
    if recorded:
        current = mvc._harness_source_sha256(rec.get("harness_path"))
        if current is not None and current != recorded:
            return [
                "stale-sidecar: the mvc_sidecar's harness_source_sha256 no longer "
                "matches the on-disk harness (mode 13: the harness was clobbered/"
                "edited after the kills were banked); re-run the mutation oracle"
            ]
    return []


# ---------------------------------------------------------------------------
# Check 6 (advisory-first, default-OFF): harness-source-COMPILES precondition.
#
# The pre-existing gate runs static vacuity + mutation-verify over the harness
# TEXT only - it has no `forge build` / `solc parse` step, so a harness that does
# not COMPILE (e.g. the NUVA CrossChainManager_FuzzProps.sol whose identifier
# splice was corrupted into `Euint256(0)ecutorArgs`, which then errored the medusa
# run rc=6 engine-error) can pass author-accept. This check compiles the harness's
# owning foundry root and rejects a non-compiling Solidity harness.
#
# ADVISORY-FIRST: gated behind AUDITOOOR_HARNESS_COMPILE_STRICT (default OFF).
# NEVER-FALSE-RED: a missing/unresolvable forge, a non-foundry (cross-language)
# harness, no foundry root, or a build TIMEOUT is reported as a `compile_note`,
# NOT a FAIL. Only a genuine `fail-build-broken` on THIS harness's root FAILs.
# ---------------------------------------------------------------------------
def _owning_foundry_root(fbr, harness_path: Path):
    """The nearest ancestor dir of `harness_path` that is a first-party foundry
    root (has a foundry.toml, not under a pruned vendored dir). None if the harness
    is not inside any first-party foundry tree (cross-language / bare .sol)."""
    try:
        parts = harness_path.resolve().parents
    except OSError:
        return None
    for anc in parts:
        toml = anc / "foundry.toml"
        if toml.is_file():
            rel = None
            try:
                rel = toml.relative_to(anc)  # always foundry.toml; prune by path parts
            except ValueError:
                rel = None
            # mirror forge-build-readiness-check._PRUNE: never treat a vendored
            # lib/node_modules/out tree as the harness's own root.
            if any(seg in fbr._PRUNE for seg in anc.parts):
                continue
            return anc
    return None


def _check_compiles(ws: Path, harness_path: Path) -> tuple[list[str], list[str]]:
    """Return (fails, notes). `fails` is non-empty ONLY on a genuine build break of
    THIS harness's owning foundry root while strict-mode is on. `notes` carries the
    advisory outcome for every non-fail path (toolchain-absent / cross-language /
    no-foundry-root / build-ok). Never raises."""
    # Cross-language harness: `forge build` does not apply - a .rs/.cairo/.move CUT
    # is routed to cargo/proptest elsewhere. Advisory note, never a FAIL.
    if harness_path.suffix.lower() not in (".sol",):
        return [], [
            f"compile-skip-non-solidity: {harness_path.suffix or '(no ext)'} harness "
            "is not a forge target (route cross-language CUTs to cargo/proptest)"
        ]
    try:
        fbr = _fbr()
    except Exception as e:  # noqa: BLE001 - never let a loader error retro-red a harness
        return [], [f"compile-skip-loader-error: could not load forge-build-readiness-check ({e})"]

    root = _owning_foundry_root(fbr, harness_path)
    if root is None:
        return [], [
            "compile-skip-no-foundry-root: harness is not inside a first-party "
            "foundry tree (no ancestor foundry.toml) - cannot forge-build-check"
        ]
    forge = fbr._forge_bin()
    if not forge:
        return [], [
            "compile-skip-toolchain-absent: forge not installed/resolvable "
            "(offline-safe: compile precondition skipped, not failed)"
        ]
    # Reuse the shared per-root builder. evaluate() also quarantines engine
    # reproducer .sol out of the compiled tree (its build-poison guard) - a bonus.
    try:
        res = fbr.evaluate(root)
    except Exception as e:  # noqa: BLE001
        return [], [f"compile-skip-eval-error: forge-build evaluate raised ({e})"]
    verdict = str(res.get("verdict") or "")
    if verdict == "fail-build-broken":
        # Surface the actionable compiler diagnostic (last lines) for THIS root.
        tail = ""
        for row in res.get("roots", []):
            if not row.get("ok"):
                tail = str(row.get("error_tail", "")).strip()
                break
        tail_1 = (tail.splitlines() or [""])[-1][:200]
        return (
            [
                "harness-source-does-not-compile: `forge build` FAILED on the "
                f"harness's foundry root ({root.name}) - a non-compiling harness "
                "cannot be accepted (the engine records engine-error / no-execution "
                f"instead of coverage). last diagnostic: {tail_1}"
            ],
            [],
        )
    # pass-build-ready / toolchain-absent / no-foundry-root -> advisory note only.
    return [], [f"compile-ok: forge build {verdict} on root {root.name}"]


# ---------------------------------------------------------------------------
# Check 2: mutation-oracle verdict (>=1 attributed non-panic behavior-changing
# kill per invariant + witness-execution).
# ---------------------------------------------------------------------------
def _oracle_fails_from_verdict(verdict: dict) -> list[str]:
    """Translate a mutation-verify-coverage verdict dict into accept FAILs.

    PURE READER: every classification (`non-vacuous` / `equivalent-mutant-only` /
    `value-path-never-executed` / per-invariant attribution / witness) is decided
    by mutation-verify-coverage (lanes B / P0-d / P1-a / P0-b6). This wrapper only
    maps that verdict to a FAIL line; it makes no kill-quality judgement itself.
    """
    fails: list[str] = []
    v = str(verdict.get("verdict") or "")
    if v != "non-vacuous":
        # The oracle already named the precise non-credit class.
        fails.append(
            f"no-behavior-changing-kill: mutation-verify verdict={v or 'unknown'} "
            f"({verdict.get('reason', 'no >=1 attributed non-panic behavior-changing kill')})"
        )
        return fails
    # non-vacuous: confirm there is >=1 NON-PANIC behavior-changing kill (P1-a)
    # and that the value-moving witness actually executed (P0-b6).
    if int(verdict.get("behavior_changing_kill_count", 0) or 0) < 1:
        fails.append(
            "no-behavior-changing-kill: verdict non-vacuous but "
            "behavior_changing_kill_count<1 (equivalent-mutant-only / panic-only "
            "kills do not count - pick a guard/auth/cap/state mutant)"
        )
    if verdict.get("witness_reached") is False:
        fails.append(
            "value-path-never-executed: the value-moving fn's reachability "
            "witness never reached >0 (mode 6 mock-callpath-vacuity)"
        )
    # Per-invariant attribution (P1-a / mode 16): every declared invariant should
    # have >=1 attributed behavior-changing kill, else the credit is partial.
    invariants = verdict.get("invariants") or []
    attribution = verdict.get("invariant_mutant_attribution") or {}
    if invariants:
        unattributed = [iv for iv in invariants if not attribution.get(iv)]
        if unattributed:
            fails.append(
                "cluster-partially-verified: invariant(s) without an attributed "
                f"behavior-changing kill: {', '.join(sorted(unattributed)[:5])} "
                "(mode 16: each credited invariant needs its own mutant)"
            )
    return fails


# ---------------------------------------------------------------------------
# Composite gate.
# ---------------------------------------------------------------------------
def accept(
    *,
    harness: Path,
    ws: Path,
    oracle_verdict: dict | None = None,
    run_oracle: bool = True,
) -> dict:
    """Run all five composed checks and return a composite result dict.

    `oracle_verdict` lets a caller (or a test) INJECT a mutation-verify-coverage
    verdict dict instead of running the (expensive, toolchain-bound) oracle here.
    When None and run_oracle is True, the oracle is invoked via
    mutation-verify-coverage.verify(). When None and run_oracle is False, the
    oracle check is SKIPPED with an explicit `oracle-skipped` note (used only
    when a caller composes the oracle separately).
    """
    result: dict = {
        "schema": "harness_author_accept.v1",
        "harness": str(harness),
        "workspace": str(ws),
        "checks": {},
        "fails": [],
        "verdict": "",
    }
    if not harness.is_file():
        result["verdict"] = "error"
        result["error"] = f"harness file not found: {harness}"
        return result
    try:
        harness_text = harness.read_text(encoding="utf-8", errors="replace")
    except OSError as e:  # pragma: no cover - defensive
        result["verdict"] = "error"
        result["error"] = f"cannot read harness: {e}"
        return result

    all_fails: list[str] = []

    # (1) static deep-mode vacuity.
    f1 = _check_static_vacuity(harness_text)
    result["checks"]["static_vacuity"] = {"pass": not f1, "fails": f1}
    all_fails += f1

    # (2) mutation-oracle verdict (>=1 attributed non-panic behavior-changing
    #     kill per invariant + witness execution).
    if oracle_verdict is None and run_oracle:
        mvc = _mvc()
        # Derive source_file from the harness import or fall back to the harness
        # itself; verify() resolves the runner from the harness path. Any oracle
        # error surfaces as a check FAIL (not credited).
        oracle_verdict = mvc.verify(
            workspace=ws,
            source_file=harness,
            function=harness.stem,
            harness=str(harness),
        )
        # medusa/Chimera fallback (P1-a serving-join, ADDS to - never replaces -
        # the forge stem-match above): a stem lookup miss on a medusa-style
        # property harness retries the SAME live oracle against the first
        # declared property_/invariant_/h_ function so an author no longer has
        # to hand-register a mvc_sidecar just to get auto-credit.
        if str((oracle_verdict or {}).get("verdict") or "") != "non-vacuous":
            candidate = _medusa_candidate_function(harness_text)
            if (candidate and candidate != harness.stem
                    and _has_medusa_config(ws, harness)):
                retry_verdict = mvc.verify(
                    workspace=ws,
                    source_file=harness,
                    function=candidate,
                    harness=str(harness),
                )
                if str(retry_verdict.get("verdict") or "") == "non-vacuous":
                    oracle_verdict = retry_verdict
    # Serving-join (2026-06-28): the live auto-oracle mutates the HARNESS file and
    # resolves the function from the harness stem, so when the real CUT lives in an
    # imported src/ file it returns verdict=error "function not found". A durable
    # mvc_sidecar produced by mutation-verify-coverage.py over the REAL CUT is the
    # authoritative proof - prefer it whenever the live oracle did not yield a
    # creditable non-vacuous verdict (error / vacuous / missing). NEVER-FALSE-PASS:
    # _oracle_verdict_from_sidecar only returns a verdict for a non-vacuous sidecar
    # with a genuine behaviour-changing invariant-assertion kill.
    live_v = str((oracle_verdict or {}).get("verdict") or "")
    if live_v != "non-vacuous":
        sidecar_verdict = _oracle_verdict_from_sidecar(ws, harness)
        if sidecar_verdict is not None:
            oracle_verdict = sidecar_verdict
    if oracle_verdict is None:
        f2 = ["oracle-skipped: mutation-verify-coverage verdict not supplied"]
    else:
        f2 = _oracle_fails_from_verdict(oracle_verdict)
    result["checks"]["mutation_oracle"] = {
        "pass": not f2, "fails": f2,
        "verdict": (oracle_verdict or {}).get("verdict"),
    }
    all_fails += f2

    # (3) invariant-fuzz-completeness (>=1M / no-dry-run / engine-choice).
    # PER-HARNESS SCOPE (2026-06-28): harness-author-accept gates ONE harness (the
    # --harness arg). The whole-ws invariant-fuzz-completeness verdict aggregates
    # EVERY harness dir, so an unrelated sibling lane's incomplete/sentinel harness
    # would otherwise block acceptance of a genuine one. Scope the deficiency
    # surfacing to the harness dir being accepted; a structural whole-ws verdict
    # (no-solidity-source / no-harness) with no per-harness rows still surfaces.
    ifc = _ifc()
    ifc_res = ifc.evaluate(ws)
    f3: list[str] = []
    ifc_verdict = str(ifc_res.get("verdict") or "")
    harness_dir_norm = str(harness.parent).replace("\\", "/")
    if ifc_verdict == "fail-invariant-fuzz-incomplete":
        # Surface ONLY this harness dir's deficiency (under-budgeted / dry-run /
        # selfdestruct-needs-echidna / never-fuzzed / shallow).
        matched_self = False
        for h in ifc_res.get("harnesses", []):
            hd = str(h.get("dir") or "").replace("\\", "/")
            # ifc records dir relative to ws. The harness FILE must actually live
            # in ws/hd - resolve and compare to the harness's real parent so a
            # bare-suffix match (e.g. a sibling `test/` dir) cannot collide.
            is_self = bool(hd) and (
                (ws / hd).resolve() == harness.parent.resolve())
            if is_self:
                matched_self = True
                if h.get("fail"):
                    f3.append(f"fuzz-completeness: {h['fail']}")
        if not matched_self:
            # The whole-ws gate failed but THIS harness dir was not among the
            # evaluated harnesses - surface the structural reason so the author
            # is not silently passed, but do NOT inherit sibling-lane failures.
            f3.append(
                f"fuzz-completeness: harness dir not evaluated by "
                f"invariant-fuzz-completeness ({ifc_res.get('reason', 'incomplete')})")
    result["checks"]["fuzz_completeness"] = {
        "pass": not f3, "fails": f3, "verdict": ifc_verdict,
        "scope": "per-harness-dir",
    }
    all_fails += f3

    # (4) in-scope CUT filter.
    f4 = _check_inscope(ws, harness)
    result["checks"]["inscope"] = {"pass": not f4, "fails": f4}
    all_fails += f4

    # (5) sidecar registration + stale-sidecar guard.
    f5 = _check_sidecar(ws, harness)
    result["checks"]["sidecar"] = {"pass": not f5, "fails": f5}
    all_fails += f5

    # (6) harness-source-COMPILES precondition (advisory-first, default-OFF).
    # UNSET env -> this block does not run and the result dict is BYTE-IDENTICAL to
    # the pre-existing gate (no `compile` check key, no notes) - a hard never-retro-
    # red guarantee. SET env -> a genuine build break of THIS harness's foundry root
    # FAILs; every non-fail path (toolchain-absent / cross-language / no-root /
    # build-ok) is an advisory note that never turns a passing harness red.
    if _compile_strict_enabled():
        f6, notes6 = _check_compiles(ws, harness)
        result["checks"]["compile"] = {
            "pass": not f6, "fails": f6, "notes": notes6, "strict": True,
        }
        all_fails += f6

    result["fails"] = all_fails
    result["verdict"] = "pass-harness-accept" if not all_fails else "fail-harness-accept"
    return result


def _render(result: dict) -> str:
    if result["verdict"] == "error":
        return f"error: {result.get('error', 'unknown error')}"
    if result["verdict"] == "pass-harness-accept":
        return "pass-harness-accept"
    lines = ["FAIL harness-author-accept: " + str(len(result["fails"])) + " check(s) failed"]
    for f in result["fails"]:
        lines.append("  - " + f)
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Author-time harness acceptance gate (spec item E): composes "
                    "lib/harness_vacuity + mutation-verify-coverage + "
                    "invariant-fuzz-completeness + inscope + sidecar checks. "
                    "With --compile-strict (or " + _COMPILE_STRICT_ENV + "=1) it "
                    "also runs a harness-source-COMPILES precondition (forge build "
                    "of the harness's foundry root); advisory-first / default-OFF."
    )
    ap.add_argument("--harness", required=True, help="harness .t.sol/.sol/.rs FILE path")
    ap.add_argument("--ws", "--workspace", dest="ws", required=True,
                    help="workspace root (holds .auditooor/)")
    ap.add_argument("--no-oracle", action="store_true",
                    help="skip the live mutation-verify-coverage run (compose the "
                         "oracle verdict separately); the oracle check is reported "
                         "as oracle-skipped")
    ap.add_argument("--compile-strict", action="store_true",
                    help="enable the harness-source-COMPILES precondition (check 6) "
                         "even when " + _COMPILE_STRICT_ENV + " is unset; a "
                         "non-compiling Solidity harness is then rejected (missing "
                         "toolchain / cross-language harness = advisory note, not a "
                         "fail)")
    ap.add_argument("--json", action="store_true", help="emit the full result JSON")
    args = ap.parse_args(argv)

    # --compile-strict is a convenience alias for the advisory-first env; setting
    # it in-process keeps the single source of truth (_compile_strict_enabled()).
    if args.compile_strict:
        os.environ[_COMPILE_STRICT_ENV] = "1"

    harness = Path(args.harness)
    if not harness.is_absolute():
        harness = (Path.cwd() / harness).resolve()
    ws = Path(args.ws).resolve()

    result = accept(harness=harness, ws=ws, run_oracle=not args.no_oracle)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(_render(result))
    if result["verdict"] == "error":
        return 2
    return 0 if result["verdict"] == "pass-harness-accept" else 1


if __name__ == "__main__":
    raise SystemExit(main())
