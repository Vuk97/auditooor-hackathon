#!/usr/bin/env python3
# <!-- r36-rebuttal: lane FIX-HONEST-ZERO-VERIFY registered via agent-pathspec-register.py -->
"""Verify (and stamp) a GENUINE honest-zero - the un-fakeable way.

The #1 hole: `audit-done-guard` accepted a hand-written
`.auditooor/honest_zero.json` as "paste-ready-or-nothing", so an agent could
declare an honest 0 by writing one file. This tool RECOMPUTES the honest-0 from
real on-disk evidence so the verdict cannot be hand-authored. The done-guard
calls `verify()` directly instead of trusting the file.

An honest 0 is GENUINE only when ALL hold (any failing => not an honest 0):
  1. audit-complete marker is `pass-audit-complete`, STRICT, and fresh (<=TTL).
  2. the unhunted-surface-followthrough gate passes (no abandoned surface) -
     re-run live, not read from a cache.
  3. NOTHING fileable is left dangling: no `submissions/paste_ready/*` (those
     are submissions, not a 0), AND no `candidate-finding` left OPEN in the
     residual-hunt verdicts (a candidate must be filed or refuted, never hidden).
  4. the load-bearing deep evidence is REAL and non-trivial: a coverage-guided
     fuzz artifact, a mutation-verify file with >=1 verified harness, and a
     coverage report all present.
  5. >=AUDITOOOR_HZ_ECON_MIN_INVARIANTS genuine, real-CUT-bound, ECONOMIC
     (non-placeholder) invariants are mutation-verified.
  6. >=1 REUSABLE residue is bankable for the next engagement (a ruled-out
     dead-end, a resolved fork base, or a mutation-verified invariant seed) -
     RECOMPUTED from disk via honest-zero-bank, never trusting a written file.
  7. the held-out HUNT-recall clears the floor (default 0.5), computed PER
     LANGUAGE SUB-TREE (a Solidity 100% recall must not mask a zk 0% recall) -
     RECOMPUTED here from the per-case hunt records, never a written number. A
     present language with no held-out corpus emits a typed
     <lang>-recall-corpus-absent verdict + a logged waiver (never silent-zero).

`verify(ws)` returns {ok, checks, reason, fingerprint}. `--stamp` writes
`.auditooor/honest_zero.json` with `verified_by`, the checks, and an evidence
fingerprint (so the record is auditable) - but the done-guard re-verifies
regardless, so the file is a cache, not a trust anchor.

CLI: python3 tools/honest-zero-verify.py --workspace <ws> [--json] [--stamp]
Exit: 0 = genuine honest-0; 1 = NOT an honest-0; 2 = usage error.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent
_SCHEMA = "auditooor.honest_zero.v2"

# A per-function mutation record is a GENUINE non-vacuous KILL when mutation_verified
# + killed AND any verdict alias says so. The per-fn producer omits oracle_verdict
# (writes verdict='killed' + genuine_verdict='non-vacuous'); core/function-coverage
# already credit it, so the recomputed honest-0 MUST read the same aliases or it
# undercounts genuine kills on every forge ws. Mirrors core-coverage._MUT_KILL_VERDICTS.
_MUT_KILL_VERDICTS = {"killed", "non-vacuous", "nonvacuous", "real", "mutation-killed"}


def _mvc_entry_is_genuine_kill(entry) -> bool:
    if not isinstance(entry, dict):
        return False
    if entry.get("mutation_verified") is not True or entry.get("killed") is not True:
        return False
    for k in ("oracle_verdict", "genuine_verdict", "verdict", "mutation_verdict"):
        v = entry.get(k)
        if isinstance(v, str) and v.strip().lower() in _MUT_KILL_VERDICTS:
            return True
    return False


def _load(name: str, fname: str):
    spec = importlib.util.spec_from_file_location(name, str(_TOOLS / fname))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


import re as _re

# Economic vocabulary regex - matches harness text that demonstrates real
# economic invariant coverage (solvency, conservation, token flows, etc.).
# A stub harness that only asserts True or has no economic keyword fails.
_ECON_VOCAB_RE = _re.compile(
    r"solvenc|conservation|collateral|debt|liquidat|redempt|mint|burn|borrow|repay"
    r"|reserve|fee|interest|baddebt|bad_debt|shares|assets|total_supply|balance"
    r"|vault|supply|withdraw|deposit|exchange_rate|price|oracle|accrued|compound"
    r"|lend|lever|margin|loss|profit|pnl|insolvent|healthy|underwater",
    _re.IGNORECASE,
)

_HZ_ECON_MIN_DEFAULT = 3
_ECON_REBUTTAL_KEY = "economic_invariants"

# F4 / E4.2: held-out HUNT-RECALL floor. A genuine-0 over a present language
# requires the held-out hunt to re-discover at least this fraction of known bugs
# (else the 0 may just be a blind hunt). Computed PER LANGUAGE SUB-TREE so a
# Solidity 100% recall cannot mask a 0% zk recall. Default 0.5.
_HZ_RECALL_FLOOR_DEFAULT = 0.5
_RECALL_REBUTTAL_KEY = "recall_floor"
# Held-out hunt-case records (one auditor-backtest hunt_case record per line,
# each carrying `language` + `outcome`). RECOMPUTED here via the auditor-backtest
# hunt_recall() over these records - a written `recall` verdict is NEVER trusted.
_RECALL_RECORDS_RELPATHS = (
    "hunt_recall_backtest.jsonl",
    "recall_backtest_hunt.jsonl",
)
# Source extensions that mark a language as PRESENT in the workspace tree. A
# present language with NO held-out corpus emits a typed <lang>-recall-corpus-
# absent verdict + a logged waiver (never a silent zero, never a brick).
_RECALL_LANG_EXTS = {
    ".sol": "solidity", ".vy": "vyper",
    ".rs": "rust", ".go": "go",
    ".move": "move", ".cairo": "cairo",
    ".circom": "circom", ".nr": "noir", ".zok": "zokrates",
    ".ts": "typescript", ".js": "javascript",
}
# Dirs that never hold in-scope source (so a present-language probe is not
# fooled by deps/build output).
_RECALL_SKIP_DIRS = {
    ".git", "node_modules", "target", "build", "out", "dist", "cache",
    ".auditooor", "lib", "vendor", "deps", "__pycache__",
}


def _corroborated_genuine_count(ws: Path) -> int:
    """Return the number of per_function entries in mutation_verify_coverage.json
    that are corroborated as genuinely non-vacuous:
      mutation_verified==True AND oracle_verdict=="non-vacuous" AND killed==True.

    This is the TOOL-WRITTEN ground truth that backs up the bare integer in
    genuine_coverage_manifest.json.  If mutation_verify_coverage.json is absent,
    malformed, or has no per_function list, returns 0.  Generic stdlib only,
    no workspace literals.
    """
    mvc_path = ws / ".auditooor" / "mutation_verify_coverage.json"
    mvc = _load_json(mvc_path)
    if not isinstance(mvc, dict):
        return 0
    per_fn = mvc.get("per_function")
    if not isinstance(per_fn, list):
        return 0
    count = 0
    for entry in per_fn:
        if _mvc_entry_is_genuine_kill(entry):
            count += 1
    return count


def _corroborated_economic_count(ws: Path) -> int:
    """Return the number of per_function entries in mutation_verify_coverage.json
    that satisfy ALL of:
      (a) mutation_verified==True AND oracle_verdict=="non-vacuous" AND killed==True
          (real kill, not silent-skip or stub)
      (b) real-CUT-bound: both the harness file AND the source_file resolve on disk
          within the workspace tree (no phantom paths)
      (c) economic: the harness file text matches _ECON_VOCAB_RE at least once
          (i.e. the harness actually exercises economic logic, not a stub/placeholder)

    Returns 0 if mutation_verify_coverage.json is absent, malformed, or has no
    per_function list.  Generic stdlib only, no workspace literals.
    """
    mvc_path = ws / ".auditooor" / "mutation_verify_coverage.json"
    mvc = _load_json(mvc_path)
    # NOTE: do NOT early-return when the aggregate is absent/empty - standalone
    # mutation-verify-coverage.v1 sidecars are folded in below and may carry the
    # genuine economic invariants even when no aggregate per_function list exists.
    per_fn = mvc.get("per_function") if isinstance(mvc, dict) else None
    count = 0
    for entry in (per_fn if isinstance(per_fn, list) else []):
        if not isinstance(entry, dict):
            continue
        # (a) mutation kill criteria (verdict-alias robust)
        if not _mvc_entry_is_genuine_kill(entry):
            continue
        # (b) real-CUT-bound: harness + source_file must resolve on disk.
        # Accept BOTH field spellings: the canonical chimera-invariant-registrar +
        # mutation-verify-coverage write `harness`/`source` (or `harness_path`),
        # while older records used `harness_file`/`source_file`. Reading only the
        # *_file spelling made this check DEAD for the canonical pipeline (no
        # producer emits `harness_file`), so a genuine mutation-verified economic
        # invariant could never be counted. The un-fakeable criteria below
        # (killed + non-vacuous + on-disk + economic vocab) are unchanged.
        harness_rel = (
            entry.get("harness_file") or entry.get("harness")
            or entry.get("harness_path") or ""
        )
        source_rel = entry.get("source_file") or entry.get("source") or ""
        if not source_rel:
            continue
        source_path = Path(source_rel) if Path(source_rel).is_absolute() else ws / source_rel
        # CUT source_file must resolve on disk (real-CUT-bound). The harness field
        # may be a FILE, a DIR (chimera registrar records the harness dir), or a
        # runner COMMAND string (mutation-verify-coverage) - only require it to
        # resolve when it looks like a path.
        if not source_path.is_file():
            continue
        harness_path = None
        if harness_rel and not harness_rel.strip().startswith(("bash ", "forge ", "sh ", "/bin/")):
            hp = Path(harness_rel) if Path(harness_rel).is_absolute() else ws / harness_rel
            if hp.is_file() or hp.is_dir():
                harness_path = hp
        # (c) economic: the harness OR the bound CUT must exercise economic logic
        # (not a placeholder). Read harness file(s) when resolvable, else the CUT.
        econ_text = ""
        try:
            if harness_path is not None and harness_path.is_file():
                econ_text = harness_path.read_text(encoding="utf-8", errors="replace")
            elif harness_path is not None and harness_path.is_dir():
                for hf in list(harness_path.rglob("*.sol"))[:20]:
                    econ_text += hf.read_text(encoding="utf-8", errors="replace")
            if not econ_text:
                econ_text = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not _ECON_VOCAB_RE.search(econ_text):
            continue
        count += 1
    return count + _standalone_economic_sidecar_count(ws)


def _standalone_economic_sidecar_count(ws: Path) -> int:
    """Count standalone mutation-verify-coverage.v1 sidecars that are genuine,
    real-CUT-bound, economic invariants. mutation-verify-coverage.py writes one
    record per invocation (CUT-keyed) under .auditooor/cross-function-coverage/ +
    mvc_sidecar*; these never land in the aggregate per_function list, so the
    aggregate-only count missed a genuinely mutation-verified economic invariant
    (e.g. the ProtocolFee core invariant). UN-FAKEABLE: require verdict
    non-vacuous AND baseline pass AND >=1 killed mutant AND the CUT source_file on
    disk AND economic vocabulary in the CUT."""
    import glob as _glob
    out_keys: set = set()
    cands: list = []
    for rel in ("cross-function-coverage", "mvc_sidecar"):
        cands += _glob.glob(str(ws / ".auditooor" / rel / "*.json"))
    cands += _glob.glob(str(ws / ".auditooor" / "mvc_sidecar*.json"))
    for p in cands:
        rec = _load_json(Path(p))
        if not isinstance(rec, dict):
            continue
        if str(rec.get("schema")) != "auditooor.mutation_verify_coverage.v1":
            continue
        if str(rec.get("verdict")) != "non-vacuous":
            continue
        base = rec.get("baseline") if isinstance(rec.get("baseline"), dict) else {}
        if str(base.get("status")) not in ("pass", "passed", "ok"):
            continue
        if not any(isinstance(m, dict) and m.get("killed")
                   for m in (rec.get("mutant_results") or [])):
            continue
        src = str(rec.get("source_file") or "").strip()
        if not src or not Path(src).is_file():
            continue
        try:
            if not _ECON_VOCAB_RE.search(Path(src).read_text(encoding="utf-8", errors="replace")):
                continue
        except OSError:
            continue
        key = (Path(src).name, str(rec.get("function") or ""))
        out_keys.add(key)
    return len(out_keys)


def _standalone_verified_count(ws: Path) -> int:
    """Count standalone mutation-verify-coverage.v1 sidecars that are genuinely
    non-vacuous (CUT-keyed, never in the aggregate per_function counts). Same
    un-fakeable criteria as the economic counter MINUS the economic-vocab filter
    (deep_evidence wants any genuine mutation-verified harness, not only economic
    ones): verdict non-vacuous AND baseline pass AND >=1 killed mutant AND the CUT
    source_file on disk."""
    import glob as _glob
    keys: set = set()
    cands: list = []
    for rel in ("cross-function-coverage", "mvc_sidecar"):
        cands += _glob.glob(str(ws / ".auditooor" / rel / "*.json"))
    cands += _glob.glob(str(ws / ".auditooor" / "mvc_sidecar*.json"))
    for p in cands:
        rec = _load_json(Path(p))
        if not isinstance(rec, dict):
            continue
        if str(rec.get("schema")) != "auditooor.mutation_verify_coverage.v1":
            continue
        if str(rec.get("verdict")) != "non-vacuous":
            continue
        base = rec.get("baseline") if isinstance(rec.get("baseline"), dict) else {}
        if str(base.get("status")) not in ("pass", "passed", "ok"):
            continue
        if not any(isinstance(m, dict) and m.get("killed")
                   for m in (rec.get("mutant_results") or [])):
            continue
        src = str(rec.get("source_file") or "").strip()
        if not src or not Path(src).is_file():
            continue
        keys.add((Path(src).name, str(rec.get("function") or "")))
    return len(keys)


def _check_economic_invariants(ws: Path) -> tuple[bool, str, str]:
    """Check 5: an honest-0 requires >=AUDITOOOR_HZ_ECON_MIN_INVARIANTS genuine,
    real-CUT-bound, ECONOMIC (non-placeholder) invariants.

    Escape hatch: l37-rebuttal file containing the key "economic_invariants" on
    a line of its own (same rebuttal-file convention used by other honest-0 checks).
    """
    # Rebuttal escape - same mechanism as the rest of the harness
    rebuttal_path = ws / ".auditooor" / "l37-rebuttal"
    if rebuttal_path.is_file():
        try:
            rb_text = rebuttal_path.read_text(encoding="utf-8", errors="replace")
            for line in rb_text.splitlines():
                if line.strip() == _ECON_REBUTTAL_KEY:
                    return True, f"ok-rebuttal: l37-rebuttal contains '{_ECON_REBUTTAL_KEY}'", "econ:rebuttal"
        except OSError:
            pass
    min_required = int(os.environ.get("AUDITOOOR_HZ_ECON_MIN_INVARIANTS", str(_HZ_ECON_MIN_DEFAULT)))
    count = _corroborated_economic_count(ws)
    if count >= min_required:
        return (
            True,
            f"{count} genuine real-CUT-bound economic invariant(s) (>={min_required} required)",
            f"econ:{count}",
        )
    return (
        False,
        f"only {count} genuine real-CUT-bound economic invariant(s) found "
        f"(need >={min_required}; set AUDITOOOR_HZ_ECON_MIN_INVARIANTS to override minimum "
        "or add 'economic_invariants' line to .auditooor/l37-rebuttal to skip)",
        "",
    )


def _check_banked_reusable(ws: Path) -> tuple[bool, str, str]:
    """Check 6: an honest-0 MUST bank >=1 reusable dead-end / fork-base / invariant
    seed for the next engagement (the corpus is wiring-not-supply; a clean 0 that
    banks nothing leaves the next re-pin to re-resolve + re-hunt from scratch).

    UN-FAKEABLE: this RECOMPUTES the bankable residue from on-disk evidence via
    honest-zero-bank.build_record(ws) - it does NOT trust reports/honest_zero_bank.jsonl
    or any written flag. A hand-written bank file is ignored; only the recomputed
    reusable_record_count counts.

    Rebuttal escape: an l37-rebuttal file containing the key 'banked_reusable' on a
    line of its own (same convention as the other honest-0 checks).
    """
    rebuttal_path = ws / ".auditooor" / "l37-rebuttal"
    if rebuttal_path.is_file():
        try:
            for line in rebuttal_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip() == "banked_reusable":
                    return True, "ok-rebuttal: l37-rebuttal contains 'banked_reusable'", "bank:rebuttal"
        except OSError:
            pass
    try:
        bank = _load("_hzb_bank", "honest-zero-bank.py")
        rec = bank.build_record(ws)
    except Exception as exc:  # defensive: a crashing recompute is NOT a pass
        return False, f"bank recompute error: {type(exc).__name__}: {exc}", ""
    n = int(rec.get("reusable_record_count") or 0)
    if n >= 1:
        de = rec.get("dead_end_total", 0)
        fb = rec.get("fork_base_count", 0)
        iv = rec.get("mutation_verified_invariant_seed_count", 0)
        return (
            True,
            f"{n} reusable record(s) bankable "
            f"(dead_ends={de}, fork_bases={fb}, invariant_seeds={iv})",
            f"bank:{n}",
        )
    return (
        False,
        "0 reusable records bankable from disk: a clean honest-0 must bank >=1 "
        "dead-end / resolved fork-base / mutation-verified invariant seed for the "
        "next engagement (run tools/honest-zero-bank.py; or add 'banked_reusable' "
        "to .auditooor/l37-rebuttal to skip)",
        "",
    )


def _present_source_languages(ws: Path) -> set:
    """Languages PRESENT in the workspace source tree (by file extension),
    skipping deps/build dirs. Used to decide which languages the recall floor
    must clear (and which a held-out corpus is missing for)."""
    langs: set = set()
    for dirpath, dirnames, filenames in os.walk(ws):
        dirnames[:] = [d for d in dirnames if d not in _RECALL_SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            lang = _RECALL_LANG_EXTS.get(ext)
            if lang:
                langs.add(lang)
    return langs


def _load_heldout_hunt_records(ws: Path) -> list:
    """Load the held-out HUNT-case records (one auditor-backtest hunt_case
    record per line) from the canonical relpaths. These are the per-case
    EVIDENCE the recall is RECOMPUTED from - a written `recall` number is never
    trusted. Returns the list of record dicts (empty when no corpus present)."""
    recs: list = []
    a = ws / ".auditooor"
    for rel in _RECALL_RECORDS_RELPATHS:
        p = a / rel
        if not p.is_file():
            continue
        try:
            for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
                raw = raw.strip()
                if not raw or raw.startswith("#"):
                    continue
                rec = json.loads(raw)
                if isinstance(rec, dict):
                    recs.append(rec)
        except (OSError, ValueError):
            continue
    return recs


def _recompute_recall_by_language(records: list) -> dict:
    """RECOMPUTE per-language hunt-recall from the held-out hunt-case records via
    the auditor-backtest hunt_recall() (the same un-fakeable computation that
    tool prints) - never reading a stored recall number. Returns
    {lang: {recall, file_recall, scorable, caught, partial, missed, na}}."""
    ab = _load("_ab_recall", "auditor-backtest.py")
    by_lang: dict = {}
    for rec in records:
        lang = (rec.get("language") or "unknown")
        by_lang.setdefault(lang, []).append(rec)
    out: dict = {}
    for lang, recs in by_lang.items():
        out[lang] = ab.hunt_recall(recs)
    return out


def _log_recall_waiver(ws: Path, lang: str, reason: str) -> None:
    """Append a logged, typed recall waiver to .auditooor/recall_waivers.jsonl.
    A corpus-absent language is NEVER silent-zeroed: the typed verdict is logged
    so the gap is auditable (and so an operator can choose to build the corpus)."""
    try:
        a = ws / ".auditooor"
        a.mkdir(parents=True, exist_ok=True)
        rec = {
            "schema": "auditooor.recall_waiver.v1",
            "language": lang,
            "verdict": f"{lang}-recall-corpus-absent",
            "reason": reason,
            "logged_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        with (a / "recall_waivers.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
    except OSError:
        pass


def _check_recall_floor(ws: Path) -> tuple[bool, str, str]:
    """Check 7 (F4 / E4.2): an honest-0 over a present language requires the
    held-out HUNT-recall to clear the floor (default 0.5), computed PER LANGUAGE
    SUB-TREE. A Solidity 100% recall must NOT mask a zk 0% recall.

    Semantics (cross-cutting rules 1+3):
      - For each language that has held-out hunt records: RECOMPUTE its recall
        from those records (un-fakeable) and FAIL if it is below the floor.
      - For a present language with NO held-out corpus: emit the typed
        <lang>-recall-corpus-absent verdict + a LOGGED waiver and treat that
        language as waived (never silent-zero, never an un-waivable brick).
      - With no held-out records and no present source language: trivially OK.

    Rebuttal escape: an l37-rebuttal file containing 'recall_floor' on a line of
    its own (same convention as the other honest-0 checks)."""
    rebuttal_path = ws / ".auditooor" / "l37-rebuttal"
    if rebuttal_path.is_file():
        try:
            for line in rebuttal_path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip() == _RECALL_REBUTTAL_KEY:
                    return True, "ok-rebuttal: l37-rebuttal contains 'recall_floor'", "recall:rebuttal"
        except OSError:
            pass

    floor = float(os.environ.get("AUDITOOOR_HZ_RECALL_FLOOR", str(_HZ_RECALL_FLOOR_DEFAULT)))
    records = _load_heldout_hunt_records(ws)
    present = _present_source_languages(ws)

    # No corpus AND no present source -> trivially clean (nothing to grade).
    if not records and not present:
        return True, "no held-out hunt corpus and no present source language (nothing to floor)", "recall:none"

    by_lang = _recompute_recall_by_language(records) if records else {}
    # Languages that have scorable held-out records (the gradeable set).
    graded = {lang: r for lang, r in by_lang.items() if r.get("scorable", 0) > 0}

    failures = []
    waived = []
    passed = []
    # 1. Floor each language that HAS a gradeable held-out corpus.
    for lang, r in sorted(graded.items()):
        rc = r["recall"]
        if rc + 1e-9 < floor:
            failures.append(f"{lang}={r['caught']}/{r['scorable']}={rc:.0%}")
        else:
            passed.append(f"{lang}={r['caught']}/{r['scorable']}={rc:.0%}")

    # 2. Present languages with NO gradeable corpus -> typed waiver (logged).
    for lang in sorted(present):
        if lang in graded:
            continue
        _log_recall_waiver(
            ws, lang,
            "no held-out hunt corpus for this present language; "
            "recall not gradeable (build a held-out corpus to remove the waiver)")
        waived.append(f"{lang}-recall-corpus-absent")

    if failures:
        return (
            False,
            f"held-out hunt-recall below floor ({floor:.0%}) for: "
            f"{', '.join(failures)}"
            + (f" [ok: {', '.join(passed)}]" if passed else "")
            + " (genuine-0 needs >=floor recall per present language; raise the "
            "hunt's re-discovery or add 'recall_floor' to .auditooor/l37-rebuttal "
            "to skip, or AUDITOOOR_HZ_RECALL_FLOOR to retune)",
            "",
        )
    detail_bits = []
    if passed:
        detail_bits.append("cleared: " + ", ".join(passed))
    if waived:
        detail_bits.append("waived (corpus-absent, logged): " + ", ".join(waived))
    if not detail_bits:
        detail_bits.append("no gradeable held-out corpus; present languages waived")
    fp = "recall:" + ",".join(f"{l}:{r['recall']:.2f}" for l, r in sorted(graded.items()))
    return True, "; ".join(detail_bits), (fp if graded else "recall:waived")


def _check_audit_complete(ws: Path, ttl_hours: float) -> tuple[bool, str, str]:
    """Reuse audit-done-guard's marker logic: fresh pass-audit-complete STRICT."""
    adg = _load("_adg_hz", "audit-done-guard.py")
    marker = adg._find_marker(ws)
    if marker is None:
        return False, "no audit-complete marker", ""
    obj = _load_json(marker)
    blob = adg._verdict_blob(obj)
    if "pass-audit-complete" not in blob:
        return False, f"audit-complete marker not pass ({marker.name})", ""
    if isinstance(obj, dict):
        strict = obj.get("strict")
        if strict is not None and str(strict).lower() in ("0", "false", "no", "none"):
            return False, "audit-complete not under STRICT", ""
    age_h = (time.time() - adg._mtime(marker)) / 3600.0
    if ttl_hours and age_h > ttl_hours:
        return False, f"audit-complete pass is STALE ({age_h:.1f}h>{ttl_hours}h)", ""
    return True, f"pass-audit-complete STRICT {age_h:.1f}h old", f"{marker.name}:{int(adg._mtime(marker))}"


def _check_unhunted(ws: Path) -> tuple[bool, str, str]:
    gate = _load("_unh_hz", "unhunted-surface-followthrough-gate.py")
    res = gate.evaluate(str(ws))
    v = res.get("verdict", "")
    ab = res.get("stats", {}).get("abandoned_count", 0)
    ok = v.startswith("pass")
    return ok, f"unhunted gate verdict={v} abandoned={ab}", f"unhunted:{ab}"


def _check_nothing_fileable(ws: Path) -> tuple[bool, str, str]:
    pr = ws / "submissions" / "paste_ready"
    pr_files = [p for p in pr.rglob("*") if p.is_file() and p.suffix in (".md", ".sol")] if pr.is_dir() else []
    if pr_files:
        return False, f"{len(pr_files)} paste_ready file(s) exist - that is a SUBMISSION, not a 0", ""
    # no candidate-finding left OPEN in residual-hunt verdicts
    rv = _load_json(ws / ".auditooor" / "residual_hunt_verdicts.json")
    rows = rv if isinstance(rv, list) else (rv.get("verdicts") if isinstance(rv, dict) else []) or []
    open_cand = [r for r in rows if isinstance(r, dict)
                 and "candidate" in str(r.get("verdict", "")).lower()]
    if open_cand:
        return False, f"{len(open_cand)} candidate-finding(s) left open (must be filed or refuted)", ""
    return True, "no paste_ready submissions and no open candidate-findings", "fileable:0"


def _genuine_campaign_fuzz_artifact(ws: Path) -> Path | None:
    """A STANDALONE coverage-guided campaign (step-2c echidna>=500k / medusa>=1M
    over the real CUT, recorded in .auditooor/fuzz_campaign_receipt.json + raw-log
    corroborated + carrying >=1 non-vacuity mutant kill) is a non-trivial deep-
    engine fuzz artifact even when it lives outside deep-engine-findings/. Mirrors
    audit-completeness-check._standalone_coverage_campaign_executed (the same
    never-false-pass guards): a no-target / rc=6 / zero-call / vacuous run leaves
    no >=threshold raw-log line and no kill, so it can never pass. Returns the
    receipt path or None."""
    import re as _re
    a = ws / ".auditooor"
    rp = a / "fuzz_campaign_receipt.json"
    d = _load_json(rp)
    if not isinstance(d, dict) or str(d.get("schema", "")) != "auditooor.fuzz_campaign_receipt.v1":
        return None
    thr = {"echidna": 500_000, "medusa": 1_000_000}
    # raw-log corroboration: max parsed "Total calls: N" across fuzz_logs/*.log
    max_log = 0
    logd = a / "fuzz_logs"
    if logd.is_dir():
        for lp in logd.glob("*.log"):
            try:
                txt = lp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for m in _re.finditer(r"Total calls:\s*([0-9][0-9_,]*)", txt):
                try:
                    n = int(m.group(1).replace(",", "").replace("_", ""))
                except ValueError:
                    continue
                max_log = max(max_log, n)
    totals = d.get("totals") if isinstance(d.get("totals"), dict) else {}
    try:
        tot_kills = int(totals.get("non_vacuity_kills") or 0)
    except (ValueError, TypeError):
        tot_kills = 0
    for c in (d.get("campaigns") or []):
        if not isinstance(c, dict):
            continue
        eng = str(c.get("engine", "")).lower()
        t = thr.get(eng)
        if not t:
            continue
        res = c.get("result") if isinstance(c.get("result"), dict) else {}
        try:
            calls = int(res.get("calls") or 0)
            passed = int(res.get("passed") or 0)
        except (ValueError, TypeError):
            continue
        if calls < t or passed < 1 or max_log < t:
            continue
        try:
            ckills = int(c.get("non_vacuity_kills") or 0)
        except (ValueError, TypeError):
            ckills = 0
        md_kill = any(
            isinstance(m, dict)
            and str(m.get("baseline", "")).upper() == "PASS"
            and str(m.get("mutant_result", "")).upper() == "FAIL"
            for m in (c.get("mutation_detail") or [])
        )
        if ckills < 1 and tot_kills < 1 and not md_kill:
            continue
        return rp
    return None


_GCM_GENUINE_VERDICTS = frozenset(
    {"non-vacuous", "genuine", "mutation-verified", "killed"})


def _reconcile_gcm_counts(gcm: dict) -> dict:
    """Recompute genuine/checkable from the manifest's own embedded verdicts[] and
    override the summary counts when they disagree (a STALE manifest pairs a
    build-broken all-error summary with a prior-good verdicts[]). checkable =
    genuine + vacuous (the verdicts that were actually mutation-checked). Returns a
    shallow copy with corrected counts; the input is unchanged when consistent or
    when there are no verdicts. Defends honest-zero-verify's conservation gate from
    a stale checkable_count=0 silently disarming it (L11, 2026-06-30)."""
    if not isinstance(gcm, dict):
        return gcm
    verdicts = gcm.get("verdicts") or []
    if not (isinstance(verdicts, list) and verdicts):
        return gcm
    from collections import Counter
    vc = Counter(str(r.get("verdict")) for r in verdicts if isinstance(r, dict))
    genuine = sum(v for k, v in vc.items() if k in _GCM_GENUINE_VERDICTS)
    checkable = genuine + vc.get("vacuous", 0)
    if (checkable != (gcm.get("checkable_count") or 0)
            or genuine != (gcm.get("mutation_verified_genuine_count") or 0)):
        out = dict(gcm)
        out["checkable_count"] = checkable
        out["mutation_verified_genuine_count"] = genuine
        return out
    return gcm


def _check_deep_evidence(ws: Path) -> tuple[bool, str, str]:
    a = ws / ".auditooor"
    fps = []
    # a coverage-guided fuzz artifact (non-trivial)
    fuzz = None
    d = a / "deep-engine-findings"
    if d.is_dir():
        for p in sorted(d.glob("*.md")):
            if p.stat().st_size > 200:
                fuzz = p
                break
    # Serving-join fix: a genuine standalone coverage-guided campaign
    # (fuzz_campaign_receipt.json + raw fuzz_logs, mutation-verified, real CUT) is
    # a non-trivial deep-engine fuzz artifact even when deep-engine-findings/ holds
    # only the no-target/rc=6 auto-run record. Guarded (>=threshold raw-log calls +
    # >=1 non-vacuity kill) so it never credits a trivial/failed run.
    if fuzz is None:
        fuzz = _genuine_campaign_fuzz_artifact(ws)
    if fuzz is None:
        return False, "no non-trivial deep-engine fuzz artifact", ""
    fps.append(f"fuzz:{fuzz.stat().st_size}")
    # mutation-verify with >=1 verified harness
    mv = _load_json(a / "mutation_verify_coverage.json")
    counts = (mv or {}).get("counts", {}) if isinstance(mv, dict) else {}
    cross_fn_verified = counts.get("cross_function_verified", 0) or 0
    per_fn_verified = counts.get("per_function_verified", 0) or 0
    # Fold standalone mutation-verify-coverage.v1 sidecars (CUT-keyed; never in the
    # aggregate per_function counts) into the per-function verified tally - the
    # same un-fakeable ground truth (non-vacuous + killed mutant + CUT on disk)
    # the aggregate counter trusts. Without this a genuinely mutation-verified
    # harness recorded only as a sidecar (e.g. the ProtocolFee economic invariants)
    # was invisible to deep_evidence.
    per_fn_verified += _standalone_verified_count(ws)
    verified = cross_fn_verified + per_fn_verified
    # VALUE-MOVING-FUNCTIONS DIRECT GATE (checked BEFORE the verified<1 early-return):
    # fires even when DEEP_AUDIT_HOLLOW.flag is absent and even when
    # mutation_verify_coverage has 0 total verified harnesses.
    # Covers workspaces that never ran the deep audit pipeline at all (no hollow
    # flag was written by hollow-engine-check.py) but have an enumerated
    # value-moving surface with zero per-function coverage.
    # Auto-enumerate if the artifact is absent (best-effort, no exception on failure).
    _vmf_path = a / "value_moving_functions.json"
    if not _vmf_path.is_file():
        _vmf_script = Path(__file__).resolve().parent / "value-moving-functions.py"
        if _vmf_script.is_file():
            import subprocess as _sp
            try:
                _sp.run(
                    [sys.executable, str(_vmf_script), str(ws)],
                    capture_output=True, timeout=60,
                )
            except Exception:
                pass
    _vmf_early = _load_json(_vmf_path)
    _vmf_count_early = ((_vmf_early.get("function_count") or 0) if isinstance(_vmf_early, dict) else 0)
    if _vmf_count_early >= 1 and per_fn_verified == 0:
        # Allow when genuine_coverage_manifest shows actual kills AND those kills
        # are CORROBORATED by per_function entries in mutation_verify_coverage.json
        # (mutation_verified==True, oracle_verdict=="non-vacuous", killed==True).
        # A hand-written manifest with a bare integer is NOT sufficient.
        _gcm_early = _load_json(a / "genuine_coverage_manifest.json")
        _gcm_early_genuine = (
            (_gcm_early.get("mutation_verified_genuine_count") or 0)
            if isinstance(_gcm_early, dict) else 0
        )
        _corroborated_early = _corroborated_genuine_count(ws)
        _has_genuine_early = _gcm_early_genuine > 0 and _corroborated_early > 0
        if not _has_genuine_early:
            return (
                False,
                f"value_moving_functions.json lists {_vmf_count_early} value-moving "
                "function(s) but per_function_verified=0 and genuine_coverage_manifest "
                "shows 0 corroborated genuine per-function mutation-verified kills: "
                "workspace has uncovered value-moving functions with no genuine "
                "per-function harness evidence",
                "",
            )
    if verified < 1:
        return False, "mutation_verify_coverage has 0 verified harnesses", ""
    fps.append(f"mutverif:{verified}")
    # HOLLOW-FLAG RECONCILIATION: if DEEP_AUDIT_HOLLOW.flag is present AND
    # per_function_verified==0, the cross-function kill count does NOT substitute
    # for per-function mutation-verified harnesses on value-moving functions.
    # The flag is written by hollow-engine-check.py when genuine_coverage_manifest
    # reports mutation_verified_genuine_count==0 with checkable_count>0 (harnesses
    # were generated and ran but every one was a silent-skip or error). Prefer the
    # flag: it is written from the genuine_coverage_manifest, which is ground truth;
    # the mutation_verify_coverage cross_function counts cover multi-function
    # compositions and cannot substitute for per-function conservation evidence.
    # HOLLOW-FLAG RECONCILIATION: DEEP_AUDIT_HOLLOW.flag is authoritative.
    # It is written by hollow-engine-check.py whenever per-function harnesses
    # were generated (gen_count>0) but 0 mutation-verified genuine kills resulted.
    # If the flag is present AND per_function_verified==0, cross-function kills
    # do NOT substitute for per-function conservation evidence.
    # The flag is stale only if genuine_coverage_manifest explicitly shows
    # mutation_verified_genuine_count > 0 (meaning the harnesses have since been
    # fixed and the flag was not cleaned up). In that case, skip the fail.
    hollow_flag = a / "DEEP_AUDIT_HOLLOW.flag"
    if hollow_flag.is_file() and per_fn_verified == 0:
        # The flag is stale only when BOTH:
        #   (a) genuine_coverage_manifest claims mutation_verified_genuine_count > 0, AND
        #   (b) that claim is CORROBORATED by mutation_verify_coverage.json having >=1
        #       per_function entry with mutation_verified==True, oracle_verdict=="non-vacuous",
        #       killed==True.
        # A hand-written manifest with a bare integer is NOT sufficient.
        gcm_for_stale = _load_json(a / "genuine_coverage_manifest.json")
        gcm_genuine_for_stale = (
            (gcm_for_stale.get("mutation_verified_genuine_count") or 0)
            if isinstance(gcm_for_stale, dict) else 0
        )
        _corroborated_stale = _corroborated_genuine_count(ws)
        _flag_is_stale = (gcm_genuine_for_stale > 0 and _corroborated_stale > 0)
        if not _flag_is_stale:
            return (
                False,
                "DEEP_AUDIT_HOLLOW.flag present and per_function_verified=0: "
                "cross-function kills do not substitute for per-function "
                "mutation-verified harnesses (reconcile contradiction - "
                f"hollow flag wins over cross_function_verified={cross_fn_verified})",
                "",
            )
    # PER-FUNCTION CONSERVATION GATE: if genuine_coverage_manifest.json records
    # that harnesses were generated and ran (checkable_count>0) but every one
    # returned error/silent-skip (mutation_verified_genuine_count==0), then
    # cross-function kills are NOT sufficient deep evidence - require at least
    # one per-function verified harness. This fires even when the hollow flag is
    # absent (e.g. when cross-function-harness-producer did not write it because
    # cross_function_verified>0 suppressed flag writing).
    gcm = _load_json(a / "genuine_coverage_manifest.json")
    if isinstance(gcm, dict):
        # SELF-CONSISTENCY GUARD (L11, 2026-06-30): a STALE manifest can pair a
        # build-broken all-error `counts` (checkable_count=0) with a prior-good
        # embedded `verdicts[]` (e.g. 29 vacuous + 11 no-mutants). A stale
        # checkable_count=0 silently DISARMS the conservation gate below even
        # though the per-row detail IS the vacuous-theater it must catch. Recompute
        # genuine/checkable from the embedded verdicts[] and trust the per-row
        # detail when the summary disagrees (never-false-pass).
        gcm = _reconcile_gcm_counts(gcm)
        gcm_genuine = gcm.get("mutation_verified_genuine_count") or 0
        gcm_checkable = gcm.get("checkable_count") or 0
        if gcm_checkable > 0 and gcm_genuine == 0 and per_fn_verified == 0:
            return (
                False,
                f"genuine_coverage_manifest: {gcm_checkable} harness(es) ran "
                f"but mutation_verified_genuine_count=0 (all error/silent-skip); "
                "per_function_verified=0 and cross_function_verified cannot "
                "substitute - vacuous harness theater fails deep_evidence",
                "",
            )
    if not (a / "coverage_report.json").is_file():
        return False, "no coverage_report.json", ""
    fps.append("cov:1")
    return True, f"fuzz+{verified} mutation-verified harness(es)+coverage present", ";".join(fps)


_CHECKS = (
    ("audit_complete", _check_audit_complete),
    ("unhunted_clean", _check_unhunted),
    ("nothing_fileable", _check_nothing_fileable),
    ("deep_evidence", _check_deep_evidence),
    ("economic_invariants", _check_economic_invariants),
    ("banked_reusable", _check_banked_reusable),
    ("recall_floor", _check_recall_floor),
)


def verify(ws: Path, ttl_hours: float = 6.0) -> dict:
    res = {"workspace": str(ws), "ok": False, "checks": {}, "reason": "", "fingerprint": ""}
    if not ws.is_dir():
        res["reason"] = f"workspace not found: {ws}"
        return res
    fps = []
    all_ok = True
    fail_reasons = []
    for name, fn in _CHECKS:
        try:
            ok, why, fp = (fn(ws, ttl_hours) if name == "audit_complete" else fn(ws))
        except Exception as exc:  # defensive: a crashing check is NOT a pass
            ok, why, fp = False, f"check error: {type(exc).__name__}: {exc}", ""
        res["checks"][name] = {"ok": ok, "detail": why}
        if fp:
            fps.append(fp)
        if not ok:
            all_ok = False
            fail_reasons.append(f"{name}: {why}")
    res["ok"] = all_ok
    res["fingerprint"] = hashlib.sha256("|".join(fps).encode()).hexdigest()[:16]
    res["reason"] = ("genuine honest-0: all evidence checks pass"
                     if all_ok else "NOT honest-0: " + "; ".join(fail_reasons))
    return res


def stamp(ws: Path, ttl_hours: float = 6.0) -> dict:
    r = verify(ws, ttl_hours)
    out = ws / ".auditooor" / "honest_zero.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({
        "schema": _SCHEMA,
        "verified_by": "honest-zero-verify.py",
        "all_gates_green": r["ok"],
        "checks": r["checks"],
        "fingerprint": r["fingerprint"],
        "reason": r["reason"],
    }, indent=2), encoding="utf-8")
    return r


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--stamp", action="store_true")
    ap.add_argument("--ttl-hours", type=float, default=float(os.environ.get("AUDIT_DONE_TTL_HOURS", "6")))
    args = ap.parse_args(argv)
    ws = Path(os.path.expanduser(args.workspace)).resolve()
    if not ws.is_dir():
        print(f"[honest-zero-verify] error: workspace not found: {ws}")
        return 2
    r = stamp(ws, args.ttl_hours) if args.stamp else verify(ws, args.ttl_hours)
    if args.json:
        print(json.dumps(r, indent=2))
    else:
        print(("HONEST-ZERO" if r["ok"] else "NOT-HONEST-ZERO") + ": " + r["reason"])
        for n, c in r["checks"].items():
            print(f"  [{'PASS' if c['ok'] else 'FAIL'}] {n}: {c['detail']}")
    return 0 if r["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
