#!/usr/bin/env python3
"""reasoner-firing-nonvacuity-check.py - the FIRING (non-vacuity) gate for the
pre-hunt LOGIC + NOVELTY reasoners (docs/LOGIC_ARSENAL_ROADMAP.md).

THE HOLE THIS CLOSES
--------------------
The shape->logic inversion is ORDERING-proven: readme_runbook_steps.json wires the
~35 LOGIC/novelty reasoners (the ``_REASONER_LEDGERS`` set in
tools/logic-obligation-resolution-check.py) to run BEFORE the step-3 hunt, and the
sibling ``logic-obligation-resolution-check.py`` asserts every EMITTED obligation
reaches a terminal verdict. But nothing asserts a reasoner ever FIRED: a reasoner
can pass the ordering gate while emitting ZERO obligations and leaving ZERO trace of
having examined anything - a silently-empty / never-written ledger reads identically
to "ran and cleanly found nothing". That is coverage-theater / vacuity: the reasoner
is wired but dead, and audit-complete still passes.

WHAT "FIRED" MEANS (per reasoner ledger)
----------------------------------------
For each wired reasoner we require EXAMINED-evidence AND one of {emitted survivors,
a recorded clean-run note, a recorded surface-absent exemption} - never a SILENT
zero. Concretely each ledger is classified:

  FIRED         >=1 anchored obligation row (function / op_a / site.file / contract /
                file+line detector). The reasoner examined the surface and emitted at
                least one obligation. Non-vacuous by construction.

  FIRED_CLEAN   No anchored obligation, BUT an EXPLICIT examined-record row is present
                (a ``cited-empty`` note, a ``report`` summary, or a ``survivors`` key)
                that is NOT degraded - i.e. the reasoner ran over the in-scope surface,
                examined it, and RECORDED that it found 0 survivors. examined>0,
                emitted=0, but the zero is EXPLICITLY recorded (not silent). PASS.

  EXEMPT        A RECORDED, source-cited language/surface-absent exemption - either
                (a) the reasoner itself emitted a DEGRADED report (report.degraded=True,
                    a crate mir_error like ``no-cargo-toml`` / ``no-crate``, or
                    any_mir=False with an error) meaning the target language/surface is
                    absent, OR
                (b) an explicit operator row in
                    <ws>/.auditooor/reasoner_firing_exemptions.jsonl carrying
                    {"ledger": <fname>, "reason": ..., "citation": ...}.
                The exemption reason is RECORDED and reported. PASS.
                NOTE: a reasoner is NEVER auto-exempted from its declared ``lang`` scope
                alone - a missing zk ledger on a non-zk workspace is legitimately N/A,
                but the N/A must be RECORDED (via the reasoner's own degraded report or
                the exemption sidecar), NOT inferred here. Silent N/A = VACUOUS.

  VACUOUS       Neither fired, nor clean-with-record, nor exempt: an EMPTY ledger file,
                a MISSING ledger file, or rows present with no anchor and no examined
                record. There is ZERO evidence the reasoner examined anything and NO
                recorded reason. This is the fail-loud case - a real capability gap.

VACUITY CAUSE (per-reasoner ``cause`` field in --json)
------------------------------------------------------
A bare VACUOUS verdict says "firing unproven" but not WHY - and the fix differs per
root cause. Every reasoner carries a ``cause`` field pinning that root cause so an
operator (or an auto-closer) knows what to do. The dataflow substrate the reasoners
consume (``.auditooor/dataflow_paths.jsonl`` + ``dataflow_paths.*.jsonl`` shards, the
same substrate ``logic-obligation-resolution-check._has_dataflow_substrate`` keys on)
is the reference input; the reasoner's ledger is its output.

  fired               Not vacuous - the reasoner FIRED or ran-clean-with-record.
                      (verdict in {fired, fired_clean}). No remediation owed.
  genuine-na          verdict==exempt: a RECORDED surface-absent / operator N/A. The
                      surface is truly absent; nothing to run. No remediation owed.
  missing-producer    VACUOUS + the substrate itself is absent or every candidate
                      shard is 0-line: no tool WROTE the reasoner's input. Fix the
                      producer (run the dataflow stage), not the reasoner.
  ordering-staleness  VACUOUS + substrate present+non-empty but NEWER than the ledger
                      (substrate mtime > ledger mtime, or the ledger is missing while
                      a fresh substrate exists): the reasoner ran BEFORE its input was
                      (re)written - re-run the reasoner over the current substrate.
  predicate-mismatch  VACUOUS + substrate present, non-empty AND not newer than the
                      ledger (reasoner ran over the current input) yet emitted 0 rows
                      with no examined-record: the reasoner's predicate matched nothing
                      / silently dropped. Fix the reasoner predicate or record a
                      cited-empty examined-record.

A recorded genuine-N/A (verdict==exempt, via the reasoner's own degraded report or the
``reasoner_firing_exemptions.jsonl`` sidecar) reads as cause=genuine-na and never as
VACUOUS - honoring the operator's recorded N/A.

POLICY (advisory-first, mirrors logic-obligation-resolution-check + the
_gate_default_on_strict graduation discipline)
  - Default / bare caller: WARN-pass (ok=True), the VACUOUS list reported LOUD.
  - Fail-closed (ok=False, verdict ``fail-reasoner-vacuous``) when >=1 reasoner is
    VACUOUS under the dedicated AUDITOOOR_L37_REASONER_FIRING_STRICT=1 OR the global
    AUDITOOOR_L37_STRICT=1 (what ``make audit-complete`` exports by default), with a
    per-gate opt-out (AUDITOOOR_L37_REASONER_FIRING_STRICT in {0,false,no}).
  - Fail-OPEN (WARN-pass) when the reasoner registry cannot be loaded / no .auditooor.

This gate does NOT auto-exempt to green a vacuous reasoner - surfacing the gap is the
whole point. The exemption path requires an explicit recorded artifact.

CLI: python3 tools/reasoner-firing-nonvacuity-check.py --workspace <ws> [--json] [--strict]
Exit: 0 = pass / advisory-warn-pass; 1 = fail (vacuous under strict); 2 = usage/IO.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path

_EXEMPTION_SIDECAR = "reasoner_firing_exemptions.jsonl"

# Crate/backend error tokens (normalized) that mean "target language/surface absent"
# - the reasoner ran but the crate/module it screens is not present in this workspace.
_SURFACE_ABSENT_TOKENS = (
    "no-cargo-toml", "no-cargo", "no-crate", "no-crates", "no-mir", "no-manifest",
    "language-absent", "surface-absent", "no-go-mod", "no-gomod", "no-package",
    "not-applicable", "n-a", "no-src", "no-source", "target-absent",
)


def _load_reasoner_ledgers() -> tuple[tuple[str, str, str], ...]:
    """Single source of truth: import ``_REASONER_LEDGERS`` from the sibling
    logic-obligation-resolution-check.py so the wired-reasoner set never drifts."""
    sib = Path(__file__).resolve().with_name("logic-obligation-resolution-check.py")
    if not sib.is_file():
        return ()
    spec = importlib.util.spec_from_file_location("_logic_obl_reg", sib)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_logic_obl_reg"] = mod
    spec.loader.exec_module(mod)
    led = getattr(mod, "_REASONER_LEDGERS", ())
    return tuple(led)


def _norm(v) -> str:
    s = str(v or "").strip().lower()
    out = [ch if ch.isalnum() else "-" for ch in s]
    return "-".join(t for t in "".join(out).split("-") if t)


def _load_jsonl(p: Path) -> list[dict]:
    rows: list[dict] = []
    try:
        txt = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rows
    for line in txt.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _is_anchored(row: dict) -> bool:
    """True iff the row is a real, site-anchored obligation (proves the reasoner
    examined a specific unit and emitted an obligation about it). Advisory rows still
    count - a needs-source advisory about a concrete site IS emitted output that proves
    firing; the resolution/quality of that obligation is the sibling gate's job."""
    if row.get("function") or row.get("source_function"):
        return True
    if row.get("op_a") and row.get("op_b"):
        return True
    site = row.get("site")
    if isinstance(site, dict) and site.get("file"):
        return True
    if row.get("contract"):
        return True
    # bare file+line detector row (e.g. slice_oob taint) with a hacker_question / evidence
    if row.get("file") and (row.get("line") is not None) and (
            row.get("detector") or row.get("evidence") or row.get("hacker_question")
            or row.get("invariant")):
        return True
    return False


def _extract_report(row: dict) -> dict:
    rep = row.get("report")
    return rep if isinstance(rep, dict) else {}


def _examined_count(row: dict) -> int:
    """Best-effort examined magnitude from a report/summary row (0 if none found)."""
    rep = _extract_report(row)
    tot = rep.get("totals") if isinstance(rep.get("totals"), dict) else {}
    for k in ("examined", "scanned", "candidates", "fns_parsed", "nodes",
              "checked_kept", "bare_arith_nodes", "untrusted_value_arith"):
        for src in (row, rep, tot):
            try:
                v = int(src.get(k, 0) or 0)
            except (TypeError, ValueError):
                v = 0
            if v > 0:
                return v
    # crate-level fns_parsed / mir_lines sum
    crates = rep.get("crates") if isinstance(rep.get("crates"), dict) else {}
    s = 0
    for c in crates.values():
        if isinstance(c, dict):
            for k in ("fns_parsed", "mir_lines", "nodes", "survivors"):
                try:
                    s += int(c.get(k, 0) or 0)
                except (TypeError, ValueError):
                    pass
    return s


def _is_examined_record(row: dict) -> bool:
    """True iff the row is an explicit RECORD that the reasoner ran and examined the
    surface (a cited-empty note, a report summary, or a survivors key). Distinguishes
    'ran-and-recorded-clean' from a SILENTLY empty ledger."""
    note = str(row.get("note") or "").lower()
    if "cited-empty" in note or "cited_empty" in note or "screen ran" in note \
            or "query ran" in note or "ran over" in note:
        return True
    if _extract_report(row):
        return True
    if "survivors" in row:
        return True
    return False


def _surface_absent_reason(row: dict) -> str | None:
    """If this report row records the target language/surface as ABSENT (degraded
    run), return a citable reason string; else None. This is a RECORDED exemption the
    reasoner itself emitted - not an inference by this gate."""
    rep = _extract_report(row)
    if not rep and "survivors" not in row and not _is_examined_record(row):
        return None
    # explicit degraded flag
    if rep.get("degraded") is True:
        # collect the crate error(s) for citation
        crates = rep.get("crates") if isinstance(rep.get("crates"), dict) else {}
        errs = []
        for name, c in crates.items():
            if isinstance(c, dict):
                for k in ("mir_error", "error", "reason", "skip_reason"):
                    if c.get(k):
                        errs.append(f"{name}.{k}={c[k]}")
        cite = "; ".join(errs) if errs else "report.degraded=True"
        return f"reasoner recorded degraded/surface-absent run ({cite})"
    # any_mir False + a crate error => rust/mir surface absent
    if rep.get("any_mir") is False:
        crates = rep.get("crates") if isinstance(rep.get("crates"), dict) else {}
        for name, c in crates.items():
            if isinstance(c, dict):
                err = str(c.get("mir_error") or c.get("error") or "")
                if _norm(err) in _SURFACE_ABSENT_TOKENS or "no-cargo" in _norm(err):
                    return f"reasoner recorded MIR/crate surface absent ({name}.mir_error={err})"
    # crate-level absent token anywhere
    crates = rep.get("crates") if isinstance(rep.get("crates"), dict) else {}
    for name, c in crates.items():
        if isinstance(c, dict):
            for k in ("mir_error", "error", "reason", "skip_reason", "backend"):
                tok = _norm(c.get(k))
                if tok in _SURFACE_ABSENT_TOKENS:
                    return f"reasoner recorded surface absent ({name}.{k}={c[k]})"
    # explicit note-level absence marker
    note = _norm(row.get("note"))
    for t in _SURFACE_ABSENT_TOKENS:
        if t in note:
            return f"reasoner note records surface absent ({row.get('note')})"
    return None


def _load_exemption_sidecar(ws: Path) -> dict[str, dict]:
    """{normalized_ledger_name: {reason, citation}} from the OPTIONAL operator-recorded
    exemption ledger. NEVER auto-created - an explicit artifact only."""
    out: dict[str, dict] = {}
    p = ws / ".auditooor" / _EXEMPTION_SIDECAR
    if not p.is_file():
        return out
    for row in _load_jsonl(p):
        led = row.get("ledger") or row.get("ledger_name") or row.get("fname")
        if not led:
            continue
        out[_norm(led)] = {
            "reason": str(row.get("reason") or "").strip(),
            "citation": str(row.get("citation") or row.get("source_ref") or "").strip(),
        }
    return out


# --- vacuity CAUSE diagnosis -------------------------------------------------
# The reasoners consume the shared dataflow substrate; its newest NON-EMPTY shard
# mtime vs the reasoner ledger mtime pins whether a vacuous reasoner is missing its
# producer, stale w.r.t. its input, or ran-fresh-but-matched-nothing.
_SUBSTRATE_BASENAMES = ("dataflow_paths.jsonl",)
_SUBSTRATE_GLOBS = ("dataflow_paths.*.jsonl",)


def _substrate_files(aud: Path) -> list[Path]:
    """Dataflow substrate shards under <ws>/.auditooor (the same substrate
    logic-obligation-resolution-check._has_dataflow_substrate keys on)."""
    out: list[Path] = []
    for b in _SUBSTRATE_BASENAMES:
        p = aud / b
        if p.is_file():
            out.append(p)
    for g in _SUBSTRATE_GLOBS:
        try:
            out.extend(sorted(aud.glob(g)))
        except OSError:
            pass
    seen: set[Path] = set()
    uniq: list[Path] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _file_has_rows(p: Path) -> bool:
    """True iff the file has >=1 non-blank line (a 0-line / whitespace-only shard is
    treated as absent == missing-producer)."""
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    return True
    except OSError:
        pass
    return False


def _substrate_mtime(aud: Path) -> float | None:
    """Newest mtime among NON-EMPTY dataflow substrate shards, or None when the
    substrate is absent / every candidate shard is 0-line (== missing-producer)."""
    mt: float | None = None
    for p in _substrate_files(aud):
        if not _file_has_rows(p):
            continue
        try:
            m = p.stat().st_mtime
        except OSError:
            continue
        if mt is None or m > mt:
            mt = m
    return mt


def _diagnose_cause(entry: dict, ledger_path: Path, sub_mtime: float | None) -> str:
    """Pin the per-reasoner vacuity CAUSE. Returns one of:
      fired               not vacuous (verdict fired / fired_clean) - no remediation
      genuine-na          verdict exempt (recorded surface-absent / operator N/A)
      missing-producer    vacuous + substrate absent / all shards 0-line
      ordering-staleness  vacuous + substrate present+fresh but NEWER than the ledger
                          (or ledger missing while a fresh substrate exists)
      predicate-mismatch  vacuous + substrate present, not newer than the ledger, yet
                          0 rows emitted (reasoner ran the current input, matched none)
    """
    v = entry.get("verdict")
    if v in ("fired", "fired_clean"):
        return "fired"
    if v == "exempt":
        return "genuine-na"
    # VACUOUS: root-cause it.
    if sub_mtime is None:
        return "missing-producer"
    if not ledger_path.is_file():
        # substrate present+non-empty, reasoner never wrote a ledger over it
        return "ordering-staleness"
    try:
        led_mtime = ledger_path.stat().st_mtime
    except OSError:
        return "ordering-staleness"
    if sub_mtime > led_mtime:
        return "ordering-staleness"
    return "predicate-mismatch"


def _classify_ledger(aud: Path, fname: str, tool: str, lang: str,
                     exemptions: dict[str, dict]) -> dict:
    p = aud / fname
    entry = {
        "ledger": fname, "tool": tool, "lang": lang,
        "present": p.is_file(), "n_rows": 0, "emitted": 0,
        "examined": 0, "verdict": "", "cause": "", "reason": "",
    }
    # (b) operator-recorded exemption always wins (explicit, source-cited artifact)
    exm = exemptions.get(_norm(fname))
    if not p.is_file():
        if exm:
            entry["verdict"] = "exempt"
            entry["reason"] = (f"recorded exemption (sidecar): "
                               f"{exm.get('reason') or 'N/A'}"
                               + (f" [{exm['citation']}]" if exm.get("citation") else ""))
            return entry
        entry["verdict"] = "vacuous"
        entry["reason"] = ("missing ledger: reasoner emitted NO ledger and no recorded "
                           "exemption - firing UNPROVEN")
        return entry

    rows = _load_jsonl(p)
    entry["n_rows"] = len(rows)
    anchored = [r for r in rows if _is_anchored(r)]
    entry["emitted"] = len(anchored)

    if anchored:
        entry["verdict"] = "fired"
        entry["examined"] = max([len(anchored)] + [_examined_count(r) for r in rows])
        entry["reason"] = f"{len(anchored)} anchored obligation(s) emitted"
        return entry

    # No anchored obligation. Look for a surface-absent (degraded) record => EXEMPT.
    for r in rows:
        reason = _surface_absent_reason(r)
        if reason:
            entry["verdict"] = "exempt"
            entry["examined"] = _examined_count(r)
            entry["reason"] = reason
            return entry

    # operator-recorded exemption (present file but no emit + a recorded reason)
    if exm:
        entry["verdict"] = "exempt"
        entry["reason"] = (f"recorded exemption (sidecar): {exm.get('reason') or 'N/A'}"
                           + (f" [{exm['citation']}]" if exm.get("citation") else ""))
        return entry

    # An explicit examined-record (cited-empty / report / survivors) that is NOT degraded
    # => FIRED_CLEAN (ran, examined, recorded 0 survivors).
    for r in rows:
        if _is_examined_record(r):
            entry["verdict"] = "fired_clean"
            entry["examined"] = _examined_count(r)
            entry["reason"] = ("examined-record present (cited-empty/report), 0 survivors "
                               "- ran clean, recorded (not silent)")
            return entry

    # Rows present but none anchored and no examined-record -> cannot prove examination.
    if rows:
        entry["verdict"] = "vacuous"
        entry["reason"] = (f"{len(rows)} row(s) present but none anchored and no "
                           "examined-record (cited-empty/report) - firing UNPROVEN")
        return entry

    # Empty file, no exemption.
    entry["verdict"] = "vacuous"
    entry["reason"] = ("empty ledger (0 rows): no obligation, no examined-record, no "
                       "recorded exemption - firing UNPROVEN")
    return entry


def check(ws: Path) -> dict:
    ws = Path(ws).resolve()
    strict = (
        os.environ.get("AUDITOOOR_L37_REASONER_FIRING_STRICT", "").strip().lower()
        not in ("", "0", "false", "no")
        if os.environ.get("AUDITOOOR_L37_REASONER_FIRING_STRICT", "").strip() != ""
        else os.environ.get("AUDITOOOR_L37_STRICT", "").strip().lower()
        not in ("", "0", "false", "no")
    )
    result: dict = {
        "workspace": str(ws), "verdict": "pass", "ok": True, "strict": strict,
        "reason": "", "n_reasoners": 0, "fired": 0, "fired_clean": 0,
        "exempt": 0, "vacuous": 0, "vacuous_ledgers": [], "per_reasoner": [],
        "cause_counts": {"fired": 0, "genuine-na": 0, "missing-producer": 0,
                         "ordering-staleness": 0, "predicate-mismatch": 0},
        "substrate_present": False, "artifacts": [],
    }
    ledgers = _load_reasoner_ledgers()
    if not ledgers:
        result["reason"] = ("could not load _REASONER_LEDGERS registry from "
                            "logic-obligation-resolution-check.py; WARN-pass")
        return result
    result["n_reasoners"] = len(ledgers)
    aud = ws / ".auditooor"
    if not aud.is_dir():
        result["reason"] = "no .auditooor dir; nothing reasoned (WARN-pass)"
        return result

    exemptions = _load_exemption_sidecar(ws)
    ex_p = aud / _EXEMPTION_SIDECAR
    if ex_p.is_file():
        result["artifacts"].append(str(ex_p))

    sub_mtime = _substrate_mtime(aud)
    result["substrate_present"] = sub_mtime is not None

    for fname, tool, lang in ledgers:
        entry = _classify_ledger(aud, fname, tool, lang, exemptions)
        entry["cause"] = _diagnose_cause(entry, aud / fname, sub_mtime)
        result["cause_counts"][entry["cause"]] = (
            result["cause_counts"].get(entry["cause"], 0) + 1)
        result["per_reasoner"].append(entry)
        v = entry["verdict"]
        if v == "fired":
            result["fired"] += 1
        elif v == "fired_clean":
            result["fired_clean"] += 1
        elif v == "exempt":
            result["exempt"] += 1
        else:
            result["vacuous"] += 1
            result["vacuous_ledgers"].append(fname)
        if entry["present"]:
            result["artifacts"].append(str(aud / fname))

    vac = result["vacuous"]
    passing = result["fired"] + result["fired_clean"] + result["exempt"]
    if vac == 0:
        result["reason"] = (
            f"all {result['n_reasoners']} wired reasoner(s) proved firing: "
            f"fired={result['fired']} fired_clean={result['fired_clean']} "
            f"exempt={result['exempt']} (0 silently-vacuous)")
        return result

    ok = not strict
    result["ok"] = ok
    result["verdict"] = "pass-advisory-vacuous" if ok else "fail-reasoner-vacuous"
    cc = result["cause_counts"]
    cause_brk = (f"missing-producer={cc['missing-producer']} "
                 f"ordering-staleness={cc['ordering-staleness']} "
                 f"predicate-mismatch={cc['predicate-mismatch']}")
    result["reason"] = (
        f"{vac} of {result['n_reasoners']} wired reasoner(s) SILENTLY VACUOUS (fired 0 "
        f"with no examined-record and no recorded exemption) [{cause_brk}]: "
        f"{', '.join(result['vacuous_ledgers'])}"
        + ("; advisory - capability-firing debt, not a gate under default policy"
           if ok else
           "; (STRICT: make each vacuous reasoner emit an examined-record / obligation, "
           "or record an explicit source-cited exemption in "
           f"{_EXEMPTION_SIDECAR}, or add a reasoner-firing-nonvacuity-rebuttal, before "
           "done)"))
    return result


def _print_human(res: dict) -> None:
    print(f"reasoner-firing-nonvacuity  ws={res['workspace']}")
    print(f"  strict={res['strict']}  n_reasoners={res['n_reasoners']}")
    print(f"  fired={res['fired']} fired_clean={res['fired_clean']} "
          f"exempt={res['exempt']} VACUOUS={res['vacuous']}")
    cc = res.get("cause_counts", {})
    print(f"  substrate_present={res.get('substrate_present')}  causes: "
          f"missing-producer={cc.get('missing-producer', 0)} "
          f"ordering-staleness={cc.get('ordering-staleness', 0)} "
          f"predicate-mismatch={cc.get('predicate-mismatch', 0)} "
          f"genuine-na={cc.get('genuine-na', 0)}")
    print(f"  {'VERDICT':11s} {'EMIT':>4} {'LANG':4s} {'CAUSE':18s} LEDGER  ::  reason")
    for e in res["per_reasoner"]:
        tag = e["verdict"].upper()
        flag = "  <-- VACUOUS" if e["verdict"] == "vacuous" else ""
        print(f"    {tag:11s} {e['emitted']:>4} {e['lang']:4s} {e.get('cause', ''):18s} "
              f"{e['ledger']}  ::  {e['reason']}{flag}")
    print(f"  verdict={res['verdict']} ok={res['ok']}")
    print(f"  {res['reason']}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--workspace", required=True)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="force fail-closed on a vacuous reasoner (same as "
                         "AUDITOOOR_L37_REASONER_FIRING_STRICT=1)")
    args = ap.parse_args(argv)
    ws = Path(os.path.expanduser(args.workspace))
    if not ws.is_dir():
        print(f"ERROR: workspace not found: {ws}", file=sys.stderr)
        return 2
    if args.strict:
        os.environ["AUDITOOOR_L37_REASONER_FIRING_STRICT"] = "1"
    res = check(ws)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        _print_human(res)
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
