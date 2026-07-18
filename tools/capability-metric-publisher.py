#!/usr/bin/env python3
# <!-- r36-rebuttal: pathspec declared via tools/agent-pathspec-register.py lane LANE-PR3b-capability-publisher; orchestrator commits; sibling auditor-backtest.py untouched -->
"""capability-metric-publisher.py - honest capability-metric publisher for the
auditooor DETECTION LAYER.

What this answers
-----------------
`tools/auditor-backtest.py` grades ONE batch of known-vuln cases CAUGHT /
PARTIAL / MISSED / NA. It does NOT know about split discipline, negative
controls, NA-rate, or fresh-target forward tests, and it has no concept of
"which number is the headline".

This publisher composes auditor-backtest.py across the FOUR splits the uplift
plan defines (docs/FIND_ALL_BUGS_CAPABILITY_UPLIFT_PLAN_2026-05-29.md) and
publishes ONE honest report:

    TRAIN        - cases detectors/invariants were authored from. CIRCULAR by
                   construction; reported but NEVER the headline.
    DEV          - tuning split. Reported.
    HELD_OUT     - cases never inspected for authoring. Its strict line recall
                   is THE finding-power number ("held-out recall is the
                   headline"). This is what generalization looks like.
    FIXED_REF    - negative controls: the SAME case at its FIXED (post-fix) ref.
                   A detector firing there (CAUGHT/PARTIAL) is a FALSE POSITIVE,
                   because the bug is gone. Reported as fixed-ref FP rate.
    FRESH_TARGET - a real unseen target forward test. This publisher does NOT
                   run a fresh target itself (that is tools/fresh-target-
                   forward-test.py's job per the plan); it surfaces an HONEST
                   slot: if reports/fresh_target_forward_tests/ has a result it
                   is summarized, otherwise the slot is "not-run" and is NEVER
                   reported as a success.

Per the plan's metric definitions:
    strict_line_recall = CAUGHT / (CAUGHT + PARTIAL + MISSED)
    file_recall        = (CAUGHT + PARTIAL) / (CAUGHT + PARTIAL + MISSED)
    na_rate            = NA / TOTAL
    fixed_ref_fp_rate  = (CAUGHT + PARTIAL on fixed ref) / (scorable fixed-ref controls)

The headline is HELD_OUT strict_line_recall. TRAIN recall is printed with an
explicit "(circular - not finding power)" tag so it cannot be mistaken for the
capability number.

Case corpus
-----------
A single JSONL where every line is a case object. Each case carries a `split`
key in {TRAIN, DEV, HELD_OUT, FRESH_TARGET} (case-insensitive; `held-out` and
`heldout` normalize to HELD_OUT). The fields auditor-backtest.py consumes are
forwarded verbatim:
    id / case_id, repo, prefix_ref (or vulnerable_ref_full_sha), vuln_class,
    file_line (or vuln_file[:vuln_line_start]).
Negative controls are derived automatically from any case that ALSO carries a
fixed ref (`fixed_ref` / `fixed_ref_full_sha`): the publisher synthesizes a
fixed-ref control case with prefix_ref swapped to the fixed ref and runs it
through the same backtest. No separate fixed-ref corpus file is required, but
one may be supplied via --fixed-ref-cases.

Offline / no-corpus posture
---------------------------
This tool is a measurement publisher; it ALWAYS exits 0 unless --strict-ci is
given AND a gate is breached. With no corpus it emits an empty-but-valid report
(every recall = null, every count = 0) so `make auditor-capability-ci` is a
green no-op on a fresh checkout rather than a hard error. The honest report
distinguishes "0 scorable cases" from "0% recall" - they are NOT the same.

Usage
-----
    python3 tools/capability-metric-publisher.py \
        [--cases reference/fetchable_vuln_corpus.jsonl] \
        [--fixed-ref-cases reference/fixed_ref_controls.jsonl] \
        [--corpus-detector-dir DIR ...] \
        [--local-checkout-root DIR] \
        [--out-dir reports/capability_metrics] \
        [--na-rate-max 0.5] [--fixed-ref-fp-max 0.1] \
        [--min-heldout-scorable 0] \
        [--strict-ci] [--json]

Writes reports/<out-dir>/latest.json (schema
auditooor.capability_metric_report.v1) and latest.md. With --json the JSON
record is also echoed to stdout.

RELATED TOOLS:
  * tools/auditor-backtest.py - the per-batch CAUGHT/MISSED/NA grader this tool
    composes. This publisher does NOT re-implement grading; it shells out to
    auditor-backtest.py --json per split and aggregates. DISJOINT file.
  * tools/audit/detector-catch-rate-backtest.py - circular self-test catch-rate;
    not split-aware and not a negative-control runner.
  * tools/hackerman-capability-status.py - reads a pre-existing realworld-recall
    scoreboard JSON; it does not RUN the backtest across splits nor compute
    fixed-ref FP. This tool PRODUCES the split report it could consume.
  * tools/fresh-target-forward-test.py - (plan) runs a real fresh target; this
    publisher only SUMMARIZES its output dir, it never fabricates a fresh run.

Stdlib only. auditor-backtest.py is invoked as a subprocess (it brings its own
yaml/slither). Exits 0 unless --strict-ci gate breach.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKTEST_TOOL = REPO_ROOT / "tools" / "auditor-backtest.py"
DEFAULT_OUT_DIR = REPO_ROOT / "reports" / "capability_metrics"
DEFAULT_FRESH_TARGET_DIR = REPO_ROOT / "reports" / "fresh_target_forward_tests"
SCHEMA = "auditooor.capability_metric_report.v1"

CANONICAL_SPLITS = ["TRAIN", "DEV", "HELD_OUT", "FIXED_REF", "FRESH_TARGET"]
HEADLINE_SPLIT = "HELD_OUT"


# --------------------------------------------------------------------------
# Split normalization
# --------------------------------------------------------------------------
def normalize_split(raw) -> str:
    s = (str(raw or "")).strip().upper().replace("-", "_")
    if s in ("HELDOUT", "HELD_OUT", "HOLDOUT"):
        return "HELD_OUT"
    if s in ("FRESHTARGET", "FRESH_TARGET"):
        return "FRESH_TARGET"
    if s in ("FIXEDREF", "FIXED_REF", "NEGATIVE_CONTROL", "CONTROL"):
        return "FIXED_REF"
    if s in ("TRAIN", "TRAINING"):
        return "TRAIN"
    if s in ("DEV", "DEVELOPMENT", "TUNE", "TUNING"):
        return "DEV"
    # default unknown -> TRAIN is the SAFEST place to report (circular, never
    # headline) so an unlabeled case cannot silently inflate held-out recall.
    return "TRAIN" if not s else s


# --------------------------------------------------------------------------
# Case field normalization (forward to the keys auditor-backtest.py reads)
# --------------------------------------------------------------------------
def _first(case, *keys, default=""):
    for k in keys:
        v = case.get(k)
        if v not in (None, ""):
            return v
    return default


def _build_file_line(case) -> str:
    fl = _first(case, "file_line")
    if fl:
        return fl
    vf = _first(case, "vuln_file")
    if not vf:
        return ""
    ls = case.get("vuln_line_start")
    if ls not in (None, ""):
        return f"{vf}:{ls}"
    return vf


def to_backtest_case(case, *, ref_key="prefix") -> dict:
    """Project an input case into the 5-key shape auditor-backtest.py consumes.

    ref_key='prefix' uses the vulnerable (pre-fix) ref; ref_key='fixed' uses the
    fixed (post-fix) ref for a negative control."""
    if ref_key == "fixed":
        ref = _first(case, "fixed_ref", "fixed_ref_full_sha", "negative_control_ref")
    else:
        ref = _first(case, "prefix_ref", "vulnerable_ref_full_sha", "vuln_ref")
    return {
        "id": _first(case, "id", "case_id", default="?"),
        "repo": _first(case, "repo", "repo_url"),
        "prefix_ref": ref,
        "vuln_class": _first(case, "vuln_class", "attack_class", "bug_class"),
        "file_line": _build_file_line(case),
    }


def has_fixed_ref(case) -> bool:
    return bool(_first(case, "fixed_ref", "fixed_ref_full_sha", "negative_control_ref"))


# --------------------------------------------------------------------------
# Corpus loading + partition
# --------------------------------------------------------------------------
def load_jsonl(path: Path) -> list:
    out = []
    if not path or not Path(path).exists():
        return out
    for raw in Path(path).read_text(errors="replace").splitlines():
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        try:
            out.append(json.loads(raw))
        except Exception:
            continue
    return out


def partition_cases(cases: list) -> dict:
    """Return {split: [original_case, ...]} for TRAIN/DEV/HELD_OUT/FRESH_TARGET.

    FIXED_REF is NOT partitioned here - it is derived from any case carrying a
    fixed ref (see build_fixed_ref_controls)."""
    parts = {"TRAIN": [], "DEV": [], "HELD_OUT": [], "FRESH_TARGET": []}
    for c in cases:
        sp = normalize_split(c.get("split"))
        if sp == "FIXED_REF":
            # an explicit FIXED_REF-labeled case is a negative control already;
            # route it through the fixed-ref handler, not a positive split.
            sp = "FRESH_TARGET" if False else None
            continue
        parts.setdefault(sp, []).append(c)
    # keep only canonical positive splits; anything exotic lands in TRAIN
    norm = {"TRAIN": [], "DEV": [], "HELD_OUT": [], "FRESH_TARGET": []}
    for sp, lst in parts.items():
        if sp in norm:
            norm[sp].extend(lst)
        else:
            norm["TRAIN"].extend(lst)
    return norm


def build_fixed_ref_controls(cases: list, extra_fixed: list) -> list:
    """Negative controls: every positive case that ALSO carries a fixed ref,
    plus any explicitly-supplied fixed-ref cases. Returns ORIGINAL case dicts
    (projection to fixed ref happens at run time)."""
    controls = []
    for c in cases:
        # an explicitly FIXED_REF-labeled case is itself a control
        if normalize_split(c.get("split")) == "FIXED_REF":
            controls.append(c)
        elif has_fixed_ref(c):
            controls.append(c)
    controls.extend(extra_fixed or [])
    return controls


# --------------------------------------------------------------------------
# Run the backtest subprocess for a batch of projected cases
# --------------------------------------------------------------------------
def _resolve_local_checkout(case, local_checkout_root):
    """If a per-case local checkout root is configured, point at
    <root>/<repo-flattened>. Honest miss otherwise (auditor-backtest will NA)."""
    if not local_checkout_root:
        return _first(case, "local_checkout") or None
    repo = _first(case, "repo", "repo_url")
    if not repo:
        return None
    flat = repo.replace("https://github.com/", "").replace(".git", "").replace("/", "__")
    cand = Path(local_checkout_root) / flat
    return str(cand) if cand.exists() else None


def run_backtest_batch(projected_cases, original_cases, *, corpus_detector_dirs,
                       local_checkout_root, ref_key, timeout=900):
    """Write a temp JSONL, invoke auditor-backtest.py --json, return the parsed
    records list. On any subprocess failure, synthesize NA records so the batch
    is honestly counted as NA (never silently dropped)."""
    if not projected_cases:
        return []
    import tempfile
    # auditor-backtest.py takes a single --local-checkout; when checkout roots
    # differ per case we cannot pass one flag for the batch, so we run per-case
    # if any case resolves a distinct checkout. Cheap + honest.
    records = []
    with tempfile.TemporaryDirectory(prefix="capmetric_") as td:
        # group by resolved local-checkout so we batch where possible
        groups = {}
        for proj, orig in zip(projected_cases, original_cases):
            lc = _resolve_local_checkout(orig, local_checkout_root)
            groups.setdefault(lc, []).append(proj)
        for lc, group in groups.items():
            cases_file = Path(td) / f"cases_{abs(hash(str(lc))) % 10_000_000}.jsonl"
            cases_file.write_text("\n".join(json.dumps(c) for c in group) + "\n")
            cmd = [sys.executable, str(BACKTEST_TOOL),
                   "--cases", str(cases_file), "--json"]
            for d in (corpus_detector_dirs or []):
                # auditor-backtest.py exposes --corpus-detector-dir per plan; if
                # the local copy predates that flag, we degrade gracefully below.
                cmd += ["--corpus-detector-dir", str(d)]
            if lc:
                cmd += ["--local-checkout", str(lc)]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=timeout, cwd=str(REPO_ROOT))
            except Exception as e:
                records.extend(_na_records(group, f"backtest-subprocess-error: {e}"))
                continue
            parsed = _parse_backtest_stdout(proc.stdout)
            if parsed is None and corpus_detector_dirs:
                # retry once without the flag in case this checkout's
                # auditor-backtest.py predates --corpus-detector-dir
                cmd2 = [c for c in cmd if c != "--corpus-detector-dir"]
                cmd2 = [c for c in cmd2 if c not in [str(d) for d in corpus_detector_dirs]]
                try:
                    proc = subprocess.run(cmd2, capture_output=True, text=True,
                                          timeout=timeout, cwd=str(REPO_ROOT))
                    parsed = _parse_backtest_stdout(proc.stdout)
                except Exception:
                    parsed = None
            if parsed is None:
                tail = (proc.stderr or proc.stdout or "").strip().splitlines()
                reason = tail[-1] if tail else "backtest-no-json-output"
                records.extend(_na_records(group, f"backtest-parse-error: {reason[:160]}"))
            else:
                records.extend(parsed)
    return records


def _parse_backtest_stdout(stdout: str):
    """auditor-backtest.py --json prints one JSON object with a 'cases' list.
    Return that list, or None if it could not be parsed."""
    s = (stdout or "").strip()
    if not s:
        return None
    # tolerate leading log noise: find the first '{'
    idx = s.find("{")
    if idx < 0:
        return None
    try:
        obj = json.loads(s[idx:])
    except Exception:
        return None
    cases = obj.get("cases")
    return cases if isinstance(cases, list) else None


def _na_records(projected_cases, reason):
    return [{
        "schema": "auditooor.auditor_backtest.v1",
        "id": c.get("id", "?"),
        "repo": c.get("repo", ""),
        "prefix_ref": c.get("prefix_ref", ""),
        "vuln_class": c.get("vuln_class", ""),
        "file_line": c.get("file_line", ""),
        "outcome": "NA",
        "caught_by": [],
        "fired_at_line": None,
        "layers": {},
        "missing_capability": "publisher-na",
        "reason": reason,
    } for c in projected_cases]


# --------------------------------------------------------------------------
# Metric computation
# --------------------------------------------------------------------------
def _counts(records):
    c = {"CAUGHT": 0, "PARTIAL": 0, "MISSED": 0, "NA": 0, "TOTAL": len(records)}
    for r in records:
        o = (r.get("outcome") or "NA").upper()
        if o not in c:
            o = "NA"
        c[o] = c.get(o, 0) + 1
    return c


def split_metrics(records) -> dict:
    c = _counts(records)
    caught, partial, missed, na, total = (c["CAUGHT"], c["PARTIAL"],
                                          c["MISSED"], c["NA"], c["TOTAL"])
    scorable = caught + partial + missed
    strict = (caught / scorable) if scorable else None
    file_r = ((caught + partial) / scorable) if scorable else None
    na_rate = (na / total) if total else None
    return {
        "total": total,
        "scorable": scorable,
        "caught": caught,
        "partial": partial,
        "missed": missed,
        "na": na,
        "na_rate": na_rate,
        "strict_line_recall": strict,
        "file_recall": file_r,
        "by_language": _by_key(records, "language"),
        "by_attack_class": _by_key(records, "vuln_class"),
    }


def _by_key(records, attr):
    """Per-language / per-attack-class strict recall sub-table."""
    buckets = {}
    for r in records:
        key = (r.get(attr) or r.get("vuln_class") or "unknown")
        key = str(key).strip().lower() or "unknown"
        b = buckets.setdefault(key, {"caught": 0, "partial": 0, "missed": 0, "na": 0})
        o = (r.get("outcome") or "NA").upper()
        if o == "CAUGHT":
            b["caught"] += 1
        elif o == "PARTIAL":
            b["partial"] += 1
        elif o == "MISSED":
            b["missed"] += 1
        else:
            b["na"] += 1
    out = {}
    for k, b in sorted(buckets.items()):
        scorable = b["caught"] + b["partial"] + b["missed"]
        out[k] = {
            **b,
            "scorable": scorable,
            "strict_line_recall": (b["caught"] / scorable) if scorable else None,
        }
    return out


def fixed_ref_metrics(records) -> dict:
    """Negative-control metrics. On a FIXED (post-fix) ref a detector firing
    (CAUGHT or PARTIAL) is a FALSE POSITIVE. NA controls are excluded from the
    FP denominator (we could not fetch the fixed source, so we cannot judge)."""
    c = _counts(records)
    fp = c["CAUGHT"] + c["PARTIAL"]
    clean = c["MISSED"]                       # silent on fixed source = correct
    judged = fp + clean                       # scorable controls
    fp_rate = (fp / judged) if judged else None
    return {
        "total": c["TOTAL"],
        "judged": judged,
        "false_positives": fp,
        "clean": clean,
        "na": c["NA"],
        "fixed_ref_fp_rate": fp_rate,
    }


# --------------------------------------------------------------------------
# Fresh-target slot (honest: summarize-or-not-run, NEVER fabricate)
# --------------------------------------------------------------------------
def fresh_target_slot(fresh_dir: Path, partition_count: int) -> dict:
    """Summarize the most recent fresh-target forward-test result if one exists,
    else report an honest 'not-run' slot. A fresh-target run is the job of
    tools/fresh-target-forward-test.py; this publisher only surfaces it."""
    slot = {
        "status": "not-run",
        "note": ("no fresh-target forward test found; run "
                 "tools/fresh-target-forward-test.py to populate "
                 "reports/fresh_target_forward_tests/. This is NOT a success "
                 "and NOT a failure - the forward test simply has not run."),
        "result_path": None,
        "proof_backed_lead_yield": None,
        "split_cases_seen": partition_count,
    }
    if not fresh_dir or not Path(fresh_dir).exists():
        return slot
    # newest dated subdir or json
    candidates = []
    for p in Path(fresh_dir).rglob("*.json"):
        candidates.append(p)
    if not candidates:
        return slot
    newest = max(candidates, key=lambda p: p.stat().st_mtime)
    try:
        data = json.loads(newest.read_text(errors="replace"))
    except Exception:
        data = {}
    yield_n = data.get("proof_backed_lead_yield")
    if yield_n is None:
        yield_n = data.get("proven_leads")
    slot.update({
        "status": "summarized",
        "note": "summarized from the most recent fresh-target forward-test output",
        "result_path": str(newest.relative_to(REPO_ROOT)) if str(newest).startswith(str(REPO_ROOT)) else str(newest),
        "proof_backed_lead_yield": yield_n,
    })
    return slot


# --------------------------------------------------------------------------
# Report assembly + gate
# --------------------------------------------------------------------------
def assemble_report(split_recs, fixed_recs, fresh_slot, *, thresholds):
    splits = {sp: split_metrics(split_recs.get(sp, [])) for sp in
              ("TRAIN", "DEV", "HELD_OUT", "FRESH_TARGET")}
    fixed = fixed_ref_metrics(fixed_recs)

    held = splits["HELD_OUT"]
    headline = held.get("strict_line_recall")
    headline_scorable = held.get("scorable", 0)

    # ---- honest gate evaluation ----
    gates = []
    na_max = thresholds["na_rate_max"]
    fp_max = thresholds["fixed_ref_fp_max"]
    min_held = thresholds["min_heldout_scorable"]

    # NA-rate gate: evaluated over ALL positive splits combined
    all_pos = []
    for sp in ("TRAIN", "DEV", "HELD_OUT", "FRESH_TARGET"):
        all_pos.extend(split_recs.get(sp, []))
    overall_c = _counts(all_pos)
    overall_na_rate = (overall_c["NA"] / overall_c["TOTAL"]) if overall_c["TOTAL"] else None
    gates.append(_gate("na_rate", overall_na_rate, na_max, "<=", overall_c["TOTAL"]))

    # fixed-ref FP gate
    gates.append(_gate("fixed_ref_fp_rate", fixed.get("fixed_ref_fp_rate"),
                       fp_max, "<=", fixed.get("judged", 0)))

    # held-out scorable-count gate (a capability claim needs cases to back it)
    gates.append(_gate("heldout_scorable", headline_scorable, min_held, ">=",
                       headline_scorable))

    breached = [g for g in gates if g["status"] == "BREACH"]

    report = {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "headline": {
            "metric": "HELD_OUT strict_line_recall",
            "value": headline,
            "value_pct": (round(headline * 100, 1) if headline is not None else None),
            "scorable_cases": headline_scorable,
            "note": ("held-out recall is THE finding-power number; TRAIN recall "
                     "is circular and is never the headline."),
            "honest_status": (
                "no-held-out-corpus" if headline_scorable == 0 else "measured"),
        },
        "splits": splits,
        "fixed_ref": fixed,
        "fresh_target": fresh_slot,
        "thresholds": thresholds,
        "gates": gates,
        "gate_status": "BREACH" if breached else "PASS",
        "gate_breaches": [g["name"] for g in breached],
    }
    return report


def _gate(name, value, threshold, op, denom):
    """Honest gate: if value is None (no scorable cases) the gate is N/A, not a
    pass and not a breach. A capability tool must never call '0 cases' a pass."""
    if value is None or denom == 0:
        status = "NA"
    elif op == "<=":
        status = "PASS" if value <= threshold else "BREACH"
    elif op == ">=":
        status = "PASS" if value >= threshold else "BREACH"
    else:
        status = "NA"
    return {"name": name, "value": value, "threshold": threshold, "op": op,
            "denom": denom, "status": status}


# --------------------------------------------------------------------------
# Markdown render
# --------------------------------------------------------------------------
def _pct(v):
    return f"{v*100:.1f}%" if isinstance(v, (int, float)) else "n/a"


def render_markdown(report) -> str:
    L = []
    L.append("# Auditor Capability Metrics")
    L.append("")
    L.append(f"_Generated {report['generated_at']} - schema `{report['schema']}`_")
    L.append("")
    hl = report["headline"]
    L.append("## Headline: held-out finding power")
    L.append("")
    L.append(f"- **HELD_OUT strict line recall: {_pct(hl['value'])}** "
             f"({hl['scorable_cases']} scorable cases)")
    L.append(f"- Status: `{hl['honest_status']}`")
    L.append(f"- {hl['note']}")
    L.append("")
    L.append("## Splits")
    L.append("")
    L.append("| split | scorable | CAUGHT | PARTIAL | MISSED | NA | strict line recall | file recall |")
    L.append("|---|---:|---:|---:|---:|---:|---:|---:|")
    for sp in ("TRAIN", "DEV", "HELD_OUT", "FRESH_TARGET"):
        m = report["splits"][sp]
        tag = " (circular - not finding power)" if sp == "TRAIN" else ""
        L.append(f"| {sp}{tag} | {m['scorable']} | {m['caught']} | {m['partial']} "
                 f"| {m['missed']} | {m['na']} | {_pct(m['strict_line_recall'])} "
                 f"| {_pct(m['file_recall'])} |")
    L.append("")
    fx = report["fixed_ref"]
    L.append("## Fixed-ref negative controls")
    L.append("")
    L.append(f"- judged controls: {fx['judged']}  (clean={fx['clean']}, "
             f"false_positives={fx['false_positives']}, na={fx['na']})")
    L.append(f"- **fixed-ref false-positive rate: {_pct(fx['fixed_ref_fp_rate'])}**")
    L.append(f"  - a detector firing on the POST-FIX source is a false positive "
             f"(the bug is gone there)")
    L.append("")
    ft = report["fresh_target"]
    L.append("## Fresh-target forward test")
    L.append("")
    L.append(f"- status: `{ft['status']}`")
    L.append(f"- {ft['note']}")
    if ft.get("result_path"):
        L.append(f"- result: `{ft['result_path']}`  "
                 f"(proof-backed lead yield: {ft.get('proof_backed_lead_yield')})")
    L.append("")
    L.append("## Gates")
    L.append("")
    L.append("| gate | value | op | threshold | denom | status |")
    L.append("|---|---|---|---|---:|---|")
    for g in report["gates"]:
        val = _pct(g["value"]) if g["name"] in ("na_rate", "fixed_ref_fp_rate") else g["value"]
        thr = _pct(g["threshold"]) if g["name"] in ("na_rate", "fixed_ref_fp_rate") else g["threshold"]
        L.append(f"| {g['name']} | {val} | {g['op']} | {thr} | {g['denom']} | `{g['status']}` |")
    L.append("")
    L.append(f"**overall gate status: `{report['gate_status']}`**")
    if report["gate_breaches"]:
        L.append("")
        L.append(f"breached: {', '.join(report['gate_breaches'])}")
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", help="positive-split case corpus JSONL "
                    "(each line carries a `split` key)")
    ap.add_argument("--fixed-ref-cases", dest="fixed_ref_cases",
                    help="extra explicit fixed-ref negative-control cases JSONL")
    ap.add_argument("--corpus-detector-dir", dest="corpus_detector_dirs",
                    action="append", default=[],
                    help="newly-generated class-detector dir (repeatable); "
                         "passed through to auditor-backtest.py for anti-overfit")
    ap.add_argument("--local-checkout-root", dest="local_checkout_root",
                    help="root holding <repo-flattened> pre-fetched trees "
                         "(offline). Per-case checkout resolved as "
                         "<root>/<owner__name>")
    ap.add_argument("--out-dir", dest="out_dir", default=str(DEFAULT_OUT_DIR))
    ap.add_argument("--fresh-target-dir", dest="fresh_target_dir",
                    default=str(DEFAULT_FRESH_TARGET_DIR))
    ap.add_argument("--na-rate-max", dest="na_rate_max", type=float, default=0.5)
    ap.add_argument("--fixed-ref-fp-max", dest="fixed_ref_fp_max", type=float,
                    default=0.10)
    ap.add_argument("--min-heldout-scorable", dest="min_heldout_scorable",
                    type=int, default=0)
    ap.add_argument("--strict-ci", dest="strict_ci", action="store_true",
                    help="exit non-zero on any gate BREACH (for CI)")
    ap.add_argument("--timeout", type=int, default=900,
                    help="per-batch backtest subprocess timeout seconds")
    ap.add_argument("--json", action="store_true",
                    help="also echo the JSON report to stdout")
    args = ap.parse_args(argv)

    thresholds = {
        "na_rate_max": args.na_rate_max,
        "fixed_ref_fp_max": args.fixed_ref_fp_max,
        "min_heldout_scorable": args.min_heldout_scorable,
    }

    cases = load_jsonl(Path(args.cases)) if args.cases else []
    extra_fixed = load_jsonl(Path(args.fixed_ref_cases)) if args.fixed_ref_cases else []

    parts = partition_cases(cases)
    fixed_controls = build_fixed_ref_controls(cases, extra_fixed)

    # ---- run each positive split through the backtest ----
    split_recs = {}
    for sp in ("TRAIN", "DEV", "HELD_OUT", "FRESH_TARGET"):
        orig = parts.get(sp, [])
        proj = [to_backtest_case(c, ref_key="prefix") for c in orig]
        split_recs[sp] = run_backtest_batch(
            proj, orig,
            corpus_detector_dirs=args.corpus_detector_dirs,
            local_checkout_root=args.local_checkout_root,
            ref_key="prefix", timeout=args.timeout)

    # ---- run fixed-ref negative controls (project onto the FIXED ref) ----
    fixed_proj = [to_backtest_case(c, ref_key="fixed") for c in fixed_controls]
    fixed_recs = run_backtest_batch(
        fixed_proj, fixed_controls,
        corpus_detector_dirs=args.corpus_detector_dirs,
        local_checkout_root=args.local_checkout_root,
        ref_key="fixed", timeout=args.timeout)

    fresh_slot = fresh_target_slot(Path(args.fresh_target_dir),
                                   len(parts.get("FRESH_TARGET", [])))

    report = assemble_report(split_recs, fixed_recs, fresh_slot,
                             thresholds=thresholds)

    # ---- publish ----
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "latest.json").write_text(json.dumps(report, indent=2) + "\n")
    (out_dir / "latest.md").write_text(render_markdown(report))

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(render_markdown(report))
        rel = out_dir
        try:
            rel = out_dir.relative_to(REPO_ROOT)
        except Exception:
            pass
        print(f"\n[capability-metric-publisher] wrote {rel}/latest.json "
              f"and {rel}/latest.md")

    if args.strict_ci and report["gate_status"] == "BREACH":
        print(f"\n[capability-metric-publisher] STRICT-CI gate BREACH: "
              f"{', '.join(report['gate_breaches'])}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
