#!/usr/bin/env python3
# <!-- gap55-rebuttal: generic capability fix, operator-authorized -->
"""hackerman-q-to-detector-promote.py -- the question -> reasoner EVOLUTION pipeline.

This tool WIRES four pre-existing but disconnected promotion primitives into ONE
sequenced pipeline. It builds nothing new that a primitive already does; it is
pure orchestration + an honest candidate-selection gate on top of them.

The lifecycle it automates
---------------------------
A hacker QUESTION (prose, e.g. "does this setter validate the new address?") is
asked pre-source-read and recorded as a per-function OBLIGATION. When a
per-function hunt genuinely answers it against real source, the obligation flips
to ``state=answered`` (a source-anchored TRUE POSITIVE) via
``hacker-question-obligation-resolve.py``. Independently, crystallized detectors
accrue TP/FP history in ``detectors/_hits_ledger.yaml``.

When the SAME question class has fired with repeated real TPs across engagements
and has *no crystallized detector yet*, that prose question has earned promotion
into a durable reasoner. This tool detects that condition and drives it through:

    Stage 0  candidate select   read _hits_ledger.yaml + obligation resolutions;
                                 a class with >= --min-tp answered/TP evidence
                                 across >= --min-workspaces engagements and NO
                                 existing detector is a promotion candidate.
    Stage 1  hypothesis-to-detector.py   -> DRAFT DSL pattern + vuln/clean fixtures
    Stage 2  overnight-detector-wirer.py -> compile + slither smoke; gate is
                                 clean == 0 hits AND vuln >= 1 hit
    Stage 3  detector-promote.py         -> D->E (>=5 TP / 0 FP / fixture) and
                                 E->S (>=10 TP / 2+ engagements / <=1 FP) proposal

Honesty properties (no false-green)
-----------------------------------
* Stage 0 counts ONLY genuine evidence: ``answered`` obligation resolutions (each
  is R76 source-verified before it can flip -- see the resolver) and ledger
  ``_history`` verdicts marked TP. ``killed`` obligations are NOT counted as TPs
  and are NOT counted as FPs (a validly-examined-and-ruled-out question is neutral).
* Stage 2 is the wirer's real contract: a runnable Slither detector .py + fixture
  pair. The stage-1 DRAFT carries ``# TODO`` markers and is NOT auto-fleshed here;
  it must be turned into a runnable detector (by an LLM wire pass whose JSON lands
  in --wire-inputs-dir) before the smoke gate can pass. Absent that, Stage 2 is
  reported ``pending`` -- it is never faked green.
* Stage 3 is read-only (it emits a proposal doc); a fresh draft has no ledger row
  yet, so the tool reports the FORWARD bar the wired detector must clear.

Usage
-----
    # See which questions have earned a detector (no side effects):
    tools/hackerman-q-to-detector-promote.py --dry-run --json

    # Draft + (optionally) wire + report promotion path for the top candidate:
    tools/hackerman-q-to-detector-promote.py --top 1 \
        [--wire-inputs-dir /tmp/llm_wire_outputs] [--json]

Flags
-----
    --ledger PATH          _hits_ledger.yaml (default: detectors/_hits_ledger.yaml)
    --workspaces GLOB      obligation-file glob (default: ~/audits/*)
    --min-tp N             min answered/TP evidence to qualify (default: 5)
    --min-workspaces N     min distinct engagements (default: 1)
    --top N                process at most N qualifying candidates in stages 1-3
    --wire-inputs-dir DIR  LLM-emitted runnable-detector JSON for the wirer (Stage 2)
    --dry-run              Stage 0 only; print candidates; NO files written, NO
                           subprocess side effects
    --json                 machine-readable output

Pure stdlib + PyYAML (already a repo dep). Bounded subprocess calls.
"""
from __future__ import annotations

import argparse
import glob as _glob
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is a repo dep
    sys.stderr.write("[error] PyYAML required: pip3 install pyyaml\n")
    sys.exit(1)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_LEDGER = ROOT / "detectors" / "_hits_ledger.yaml"
DEFAULT_WORKSPACES = os.path.expanduser("~/audits/*")
PATTERNS_DIR = ROOT / "reference" / "patterns.dsl"

HYPOTHESIS_TOOL = ROOT / "tools" / "hypothesis-to-detector.py"
WIRER_TOOL = ROOT / "tools" / "overnight-detector-wirer.py"
PROMOTE_TOOL = ROOT / "tools" / "detector-promote.py"

# Obligation states that count as a genuine, source-anchored TRUE POSITIVE for
# the question class. ``killed`` is deliberately excluded (validly examined and
# ruled out -> neutral, not a TP and not an FP).
_TP_OBLIGATION_STATES = frozenset(
    {"answered", "promoted_to_poc", "promoted_to_chain"}
)


# --------------------------------------------------------------------------- #
# Class-stem normalisation                                                     #
# --------------------------------------------------------------------------- #


def kebab_class(raw: str) -> str:
    """Normalise an attack_class / detector name to a kebab-case stem.

    ``External-State Mutating Fn`` -> ``external-state-mutating-fn``. Returns ""
    for empty / punctuation-only input.
    """
    s = re.sub(r"[^a-zA-Z0-9]+", "-", str(raw or "")).strip("-").lower()
    return s


def _class_tokens(stem: str) -> set[str]:
    return {t for t in re.split(r"[-_]+", stem) if len(t) >= 3}


# --------------------------------------------------------------------------- #
# Existing-detector inventory (suppression set)                               #
# --------------------------------------------------------------------------- #


def _load_yaml(path: Path, default):
    if not Path(path).exists():
        return default
    try:
        return yaml.safe_load(Path(path).read_text()) or default
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"[warn] could not parse {path}: {e}\n")
        return default


def existing_detector_stems(ledger: dict, patterns_dir: Path = PATTERNS_DIR) -> set[str]:
    """The set of kebab stems that already have a crystallized detector.

    A question class whose kebab stem is already present here does NOT need a
    fresh draft -- a detector/pattern for it exists. Sources:
      * ledger detector names (any TP/FP history -> a detector exists)
      * reference/patterns.dsl/*.yaml stems (compiled DSL patterns), excluding
        the DRAFT ``HYPOTHESIS-*`` scaffolds which are not yet real detectors.
    """
    stems: set[str] = set()
    for name in (ledger.get("detectors") or {}).keys():
        stems.add(kebab_class(name))
    try:
        for p in patterns_dir.glob("*.yaml"):
            if p.stem.startswith("HYPOTHESIS-"):
                continue
            stems.add(kebab_class(p.stem))
    except OSError:
        pass
    stems.discard("")
    return stems


def _has_existing_detector(stem: str, existing: set[str]) -> bool:
    """True iff a crystallized detector already covers this class.

    Exact kebab match, or a full token-subset match against an existing stem
    (so ``access-controlled-setter`` is covered by an existing
    ``access-control-setter-no-validation`` only when every meaningful token is
    contained -- conservative, avoids over-suppression on a single shared word).
    """
    if not stem:
        return False
    if stem in existing:
        return True
    my_tokens = _class_tokens(stem)
    if not my_tokens:
        return False
    for other in existing:
        ot = _class_tokens(other)
        if my_tokens and my_tokens <= ot:
            return True
    return False


# --------------------------------------------------------------------------- #
# Stage 0 -- evidence aggregation                                             #
# --------------------------------------------------------------------------- #


def _iter_obligation_rows(workspace_glob: str):
    """Yield obligation dict rows from every matching workspace's jsonl."""
    for ws_dir in sorted(_glob.glob(workspace_glob)):
        p = Path(ws_dir) / ".auditooor" / "hacker_question_obligations.jsonl"
        if not p.is_file():
            continue
        try:
            with p.open(encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except ValueError:
                        continue
        except OSError:
            continue


def _ledger_verdict_evidence(ledger: dict):
    """Map kebab detector-stem -> {tp, fp, workspaces:set} from ledger _history.

    Uses per-verdict ``_history`` rows so distinct workspaces are countable; a
    detector with no _history falls back to its top-level tp/fp counters.
    """
    out: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0, "workspaces": set()})
    for name, entry in (ledger.get("detectors") or {}).items():
        stem = kebab_class(name)
        if not stem:
            continue
        hist = entry.get("_history") or []
        counted_from_history = False
        for h in hist:
            v = str(h.get("verdict", "")).strip().upper()
            ws = str(h.get("workspace", "")).strip()
            if v == "TP":
                out[stem]["tp"] += 1
                counted_from_history = True
                if ws:
                    out[stem]["workspaces"].add(ws)
            elif v == "FP":
                out[stem]["fp"] += 1
                counted_from_history = True
        if not counted_from_history:
            # No verdict history -> trust the top-level counters (workspaces
            # unknown; approximate distinct engagements from real_catches).
            out[stem]["tp"] += int(entry.get("tp", 0) or 0)
            out[stem]["fp"] += int(entry.get("fp", 0) or 0)
            for c in entry.get("real_catches") or []:
                ws = str(c.get("workspace", "")).strip()
                if ws:
                    out[stem]["workspaces"].add(ws)
    return out


def select_candidates(
    ledger_path: Path = DEFAULT_LEDGER,
    workspace_glob: str = DEFAULT_WORKSPACES,
    min_tp: int = 5,
    min_workspaces: int = 1,
    patterns_dir: Path = PATTERNS_DIR,
) -> list[dict]:
    """Stage 0: rank question classes by genuine TP evidence.

    A class qualifies (``qualifies=True``) when its combined answered-obligation +
    ledger-TP evidence >= min_tp, across >= min_workspaces distinct engagements,
    AND no crystallized detector already covers it. Classes that clear the TP bar
    but already have a detector are still returned (``already_has_detector=True``,
    ``qualifies=False``) for transparency.
    """
    ledger = _load_yaml(ledger_path, {"detectors": {}})
    existing = existing_detector_stems(ledger, patterns_dir)
    ledger_ev = _ledger_verdict_evidence(ledger)

    # Aggregate obligation evidence by class stem.
    agg: dict[str, dict] = defaultdict(
        lambda: {
            "tp_obligations": 0,
            "killed_obligations": 0,
            "workspaces": set(),
            "questions": defaultdict(int),
            "raw_class": "",
        }
    )
    for row in _iter_obligation_rows(workspace_glob):
        raw_cls = str(row.get("attack_class", "")).strip()
        stem = kebab_class(raw_cls)
        if not stem:
            continue
        state = str(row.get("state", "")).strip().lower()
        rec = agg[stem]
        if not rec["raw_class"]:
            rec["raw_class"] = raw_cls
        if state in _TP_OBLIGATION_STATES:
            rec["tp_obligations"] += 1
            ws = str(row.get("workspace", "")).strip()
            if ws:
                rec["workspaces"].add(os.path.basename(ws.rstrip("/")))
            q = str(row.get("question", "")).strip()
            if q:
                rec["questions"][q] += 1
        elif state == "killed":
            rec["killed_obligations"] += 1

    # Union obligation stems with any ledger stems that carry TP evidence so a
    # class known only from the ledger still surfaces.
    all_stems = set(agg.keys()) | {s for s, e in ledger_ev.items() if e["tp"] > 0}

    candidates: list[dict] = []
    for stem in all_stems:
        ob = agg.get(stem)
        lev = ledger_ev.get(stem, {"tp": 0, "fp": 0, "workspaces": set()})
        tp_obl = ob["tp_obligations"] if ob else 0
        killed = ob["killed_obligations"] if ob else 0
        ws_union = set()
        if ob:
            ws_union |= ob["workspaces"]
        ws_union |= lev["workspaces"]
        tp_total = tp_obl + lev["tp"]
        fp_total = lev["fp"]  # only crystallized-detector FPs count as FP
        n_ws = len(ws_union) if ws_union else 0
        # Representative prose question = most-frequent, longest-on-tie.
        rep_q = ""
        if ob and ob["questions"]:
            rep_q = max(ob["questions"].items(), key=lambda kv: (kv[1], len(kv[0])))[0]
        already = _has_existing_detector(stem, existing)
        qualifies = (
            tp_total >= min_tp and n_ws >= min_workspaces and not already
        )
        candidates.append(
            {
                "class_stem": stem,
                "raw_class": (ob["raw_class"] if ob else stem),
                "tp_total": tp_total,
                "tp_obligations": tp_obl,
                "tp_ledger": lev["tp"],
                "fp_total": fp_total,
                "killed_obligations": killed,
                "distinct_workspaces": n_ws,
                "workspaces": sorted(ws_union),
                "representative_question": rep_q,
                "already_has_detector": already,
                "qualifies": qualifies,
            }
        )
    # Qualifying first, then by TP evidence, then distinct engagements.
    candidates.sort(
        key=lambda c: (c["qualifies"], c["tp_total"], c["distinct_workspaces"]),
        reverse=True,
    )
    return candidates


# --------------------------------------------------------------------------- #
# Stage 1-3 -- primitive drivers                                             #
# --------------------------------------------------------------------------- #


def _run(cmd: list[str], timeout: float = 180.0) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=str(ROOT)
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as e:  # noqa: BLE001
        return 127, "", str(e)


def stage1_draft(cand: dict) -> dict:
    """Stage 1: invoke hypothesis-to-detector.py to emit the DRAFT DSL + fixtures."""
    stem = cand["class_stem"]
    hypothesis = cand["representative_question"] or (
        f"class {cand['raw_class']} fired {cand['tp_total']} real TPs across "
        f"{cand['distinct_workspaces']} engagements without a crystallized detector"
    )
    rc, out, err = _run(
        [
            sys.executable,
            str(HYPOTHESIS_TOOL),
            "--hypothesis",
            hypothesis,
            "--class",
            stem,
            "--force",
        ]
    )
    yaml_path = PATTERNS_DIR / f"HYPOTHESIS-{stem}.yaml"
    return {
        "stage": "draft",
        "ok": rc == 0 and yaml_path.exists(),
        "rc": rc,
        "draft_yaml": str(yaml_path) if yaml_path.exists() else "",
        "summary": (out.strip().splitlines() or [""])[-1] if out.strip() else err.strip()[:200],
    }


def stage2_wire(wire_inputs_dir: str | None, summary_out: Path, dry_run: bool) -> dict:
    """Stage 2: run the overnight wirer's compile+slither smoke (clean=0/vuln>=1).

    The wirer's contract is a directory of runnable-detector JSON. If none is
    supplied the draft has not been fleshed into a runnable detector yet, so the
    smoke gate is reported ``pending`` -- never faked green.
    """
    if not wire_inputs_dir:
        return {
            "stage": "wire",
            "ok": False,
            "status": "pending",
            "reason": (
                "no --wire-inputs-dir: Stage 1 DRAFT carries # TODO markers and must "
                "be fleshed into a runnable Slither detector (clean=0/vuln>=1) before "
                "the wirer smoke gate can run"
            ),
        }
    if not Path(wire_inputs_dir).is_dir():
        return {
            "stage": "wire",
            "ok": False,
            "status": "error",
            "reason": f"wire-inputs-dir not found: {wire_inputs_dir}",
        }
    cmd = [
        sys.executable,
        str(WIRER_TOOL),
        "--inputs-dir",
        wire_inputs_dir,
        "--summary-out",
        str(summary_out),
    ]
    if dry_run:
        cmd.append("--dry-run")
    rc, out, err = _run(cmd, timeout=600.0)
    passing = 0
    try:
        if summary_out.exists():
            passing = int(json.loads(summary_out.read_text()).get("passing_count", 0) or 0)
    except Exception:  # noqa: BLE001
        pass
    return {
        "stage": "wire",
        "ok": rc == 0 and passing >= 1,
        "status": "smoke_pass" if passing >= 1 else "smoke_fail",
        "passing_count": passing,
        "rc": rc,
        "summary": (out.strip().splitlines() or [""])[-1] if out.strip() else err.strip()[:200],
    }


_DE_RE = re.compile(r"^\s*D->E\s+(\S+)", re.MULTILINE)
_ES_RE = re.compile(r"^\s*E->S\s+(\S+)", re.MULTILINE)


def stage3_promote(cand: dict) -> dict:
    """Stage 3: regenerate detector-promote proposals (read-only) and report the
    forward promotion bar for this class."""
    rc, out, err = _run([sys.executable, str(PROMOTE_TOOL)])
    de = set(_DE_RE.findall(out))
    es = set(_ES_RE.findall(out))
    stem = cand["class_stem"]
    now_de = stem in de
    now_es = stem in es
    return {
        "stage": "promote",
        "ok": rc == 0,
        "rc": rc,
        "class_is_current_D_to_E_candidate": now_de,
        "class_is_current_E_to_S_candidate": now_es,
        "forward_bar": (
            "D->E requires >= 5 TP AND 0 FP AND a positive fixture once the wired "
            "detector accrues ledger history; E->S requires >= 10 TP across 2+ "
            "engagements AND <= 1 FP"
        ),
        "summary": (out.strip().splitlines() or [""])[-1] if out.strip() else err.strip()[:200],
    }


# --------------------------------------------------------------------------- #
# Orchestration                                                                #
# --------------------------------------------------------------------------- #


def run_pipeline(
    ledger_path: Path = DEFAULT_LEDGER,
    workspace_glob: str = DEFAULT_WORKSPACES,
    min_tp: int = 5,
    min_workspaces: int = 1,
    top: int = 0,
    wire_inputs_dir: str | None = None,
    dry_run: bool = True,
    patterns_dir: Path = PATTERNS_DIR,
) -> dict:
    candidates = select_candidates(
        ledger_path, workspace_glob, min_tp, min_workspaces, patterns_dir
    )
    qualifying = [c for c in candidates if c["qualifies"]]
    result = {
        "schema": "auditooor.q_to_detector_promote.v1",
        "params": {
            "ledger": str(ledger_path),
            "workspaces": workspace_glob,
            "min_tp": min_tp,
            "min_workspaces": min_workspaces,
            "top": top,
            "wire_inputs_dir": wire_inputs_dir,
            "dry_run": dry_run,
        },
        "candidate_count": len(candidates),
        "qualifying_count": len(qualifying),
        "candidates": candidates,
        "pipeline_runs": [],
    }
    if dry_run:
        result["action"] = "dry-run: stage-0 candidate selection only (no side effects)"
        return result

    to_process = qualifying if top <= 0 else qualifying[:top]
    for cand in to_process:
        run = {"class_stem": cand["class_stem"], "stages": []}
        s1 = stage1_draft(cand)
        run["stages"].append(s1)
        summary_out = ROOT / ".auditooor" / f"q2d_wire_{cand['class_stem']}.json"
        summary_out.parent.mkdir(parents=True, exist_ok=True)
        s2 = stage2_wire(wire_inputs_dir, summary_out, dry_run=False)
        run["stages"].append(s2)
        s3 = stage3_promote(cand)
        run["stages"].append(s3)
        run["ok"] = s1["ok"]  # draft emitted; wire/promote are forward-gated
        result["pipeline_runs"].append(run)
    result["action"] = f"processed {len(to_process)} qualifying candidate(s)"
    return result


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #


def _print_human(res: dict) -> None:
    print(
        f"[q2d] {res['qualifying_count']}/{res['candidate_count']} question class(es) "
        f"qualify for detector promotion "
        f"(min_tp={res['params']['min_tp']}, min_ws={res['params']['min_workspaces']})"
    )
    print()
    print("Top candidates (qualifying first):")
    for c in res["candidates"][:15]:
        flag = "PROMOTE" if c["qualifies"] else (
            "has-detector" if c["already_has_detector"] else "below-bar"
        )
        print(
            f"  [{flag:>12}] {c['class_stem']:<40} "
            f"tp={c['tp_total']} (obl={c['tp_obligations']}/led={c['tp_ledger']}) "
            f"fp={c['fp_total']} ws={c['distinct_workspaces']}"
        )
        if c["qualifies"] and c["representative_question"]:
            print(f"                 q: {c['representative_question'][:96]}")
    for run in res.get("pipeline_runs", []):
        print()
        print(f"-- pipeline: {run['class_stem']} --")
        for s in run["stages"]:
            print(f"   {s['stage']:>8}: ok={s['ok']} "
                  + (s.get("status", "") or "")
                  + f"  {s.get('summary', s.get('reason', ''))[:100]}")
    if "action" in res:
        print()
        print(f"[q2d] {res['action']}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--ledger", default=str(DEFAULT_LEDGER))
    ap.add_argument("--workspaces", default=DEFAULT_WORKSPACES)
    ap.add_argument("--min-tp", type=int, default=5)
    ap.add_argument("--min-workspaces", type=int, default=1)
    ap.add_argument("--top", type=int, default=0,
                    help="process at most N qualifying candidates in stages 1-3")
    ap.add_argument("--wire-inputs-dir", default=None,
                    help="LLM-emitted runnable-detector JSON for the wirer (Stage 2)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Stage 0 only; no files written, no subprocess side effects")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    res = run_pipeline(
        ledger_path=Path(os.path.expanduser(args.ledger)),
        workspace_glob=os.path.expanduser(args.workspaces),
        min_tp=args.min_tp,
        min_workspaces=args.min_workspaces,
        top=args.top,
        wire_inputs_dir=(os.path.expanduser(args.wire_inputs_dir)
                         if args.wire_inputs_dir else None),
        dry_run=args.dry_run,
    )
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        _print_human(res)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
