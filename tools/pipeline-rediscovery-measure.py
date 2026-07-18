#!/usr/bin/env python3
"""pipeline-rediscovery-measure.py - HONEST full-pipeline finding-power measure.

WHAT THIS IS (and is NOT)
-------------------------
`tools/auditor-backtest.py` measures STATIC-DETECTOR recall: does a regex/DSL
detector FIRE on a known bug's source line? That is a narrow proxy. A regex
firing on a line near a bug is not the same as the audit pipeline's HYPOTHESIS
layer SURFACING the bug as something worth proving.

RELATED TOOLS:
  - tools/auditor-backtest.py       : static-detector regex recall (proxy).
                                      DO NOT confuse with this. That answers
                                      "does a pattern fire on the line?". This
                                      answers "does the hypothesis layer derive
                                      an invariant / generate a hypothesis that
                                      POINTS AT the known bug's function/file?".
  - tools/novel-vector-invariant-miner.py : the per-function invariant miner
                                      (HYPOTHESIS source #1) this tool drives.
  - tools/corpus-driven-hunt.py     : the corpus-driven live-hypothesis hunt
                                      (HYPOTHESIS source #2) this tool drives.
  - tools/detector-catch-rate-backtest.py (audit/) : another static-catch-rate
                                      tool; same proxy family as auditor-backtest.

THE GAP THIS TOOL FILLS: a forward-test of the REAL hypothesis-generation
layer (novel-vector miner UNION corpus-driven-hunt) against each recorded
on-chain-confirmed bug, scoring REDISCOVERY = "did the pipeline surface a
hypothesis whose target function/file maps to the recorded vuln?". This is
the real finding-power signal, distinct from a static regex catch.

REDISCOVERY DEFINITION (per corpus case with recorded file:line L in file F):
  - file-level rediscovery  : any derived invariant / generated hypothesis cites
                              file F (basename match).
  - line-level rediscovery  : EITHER a hypothesis cites file F at a line within
                              +/-LINE_TOL (default 25) of L, OR a novel-vector
                              invariant targets a function whose source line-span
                              (resolved from F itself) contains L.
  surfacing_stage records which layer surfaced it:
    "novel-vector-fn-span" | "corpus-hunt-candidate-fn" |
    "corpus-hunt-evidence" | "none".

FORWARD-TEST / ANTI-OVERFIT GUARANTEES (operator demand #1):
  - This tool NEVER hands the miner/hunt the answer. It runs the real pipeline
    against the WHOLE target file (the miner derives invariants for every
    function; the hunt scans the source dir) and only AFTER asks "did any
    output land on the recorded function/file?".
  - HELD_OUT cases are graded but their *vuln_class* never informed any
    detector authoring (class-disjoint split). This tool reads held-out SOURCE
    only to (a) run the miner on it and (b) resolve a function line-span; it
    does NOT read the held-out source to author or tune any class pattern - it
    contains ZERO instance literals and ZERO class-specific tuning. The
    rediscovery logic is identical for every case regardless of class.
  - A fabricated, instance-memorized, or noise catch is FAILURE. A truthful low
    number is SUCCESS.

COST BOUND: per-function miner only (--max-per-fn small) + a single
corpus-driven-hunt scan per case. No full-engine fuzz, no MIMO unless the
caller passes --mimo-budget (default 0 = pure deterministic).

USAGE:
  python3 tools/pipeline-rediscovery-measure.py \
      --corpus reference/fetchable_vuln_corpus.jsonl \
      --split-mode class-disjoint \
      --out-dir reports/pipeline_rediscovery
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS = REPO_ROOT / "tools"

LINE_TOL_DEFAULT = 25

# ---------------------------------------------------------------------------
# Language-aware function -> line-span resolver.
# Mirrors the function-name regexes the novel-vector miner uses, but captures
# the START line so we can build a [start, end) span. Class-agnostic; no
# instance literals.
# ---------------------------------------------------------------------------

_SOL_FN_RE = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(")
_RS_FN_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]")
_GO_FN_RE = re.compile(r"\bfunc\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(")
_TS_FN_RE = re.compile(
    r"\b(?:function\s+([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*[:=]\s*(?:async\s*)?\()"
)


def _fn_regex_for(lang: str) -> re.Pattern | None:
    return {
        "solidity": _SOL_FN_RE,
        "rust": _RS_FN_RE,
        "go": _GO_FN_RE,
        "typescript": _TS_FN_RE,
    }.get(lang)


def function_spans(source_path: Path, lang: str) -> list[tuple[str, int, int]]:
    """Return [(fn_name, start_line, end_line)] (1-based, end exclusive-ish).

    A function's span runs from its declaration line to the line just before
    the next function declaration (or EOF). This is a bounded heuristic - it
    does not brace-match - but it is sufficient to answer "is L inside fn F?"
    for the rediscovery test and is identical for every case (no per-class
    tuning).
    """
    rx = _fn_regex_for(lang)
    if rx is None:
        return []
    try:
        lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    decls: list[tuple[str, int]] = []
    for i, ln in enumerate(lines, start=1):
        m = rx.search(ln)
        if not m:
            continue
        name = next((g for g in m.groups() if g), None)
        if not name:
            continue
        if lang == "rust" and name.startswith("test"):
            continue
        if lang == "go" and (not name[0].isupper() or name.startswith("Test")):
            # the miner only keeps exported Go fns; mirror that for span fidelity
            # but ALSO keep unexported so a line inside an unexported helper can
            # still be attributed to the *enclosing* exported fn span. We keep
            # all decls here and let span-containment decide.
            pass
        decls.append((name, i))
    spans: list[tuple[str, int, int]] = []
    for idx, (name, start) in enumerate(decls):
        end = decls[idx + 1][1] - 1 if idx + 1 < len(decls) else len(lines)
        spans.append((name, start, max(start, end)))
    return spans


def fn_span_containing(spans: list[tuple[str, int, int]], line: int) -> str | None:
    for name, start, end in spans:
        if start <= line <= end:
            return name
    return None


# ---------------------------------------------------------------------------
# Pipeline drivers (subprocess; bounded).
# ---------------------------------------------------------------------------

def run_novel_vector_miner(
    workspace: str, contract: Path, lang: str, max_per_fn: int, mimo_budget: int
) -> dict:
    cmd = [
        sys.executable,
        str(TOOLS / "novel-vector-invariant-miner.py"),
        "--workspace", workspace,
        "--contract", str(contract),
        "--lang", lang,
        "--max-per-fn", str(max_per_fn),
        "--json",
    ]
    if mimo_budget > 0:
        cmd += ["--mimo-refine", "--mimo-budget", str(mimo_budget)]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=240, cwd=str(REPO_ROOT)
        )
    except subprocess.TimeoutExpired:
        return {"_error": "timeout", "invariants": []}
    if out.returncode != 0:
        return {"_error": f"rc={out.returncode}: {out.stderr[-300:]}", "invariants": []}
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return {"_error": "json-decode", "invariants": []}


def run_corpus_hunt(workspace: str, source_root: Path, top: int, max_functions: int) -> dict:
    cmd = [
        sys.executable,
        str(TOOLS / "corpus-driven-hunt.py"),
        workspace,
        "--source", str(source_root),
        "--top", str(top),
        "--max-functions", str(max_functions),
        "--no-brain-prime-gate",
        "--no-hacker-questions",
        "--json",
    ]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300, cwd=str(REPO_ROOT)
        )
    except subprocess.TimeoutExpired:
        return {"_error": "timeout", "hypotheses": []}
    if out.returncode != 0:
        return {"_error": f"rc={out.returncode}: {out.stderr[-300:]}", "hypotheses": []}
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        return {"_error": "json-decode", "hypotheses": []}


# ---------------------------------------------------------------------------
# Rediscovery scoring.
# ---------------------------------------------------------------------------

def _basename(p: str) -> str:
    return os.path.basename(p.replace("\\", "/"))


def score_case(
    case: dict,
    nv_out: dict,
    hunt_out: dict,
    line_tol: int,
) -> dict:
    """Return the per-case rediscovery result dict."""
    file_rel, line_s = case["file_line"].rsplit(":", 1)
    target_line = int(line_s)
    target_base = _basename(file_rel)
    lang = case["language"]
    source_full = Path(case["local_checkout"]) / file_rel

    rediscovered_file = False
    rediscovered_line = False
    surfacing_stage = "none"
    evidence: list[dict] = []

    # ----- Layer 1: novel-vector miner (function-span containment) -----
    # The miner emits function NAMES targeted by derived invariants. We resolve
    # those names to line spans in the ACTUAL target file and ask whether the
    # recorded line falls inside any targeted function's span.
    spans = function_spans(source_full, lang)
    nv_target_fns = {
        inv.get("function")
        for inv in nv_out.get("invariants", [])
        if inv.get("function")
    }
    if nv_target_fns:
        # HONESTY NOTE: the miner is pointed at this exact file BY THIS HARNESS,
        # so "the miner produced specs for file F" is NOT a real file-selection
        # signal and is DELIBERATELY NOT credited as file-level rediscovery
        # (that would be handing the pipeline the answer). The miner contributes
        # ONLY line-level credit: it must have targeted the *specific function*
        # whose span contains the recorded bug line - a genuine within-file
        # selection. File-level credit comes exclusively from corpus-driven-hunt
        # (Layer 2), which scans a DIRECTORY and chooses which files to cite.
        enclosing = fn_span_containing(spans, target_line)
        for name, start, end in spans:
            if name in nv_target_fns and start <= target_line <= end:
                rediscovered_line = True
                surfacing_stage = "novel-vector-fn-span"
                evidence.append(
                    {
                        "stage": "novel-vector-fn-span",
                        "function": name,
                        "span": [start, end],
                        "target_line": target_line,
                    }
                )
                break
        # also count: recorded line is inside the enclosing fn AND the miner
        # targeted that enclosing fn (handles helper-line attribution).
        if not rediscovered_line and enclosing and enclosing in nv_target_fns:
            rediscovered_line = True
            surfacing_stage = "novel-vector-fn-span"
            evidence.append(
                {
                    "stage": "novel-vector-fn-span",
                    "function": enclosing,
                    "via": "enclosing-fn",
                    "target_line": target_line,
                }
            )

    # ----- Layer 2: corpus-driven-hunt (candidate_functions + evidence) -----
    def _cite_iter():
        for h in hunt_out.get("hypotheses", []):
            for cf in h.get("candidate_functions", []) or []:
                yield "corpus-hunt-candidate-fn", cf
            for ev in h.get("in_target_evidence", []) or []:
                yield "corpus-hunt-evidence", ev

    for stage, cite in _cite_iter():
        cfile = cite.get("file")
        cline = cite.get("line")
        if not cfile:
            continue
        if _basename(cfile) != target_base:
            continue
        # file-level hit from the hunt
        rediscovered_file = True
        if surfacing_stage == "none":
            surfacing_stage = stage
        if isinstance(cline, int) and abs(cline - target_line) <= line_tol:
            if not rediscovered_line:
                rediscovered_line = True
                surfacing_stage = stage
                evidence.append(
                    {
                        "stage": stage,
                        "file": _basename(cfile),
                        "cited_line": cline,
                        "target_line": target_line,
                        "delta": cline - target_line,
                    }
                )

    return {
        "case_id": case["case_id"],
        "class": case["vuln_class"],
        "language": lang,
        "split": case["split"],
        "file": file_rel,
        "target_line": target_line,
        "rediscovered_file": rediscovered_file,
        "rediscovered_line": rediscovered_line,
        "surfacing_stage": surfacing_stage,
        "nv_ran_on_file": bool(nv_target_fns),
        "nv_functions_targeted": len(nv_target_fns),
        "nv_error": nv_out.get("_error"),
        "hunt_error": hunt_out.get("_error"),
        "evidence": evidence[:5],
    }


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------

def load_corpus(path: Path) -> list[dict]:
    cases = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            cases.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return cases


def summarize(results: list[dict]) -> dict:
    def _rate(rows, key):
        if not rows:
            return None
        return round(sum(1 for r in rows if r[key]) / len(rows), 4)

    by_split: dict[str, dict] = {}
    by_class: dict[str, dict] = {}
    for split in sorted({r["split"] for r in results}):
        rows = [r for r in results if r["split"] == split]
        by_split[split] = {
            "n": len(rows),
            "rediscovery_file": _rate(rows, "rediscovered_file"),
            "rediscovery_line": _rate(rows, "rediscovered_line"),
        }
    for cls in sorted({r["class"] for r in results}):
        rows = [r for r in results if r["class"] == cls]
        by_class[cls] = {
            "n": len(rows),
            "splits": sorted({r["split"] for r in rows}),
            "rediscovery_file": _rate(rows, "rediscovered_file"),
            "rediscovery_line": _rate(rows, "rediscovered_line"),
        }
    return {
        "overall": {
            "n": len(results),
            "rediscovery_file": _rate(results, "rediscovered_file"),
            "rediscovery_line": _rate(results, "rediscovered_line"),
        },
        "by_split": by_split,
        "by_class": by_class,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", default="reference/fetchable_vuln_corpus.jsonl",
                    help="corpus jsonl (class-disjoint or instance-holdout)")
    ap.add_argument("--split-mode", default=None,
                    help="label only (e.g. class-disjoint / instance-holdout); inferred from filename if omitted")
    ap.add_argument("--out-dir", default="reports/pipeline_rediscovery")
    ap.add_argument("--line-tol", type=int, default=LINE_TOL_DEFAULT)
    ap.add_argument("--max-per-fn", type=int, default=3)
    ap.add_argument("--hunt-top", type=int, default=8)
    ap.add_argument("--hunt-max-functions", type=int, default=40)
    ap.add_argument("--mimo-budget", type=int, default=0,
                    help="0 = pure deterministic (default). >0 enables miner MIMO refine.")
    ap.add_argument("--only-split", default=None, choices=["TRAIN", "HELD_OUT"],
                    help="grade only one split (e.g. HELD_OUT to forward-test generalization)")
    ap.add_argument("--limit", type=int, default=0, help="cap cases (debug)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    corpus_path = (REPO_ROOT / args.corpus) if not os.path.isabs(args.corpus) else Path(args.corpus)
    cases = load_corpus(corpus_path)
    if args.only_split:
        cases = [c for c in cases if c.get("split") == args.only_split]
    if args.limit:
        cases = cases[: args.limit]

    split_mode = args.split_mode
    if not split_mode:
        split_mode = "instance-holdout" if "instance_holdout" in corpus_path.name else "class-disjoint"

    results: list[dict] = []
    for c in cases:
        file_rel = c["file_line"].rsplit(":", 1)[0]
        source_full = Path(c["local_checkout"]) / file_rel
        if not source_full.is_file():
            results.append({
                "case_id": c["case_id"], "class": c["vuln_class"],
                "language": c["language"], "split": c["split"], "file": file_rel,
                "target_line": int(c["file_line"].rsplit(":", 1)[1]),
                "rediscovered_file": False, "rediscovered_line": False,
                "surfacing_stage": "none", "nv_functions_targeted": 0,
                "nv_error": "source-missing", "hunt_error": "source-missing",
                "evidence": [],
            })
            continue
        ws = c["local_checkout"]
        lang = c["language"]
        # Layer 1: miner on the exact target file.
        if lang in ("solidity", "rust", "go", "move"):
            nv_out = run_novel_vector_miner(ws, source_full, lang, args.max_per_fn, args.mimo_budget)
        else:
            # miner only supports sol/rust/go/move; TS falls through to hunt only.
            nv_out = {"_error": f"miner-unsupported-lang:{lang}", "invariants": []}
        # Layer 2: hunt on the file's directory (real source-dir scan).
        hunt_out = run_corpus_hunt(ws, source_full.parent, args.hunt_top, args.hunt_max_functions)
        res = score_case(c, nv_out, hunt_out, args.line_tol)
        results.append(res)
        sys.stderr.write(
            f"[{res['split']:9s}] {res['class']:24s} file={int(res['rediscovered_file'])} "
            f"line={int(res['rediscovered_line'])} stage={res['surfacing_stage']:24s} "
            f"{res['case_id'][:48]}\n"
        )

    summary = summarize(results)
    date = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
    out_dir = (REPO_ROOT / args.out_dir) if not os.path.isabs(args.out_dir) else Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{split_mode}-{date}.json"
    payload = {
        "schema": "auditooor.pipeline_rediscovery_measure.v1",
        "generated_at_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "split_mode": split_mode,
        "corpus": str(corpus_path),
        "line_tol": args.line_tol,
        "max_per_fn": args.max_per_fn,
        "mimo_budget": args.mimo_budget,
        "hypothesis_layers": ["novel-vector-invariant-miner", "corpus-driven-hunt"],
        "headline_metric": "rediscovery_line",
        "file_level_caveat": (
            "rediscovery_file is a WEAK signal and is NOT the headline. The "
            "corpus-driven-hunt scans the bug-file's own directory, so a "
            "file-level cite is a near-trivial selection when the dir is small. "
            "The miner is deliberately given NO file-level credit (it is pointed "
            "at the file by the harness). Use rediscovery_line as the honest "
            "finding-power number: it requires the hypothesis layer to land on "
            "the bug's specific function/line, a real within-file selection."
        ),
        "rediscovery_definition": (
            "file-level: a derived invariant/hypothesis cites the recorded file. "
            "line-level: a hypothesis cites the file within +/-line_tol of the "
            "recorded line, OR a novel-vector invariant targets the function whose "
            "span contains the recorded line. Forward-test: the pipeline is never "
            "handed the answer."
        ),
        "anti_overfit": (
            "class-disjoint held-out classes never informed detector authoring; "
            "scoring logic is class-agnostic with zero instance literals; held-out "
            "source is read only to run the miner and resolve fn spans, never to "
            "tune a class pattern."
        ),
        "summary": summary,
        "cases": results,
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"\n=== pipeline-rediscovery-measure [{split_mode}] ===")
        print(f"out: {out_path}")
        print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
