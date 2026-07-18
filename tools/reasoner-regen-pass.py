#!/usr/bin/env python3
"""reasoner-regen-pass.py - obligation-substrate REGEN-ORDERING pass.

THE HOLE THIS CLOSES
--------------------
The ~35 pre-hunt LOGIC / NOVELTY reasoners (the ``_REASONER_LEDGERS`` set in
tools/logic-obligation-resolution-check.py) each CONSUME a dataflow / state-coupling
SUBSTRATE (dataflow_paths.jsonl, state_coupling_edges.jsonl, and their scoped
sidecars) and EMIT an obligation ledger (``*_obligations.jsonl``). The runbook wires
the substrate producer (step-1c dataflow slice; coupling-edge --autorun-producers)
BEFORE the reasoners, so on a clean single pass the ordering is correct.

But across RE-runs the ordering can INVERT: a substrate producer re-runs (a fresh
dataflow_paths.jsonl / state_coupling_edges.jsonl is materialized) AFTER a reasoner
already emitted its ledger in a prior pass. The reasoner's ledger mtime now PREDATES
its substrate - the obligations were reasoned over a STALE substrate and were never
regenerated. Nothing in the pipeline detected this: the ordering gate only proves the
static wiring, and the firing / resolution gates only look at whether a ledger exists
and reaches a terminal verdict - a ledger reasoned over an OUT-OF-DATE substrate reads
identically to a fresh one.

WHAT THIS PASS DOES
-------------------
A small, BOUNDED orchestration step. For every wired reasoner it:

  1. resolves the reasoner's SUBSTRATE dependency (parsed from the runbook step's
     ``reads`` + ``what_must_be_done`` text against a known substrate basename set),
  2. compares the emitted ledger's mtime against the newest existing substrate mtime,
  3. classifies the reasoner FRESH / STALE / MISSING / NO-SUBSTRATE, and
  4. (with ``--apply``) RE-INVOKES only the STALE (and optionally MISSING) reasoners,
     each under an individual timeout, so the ledger is regenerated over the current
     substrate. Receipts are appended to
     ``<ws>/.auditooor/reasoner_regen_receipts.jsonl``.

It NEVER re-runs a fresh reasoner and NEVER touches a reasoner whose substrate is
absent (that is a language/surface-absent case owned by the firing-nonvacuity gate).

SINGLE SOURCE OF TRUTH
----------------------
The wired-reasoner set is IMPORTED from logic-obligation-resolution-check.py
(``_REASONER_LEDGERS``) - this tool never hardcodes the reasoner list, so it can never
drift from the resolution / firing gates. The per-reasoner re-run command is extracted
from the runbook's own ``what_must_be_done`` field.

Exit codes:
  0  = nothing stale (report mode), or every stale reasoner re-ran OK (apply mode)
  1  = stale reasoners found and ``--fail-on-stale`` set (report mode), OR a re-run
       failed / timed out (apply mode)
  2  = usage / IO error
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

# Substrate basenames a reasoner may depend on. Scoped sidecars (dataflow_paths_*.jsonl)
# are matched by the `_matches_substrate` prefix rule below.
SUBSTRATE_BASENAMES: tuple[str, ...] = (
    "dataflow_paths.jsonl",
    "state_coupling_edges.jsonl",
)
# Prefixes so scoped sidecars (dataflow_paths_solidity.jsonl, ...) also count.
_SUBSTRATE_PREFIXES: tuple[str, ...] = (
    "dataflow_paths",
    "state_coupling_edges",
)

_RECEIPT_SIDECAR = "reasoner_regen_receipts.jsonl"
_DEFAULT_RUNBOOK = "readme_runbook_steps.json"
_DEFAULT_TIMEOUT = 240  # per-reasoner wall-clock ceiling (seconds)


# --------------------------------------------------------------------------- #
# reasoner-set import (single source of truth)                                #
# --------------------------------------------------------------------------- #
def load_reasoner_ledgers() -> tuple[tuple[str, str, str], ...]:
    """Import ``_REASONER_LEDGERS`` from the sibling resolution gate so the wired set
    never drifts. Returns tuples of (ledger_basename, tool_basename, language)."""
    sib = Path(__file__).resolve().with_name("logic-obligation-resolution-check.py")
    if not sib.is_file():
        return ()
    spec = importlib.util.spec_from_file_location("_regen_logic_obl_reg", sib)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_regen_logic_obl_reg"] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    led = getattr(mod, "_REASONER_LEDGERS", ())
    return tuple(led)


# --------------------------------------------------------------------------- #
# pure helpers (unit-tested with synthetic fixtures)                          #
# --------------------------------------------------------------------------- #
def _basename(p: str) -> str:
    return os.path.basename((p or "").strip().strip("`'\" "))


def _ledger_relpath(p: str) -> str:
    """Preserve a ledger's path below .auditooor instead of flattening it."""
    value = (p or "").strip().strip("`'\" ").replace("\\", "/")
    marker = ".auditooor/"
    if marker in value:
        value = value.split(marker, 1)[1]
    return value.lstrip("./")


def matches_substrate(name: str) -> bool:
    """True if a filename is a substrate file (exact basename or scoped prefix)."""
    b = _basename(name)
    if b in SUBSTRATE_BASENAMES:
        return True
    for pre in _SUBSTRATE_PREFIXES:
        if b.startswith(pre) and b.endswith(".jsonl"):
            return True
    return False


def substrate_deps_from_text(*texts: str) -> list[str]:
    """Scan runbook step text (reads + what_must_be_done) for substrate basenames the
    reasoner depends on. Returns a sorted, de-duplicated list of substrate basenames."""
    found: set[str] = set()
    blob = " ".join(t for t in texts if t)
    # match dataflow_paths.jsonl / state_coupling_edges.jsonl and scoped *_x.jsonl
    for m in re.finditer(r"[A-Za-z0-9_./-]+\.jsonl", blob):
        tok = m.group(0)
        if matches_substrate(tok):
            found.add(_basename(tok))
    return sorted(found)


def extract_rerun_command(what_must_be_done: str, tool_basename: str) -> str | None:
    """Extract the reasoner's re-run command from the runbook's what_must_be_done.

    Prefers a backtick-wrapped ``python3 tools/<tool> ...`` invocation; falls back to a
    canonical ``python3 tools/<tool> --workspace <ws>`` when the tool basename is known
    but no explicit command string is present. Returns None when neither is available.
    The returned string may contain a ``<ws>`` placeholder for the workspace path.
    """
    text = what_must_be_done or ""
    # 1) backtick-wrapped command mentioning the tool basename
    for m in re.finditer(r"`([^`]+)`", text):
        cmd = m.group(1).strip()
        if tool_basename and tool_basename in cmd and "python" in cmd:
            return cmd
    # 2) bare (un-backticked) python invocation of the tool
    if tool_basename:
        m = re.search(
            r"(python3?\s+tools/" + re.escape(tool_basename) + r"[^\n.`]*)", text
        )
        if m:
            return m.group(1).strip()
        # 3) canonical fallback
        return f"python3 tools/{tool_basename} --workspace <ws>"
    return None


def classify_staleness(
    ledger_exists: bool,
    ledger_mtime: float | None,
    substrate_mtimes: list[float],
) -> str:
    """Pure staleness classifier.

    Returns one of:
      "no-substrate" - no substrate file exists (reasoner's surface may be absent)
      "missing"      - substrate exists but the reasoner never emitted a ledger
      "stale"        - ledger mtime PREDATES the newest substrate mtime
      "fresh"        - ledger is at-or-after the newest substrate mtime
    """
    live = [m for m in substrate_mtimes if m is not None]
    if not live:
        return "no-substrate"
    if not ledger_exists or ledger_mtime is None:
        return "missing"
    if ledger_mtime < max(live):
        return "stale"
    return "fresh"


# --------------------------------------------------------------------------- #
# spec assembly + on-disk plan                                                #
# --------------------------------------------------------------------------- #
def build_reasoner_specs(runbook: dict, ledgers: tuple[tuple[str, str, str], ...]) -> list[dict]:
    """Join the imported reasoner set to the runbook steps to produce, per reasoner:
    {ledger, tool, lang, substrates:[...], command, step_id, uses_global_substrate}.

    MAP-COVERAGE (single source of truth): EVERY reasoner in ``_REASONER_LEDGERS`` (the
    same set the firing-nonvacuity gate tracks) becomes a spec - none is silently
    dropped. A reasoner that declares an explicit substrate dep in its runbook text is
    keyed on that per-reasoner substrate; one that declares NONE falls back to the
    GLOBAL dataflow substrate reference (``uses_global_substrate=True``) - the SAME
    reference reasoner-firing-nonvacuity-check keys ordering-staleness on - so it is
    still a regen-ordering candidate and can drain (previously these were EXCLUDED,
    leaving the 24 screen/hypothesis reasoners permanently ordering-stale)."""
    steps = runbook.get("steps", []) if isinstance(runbook, dict) else []
    by_emit: dict[str, dict] = {}
    for s in steps:
        emit = s.get("emit_artifact")
        if emit:
            by_emit[_basename(emit)] = s
    specs: list[dict] = []
    for ledger, tool, lang in ledgers:
        step = by_emit.get(_basename(ledger))
        reads = ""
        wmbd = ""
        step_id = None
        if step:
            reads = step.get("reads") or ""
            if isinstance(reads, list):
                reads = " ".join(str(x) for x in reads)
            wmbd = step.get("what_must_be_done") or ""
            step_id = step.get("step_id")
        subs = substrate_deps_from_text(reads, wmbd)
        uses_global = not subs
        cmd = extract_rerun_command(wmbd, tool)
        specs.append(
            {
                "ledger": _ledger_relpath(ledger),
                "tool": tool,
                "lang": lang,
                "substrates": subs,
                "uses_global_substrate": uses_global,
                "command": cmd,
                "step_id": step_id,
            }
        )
    return specs


def _mtime(p: Path) -> float | None:
    try:
        return p.stat().st_mtime
    except OSError:
        return None


def _file_has_rows(p: Path) -> bool:
    """True iff the file has >=1 non-blank line (mirrors the firing gate's non-empty
    substrate rule - a 0-line shard is treated as absent)."""
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    return True
    except OSError:
        pass
    return False


def global_substrate(auditooor_dir: Path) -> tuple[float | None, list[str]]:
    """The GLOBAL dataflow substrate reference - the SAME set
    reasoner-firing-nonvacuity-check keys ordering-staleness on
    (``dataflow_paths.jsonl`` + ``dataflow_paths.*`` shards, NON-EMPTY only). Returns
    (newest_mtime_or_None, sorted_present_basenames). Reasoners that declare no explicit
    substrate dep in the runbook are keyed on this reference so the regen-pass staleness
    computation cannot drift from the firing gate."""
    newest: float | None = None
    names: list[str] = []
    try:
        entries = list(auditooor_dir.iterdir())
    except OSError:
        entries = []
    for p in entries:
        if not p.is_file():
            continue
        b = p.name
        if not (b == "dataflow_paths.jsonl" or (b.startswith("dataflow_paths") and b.endswith(".jsonl"))):
            continue
        if not _file_has_rows(p):
            continue
        m = _mtime(p)
        if m is None:
            continue
        names.append(b)
        if newest is None or m > newest:
            newest = m
    return newest, sorted(names)


def compute_regen_plan(specs: list[dict], auditooor_dir: Path, include_missing: bool = False) -> list[dict]:
    """Stat the substrate + ledger files under <ws>/.auditooor and classify each
    reasoner. ``will_rerun`` is True for STALE (and MISSING when include_missing).

    A spec with ``uses_global_substrate`` is keyed on the GLOBAL dataflow substrate
    reference (``global_substrate``) - identical to the firing gate - instead of a
    per-reasoner declared dep."""
    g_mtime, g_names = global_substrate(auditooor_dir)
    plan: list[dict] = []
    for spec in specs:
        # newest mtime across the reasoner's (existing) substrate deps
        sub_mtimes: list[float] = []
        present_subs: list[str] = []
        if spec.get("uses_global_substrate"):
            if g_mtime is not None:
                sub_mtimes.append(g_mtime)
                present_subs = list(g_names)
        else:
            for sb in spec["substrates"]:
                m = _mtime(auditooor_dir / sb)
                if m is not None:
                    sub_mtimes.append(m)
                    present_subs.append(sb)
        ledger_path = auditooor_dir / spec["ledger"]
        lm = _mtime(ledger_path)
        verdict = classify_staleness(lm is not None, lm, sub_mtimes)
        will = verdict == "stale" or (include_missing and verdict == "missing")
        plan.append(
            {
                "ledger": spec["ledger"],
                "tool": spec["tool"],
                "lang": spec["lang"],
                "step_id": spec["step_id"],
                "command": spec["command"],
                "substrates_present": present_subs,
                "substrate_mtime": max(sub_mtimes) if sub_mtimes else None,
                "ledger_mtime": lm,
                "verdict": verdict,
                "will_rerun": will,
            }
        )
    return plan


# --------------------------------------------------------------------------- #
# re-invocation (apply mode)                                                   #
# --------------------------------------------------------------------------- #
def _default_runner(cmd_argv: list[str], cwd: str, timeout: int) -> dict:
    t0 = time.time()
    try:
        cp = subprocess.run(
            cmd_argv,
            cwd=cwd,
            timeout=timeout,
            capture_output=True,
            text=True,
        )
        return {
            "rc": cp.returncode,
            "timed_out": False,
            "duration_s": round(time.time() - t0, 2),
            "stderr_tail": (cp.stderr or "")[-400:],
        }
    except subprocess.TimeoutExpired:
        return {"rc": None, "timed_out": True, "duration_s": timeout, "stderr_tail": "TIMEOUT"}
    except OSError as e:
        return {"rc": None, "timed_out": False, "duration_s": round(time.time() - t0, 2), "stderr_tail": str(e)[-400:]}


_AUTORUN_FLAG = "--autorun-producers"


def is_producer(command: str | None) -> bool:
    """True iff the re-run command REGENERATES a substrate shard (bears
    ``--autorun-producers``). Such a run BUMPS the substrate mtime and, if run after a
    sibling consumer, snaps that consumer back to ordering-stale - so producers must run
    FIRST and the substrate must then be FROZEN while consumers re-run."""
    return _AUTORUN_FLAG in (command or "")


def freeze_command(command: str | None) -> str:
    """Strip ``--autorun-producers`` so a re-run reads the EXISTING substrate without
    regenerating (bumping) it - the freeze that keeps a just-run consumer fresh."""
    if not command:
        return command or ""
    toks = [t for t in command.split() if t != _AUTORUN_FLAG]
    return " ".join(toks)


def resolve_command_argv(command: str, workspace: str) -> list[str] | None:
    """Substitute the <ws> placeholder and split into argv. Returns None if no command."""
    if not command:
        return None
    resolved = command.replace("<ws>", workspace)
    # Runbook commands may document operator-supplied placeholders rather than a
    # directly executable invocation. Never pass those tokens to argparse as if
    # they were real paths or optional flags.
    if re.search(r"<[^>]+>|\[[^\]]*<[^>]+>[^\]]*\]", resolved):
        return None
    return resolved.split()


def _workspace_languages(workspace: Path) -> dict[str, bool]:
    """Reuse the polyglot router's in-scope language discovery."""
    try:
        spec = importlib.util.spec_from_file_location(
            "_regen_dataflow_router", Path(__file__).resolve().with_name("dataflow.py"))
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(mod)
        return dict(mod._present_languages(workspace))
    except Exception:
        return {}


def apply_language_applicability(plan: list[dict], present: dict[str, bool]) -> list[dict]:
    """Mark language-specific reasoners N/A when that first-party arm is absent."""
    aliases = {"sol": "solidity", "evm": "solidity", "circom": "zk", "js": "javascript"}
    for row in plan:
        lang = str(row.get("lang") or "any").lower()
        applicable = True
        if lang not in ("any", "both", "mixed", ""):
            applicable = bool(present.get(aliases.get(lang, lang), False))
        elif lang == "both":
            applicable = any(present.values())
        row["language_applicable"] = applicable
        if not applicable:
            row["verdict"] = "language-not-applicable"
            row["will_rerun"] = False
        elif row.get("will_rerun") and resolve_command_argv(
                str(row.get("command") or ""), "/workspace") is None:
            row["verdict"] = "manual-input-required"
            row["will_rerun"] = False
    return plan


def _run_entry(entry: dict, workspace: str, repo_root: Path, timeout: int, runner, phase: str) -> dict:
    cmd = entry.get("command") or ""
    if phase == "consumer":
        cmd = freeze_command(cmd)  # FREEZE: no substrate re-bump on the consumer pass
    argv = resolve_command_argv(cmd, workspace)
    if not argv:
        return {**_receipt_base(entry, workspace), "rc": None, "timed_out": False,
                "error": "no-command", "phase": phase}
    res = runner(argv, str(repo_root), timeout)
    return {**_receipt_base(entry, workspace), "argv": argv, "phase": phase, **res}


def apply_regen(plan: list[dict], workspace: str, repo_root: Path, timeout: int,
                runner=_default_runner, specs: list[dict] | None = None,
                auditooor_dir: Path | None = None, include_missing: bool = False) -> list[dict]:
    """Re-invoke every will_rerun reasoner in TWO topologically-ordered phases:

      PHASE A (producers first): run every will_rerun reasoner whose command bears
        ``--autorun-producers`` WITH the flag - regenerating all substrate shards up
        front, so no later re-run can re-bump the substrate under an already-fresh
        consumer.

      PHASE B (frozen consumers): the substrate is now FROZEN. Re-stat and re-classify
        over the freshly-regenerated substrate (when ``specs`` + ``auditooor_dir`` are
        supplied) and re-run every still-stale reasoner with ``--autorun-producers``
        STRIPPED, so each consumer's ledger mtime lands AFTER the substrate mtime and
        the reasoner is no longer ordering-stale.

    When ``specs``/``auditooor_dir`` are omitted (pure unit path), phase B falls back to
    the original plan's non-producer will_rerun entries. Returns receipt rows."""
    receipts: list[dict] = []

    # PHASE A: producers first (autorun kept -> regenerate substrate up front).
    producers = [e for e in plan if e.get("will_rerun") and is_producer(e.get("command"))]
    for entry in producers:
        receipts.append(_run_entry(entry, workspace, repo_root, timeout, runner, "producer"))

    # PHASE B: substrate frozen. Recompute over the regenerated substrate when possible.
    if specs is not None and auditooor_dir is not None:
        plan_b = compute_regen_plan(specs, auditooor_dir, include_missing=include_missing)
        eligible_ledgers = {
            str(e.get("ledger")) for e in plan
            if e.get("verdict") not in ("language-not-applicable", "manual-input-required")
        }
        phase_b = [e for e in plan_b
                   if e.get("will_rerun") and str(e.get("ledger")) in eligible_ledgers]
    else:
        phase_b = [e for e in plan if e.get("will_rerun") and not is_producer(e.get("command"))]
    for entry in phase_b:
        receipts.append(_run_entry(entry, workspace, repo_root, timeout, runner, "consumer"))

    return receipts


def _receipt_base(entry: dict, workspace: str) -> dict:
    return {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "workspace": workspace,
        "ledger": entry.get("ledger"),
        "tool": entry.get("tool"),
        "step_id": entry.get("step_id"),
        "reason": entry.get("verdict"),
    }


def persist_machine_applicability_exemptions(
    plan: list[dict], auditooor_dir: Path, present_languages: dict[str, bool]
) -> int:
    """Persist explicit, machine-cited N/A rows for absent-language reasoners.

    The firing gate deliberately refuses to infer N/A from a missing ledger. The
    regen planner already performs authoritative in-scope language discovery, so
    apply mode records that decision instead of leaving a silent vacuity behind.
    """
    path = auditooor_dir / "reasoner_firing_exemptions.jsonl"
    existing: list[dict] = []
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                existing.append(row)
    by_ledger = {str(row.get("ledger") or ""): row for row in existing}
    added = 0
    for row in plan:
        if row.get("verdict") != "language-not-applicable":
            continue
        ledger = str(row.get("ledger") or "")
        if not ledger or ledger in by_ledger:
            continue
        lang = str(row.get("lang") or "unknown")
        record = {
            "ledger": ledger,
            "reason": f"declared language arm '{lang}' is absent from in-scope workspace sources",
            "citation": f"machine-language-inventory:{json.dumps(present_languages, sort_keys=True)}",
            "source": "tools/reasoner-regen-pass.py",
        }
        existing.append(record)
        by_ledger[ledger] = record
        added += 1
    if added:
        path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in existing),
            encoding="utf-8",
        )
    return added


def persist_successful_empty_run_receipts(receipts: list[dict], auditooor_dir: Path) -> int:
    """Turn a successful, empty expected ledger into an explicit examined record.

    This is not survivor or proof credit. It only distinguishes a command that
    returned success and wrote its expected empty ledger from a tool that never ran.
    """
    terminal: dict[str, dict] = {}
    for receipt in receipts:
        terminal[str(receipt.get("ledger") or "")] = receipt
    written = 0
    for ledger, receipt in terminal.items():
        if not ledger or receipt.get("rc") != 0 or receipt.get("timed_out") or receipt.get("error"):
            continue
        path = auditooor_dir / ledger
        if not path.is_file() or _file_has_rows(path):
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "schema": "auditooor.reasoner_examined_empty.v1",
            "survivors": 0,
            "note": "cited-empty: reasoner command completed successfully and wrote zero survivors",
            "tool": receipt.get("tool"),
            "command": receipt.get("argv"),
            "receipt_ts": receipt.get("ts"),
        }
        path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
        written += 1
    return written


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Obligation-substrate regen-ordering pass.")
    ap.add_argument("--workspace", "-w", required=True, help="workspace root (contains .auditooor/)")
    ap.add_argument("--runbook", default=None, help="path to readme_runbook_steps.json")
    ap.add_argument("--apply", action="store_true", help="re-invoke stale reasoners (default: report only)")
    ap.add_argument("--include-missing", action="store_true", help="also re-run reasoners whose ledger is absent")
    ap.add_argument("--timeout", type=int, default=_DEFAULT_TIMEOUT, help="per-reasoner timeout (s)")
    ap.add_argument("--fail-on-stale", action="store_true", help="exit 1 in report mode if any reasoner is stale")
    ap.add_argument("--json", action="store_true", help="emit the plan as JSON")
    args = ap.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    runbook_path = Path(args.runbook) if args.runbook else (repo_root / "tools" / _DEFAULT_RUNBOOK)
    try:
        runbook = json.loads(runbook_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"reasoner-regen-pass: cannot read runbook {runbook_path}: {e}", file=sys.stderr)
        return 2

    ws_root = Path(args.workspace)
    auditooor_dir = ws_root / ".auditooor"
    if not auditooor_dir.is_dir():
        print(f"reasoner-regen-pass: no .auditooor dir under {ws_root} (nothing to do)", file=sys.stderr)
        return 0

    ledgers = load_reasoner_ledgers()
    specs = build_reasoner_specs(runbook, ledgers)
    plan = compute_regen_plan(specs, auditooor_dir, include_missing=args.include_missing)
    present_languages = _workspace_languages(ws_root)
    plan = apply_language_applicability(plan, present_languages)

    stale = [p for p in plan if p["verdict"] == "stale"]
    missing = [p for p in plan if p["verdict"] == "missing"]
    to_run = [p for p in plan if p["will_rerun"]]

    summary = {
        "workspace": str(ws_root),
        "reasoners_considered": len(plan),
        "stale": len(stale),
        "missing": len(missing),
        "will_rerun": len(to_run),
        "mode": "apply" if args.apply else "report",
    }

    receipts: list[dict] = []
    rc = 0
    if args.apply and to_run:
        receipts = apply_regen(plan, str(ws_root), repo_root, args.timeout,
                               specs=specs, auditooor_dir=auditooor_dir,
                               include_missing=args.include_missing)
        summary["machine_applicability_exemptions_added"] = (
            persist_machine_applicability_exemptions(plan, auditooor_dir, present_languages)
        )
        summary["successful_empty_receipts_written"] = (
            persist_successful_empty_run_receipts(receipts, auditooor_dir)
        )
        # persist receipts
        try:
            with (auditooor_dir / _RECEIPT_SIDECAR).open("a", encoding="utf-8") as fh:
                for r in receipts:
                    fh.write(json.dumps(r) + "\n")
        except OSError as e:
            print(f"reasoner-regen-pass: WARN could not write receipts: {e}", file=sys.stderr)
        # A producer attempt may fail while the frozen consumer subsequently
        # regenerates the same ledger successfully. Judge terminal outcome per
        # ledger, while retaining every receipt for diagnostics.
        terminal: dict[str, dict] = {}
        for receipt in receipts:
            terminal[str(receipt.get("ledger") or "")] = receipt
        failed = [
            r for r in terminal.values()
            if r.get("timed_out") or r.get("error")
            or (r.get("rc") is not None and r.get("rc") != 0)
        ]
        summary["reran"] = len(receipts)
        summary["failed"] = len(failed)
        if failed:
            rc = 1
    elif args.apply:
        summary["machine_applicability_exemptions_added"] = (
            persist_machine_applicability_exemptions(plan, auditooor_dir, present_languages)
        )
        summary["successful_empty_receipts_written"] = 0
    elif stale and args.fail_on_stale:
        rc = 1

    if args.json:
        print(json.dumps({"summary": summary, "plan": plan, "receipts": receipts}, indent=2))
    else:
        print(f"reasoner-regen-pass: {summary['mode']} | considered={summary['reasoners_considered']} "
              f"stale={summary['stale']} missing={summary['missing']} will_rerun={summary['will_rerun']}")
        for p in plan:
            if p["verdict"] in ("stale", "missing"):
                mark = "RERUN" if p["will_rerun"] else "skip"
                print(f"  [{p['verdict']:>6}] {p['ledger']:<52} <- {','.join(p['substrates_present']) or '(none)'} [{mark}]")
        if args.apply:
            print(f"reasoner-regen-pass: reran={summary.get('reran',0)} failed={summary.get('failed',0)}")

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
