#!/usr/bin/env python3
# r36-rebuttal: lane IMP-ZK-ENFORCE registered in .auditooor/agent_pathspec.json agents[]
"""G14.1 workflow/Agent drill -> MIMO sidecar emitter.

# G14: this tool emits MIMO-compatible sidecars (not a corpus record itself).

Workflow / Agent drill findings (CONFIRMED and KILL) are routed through the
EXISTING MIMO sidecar pipeline rather than living only in a worker's return
value. This emitter writes ONE canonical MIMO sidecar JSON per finding into

    audit/corpus_tags/derived/mimo_harness_<ws>_workflow/<task_id>.json

The output shape is exactly what the three canonical readers expect:
  - tools/triage-kill-promoter.py:parse_mimo_sidecar
  - tools/r76-hallucination-guard.py:scan_mimo_dir
  - tools/workspace-coverage-heatmap.py:collect_hits

All three do ``json.loads(d["result"])`` after stripping code fences, so
``result`` MUST be a JSON STRING (not a dict). The top-level shape is:

    {"status": "ok", "task_id": <id>, "workspace": <ws>,
     "result": "<json.dumps(inner)>"}

where inner =
    {"verdict", "applies_to_target", "confidence", "file_line",
     "code_excerpt", "severity_final", "reasoning", "file_path_hint"}

R76 honesty at emit time (G14.1 requirement): if the verdict is
CONFIRMED-class AND (file_line is empty / N/A / conceptual OR code_excerpt
is not grep-findable in the workspace), the emitter REFUSES to write a
CONFIRMED sidecar and DOWNGRADES it to MAYBE (applies_to_target=maybe,
verdict cleared) so a hallucinated pattern never enters the corpus as
CONFIRMED. This reuses tools/r76-hallucination-guard.py:check_candidate.

USAGE:
  python3 tools/workflow-drill-sidecar-emit.py \\
      --workspace hyperbridge --task-id hb-claim-underflow \\
      --verdict CONFIRMED --applies-to-target yes --confidence high \\
      --file-line "pallet-ismp/src/lib.rs:L120" \\
      --code-excerpt "let amount = balance.checked_sub(fee)" \\
      --severity Medium --reasoning "unchecked sub underflow" \\
      --file-path-hint pallet-ismp/src/lib.rs

  # Batch from a JSON list (stdin or file):
  python3 tools/workflow-drill-sidecar-emit.py --workspace hyperbridge \\
      --from-json findings.json

Exit codes: 0 = emitted, 1 = downgraded-and-emitted (R76 honesty), 2 = error.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

AUDITOOOR_ROOT = Path(__file__).resolve().parent.parent
AUDITS_ROOT = Path.home() / "audits"
DERIVED_ROOT = AUDITOOOR_ROOT / "audit" / "corpus_tags" / "derived"

CONFIRMED_TOKENS = ("CONFIRMED", "PROMOTE", "REAL-BUG-PROMOTE", "VERIFIED")


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_r76_check_candidate():
    """Import check_candidate from tools/r76-hallucination-guard.py (its
    module name has hyphens, so load by file path)."""
    guard_path = AUDITOOOR_ROOT / "tools" / "r76-hallucination-guard.py"
    if not guard_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("_r76_guard", guard_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return getattr(mod, "check_candidate", None)
    except Exception:
        return None


def workspace_to_path(ws: str) -> Path:
    """Resolve a workspace NAME or PATH to a path. Accepts either a bare
    name (hyperbridge) or an absolute path."""
    p = Path(ws).expanduser()
    if p.is_absolute() or p.exists():
        return p
    return AUDITS_ROOT / ws


def _is_confirmed(verdict: str) -> bool:
    v = (verdict or "").upper()
    return any(tok in v for tok in CONFIRMED_TOKENS)


def build_sidecar(
    *,
    workspace: str,
    task_id: str,
    verdict: str,
    applies_to_target: str,
    confidence: str,
    file_line: str,
    code_excerpt: str,
    severity: str,
    reasoning: str,
    file_path_hint: str,
    function_anchor: dict | None = None,
    r76_check=None,
) -> tuple[dict, bool]:
    """Return (sidecar_dict, downgraded_bool).

    Applies R76 emit-time honesty: a CONFIRMED-class verdict with a missing /
    conceptual file_line OR a code_excerpt not present in the workspace is
    downgraded to MAYBE before being written.
    """
    downgraded = False
    eff_verdict = verdict or ""
    eff_applies = (applies_to_target or "").strip().lower()

    if _is_confirmed(eff_verdict) and r76_check is not None:
        ws_path = workspace_to_path(workspace)
        try:
            res = r76_check(eff_verdict, file_line or "", code_excerpt or "",
                            ws_path if ws_path.is_dir() else None)
        except Exception:
            res = {"verdict": "error"}
        rv = str(res.get("verdict", ""))
        if rv.startswith("fail"):
            # Hallucination signal: downgrade CONFIRMED -> MAYBE.
            downgraded = True
            eff_verdict = "MAYBE"
            eff_applies = "maybe"
            reasoning = (
                f"[R76-downgrade: {rv}] " + (reasoning or "")
            ).strip()

    inner = {
        "verdict": eff_verdict,
        "applies_to_target": eff_applies or (applies_to_target or "").strip().lower(),
        "confidence": (confidence or "").strip().lower(),
        "file_line": file_line or "",
        "code_excerpt": code_excerpt or "",
        "severity_final": severity or "",
        "reasoning": reasoning or "",
        "file_path_hint": file_path_hint or "",
    }
    # Explicit subject anchor: for a PER-FUNCTION hunt task the subject fn is
    # authoritative (the assignment), independent of which evidence line file_line
    # cites. function-coverage-completeness anchors credit on function_anchor.{fn,
    # function,file,line}; without it a per-fn KILL with a file_line pointing at a
    # relevant-code line (or a proxy stub in a different file) cannot be matched to
    # its subject fn - especially when the fn NAME is non-unique across files (e.g.
    # registerOperator in both the proxy and the module). Carry file+fn+line so the
    # consumer resolves the EXACT (file, decl-line) unit, never a name-only guess.
    _anchor_obj = None
    if isinstance(function_anchor, dict):
        _af = str(function_anchor.get("file") or "").strip()
        _an = str(function_anchor.get("fn") or function_anchor.get("function") or "").strip()
        _al = function_anchor.get("line")
        if _af or _an:
            _anchor_obj = {"file": _af, "fn": _an, "function": _an}
            try:
                if _al not in (None, ""):
                    _anchor_obj["line"] = int(_al)
            except (TypeError, ValueError):
                pass
            inner["function_anchor"] = _anchor_obj
    sidecar = {
        "status": "ok",
        "task_id": task_id,
        "workspace": workspace,
        "source": "workflow-drill-sidecar-emit",
        "emitted_at_utc": iso_now(),
        # CRITICAL: result is a JSON STRING (all 3 readers json.loads it).
        "result": json.dumps(inner),
    }
    # function-coverage-completeness reads function_anchor from the TOP-LEVEL
    # sidecar (outer.get("function_anchor")), not from inside the result string -
    # so the authoritative per-fn subject anchor MUST live here for the consumer
    # to credit the exact (file, decl-line) unit. (Also kept inside inner above
    # for any reader that parses the result payload directly.)
    if _anchor_obj is not None:
        sidecar["function_anchor"] = _anchor_obj
    return sidecar, downgraded


def emit_one(rec: dict, out_dir: Path, r76_check=None) -> tuple[Path, bool]:
    ws = str(rec.get("workspace") or "unknown")
    task_id = str(rec.get("task_id") or "untitled")
    sidecar, downgraded = build_sidecar(
        workspace=ws,
        task_id=task_id,
        verdict=str(rec.get("verdict") or ""),
        applies_to_target=str(rec.get("applies_to_target") or ""),
        confidence=str(rec.get("confidence") or ""),
        file_line=str(rec.get("file_line") or ""),
        code_excerpt=str(rec.get("code_excerpt") or ""),
        severity=str(rec.get("severity") or rec.get("severity_final") or ""),
        reasoning=str(rec.get("reasoning") or ""),
        file_path_hint=str(rec.get("file_path_hint") or ""),
        function_anchor=(rec.get("function_anchor")
                         if isinstance(rec.get("function_anchor"), dict)
                         else ({"file": rec.get("anchor_file"),
                                "fn": rec.get("anchor_fn"),
                                "line": rec.get("anchor_line")}
                               if (rec.get("anchor_file") or rec.get("anchor_fn"))
                               else None)),
        r76_check=r76_check,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    # Sanitise task_id for a filename.
    safe = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in task_id)
    out_path = out_dir / f"{safe}.json"
    # COLLISION-SAFE: never silently overwrite a prior sidecar. Parallel agents
    # routinely pass DUPLICATE task_ids (e.g. each independently auto-numbers
    # perfn_mimo_etherfi_00161.. from the same base), which would overwrite each
    # other and SILENTLY LOSE per-function coverage. If the target exists and its
    # content differs, disambiguate with a short content hash (so an idempotent
    # re-emit of the SAME content maps back to the same file - no dup spam - while
    # genuinely distinct verdicts each get their own file - no lost coverage).
    if out_path.exists():
        new_blob = json.dumps(sidecar, indent=2)
        try:
            existing = out_path.read_text(encoding="utf-8")
        except OSError:
            existing = None
        if existing != new_blob:
            h = hashlib.sha1(
                (str(rec.get("file_line") or "") + "|"
                 + str(rec.get("code_excerpt") or "") + "|"
                 + str(rec.get("reasoning") or "")).encode("utf-8", "replace")
            ).hexdigest()[:8]
            cand = out_dir / f"{safe}-{h}.json"
            n = 2
            while cand.exists() and cand.read_text(encoding="utf-8", errors="replace") != new_blob:
                cand = out_dir / f"{safe}-{h}-{n}.json"
                n += 1
            out_path = cand
    out_path.write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
    return out_path, downgraded


def out_dir_for(workspace: str, base: Path | None = None) -> Path:
    base = base or DERIVED_ROOT
    # Workspace dir uses the bare name (so collect_hits' mimo_harness_<ws>*
    # glob picks it up).
    ws_name = Path(workspace).name if "/" in workspace else workspace
    return base / f"mimo_harness_{ws_name}_workflow"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=(
            "G14.1 workflow/Agent drill -> MIMO sidecar emitter. Writes the "
            "canonical MIMO sidecar shape into "
            "audit/corpus_tags/derived/mimo_harness_<ws>_workflow/ so the "
            "existing PostToolUse hook (Steps C/D) auto-ingests it."
        ),
    )
    p.add_argument("--workspace", help="Workspace name (e.g. hyperbridge) or path.")
    p.add_argument("--task-id", help="Unique finding/task id.")
    p.add_argument("--verdict", default="", help="CONFIRMED | KILL | MAYBE | ...")
    p.add_argument("--applies-to-target", default="", choices=["", "yes", "no", "maybe"])
    p.add_argument("--confidence", default="", choices=["", "high", "med", "medium", "low"])
    p.add_argument("--file-line", default="", help="file:Lnn citation.")
    p.add_argument("--code-excerpt", default="", help="verbatim source excerpt.")
    p.add_argument("--severity", default="", help="Low | Medium | High | Critical.")
    p.add_argument("--reasoning", default="", help="free-text reasoning.")
    p.add_argument("--file-path-hint", default="", help="workspace-relative source path.")
    p.add_argument("--anchor-file", default="",
                   help="PER-FN subject anchor: workspace-relative file of the subject function "
                        "(authoritative subject, independent of --file-line evidence cite).")
    p.add_argument("--anchor-fn", default="",
                   help="PER-FN subject anchor: subject function name.")
    p.add_argument("--anchor-line", default="",
                   help="PER-FN subject anchor: subject function DECLARATION line number.")
    p.add_argument(
        "--from-json",
        default=None,
        help="Path to a JSON file (or '-' for stdin) holding a list of finding dicts.",
    )
    p.add_argument(
        "--out-base",
        default=None,
        help="Override derived root (default: audit/corpus_tags/derived).",
    )
    p.add_argument(
        "--no-r76",
        action="store_true",
        help="Disable R76 emit-time honesty downgrade (testing only).",
    )
    p.add_argument("--json", action="store_true", help="Emit a JSON summary to stdout.")
    args = p.parse_args(argv)

    r76_check = None if args.no_r76 else _load_r76_check_candidate()
    out_base = Path(args.out_base).expanduser() if args.out_base else DERIVED_ROOT

    records: list[dict] = []
    if args.from_json:
        try:
            if args.from_json == "-":
                raw = sys.stdin.read()
            else:
                raw = Path(args.from_json).expanduser().read_text(encoding="utf-8")
            parsed = json.loads(raw)
        except Exception as exc:
            print(json.dumps({"status": "error", "reason": f"bad --from-json: {exc}"}))
            return 2
        if isinstance(parsed, dict):
            parsed = [parsed]
        if not isinstance(parsed, list):
            print(json.dumps({"status": "error", "reason": "--from-json must be a list or dict"}))
            return 2
        records = [r for r in parsed if isinstance(r, dict)]
    else:
        if not args.workspace or not args.task_id:
            print(json.dumps({
                "status": "error",
                "reason": "--workspace and --task-id required unless --from-json is used",
            }))
            return 2
        records = [{
            "workspace": args.workspace,
            "task_id": args.task_id,
            "verdict": args.verdict,
            "applies_to_target": args.applies_to_target,
            "confidence": args.confidence,
            "file_line": args.file_line,
            "code_excerpt": args.code_excerpt,
            "severity": args.severity,
            "reasoning": args.reasoning,
            "file_path_hint": args.file_path_hint,
            "function_anchor": ({"file": args.anchor_file, "fn": args.anchor_fn,
                                 "line": args.anchor_line}
                                if (args.anchor_file or args.anchor_fn) else None),
        }]

    emitted: list[dict] = []
    any_downgraded = False
    for rec in records:
        ws = str(rec.get("workspace") or args.workspace or "unknown")
        od = out_dir_for(ws, out_base)
        path, downgraded = emit_one(rec, od, r76_check=r76_check)
        any_downgraded = any_downgraded or downgraded
        emitted.append({
            "path": str(path),
            "task_id": str(rec.get("task_id") or ""),
            "workspace": ws,
            "downgraded": downgraded,
        })

    summary = {
        "status": "ok",
        "emitted_count": len(emitted),
        "downgraded_count": sum(1 for e in emitted if e["downgraded"]),
        "emitted": emitted,
    }
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        for e in emitted:
            tag = " [R76-DOWNGRADED]" if e["downgraded"] else ""
            print(f"emitted {e['path']}{tag}")
    return 1 if any_downgraded else 0


if __name__ == "__main__":
    sys.exit(main())
