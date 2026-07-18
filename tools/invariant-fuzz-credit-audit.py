#!/usr/bin/env python3
"""invariant-fuzz-credit-audit.py - retroactive cross-workspace scanner for
DEPTH-false-credits in the invariant-fuzz asset-coverage plane.

BACKGROUND (verified false-green class): the invariant-fuzz asset-coverage gate
credited an asset as "covered" on MUTATION-VERIFICATION alone (harness quality)
with NO fuzz-DEPTH floor. A shallow forge-invariant sidecar (runs:256 = 128,000
calls, mode='manual-mutant-harness', no campaign_calls) could therefore close a
>=1M asset-gap. Fuzz-DEPTH (a coverage-guided medusa/echidna/go campaign meeting
its call floor) and mutation-QUALITY are DIFFERENT axes; a sidecar can be
mutation_verified and still be sub-floor on depth.

This tool is a VISIBILITY + retroactive net. It does NOT hard-fail (the hard-fail
lives in the invariant-fuzz gate itself, fixed in a separate lane). It enumerates
every mvc_sidecar/*.json, and for each mutation_verified/non-vacuous sidecar
decides whether it carries REAL coverage-guided engine campaign evidence meeting
the engine call floor. A mutation_verified sidecar with NO such evidence is a
SUSPECT depth-false-credit.

SELF-CONTAINED: the depth-floor logic is replicated here on purpose (do NOT import
from invariant-fuzz-completeness.py) so this scanner cannot race a concurrent fix
to that gate.

Floors (coverage-guided campaigns only):
  * medusa                >= 1,000,000 calls
  * echidna               >=   500,000 calls
  * go-native fuzz        >= 1,000,000 calls (counts its own campaign_calls)
A forge invariant/fuzz `runs:N` (N*depth) is NOT a coverage-guided campaign and
does NOT clear the medusa floor regardless of the product.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

MIN_CALLS_MEDUSA = 1_000_000
MIN_CALLS_ECHIDNA = 500_000
MIN_CALLS_GO = 1_000_000

# Keys anywhere in the sidecar (recursively) that record a real executed
# coverage-guided campaign call count. Deliberately does NOT include `runs`
# (a forge run count is not a coverage-guided call campaign).
CALL_KEYS = {
    "campaign_calls",
    "calls_executed",
    "callsexecuted",
    "total_calls",
    "total_calls_baseline",
    "medusa_calls",
    "echidna_calls",
    "num_calls",
    "call_count",  # a real medusa/echidna sidecar sometimes records under call_count
    "calls",  # only credited when the owning engine is coverage-guided (gated below)
}

# Engine-class detection -----------------------------------------------------
# Coverage-guided engines that CAN clear a depth floor.
COVERAGE_GUIDED = ("medusa", "echidna", "go-native", "go_native", "gonative")


def _engine_class(engine: str, mode: str) -> str:
    """Return one of: 'medusa', 'echidna', 'go', or 'non-coverage-guided'."""
    e = (engine or "").lower()
    m = (mode or "").lower()
    # HAND-REGISTERED records (manual/premade) are asserted, never a real campaign -
    # non-coverage-guided even if they name an engine.
    if m in ("manual", "premade") or "manual-mutant-harness" in m or "premade-mutant-harness" in m:
        return "non-coverage-guided"
    # A coverage-guided ENGINE with a real campaign wins over a bare `*-mutant-harness`
    # mode suffix: `mode='medusa-campaign-plus-mutant-harness'` IS a real medusa campaign
    # that ALSO ran a mutant - do NOT misclassify it as non-coverage-guided (nuva
    # CrossChainVault false-flag). The engine check must come BEFORE the mode heuristic.
    if "echidna" in e:
        return "echidna"
    if "medusa" in e:
        # 'medusa+forge' still has a medusa campaign -> medusa class.
        return "medusa"
    if e.startswith("go") or "go-native" in e or "go_native" in e or "gonative" in e:
        return "go"
    # No coverage-guided engine: a bare *-mutant-harness mode, forge, or empty is
    # non-coverage-guided.
    return "non-coverage-guided"


def _floor_for(engine_class: str) -> int:
    return {
        "medusa": MIN_CALLS_MEDUSA,
        "echidna": MIN_CALLS_ECHIDNA,
        "go": MIN_CALLS_GO,
    }.get(engine_class, MIN_CALLS_MEDUSA)


def _collect_call_counts(obj, out: list) -> None:
    """Recursively gather all numeric values under CALL_KEYS."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (int, float)) and str(k).lower() in CALL_KEYS:
                try:
                    out.append(int(v))
                except (TypeError, ValueError):
                    pass
            else:
                _collect_call_counts(v, out)
    elif isinstance(obj, list):
        for it in obj:
            _collect_call_counts(it, out)


def _collect_runs(obj, out: list) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() == "runs" and isinstance(v, (int, float)):
                try:
                    out.append(int(v))
                except (TypeError, ValueError):
                    pass
            else:
                _collect_runs(v, out)
    elif isinstance(obj, list):
        for it in obj:
            _collect_runs(it, out)


def _asset_of(d: dict) -> str:
    for k in ("cut", "source_file", "contract", "target"):
        v = d.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    sfs = d.get("source_files")
    if isinstance(sfs, list) and sfs:
        return str(sfs[0])
    return "(unknown-asset)"


def evaluate_sidecar(path: Path) -> dict | None:
    """Return an evaluation dict, or None if the sidecar is not evaluated
    (not mutation_verified, or explicitly vacuous, or unparseable)."""
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(d, dict):
        return None

    mutation_verified = bool(d.get("mutation_verified") is True)
    if not mutation_verified:
        return None  # (e) non-mutation-verified -> not evaluated
    if d.get("non_vacuous") is False:
        return None  # explicitly vacuous -> not credited, not evaluated

    engine = str(d.get("engine", "") or "")
    mode = str(d.get("mode", "") or "")
    engine_class = _engine_class(engine, mode)
    # A forge/manual sidecar can carry an ADDITIVE nested coverage-guided campaign
    # (e.g. the factory sidecars: top-level engine=forge-invariant + a real
    # `medusa_campaign` block with >=1.2M calls). Classify by the nested coverage-guided
    # engine so the recursive call-count (below) can clear the floor - mirrors the gate,
    # which reads medusa_campaign.* directly. Only UPGRADES a non-coverage-guided class.
    if engine_class == "non-coverage-guided":
        for _k, _v in (d.items() if isinstance(d, dict) else []):
            if isinstance(_v, dict) and _v.get("engine"):
                _nc = _engine_class(str(_v.get("engine")), str(_v.get("mode", "")))
                if _nc != "non-coverage-guided":
                    engine_class = _nc
                    break

    call_counts: list = []
    _collect_call_counts(d, call_counts)
    max_calls = max(call_counts) if call_counts else 0

    runs: list = []
    _collect_runs(d, runs)
    max_runs = max(runs) if runs else 0

    floor = _floor_for(engine_class)

    if engine_class == "non-coverage-guided":
        cleared = False
        reason = (
            f"engine='{engine or '(none)'}' mode='{mode or '(none)'}' is not a "
            f"coverage-guided campaign (forge/manual/premade); no medusa/echidna/"
            f"go depth floor can be cleared"
        )
    else:
        cleared = max_calls >= floor
        if cleared:
            reason = f"{engine_class} campaign {max_calls} calls >= floor {floor}"
        else:
            reason = (
                f"{engine_class} campaign evidence {max_calls} calls < floor "
                f"{floor} (sub-floor or no recorded campaign)"
            )

    suspect = mutation_verified and not cleared
    return {
        "sidecar": str(path),
        "asset": _asset_of(d),
        "engine": engine or None,
        "engine_class": engine_class,
        "mode": mode or None,
        "manual_registration": bool(d.get("manual_registration") is True),
        "mutation_verified": mutation_verified,
        "recorded_calls": max_calls,
        "recorded_runs": max_runs,
        "call_floor": floor,
        "cleared_call_floor": cleared,
        "suspect": suspect,
        "reason": reason,
    }


def _find_sidecar_dirs_for_ws(ws: Path) -> list[Path]:
    d = ws / ".auditooor" / "mvc_sidecar"
    return [d] if d.is_dir() else []


def _discover_all(timeout: int = 60) -> list[Path]:
    roots = ["/Users/wolf/audits", "/Users/wolf/auditooor-worktrees"]
    dirs: list[Path] = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        try:
            out = subprocess.run(
                ["gtimeout", str(timeout), "find", root, "-maxdepth", "3",
                 "-type", "d", "-name", "mvc_sidecar"],
                capture_output=True, text=True, timeout=timeout + 5,
            ).stdout
        except Exception:
            # fall back to non-gtimeout find
            try:
                out = subprocess.run(
                    ["find", root, "-maxdepth", "3", "-type", "d",
                     "-name", "mvc_sidecar"],
                    capture_output=True, text=True, timeout=timeout,
                ).stdout
            except Exception:
                out = ""
        for line in out.splitlines():
            line = line.strip()
            if line and os.path.isdir(line):
                dirs.append(Path(line))
    return dirs


def _norm_asset(ws: Path, asset: str) -> str:
    """Normalize an asset path so an absolute (/Users/.../ws/src/X.sol) and a relative
    (src/X.sol) reference collapse to the SAME key (else the same asset is double-counted
    as two distinct suspects). Strips the ws root prefix; falls back to the raw string."""
    if not asset or asset == "(unknown-asset)":
        return "(unknown-asset)"
    a = asset.strip().replace("\\", "/")
    wsp = str(ws).replace("\\", "/").rstrip("/") + "/"
    if a.startswith(wsp):
        a = a[len(wsp):]
    return a.lstrip("/")


def audit_workspace(ws: Path) -> dict:
    """Evaluate one workspace (a workspace root that contains .auditooor)."""
    records = []
    for sd in _find_sidecar_dirs_for_ws(ws):
        for f in sorted(sd.glob("*.json")):
            ev = evaluate_sidecar(f)
            if ev is not None:
                ev["asset_norm"] = _norm_asset(ws, ev.get("asset", ""))
                records.append(ev)
    # An asset is genuinely COVERED if ANY of its sidecars cleared the call floor
    # (a fresh >=1M campaign supersedes an older 128k mutation-verify record for the
    # SAME asset - the shallow one is redundant, not debt). Report suspect ASSETS
    # (distinct, path-normalized, uncovered) so the count matches the gate asset-gap,
    # not the raw shallow-sidecar count (nuva was 50 sidecars but only 5 real gaps).
    covered = {r["asset_norm"] for r in records
               if r.get("cleared_call_floor") and r["asset_norm"] != "(unknown-asset)"}
    suspects = [r for r in records
                if r["suspect"] and r["asset_norm"] not in covered]
    suspect_assets = sorted({r["asset_norm"] for r in suspects})
    return {
        "workspace": str(ws),
        "evaluated": len(records),
        "suspect_asset_count": len(suspect_assets),
        "suspect_assets": suspect_assets,
        "suspect_sidecar_count": len(suspects),
        "suspects": suspects,
        "all_records": records,
    }


def _ws_root_from_sidecar_dir(sd: Path) -> Path:
    # sd = <ws>/.auditooor/mvc_sidecar
    return sd.parent.parent


def _write_ws_report(ws: Path, result: dict) -> Path | None:
    outdir = ws / ".auditooor"
    if not outdir.is_dir():
        return None
    out = outdir / "invariant_fuzz_credit_audit.json"
    payload = {
        "schema_id": "auditooor.invariant_fuzz_credit_audit.v1",
        "workspace": str(ws),
        "evaluated": result["evaluated"],
        "suspect_asset_count": result["suspect_asset_count"],
        "suspects": result["suspects"],
    }
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


ROLLUP_PATH = Path(
    "/Users/wolf/auditooor-mcp/reports/invariant_fuzz_credit_audit_rollup.json"
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--workspace", help="workspace root (contains .auditooor/)")
    ap.add_argument("--all", action="store_true",
                    help="auto-discover every workspace with an mvc_sidecar dir")
    ap.add_argument("--json", action="store_true", help="emit JSON to stdout")
    ap.add_argument("--no-write", action="store_true",
                    help="do not write durable reports")
    args = ap.parse_args(argv)

    if not args.workspace and not args.all:
        ap.error("one of --workspace or --all is required")

    workspaces: list[Path] = []
    if args.all:
        for sd in _discover_all():
            ws = _ws_root_from_sidecar_dir(sd)
            if ws not in workspaces:
                workspaces.append(ws)
    if args.workspace:
        ws = Path(args.workspace).resolve()
        if ws not in workspaces:
            workspaces.append(ws)

    results = []
    for ws in workspaces:
        res = audit_workspace(ws)
        results.append(res)
        if not args.no_write:
            _write_ws_report(ws, res)

    # Roll-up (durable), sorted by suspect count desc.
    rollup_rows = sorted(
        ({"workspace": r["workspace"],
          "workspace_name": Path(r["workspace"]).name,
          "evaluated": r["evaluated"],
          "suspect_asset_count": r["suspect_asset_count"],
          "suspects": [{"sidecar": s["sidecar"], "asset": s["asset"],
                        "engine": s["engine"], "mode": s["mode"],
                        "recorded_calls": s["recorded_calls"],
                        "manual_registration": s["manual_registration"],
                        "reason": s["reason"]}
                       for s in r["suspects"]]}
         for r in results),
        key=lambda x: x["suspect_asset_count"], reverse=True,
    )
    rollup = {
        "schema_id": "auditooor.invariant_fuzz_credit_audit_rollup.v1",
        "total_workspaces": len(results),
        "total_suspect_assets": sum(r["suspect_asset_count"] for r in results),
        "workspaces": rollup_rows,
    }
    if not args.no_write:
        try:
            ROLLUP_PATH.parent.mkdir(parents=True, exist_ok=True)
            ROLLUP_PATH.write_text(json.dumps(rollup, indent=2), encoding="utf-8")
        except Exception as e:  # pragma: no cover
            print(f"[invariant-fuzz-credit-audit] WARN rollup write failed: {e}",
                  file=sys.stderr)

    if args.json:
        print(json.dumps(rollup, indent=2))
        return 0

    # Human summary.
    print("[invariant-fuzz-credit-audit] DEPTH-false-credit retroactive scan")
    print(f"  workspaces scanned : {len(results)}")
    print(f"  suspect assets     : {rollup['total_suspect_assets']} "
          f"(mutation_verified but sub-floor / non-coverage-guided)")
    print("  --- roll-up (suspect_asset_count desc) ---")
    print(f"  {'workspace':<28} {'evaluated':>9} {'suspect':>8}")
    for row in rollup_rows:
        print(f"  {row['workspace_name']:<28} {row['evaluated']:>9} "
              f"{row['suspect_asset_count']:>8}")
    # Per-suspect detail for non-empty workspaces.
    for row in rollup_rows:
        if row["suspect_asset_count"] == 0:
            continue
        print(f"\n  [{row['workspace_name']}] suspects:")
        for s in row["suspects"]:
            print(f"    - {Path(s['sidecar']).name}: asset={s['asset']} "
                  f"engine={s['engine']} mode={s['mode']} "
                  f"calls={s['recorded_calls']}")
            print(f"      reason: {s['reason']}")
    if not args.no_write:
        print(f"\n  roll-up written -> {ROLLUP_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
