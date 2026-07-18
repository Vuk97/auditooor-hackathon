#!/usr/bin/env python3
"""invariant-scope-preflight.py - match every candidate invariant-fuzz lane asset
against SCOPE / known-findings / SEVERITY *before* we invest a 1M-call campaign on it.

THE IDEA (operator 2026-07-07): the invariant-fuzz-completeness gate demands a real
harness for EVERY value-moving in-scope file. But many of those assets' failure modes
are OUT OF SCOPE (SCOPE.md), already DISCLOSED in a prior audit (ineligible), covered by
a FILED finding, or map to NO in-scope SEVERITY.md row - so fuzzing them is coverage
theater. We were building ~40 Strata lanes, several purely OOS. This preflight classifies
each candidate lane-asset on THREE axes so we invest only where a counterexample would be
a REAL fileable finding:

  axis 1 SCOPE     - scope_authority.is_inscope_file (authoritative). OOS -> AUTO-EXEMPT.
  axis 2 KNOWN     - prior_audits/known_issues.jsonl + INGESTED_FINDINGS + filed
                     submissions mentioning the asset (ADVISORY: verify-not-dupe before
                     investing; NOT auto-exempt - a prior finding on a file does not
                     disclose every invariant on it).
  axis 3 SEVERITY  - which SEVERITY.md impact rows a conservation/custody failure on this
                     asset could hit (so we know the lane is fileable, not just busywork).

NEVER-FALSE / NEVER-EXEMPT-AWAY-REAL-SURFACE: the ONLY auto-exemption is OOS via the
authoritative scope manifest (with a cite). Everything else stays REQUIRES_LANE and merely
carries dedup/severity CONTEXT - the operator/agent then either builds the lane or writes a
CITED disposition (non_economic_dispositions.json), which the existing gate honours. Default
is always REQUIRES_LANE. This tool NEVER greens a gate; it steers investment.

ADVISORY-FIRST: emits .auditooor/invariant_scope_preflight.json + a WARN verdict. The OOS
auto-exempt set is consumed by invariant-fuzz-completeness._asset_coverage (additive, like
dispositions), so an OOS file is dropped from the gap list with a cite - never silently.
"""
from __future__ import annotations

import argparse
import importlib.util as _ilu
import json
import re
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(mod_name: str, filename: str):
    try:
        spec = _ilu.spec_from_file_location(mod_name, _HERE / filename)
        m = _ilu.module_from_spec(spec)
        spec.loader.exec_module(m)
        return m
    except Exception:  # noqa: BLE001
        return None


def _value_moving_files(ws: Path) -> set[str]:
    """The RAW value-moving file set (value_moving_functions.json), NOT pre-intersected
    with in-scope - so the OOS axis is live: a value-moving file that scope_authority calls
    OOS is classified EXEMPT_OOS here rather than being silently dropped upstream. (The
    invariant-fuzz gate's own lane requirement uses the in-scope-intersected subset; this
    superset lets us SEE + cite the OOS ones instead of losing them.)"""
    out: set[str] = set()
    p = ws / ".auditooor" / "value_moving_functions.json"
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        for f in (d.get("functions") or []):
            fp = str(f.get("file") or "").split(":")[0]
            if fp:
                out.add(fp)
    except (OSError, ValueError):
        pass
    # union in the in-scope value-moving set too (source-scan adds files the raw json may
    # lack), so nothing the gate demands a lane for escapes classification.
    m = _load("ifc", "invariant-fuzz-completeness.py")
    if m is not None and hasattr(m, "_value_moving_inscope_files"):
        try:
            out |= set(m._value_moving_inscope_files(ws))
        except Exception:  # noqa: BLE001
            pass
    return out


def _is_inscope(ws: Path, f: str) -> bool | None:
    """authoritative scope verdict; None if scope_authority unavailable (fail-open: treat
    as in-scope so we NEVER auto-exempt on a missing authority)."""
    sa = _load("scope_authority", "scope_authority.py")
    if sa is None or not hasattr(sa, "is_inscope_file"):
        return None
    try:
        return bool(sa.is_inscope_file(ws, f))
    except Exception:  # noqa: BLE001
        return None


def _base(f: str) -> str:
    return Path(str(f).split(":")[0]).name


def _prior_audit_hits(ws: Path, basename: str) -> list:
    """known_issues.jsonl entries whose `file` names this asset (dedup ADVISORY)."""
    hits = []
    p = ws / "prior_audits" / "known_issues.jsonl"
    if p.is_file():
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                r = json.loads(ln)
            except ValueError:
                continue
            if basename.replace(".sol", "") in str(r.get("file") or ""):
                hits.append({"id": r.get("id"), "severity": r.get("severity"),
                             "status": r.get("status"), "dedup_class": r.get("dedup_class"),
                             "disclosed_in": r.get("disclosed_in")})
    return hits


def _filed_mentions(ws: Path, basename: str) -> list:
    """paste_ready/filed submissions that cite this asset with a file:line range
    (ADVISORY: possibly covered as an affected instance - verify affected-vs-context)."""
    out = []
    pr = ws / "submissions" / "paste_ready"
    if not pr.is_dir():
        return out
    pat = re.compile(re.escape(basename) + r":\d")
    for md in pr.rglob("*.md"):
        try:
            txt = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if pat.search(txt):
            try:
                rel = str(md.relative_to(ws))
            except ValueError:
                rel = str(md)
            out.append(rel)
    return out


def _severity_rows(ws: Path) -> list:
    """The SEVERITY.md impact ladder (verbatim, for the in-scope-impact axis)."""
    rows = []
    p = ws / "SEVERITY.md"
    if p.is_file():
        tier = None
        for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = ln.strip()
            m = re.match(r"^#+\s*(Critical|High|Medium|Low)", s, re.I)
            if m:
                tier = m.group(1)
            elif s.startswith("- ") and tier:
                rows.append({"tier": tier, "impact": s[2:].strip()})
    return rows


def check(ws: Path) -> dict:
    ws = ws.expanduser().resolve()
    vm = sorted(_value_moving_files(ws))
    sev = _severity_rows(ws)
    assets = []
    exempt_oos = []
    requires_lane = []
    review_dedup = []
    for f in vm:
        insc = _is_inscope(ws, f)
        bn = _base(f)
        prior = _prior_audit_hits(ws, bn)
        filed = _filed_mentions(ws, bn)
        if insc is False:
            cls = "EXEMPT_OOS"
            cite = "scope_authority.is_inscope_file=False (not in inscope manifest)"
            exempt_oos.append(f)
        elif prior or filed:
            cls = "REVIEW_DEDUP"  # still owes a lane OR a cited disposition - NOT auto-exempt
            cite = ""
            review_dedup.append(f)
        else:
            cls = "REQUIRES_LANE"
            cite = ""
            requires_lane.append(f)
        assets.append({
            "asset": f, "classification": cls, "requires_lane": cls != "EXEMPT_OOS",
            "cite": cite, "prior_audit_hits": prior, "filed_mentions": filed,
        })
    verdict = "warn-invariant-scope-preflight" if (review_dedup or requires_lane) else "pass-invariant-scope-preflight"
    return {
        "schema": "invariant_scope_preflight/v1", "gate": "invariant-scope-preflight",
        "verdict": verdict,
        "counts": {"value_moving": len(vm), "requires_lane": len(requires_lane),
                   "review_dedup": len(review_dedup), "exempt_oos": len(exempt_oos)},
        "exempt_oos_files": exempt_oos,   # consumed by _asset_coverage (additive, cited)
        "severity_ladder": sev,
        "assets": assets,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--write", action="store_true",
                    help="persist to .auditooor/invariant_scope_preflight.json")
    a = ap.parse_args(argv)
    r = check(a.workspace)
    if a.write:
        outp = a.workspace.expanduser().resolve() / ".auditooor" / "invariant_scope_preflight.json"
        outp.parent.mkdir(parents=True, exist_ok=True)
        outp.write_text(json.dumps(r, indent=2), encoding="utf-8")
    if a.json:
        print(json.dumps(r, indent=2))
    else:
        c = r["counts"]
        print(f"invariant-scope-preflight: {r['verdict']} "
              f"({c['requires_lane']} REQUIRES_LANE, {c['review_dedup']} REVIEW_DEDUP "
              f"(dedup-before-invest), {c['exempt_oos']} EXEMPT_OOS of {c['value_moving']} "
              f"value-moving)")
        for x in r["assets"]:
            if x["classification"] != "REQUIRES_LANE":
                tag = x["classification"]
                extra = (f" prior={[h['id'] for h in x['prior_audit_hits']]}" if x["prior_audit_hits"] else "")
                extra += (f" filed={len(x['filed_mentions'])}" if x["filed_mentions"] else "")
                print(f"  [{tag}] {_base(x['asset'])}{extra}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
