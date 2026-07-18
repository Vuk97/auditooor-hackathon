#!/usr/bin/env python3
"""finding-target-scope-check.py - is a finding's ROOT-CAUSE file an enumerated
in-scope TARGET, or an in-repo OOS dependency?

Operator-caught 2026-07-01 (strata SharesCooldown): a hunt worker surfaced a real
bug whose root cause lives in `SharesCooldown.sol` - a file that IS in the repo and
IS reached by in-scope flow (Tranche.redeem -> StrataCDO.cooldownShares ->
SharesCooldown), but is NOT one of the 13 enumerated in-scope targets (it was
audited separately). Per R38/scope-authority a finding's PRIMARY IMPACT must land
on an in-scope target; an OOS-dependency root cause is not fileable unless an
in-scope primary impact is argued. The worker had to hand-derive this every time.

This gate automates that determination, all-workspace / all-language, using the
AUTHORITATIVE enumerated in-scope set already built by the pipeline
(`.auditooor/inscope_units.jsonl`) - which is correct precisely because it is an
ALLOWLIST (strata: "exactly the 13 targets enumerated"; SharesCooldown has 0
units). We do NOT re-parse SCOPE.md's default-in-scope logic (scope-md-parser
defaults denylist=in-scope, wrong for an enumerated-allowlist program).

ANTI-FALSE-NEGATIVE (the load-bearing posture): this gate FLAGS for review, it does
NOT hard-kill. A root cause in a non-enumerated file only requires the finding to
either (a) cite an enumerated in-scope file as its impact target (R38 in-scope-by-
impact) or (b) carry an explicit `oos-target-rebuttal: <reason>`. When the enumeration
is absent or the root-cause file cannot be determined, it WARN-passes (never a
false-OOS kill of a real finding).

Verdicts:
  pass-root-cause-in-scope            root-cause file IS an enumerated in-scope target
  pass-in-scope-impact-target-cited   root cause OOS but an enumerated in-scope file is
                                      cited (R38 primacy-of-impact may apply -> keep, review)
  pass-rebuttal                       oos-target-rebuttal marker present
  pass-no-enumeration                 inscope_units.jsonl absent -> cannot classify (WARN)
  pass-indeterminate-root-cause       could not extract a root-cause file (WARN)
  flag-root-cause-in-oos-dependency   root cause in a NON-enumerated file AND no in-scope
                                      target cited AND no rebuttal -> not fileable as-is

Schema: auditooor.finding_target_scope_check.v1
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA_ID = "auditooor.finding_target_scope_check.v1"

# `File.sol:123`, `path/to/File.sol#L12`, `X.go:45`, etc.
_FILE_REF_RE = re.compile(
    r"([A-Za-z0-9_./-]+\.(?:sol|go|rs|move|vy|cairo|py))\b", re.IGNORECASE
)
_REBUTTAL_RE = re.compile(
    r"oos-target-rebuttal\s*:\s*([^\n>]{1,200})", re.IGNORECASE
)
# Section headings that name the root cause.
_ROOT_CAUSE_HEADS = ("root cause", "vulnerable code", "vulnerability detail",
                     "the bug", "defect")


def _enumerated_basenames(ws: Path) -> set[str] | None:
    """Enumerated in-scope file BASENAMES from inscope_units.jsonl (the allowlist).
    None if the file is absent (cannot classify)."""
    p = ws / ".auditooor" / "inscope_units.jsonl"
    if not p.is_file():
        return None
    bn: set[str] = set()
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        f = str(r.get("file") or r.get("path") or "")
        if f:
            bn.add(Path(f).name)
    return bn


def _basename(ref: str) -> str:
    return Path(ref.split(":")[0].split("#")[0]).name


def _extract_root_cause_file(md: str) -> str | None:
    """Best-effort: the file cited in the Root Cause / Vulnerable Code section,
    else the most-cited source file across the whole finding."""
    lines = md.splitlines()
    # 1) look inside a Root-Cause-like section for the first file ref
    in_rc = False
    for ln in lines:
        low = ln.strip().lower()
        if ln.lstrip().startswith("#") and any(h in low for h in _ROOT_CAUSE_HEADS):
            in_rc = True
            continue
        if in_rc:
            if ln.lstrip().startswith("#") and ln.strip("# ").strip():
                in_rc = False  # next heading ends the section
                continue
            m = _FILE_REF_RE.search(ln)
            if m:
                return _basename(m.group(1))
    # 2) fallback: most-frequently-cited source file
    refs = [_basename(m.group(1)) for m in _FILE_REF_RE.finditer(md)]
    if not refs:
        return None
    from collections import Counter
    return Counter(refs).most_common(1)[0][0]


def check_finding(finding_md_path: Path, ws: Path,
                  root_cause_override: str | None = None) -> dict:
    out = {"schema_id": SCHEMA_ID, "finding": finding_md_path.name,
           "verdict": None, "root_cause_file": None, "reasons": []}
    try:
        md = finding_md_path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        out["verdict"] = "pass-indeterminate-root-cause"
        out["reasons"].append(f"cannot read finding: {e}")
        return out

    enum = _enumerated_basenames(ws)
    if enum is None:
        out["verdict"] = "pass-no-enumeration"
        out["reasons"].append("no .auditooor/inscope_units.jsonl - cannot classify "
                              "target scope (WARN; run step-1 to enumerate)")
        return out

    rc = _basename(root_cause_override) if root_cause_override else _extract_root_cause_file(md)
    out["root_cause_file"] = rc
    if not rc:
        out["verdict"] = "pass-indeterminate-root-cause"
        out["reasons"].append("could not extract a root-cause file (WARN, not flagged)")
        return out

    if rc in enum:
        out["verdict"] = "pass-root-cause-in-scope"
        out["reasons"].append(f"root-cause file '{rc}' IS an enumerated in-scope target")
        return out

    # root cause is in a NON-enumerated (in-repo OOS-dependency) file.
    rebut = _REBUTTAL_RE.search(md)
    cited = {_basename(m.group(1)) for m in _FILE_REF_RE.finditer(md)}
    in_scope_cited = sorted(cited & enum)
    if in_scope_cited:
        out["verdict"] = "pass-in-scope-impact-target-cited"
        out["reasons"].append(
            f"root-cause file '{rc}' is NOT enumerated, but enumerated in-scope file(s) "
            f"{in_scope_cited} are cited - R38 primacy-of-impact MAY apply; keep + review "
            "(does the PRIMARY impact land on the in-scope target?)")
        return out
    if rebut:
        out["verdict"] = "pass-rebuttal"
        out["reasons"].append(f"oos-target-rebuttal: {rebut.group(1).strip()}")
        return out

    out["verdict"] = "flag-root-cause-in-oos-dependency"
    out["reasons"].append(
        f"root-cause file '{rc}' is NOT one of the enumerated in-scope targets and NO "
        "enumerated in-scope file is cited as an impact target -> not fileable as primary "
        "(R38). If an in-scope target's funds/state are the PRIMARY impact, cite that file; "
        "else add `oos-target-rebuttal: <reason>` or dispose OOS.")
    return out


def _permits(verdict: str) -> bool:
    return verdict.startswith("pass")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--finding", required=True, help="path to the finding .md")
    ap.add_argument("--workspace", "-w", required=True, help="workspace root (has .auditooor/)")
    ap.add_argument("--root-cause-file", default=None,
                    help="override: the root-cause source file (else auto-extracted)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    res = check_finding(Path(args.finding).expanduser(),
                        Path(args.workspace).expanduser().resolve(),
                        args.root_cause_file)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"[finding-target-scope] verdict={res['verdict']} root_cause_file={res['root_cause_file']}")
        for r in res["reasons"]:
            print(f"  - {r}")
    return 0 if _permits(res["verdict"]) else 1


if __name__ == "__main__":
    sys.exit(main())
