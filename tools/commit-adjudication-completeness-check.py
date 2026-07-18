#!/usr/bin/env python3
"""commit-adjudication-completeness - fail-closed when a security-shaped fix-commit
that touches an IN-SCOPE file was CLASSIFIED by backward commit-mining but never
ADJUDICATED to a terminal bug-or-not verdict.

THE gap this closes (operator-caught, strata 2026-07-02): Tier-6 backward
commit-mining CLASSIFIES security-shaped commits into
`.auditooor/commit_lifecycle_ledger.json` -> `lanes_residual`, but nothing forced
those residuals to a terminal ADJUDICATION (FINDING / COMPLETE / OOS). strata passed
`audit-complete` as honest-0 with 32 security-shaped commits un-adjudicated - a real
false-green, because "classified" is not "ruled a bug or not". A backward fix-commit
that was incompletely applied or later partially reverted = a LIVE BUG at the pin,
and skipping the adjudication silently drops that whole exploit avenue.

The gate:
  - reads the residual security-shaped commits from commit_lifecycle_ledger.json
  - SCOPE-FILTERS each by its touched files (git show --name-only): a commit whose
    diff touches NO in-scope file is auto-OOS (not actionable) - so the actionable
    set is small (most residuals are OOS strategy/test commits)
  - requires each IN-SCOPE residual commit to carry a terminal adjudication in
    `.auditooor/commit_adjudications.jsonl`
    (schema: {"sha","verdict":"finding|complete|oos","reason","source_ref"})
  - FAIL-CLOSED when the git repo is absent (cannot prove OOS without the diff ->
    every residual is actionable) or an in-scope residual lacks a verdict.

Advisory by default (warn, rc 0); AUDITOOOR_COMMIT_ADJUDICATION_STRICT=1 makes it
hard-fail (rc 1). A ws-level rebuttal file
`.auditooor/commit_adjudication_rebuttal.md` (non-empty) downgrades a fail to warn,
mirroring the codified-rules rebuttal pattern.

Generic + language-agnostic: reads only the ledger, the src git repo, and the
scope manifest.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_TERMINAL = {"finding", "complete", "oos"}


def _load_scope_authority():
    p = _REPO_ROOT / "tools" / "scope_authority.py"
    spec = importlib.util.spec_from_file_location("_sa_commitadj", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


SA = _load_scope_authority()


def _load_json(p: Path) -> Any:
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _residual_security_commits(ws: Path) -> list[dict]:
    ledger = _load_json(ws / ".auditooor" / "commit_lifecycle_ledger.json")
    if not isinstance(ledger, dict):
        return []
    seen: dict[str, dict] = {}
    for c in ledger.get("lanes_residual", []) or []:
        if not isinstance(c, dict):
            continue
        if "security" not in str(c.get("classification", "")).lower():
            continue
        sha = str(c.get("sha") or "")
        if sha and sha not in seen:
            seen[sha] = {"sha": sha, "hint": str(c.get("hint", ""))[:120]}
    return list(seen.values())


def _find_src_repo(ws: Path) -> Path | None:
    """The git repo holding the audited source (NOT the .auditooor bookkeeping).
    Prefer a repo that contains an in-scope file; fall back to the first .git under
    the workspace that is not the workspace's own bookkeeping."""
    ins = SA.load_inscope(ws)
    cands = []
    for gitdir in ws.rglob(".git"):
        if ".auditooor" in gitdir.parts or "node_modules" in gitdir.parts or "lib" in gitdir.parts:
            continue
        repo = gitdir.parent
        cands.append(repo)
    # prefer the repo whose tree contains an in-scope basename
    if ins and ins.present:
        for repo in cands:
            for bn in list(ins.basenames)[:5]:
                if any(repo.rglob(bn)):
                    return repo
    return cands[0] if cands else None


def _touched_files(repo: Path, sha: str) -> list[str] | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "show", "--name-only", "--pretty=format:", sha],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]


# Production source extensions (a runtime fund-impact can only originate here).
_PROD_EXT = (".sol", ".rs", ".go", ".move", ".vy", ".cairo", ".fe", ".yul",
             ".huff", ".nr", ".ts", ".js")
# Path segments that mark a NON-production file (tests / mocks / scripts / docs /
# CI / config) - a fix here cannot ship a runtime vulnerability.
_NONPROD_SEG = ("/test/", "/tests/", "/mock", "/mocks/", "/script", "/scripts/",
                "/docs/", "/.github/", "test/", "tests/")
_NONPROD_SUFFIX = (".t.sol", ".test.ts", ".test.js", ".spec.ts", ".md", ".toml",
                   ".json", ".yml", ".yaml", ".txt", ".lock", ".cfg", ".ini")


def _is_production_file(path: str) -> bool:
    """A production source file whose bug could reach a runtime impact. Test /
    mock / script / docs / CI / config files are NON-production - a fix there
    cannot ship a vulnerability, so those (and only those) may auto-clear. NOTE:
    an out-of-scope PRODUCTION contract is STILL production - under primacy-of-
    impact (R38) an OOS mechanism can drive an in-scope impact, so it must be
    adjudicated for impact-reachability, never auto-cleared by file location."""
    p = str(path or "").replace("\\", "/").lower()
    if not p:
        return False
    if p.endswith(_NONPROD_SUFFIX):
        return False
    if any(seg in p for seg in _NONPROD_SEG):
        return False
    return p.endswith(_PROD_EXT)


def _load_adjudications(ws: Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    p = ws / ".auditooor" / "commit_adjudications.jsonl"
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        # a terminal verdict counts ONLY with a substantive reason - an OOS verdict
        # must carry an impact-reachability justification (why the OOS mechanism
        # cannot reach an in-scope impact), never a bare "file is out of scope".
        if (isinstance(rec, dict)
                and str(rec.get("verdict", "")).lower() in _TERMINAL
                and len(str(rec.get("reason") or "").strip()) >= 30):
            sha = str(rec.get("sha") or "")
            if sha:
                out[sha] = rec
    return out


def _rebuttal(ws: Path) -> str | None:
    p = ws / ".auditooor" / "commit_adjudication_rebuttal.md"
    try:
        t = p.read_text(encoding="utf-8", errors="replace").strip()
        return t or None
    except OSError:
        return None


# markers in SCOPE.md that select PRIMACY-OF-IMPACT (an OOS mechanism reaching an
# in-scope impact is in scope). Absent -> PRIMACY-OF-RULES (enumerated scope; only
# in-scope items matter, an OOS production contract is genuinely out).
_IMPACT_MODE_MARKERS = (
    "primacy of impact", "primacy-of-impact", "regardless of the contract",
    "regardless of location", "regardless of which contract",
    "any bug that leads to", "any impact that leads to loss",
    "impact is in scope regardless",
)


def _scope_mode(ws: Path) -> str:
    """'impact' (primacy-of-impact) or 'rules' (primacy-of-rules, the default).

    Order of authority: explicit env override -> a SCOPE.md primacy-of-impact
    clause -> default 'rules'. This is the operator's distinction: under
    primacy-of-rules ONLY the enumerated in-scope items matter (an OOS production
    mechanism is genuinely out); under primacy-of-impact an OOS mechanism that
    reaches an in-scope IMPACT must be adjudicated for reachability."""
    env = os.environ.get("AUDITOOOR_SCOPE_MODE", "").strip().lower()
    if env in ("impact", "rules"):
        return env
    for name in ("SCOPE.md", "scope.md"):
        p = ws / name
        try:
            txt = p.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        # An EXPLICIT declaration is authoritative and wins over loose markers.
        # Guard the negated-mention trap: "Primacy of RULES (not Primacy of Impact)"
        # must resolve to RULES, not match "primacy of impact" inside the negation.
        if ("primacy of rules" in txt or "primacy-of-rules" in txt
                or "not primacy of impact" in txt or "not primacy-of-impact" in txt):
            return "rules"
        if "primacy of impact" in txt or "primacy-of-impact" in txt:
            return "impact"
        if any(m in txt for m in _IMPACT_MODE_MARKERS):
            return "impact"
    return "rules"


def check(ws: Path) -> dict:
    residual = _residual_security_commits(ws)
    if not residual:
        return {"verdict": "pass-no-residual-security-commits", "actionable": 0,
                "violations": [], "note": "no residual security-shaped commits in the ledger"}
    repo = _find_src_repo(ws)
    adj = _load_adjudications(ws)
    mode = _scope_mode(ws)
    violations = []
    actionable = 0
    nonprod_auto = 0
    oos_rules_auto = 0
    for c in residual:
        sha = c["sha"]
        touched = _touched_files(repo, sha) if repo else None
        in_scope: bool | None
        if touched is not None:
            prod = [f for f in touched if _is_production_file(f)]
            if not prod:
                nonprod_auto += 1
                continue  # only test/mock/script/docs/CI/config or an empty merge
                          # diff -> cannot ship a runtime impact, safe to auto-clear
            in_scope = any(SA.is_inscope_file(ws, f) for f in prod)
            if mode == "rules" and not in_scope:
                # PRIMACY-OF-RULES: only the enumerated in-scope items matter, so an
                # OOS production mechanism is genuinely out of scope - auto-clear.
                oos_rules_auto += 1
                continue
            # PRIMACY-OF-IMPACT (mode == impact): an OOS production mechanism can
            # still drive an in-scope IMPACT, so it is actionable and must be
            # adjudicated for reachability - NOT auto-cleared by file location.
        else:
            in_scope = None  # src repo absent -> cannot classify -> fail-closed
        actionable += 1
        if sha not in adj:
            violations.append({
                "sha": sha, "hint": c["hint"], "in_scope": in_scope,
                "reason": ("in-scope production file" if in_scope
                           else "out-of-scope production mechanism (primacy-of-impact) - needs impact-reachability verdict"
                           if in_scope is False
                           else "src repo absent - cannot prove reachability (fail-closed)")})
    if not violations:
        return {"verdict": "pass-commit-adjudication-complete", "actionable": actionable,
                "scope_mode": mode, "nonprod_auto_cleared": nonprod_auto,
                "oos_rules_auto_cleared": oos_rules_auto, "violations": []}
    # advisory (warn) by default; hard verdict (fail) only under strict - so the
    # audit-done-guard wiring can never retroactively brick a prior audit that never
    # adjudicated, while AUDITOOOR_COMMIT_ADJUDICATION_STRICT=1 turns on enforcement.
    strict = bool(os.environ.get("AUDITOOOR_COMMIT_ADJUDICATION_STRICT"))
    return {"verdict": ("fail-commit-adjudication-incomplete" if strict
                        else "warn-commit-adjudication-incomplete"),
            "actionable": actionable, "scope_mode": mode,
            "nonprod_auto_cleared": nonprod_auto,
            "oos_rules_auto_cleared": oos_rules_auto, "violations": violations}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ws", "--workspace", dest="ws", required=True)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    ws = Path(a.ws)
    rep = check(ws)
    strict = bool(os.environ.get("AUDITOOOR_COMMIT_ADJUDICATION_STRICT"))
    reb = _rebuttal(ws)
    failed = rep["verdict"].startswith("fail-")
    if a.json:
        rep["strict"] = strict
        rep["rebuttal"] = bool(reb)
        print(json.dumps(rep, indent=2))
    else:
        print(f"[commit-adjudication-completeness] verdict: {rep['verdict']} "
              f"(mode={rep.get('scope_mode', '?')}, actionable={rep.get('actionable', 0)}, "
              f"nonprod_auto={rep.get('nonprod_auto_cleared', 0)}, "
              f"oos_rules_auto={rep.get('oos_rules_auto_cleared', 0)}, "
              f"strict={strict})")
        for v in rep.get("violations", []):
            print(f"  UN-ADJUDICATED {v['sha'][:12]}  {v['reason']}  | {v['hint']}")
        if failed and reb:
            print(f"  [rebuttal downgrades to warn] {reb[:100]}")
    if failed and strict and not reb:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
