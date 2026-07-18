#!/usr/bin/env python3
"""Per-draft finding-evidence-honesty gate (Rule R80).

The whole-workspace gate (tools/audit-honesty-check.py) computes TRUE coverage,
hollow/mock engine execution, and harness reality for an ENTIRE workspace. This
gate is the PER-DRAFT companion: when a single submission cites a harness / fuzz
/ symbolic / invariant run as LOAD-BEARING proof evidence, it verifies that the
cited evidence actually satisfies the same three honesty principles the workspace
gate enforces:

  R-B (real engine execution): the cited engine/run is genuinely executed, not
      engine-error / no-execution / assert(true)-only.
  R-C (mutation-verified): the cited harness has a mutation-verification record
      (inject bug -> invariant fails -> restore -> passes).
  R-D (non-mock CUT): the cited harness deploys a real in-scope src/ contract,
      not a mock / reimplementation standing in for the contract-under-test.

If a draft cites NO such evidence (a prose-only draft), this rule does NOT fire
(pass-no-harness-evidence-cited) - other gates cover prose-only drafts. The
posture is graceful: a prose draft is never false-failed, and a cited-but-
unlocatable harness only hard-fails under --strict.

Verdicts (exact vocab):
  pass-out-of-scope                  - severity below the gate's floor (LOW/MEDIUM
                                       with --severity), so R80 does not fire.
  pass-no-harness-evidence-cited     - no harness/fuzz/symbolic evidence cited
                                       (out of scope of THIS rule).
  pass-real-in-scope-proof           - all three principles (R-B/R-C/R-D) hold.
  ok-rebuttal                        - a fail was overridden by a valid r80-rebuttal.
  needs-evidence-path                - evidence cited but the harness can't be
                                       located (hard fail only under --strict;
                                       otherwise downgraded to a WARN pass).
  fail-hollow-engine-cited           - the cited engine run is hollow.
  fail-non-mutation-verified         - no mutation-verification record for the harness.
  fail-mock-cut-cited                - the cited CUT is a mock / reimplementation.
  error                              - cannot read the draft / unexpected error.

Override marker: a visible bounded line `r80-rebuttal: <reason>` (<=200 chars)
OR the HTML-comment form `<!-- r80-rebuttal: <reason> -->`. Empty or oversized
reason is ignored; the original fail verdict stands.

Exit codes: 0 on pass-* / ok-rebuttal; 1 on any fail-* (and needs-evidence-path
under --strict); 2 on error.

Usage:
  finding-evidence-honesty-check.py <draft.md> [--workspace <ws>]
      [--severity {auto,LOW,MEDIUM,HIGH,CRITICAL}] [--strict] [--json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.r80_finding_evidence_honesty.v1"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
# R80 fires at every severity by default (severity-agnostic, like R52/R54) -
# an honest-evidence claim matters at all severities. The --severity flag only
# downgrades to pass-out-of-scope when the operator explicitly passes LOW/MEDIUM.
# (auto / unset = fires.)

# ---------------------------------------------------------------------------
# Rebuttal parsing (parity with tools/v3-grade-poc-check.py).
# ---------------------------------------------------------------------------
REBUTTAL_RE = re.compile(r"<!--\s*r80-rebuttal:\s*(.*?)\s*-->", re.IGNORECASE | re.DOTALL)
REBUTTAL_LINE_RE = re.compile(r"(?im)^\s*(?:[-*]\s*)?r80[-_ ]rebuttal\s*:\s*(.+?)\s*$")


def _rebuttal(text: str) -> str | None:
    match = REBUTTAL_LINE_RE.search(text)
    if not match:
        match = REBUTTAL_RE.search(text)
    if not match:
        return None
    return " ".join(match.group(1).split())


# ---------------------------------------------------------------------------
# Harness-evidence detection.
# ---------------------------------------------------------------------------
# Keywords / patterns that signal the draft cites a harness / coverage / fuzz /
# symbolic / invariant run as LOAD-BEARING evidence.
_EVIDENCE_KEYWORDS = (
    r"\bharness\b",
    r"\bchimera\b",
    r"\brecon\b",
    r"\binvariant\b",
    r"\bmedusa\b",
    r"\bechidna\b",
    r"\bhalmos\b",
    r"\bfoundry\b",
    r"\bfuzz\w*\b",
    r"\bproven by\b",
    r"\bproof artifact\b",
    r"\bcoverage\b",
    r"\bPoC passes\b",
    r"\bsymbolic\b",
)
_EVIDENCE_RE = re.compile("|".join(_EVIDENCE_KEYWORDS), re.IGNORECASE)
# Cited PoC / harness path tokens.
_POC_PATH_RE = re.compile(
    r"[\w./@-]+(?:\.t\.sol|_test\.(?:go|rs|sol)|Setup\.sol|Properties\.sol)"
    r"|(?:poc-tests|per_function_invariants|chimera|recon)/[\w./@-]+",
    re.IGNORECASE,
)


def cites_harness_evidence(text: str) -> tuple[bool, list[str]]:
    """Return (cites, signals) - whether the draft cites load-bearing harness evidence."""
    signals: list[str] = []
    for m in _EVIDENCE_RE.finditer(text):
        tok = m.group(0).lower()
        if tok not in signals:
            signals.append(tok)
    paths = []
    for m in _POC_PATH_RE.finditer(text):
        p = m.group(0)
        if p not in paths:
            paths.append(p)
    return (bool(signals) or bool(paths)), signals + [f"path:{p}" for p in paths[:10]]


# ---------------------------------------------------------------------------
# audit-honesty-check.py import (reuse its classifiers).
# ---------------------------------------------------------------------------
def _import_honesty():
    """Import the sibling audit-honesty-check.py (hyphenated filename) as a module."""
    here = Path(__file__).resolve().parent
    target = here / "audit-honesty-check.py"
    if not target.is_file():
        return None
    spec = importlib.util.spec_from_file_location("audit_honesty_check", str(target))
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


# ---------------------------------------------------------------------------
# Workspace inference.
# ---------------------------------------------------------------------------
def _infer_workspace(draft: Path) -> Path | None:
    """Walk up from the draft to the dir containing submissions/ or .auditooor/."""
    for parent in [draft.parent, *draft.parents]:
        if (parent / "submissions").is_dir() or (parent / ".auditooor").is_dir():
            return parent
    return None


# ---------------------------------------------------------------------------
# Mutation-verification record detection.
# ---------------------------------------------------------------------------
_MUTATION_MARKER_RE = re.compile(
    r"mutation[- ]?verif|inject(?:ed)?\s+(?:a\s+)?bug.*invariant.*fail"
    r"|invariant\s+fails.*restore.*pass",
    re.IGNORECASE | re.DOTALL,
)


def _has_mutation_record(ws: Path, draft_text: str) -> tuple[bool, str]:
    """Detect a mutation-verification record tied to the harness.

    Two acceptable sources:
      (a) a workspace artifact .auditooor/*mutation*.json{,l}, OR
      (b) an in-draft 'mutation-verified' / 'inject bug -> invariant fails ->
          restore -> passes' marker.
    """
    aud = ws / ".auditooor"
    if aud.is_dir():
        for pat in ("*mutation*.json", "*mutation*.jsonl"):
            for p in aud.glob(pat):
                if p.is_file() and p.stat().st_size > 0:
                    return True, f"artifact:{p.relative_to(ws)}"
    # Also accept a top-level mutation artifact directly in the workspace.
    for pat in ("*mutation*.json", "*mutation*.jsonl"):
        for p in ws.glob(pat):
            if p.is_file() and p.stat().st_size > 0:
                return True, f"artifact:{p.relative_to(ws)}"
    if _MUTATION_MARKER_RE.search(draft_text):
        return True, "draft-marker"
    return False, ""


# ---------------------------------------------------------------------------
# Core evaluation.
# ---------------------------------------------------------------------------
def evaluate(draft: Path, ws: Path | None, *, strict: bool, honesty) -> dict:
    text = draft.read_text(encoding="utf-8", errors="replace")

    cites, signals = cites_harness_evidence(text)
    payload: dict = {
        "schema": SCHEMA,
        "gate": "R80-FINDING-EVIDENCE-HONESTY",
        "file": str(draft),
        "workspace": str(ws) if ws else None,
        "cites_harness_evidence": cites,
        "evidence_signals": signals,
    }

    if not cites:
        payload["verdict"] = "pass-no-harness-evidence-cited"
        payload["reason"] = "no harness/fuzz/symbolic/invariant evidence cited; R80 does not fire"
        return payload

    # Evidence is cited. We need the workspace + classifiers to verify it.
    if ws is None or not ws.is_dir():
        return _maybe_rebuttal(payload, text, strict_verdict="needs-evidence-path", strict=strict,
                               note="harness evidence cited but no workspace located to verify it")
    if honesty is None:
        return _maybe_rebuttal(payload, text, strict_verdict="needs-evidence-path", strict=strict,
                               note="could not import audit-honesty-check.py to reuse classifiers")

    # Detect language and run the engine/harness reality classifiers.
    try:
        lang = honesty._detect_lang(ws)
        eng = honesty._engine_reality(ws, lang)
    except Exception as exc:  # pragma: no cover - defensive
        payload["verdict"] = "error"
        payload["error"] = f"classifier failure: {exc}"
        return payload

    real_inscope = eng.get("real_inscope_harnesses") or []
    mock_only = eng.get("mock_target_runs") or []
    real_execution = bool(eng.get("real_execution"))

    payload["language"] = lang
    payload["engine_reality"] = {
        "real_execution": real_execution,
        "real_inscope_harnesses": real_inscope,
        "mock_target_runs": mock_only,
        "top_level_engines": eng.get("top_level_engines"),
        "per_function": eng.get("per_function"),
    }

    # Locate the cited harness: if NONE of the reality classifiers found ANY
    # real or mock harness/engine, we couldn't actually locate the cited evidence.
    located = bool(real_inscope or mock_only or real_execution
                   or (eng.get("per_function") or {}).get("real_harnesses")
                   or (eng.get("per_function") or {}).get("stub_harnesses"))
    if not located:
        return _maybe_rebuttal(payload, text, strict_verdict="needs-evidence-path", strict=strict,
                               note="harness evidence cited but no locatable harness/engine in workspace")

    # R-D non-mock CUT: a mock-only run with NO real in-scope harness is a mock CUT.
    if mock_only and not real_inscope:
        return _maybe_rebuttal(payload, text, fail_verdict="fail-mock-cut-cited", strict=strict,
                               note=f"cited harness CUT is mock-only (no real src/ deploy): {mock_only}")

    # R-B real engine execution: must NOT be hollow (engine-error / no-execution /
    # assert(true)-only). real_execution is False when all engines errored/absent
    # AND no real per-function/in-scope harness exists.
    if not real_execution:
        pf = eng.get("per_function") or {}
        return _maybe_rebuttal(payload, text, fail_verdict="fail-hollow-engine-cited", strict=strict,
                               note=(f"cited engine run is hollow: top-level={eng.get('top_level_engines')},"
                                     f" stub_harnesses={pf.get('stub_harnesses')},"
                                     f" real_harnesses={pf.get('real_harnesses')}"))

    # R-C mutation-verified: the cited harness needs a mutation-verification record.
    has_mut, mut_src = _has_mutation_record(ws, text)
    payload["mutation_record"] = {"present": has_mut, "source": mut_src}
    if not has_mut:
        return _maybe_rebuttal(payload, text, fail_verdict="fail-non-mutation-verified", strict=strict,
                               note="cited harness has no mutation-verification record")

    payload["verdict"] = "pass-real-in-scope-proof"
    payload["reason"] = "cited evidence is a real, mutation-verified, non-mock in-scope proof"
    return payload


def _maybe_rebuttal(payload: dict, text: str, *, fail_verdict: str | None = None,
                    strict_verdict: str | None = None, strict: bool = False,
                    note: str = "") -> dict:
    """Apply the rebuttal override for a fail / needs-evidence verdict.

    For `needs-evidence-path` (strict_verdict): hard fail only under --strict;
    otherwise downgraded to a WARN pass-no-harness-evidence-cited so a prose
    draft is never false-failed.
    """
    if strict_verdict == "needs-evidence-path":
        if strict:
            # Allow rebuttal to lift it.
            rb = _rebuttal(text)
            if rb and len(rb) <= 200:
                payload["verdict"] = "ok-rebuttal"
                payload["rebuttal"] = rb
                payload["original_verdict"] = "needs-evidence-path"
                payload["note"] = note
                return payload
            payload["verdict"] = "needs-evidence-path"
            payload["note"] = note
            return payload
        # Non-strict: graceful WARN pass.
        payload["verdict"] = "pass-no-harness-evidence-cited"
        payload["warn"] = note
        payload["note"] = "evidence cited but unlocatable; downgraded to WARN pass (use --strict to fail)"
        return payload

    # A genuine fail verdict.
    assert fail_verdict is not None
    rb = _rebuttal(text)
    if rb and len(rb) <= 200:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rb
        payload["original_verdict"] = fail_verdict
        payload["note"] = note
        return payload
    payload["verdict"] = fail_verdict
    payload["note"] = note
    return payload


def run(draft: Path, *, workspace: Path | None = None, severity_override: str | None = None,
        strict: bool = False) -> tuple[int, dict]:
    if not draft.is_file():
        return 2, {"schema": SCHEMA, "gate": "R80-FINDING-EVIDENCE-HONESTY",
                   "file": str(draft), "verdict": "error", "error": "cannot read draft: not a file"}
    try:
        text = draft.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return 2, {"schema": SCHEMA, "gate": "R80-FINDING-EVIDENCE-HONESTY",
                   "file": str(draft), "verdict": "error", "error": f"cannot read draft: {exc}"}

    # Severity gating: only LOW/MEDIUM explicit override downgrades to out-of-scope.
    if severity_override and severity_override.lower() not in ("auto",):
        sev = severity_override.lower()
        if sev in SEVERITY_RANK and SEVERITY_RANK[sev] < SEVERITY_RANK["high"]:
            return 0, {"schema": SCHEMA, "gate": "R80-FINDING-EVIDENCE-HONESTY",
                       "file": str(draft), "verdict": "pass-out-of-scope",
                       "severity": sev,
                       "reason": "severity below HIGH (explicit --severity); R80 does not fire"}

    ws = workspace if workspace is not None else _infer_workspace(draft)
    if ws is not None:
        ws = ws.expanduser().resolve()
    honesty = _import_honesty()

    try:
        payload = evaluate(draft, ws, strict=strict, honesty=honesty)
    except Exception as exc:  # pragma: no cover - defensive
        return 2, {"schema": SCHEMA, "gate": "R80-FINDING-EVIDENCE-HONESTY",
                   "file": str(draft), "verdict": "error", "error": str(exc)}

    verdict = payload.get("verdict", "error")
    if verdict.startswith("fail-") or (verdict == "needs-evidence-path"):
        return 1, payload
    if verdict == "error":
        return 2, payload
    return 0, payload


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("draft", type=Path)
    ap.add_argument("--workspace", type=Path, default=None)
    ap.add_argument("--severity",
                    type=lambda s: s.lower() if s.lower() == "auto" else s.upper(),
                    choices=["auto", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                    default="auto")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    code, payload = run(a.draft.expanduser().resolve(),
                        workspace=a.workspace,
                        severity_override=a.severity,
                        strict=a.strict)
    if a.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[finding-evidence-honesty-check] {payload['file']}: {payload['verdict']}")
        if payload.get("note"):
            print(f"  note: {payload['note']}")
        if payload.get("warn"):
            print(f"  WARN: {payload['warn']}")
        if payload.get("reason"):
            print(f"  reason: {payload['reason']}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
