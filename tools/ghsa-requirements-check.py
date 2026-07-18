#!/usr/bin/env python3
# r36-rebuttal: lane TASK-B-GHSA-AWARE-MODE registered in .auditooor/agent_pathspec.json
"""
ghsa-requirements-check.py
Rule 37 emit tier: tool utility (no corpus record emitted)

GHSA-MODE replacement for the Cantina-tuned structural gates (#31 program-
impact-mapping, #41 impact-contract, #42 final-paste-form selectors). When
pre-submit-check.sh detects a GHSA-format draft it SKIPS those Cantina gates and
runs this one instead, which enforces the GHSA paste contract documented in
docs/GHSA_ZEBRA_PASTE_TEMPLATE.md:

  (1) the 4 advisory sections present and non-empty:
        ### Summary / ### Details / ### PoC / ### Impact
  (2) an `## Affected products` block (ecosystem + package + affected versions)
  (3) a CVSS:3.1 vector string
  (4) at least one CWE-<n> weakness id
  (5) an Originality section AND a Prior-Audit Supersede Scan section (R47/R53
      originality discipline still applies to GHSA filings)

It reuses tools/ghsa-advisory-export.py's parser (parse_draft / validate_advisory)
for (1)-(4) so the requirement set stays single-sourced with the exporter.

RELATED TOOLS:
  - tools/ghsa-advisory-export.py    : renders the .advisory.{md,txt,json}. This
    gate imports its parser; the two stay in lockstep on the section/CVSS/CWE
    contract.
  - tools/ghsa-mode-detect.py        : classifies the draft as GHSA-format.
  - tools/ghsa-poc-inline-check.py   : the separate inline-PoC gate.

Usage:
  python3 tools/ghsa-requirements-check.py <draft.md> [--json] [--strict]

Verdicts:
  pass-ghsa-requirements-met : all required sections/fields present.
  fail-ghsa-requirements     : one or more hard requirements missing.
  error                      : file unreadable / exporter parser unavailable.

Exit code: 0 pass, 1 fail, 2 error.
"""

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.ghsa_requirements_check.v1"

_REPO = Path(__file__).resolve().parent.parent
_EXPORTER = _REPO / "tools" / "ghsa-advisory-export.py"

# Originality / supersede headers (R47 / R53). Accept the canonical variants
# used across the workspace paste templates.
ORIGINALITY_RE = re.compile(
    r"^##\s+(?:Originality|Originality\s*&?\s*Scope|Scope\s+And\s+Originality)\b.*$",
    re.IGNORECASE | re.MULTILINE,
)
SUPERSEDE_RE = re.compile(
    r"^##\s+(?:Prior[- ]Audit\s+Supersede\s+Scan|Supersede\s+Scan|Acknowledgement\s+Scan)\b.*$",
    re.IGNORECASE | re.MULTILINE,
)


def _load_exporter():
    spec = importlib.util.spec_from_file_location("_ghsa_advisory_export", _EXPORTER)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:
        return None
    return mod


def check(draft_path: Path):
    md = draft_path.read_text(encoding="utf-8", errors="replace")
    exporter = _load_exporter()
    if exporter is None:
        return 2, {
            "schema": SCHEMA,
            "draft": str(draft_path),
            "verdict": "error",
            "reason": f"cannot import GHSA exporter parser ({_EXPORTER})",
        }

    parsed = exporter.parse_draft(md)
    # validate_advisory wants the rendered body for residue checks; pass the
    # advisory body so its HTML-comment residue rule only fires on the rendered
    # section text, not the source draft's leading rebuttal markers.
    body = exporter.build_advisory_body(parsed)
    _result = exporter.validate_advisory(parsed, body)
    failures = list(_result.get("failures") or [])
    warnings = list(_result.get("warnings") or [])

    # Drop the residue failure: source drafts legitimately carry leading
    # rebuttal HTML-comments; the .advisory.md export strips them. The pre-submit
    # hygiene gate (#43) handles residue on the paste artifact separately.
    failures = [f for f in failures if "HTML-comment residue" not in f]

    missing_sections = [
        f.split(": ", 1)[-1]
        for f in failures
        if f.startswith("missing/empty section")
    ]
    no_cvss = any("CVSS" in f for f in failures)
    no_cwe = any("CWE" in f for f in failures)

    # (5) Originality + supersede sections
    has_originality = bool(ORIGINALITY_RE.search(md))
    has_supersede = bool(SUPERSEDE_RE.search(md))
    if not has_originality:
        failures.append("missing Originality section (R47/R53 originality discipline)")
    if not has_supersede:
        failures.append("missing Prior-Audit Supersede Scan / Acknowledgement Scan section")

    payload = {
        "schema": SCHEMA,
        "draft": str(draft_path),
        "title": parsed.get("title", ""),
        "sections_present": {
            k: bool(parsed["sections"].get(k)) for k in exporter._SECTION_KEYS
        },
        "missing_sections": missing_sections,
        "cvss": parsed.get("cvss", ""),
        "cwes": parsed.get("cwes", []),
        "affected": parsed.get("affected", {}),
        "has_originality": has_originality,
        "has_supersede": has_supersede,
        "warnings": warnings,
        "failures": failures,
    }

    if failures:
        payload["verdict"] = "fail-ghsa-requirements"
        payload["reason"] = "; ".join(failures)
        return 1, payload

    payload["verdict"] = "pass-ghsa-requirements-met"
    payload["reason"] = (
        "4 advisory sections + Affected + CVSS:3.1 + CWE + Originality + "
        "Supersede sections all present"
    )
    return 0, payload


def main(argv=None):
    ap = argparse.ArgumentParser(description="GHSA-mode requirement gate.")
    ap.add_argument("draft", help="path to the GHSA-format draft .md")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true",
                    help="treat warnings (affected-products fields) as failures")
    args = ap.parse_args(argv)

    path = Path(args.draft).expanduser()
    if not path.is_file():
        payload = {"schema": SCHEMA, "verdict": "error", "reason": f"file not found: {path}"}
        if args.json:
            print(json.dumps(payload))
        else:
            print(f"[error] {payload['reason']}", file=sys.stderr)
        return 2

    rc, payload = check(path)
    if args.strict and rc == 0 and payload.get("warnings"):
        payload["verdict"] = "fail-ghsa-requirements"
        payload["reason"] = "strict: " + "; ".join(payload["warnings"])
        payload["failures"] = list(payload.get("warnings") or [])
        rc = 1

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"{payload['verdict']}: {payload.get('reason', '')}")
        if payload.get("warnings"):
            for w in payload["warnings"]:
                print(f"  warn: {w}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
