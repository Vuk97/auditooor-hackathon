#!/usr/bin/env python3
# r36-rebuttal: lane TASK-B-GHSA-AWARE-MODE registered in .auditooor/agent_pathspec.json
"""
ghsa-mode-detect.py
Rule 37 emit tier: tool utility (no corpus record emitted)

Detect whether a pre-submit draft targets the GitHub Security Advisory (GHSA)
"Report a vulnerability" form rather than Cantina / HackenProof / Immunefi.

When a GHSA draft is detected, pre-submit-check.sh enters GHSA_MODE: the
Cantina-tuned gates (#11 scope-review artifact, #31 program-impact-mapping,
#41 impact-contract, #42 final-paste-form selectors) are SKIPPED and the GHSA
equivalents (the 4 advisory sections + Affected products + a CVSS:3.1 vector +
>=1 CWE + Originality/Supersede sections + inline PoC) are required instead.
See docs/GHSA_ZEBRA_PASTE_TEMPLATE.md for the format.

A draft is GHSA-format when ANY of:
  (a) it carries the explicit marker `<!-- target-format: ghsa -->`, OR
  (b) a sibling `<stem>.advisory.md` exists next to the draft (the real
      maintainer-facing paste artifact emitted by ghsa-advisory-export.py), OR
  (c) the body contains a `## Advisory Details` header AND a `CVSS:3.1/` vector
      string AND at least one `CWE-<n>` weakness id.

The detector also resolves the PASTE ARTIFACT: the `.advisory.md` sibling when
present (the clean GitHub-rendered paste), otherwise the source draft itself.
pre-submit-check.sh routes Check #43 (final-paste-hygiene) at the paste artifact
so the source draft's leading rebuttal HTML-comments do not trip the gate.

RELATED TOOLS:
  - tools/ghsa-advisory-export.py : converts a GHSA-format MD draft into the
    .advisory.md / .advisory.txt / .advisory.json artifacts. This detector is
    the upstream classifier; the export tool is the renderer. They compose.
  - tools/ghsa-requirements-check.py : enforces the GHSA-equivalent requirement
    set once GHSA_MODE is set. This detector only classifies + resolves paths.
  - tools/hackenproof-poc-not-inline-check.py : the HackenProof sibling gate
    (PoC must NOT be inline). GHSA is the opposite (PoC MUST be inline).

Usage:
  python3 tools/ghsa-mode-detect.py <draft.md> [--json]
  python3 tools/ghsa-mode-detect.py <draft.md> --field is_ghsa
  python3 tools/ghsa-mode-detect.py <draft.md> --field paste_artifact

Exit code:
  0  GHSA-format draft detected
  1  not a GHSA-format draft
  2  error (file not found / unreadable)

--field is_ghsa         : print `1` (GHSA) or `0` (not), exit 0 either way.
--field paste_artifact  : print the resolved paste-artifact path, exit 0.
--field detected_via    : print the detection signal(s), exit 0.
(With --field the exit code is always 0 so callers can capture the value with
$( ) without `set -e` aborting on a non-GHSA draft.)
"""

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "auditooor.ghsa_mode_detect.v1"

MARKER_RE = re.compile(r"<!--\s*target-format:\s*ghsa\s*-->", re.IGNORECASE)
ADVISORY_DETAILS_RE = re.compile(r"^##\s+Advisory Details\s*$", re.IGNORECASE | re.MULTILINE)
CVSS_RE = re.compile(r"CVSS:3\.1/(?:[A-Z]{1,2}:[A-Z](?:/)?)+")
CWE_RE = re.compile(r"\bCWE-\d+\b")


def detect(draft_path: Path):
    """Return (is_ghsa: bool, detected_via: list[str], paste_artifact: Path)."""
    text = draft_path.read_text(encoding="utf-8", errors="replace")
    detected_via = []

    if MARKER_RE.search(text):
        detected_via.append("marker:<!-- target-format: ghsa -->")

    # sibling .advisory.md (the export artifact). A draft that is itself the
    # .advisory.md is trivially GHSA-format too.
    stem = draft_path.name
    sibling = None
    if stem.endswith(".advisory.md"):
        detected_via.append("self:.advisory.md")
        sibling = draft_path
    else:
        base = stem[:-3] if stem.endswith(".md") else stem
        cand = draft_path.with_name(base + ".advisory.md")
        if cand.exists():
            detected_via.append(f"sibling:{cand.name}")
            sibling = cand

    # structural triple: ## Advisory Details + CVSS:3.1 vector + >=1 CWE
    has_details = bool(ADVISORY_DETAILS_RE.search(text))
    has_cvss = bool(CVSS_RE.search(text))
    has_cwe = bool(CWE_RE.search(text))
    if has_details and has_cvss and has_cwe:
        detected_via.append("structural:advisory-details+cvss3.1+cwe")

    is_ghsa = bool(detected_via)

    # Resolve the paste artifact: prefer the .advisory.md sibling (clean paste).
    paste_artifact = sibling if sibling is not None else draft_path

    return is_ghsa, detected_via, paste_artifact


def main(argv=None):
    ap = argparse.ArgumentParser(description="Detect a GHSA-format pre-submit draft.")
    ap.add_argument("draft", help="path to the draft .md")
    ap.add_argument("--json", action="store_true", help="emit JSON")
    ap.add_argument(
        "--field",
        choices=["is_ghsa", "paste_artifact", "detected_via"],
        help="print only one field; exit 0 regardless of GHSA status",
    )
    args = ap.parse_args(argv)

    path = Path(args.draft).expanduser()
    if not path.is_file():
        if args.field:
            # field mode never aborts the caller
            print("0" if args.field == "is_ghsa" else "")
            return 0
        if args.json:
            print(json.dumps({"schema": SCHEMA, "error": f"file not found: {path}"}))
        else:
            print(f"[error] file not found: {path}", file=sys.stderr)
        return 2

    is_ghsa, detected_via, paste_artifact = detect(path)

    if args.field == "is_ghsa":
        print("1" if is_ghsa else "0")
        return 0
    if args.field == "paste_artifact":
        print(str(paste_artifact))
        return 0
    if args.field == "detected_via":
        print(",".join(detected_via))
        return 0

    payload = {
        "schema": SCHEMA,
        "draft": str(path),
        "is_ghsa": is_ghsa,
        "detected_via": detected_via,
        "paste_artifact": str(paste_artifact),
    }
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(f"draft:          {path}")
        print(f"is_ghsa:        {is_ghsa}")
        print(f"detected_via:   {', '.join(detected_via) or '(none)'}")
        print(f"paste_artifact: {paste_artifact}")
    return 0 if is_ghsa else 1


if __name__ == "__main__":
    raise SystemExit(main())
