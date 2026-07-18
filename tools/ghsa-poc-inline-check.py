#!/usr/bin/env python3
# r36-rebuttal: lane ZEBRA-GHSA-MD-EXPORT registered in .auditooor/agent_pathspec.json
"""
ghsa-poc-inline-check.py
Rule 37 emit tier: tool utility (no corpus record emitted)

Gate for a GitHub Security Advisory (GHSA) ".advisory.md" paste. GitHub's
private "Report a vulnerability" form renders MARKDOWN and wants the PoC kept
INLINE (the opposite of HackenProof, where the PoC is shipped in a zip and the
draft body carries only a pointer). This gate validates that a .advisory.md is
a clean, paste-ready GHSA markdown body:

  - has the 4 fixed Advisory-Details sections in order:
        ### Summary / ### Details / ### PoC / ### Impact
  - keeps the PoC INLINE (the ### PoC body contains at least one fenced code
    block - the cargo/forge invocation and/or the executed transcript - and is
    NOT a pointer-to-zip / "see attached" stub)
  - has the 3 GHSA form sections: ## Affected products / ## Severity / ## Weaknesses
  - carries a CVSS:3.1 vector string
  - carries >=1 CWE id
  - contains 0 HTML comments (no leaked rebuttal markers)
  - contains 0 internal leaks (/Users/wolf, auditooor, internal labels) and no
    internal gate-only section headers (## Originality / ## Prior-Audit Supersede
    Scan / ## Rubric Row Mapping / ## Escalate-First Attempt)

RELATED TOOLS:
  - tools/ghsa-advisory-export.py emits the .advisory.md this gate validates.
  - tools/hackenproof-poc-zip-check.py is the inverse gate (PoC must be in a zip,
    body must be a pointer). GHSA = inline; HackenProof = zip. Do NOT confuse them.

Verdicts:
  pass-ghsa-md-inline-poc   : all checks pass.
  fail-no-inline-poc        : ### PoC has no inline fenced code block (or is a
                              pointer-to-zip stub).
  fail-html-comments        : an HTML comment is present anywhere in the body.
  fail-missing-section      : a required section / CVSS / CWE is missing.
  fail-internal-leak        : an internal path/label or gate-only section leaked.

Usage:
  python3 tools/ghsa-poc-inline-check.py <path.advisory.md> [--json] [--strict]
"""

import argparse
import json
import os
import re
import sys

# Order-sensitive required Advisory-Details subsections.
_REQUIRED_SUBSECTIONS = ["summary", "details", "poc", "impact"]

# Required GHSA form sections (## level).
_REQUIRED_FORM_SECTIONS = ["affected products", "severity", "weaknesses"]

# Internal gate-only sections that must NOT appear in the paste.
_INTERNAL_SECTION_HEADERS = (
    "originality",
    "prior-audit supersede scan",
    "prior audit supersede scan",
    "rubric row mapping",
    "escalate-first attempt",
)

# Internal-label / path residue that must not leak into a maintainer-facing body.
_INTERNAL_LEAK_RE = re.compile(
    r"/Users/wolf"
    r"|\bauditooor\b"
    r"|\bWorker-[A-Z]+\b"
    r"|\bcontext_pack_id\b"
    r"|\bcontext_pack_hash\b"
    r"|submissions/(?:paste_ready|staging|filed|held|superseded)/",
    re.IGNORECASE,
)

# Pointer-to-zip / "see attached" stubs that mean the PoC is NOT inline.
_POINTER_STUB_RE = re.compile(
    r"see\s+(?:the\s+)?attach|"
    r"poc(?:\s+is)?\s+(?:in|attached|bundled)\b|"
    r"-poc\.zip\b|"
    r"\.poc-transcript\.txt\b|"
    r"bundled\s+(?:zip|archive)|"
    r"see\s+the\s+(?:zip|archive)",
    re.IGNORECASE,
)

_CVSS_RE = re.compile(r"CVSS:3\.1/(?:[A-Z]{1,2}:[A-Z]/?)+")
_CWE_RE = re.compile(r"CWE-\d+")


def _iter_lines_with_fence_state(md):
    """Yield (line, in_fence) for each line; toggles on ``` / ~~~ fences."""
    in_fence = False
    fence_re = re.compile(r"^\s*(```|~~~)")
    for line in md.split("\n"):
        if fence_re.match(line):
            # the fence line itself is a boundary; report it as in_fence=True
            yield line, True
            in_fence = not in_fence
            continue
        yield line, in_fence


def _section_bodies(md):
    """Map level-3 header (lowercased, first word group) -> body text.

    Headers inside code fences are ignored.
    """
    bodies = {}
    order = []
    cur_key = None
    cur_buf = []
    h3_re = re.compile(r"^###\s+(.+?)\s*$")

    def _key(name):
        n = name.strip().lower()
        if n.startswith("summary"):
            return "summary"
        if n.startswith("details"):
            return "details"
        if n.startswith("poc") or "proof of concept" in n:
            return "poc"
        if n.startswith("impact"):
            return "impact"
        return None

    for line, in_fence in _iter_lines_with_fence_state(md):
        if not in_fence:
            m = h3_re.match(line)
            # also stop the current section body at a level-1/2 header
            if line.startswith("# ") or line.startswith("## "):
                if cur_key:
                    bodies[cur_key] = "\n".join(cur_buf).strip()
                cur_key = None
                cur_buf = []
                continue
            if m:
                if cur_key:
                    bodies[cur_key] = "\n".join(cur_buf).strip()
                k = _key(m.group(1))
                cur_key = k
                cur_buf = []
                if k and k not in order:
                    order.append(k)
                continue
        if cur_key:
            cur_buf.append(line)
    if cur_key:
        bodies[cur_key] = "\n".join(cur_buf).strip()
    return bodies, order


def _form_section_headers(md):
    """Return the list of lowercased `## ` headers (outside code fences)."""
    out = []
    for line, in_fence in _iter_lines_with_fence_state(md):
        if not in_fence and line.startswith("## "):
            out.append(line[3:].strip().lower())
    return out


def _has_inline_fence(body):
    """True if the body contains at least one fenced code block."""
    fence_re = re.compile(r"^\s*(```|~~~)", re.MULTILINE)
    return len(fence_re.findall(body)) >= 2  # need open + close


def check(md):
    failures = []
    # primary verdict precedence: html-comments -> internal-leak -> missing-section -> no-inline-poc
    verdict = "pass-ghsa-md-inline-poc"

    bodies, order = _section_bodies(md)
    form_headers = _form_section_headers(md)

    # --- HTML comments (outside code fences) ---
    html_comment = False
    for line, in_fence in _iter_lines_with_fence_state(md):
        if not in_fence and "<!--" in line:
            html_comment = True
            break

    # --- internal leaks ---
    leaked_sections = [h for h in form_headers
                       if any(h.startswith(s) for s in _INTERNAL_SECTION_HEADERS)]
    leak_hit = False
    for line, in_fence in _iter_lines_with_fence_state(md):
        if not in_fence and _INTERNAL_LEAK_RE.search(line):
            leak_hit = True
            break

    # --- required subsections in order ---
    missing_sub = [k for k in _REQUIRED_SUBSECTIONS if not bodies.get(k)]
    out_of_order = False
    if not missing_sub:
        present_order = [k for k in order if k in _REQUIRED_SUBSECTIONS]
        if present_order != _REQUIRED_SUBSECTIONS:
            out_of_order = True

    # --- required form sections ---
    missing_form = [s for s in _REQUIRED_FORM_SECTIONS
                    if not any(h.startswith(s) for h in form_headers)]

    # --- CVSS + CWE ---
    has_cvss = bool(_CVSS_RE.search(md))
    cwes = sorted(set(_CWE_RE.findall(md)))

    # --- inline PoC ---
    poc_body = bodies.get("poc", "")
    poc_inline = _has_inline_fence(poc_body)
    poc_pointer = bool(_POINTER_STUB_RE.search(poc_body)) and not poc_inline

    # Assemble failures (precedence order).
    if html_comment:
        failures.append("HTML comment present in advisory body")
    if leaked_sections:
        for s in leaked_sections:
            failures.append(f"internal gate-only section leaked: {s}")
    if leak_hit:
        failures.append("internal path/label residue in advisory body")
    if missing_sub:
        failures.append("missing/empty Advisory-Details subsection(s): "
                        + ", ".join(missing_sub))
    if out_of_order:
        failures.append("Advisory-Details subsections out of order "
                        "(want Summary/Details/PoC/Impact)")
    if missing_form:
        failures.append("missing GHSA form section(s): " + ", ".join(missing_form))
    if not has_cvss:
        failures.append("no CVSS:3.1 vector string found")
    if not cwes:
        failures.append("no CWE id found (>=1 required)")
    if not missing_sub and (not poc_inline or poc_pointer):
        if poc_pointer:
            failures.append("### PoC is a pointer-to-zip stub, not inline")
        else:
            failures.append("### PoC has no inline fenced code block")

    # verdict mapping
    if html_comment:
        verdict = "fail-html-comments"
    elif leaked_sections or leak_hit:
        verdict = "fail-internal-leak"
    elif missing_sub or out_of_order or missing_form or not has_cvss or not cwes:
        verdict = "fail-missing-section"
    elif not poc_inline or poc_pointer:
        verdict = "fail-no-inline-poc"
    else:
        verdict = "pass-ghsa-md-inline-poc"

    return {
        "schema": "auditooor.ghsa_poc_inline_check.v1",
        "verdict": verdict,
        "ok": verdict == "pass-ghsa-md-inline-poc",
        "failures": failures,
        "evidence": {
            "subsections_present": [k for k in _REQUIRED_SUBSECTIONS if bodies.get(k)],
            "form_sections": form_headers,
            "poc_inline_fence": poc_inline,
            "poc_pointer_stub": poc_pointer,
            "html_comments": html_comment,
            "internal_leak": bool(leaked_sections) or leak_hit,
            "cvss_present": has_cvss,
            "cwes": cwes,
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Validate a GHSA .advisory.md paste (markdown body with "
                    "inline PoC) for paste-readiness.")
    ap.add_argument("path", help="Path to the .advisory.md to validate.")
    ap.add_argument("--json", action="store_true", dest="emit_json")
    ap.add_argument("--strict", action="store_true",
                    help="Exit non-zero on any failure (default also exits "
                         "non-zero on fail; --strict is kept for parity).")
    args = ap.parse_args(argv)

    path = os.path.abspath(args.path)
    if not os.path.isfile(path):
        print(f"ERROR: file not found: {path}", file=sys.stderr)
        return 1
    with open(path, "r", encoding="utf-8") as f:
        md = f.read()

    res = check(md)
    if args.emit_json:
        print(json.dumps(res, indent=2))
    else:
        tag = "PASS" if res["ok"] else "FAIL"
        print(f"[{tag}] {res['verdict']}  {path}")
        for fl in res["failures"]:
            print(f"  FAIL: {fl}")
    return 0 if res["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
