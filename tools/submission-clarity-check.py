#!/usr/bin/env python3
"""submission-clarity-check.py - enforce that a paste-ready/filed finding READS clearly.

WHY THIS EXISTS (2026-07-06, operator observation): our SEI evmrpc-filter-DoS Medium
passed every one of pre-submit-check.sh's ~130 gates yet a DUPLICATE report of the SAME
bug was judged clearer. The difference was pure PRESENTATION, not correctness:

  * the winning report LED with a 4-sentence plain-English "The Bug" summary; ours opened
    with 9 HTML rebuttal comments + a Severity block before any human sentence;
  * the winning report had a crisp "what the exploit demonstrates" + a measured impact
    table; ours buried "it proves the two mechanism claims" inside dense PoC prose.

pre-submit-check.sh enforces IMPACT / SCOPE / SEVERITY correctness exhaustively but has
ZERO readability gate. submissions-lint.py requires a `## Summary` but only runs on the
internal SUBMISSIONS.md / submissions/clean/ authoring format - NOT on the paste_ready /
filed docs that pre-submit-check.sh actually gates. So a filed finding can (and did) ship
with no lead Summary and no named "what the PoC proves" section.

This check closes that gap for ANY finding markdown, language-agnostic. Advisory-first
(warn, never hard-block a correct finding) unless --strict. Three clarity signals:

  C1 lead-summary      - a `## Summary` / `## The Bug` / `## TL;DR` / `## Overview`
                         (or `## Finding Description`) H2 appears BEFORE the heavy
                         machinery (Impact Contract / Program Impact Mapping / Escalation
                         / Exploitability Ledger / Configured-Impact) AND its body is
                         >=2 plain-English sentences that cite >=1 concrete `file.ext:line`.
  C2 what-poc-proves   - if the finding cites a PoC, it states in plain English what that
                         PoC/test PROVES (a named `## What the PoC proves` section is best;
                         an explicit "this PoC proves ... " sentence is accepted with a
                         nudge to promote it to a section).
  C3 lead-readability  - the doc does NOT open with a wall of >=2 HTML rebuttal comments
                         before the first human sentence; lead with the narrative, put the
                         `<!-- *-rebuttal -->` markers BELOW the summary.

Verdicts: pass-clarity | warn-clarity-issues | fail-missing-file | fail-empty. Exit 1 on a
fail-* always; on warn-* only under --strict. Emits a JSON verdict (--json) and always
writes <ws>/.auditooor/submission_clarity_report.json when --workspace is resolvable.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# H2/H3 titles (lower-cased, punctuation-stripped) that count as a lead SUMMARY.
_SUMMARY_TITLES = (
    "summary", "the bug", "tldr", "tl dr", "overview", "finding description",
    "finding summary", "what happened", "in short",
)
# Headings that mark the START of the heavy correctness machinery. A summary must
# appear BEFORE the first of these to actually lead the document.
_MACHINERY_TITLES = (
    "impact contract", "program impact mapping", "rubric row mapping",
    "escalation analysis", "exploitability ledger", "configured-impact trace",
    "impact characterization", "downstream consumer trace", "reachability trace",
)
# A PoC section (its presence makes C2 applicable).
_POC_TITLE_RE = re.compile(r"\b(proof of concept|poc|exploit|reproduc)", re.IGNORECASE)
# A named "what the PoC/test proves" section.
_PROVES_TITLE_RE = re.compile(
    r"what (the )?(poc|test|tests|exploit|harness)\s+(prove|demonstrate|show)", re.IGNORECASE)
# An inline plain-English proves-claim (accepted, nudged to a section).
_PROVES_INLINE_RE = re.compile(
    r"\b(this poc|the poc|the test|this test|it)\s+(prove|proves|demonstrate|demonstrates|"
    r"establish|establishes|show|shows)\b", re.IGNORECASE)
# A named recommendation / mitigation / fix section (C4). A finding must tell the
# protocol how to fix it - a triager and the fixing dev both look for this heading.
_RECO_TITLE_RE = re.compile(
    r"\b(recommendation|recommendations|recommended fix|mitigation|remediation|"
    r"suggested fix|how to fix|the fix|proposed fix)\b", re.IGNORECASE)
_FILE_LINE_RE = re.compile(r"[\w./-]+\.[A-Za-z0-9_]+:L?\d+")
_HTML_COMMENT_RE = re.compile(r"^\s*<!--.*?-->\s*$")
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_SENTENCE_SPLIT_RE = re.compile(r"[.!?](?:\s|$)")


def _norm_title(t: str) -> str:
    return re.sub(r"[^a-z0-9 ]", "", t.lower()).strip()


def _headings(text: str):
    """Return [(line_index, level, normalized_title, raw_title)] in document order."""
    out = []
    for i, ln in enumerate(text.splitlines()):
        m = _HEADING_RE.match(ln)
        if m:
            out.append((i, len(m.group(1)), _norm_title(m.group(2)), m.group(2)))
    return out


def _section_body(lines: list[str], start_line: int) -> str:
    """Text between the heading at start_line and the next heading."""
    body = []
    for ln in lines[start_line + 1:]:
        if _HEADING_RE.match(ln):
            break
        body.append(ln)
    return "\n".join(body)


def _plain_sentences(body: str) -> int:
    """Count plain-English sentences, ignoring code fences / bullet-only rubric quotes."""
    # Strip fenced code blocks and blockquotes (verbatim rubric rows are not prose).
    no_code = re.sub(r"```.*?```", " ", body, flags=re.DOTALL)
    no_quote = "\n".join(l for l in no_code.splitlines() if not l.lstrip().startswith(">"))
    prose = " ".join(l for l in no_quote.splitlines()
                     if l.strip() and not l.lstrip().startswith(("<!--", "|", "-", "*", "#")))
    if not prose.strip():
        # Fall back: allow bullet prose (some summaries are bulleted), but require length.
        prose = " ".join(l.lstrip("-*").strip() for l in no_quote.splitlines()
                         if l.strip() and not l.lstrip().startswith(("<!--", "|", "#")))
    return len([s for s in _SENTENCE_SPLIT_RE.split(prose) if len(s.split()) >= 4])


def evaluate(md_text: str) -> dict:
    """Return a clarity verdict dict for a finding markdown body."""
    res = {"verdict": "pass-clarity", "warnings": [], "signals": {}}
    if not md_text.strip():
        res["verdict"] = "fail-empty"
        res["warnings"] = ["finding markdown is empty"]
        return res
    lines = md_text.splitlines()
    heads = _headings(md_text)

    # --- machinery boundary (first heavy-correctness heading) ---
    machinery_line = None
    for (ln, _lvl, nt, _raw) in heads:
        if any(nt.startswith(m) or m in nt for m in _MACHINERY_TITLES):
            machinery_line = ln
            break

    # --- C1: lead-summary ---
    summary_head = None
    for (ln, lvl, nt, raw) in heads:
        if lvl >= 2 and any(nt == s or nt.startswith(s + " ") or nt == s.replace(" ", "")
                            for s in _SUMMARY_TITLES):
            summary_head = (ln, raw)
            break
    if summary_head is None:
        res["signals"]["lead_summary"] = "absent"
        res["warnings"].append(
            "C1 no lead Summary: add a `## Summary` (or `## The Bug` / `## TL;DR`) H2 near the "
            "TOP with 2-6 plain-English sentences (what breaks, where by file:line, who is "
            "impacted, how triggered) - the reader should grasp the bug before any rubric/rebuttal.")
    else:
        ln, raw = summary_head
        body = _section_body(lines, ln)
        after_machinery = machinery_line is not None and ln > machinery_line
        n_sent = _plain_sentences(body)
        has_cite = bool(_FILE_LINE_RE.search(body))
        if after_machinery:
            res["signals"]["lead_summary"] = "present-but-late"
            res["warnings"].append(
                f"C1 Summary `{raw}` appears AFTER the correctness machinery - move it above "
                "the Impact Contract / Escalation blocks so it LEADS the document.")
        elif n_sent < 2:
            res["signals"]["lead_summary"] = "too-thin"
            res["warnings"].append(
                f"C1 Summary `{raw}` is too thin ({n_sent} plain sentence(s)) - give 2-6 sentences "
                "of plain English, not just a rubric quote.")
        elif not has_cite:
            res["signals"]["lead_summary"] = "no-cite"
            res["warnings"].append(
                f"C1 Summary `{raw}` cites no concrete `file.ext:line` - name where the bug lives "
                "so it reads as a real finding, not an abstraction.")
        else:
            res["signals"]["lead_summary"] = "ok"

    # --- C2: what-the-PoC-proves (only if a PoC is cited) ---
    has_poc = any(_POC_TITLE_RE.search(raw) for (_ln, _lvl, _nt, raw) in heads) or \
        bool(re.search(r"---\s*PASS:|proof.?of.?concept|\bPoC\b", md_text))
    if has_poc:
        named_section = any(_PROVES_TITLE_RE.search(raw) for (_ln, _lvl, _nt, raw) in heads)
        inline_claim = bool(_PROVES_INLINE_RE.search(md_text))
        if named_section:
            res["signals"]["what_poc_proves"] = "ok-section"
        elif inline_claim:
            res["signals"]["what_poc_proves"] = "inline-only"
            res["warnings"].append(
                "C2 the PoC's proof-claim is only inline prose - promote it to a named "
                "`## What the PoC proves` section that maps each test to the exact claim it "
                "establishes (e.g. 'test A proves creation never caps; test B proves the reaper "
                "evicts only by staleness'). Copy-paste readers scan for this heading.")
        else:
            res["signals"]["what_poc_proves"] = "absent"
            res["warnings"].append(
                "C2 finding cites a PoC but never states what it PROVES: add a "
                "`## What the PoC proves` section mapping each test to the claim it establishes.")
    else:
        res["signals"]["what_poc_proves"] = "n/a-no-poc"

    # --- C3: lead-readability (no comment wall before the first human sentence) ---
    comment_run = 0
    first_prose_after_comments = None
    seen_h1 = False
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        if _HEADING_RE.match(ln):
            if not seen_h1:
                seen_h1 = True
                continue
            # a heading (other than H1) reached before prose -> stop scanning the lead
            break
        if _HTML_COMMENT_RE.match(ln):
            if seen_h1:
                comment_run += 1
            continue
        # first real prose line after the H1
        first_prose_after_comments = s
        break
    if comment_run >= 2 and first_prose_after_comments is None:
        res["signals"]["lead_readability"] = "comment-wall"
        res["warnings"].append(
            f"C3 the document opens with {comment_run} HTML rebuttal comment(s) before any human "
            "sentence - lead with the Summary narrative and move the `<!-- *-rebuttal -->` markers "
            "BELOW it (they are for the gate, not the reader).")
    else:
        res["signals"]["lead_readability"] = "ok"

    # --- C4: recommendation / mitigation section ---
    # Every finding must tell the protocol HOW to fix it. A triager and the fixing dev both
    # scan for this heading; a submission that proves a bug but never states the fix reads as
    # incomplete. Advisory (warn) - promote to fail under L37 if desired.
    reco_section = any(_RECO_TITLE_RE.search(raw) for (_ln, _lvl, _nt, raw) in heads)
    if reco_section:
        res["signals"]["recommendation"] = "ok-section"
    else:
        res["signals"]["recommendation"] = "absent"
        res["warnings"].append(
            "C4 no recommendation/mitigation section: add a `## Recommendation` (or "
            "`## Mitigation`) H2 stating the concrete fix (name the file:line and the code "
            "change). A triager and the fixing dev both look for this heading.")

    if res["warnings"]:
        res["verdict"] = "warn-clarity-issues"
    return res


def _resolve_finding_md(path: Path) -> Path | None:
    if path.is_file() and path.suffix == ".md":
        return path
    if path.is_dir():
        # per-finding folder: prefer <folder>/<folder>.md then any single .md
        cand = path / f"{path.name}.md"
        if cand.is_file():
            return cand
        mds = [p for p in path.glob("*.md")]
        if len(mds) == 1:
            return mds[0]
    return None


def _find_ws_root(start: Path) -> Path | None:
    cur = start if start.is_dir() else start.parent
    for _ in range(8):
        if (cur / "SCOPE.md").exists() or (cur / "OOS_CHECKLIST.md").exists() or (cur / ".auditooor").is_dir():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def main(argv) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("finding", help="finding .md file OR per-finding folder OR workspace")
    ap.add_argument("--workspace", help="workspace root (for artifact write); inferred if omitted")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="exit 1 on warn-* too")
    args = ap.parse_args(argv)

    p = Path(args.finding).expanduser().resolve()
    md = _resolve_finding_md(p)
    if md is None:
        out = {"verdict": "fail-missing-file", "warnings": [f"no finding .md at {p}"], "signals": {}}
        print(json.dumps(out, indent=2) if args.json else f"fail-missing-file\t{p}")
        return 1
    res = evaluate(md.read_text(encoding="utf-8", errors="replace"))
    res["finding"] = str(md)

    ws = Path(args.workspace).expanduser().resolve() if args.workspace else _find_ws_root(md)
    if ws and (ws / ".auditooor").is_dir():
        try:
            (ws / ".auditooor" / "submission_clarity_report.json").write_text(
                json.dumps(res, indent=2), encoding="utf-8")
        except OSError:
            pass

    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"{res['verdict']}\t{md.name}")
        for w in res["warnings"]:
            print(f"  - {w}")
    if res["verdict"].startswith("fail-"):
        return 1
    if args.strict and res["verdict"].startswith("warn-"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
