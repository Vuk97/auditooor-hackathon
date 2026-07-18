#!/usr/bin/env python3
"""poc-transcript-check.py - a submission that CLAIMS a runnable PoC PASS must carry the
actual execution TRANSCRIPT (the run command + its output showing the result) AND a plain
statement of WHAT THE POC PROVES.

MOTIVATION (2026-07-05, operator-caught): pre-submit-check verified that PoC *code* is
inline (Check #4c) and that a forge test *passes* when run (Check #10), but nothing
verified that a submission claiming "the PoC PASSES" actually embeds the run transcript
(command + captured PASS/ok/assert output) and a one-line summary of the assertion. A
"PoC PASSES" claim with no transcript is theater - the reviewer cannot see the run.

This check fires ONLY when the submission claims a run occurred (so pure-reasoning or
honestly-narrowed findings are unaffected). When a run is claimed it requires BOTH:
  (1) an execution transcript - a fenced code block containing a run COMMAND token
      (go test / forge test / medusa / echidna / cargo test / pytest / halmos / a shell
      `$ ...`) AND a RESULT token (PASS / FAIL / ok / --- PASS / panic / assertion / X
      passed) - OR a sibling transcript file in the submission folder
      (*poc*transcript*, *.poc-transcript*, poc/*.txt, *_transcript.txt);
  (2) a WHAT-IT-PROVES summary - a sentence stating what the PoC demonstrates/asserts.

rc 0 = present (or no run claimed); rc 1 = run claimed but transcript or summary missing.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# The submission asserts a PoC was actually RUN (not merely written).
_RUN_CLAIM_RX = re.compile(
    r"\b(poc\s+pass|passes|passed|--- pass|\bok\b\s+\S*\btest|"
    r"go test|forge test|medusa|echidna|cargo test|pytest|halmos|"
    r"runnable poc|executed poc|poc.{0,20}\bpass|test.{0,20}\bpass)",
    re.I,
)
# A run COMMAND appears in a transcript.
_CMD_RX = re.compile(
    r"(go\s+test|forge\s+test|medusa\b|echidna\b|cargo\s+test|pytest\b|halmos\b|"
    r"^\s*\$\s+\S|python3?\s+\S+\.py)",
    re.I | re.M,
)
# A run RESULT appears in a transcript.
_RESULT_RX = re.compile(
    r"(---\s*PASS|^\s*PASS\b|\[\s*PASS\s*\]|\[\s*FAIL\s*\]|\[\s*SKIP\s*\]|"
    r"^\s*ok\s+\S|\bFAIL\b|\d+\s+pass(ed|ing)?|"
    r"\bpanic\b|assert(ion)?|counterexample|\bexit\s*(code\s*)?0\b|coverage:)",
    re.I | re.M,
)
# A WHAT-IT-PROVES summary sentence.
_PROVES_RX = re.compile(
    r"(prov(e|es|ing|en)|demonstrat|assert|shows?\s+that|confirms?|"
    r"the (test|poc|harness)\s+\w+|verif(y|ies|ied))",
    re.I,
)
_FENCE_RX = re.compile(r"```[^\n]*\n(.*?)```", re.S)
_TRANSCRIPT_GLOBS = (
    "*poc*transcript*", "*.poc-transcript*", "*_transcript.txt",
    "poc/*.txt", "poc/*.log", "*poc*.log",
)


def _sibling_transcript(md: Path) -> Path | None:
    folder = md.parent
    for pat in _TRANSCRIPT_GLOBS:
        for f in folder.glob(pat):
            if f.is_file() and f.stat().st_size > 20:
                try:
                    t = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if _RESULT_RX.search(t):
                    return f
    return None


def _embedded_transcript(text: str) -> bool:
    for block in _FENCE_RX.findall(text):
        if _CMD_RX.search(block) and _RESULT_RX.search(block):
            return True
    return False


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: poc-transcript-check.py <submission.md>", file=sys.stderr)
        return 2
    md = Path(sys.argv[1])
    if not md.is_file():
        print(f"file not found: {md}", file=sys.stderr)
        return 2
    text = md.read_text(encoding="utf-8", errors="replace")

    if not _RUN_CLAIM_RX.search(text):
        print("no runnable-PoC-PASS claim -> transcript not required (reasoning/narrowed finding)")
        return 0

    missing = []
    transcript_ok = _embedded_transcript(text)
    sib = None
    if not transcript_ok:
        sib = _sibling_transcript(md)
        transcript_ok = sib is not None
    if not transcript_ok:
        missing.append(
            "EXECUTION TRANSCRIPT - the submission claims a PoC PASS but no run transcript "
            "is present. Embed a fenced code block with the run command (e.g. `go test "
            "./evmrpc/ -run ...`) AND its captured output (--- PASS / ok / assertion), or "
            "add a sibling *poc-transcript*.txt in the submission folder.")

    if not _PROVES_RX.search(text):
        missing.append(
            "WHAT-IT-PROVES SUMMARY - add a sentence stating what the PoC "
            "demonstrates/asserts (e.g. 'the test proves len(a.filters) grows to N with "
            "zero rejections and no eviction within the timeout').")

    if missing:
        print("POC-TRANSCRIPT gate FAILED (a claimed PoC PASS needs its receipts):")
        for m in missing:
            print(f"  - {m}")
        return 1

    where = "embedded fenced transcript" if _embedded_transcript(text) else f"sibling {sib.name}"
    print(f"POC-TRANSCRIPT OK: run transcript present ({where}) + what-it-proves summary present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
