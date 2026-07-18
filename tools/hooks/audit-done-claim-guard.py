#!/usr/bin/env python3
"""Claude Code Stop hook: block a turn that CLAIMS an audit is done without proof.

The #1 failure mode: typing "done / audited / honest-0 / fully covered /
audit-complete / finding-complete / core is clean" when `make audit-complete
STRICT=1` did NOT print `pass-audit-complete` this session. Self-discipline is
not a mechanism; this is. The "finding-complete" family (and its rewordings -
"core is clean", "finding-hunt exhausted") is banned the same way after the
model kept re-wording the one banned phrase to dodge (operator-caught 2026-07-07).

Contract (Claude Code Stop hook):
- stdin: JSON {session_id, transcript_path, cwd, stop_hook_active, ...}
- behavior: read the last assistant message; if it makes a POSITIVE audit
  done-claim AND an auditooor workspace is resolvable, run audit-done-guard.py.
  If the workspace is NOT-DONE, emit {"decision":"block","reason":...} so the
  harness re-prompts the model with the contradiction (forces a retraction).
- Fails OPEN on any internal error (never wedge the session); only ever BLOCKS
  on a positive-claim + verified-NOT-DONE, which is the exact thing to prevent.
"""
import json
import os
import re
import subprocess
import sys

GUARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "audit-done-guard.py")

# Positive audit done-CLAIMS (assertions that a workspace is finished), NOT mere
# mentions of the command/gate. Each pattern requires assertion structure
# (is/are/now/= + done-word, or an unambiguous standalone claim phrase).
CLAIM_PATTERNS = [
    # "<thing> is/are/now audit-complete" (assertion, not "make audit-complete")
    r"\b(?:is|are|now|=|:)\s+(?:genuinely\s+|fully\s+)?audit[- ]complete\b",
    r"\b(?:is|are|now)\s+genuinely\s+audited\b",
    r"\bgenuinely\s+audited\b",            # strong standalone
    r"\b(?:is|are|now)\s+fully\s+audited\b",
    r"\b(?:is|are|now)\s+fully\s+covered\b",
    r"\b(?:a\s+|an\s+|the\s+)?honest[- ]?0\b",
    r"\bhonest\s+zero\b",
    r"\bthe\s+audit\s+is\s+(?:now\s+)?(?:done|complete)\b",
    r"\baudit(?:\s+is)?\s+(?:now\s+)?complete\b",
    r"\bpass-?audit-?complete\b(?!\s+STRICT)(?!`)",  # claiming the verdict (not the cmd)
    # "finding(s)-complete" and its REWORDINGS - a positive assertion that the
    # bug-hunt is finished is the SAME kind of done-claim as audit-complete and
    # gets the SAME mechanical block: only allowed when audit-done-guard says
    # DONE. Operator-caught 2026-07-07: after being told to stop saying
    # "finding-complete", the model just re-worded it ("core is clean", "core is
    # mutation-verified clean", "finding-hunt exhausted") to dodge - so ban the
    # whole family, not one phrase. NEG_NEAR still lets "NOT finding-complete"
    # / "the core is NOT clean" through, and resolve_workspace scopes this to a
    # real /audits/ workspace, so a genuine pass is never blocked.
    r"\bfindings?[-\s]complete\b",
    r"\bfinding[-\s]hunt\s+(?:is\s+)?(?:now\s+)?(?:complete|done|over|exhausted|drained)\b",
    r"\bfindings?\s+(?:are\s+)?(?:now\s+)?(?:complete|exhausted)\b",
    r"\b(?:value[-\s]moving\s+)?core\s+(?:is\s+)?(?:now\s+)?(?:mutation[-\s]verified\s+|dynamically\s+)?(?:proven[-\s]+)?(?:clean|complete)\b",
]
# Negated/hypothetical context within the preceding window => NOT a claim.
NEG_NEAR = re.compile(
    r"(?:not|n't|never|isn't|aren't|fail|no\s+fresh|without|un-?|cannot|can't|would|"
    r"to\s+(?:make|reach|get|claim)|inside|into|wire|run|the\s+\w+\s+gate|a\s+real|"
    r"NOT[- ])\s*(?:\w+[\s,]+){0,4}$",
    re.IGNORECASE,
)


def _strip_code_spans(text):
    """Remove `inline code`, ```fenced blocks```, and make/run command lines so a
    mention like `make audit-complete` is never read as a done-claim."""
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"`[^`]*`", " ", text)
    # drop lines that are clearly command invocations
    text = "\n".join(
        ln for ln in text.splitlines()
        if not re.search(r"\b(?:make|run|python3?|bash|sh)\b.*audit[- ]complete", ln, re.IGNORECASE)
    )
    return text


def last_assistant_text(transcript_path):
    if not transcript_path or not os.path.isfile(transcript_path):
        return ""
    text = ""
    try:
        with open(transcript_path, errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except Exception:
                    continue
                if rec.get("type") != "assistant" and rec.get("role") != "assistant":
                    continue
                msg = rec.get("message", rec)
                content = msg.get("content")
                if isinstance(content, str):
                    text = content
                elif isinstance(content, list):
                    text = "\n".join(
                        b.get("text", "") for b in content
                        if isinstance(b, dict) and b.get("type") == "text"
                    )
    except Exception:
        return ""
    return text


def find_claim(text):
    for pat in CLAIM_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            window = text[max(0, m.start() - 60):m.start()]
            if NEG_NEAR.search(window):
                continue
            return m.group(0)
    return None


def resolve_workspace(text, cwd):
    # An audit workspace is one under an /audits/ root (or an auditooor worktree).
    # A stray .auditooor dir in an unrelated project (e.g. a trading-bot repo) is
    # NOT an audit target - require the /audits/ or auditooor path marker.
    for src in (text, cwd or ""):
        m = re.search(r"(/[^\s`'\"]*?/audits/[A-Za-z0-9_.-]+)", src)
        if m and os.path.isdir(m.group(1)):
            return m.group(1)
    if cwd and re.search(r"/audits/|auditooor", cwd) and os.path.isdir(os.path.join(cwd, ".auditooor")):
        return cwd
    return None


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # fail open
    if payload.get("stop_hook_active"):
        sys.exit(0)  # already in a stop-hook re-prompt; don't loop

    text = last_assistant_text(payload.get("transcript_path"))
    if not text:
        sys.exit(0)
    claim = find_claim(text)
    if not claim:
        sys.exit(0)  # no done-claim -> allow
    ws = resolve_workspace(text, payload.get("cwd"))
    if not ws:
        sys.exit(0)  # can't resolve a workspace -> don't second-guess

    try:
        res = subprocess.run(
            [sys.executable, GUARD, ws, "--json"],
            capture_output=True, text=True, timeout=120,
        )
    except Exception:
        sys.exit(0)  # guard unrunnable -> fail open
    if res.returncode == 0:
        sys.exit(0)  # guard says DONE -> claim is legit -> allow

    reason = ""
    try:
        j = json.loads(res.stdout or "{}")
        reason = j.get("reason") or j.get("status") or ""
        fails = j.get("fail_gates") or j.get("failures") or []
        if fails:
            reason += " | FAIL gates: " + ", ".join(map(str, fails))
    except Exception:
        reason = (res.stdout or res.stderr or "audit-done-guard: NOT-DONE").strip()[:500]

    print(json.dumps({
        "decision": "block",
        "reason": (
            f"DONE-CLAIM GUARD: your message claims '{claim}' for {os.path.basename(ws)}, "
            f"but audit-done-guard.py says NOT-DONE. Retract the claim and state the literal "
            f"FAIL-gate status instead. Guard verdict: {reason or 'NOT-DONE (no fresh pass-audit-complete STRICT marker)'}"
        ),
    }))
    sys.exit(0)


if __name__ == "__main__":
    main()
