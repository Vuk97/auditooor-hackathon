#!/usr/bin/env python3
"""Claude Code Stop hook: block an INTERIM audit-progress claim made WITHOUT
running the tick's conformance anchor.

Sibling of `audit-done-claim-guard.py`. That hook blocks a FINAL
done / honest-0 claim; this one closes the adjacent gap: a per-tick claim
("hunt drained", "step-3 done", "progressing per README", "audited",
"coverage complete", "X% covered") typed WITHOUT actually running the anchor
that would substantiate progress that tick - i.e. `tools/audit-next-step.py`
or `tools/readme-conformance-check.py` for the workspace.

Contract (Claude Code Stop hook):
- stdin: JSON {session_id, transcript_path, cwd, stop_hook_active, ...}
- behavior: read the last assistant turn's text; if it makes a positive
  AUDIT-PROGRESS claim AND an auditooor workspace is resolvable AND the SAME
  turn's tool output does NOT show the anchor ran, emit
  {"decision":"block","reason":...} so the harness re-prompts the model to
  either run the anchor or retract the progress claim.
- Fails OPEN on any internal error, when no audit workspace is in play, when no
  progress-claim is detected, or when the anchor did run - never wedges an
  ordinary turn. It only ever BLOCKS on progress-claim + audit-ws + anchor-absent.

Reuses `audit-done-claim-guard`'s workspace resolver and code-span stripper so
the two hooks agree on "is this an audit workspace" and never read a `make`
mention as a claim.
"""
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)

try:
    # Reuse the sibling hook's helpers - single source of truth for ws-detection
    # and code-span stripping. Import by file (hyphenated module name).
    import importlib.util as _ilu

    _spec = _ilu.spec_from_file_location(
        "audit_done_claim_guard",
        os.path.join(_HERE, "audit-done-claim-guard.py"),
    )
    _dcg = _ilu.module_from_spec(_spec)
    _spec.loader.exec_module(_dcg)
    _strip_code_spans = _dcg._strip_code_spans
    _resolve_workspace = _dcg.resolve_workspace
except Exception:  # pragma: no cover - fall back to local copies if import fails
    _dcg = None

    def _strip_code_spans(text):
        text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
        text = re.sub(r"`[^`]*`", " ", text)
        return "\n".join(
            ln for ln in text.splitlines()
            if not re.search(r"\b(?:make|run|python3?|bash|sh)\b.*audit[- ]complete",
                             ln, re.IGNORECASE)
        )

    def _resolve_workspace(text, cwd):
        for src in (text, cwd or ""):
            m = re.search(r"(/[^\s`'\"]*?/audits/[A-Za-z0-9_.-]+)", src)
            if m and os.path.isdir(m.group(1)):
                return m.group(1)
        if cwd and re.search(r"/audits/|auditooor", cwd) and \
                os.path.isdir(os.path.join(cwd, ".auditooor")):
            return cwd
        return None


# Per-tick AUDIT-PROGRESS claims. These are interim "I made progress" assertions
# distinct from the terminal done-claims the sibling hook owns. Kept tight to a
# progress verb/phrase so ordinary prose never trips them.
PROGRESS_PATTERNS = [
    r"\bhunt\s+(?:is\s+)?(?:now\s+)?drained\b",
    r"\bhunt\s+(?:is\s+)?(?:now\s+)?done\b",
    r"\bqueue\s+(?:is\s+)?(?:now\s+)?drained\b",
    r"\bstep[-\s]?[0-9][a-z]?\s+(?:is\s+)?(?:now\s+)?(?:done|complete|passed|green)\b",
    r"\b(?:is|are|now)\s+progressing\s+per\s+(?:the\s+)?readme\b",
    r"\bprogressing\s+per\s+(?:the\s+)?readme\b",
    r"\b(?:is|are|now)\s+audited\b",
    r"\bcoverage\s+(?:is\s+)?(?:now\s+)?complete\b",
    # "N% covered" used as a done-flavored claim (e.g. "100% covered", "fully covered")
    r"\b(?:100|fully)\s*%?\s+covered\b",
    r"\b\d{1,3}\s*%\s+covered\b",
]

# Negated / hypothetical context in the preceding window => not a claim.
NEG_NEAR = re.compile(
    r"(?:not|n't|never|isn't|aren't|fail|no\s+fresh|without|un-?|cannot|can't|would|"
    r"need\s+to|have\s+to|to\s+(?:make|reach|get|claim|drain|cover)|once|until|"
    r"NOT[- ])\s*(?:\w+[\s,]+){0,4}$",
    re.IGNORECASE,
)

# Evidence in this turn's tool output that the conformance anchor actually ran.
ANCHOR_RUN = re.compile(
    r"audit-next-step\.py|readme-conformance-check\.py|"
    r"audit_next_step\.py|readme_conformance_check\.py",
    re.IGNORECASE,
)


def _iter_records(transcript_path):
    if not transcript_path or not os.path.isfile(transcript_path):
        return
    try:
        with open(transcript_path, errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except Exception:
        return


def _rec_role(rec):
    return rec.get("type") or rec.get("role") or ""


def _is_real_user_prompt(rec):
    """True only for a genuine human user message, NOT a tool_result record.

    In a Claude Code turn, tool_result blocks are carried on `user`-role records.
    The turn boundary is the last GENUINE human prompt, so those must not count -
    otherwise a tool_result would falsely reset the turn and hide the tool_use
    that produced it.
    """
    if _rec_role(rec) != "user":
        return False
    msg = rec.get("message", rec)
    content = msg.get("content")
    if isinstance(content, str):
        return True  # plain human text
    if isinstance(content, list):
        # a real prompt has text/image blocks; a tool echo has tool_result blocks
        for b in content:
            if isinstance(b, dict) and b.get("type") in ("tool_result", "tool_use"):
                return False
        return True
    return False


def last_assistant_text(records):
    """Text of the final assistant message in the transcript."""
    text = ""
    for rec in records:
        if _rec_role(rec) not in ("assistant",):
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
    return text


def _flatten(obj):
    """Flatten a record's tool-bearing content into a searchable string."""
    out = []

    def walk(x):
        if isinstance(x, str):
            out.append(x)
        elif isinstance(x, dict):
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(obj)
    return "\n".join(out)


def anchor_ran_this_turn(records):
    """True if the current turn's tool activity shows the anchor ran.

    'Current turn' = records at/after the last user message. We scan tool_use
    inputs (the command that was run) and tool_result outputs for the anchor
    script name. Both the Bash command and its stdout are captured in the
    transcript, so either witnesses a run.
    """
    # Find the index of the last GENUINE human prompt; the turn is everything
    # after it (tool_result records are user-role but belong to the turn).
    last_user = -1
    for i, rec in enumerate(records):
        if _is_real_user_prompt(rec):
            last_user = i
    turn = records[last_user + 1:] if last_user >= 0 else records
    for rec in turn:
        role = _rec_role(rec)
        # tool_use lives in assistant messages; tool_result in user messages,
        # but we already restricted to post-last-user records for the current
        # turn. Scan every record's content blocks generically.
        msg = rec.get("message", rec)
        content = msg.get("content")
        blob = ""
        if isinstance(content, list):
            for b in content:
                if not isinstance(b, dict):
                    continue
                btype = b.get("type")
                if btype in ("tool_use", "tool_result", "server_tool_use",
                             "web_search_tool_result"):
                    blob += "\n" + _flatten(b)
        elif isinstance(content, str) and role not in ("assistant",):
            # a stringified tool_result carried on a user record
            blob += "\n" + content
        # also catch top-level toolUseResult side-channel some transcripts use
        if "toolUseResult" in rec:
            blob += "\n" + _flatten(rec.get("toolUseResult"))
        if blob and ANCHOR_RUN.search(blob):
            return True
    return False


def find_progress_claim(text):
    for pat in PROGRESS_PATTERNS:
        for m in re.finditer(pat, text, re.IGNORECASE):
            window = text[max(0, m.start() - 60):m.start()]
            if NEG_NEAR.search(window):
                continue
            return m.group(0)
    return None


def evaluate(payload):
    """Pure decision function (testable). Returns (decision_dict_or_None)."""
    if payload.get("stop_hook_active"):
        return None  # already in a stop-hook re-prompt; don't loop
    records = list(_iter_records(payload.get("transcript_path")))
    if not records:
        return None
    text = last_assistant_text(records)
    if not text:
        return None
    claim = find_progress_claim(_strip_code_spans(text))
    if not claim:
        return None  # no progress-claim -> allow
    ws = _resolve_workspace(text, payload.get("cwd"))
    if not ws:
        return None  # not an audit workspace -> allow
    if anchor_ran_this_turn(records):
        return None  # anchor ran this tick -> claim is substantiated -> allow
    return {
        "decision": "block",
        "reason": (
            f"TICK-HONESTY GUARD: your message claims audit progress "
            f"('{claim}') for {os.path.basename(ws)}, but this turn did NOT run the "
            f"conformance anchor (tools/audit-next-step.py or "
            f"tools/readme-conformance-check.py). Interim progress must be anchored, "
            f"not eyeballed from memory. Run "
            f"`python3 tools/audit-next-step.py {ws} --json` (or "
            f"readme-conformance-check.py) and report its actual verdict, or retract "
            f"the progress claim."
        ),
    }


def main():
    try:
        payload = json.load(sys.stdin)
    except Exception:
        sys.exit(0)  # fail open
    try:
        decision = evaluate(payload)
    except Exception:
        sys.exit(0)  # fail open on any internal error
    if decision:
        print(json.dumps(decision))
    sys.exit(0)


if __name__ == "__main__":
    main()
