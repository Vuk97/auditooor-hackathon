#!/usr/bin/env python3
"""Regression tests for the per-tick audit-progress honesty Stop hook.

Cases:
  (i)   progress-claim turn, NO anchor in tool output          -> BLOCK
  (ii)  same claim WITH audit-next-step.py in tool output      -> ALLOW
  (iii) ordinary non-progress turn                             -> ALLOW (no false block)
  (iv)  progress-claim but NOT an audit workspace              -> ALLOW
Stdlib-only. Runnable directly (prints ok/FAIL) or under pytest/unittest.
"""
import importlib.util
import json
import os
import tempfile

_HERE = os.path.dirname(os.path.abspath(__file__))
_MOD = os.path.join(_HERE, "..", "hooks", "audit-tick-honesty-guard.py")
spec = importlib.util.spec_from_file_location("audit_tick_honesty_guard", _MOD)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def _write_transcript(records):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    return path


def _make_ws():
    """A real /audits/<ws> dir with a .auditooor marker so the resolver bites."""
    root = tempfile.mkdtemp()
    ws = os.path.join(root, "audits", "faketarget")
    os.makedirs(os.path.join(ws, ".auditooor"), exist_ok=True)
    return ws


def _user(text):
    return {"type": "user", "message": {"role": "user", "content": text}}


def _assistant_text(text):
    return {"type": "assistant", "message": {"role": "assistant",
            "content": [{"type": "text", "text": text}]}}


def _assistant_tool_use(cmd):
    return {"type": "assistant", "message": {"role": "assistant", "content": [
        {"type": "tool_use", "name": "Bash", "input": {"command": cmd}}]}}


def _tool_result(text):
    return {"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "content": [{"type": "text", "text": text}]}]}}


def _eval(records, ws):
    path = _write_transcript(records)
    try:
        return g.evaluate({"transcript_path": path, "cwd": ws})
    finally:
        os.unlink(path)


CLAIM = "The hunt is now drained and step-3 is complete for this workspace."


def test_i_progress_claim_no_anchor_blocks():
    ws = _make_ws()
    records = [_user("keep going"), _assistant_text(CLAIM + " " + ws)]
    d = _eval(records, ws)
    assert d and d.get("decision") == "block", d


def test_ii_progress_claim_with_anchor_allows():
    ws = _make_ws()
    records = [
        _user("keep going"),
        _assistant_tool_use(f"python3 tools/audit-next-step.py {ws} --json"),
        _tool_result("NEXT REQUIRED STEP = step-3 ... DONE"),
        _assistant_text(CLAIM + " " + ws),
    ]
    d = _eval(records, ws)
    assert d is None, d


def test_iii_ordinary_turn_allows():
    ws = _make_ws()
    records = [
        _user("what does this function do?"),
        _assistant_text("This function computes the net APR from the tranche split. "
                        "It reads two storage slots and returns the difference."),
    ]
    d = _eval(records, ws)
    assert d is None, d


def test_iv_non_audit_ws_allows():
    # Progress-claim phrasing but cwd is a non-/audits/ project -> no ws -> allow.
    records = [_user("keep going"),
               _assistant_text("The hunt is now drained and step-3 is complete.")]
    path = _write_transcript(records)
    try:
        d = g.evaluate({"transcript_path": path,
                        "cwd": "/Users/wolf/Downloads/polymarket/clob2"})
    finally:
        os.unlink(path)
    assert d is None, d


def test_v_negated_progress_is_not_a_claim():
    ws = _make_ws()
    records = [_user("status?"),
               _assistant_text(f"The hunt is NOT drained yet for {ws}; step-3 is still RED.")]
    d = _eval(records, ws)
    assert d is None, d


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print("ok" if not failed else f"{failed} FAILED")
    raise SystemExit(1 if failed else 0)
