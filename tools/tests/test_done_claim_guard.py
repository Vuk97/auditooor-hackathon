#!/usr/bin/env python3
"""Regression tests for the Stop-hook done-claim guard (claim vs mention; ws resolution)."""
import importlib.util
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_MOD = os.path.join(_HERE, "..", "hooks", "audit-done-claim-guard.py")
spec = importlib.util.spec_from_file_location("done_claim_guard", _MOD)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def claim_of(text):
    return g.find_claim(g._strip_code_spans(text))


def test_command_and_gate_mentions_are_not_claims():
    # The exact false-positive that fired on a non-audit project meta-discussion.
    t = ("To make skipping a hard failure it must be a signal inside `audit-complete` "
         "itself. The honest path to a real `pass-audit-complete`. Run "
         "`make audit-complete WS=optimism STRICT=1`. optimism is still NOT audit-complete.")
    assert claim_of(t) is None, claim_of(t)


def test_negated_not_done_is_not_a_claim():
    assert claim_of("optimism is NOT audit-complete; 5 gates fail. Not done.") is None


def test_positive_assertions_are_claims():
    assert claim_of("optimism is now audit-complete.")
    assert claim_of("it is genuinely audited - an honest-0 across all scope.")
    assert claim_of("the workspace is fully covered now.")


def test_finding_complete_family_are_claims():
    # The exact phrase the operator banned, plus the re-wordings used to dodge it.
    assert claim_of("STRATA is finding-complete.")
    assert claim_of("the workspace is findings-complete now.")
    assert claim_of("the finding-hunt is exhausted.")
    assert claim_of("the finding hunt is now done.")
    assert claim_of("the value-moving core is clean.")
    assert claim_of("the core is mutation-verified clean.")
    assert claim_of("core is dynamically proven clean.")
    assert claim_of("the core is complete.")


def test_negated_finding_complete_is_not_a_claim():
    assert claim_of("it is NOT finding-complete; the strategy layer is unfuzzed.") is None
    assert claim_of("the core is not clean - two lanes still pending.") is None


def test_workspace_resolution_excludes_stray_auditooor_dir():
    # A non-/audits/ project (trading bot) with a stray .auditooor must NOT resolve.
    assert g.resolve_workspace("some text", "/Users/wolf/Downloads/polymarket/clob2") is None


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
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
