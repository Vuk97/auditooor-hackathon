#!/usr/bin/env python3
"""Regression tests for the Workflow random-dispatch conformance hook."""
import importlib.util
import io
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_MOD = os.path.join(_HERE, "..", "hooks", "workflow-dispatch-conformance.py")
spec = importlib.util.spec_from_file_location("wf_disp_conf", _MOD)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def _decide(payload, env=None):
    old_stdin, old_stdout, old_env = sys.stdin, sys.stdout, dict(os.environ)
    if env:
        os.environ.update(env)
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout = io.StringIO()
    try:
        try:
            g.main()
        except SystemExit:
            pass
        out = sys.stdout.getvalue().strip()
    finally:
        sys.stdin, sys.stdout = old_stdin, old_stdout
        os.environ.clear(); os.environ.update(old_env)
    return "deny" if (out and "deny" in out) else "allow"


def test_bespoke_audit_hunt_is_denied():
    p = {"tool_name": "Workflow", "cwd": "/Users/wolf",
         "tool_input": {"name": "rubric-hunt", "script": 'WS="/Users/wolf/audits/optimism"; await agent("hunt rubric row return fileable severity finding",{schema:F})'}}
    assert _decide(p) == "deny"


def test_canonical_routing_allowed():
    p = {"tool_name": "Workflow", "cwd": "/Users/wolf",
         "tool_input": {"name": "x", "script": 'WS="/Users/wolf/audits/optimism"; agent("hunt finding severity"); // verdict-sink.py sinks results'}}
    assert _decide(p) == "allow"


def test_infra_fix_workflow_allowed():
    p = {"tool_name": "Workflow", "cwd": "/Users/wolf",
         "tool_input": {"name": "fix-coverage-gate", "script": 'WS="/Users/wolf/audits/optimism"; agent("fix the severity false-green bug")'}}
    assert _decide(p) == "allow"


def test_non_audit_workspace_allowed():
    p = {"tool_name": "Workflow", "cwd": "/tmp",
         "tool_input": {"name": "x", "script": 'agent("find severity finding in trading bot",{schema:F})'}}
    assert _decide(p) == "allow"


def test_override_env_allows():
    p = {"tool_name": "Workflow", "cwd": "/Users/wolf",
         "tool_input": {"name": "x", "script": 'WS="/Users/wolf/audits/optimism"; agent("hunt fileable finding")'}}
    assert _decide(p, env={"AUDITOOOR_BESPOKE_DISPATCH_OK": "1"}) == "allow"


def test_non_workflow_tool_ignored():
    assert _decide({"tool_name": "Bash", "tool_input": {"command": "ls"}}) == "allow"


def test_infra_name_in_script_meta_allows():
    # meta.name (not tool_input.name) carries the infra signal -> must ALLOW
    p = {"tool_name": "Workflow", "cwd": "/Users/wolf",
         "tool_input": {"script": 'export const meta={name:"feeder-fix-infra-audit-the-audits",description:"pinpoint break"}; WS="/Users/wolf/audits/optimism"; agent("diagnose severity exploit-queue break")'}}
    assert _decide(p) == "allow"


def test_hunt_name_in_script_meta_still_denies():
    p = {"tool_name": "Workflow", "cwd": "/Users/wolf",
         "tool_input": {"script": 'export const meta={name:"optimism-rubric-hunt",description:"hunt findings"}; WS="/Users/wolf/audits/optimism"; agent("hunt fileable severity finding")'}}
    assert _decide(p) == "deny"


def test_signed_dispatch_intent_allows_hunt_shaped():
    # a hunt-shaped workflow that is genuinely capability work passes IFF explicitly
    # signed with DISPATCH-INTENT (the "forced sign").
    p = {"tool_name": "Workflow", "cwd": "/Users/wolf",
         "tool_input": {"script": 'export const meta={name:"opt-cap"}; // DISPATCH-INTENT: capability\nWS="/Users/wolf/audits/optimism"; agent("emit fileable severity finding refute",{schema:F})'}}
    assert _decide(p) == "allow"


def test_signed_meta_dispatch_intent_field_allows():
    p = {"tool_name": "Workflow", "cwd": "/Users/wolf",
         "tool_input": {"script": 'export const meta={name:"x",dispatch_intent:"generic-fix"}; WS="/Users/wolf/audits/optimism"; agent("hunt fileable severity finding")'}}
    assert _decide(p) == "allow"


def test_verification_intent_allows_operator_directed_proof():
    # operator-directed adversarial verification of an existing finding is a sanctioned,
    # signable category (it reads source + emits an exploitability verdict).
    p = {"tool_name": "Workflow", "cwd": "/Users/wolf",
         "tool_input": {"script": '// DISPATCH-INTENT: verification\nWS="/Users/wolf/audits/optimism"; agent("prove exploitable severity finding via upstream trace")'}}
    assert _decide(p) == "allow"


def test_unsigned_hunt_with_bogus_intent_still_denies():
    # an unrecognized intent value must NOT pass (no laundering via a fake marker)
    p = {"tool_name": "Workflow", "cwd": "/Users/wolf",
         "tool_input": {"script": 'WS="/Users/wolf/audits/optimism"; /* DISPATCH-INTENT: pleaseallowme */ agent("hunt fileable severity finding")'}}
    assert _decide(p) == "deny"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"ok   {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print("ok" if not failed else f"{failed} FAILED")
    raise SystemExit(1 if failed else 0)
