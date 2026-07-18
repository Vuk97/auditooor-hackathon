"""
proof_of_life.py — first Python detector, proves the cross-language engine works.

Flags any `def` whose body contains a call to `eval(` — a trivial demo of
the AstEngine's `functions()` + `body_contains_call_to()` helpers wired
for tree-sitter-python.

Intended for the `detectors/python_wave1/test_fixtures/test_detectors.sh`
regression-check.
"""

from __future__ import annotations


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        if not engine.body_contains_call_to(fn, r"^eval$"):
            continue
        name = engine.fn_name(fn)
        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (f"Python `def {name}` contains a call to `eval()` — "
                        f"code-injection risk on untrusted input."),
        })
    return hits
