"""
proof_of_life.py — first Go detector, proves the cross-language engine works.

Flags any top-level Go function whose identifier starts with `Insecure` —
a trivial demo indicating the AstEngine's language-neutral `functions()`
+ `fn_name()` helpers are wired correctly for tree-sitter-go.

Intended for the `detectors/go_wave1/test_fixtures/test_detectors.sh`
regression-check.
"""

from __future__ import annotations


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name.startswith("Insecure"):
            continue
        hits.append({
            "severity": "med",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (f"Go function `{name}` uses the `Insecure*` naming "
                        f"convention — review for intentional weakening."),
        })
    return hits
