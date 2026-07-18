"""
proof_of_life.py

Trivial harness sentinel for the solana_wave1 detector batch. Flags any
Rust fn named exactly `proof_of_life`. Used by the test harness to confirm
the engine-first loader, AstEngine Rust parsing, and fixture plumbing all
work before trusting the real detectors.
"""

from __future__ import annotations

DETECTOR_ID = "solana_wave1.proof_of_life"


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        if engine.fn_name(fn) == "proof_of_life":
            hits.append({
                "severity": "info",
                "line": engine.line(fn),
                "col": engine.col(fn),
                "snippet": engine.text(fn).splitlines()[0][:160],
                "message": "proof_of_life sentinel fn detected.",
            })
    return hits
