"""Shared rebuttal-marker gate helper (Rank 3 friction fix).

Historically each R-rule gate inlined:

    rebuttal = _rebuttal(text)
    if rebuttal and len(rebuttal) <= 200:
        payload["verdict"] = "ok-rebuttal"
        payload["rebuttal"] = rebuttal
        return 0, payload

An over-length rebuttal (`len > 200`) silently fell through to the FAIL path with
NO indication that a rebuttal was present-but-rejected. Agents then saw a red gate
with a rebuttal already in the draft and could not tell the marker was dropped for
being too long. That silent rejection cost real triage/agent effort at NUVA.

This module centralizes the gate so rejection is LOUD (recorded on the payload +
emitted to stderr) while keeping the 200-char cap and NOT adding any `return 0`
escape - an over-length rebuttal STILL fails the gate, it is just no longer silent.

Model: opposed-trace-actor-separation-check.py:365-367 (the pre-existing loud branch).

The cap (200) is exported as REBUTTAL_MAX_LEN so callers stay in lockstep.
"""

from __future__ import annotations

import sys
from typing import Any

# Single source of truth for the rebuttal reason length cap shared across all
# R-rule gates. Must match the historical inline `<= 200` checks.
REBUTTAL_MAX_LEN = 200


def apply_rebuttal_gate(
    payload: dict[str, Any],
    rebuttal: str | None,
    *,
    accept_verdict: str = "ok-rebuttal",
    stderr: bool = True,
) -> bool:
    """Apply the shared rebuttal-marker gate to ``payload`` in place.

    Returns ``True`` when the rebuttal was ACCEPTED (caller should
    ``return 0, payload`` - the gate passes via the override marker).

    Returns ``False`` when the caller must CONTINUE to its normal
    substance checks, i.e. one of:
      * no rebuttal marker present, or
      * a rebuttal marker was present but over the length cap - in which
        case the payload is annotated LOUDLY (``rebuttal_rejected`` +
        ``rebuttal_reason`` + the offending length) and a warning is
        written to stderr. The gate does NOT pass; the caller proceeds to
        its FAIL path exactly as before, but the drop is now visible.

    Accepting on ``<=`` and rejecting on ``>`` preserves the exact historical
    boundary (a reason of exactly 200 chars is still accepted).
    """
    if not rebuttal:
        return False

    length = len(rebuttal)
    if length <= REBUTTAL_MAX_LEN:
        payload["verdict"] = accept_verdict
        payload["rebuttal"] = rebuttal
        return True

    # Over-length: LOUD rejection, but still fails (no early return 0).
    payload["rebuttal_rejected"] = True
    payload["rebuttal_reason"] = (
        f"rebuttal exceeds {REBUTTAL_MAX_LEN} chars ({length}); treated as absent"
    )
    payload["rebuttal_length"] = length
    if stderr:
        gate = payload.get("gate") or payload.get("file") or "gate"
        print(
            f"warning [{gate}]: rebuttal marker present but {length} chars "
            f"(> {REBUTTAL_MAX_LEN} cap) - REJECTED as absent; shorten the reason "
            f"to <= {REBUTTAL_MAX_LEN} chars to defer this gate.",
            file=sys.stderr,
        )
    return False
