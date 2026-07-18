"""test_auto_tier_section_no_hardcoded_rubric.py - regression for Rule 63
Section 15i (auto-tier-assignment) hardcoded-rubric bug (lane L5, LOW).

BUG: _format_auto_tier_assignment_section injected a HARDCODED dYdX/Cosmos
consensus-chain tier example ('consensus halt', 'matching-engine
degradation', 'Indexer-side misleading') labeled 'verbatim from canonical
SEVERITY.md rubrics'. The fn takes only lane_type (no workspace/severity),
so EVERY Solidity DeFi target (e.g. strata ERC-4626) got the wrong-language
tier hint, contradicting the correct per-task workspace SEVERITY.md in the
same prompt.

FIX: drop the literal consensus-chain example tier lines; keep only the
Rule-63 directive that points at rubric-auto-tier-assigner.py (which
re-parses the workspace SEVERITY.md at run-time).
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "dispatch_agent_with_prebriefing", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module at {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dispatch_agent_with_prebriefing"] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


prebriefing = _load_module()


def _render(lane_type: str = "hunt") -> str:
    lines = prebriefing._format_auto_tier_assignment_section(lane_type=lane_type)
    return "\n".join(lines)


def test_no_hardcoded_consensus_chain_tier_examples():
    """The rendered section must not leak a wrong-language (consensus-chain)
    tier rubric into a Solidity DeFi prompt."""
    rendered = _render("hunt")
    assert rendered, "section should render non-empty for an auto-tier lane"
    for leak in ("consensus halt", "matching-engine", "Indexer-side"):
        assert leak not in rendered, (
            f"hardcoded wrong-language tier fragment {leak!r} still present"
        )


def test_rule63_directive_and_tool_reference_preserved():
    """The Rule-63 directive + rubric-auto-tier-assigner reference must
    survive the fix (the section's real value)."""
    rendered = _render("hunt")
    assert "Rule 63" in rendered
    assert "rubric-auto-tier-assigner.py" in rendered
    assert "Section 15i" in rendered
    # Still instructs that the WORKSPACE SEVERITY.md is authoritative.
    assert "SEVERITY.md" in rendered


def test_section_empty_for_non_auto_tier_lane():
    """Unchanged behavior: a lane not in the auto-tier set renders nothing."""
    assert prebriefing._format_auto_tier_assignment_section(
        lane_type="not-a-real-lane"
    ) == []
