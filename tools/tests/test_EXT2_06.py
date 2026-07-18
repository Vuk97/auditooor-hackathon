"""Non-vacuity tests for EXT2-06 non-monotonic-guard-composition-screen.

Three mandatory legs:
  (1) PLANTED POSITIVE - a directional self-referential ratchet with an external
      opposite-direction escape writer FIRES (raise-then-lower composition).
  (2) COVERED / BENIGN NEGATIVE - the same monotone ratchet with NO opposite
      writer (a genuine one-way ratchet) is SILENT.
  (3) NEUTRALIZE the core predicate - monkeypatching `_directional_self_guard`
      to a constant None STOPS the planted positive from firing.

Plus a bonus arm-B leg (resettable one-shot latch) to keep both arms non-vacuous.
"""
import importlib.util
from pathlib import Path

_TOOL = (Path(__file__).resolve().parents[1]
         / "non-monotonic-guard-composition-screen.py")
_spec = importlib.util.spec_from_file_location("nonmono_ext2_06", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# --- PLANTED POSITIVE (ARM A): up-only ratchet + external reset escape -------
POSITIVE = """
pragma solidity ^0.8.0;
contract Roles {
    mapping(address => uint256) public expiry;

    // per-call up-only guard: "cannot lower an expiry"
    function extendExpiry(address who, uint256 newExpiry) external {
        require(newExpiry >= expiry[who], "cannot lower expiry");
        expiry[who] = newExpiry;
    }

    // external opposite-direction mover: composes raise-then-lower
    function revokeExpiry(address who) external {
        expiry[who] = 0;
    }
}
"""

# --- BENIGN NEGATIVE: a genuine one-way ratchet, no escape --------------------
NEGATIVE = """
pragma solidity ^0.8.0;
contract Ratchet {
    uint256 public highWater;

    function raise(uint256 newHigh) external {
        require(newHigh >= highWater, "monotone");
        highWater = newHigh;
    }
}
"""

# --- BONUS ARM-B: resettable one-shot latch ----------------------------------
LATCH = """
pragma solidity ^0.8.0;
contract Once {
    bool public initialized;

    function initializeOnce(uint256 x) external {
        require(!initialized, "already init");
        initialized = true;
        // ... one-shot setup keyed on x ...
    }

    function reset() external {
        initialized = false;
    }
}
"""


def _scan(src, name="Fixture.sol"):
    return mod.scan_file(Path(name), name, file_text=src)


def _fired(rows):
    return [r for r in rows if r.get("fires")]


def test_planted_positive_fires():
    rows = _scan(POSITIVE)
    fired = _fired(rows)
    assert fired, "expected the raise-then-lower composition to fire"
    hit = next(r for r in fired if r["arm"] == "directional")
    assert hit["function"] == "extendExpiry"
    assert hit["slot"] == "expiry"
    assert hit["direction"] == "up"
    assert hit["composition_shape"] == "raise-then-lower"
    assert "revokeExpiry" in hit["escape_writers"]
    assert hit["guard_reference_is_self_mutable_slot"] is True
    assert hit["verdict"] == "needs-fuzz"
    assert hit["advisory"] is True and hit["auto_credit"] is False


def test_benign_ratchet_is_silent():
    rows = _scan(NEGATIVE)
    # the directional point is still ENUMERATED (advisory), but must NOT fire:
    assert rows, "the monotone guard should be enumerated as an enforcement point"
    assert not _fired(rows), "a one-way ratchet with no escape must not fire"
    dpt = next(r for r in rows if r["arm"] == "directional")
    assert dpt["function"] == "raise" and dpt["fires"] is False


def test_neutralize_core_predicate_stops_positive(monkeypatch):
    # Neutralize the CORE PREDICATE (directional self-guard detection) to a
    # constant "no directional guard here". The planted positive must go silent.
    monkeypatch.setattr(mod, "_directional_self_guard",
                        lambda *a, **k: None)
    rows = _scan(POSITIVE)
    assert not _fired(rows), (
        "with the directional-self-guard predicate neutralized, the "
        "raise-then-lower composition must no longer fire")


def test_arm_b_resettable_latch_fires():
    rows = _scan(LATCH)
    fired = _fired(rows)
    assert fired, "expected the resettable one-shot latch to fire"
    hit = next(r for r in fired if r["arm"] == "one-shot-latch")
    assert hit["function"] == "initializeOnce"
    assert hit["slot"] == "initialized"
    assert "reset" in hit["escape_writers"]
    assert hit["composition_shape"] == "set-then-reset"


def test_arm_b_latch_without_reset_is_silent():
    # same latch but drop the external reset -> genuine one-shot, must be silent
    src = LATCH.replace(
        "    function reset() external {\n        initialized = false;\n    }\n",
        "")
    rows = _scan(src)
    latch_rows = [r for r in rows if r["arm"] == "one-shot-latch"]
    assert latch_rows, "the latch should still be enumerated"
    assert not _fired(latch_rows), "an un-resettable one-shot latch must not fire"
