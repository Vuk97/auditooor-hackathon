"""
test_wave14_initializer_guard.py

Guard tests for the type-guard gating FP fix on the three over-firing
name_match_missing_call initializer-family detectors:
    detectors/wave14/missing_access_control_on_initializer_function.py
    detectors/wave14/implementation_contract_can_be_used.py
    detectors/wave14/uninitialized_staking_state.py

The guards (added to the `name_match_missing_call` skeleton in
detectors/_skeletons/skeleton_name_match_missing_call.py.tmpl and regenerated
via tools/gen-detector.py) skip a candidate function when it carries an
`initializer`/`reinitializer` modifier, an access modifier
(onlyOwner/onlyRole/onlyAdmin/onlyProxyAdmin/onlyGovernance), or lives in a
contract whose constructor calls `_disableInitializers()`.

slither is not a hard dependency of this repo, so these tests do NOT spin up a
full slither run. They:
  (1) verify each regenerated detector source carries the guard call sites
      (durable-fix presence), and
  (2) exercise the two guard helper functions (`_has_guard_modifier`,
      `_constructor_disables_initializers`) against lightweight stub objects
      that mimic the slither object model, proving:
        - initialize() WITH _disableInitializers + initializer modifier -> guarded
        - unguarded initialize() -> NOT guarded (true positive preserved)

Run with:
    python3 -m unittest tools.tests.test_wave14_initializer_guard
"""
from __future__ import annotations

import importlib.util
import re
import sys
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
WAVE14_DIR = REPO_ROOT / "detectors" / "wave14"

_DETECTORS = [
    "missing_access_control_on_initializer_function",
    "implementation_contract_can_be_used",
    "uninitialized_staking_state",
]


# ---------------------------------------------------------------------------
# Lightweight stubs mimicking the slither object model used by the guards
# ---------------------------------------------------------------------------
class _StubModifier:
    def __init__(self, name):
        self.name = name


class _StubCallee:
    def __init__(self, name):
        self.name = name


class _StubInternalCall:
    """Mimics a slither internal-call edge with a `.function` attribute."""

    def __init__(self, name):
        self.function = _StubCallee(name)


class _StubFunction:
    def __init__(self, name, modifiers=None):
        self.name = name
        self.modifiers = modifiers or []


class _StubConstructor:
    def __init__(self, internal_calls=None):
        self.internal_calls = internal_calls or []
        self.solidity_calls = []


class _StubContract:
    def __init__(self, constructor=None):
        self.constructor = constructor
        self.constructors_declared = [constructor] if constructor else []


def _load_skeleton_helpers():
    """Load the guard helper fns by rendering them from a regenerated detector.

    The helpers live verbatim in every regenerated detector, so we import one
    detector module and pull `_has_guard_modifier` /
    `_constructor_disables_initializers` off it. slither import is shimmed so
    the module loads without slither installed.
    """
    # Shim `slither.detectors.abstract_detector` so the detector module imports.
    if "slither" not in sys.modules:
        slither = types.ModuleType("slither")
        det = types.ModuleType("slither.detectors")
        absd = types.ModuleType("slither.detectors.abstract_detector")

        class AbstractDetector:  # minimal base
            pass

        class DetectorClassification:
            LOW = MEDIUM = HIGH = INFORMATIONAL = OPTIMIZATION = 0

        absd.AbstractDetector = AbstractDetector
        absd.DetectorClassification = DetectorClassification
        det.abstract_detector = absd
        slither.detectors = det
        sys.modules["slither"] = slither
        sys.modules["slither.detectors"] = det
        sys.modules["slither.detectors.abstract_detector"] = absd

    script = WAVE14_DIR / f"{_DETECTORS[0]}.py"
    spec = importlib.util.spec_from_file_location("_w14_guard_probe", script)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_w14_guard_probe"] = mod
    spec.loader.exec_module(mod)
    return mod


class TestWave14InitializerGuardPresence(unittest.TestCase):
    """Durable fix: every regenerated detector carries the guard call sites."""

    def test_guard_callsites_present_in_all_three(self):
        for name in _DETECTORS:
            src = (WAVE14_DIR / f"{name}.py").read_text()
            self.assertIn(
                "_has_guard_modifier(f)", src,
                f"{name}: missing _has_guard_modifier guard call",
            )
            self.assertIn(
                "_constructor_disables_initializers(c)", src,
                f"{name}: missing _constructor_disables_initializers guard call",
            )

    def test_access_modifier_list_present(self):
        src = (WAVE14_DIR / f"{_DETECTORS[0]}.py").read_text()
        for mod_name in ("onlyOwner", "onlyRole", "onlyAdmin",
                         "onlyProxyAdmin", "onlyGovernance"):
            self.assertIn(mod_name, src, f"access modifier {mod_name} not gated")
        self.assertTrue(
            re.search(r"reinitializer", src),
            "reinitializer not present in guard regex",
        )


class TestWave14GuardHelpers(unittest.TestCase):
    """Exercise the guard helper functions against stub slither objects."""

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_skeleton_helpers()

    # --- _has_guard_modifier ------------------------------------------------
    def test_initializer_modifier_is_guarded(self):
        f = _StubFunction("initialize", modifiers=[_StubModifier("initializer")])
        self.assertTrue(self.mod._has_guard_modifier(f))

    def test_reinitializer_modifier_is_guarded(self):
        f = _StubFunction("initializeV2", modifiers=[_StubModifier("reinitializer")])
        self.assertTrue(self.mod._has_guard_modifier(f))

    def test_access_modifier_is_guarded(self):
        for m in ("onlyOwner", "onlyRole", "onlyAdmin",
                  "onlyProxyAdmin", "onlyGovernance"):
            f = _StubFunction("initialize", modifiers=[_StubModifier(m)])
            self.assertTrue(
                self.mod._has_guard_modifier(f),
                f"{m} should be treated as an access guard",
            )

    def test_unguarded_initialize_not_guarded_by_modifier(self):
        """TRUE POSITIVE preserved: a bare initialize() has no guard modifier."""
        f = _StubFunction("initialize", modifiers=[])
        self.assertFalse(self.mod._has_guard_modifier(f))

    # --- _constructor_disables_initializers ---------------------------------
    def test_constructor_disable_initializers_is_guarded(self):
        ctor = _StubConstructor(
            internal_calls=[_StubInternalCall("_disableInitializers")]
        )
        c = _StubContract(constructor=ctor)
        self.assertTrue(self.mod._constructor_disables_initializers(c))

    def test_constructor_without_disable_not_guarded(self):
        """TRUE POSITIVE preserved: ctor that does NOT disable initializers."""
        ctor = _StubConstructor(internal_calls=[_StubInternalCall("_someOtherSetup")])
        c = _StubContract(constructor=ctor)
        self.assertFalse(self.mod._constructor_disables_initializers(c))

    def test_no_constructor_not_guarded(self):
        c = _StubContract(constructor=None)
        self.assertFalse(self.mod._constructor_disables_initializers(c))

    # --- combined: the spec's two named cases -------------------------------
    def test_guarded_initialize_combo_skipped(self):
        """initialize() WITH _disableInitializers + initializer modifier: guarded."""
        f = _StubFunction("initialize", modifiers=[_StubModifier("initializer")])
        ctor = _StubConstructor(
            internal_calls=[_StubInternalCall("_disableInitializers")]
        )
        c = _StubContract(constructor=ctor)
        guarded = self.mod._has_guard_modifier(f) or \
            self.mod._constructor_disables_initializers(c)
        self.assertTrue(guarded, "guarded initialize() must be skipped")

    def test_unguarded_initialize_combo_still_flagged(self):
        """Unguarded initialize() (no modifier, no _disableInitializers): NOT skipped."""
        f = _StubFunction("initialize", modifiers=[])
        ctor = _StubConstructor(internal_calls=[])
        c = _StubContract(constructor=ctor)
        guarded = self.mod._has_guard_modifier(f) or \
            self.mod._constructor_disables_initializers(c)
        self.assertFalse(guarded, "unguarded initialize() must remain a candidate")


if __name__ == "__main__":
    unittest.main()
