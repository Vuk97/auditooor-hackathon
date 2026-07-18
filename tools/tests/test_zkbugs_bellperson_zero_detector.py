#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR_DIR = ROOT / "detectors" / "rust_wave1"
DETECTOR = DETECTOR_DIR / "zkbugs_bellperson_unconstrained_zero_default.py"


def _load_detector():
    if str(DETECTOR_DIR) not in sys.path:
        sys.path.insert(0, str(DETECTOR_DIR))
    spec = importlib.util.spec_from_file_location("zkbugs_bellperson_zero_detector", DETECTOR)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkBugsBellpersonZeroDetectorTest(unittest.TestCase):
    def test_flags_allocated_zero_used_as_selector_default(self) -> None:
        detector = _load_detector()
        body = """
        {
            let zero = AllocatedNum::alloc(cs.namespace(|| "default zero"), || Ok(Scalar::zero()))?;
            selector_dot_product(cs.namespace(|| "select"), selectors, cases, zero.clone())?;
        }
        """
        self.assertEqual(detector.unconstrained_zero_default_vars(body), ["zero"])

    def test_ignores_constrained_zero_before_selector_use(self) -> None:
        detector = _load_detector()
        body = """
        {
            let zero = AllocatedNum::alloc(cs.namespace(|| "default zero"), || Ok(Scalar::zero()))?;
            zero.enforce_equal(cs.namespace(|| "zero is really zero"), &AllocatedNum::zero())?;
            selector_dot_product(cs.namespace(|| "select"), selectors, cases, zero.clone())?;
        }
        """
        self.assertEqual(detector.unconstrained_zero_default_vars(body), [])

    def test_ignores_allocated_zero_not_reaching_selector(self) -> None:
        detector = _load_detector()
        body = """
        {
            let zero = AllocatedNum::alloc(cs.namespace(|| "zero"), || Ok(Scalar::zero()))?;
            let out = zero.square(cs.namespace(|| "square"))?;
        }
        """
        self.assertEqual(detector.unconstrained_zero_default_vars(body), [])


if __name__ == "__main__":
    unittest.main()
