#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-detect.py"


def _load_tool_module():
    spec = importlib.util.spec_from_file_location("rust_detect", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class RustDetectNestedLoaderTest(unittest.TestCase):
    def test_nested_detector_is_discovered_and_executable(self) -> None:
        module = _load_tool_module()
        with tempfile.TemporaryDirectory(prefix="rust-detect-nested-") as tmp:
            detectors_dir = Path(tmp)
            (detectors_dir / "_util.py").write_text(
                "def marker():\n"
                "    return 'root-util'\n",
                encoding="utf-8",
            )
            nested = detectors_dir / "nested_gap"
            nested.mkdir()
            (nested / "nested_probe.py").write_text(
                "from _util import marker\n\n"
                "def run(tree, source, filepath, *, engine=None):\n"
                "    assert engine is not None\n"
                "    return [{\n"
                "        'severity': 'low',\n"
                "        'line': 1,\n"
                "        'col': 1,\n"
                "        'message': marker(),\n"
                "        'snippet': source.decode('utf-8'),\n"
                "    }]\n",
                encoding="utf-8",
            )

            detectors = module._load_detectors(detectors_dir, only="nested_probe")

        self.assertEqual(len(detectors), 1)
        name, detector, accepts_engine = detectors[0]
        self.assertEqual(name, "nested_probe")
        self.assertTrue(accepts_engine)

        hits = detector.run(None, b"fn main() {}", "sample.rs", engine=object())
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["message"], "root-util")
        self.assertEqual(hits[0]["snippet"], "fn main() {}")

    def test_exact_only_match_loads_named_subdirectory_detector(self) -> None:
        module = _load_tool_module()
        with tempfile.TemporaryDirectory(prefix="rust-detect-subdir-") as tmp:
            detectors_dir = Path(tmp)
            (detectors_dir / "_util.py").write_text(
                "def marker():\n"
                "    return 'root-util'\n",
                encoding="utf-8",
            )
            nested = detectors_dir / "r76_stablecoin_rust"
            nested.mkdir()
            (nested / "stable_swap_pools_don_t_apply_rate_multipliers_for_decimals.py").write_text(
                "from _util import marker\n\n"
                "def run(tree, source, filepath, *, engine=None):\n"
                "    return [{\n"
                "        'severity': 'low',\n"
                "        'line': 1,\n"
                "        'col': 1,\n"
                "        'message': marker(),\n"
                "        'snippet': source.decode('utf-8'),\n"
                "    }]\n",
                encoding="utf-8",
            )

            detectors = module._load_detectors(
                detectors_dir,
                only="stable_swap_pools_don_t_apply_rate_multipliers_for_decimals",
            )

        self.assertEqual(len(detectors), 1)
        self.assertEqual(detectors[0][0], "stable_swap_pools_don_t_apply_rate_multipliers_for_decimals")


if __name__ == "__main__":
    unittest.main()
