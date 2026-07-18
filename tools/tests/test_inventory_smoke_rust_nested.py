from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "inventory-smoke-rust.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("inventory_smoke_rust", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["inventory_smoke_rust"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).strip() + "\n", encoding="utf-8")


class InventorySmokeRustNestedTests(unittest.TestCase):
    def test_nested_detector_file_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory(prefix="inventory-smoke-rust-") as tmp:
            root = Path(tmp)
            detectors_dir = root / "detectors" / "rust_wave1"
            nested = detectors_dir / "r76_stablecoin_rust"
            nested.mkdir(parents=True)
            _write(nested / "stable_swap_pools_don_t_apply_rate_multipliers_for_decimals.py", "def run(*args, **kwargs): return []")
            _write(detectors_dir / "top_level_ok.py", "def run(*args, **kwargs): return []")
            (detectors_dir / "test_fixtures").mkdir()

            det_files = sorted(
                p for p in detectors_dir.rglob("*.py")
                if not p.name.startswith("_")
                and "__pycache__" not in p.parts
                and "test_fixtures" not in p.parts
            )

        rels = [str(path.relative_to(detectors_dir)) for path in det_files]
        self.assertIn(
            "r76_stablecoin_rust/stable_swap_pools_don_t_apply_rate_multipliers_for_decimals.py",
            rels,
        )
        self.assertIn("top_level_ok.py", rels)


if __name__ == "__main__":
    unittest.main()
