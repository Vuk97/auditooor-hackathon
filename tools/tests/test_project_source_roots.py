import json
import tempfile
import unittest
from pathlib import Path

from tools.lib.project_source_roots import (
    declared_rust_project_root_specs,
    declared_rust_project_roots,
    rust_crate_scan_roots,
    rust_subdir_scan_roots,
)


class ProjectSourceRootsTests(unittest.TestCase):
    def test_readiness_declared_rc28_root_wins_over_legacy_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            root = ws / "external" / "base-rc28-clean"
            (root / "crates" / "execution" / "rpc").mkdir(parents=True)
            (root / "crates" / "consensus" / "rpc").mkdir(parents=True)
            (root / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
            (root / "crates" / "execution" / "rpc" / "lib.rs").write_text(
                "pub fn rpc() {}\n",
                encoding="utf-8",
            )
            auditooor = ws / ".auditooor"
            auditooor.mkdir()
            (auditooor / "project_source_root_readiness.json").write_text(
                json.dumps(
                    {
                        "roots": [
                            {
                                "declared_path": "external/base-rc28-clean",
                                "resolved_path": str(root),
                                "language_presence": {"rust": 1},
                                "rejection_reasons": [],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(declared_rust_project_roots(ws), ["external/base-rc28-clean"])
            self.assertEqual(
                declared_rust_project_root_specs(ws),
                [
                    {
                        "path": "external/base-rc28-clean",
                        "resolved_path": str(root.resolve()),
                        "label": "",
                        "artifact_slug": "rc28-clean",
                    }
                ],
            )
            self.assertEqual(
                rust_crate_scan_roots(ws, ("external/base/crates", "crates")),
                ["external/base-rc28-clean/crates"],
            )
            self.assertEqual(
                rust_subdir_scan_roots(
                    ws,
                    ("crates/execution/rpc", "crates/consensus/rpc"),
                    ("external/base/crates/execution/rpc",),
                ),
                [
                    "external/base-rc28-clean/crates/execution/rpc",
                    "external/base-rc28-clean/crates/consensus/rpc",
                ],
            )

    def test_falls_back_when_no_declared_rust_root_exists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            self.assertEqual(
                rust_crate_scan_roots(ws, ("external/base/crates", "crates")),
                ["external/base/crates", "crates"],
            )


if __name__ == "__main__":
    unittest.main()
