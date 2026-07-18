"""test_dispatch_per_fn_detector_corroboration.py

Guards Gap #9: the per-function dispatch brief surfaces static-analyzer
(detector) hits whose SOURCE FILE matches the function under hunt, joined from
the workspace ``.auditooor/detector_action_graph.json`` +
``.auditooor/detector_action_graphs/*.json`` producers - WITHOUT regenerating
the pre-flight pack.

Checks:
 1. _detector_hit_file strips a trailing ``:<line>`` and leaves a bare path.
 2. _collect_per_fn_detector_hits joins by file and ONLY returns hits in the
    function's own source file (no cross-file false positives).
 3. _collect_per_fn_detector_hits dedupes (slug, file_path) across the main
    graph and the per-hit files, and honours the limit.
 4. _collect_per_fn_detector_hits returns [] when no producer artifact exists
    (honest absence, never a fabricated hit) and on a None workspace.
 5. _format_pre_flight_pack_section renders the corroboration table for a
    matched pack whose source_ref file has detector hits, and omits it when the
    file has none.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest

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


def _write_ws_with_detectors(root: pathlib.Path) -> pathlib.Path:
    det = root / ".auditooor"
    (det / "detector_action_graphs").mkdir(parents=True)
    # main graph: single detector_hit in OperatorLib.sol
    (det / "detector_action_graph.json").write_text(
        json.dumps(
            {
                "detector_hit": {
                    "detector_slug": "integer-overflow-clamp",
                    "file_path": "src/contracts/libraries/OperatorLib.sol:58",
                    "severity": "MEDIUM",
                    "snippet": "narrows block.number to uint32",
                }
            }
        ),
        encoding="utf-8",
    )
    # per-hit file: a second hit in the SAME file + one in a DIFFERENT file
    (det / "detector_action_graphs" / "hit_000.json").write_text(
        json.dumps(
            {
                "detector_hit": {
                    "detector_slug": "integer-overflow-clamp",
                    "file_path": "src/contracts/libraries/OperatorLib.sol:85",
                    "severity": "MEDIUM",
                    "snippet": "second narrowing site",
                }
            }
        ),
        encoding="utf-8",
    )
    (det / "detector_action_graphs" / "hit_001.json").write_text(
        json.dumps(
            {
                "detector_hit": {
                    "detector_slug": "reentrancy",
                    "file_path": "src/contracts/token/CSSVToken.sol:37",
                    "severity": "HIGH",
                    "snippet": "external call before state write",
                }
            }
        ),
        encoding="utf-8",
    )
    # a duplicate of the main hit, to prove dedup
    (det / "detector_action_graphs" / "hit_002.json").write_text(
        json.dumps(
            {
                "detector_hit": {
                    "detector_slug": "integer-overflow-clamp",
                    "file_path": "src/contracts/libraries/OperatorLib.sol:58",
                    "severity": "MEDIUM",
                    "snippet": "duplicate of main",
                }
            }
        ),
        encoding="utf-8",
    )
    return root


class DetectorHitFileTest(unittest.TestCase):
    def test_strips_line_suffix(self):
        self.assertEqual(
            prebriefing._detector_hit_file("a/b/Foo.sol:58"), "a/b/Foo.sol"
        )

    def test_leaves_bare_path(self):
        self.assertEqual(prebriefing._detector_hit_file("a/b/Foo.sol"), "a/b/Foo.sol")

    def test_non_numeric_suffix_untouched(self):
        # a ':' that is not a line number must not be stripped
        self.assertEqual(
            prebriefing._detector_hit_file("workspace:engage_report.json"),
            "workspace:engage_report.json",
        )


class CollectPerFnDetectorHitsTest(unittest.TestCase):
    def test_joins_same_file_only(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _write_ws_with_detectors(pathlib.Path(td))
            hits = prebriefing._collect_per_fn_detector_hits(
                ws, "src/contracts/libraries/OperatorLib.sol:204"
            )
            files = {h["file_path"] for h in hits}
            # both OperatorLib hits present, CSSVToken hit absent
            self.assertIn("src/contracts/libraries/OperatorLib.sol:58", files)
            self.assertIn("src/contracts/libraries/OperatorLib.sol:85", files)
            self.assertNotIn("src/contracts/token/CSSVToken.sol:37", files)

    def test_dedupes_slug_and_path(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _write_ws_with_detectors(pathlib.Path(td))
            hits = prebriefing._collect_per_fn_detector_hits(
                ws, "src/contracts/libraries/OperatorLib.sol:204"
            )
            keys = [(h["detector_slug"], h["file_path"]) for h in hits]
            self.assertEqual(len(keys), len(set(keys)), "expected dedup")
            # exactly the 2 distinct OperatorLib hits (58 + 85), :58 not doubled
            self.assertEqual(len(hits), 2)

    def test_respects_limit(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _write_ws_with_detectors(pathlib.Path(td))
            hits = prebriefing._collect_per_fn_detector_hits(
                ws, "src/contracts/libraries/OperatorLib.sol:204", limit=1
            )
            self.assertEqual(len(hits), 1)

    def test_no_producer_returns_empty(self):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / ".auditooor").mkdir()
            self.assertEqual(
                prebriefing._collect_per_fn_detector_hits(ws, "src/Foo.sol:1"), []
            )

    def test_none_workspace_returns_empty(self):
        self.assertEqual(
            prebriefing._collect_per_fn_detector_hits(None, "src/Foo.sol:1"), []
        )


class FormatSectionCorroborationTest(unittest.TestCase):
    def _matched_context(self, pack_path: pathlib.Path) -> dict:
        return {
            "schema": "auditooor.pre_flight_pack_context.v1",
            "status": "matched",
            "matched": True,
            "path": str(pack_path),
            "reason": "test",
            "pack_count": 1,
            "excerpt": "{}",
        }

    def test_table_rendered_when_hits_present(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _write_ws_with_detectors(pathlib.Path(td))
            pack = ws / "pack.json"
            pack.write_text(
                json.dumps(
                    {
                        "source_ref": "src/contracts/libraries/OperatorLib.sol:204",
                        "function": "updateClusterOperatorsOnRegistration",
                    }
                ),
                encoding="utf-8",
            )
            out = "\n".join(
                prebriefing._format_pre_flight_pack_section(
                    self._matched_context(pack), ws
                )
            )
            self.assertIn("Static-analyzer corroboration", out)
            self.assertIn("integer-overflow-clamp", out)
            self.assertNotIn("reentrancy", out)  # CSSVToken hit not joined

    def test_table_omitted_when_no_hits_for_file(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _write_ws_with_detectors(pathlib.Path(td))
            pack = ws / "pack.json"
            pack.write_text(
                json.dumps(
                    {
                        "source_ref": "src/contracts/no/Detector.sol:10",
                        "function": "foo",
                    }
                ),
                encoding="utf-8",
            )
            out = "\n".join(
                prebriefing._format_pre_flight_pack_section(
                    self._matched_context(pack), ws
                )
            )
            self.assertNotIn("Static-analyzer corroboration", out)


if __name__ == "__main__":
    unittest.main()
