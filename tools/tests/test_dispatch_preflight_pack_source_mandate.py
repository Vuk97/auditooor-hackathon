"""test_dispatch_preflight_pack_source_mandate.py

Guards the fix for dispatch-agent hallucination risk (issue: pack-only hunting
hallucinated 5/10 false-positive HIGHs when agents had only the condensed pack
JSON and no real function body).

Checks:
 1. _format_pre_flight_pack_section for a matched pack (no workspace, no pack
    file) always contains the source-read mandate string and the 5/10 FP warning.
 2. _format_pre_flight_pack_section for a matched pack with a real pack file
    whose source_ref resolves to an existing file embeds the function body.
 3. _format_pre_flight_pack_section for a matched pack with a pack file whose
    source_ref does NOT resolve still contains the source-read mandate (no crash).
 4. _format_pre_flight_pack_section for a not-matched / missing context does NOT
    inject the mandate (no pack = nothing to warn about).
 5. The full format_skeleton_as_markdown prompt for a matched pack contains the
    source-read mandate and the 5/10 FP warning (end-to-end).
 6. The full format_skeleton_as_markdown prompt for a matched pack with a real
    source_ref embeds the real body (end-to-end).
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
import tempfile
import textwrap
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

# Sentinel strings that MUST appear in any matched-pack dispatch output.
_MANDATE_SENTINEL = "SOURCE-READ MANDATE"
_FP_WARNING_SENTINEL = "5/10 false-positive HIGHs"
_R76_SENTINEL = "R76"


def _fake_skeleton_payload():
    return {
        "schema": "auditooor.vault_dispatch_brief_skeleton.v1",
        "kind": "dispatch_brief_skeleton",
        "context_pack_id": "fake:test",
        "context_pack_hash": "a" * 64,
        "lane_type": "hunt",
        "severity": "HIGH",
        "lane_specific_rules": ["R76"],
        "skeleton_sections": {},
        "recall_summary": "RESUME: test",
        "rubric_excerpt": {"rows": [], "tier_sections": [], "parsed": True},
        "originality_anchors": [],
        "routine_violation_warnings": [],
        "busywork_refusals": [],
        "pre_submit_preview": [],
    }


class TestPackSourceReadMandate(unittest.TestCase):
    """Unit tests for _format_pre_flight_pack_section."""

    def _matched_context_no_path(self):
        """A matched context dict with no real pack file on disk."""
        return {
            "schema": "auditooor.pre_flight_pack_context.v1",
            "status": "matched",
            "matched": True,
            "path": "",  # no real file
            "reason": "test fixture",
            "pack_count": 1,
            "excerpt": '{"function": "foo", "source_ref": ""}',
        }

    def test_mandate_present_matched_no_file(self):
        """Mandate + FP warning appear even when no real pack file / ws available."""
        ctx = self._matched_context_no_path()
        output = "\n".join(
            prebriefing._format_pre_flight_pack_section(ctx, workspace_path=None)
        )
        self.assertIn(_MANDATE_SENTINEL, output, "SOURCE-READ MANDATE missing")
        self.assertIn(_FP_WARNING_SENTINEL, output, "5/10 FP warning missing")
        self.assertIn(_R76_SENTINEL, output, "R76 reference missing")

    def test_mandate_absent_for_missing_pack(self):
        """Not-matched context must NOT inject the mandate (no pack = nothing to warn)."""
        ctx = {
            "schema": "auditooor.pre_flight_pack_context.v1",
            "status": "missing-pack-dir",
            "matched": False,
            "reason": "pack dir absent",
            "expected_dir": "/tmp/fake/.auditooor/pre_flight_packs",
        }
        output = "\n".join(
            prebriefing._format_pre_flight_pack_section(ctx, workspace_path=None)
        )
        self.assertNotIn(_MANDATE_SENTINEL, output)

    def test_mandate_absent_for_none_context(self):
        """None context (no MCP context at all) must NOT inject the mandate."""
        output = "\n".join(
            prebriefing._format_pre_flight_pack_section(None, workspace_path=None)
        )
        self.assertNotIn(_MANDATE_SENTINEL, output)

    def test_body_embedded_when_source_ref_resolves(self):
        """When source_ref points to a real file, the real body is embedded."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = pathlib.Path(tmpdir)
            # Write a minimal Solidity file as the target.
            src_dir = ws / "src"
            src_dir.mkdir()
            sol_file = src_dir / "Foo.sol"
            sol_file.write_text(
                textwrap.dedent(
                    """\
                    // SPDX-License-Identifier: MIT
                    pragma solidity ^0.8.0;
                    contract Foo {
                        function bar(uint256 x) external pure returns (uint256) {
                            return x * 2;
                        }
                    }
                    """
                )
            )
            # Write a minimal pack JSON referencing the function.
            pack_dir = ws / ".auditooor" / "pre_flight_packs"
            pack_dir.mkdir(parents=True)
            pack_file = pack_dir / "pre_flight_pack_Foo_bar.json"
            pack_data = {
                "schema": "auditooor.pre_flight_pack.v1",
                "function": "bar",
                "source_ref": "src/Foo.sol:4",
                "contract": "Foo",
                "per_function_hunter_brief": "look for overflow",
            }
            pack_file.write_text(json.dumps(pack_data))
            ctx = {
                "schema": "auditooor.pre_flight_pack_context.v1",
                "status": "matched",
                "matched": True,
                "path": str(pack_file),
                "reason": "test fixture with real file",
                "pack_count": 1,
                "excerpt": json.dumps(pack_data),
            }
            output = "\n".join(
                prebriefing._format_pre_flight_pack_section(ctx, workspace_path=ws)
            )
            # Mandate must still be present.
            self.assertIn(_MANDATE_SENTINEL, output, "SOURCE-READ MANDATE missing")
            self.assertIn(_FP_WARNING_SENTINEL, output, "5/10 FP warning missing")
            # The real body keyword should appear (we embedded the real source).
            self.assertIn("bar", output, "function body 'bar' not embedded")
            self.assertIn("x * 2", output, "body content not embedded verbatim")

    def test_no_crash_when_source_ref_bad(self):
        """Pack file with a non-existent source_ref: no crash, mandate still present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = pathlib.Path(tmpdir)
            pack_dir = ws / ".auditooor" / "pre_flight_packs"
            pack_dir.mkdir(parents=True)
            pack_file = pack_dir / "pre_flight_pack_Ghost_ghost.json"
            pack_data = {
                "schema": "auditooor.pre_flight_pack.v1",
                "function": "ghost",
                "source_ref": "src/NoSuchFile.sol:999",
            }
            pack_file.write_text(json.dumps(pack_data))
            ctx = {
                "schema": "auditooor.pre_flight_pack_context.v1",
                "status": "matched",
                "matched": True,
                "path": str(pack_file),
                "reason": "test fixture bad source_ref",
                "pack_count": 1,
                "excerpt": json.dumps(pack_data),
            }
            output = "\n".join(
                prebriefing._format_pre_flight_pack_section(ctx, workspace_path=ws)
            )
            # Must not raise; mandate must still be present.
            self.assertIn(_MANDATE_SENTINEL, output)


class TestPackMandateEndToEnd(unittest.TestCase):
    """End-to-end: format_skeleton_as_markdown includes the mandate."""

    def _build_matched_context(self, pack_path: str = "", excerpt: str = "") -> dict:
        return {
            "schema": "auditooor.pre_flight_pack_context.v1",
            "status": "matched",
            "matched": True,
            "path": pack_path,
            "reason": "e2e test fixture",
            "pack_count": 1,
            "excerpt": excerpt or '{"function": "foo"}',
        }

    def test_mandate_in_full_prompt_no_body(self):
        """format_skeleton_as_markdown emits mandate for a matched pack (no body)."""
        prompt = prebriefing.format_skeleton_as_markdown(
            _fake_skeleton_payload(),
            lane_type="hunt",
            severity="HIGH",
            workspace_path=None,
            pre_flight_pack_context=self._build_matched_context(),
        )
        self.assertIn(_MANDATE_SENTINEL, prompt)
        self.assertIn(_FP_WARNING_SENTINEL, prompt)
        self.assertIn(_R76_SENTINEL, prompt)

    def test_mandate_in_full_prompt_with_body(self):
        """format_skeleton_as_markdown embeds body + mandate when source_ref resolves."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = pathlib.Path(tmpdir)
            src_dir = ws / "src"
            src_dir.mkdir()
            sol_file = src_dir / "Bar.sol"
            sol_file.write_text(
                textwrap.dedent(
                    """\
                    // SPDX-License-Identifier: MIT
                    pragma solidity ^0.8.0;
                    contract Bar {
                        function withdraw(address to, uint256 amt) external {
                            payable(to).transfer(amt);
                        }
                    }
                    """
                )
            )
            pack_dir = ws / ".auditooor" / "pre_flight_packs"
            pack_dir.mkdir(parents=True)
            pack_file = pack_dir / "pre_flight_pack_Bar_withdraw.json"
            pack_data = {
                "schema": "auditooor.pre_flight_pack.v1",
                "function": "withdraw",
                "source_ref": "src/Bar.sol:4",
                "contract": "Bar",
            }
            pack_file.write_text(json.dumps(pack_data))
            ctx = self._build_matched_context(
                pack_path=str(pack_file),
                excerpt=json.dumps(pack_data),
            )
            prompt = prebriefing.format_skeleton_as_markdown(
                _fake_skeleton_payload(),
                lane_type="hunt",
                severity="HIGH",
                workspace_path=ws,
                pre_flight_pack_context=ctx,
            )
            self.assertIn(_MANDATE_SENTINEL, prompt)
            self.assertIn(_FP_WARNING_SENTINEL, prompt)
            # Body should be embedded.
            self.assertIn("withdraw", prompt)
            self.assertIn("payable(to).transfer(amt)", prompt)

    def test_no_mandate_for_unmatched_pack(self):
        """No mandate when pack is not matched (no pack available)."""
        ctx = {
            "schema": "auditooor.pre_flight_pack_context.v1",
            "status": "missing-pack-dir",
            "matched": False,
            "reason": "no pack dir",
            "expected_dir": "/tmp/nope",
        }
        prompt = prebriefing.format_skeleton_as_markdown(
            _fake_skeleton_payload(),
            lane_type="hunt",
            severity="HIGH",
            workspace_path=None,
            pre_flight_pack_context=ctx,
        )
        self.assertNotIn(_MANDATE_SENTINEL, prompt)


if __name__ == "__main__":
    unittest.main()


class TestAnchorFallbackSuppression(unittest.TestCase):
    """2026-07-03: when build_pre_flight_pack_context falls back to the NEWEST pack
    as a bare 'workspace anchor' (dispatch prompt named no specific pack), the pack
    is very likely for a DIFFERENT function/contract than the assignment (observed:
    an EVM RedemptionProxy pack injected into a Go/Cosmos hunt). The render must NOT
    present that unrelated body under the 'TARGET FUNCTION' header - it must suppress
    it and warn. A genuine match is unchanged."""

    def _ws_with_pack(self, tmpdir):
        ws = pathlib.Path(tmpdir)
        src_dir = ws / "src"
        src_dir.mkdir()
        (src_dir / "Foo.sol").write_text(
            "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n"
            "contract Foo {\n"
            "    function bar(uint256 x) external pure returns (uint256) {\n"
            "        return x * 2;\n"
            "    }\n}\n"
        )
        pack_dir = ws / ".auditooor" / "pre_flight_packs"
        pack_dir.mkdir(parents=True)
        pack_file = pack_dir / "pre_flight_pack_Foo_bar.json"
        pack_data = {
            "schema": "auditooor.pre_flight_pack.v1",
            "function": "bar",
            "source_ref": "src/Foo.sol:4",
            "contract": "Foo",
        }
        pack_file.write_text(json.dumps(pack_data))
        return ws, pack_file, pack_data

    def test_anchor_fallback_suppresses_unrelated_body_and_warns(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ws, pack_file, pack_data = self._ws_with_pack(tmpdir)
            ctx = {
                "schema": "auditooor.pre_flight_pack_context.v1",
                "status": "matched", "matched": True, "path": str(pack_file),
                # THE fallback reason string produced by build_pre_flight_pack_context.
                "reason": "no exact dispatch target match; using newest pack as workspace anchor",
                "pack_count": 3, "excerpt": json.dumps(pack_data),
            }
            output = "\n".join(
                prebriefing._format_pre_flight_pack_section(ctx, workspace_path=ws))
            # The misleading target-framed body must be SUPPRESSED.
            self.assertNotIn("TARGET FUNCTION + CONTEXT", output,
                             "fallback must not present unrelated body as the target")
            self.assertNotIn("x * 2", output, "unrelated pack body must be suppressed")
            # The NOT-YOUR-TARGET warning must be present.
            self.assertIn("NON-TARGET WORKSPACE-ANCHOR PACK", output)
            # The source-read mandate is still present (agents still read real source).
            self.assertIn(_MANDATE_SENTINEL, output)

    def test_genuine_match_still_embeds_body(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ws, pack_file, pack_data = self._ws_with_pack(tmpdir)
            ctx = {
                "schema": "auditooor.pre_flight_pack_context.v1",
                "status": "matched", "matched": True, "path": str(pack_file),
                "reason": "prompt names exact pack filename",  # genuine match
                "pack_count": 1, "excerpt": json.dumps(pack_data),
            }
            output = "\n".join(
                prebriefing._format_pre_flight_pack_section(ctx, workspace_path=ws))
            self.assertIn("TARGET FUNCTION + CONTEXT", output)
            self.assertIn("x * 2", output, "genuine match must still embed the real body")
            self.assertNotIn("NON-TARGET WORKSPACE-ANCHOR PACK", output)


if __name__ == "__main__":
    unittest.main()
