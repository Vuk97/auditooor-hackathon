"""test_filing_finalization_dod.py - unit tests for the platform-aware
Filing Finalization Definition-of-Done injection (lane spawn-worker-filing-dod).

Covers:
  1. resolve_workspace_platform maps zebra -> github-ghsa, dydx -> cantina,
     spark -> immunefi, hyperbridge -> hackenproof (via SCOPE.md/SEVERITY.md
     keyword + workspace dir name), and an unknown workspace -> generic.
  2. A filing-lane brief CONTAINS the Filing Finalization Definition-of-Done
     block with the resolved platform's canonical_template path.
  3. A hunt-lane brief does NOT contain the DoD block.
  4. The registry JSON has all 4 platforms + generic, each with a real
     canonical_template path that exists on disk.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"
REGISTRY_PATH = REPO_ROOT / "reference" / "platform_submission_requirements.json"


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

DOD_HEADER = "## Filing Finalization - Definition of Done"


def _make_ws(tmp: pathlib.Path, name: str, scope_text: str) -> pathlib.Path:
    ws = tmp / name
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "SCOPE.md").write_text(scope_text, encoding="utf-8")
    return ws


class TestResolveWorkspacePlatform(unittest.TestCase):
    def test_zebra_resolves_github_ghsa(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(
                pathlib.Path(td),
                "zebra",
                "Zebra/Zcash bug bounty under the ZCG rubric. File via GHSA "
                "'Report a vulnerability'. (Immunefi is mentioned only as a "
                "comparison.)",
            )
            self.assertEqual(
                prebriefing.resolve_workspace_platform(ws), "github-ghsa"
            )

    def test_dydx_resolves_cantina(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(
                pathlib.Path(td),
                "dydx",
                "dYdX bug bounty hosted on Cantina. Severity-only payout.",
            )
            self.assertEqual(prebriefing.resolve_workspace_platform(ws), "cantina")

    def test_spark_resolves_immunefi(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(
                pathlib.Path(td),
                "spark",
                "Spark Immunefi program. Primacy of Impact applies.",
            )
            self.assertEqual(prebriefing.resolve_workspace_platform(ws), "immunefi")

    def test_hyperbridge_resolves_hackenproof(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(
                pathlib.Path(td),
                "hyperbridge",
                "Hyperbridge bug bounty on HackenProof. High band 5k-15k USD.",
            )
            self.assertEqual(
                prebriefing.resolve_workspace_platform(ws), "hackenproof"
            )

    def test_unknown_resolves_generic(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(
                pathlib.Path(td),
                "mystery-protocol",
                "A bug bounty with no recognizable platform keyword here.",
            )
            self.assertEqual(prebriefing.resolve_workspace_platform(ws), "generic")

    def test_none_workspace_resolves_generic(self):
        self.assertEqual(prebriefing.resolve_workspace_platform(None), "generic")

    def test_dir_name_alone_resolves(self):
        # Even with an empty SCOPE, the workspace dir name "zebra" is a signal.
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(pathlib.Path(td), "zebra", "no platform keyword")
            self.assertEqual(
                prebriefing.resolve_workspace_platform(ws), "github-ghsa"
            )


class TestFilingFinalizationInjection(unittest.TestCase):
    def _brief(self, lane_type: str, ws: pathlib.Path) -> str:
        # payload=None exercises the skeleton-unavailable path deterministically
        # (no MCP call); the DoD section is injected on both code paths.
        return prebriefing.format_skeleton_as_markdown(
            None,
            lane_type=lane_type,
            severity="HIGH",
            workspace_path=ws,
        )

    def test_filing_lane_contains_dod_with_platform_template(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(
                pathlib.Path(td),
                "zebra",
                "Zebra GHSA bounty under the ZCG rubric.",
            )
            brief = self._brief("filing", ws)
            self.assertIn(DOD_HEADER, brief)
            self.assertIn("github-ghsa", brief)
            self.assertIn("docs/GHSA_ZEBRA_PASTE_TEMPLATE.md", brief)
            # The mandatory pre-submit gate must be stated.
            self.assertIn("pre-submit-check.sh", brief)
            self.assertIn("rc=0", brief)

    def test_triager_response_lane_also_gets_dod(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(pathlib.Path(td), "dydx", "Cantina bounty.")
            brief = self._brief("triager-response", ws)
            self.assertIn(DOD_HEADER, brief)
            self.assertIn("cantina", brief)
            self.assertIn("docs/CANONICAL_CANTINA_PASTE_TEMPLATE.md", brief)

    def test_hunt_lane_does_not_contain_dod(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(
                pathlib.Path(td),
                "zebra",
                "Zebra GHSA bounty under the ZCG rubric.",
            )
            brief = self._brief("hunt", ws)
            self.assertNotIn(DOD_HEADER, brief)

    def test_drill_lane_does_not_contain_dod(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(pathlib.Path(td), "spark", "Immunefi PoI program.")
            brief = self._brief("drill", ws)
            self.assertNotIn(DOD_HEADER, brief)

    def test_context_none_for_hunt_lane(self):
        ctx = prebriefing.build_filing_finalization_context(
            lane_type="hunt", workspace_path=None
        )
        self.assertIsNone(ctx)

    def test_context_populated_for_filing_lane(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_ws(
                pathlib.Path(td),
                "hyperbridge",
                "HackenProof bounty.",
            )
            ctx = prebriefing.build_filing_finalization_context(
                lane_type="escalation", workspace_path=ws
            )
            self.assertIsNotNone(ctx)
            self.assertEqual(ctx["platform_id"], "hackenproof")
            self.assertEqual(
                ctx["canonical_template"],
                "docs/CANONICAL_HACKENPROOF_PASTE_TEMPLATE.md",
            )
            self.assertTrue(ctx["required_sections"])


class TestRegistryIntegrity(unittest.TestCase):
    def test_registry_has_all_platforms_and_real_templates(self):
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        platforms = data["platforms"]
        for pid in ("cantina", "github-ghsa", "immunefi", "hackenproof", "generic"):
            self.assertIn(pid, platforms, f"missing platform {pid}")
            entry = platforms[pid]
            tmpl = entry["canonical_template"]
            self.assertTrue(
                (REPO_ROOT / tmpl).is_file(),
                f"{pid} canonical_template missing on disk: {tmpl}",
            )
            self.assertTrue(entry["required_sections"], f"{pid} has no sections")
            self.assertTrue(entry["poc_inline_required"])

    # --- NEW: output_format, markdown_allowed, poc_delivery, field_rules ---

    def test_all_platforms_have_output_format(self):
        """Every platform must have an output_format field."""
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        for pid, entry in data["platforms"].items():
            self.assertIn("output_format", entry, f"{pid} missing output_format")
            self.assertIn(
                entry["output_format"],
                ("markdown", "plaintext-txt"),
                f"{pid} unexpected output_format value",
            )

    def test_all_platforms_have_markdown_allowed(self):
        """Every platform must have a boolean markdown_allowed field."""
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        for pid, entry in data["platforms"].items():
            self.assertIn("markdown_allowed", entry, f"{pid} missing markdown_allowed")
            self.assertIsInstance(entry["markdown_allowed"], bool, f"{pid} markdown_allowed not bool")

    def test_all_platforms_have_poc_delivery(self):
        """Every platform must have a non-empty poc_delivery string."""
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        for pid, entry in data["platforms"].items():
            self.assertIn("poc_delivery", entry, f"{pid} missing poc_delivery")
            self.assertTrue(
                isinstance(entry["poc_delivery"], str) and entry["poc_delivery"].strip(),
                f"{pid} poc_delivery is empty",
            )

    def test_all_platforms_have_field_rules(self):
        """Every platform must have a non-empty field_rules list."""
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        for pid, entry in data["platforms"].items():
            self.assertIn("field_rules", entry, f"{pid} missing field_rules")
            self.assertIsInstance(entry["field_rules"], list, f"{pid} field_rules not a list")
            self.assertTrue(len(entry["field_rules"]) > 0, f"{pid} field_rules is empty")

    def test_hackenproof_is_plaintext_no_markdown(self):
        """HackenProof must be output_format=plaintext-txt and markdown_allowed=False."""
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        hp = data["platforms"]["hackenproof"]
        self.assertEqual(hp["output_format"], "plaintext-txt")
        self.assertFalse(hp["markdown_allowed"])

    def test_hackenproof_poc_delivery_mentions_external(self):
        """HackenProof poc_delivery must describe the attached-file / external delivery mode."""
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        hp = data["platforms"]["hackenproof"]
        delivery = hp["poc_delivery"].lower()
        self.assertTrue(
            "attach" in delivery or "zip" in delivery or "external" in delivery,
            "HackenProof poc_delivery must mention attached/zip/external",
        )

    def test_markdown_platforms_have_inline_poc(self):
        """Markdown-allowed platforms must have poc_delivery mentioning inline."""
        data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
        for pid in ("cantina", "immunefi", "github-ghsa", "generic"):
            entry = data["platforms"][pid]
            delivery = entry["poc_delivery"].lower()
            self.assertIn(
                "inline",
                delivery,
                f"{pid} poc_delivery should mention inline",
            )


class TestFilingFinalizationDoDOutputFormat(unittest.TestCase):
    """Verify the DoD section reflects the new output_format / poc_delivery fields."""

    def _brief_for_platform(self, scope_text: str, dir_name: str, lane_type: str = "filing") -> str:
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td) / dir_name
            ws.mkdir(parents=True, exist_ok=True)
            (ws / "SCOPE.md").write_text(scope_text, encoding="utf-8")
            return prebriefing.format_skeleton_as_markdown(
                None,
                lane_type=lane_type,
                severity="HIGH",
                workspace_path=ws,
            )

    def test_hackenproof_dod_says_plaintext_no_markdown(self):
        brief = self._brief_for_platform("HackenProof bounty.", "hyperbridge")
        self.assertIn("PLAIN", brief, "HackenProof DoD must mention PLAIN")
        self.assertIn("plaintext-txt", brief)

    def test_hackenproof_dod_says_no_markdown(self):
        brief = self._brief_for_platform("HackenProof bounty.", "hyperbridge")
        self.assertIn("NO markdown", brief.replace("NO - PLAIN TEXT ONLY", "NO markdown"))

    def test_hackenproof_dod_says_poc_attached_zip(self):
        brief = self._brief_for_platform("HackenProof bounty.", "hyperbridge")
        # The poc_delivery for hackenproof mentions attached zip
        self.assertTrue(
            "zip" in brief.lower() or "attach" in brief.lower(),
            "HackenProof DoD must mention attached zip for PoC delivery",
        )

    def test_cantina_dod_says_markdown_allowed(self):
        brief = self._brief_for_platform("Cantina bug bounty.", "dydx")
        # The DoD section renders a line like:
        #   **Output format**: `markdown` | **Markdown allowed**: YES - markdown rendered
        self.assertIn("markdown", brief.lower())
        # "Markdown allowed" (with space) is the rendered label
        self.assertIn("Markdown allowed", brief)

    def test_cantina_dod_has_output_format(self):
        brief = self._brief_for_platform("Cantina bounty.", "dydx")
        # "Output format" (with space) is the rendered label in the DoD block
        self.assertIn("Output format", brief)
        self.assertIn("markdown", brief)


class TestPlatformExportTool(unittest.TestCase):
    """Verify tools/platform-export.py delegates HackenProof to the canonical exporter.

    platform-export.py is now a thin ROUTER that delegates the hackenproof path to
    tools/hackenproof-plain-export.py (the canonical tool).  It no longer defines its
    own strip_markdown_to_plain / validate_hackenproof_plain functions.
    Tests here assert the delegation contract, not the stripping implementation
    (that is tested in test_hackenproof_plain_export.py).
    """

    EXPORT_TOOL = REPO_ROOT / "tools" / "platform-export.py"
    HP_EXPORT_TOOL = REPO_ROOT / "tools" / "hackenproof-plain-export.py"

    def _load_export_mod(self):
        spec = importlib.util.spec_from_file_location("platform_export", self.EXPORT_TOOL)
        if spec is None or spec.loader is None:
            self.skipTest("Cannot load platform-export.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        return mod

    def _load_hp_mod(self):
        spec = importlib.util.spec_from_file_location("hp_export", self.HP_EXPORT_TOOL)
        if spec is None or spec.loader is None:
            self.skipTest("Cannot load hackenproof-plain-export.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[attr-defined]
        return mod

    def test_router_does_not_define_strip_markdown_to_plain(self):
        """platform-export.py must NOT define its own strip_markdown_to_plain.

        The stripping implementation lives exclusively in hackenproof-plain-export.py.
        """
        mod = self._load_export_mod()
        self.assertFalse(
            hasattr(mod, "strip_markdown_to_plain"),
            "platform-export.py must not define strip_markdown_to_plain "
            "(the canonical tool hackenproof-plain-export.py owns that function)",
        )

    def test_router_does_not_define_validate_hackenproof_plain(self):
        """platform-export.py must NOT define its own validate_hackenproof_plain."""
        mod = self._load_export_mod()
        self.assertFalse(
            hasattr(mod, "validate_hackenproof_plain"),
            "platform-export.py must not define validate_hackenproof_plain "
            "(the canonical tool owns that function)",
        )

    def test_router_defines_delegate_helper(self):
        """platform-export.py must expose _delegate_to_hackenproof_exporter."""
        mod = self._load_export_mod()
        self.assertTrue(
            hasattr(mod, "_delegate_to_hackenproof_exporter"),
            "platform-export.py must have _delegate_to_hackenproof_exporter",
        )

    def test_hackenproof_output_validates_via_canonical_validator(self):
        """Router's hackenproof export must produce a .txt that validates ok=true
        via the canonical hackenproof-plain-export.py --validate path.

        This proves end-to-end delegation: router calls canonical tool; canonical
        tool's output passes the canonical validator.
        """
        hp_mod = self._load_hp_mod()
        with tempfile.TemporaryDirectory() as td:
            draft = pathlib.Path(td) / "my-finding.md"
            draft.write_text(
                "# My Finding Title\n\n"
                "1. Title\n\nmy finding title\n\n"
                "2. Vulnerability details\n\n"
                "Something bad happens in the contract.\n\n"
                "3. Validation steps\n\n"
                "Run: cargo test\n"
                "Result: test passes\n\n"
                "4. Supporting files / PoC\n\n- my-finding-poc.zip\n",
                encoding="utf-8",
            )
            # Run via CLI subprocess to test the full delegation path
            import subprocess as sp
            result = sp.run(
                [sys.executable, str(self.EXPORT_TOOL), str(draft), "--platform", "hackenproof"],
                capture_output=True, text=True, check=False,
            )
            # The router must produce the .txt output file
            out_txt = pathlib.Path(td) / "my-finding.hackenproof-plain.txt"
            self.assertTrue(
                out_txt.exists(),
                f"Router did not produce .hackenproof-plain.txt; "
                f"stdout={result.stdout!r} stderr={result.stderr!r}",
            )
            # The output must validate ok=true via the canonical validator
            val = hp_mod.validate_plain_text(str(out_txt))
            self.assertTrue(
                val["ok"],
                f"Router output failed canonical validator: {val['failures']}",
            )
            self.assertEqual(val["schema"], "auditooor.hackenproof_plain_validate.v1")

    def test_export_draft_hackenproof_writes_txt_and_json(self):
        """export_draft() for hackenproof produces a .txt and .json sidecar via delegation."""
        mod = self._load_export_mod()
        hp_mod = self._load_hp_mod()
        registry = mod.load_registry()
        with tempfile.TemporaryDirectory() as td:
            draft = pathlib.Path(td) / "my-finding.md"
            draft.write_text(
                "# Title\n\n"
                "1. Title\n\nmy finding\n\n"
                "2. Vulnerability details\n\nDetails here.\n\n"
                "3. Validation steps\n\nRun: cargo test\n\n"
                # Deliberately avoid a bare -poc.zip reference so the
                # hackenproof-poc-not-inline-check gate (which enforces that a
                # referenced zip actually exists on disk) doesn't fail rc=3
                # before the json sidecar is written.
                "4. Supporting files / PoC\n\n- see attached files\n",
                encoding="utf-8",
            )
            out = mod.export_draft(draft, "hackenproof", None, registry)
            self.assertTrue(out.exists(), f"Output file not produced: {out}")
            self.assertTrue(out.name.endswith(".txt") or "hackenproof" in out.name)
            content = out.read_text(encoding="utf-8")
            # No markdown headings should remain (stripping by canonical tool)
            for line in content.splitlines():
                self.assertFalse(
                    line.strip().startswith("#"),
                    f"Markdown heading leaked into plain text: {line!r}",
                )
            # Sidecar JSON should exist (produced by canonical tool)
            sidecar = draft.parent / "my-finding.hackenproof-plain.json"
            self.assertTrue(sidecar.exists(), "Canonical tool must produce .json sidecar")
            sidecar_data = json.loads(sidecar.read_text())
            # The sidecar schema must come from the canonical tool.
            # Export mode: schema=auditooor.hackenproof_plain_export.v1 (has section2_over_limit etc)
            # Validate mode: schema=auditooor.hackenproof_plain_validate.v1 (has ok)
            self.assertIn(sidecar_data.get("schema", ""), (
                "auditooor.hackenproof_plain_validate.v1",
                "auditooor.hackenproof_plain_export.v1",
            ), f"Unexpected sidecar schema: {sidecar_data.get('schema')}")
            # Both schemas have a boolean correctness indicator (different keys)
            schema = sidecar_data.get("schema", "")
            if "validate" in schema:
                self.assertIn("ok", sidecar_data)
            else:
                self.assertIn("section2_over_limit", sidecar_data)

    def test_export_draft_hackenproof_output_matches_canonical_tool_output(self):
        """Router's hackenproof output must match what the canonical tool would produce.

        Run both paths on the same draft and assert identical .txt content.
        This is the definitive delegation proof: the router adds NO stripping logic
        of its own, so the outputs must be identical.
        """
        import subprocess as sp
        with tempfile.TemporaryDirectory() as td:
            td = pathlib.Path(td)
            draft_content = (
                "# Title - router vs canonical comparison\n\n"
                "1. Title\n\nRouter vs canonical\n\n"
                "2. Vulnerability details\n\n"
                "A **critical** vulnerability in `foo()` at `bar.rs:42`.\n\n"
                "3. Validation steps\n\nRun tests.\n\n"
                "4. Supporting files / PoC\n\n- router-test-poc.zip\n"
            )
            # Draft for router path
            draft_router = td / "router-test.md"
            draft_router.write_text(draft_content, encoding="utf-8")
            # Draft for canonical path (different dir, same content)
            (td / "canonical").mkdir()
            draft_canonical = td / "canonical" / "router-test.md"
            draft_canonical.write_text(draft_content, encoding="utf-8")

            # Run router
            router_out = td / "router-test.hackenproof-plain.txt"
            r1 = sp.run(
                [sys.executable, str(self.EXPORT_TOOL), str(draft_router),
                 "--platform", "hackenproof", "--out", str(router_out)],
                capture_output=True, text=True, check=False,
            )
            # Run canonical tool directly
            canonical_out = td / "canonical" / "router-test.hackenproof-plain.txt"
            r2 = sp.run(
                [sys.executable, str(self.HP_EXPORT_TOOL), "--draft", str(draft_canonical),
                 "--platform", "hackenproof", "--out", str(canonical_out)],
                capture_output=True, text=True, check=False,
            )

            self.assertTrue(router_out.exists(), f"Router did not produce output; stderr={r1.stderr!r}")
            self.assertTrue(canonical_out.exists(), f"Canonical tool did not produce output; stderr={r2.stderr!r}")

            router_text = router_out.read_text(encoding="utf-8")
            canonical_text = canonical_out.read_text(encoding="utf-8")
            self.assertEqual(
                router_text, canonical_text,
                "Router output differs from canonical tool output - "
                "platform-export.py must not perform its own stripping",
            )

    def test_export_draft_hackenproof_on_real_zebra_draft_strips_markdown(self):
        """Run hackenproof export on the real zebra paste_ready draft - verify markdown stripped.

        The zebra draft uses ### sub-sections; the canonical tool's output should have
        no ATX headings, no fenced blocks, ASCII-only.  The test skips if the draft
        is not present on disk.
        """
        hp_mod = self._load_hp_mod()
        candidates = [
            pathlib.Path("/Users/wolf/audits/zebra/submissions/paste_ready")
            / "zebra-rpc-getaddresstxids-unbounded-span-dos"
            / "zebra-rpc-getaddresstxids-unbounded-span-dos.md",
            pathlib.Path("/Users/wolf/audits/zebra/submissions/filed")
            / "zebra-mempool-per-peer-cap-keyed-on-ip-port-not-ip-HIGH"
            / "zebra-mempool-per-peer-cap-keyed-on-ip-port-not-ip-HIGH.advisory.md",
        ]
        real_draft = next((p for p in candidates if p.exists()), None)
        if real_draft is None:
            self.skipTest("Real zebra draft not found at expected paths")
        with tempfile.TemporaryDirectory() as td:
            import shutil
            tmp_draft = pathlib.Path(td) / real_draft.name
            shutil.copy(real_draft, tmp_draft)
            import subprocess as sp
            out_txt = pathlib.Path(td) / (tmp_draft.stem + ".hackenproof-plain.txt")
            result = sp.run(
                [sys.executable, str(self.EXPORT_TOOL), str(tmp_draft),
                 "--platform", "hackenproof", "--out", str(out_txt)],
                capture_output=True, text=True, check=False,
            )
            self.assertTrue(
                out_txt.exists(),
                f"Router did not produce output for real zebra draft; "
                f"stdout={result.stdout!r} stderr={result.stderr!r}",
            )
            content = out_txt.read_text(encoding="utf-8")
            # No ATX headings should remain after delegation to canonical tool
            for line in content.splitlines():
                self.assertFalse(
                    re.match(r"^#{1,6}\s", line),
                    f"ATX heading leaked into plain text: {line!r}",
                )
            # No fenced code blocks
            self.assertNotIn("```", content)
            # ASCII only
            non_ascii = sum(1 for c in content if ord(c) >= 128)
            self.assertEqual(non_ascii, 0, f"{non_ascii} non-ASCII chars leaked into plain text")


if __name__ == "__main__":
    unittest.main(verbosity=2)
