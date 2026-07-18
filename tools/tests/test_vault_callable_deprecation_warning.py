"""Tests for Phase NEG-B (iter18, 2026-05-23): deprecation_warning injection.

Spec: ``docs/MCP_CALLABLE_DEPRECATIONS_2026-05-23.md``
Lane report: ``reports/v3_iter_2026-05-23_iter18_phase_neg/lane_NEG_B_silent_callables/results.md``

The 6 callables in ``_DEPRECATED_CALLABLES`` (iter14 Lane MMMM verdict,
reconfirmed by WF-6 §2d and WF-10 §6 at iter17) are NOT removed; they
get a ``deprecation_warning`` field injected by the ``call()`` wrapper
into their response envelope. This preserves call-site compatibility
through the 30-day cool-off window (target removal 2026-06-30).

Assertions:
  1. Each of the 6 deprecated callables emits a well-formed
     ``deprecation_warning`` dict with ``callable``, ``status``,
     ``removal_target``, ``replacement``, ``reason``, ``doc`` keys.
  2. Non-deprecated callables receive NO ``deprecation_warning`` key.
  3. The injected warning does NOT clobber a pre-existing key (forward
     compat for future method bodies that may emit their own).
  4. The replacement callable named in each warning IS itself a
     registered ``vault_*`` method on the server (no broken pointer).
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_deprecation_warning_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


class DeprecationWarningInjectionTests(unittest.TestCase):
    """Verify the call() wrapper injects deprecation_warning correctly."""

    def setUp(self) -> None:
        # Telemetry kill-switch so the tests do not append to a real log.
        import os
        os.environ["AUDITOOOR_MCP_TELEMETRY_DISABLE"] = "1"
        # The MCP server class is VaultQuery. Use the repo defaults (the
        # warning-injection logic does not depend on vault contents).
        vault_dir = REPO_ROOT / "obsidian-vault"
        if not vault_dir.exists():
            # Fall back to the active vault per the operator runtime.
            vault_dir = Path.home() / "Documents" / "Codex" / "auditooor" / "obsidian-vault"
        self.server = vault_mcp_server.VaultQuery(vault_dir, REPO_ROOT)

    def test_deprecated_callables_inject_warning(self) -> None:
        """Each of the 6 deprecated callables emits the warning envelope."""
        for name, meta in vault_mcp_server._DEPRECATED_CALLABLES.items():
            with self.subTest(callable=name):
                result = self.server.call(name, {})
                self.assertIsInstance(result, dict, f"{name} must return dict")
                self.assertIn(
                    "deprecation_warning", result,
                    f"{name} response missing deprecation_warning",
                )
                warn = result["deprecation_warning"]
                self.assertIsInstance(warn, dict)
                self.assertEqual(warn["callable"], name)
                self.assertEqual(warn["status"], "deprecated")
                self.assertEqual(warn["removal_target"], meta["removal_target"])
                self.assertEqual(warn["replacement"], meta["replacement"])
                self.assertEqual(warn["reason"], meta["reason"])
                self.assertEqual(
                    warn["doc"],
                    "docs/MCP_CALLABLE_DEPRECATIONS_2026-05-23.md",
                )

    def test_non_deprecated_callable_has_no_warning(self) -> None:
        """vault_resume_context is a Layer-1 canonical callable; no warning."""
        result = self.server.call(
            "vault_resume_context",
            {"workspace_path": str(REPO_ROOT), "limit": 1},
        )
        self.assertIsInstance(result, dict)
        self.assertNotIn("deprecation_warning", result)

    def test_other_canonical_callables_have_no_warning(self) -> None:
        """Sample 5 canonical Layer-1/Layer-2 callables; none get the warning."""
        canonical = [
            "vault_resume_context",
            "vault_exploit_context",
            "vault_knowledge_gap_context",
            "vault_engagement_status",
            "vault_harness_context",
        ]
        for name in canonical:
            with self.subTest(callable=name):
                result = self.server.call(name, {})
                self.assertIsInstance(result, dict)
                self.assertNotIn(
                    "deprecation_warning", result,
                    f"{name} (canonical) unexpectedly received deprecation_warning",
                )

    def test_replacement_callables_are_registered(self) -> None:
        """Every replacement named in a deprecation_warning must be a real method."""
        registered = {
            schema["name"] for schema in vault_mcp_server.TOOL_SCHEMAS
        }
        for name, meta in vault_mcp_server._DEPRECATED_CALLABLES.items():
            with self.subTest(callable=name):
                replacement = meta["replacement"]
                self.assertIn(
                    replacement, registered,
                    f"{name}'s replacement {replacement!r} is not in TOOL_SCHEMAS",
                )

    def test_deprecation_warning_does_not_clobber_existing_key(self) -> None:
        """If a method body ever emits its own deprecation_warning, preserve it."""
        # setdefault is the chosen semantic; verify by monkey-patching the
        # dispatcher to inject a known sentinel for one deprecated callable.
        sentinel = {"sentinel": "preserved-from-method-body"}
        original_dispatch = self.server._dispatch

        def patched_dispatch(name: str, args: dict[str, Any]) -> dict[str, Any]:
            if name == "vault_dupe_advisory_check":
                return {"deprecation_warning": sentinel, "ok": True}
            return original_dispatch(name, args)

        self.server._dispatch = patched_dispatch  # type: ignore[assignment]
        try:
            result = self.server.call("vault_dupe_advisory_check", {})
        finally:
            self.server._dispatch = original_dispatch  # type: ignore[assignment]
        self.assertEqual(result["deprecation_warning"], sentinel)

    def test_deprecated_set_matches_iter14_mmmm_list(self) -> None:
        """The deprecated callables match the iter14 Lane MMMM verdict.

        vault_anti_pattern_corpus was REMOVED from the set 2026-06-19
        (A7-deprecation-fix): the detector reports it as live-low-volume
        with genuine production callers, so its deprecation was rescinded.
        """
        expected = {
            "vault_fanout_pattern_library",
            "vault_detector_backtest",
            "vault_bug_class_priority",
            "vault_exploit_chain_unifier",
            "vault_dupe_advisory_check",
        }
        self.assertEqual(
            set(vault_mcp_server._DEPRECATED_CALLABLES.keys()),
            expected,
        )


class DeprecatedCallablesHaveNoProductionCallerTests(unittest.TestCase):
    """A7-deprecation-fix regression guard.

    Every name in ``_DEPRECATED_CALLABLES`` must have NO genuine production
    (--call) caller. A genuine caller is a non-test, non-self, non-infra
    ``tools/*.py`` orchestrator that wires the callable via subprocess.

    Infra surfaces that legitimately reference every callable (smoke test,
    latency benchmark, the detector itself, the server, this deprecation
    test, capability-inventory and corpus-bootstrap scaffolds) are NOT
    production callers and are filtered out.

    This test FAILED on ``vault_anti_pattern_corpus`` before the fix (it has
    5 genuine production callers) and PASSES after that entry is removed from
    the deprecation registry. The drift it catches is exactly the bug
    A7-deprecation-fix corrects: a live-wired callable flagged for removal.
    """

    # Non-production reference surfaces: benchmark / smoke / inventory /
    # self-reference scaffolds that name every callable by design.
    _INFRA_BASENAMES = {
        "hackerman-mcp-smoke-test.py",
        "hackerman-mcp-latency-benchmark.py",
        "callable-caller-detector.py",
        "vault-mcp-server.py",
        "capability-inventory-build.py",
        "anti-pattern-corpus-bootstrap.py",
        "auditor-backtest.py",
    }

    def _detector_path(self) -> Path:
        return REPO_ROOT / "tools" / "callable-caller-detector.py"

    def _genuine_production_callers(self, name: str) -> list[str]:
        """Run the detector and return non-test, non-infra caller basenames."""
        import json
        import os
        import subprocess

        proc = subprocess.run(
            [
                sys.executable,
                str(self._detector_path()),
                name,
                "--scope",
                "local",
                "--json",
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"callable-caller-detector failed for {name}: {proc.stderr[-400:]}",
        )
        data = json.loads(proc.stdout)
        genuine: list[str] = []
        for caller in data.get("callers", []):
            basename = os.path.basename(caller.get("file", ""))
            if caller.get("is_test") or caller.get("is_self"):
                continue
            if basename.startswith("test_"):
                continue
            # docs / self-registry / enforcement-hook allowlists are not
            # production --call wiring. The .sh usage-enforce hook names every
            # canonical callable as a flat allowlist by design (spec: do NOT
            # treat the hook KNOWN_CALLABLES list as a deprecation signal).
            if caller.get("surface") in {
                "docs_md",
                "registry_self_ref",
                "pre_submit_check_and_sh_wrappers",
            }:
                continue
            if basename in self._INFRA_BASENAMES:
                continue
            genuine.append(basename)
        return sorted(set(genuine))

    def test_deprecated_callables_have_no_production_caller(self) -> None:
        """No registry-deprecated callable may have a live production caller."""
        if not self._detector_path().exists():
            self.skipTest("callable-caller-detector.py absent")
        for name in vault_mcp_server._DEPRECATED_CALLABLES:
            with self.subTest(callable=name):
                genuine = self._genuine_production_callers(name)
                self.assertEqual(
                    genuine,
                    [],
                    f"{name} is in _DEPRECATED_CALLABLES but has genuine "
                    f"production callers {genuine}; remove it from the "
                    f"deprecation registry (A7-deprecation-fix).",
                )

    def test_anti_pattern_corpus_is_not_deprecated(self) -> None:
        """Explicit anchor: the rescinded callable is gone from the registry."""
        self.assertNotIn(
            "vault_anti_pattern_corpus",
            vault_mcp_server._DEPRECATED_CALLABLES,
            "vault_anti_pattern_corpus is live-wired and must not be deprecated",
        )

    def test_anti_pattern_corpus_has_production_callers(self) -> None:
        """Witness that the rescinded callable really is live-wired.

        This proves the regression guard above is load-bearing: if the
        callable had no production caller, removing it from the registry
        would be cosmetic.
        """
        if not self._detector_path().exists():
            self.skipTest("callable-caller-detector.py absent")
        genuine = self._genuine_production_callers("vault_anti_pattern_corpus")
        self.assertTrue(
            genuine,
            "vault_anti_pattern_corpus expected to have genuine production "
            "callers; if it does not, the A7 premise is wrong",
        )


if __name__ == "__main__":
    unittest.main()
