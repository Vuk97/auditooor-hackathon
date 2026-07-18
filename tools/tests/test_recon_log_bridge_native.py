"""Tests for the native @recon-fuzz/log-parser integration in
``tools/recon-log-bridge.py``.

These tests cover three contracts:

1. **Native path** — when a native parser binary is on PATH, the bridge
   shells out and converts the parser's JSON document into one or more
   ``deep_counterexample.v1`` records.
2. **Stdlib fallback** — when the native parser is unavailable, the
   bridge silently falls back to the stdlib parser (no crash).
3. **Equivalence** — the same Medusa log fed to both parsers produces
   overlapping counterexamples (native is allowed to find more).

The native parser is mocked via a tiny shell-script shim so the suite is
hermetic and does not require ``@recon-fuzz/log-parser`` to be
installed. ``AUDITOOOR_RECON_LOG_PARSER_BIN`` lets us override the
binary the bridge looks up.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "recon-log-bridge.py"


# --- module loading --------------------------------------------------------
#
# The bridge filename uses hyphens, which we cannot import via ``import``
# directly. Load it with importlib so we can call its parser functions in
# unit-style tests too.
def _load_bridge_module():
    spec = importlib.util.spec_from_file_location("recon_log_bridge", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


# --- shim builders ---------------------------------------------------------


def _write_native_shim(target: Path, payload: dict | None, *, exit_code: int = 0) -> Path:
    """Create a fake native parser binary that prints ``payload`` as JSON
    and exits ``exit_code``. ``--version`` is handled explicitly so the
    bridge's probe step succeeds.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    payload_json = json.dumps(payload or {})
    # Use python3 so we don't depend on host shell semantics.
    target.write_text(textwrap.dedent(f"""\
        #!/usr/bin/env python3
        import json, sys
        argv = sys.argv[1:]
        if argv and argv[0] == "--version":
            print("recon-log-parser-mock 0.0.1")
            sys.exit(0)
        # Emit the canned JSON. We deliberately ignore --engine / --json /
        # the positional log so the test stays simple.
        sys.stdout.write({payload_json!r})
        sys.exit({exit_code})
    """))
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target


def _write_failing_shim(target: Path) -> Path:
    """Native parser shim whose ``--version`` exits non-zero so the
    bridge's availability probe returns False.
    """
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(textwrap.dedent("""\
        #!/usr/bin/env python3
        import sys
        sys.exit(2)
    """))
    target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target


# --- subprocess CLI tests --------------------------------------------------


SAMPLE_NATIVE_PAYLOAD = {
    "engine": "medusa",
    "counterexamples": [
        {
            "property": "property_vault_solvent",
            "callSequence": [
                {"target": "Vault", "function": "deposit", "args": ["100"], "raw": "Vault.deposit(100)"},
                {"target": "Vault", "function": "withdraw", "args": ["200"], "raw": "Vault.withdraw(200)"},
            ],
            "rawExcerpt": "Medusa: vault solvency invariant broke",
        },
        {
            "property": "invariant_no_negative_supply",
            "callSequence": [
                {"target": "Token", "function": "burn", "args": ["1"], "raw": "Token.burn(1)"},
            ],
            "rawExcerpt": "Medusa: supply went negative",
        },
    ],
    "metadata": {"parserVersion": "0.0.1"},
}


class NativeBridgeCLITests(unittest.TestCase):
    """End-to-end CLI tests via subprocess, using a shim binary."""

    def _run_bridge(
        self,
        env_overrides: dict[str, str],
        args: list[str],
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        # Make sure no system-installed parser leaks into the test.
        env.pop("AUDITOOOR_RECON_LOG_PARSER_BIN", None)
        env["AUDITOOOR_DISABLE_NATIVE_RECON_PARSER"] = "0"
        env.update(env_overrides)
        return subprocess.run(
            ["python3", str(TOOL), *args],
            text=True,
            capture_output=True,
            env=env,
        )

    def test_native_parser_path_writes_one_record_per_counterexample(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            log = ws / "medusa.log"
            log.write_text("Medusa fuzzer log content (ignored by shim)\n")
            shim = _write_native_shim(root / "shim" / "recon-log-parser", SAMPLE_NATIVE_PAYLOAD)
            result = self._run_bridge(
                {"AUDITOOOR_RECON_LOG_PARSER_BIN": str(shim)},
                [
                    "--workspace",
                    str(ws),
                    "--engine",
                    "medusa",
                    "--log",
                    str(log),
                    "--print-json",
                ],
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            manifest = json.loads(result.stdout)
            self.assertEqual(manifest["parser"], "native")
            self.assertEqual(manifest["status"], "recorded")
            self.assertEqual(len(manifest["records"]), 2)
            for path_str in manifest["records"]:
                record = json.loads(Path(path_str).read_text())
                self.assertEqual(
                    record["schema_version"], "auditooor.deep_counterexample.v1"
                )
                self.assertEqual(record["evidence_class"], "scaffolded_unverified")
            # The first counterexample should preserve the parsed call
            # sequence verbatim.
            first = json.loads(Path(manifest["records"][0]).read_text())
            self.assertIn("Vault.deposit(100)", first["input_sequence"])
            self.assertIn("Vault.withdraw(200)", first["input_sequence"])

    def test_failing_native_probe_falls_back_to_stdlib(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            log = ws / "medusa.log"
            log.write_text(
                "FAILED property_no_bad_debt\n"
                "Call sequence:\n"
                "  Market.resolve(1)\n"
            )
            shim = _write_failing_shim(root / "shim" / "recon-log-parser")
            result = self._run_bridge(
                {"AUDITOOOR_RECON_LOG_PARSER_BIN": str(shim)},
                [
                    "--workspace",
                    str(ws),
                    "--engine",
                    "medusa",
                    "--log",
                    str(log),
                    "--print-json",
                ],
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            manifest = json.loads(result.stdout)
            # Failing --version probe -> bridge silently uses stdlib.
            self.assertEqual(manifest["parser"], "stdlib-fallback")
            self.assertEqual(manifest["status"], "recorded")

    def test_disable_env_forces_stdlib_even_when_shim_present(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            log = ws / "medusa.log"
            log.write_text(
                "FAILED property_pause_consistent\n"
                "Call sequence:\n"
                "  Pauser.pause()\n"
            )
            shim = _write_native_shim(root / "shim" / "recon-log-parser", SAMPLE_NATIVE_PAYLOAD)
            result = self._run_bridge(
                {
                    "AUDITOOOR_RECON_LOG_PARSER_BIN": str(shim),
                    "AUDITOOOR_DISABLE_NATIVE_RECON_PARSER": "1",
                },
                [
                    "--workspace",
                    str(ws),
                    "--engine",
                    "medusa",
                    "--log",
                    str(log),
                    "--print-json",
                ],
            )
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            manifest = json.loads(result.stdout)
            self.assertEqual(manifest["parser"], "stdlib-fallback")


# --- in-process equivalence tests ------------------------------------------


class NativeBridgeEquivalenceTests(unittest.TestCase):
    """Compare native vs. stdlib parsing in-process for the same log."""

    def setUp(self) -> None:
        self.module = _load_bridge_module()

    def test_same_log_overlapping_counterexamples_native_may_find_more(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            ws.mkdir()
            log = ws / "medusa.log"
            log.write_text(
                "FAILED property_vault_solvent\n"
                "Call sequence:\n"
                "  Vault.deposit(100)\n"
                "  Vault.withdraw(200)\n"
            )
            stdlib = self.module._parse_log_stdlib("medusa", log)
            self.assertTrue(stdlib["has_failure"])
            self.assertEqual(stdlib["target_function"], "property_vault_solvent")

            # Build a native payload that overlaps with the stdlib find
            # (same property name) plus one additional counterexample.
            native_payload = {
                "engine": "medusa",
                "counterexamples": [
                    {
                        "property": "property_vault_solvent",
                        "callSequence": [
                            {"raw": "Vault.deposit(100)"},
                            {"raw": "Vault.withdraw(200)"},
                        ],
                        "rawExcerpt": "shared",
                    },
                    {
                        "property": "property_extra_invariant",
                        "callSequence": [{"raw": "Pool.swap(7)"}],
                        "rawExcerpt": "extra",
                    },
                ],
            }
            native_counterexamples = self.module._native_to_counterexamples(
                native_payload, "medusa", log
            )
            self.assertGreaterEqual(len(native_counterexamples), 1)

            stdlib_targets = {stdlib["target_function"]}
            native_targets = {ce["target_function"] for ce in native_counterexamples}
            # Equivalence requirement: every stdlib target must appear in
            # the native set; native is allowed to find more.
            self.assertTrue(stdlib_targets.issubset(native_targets))
            self.assertGreaterEqual(len(native_targets), len(stdlib_targets))

    def test_native_call_sequence_supports_string_and_dict_entries(self) -> None:
        # The published shape may be either pre-rendered strings or
        # structured dicts. Both must be accepted.
        from_strings = self.module._native_call_sequence_to_strings(
            ["A.foo()", "B.bar(1, 2)"]
        )
        self.assertEqual(from_strings, ["A.foo()", "B.bar(1, 2)"])
        from_dicts = self.module._native_call_sequence_to_strings(
            [
                {"target": "A", "function": "foo", "args": []},
                {"target": "B", "function": "bar", "args": [1, 2]},
            ]
        )
        self.assertEqual(from_dicts, ["A.foo()", "B.bar(1, 2)"])

    def test_no_native_binary_returns_stdlib_label(self) -> None:
        # Force-disable the native probe and confirm the orchestrator
        # tags the result as ``stdlib-fallback``.
        prev = os.environ.get("AUDITOOOR_DISABLE_NATIVE_RECON_PARSER")
        os.environ["AUDITOOOR_DISABLE_NATIVE_RECON_PARSER"] = "1"
        try:
            with tempfile.TemporaryDirectory() as td:
                log = Path(td) / "log.txt"
                log.write_text("PASS test_clean\n")
                result = self.module.parse_log("medusa", log)
            self.assertEqual(result["parser"], "stdlib-fallback")
        finally:
            if prev is None:
                os.environ.pop("AUDITOOOR_DISABLE_NATIVE_RECON_PARSER", None)
            else:
                os.environ["AUDITOOOR_DISABLE_NATIVE_RECON_PARSER"] = prev


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
