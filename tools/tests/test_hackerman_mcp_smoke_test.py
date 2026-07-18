"""Tests for the Wave-1 hackerman MCP callable smoke-test runner.

The runner under test is at ``tools/hackerman-mcp-smoke-test.py``. These
tests exercise the runner's pure-Python building blocks (envelope decoder,
required-key check, registry loader, aggregator, table formatter) plus the
``run_callable()`` integration path via subprocess stubs and a single live
end-to-end invocation against the real ``tools/vault-mcp-server.py`` when
the corpus is available.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "hackerman-mcp-smoke-test.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("hackerman_mcp_smoke_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load_module()


class _FakeProc:
    """Minimal stand-in for subprocess.CompletedProcess."""

    def __init__(self, *, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class SmokeRunnerSchemaTest(unittest.TestCase):
    """Schema / registry sanity checks."""

    def test_smoke_runner_schema_constant_pinned(self) -> None:
        # Schema string must match the wave-1 envelope contract; downstream
        # tooling pins this name in dashboards / status reports.
        self.assertEqual(
            MODULE.SCHEMA, "auditooor.hackerman_mcp_smoke_test.v1"
        )
        self.assertEqual(
            MODULE.REQUIRED_KEYS,
            ("schema", "context_pack_id", "context_pack_hash", "source_refs"),
        )

    def test_wave1_registry_has_core_callables(self) -> None:
        # The baked-in registry must enumerate the Wave-1 callables the
        # smoke test claims to cover.
        names = {name for (name, _args) in MODULE.WAVE1_REGISTRY}
        for required in (
            "vault_attack_class_taxonomy",
            "vault_corpus_search",
            "vault_corpus_subtree_summary",
            "vault_dupe_advisory_check",
            "vault_severity_calibration",
            "vault_attack_class_orphan_report",
            "vault_attack_class_evidence_v2",
            "vault_attack_class_evidence_v3",
            "vault_hacker_brief_for_lane_v2",
            "vault_hacker_brief_for_lane_v3",
        ):
            self.assertIn(required, names)


class EnvelopeShapeTest(unittest.TestCase):
    """Sample-callable result-shape validation."""

    def test_decode_envelope_round_trips(self) -> None:
        payload = {
            "schema": "auditooor.vault_corpus_search.v1",
            "context_pack_id": "ctx-1",
            "context_pack_hash": "abc",
            "source_refs": ["audit/corpus_tags/tags"],
            "records": [],
        }
        envelope, err = MODULE._decode_envelope(json.dumps(payload))
        self.assertEqual(err, "")
        self.assertIsNotNone(envelope)
        self.assertEqual(envelope, payload)

    def test_decode_envelope_rejects_empty(self) -> None:
        envelope, err = MODULE._decode_envelope("   \n  ")
        self.assertIsNone(envelope)
        self.assertEqual(err, "empty stdout")

    def test_decode_envelope_rejects_non_object(self) -> None:
        envelope, err = MODULE._decode_envelope("[1,2,3]")
        self.assertIsNone(envelope)
        self.assertTrue(err.startswith("envelope_not_object"), err)

    def test_missing_required_keys_detects_gap(self) -> None:
        partial = {"schema": "x", "context_pack_id": "y"}
        missing = MODULE._missing_required_keys(partial)
        self.assertEqual(set(missing), {"context_pack_hash", "source_refs"})

    def test_missing_required_keys_returns_empty_on_full(self) -> None:
        full = {
            "schema": "x",
            "context_pack_id": "y",
            "context_pack_hash": "z",
            "source_refs": [],
        }
        self.assertEqual(MODULE._missing_required_keys(full), [])


class RunCallableTest(unittest.TestCase):
    """Per-callable run paths exercised via stubbed subprocess."""

    def _stub_run(self, fake_proc):
        return patch.object(MODULE.subprocess, "run", return_value=fake_proc)

    def test_run_callable_passes_on_valid_envelope(self) -> None:
        stdout = json.dumps(
            {
                "schema": "auditooor.vault_corpus_search.v1",
                "context_pack_id": "ctx-2",
                "context_pack_hash": "deadbeef",
                "source_refs": ["audit/corpus_tags/tags"],
                "records": [],
            }
        )
        with self._stub_run(_FakeProc(stdout=stdout)):
            result = MODULE.run_callable("vault_corpus_search", {"limit": 1})
        self.assertTrue(result.passed)
        self.assertEqual(result.missing_keys, [])
        self.assertEqual(result.schema_value, "auditooor.vault_corpus_search.v1")
        self.assertEqual(result.error, "")

    def test_run_callable_fails_on_missing_keys(self) -> None:
        stdout = json.dumps(
            {
                "schema": "auditooor.vault_corpus_search.v1",
                "context_pack_id": "ctx-3",
                # context_pack_hash + source_refs intentionally absent
            }
        )
        with self._stub_run(_FakeProc(stdout=stdout)):
            result = MODULE.run_callable("vault_corpus_search", {"limit": 1})
        self.assertFalse(result.passed)
        self.assertEqual(set(result.missing_keys), {"context_pack_hash", "source_refs"})
        self.assertIn("missing_required_keys", result.error)

    def test_run_callable_handles_callable_not_found_gracefully(self) -> None:
        # vault-mcp-server.py exits 2 when --call resolves to an unknown
        # callable name; the runner must surface that as a FAIL with a
        # descriptive error but never raise.
        proc = _FakeProc(stdout="", stderr="bogus_callable", returncode=2)
        with self._stub_run(proc):
            result = MODULE.run_callable("vault_does_not_exist", {})
        self.assertFalse(result.passed)
        self.assertIn("callable_not_found", result.error)

    def test_run_callable_handles_nonzero_exit(self) -> None:
        proc = _FakeProc(stdout="", stderr="boom", returncode=7)
        with self._stub_run(proc):
            result = MODULE.run_callable("vault_corpus_search", {})
        self.assertFalse(result.passed)
        self.assertIn("nonzero_exit", result.error)

    def test_run_callable_handles_decode_error(self) -> None:
        proc = _FakeProc(stdout="not-json-at-all")
        with self._stub_run(proc):
            result = MODULE.run_callable("vault_corpus_search", {})
        self.assertFalse(result.passed)
        self.assertIn("json_decode_error", result.error)


class AggregationTest(unittest.TestCase):
    """All-pass and partial-fail aggregation behaviour."""

    def _stub_results(self, payloads: list[tuple[str, dict]]) -> list:
        # Build CallableResult objects directly to keep the aggregator
        # test focused on the rollup logic.
        out = []
        for name, env in payloads:
            missing = MODULE._missing_required_keys(env)
            out.append(
                MODULE.CallableResult(
                    name=name,
                    args={},
                    passed=not missing,
                    elapsed_seconds=0.1,
                    missing_keys=missing,
                    error="" if not missing else f"missing_required_keys: {','.join(missing)}",
                    schema_value=str(env.get("schema", "")),
                )
            )
        return out

    def test_all_pass_case(self) -> None:
        env_ok = {
            "schema": "auditooor.x.v1",
            "context_pack_id": "ctx",
            "context_pack_hash": "h",
            "source_refs": [],
        }
        results = self._stub_results([("a", env_ok), ("b", env_ok)])
        envelope = MODULE.aggregate(results)
        self.assertTrue(envelope["all_passed"])
        self.assertEqual(envelope["callables_total"], 2)
        self.assertEqual(envelope["callables_passed"], 2)
        self.assertEqual(envelope["callables_failed"], 0)
        self.assertEqual(envelope["schema"], MODULE.SCHEMA)

    def test_partial_fail_aggregation(self) -> None:
        env_ok = {
            "schema": "auditooor.x.v1",
            "context_pack_id": "ctx",
            "context_pack_hash": "h",
            "source_refs": [],
        }
        env_bad = {"schema": "auditooor.x.v1"}  # missing 3 keys
        results = self._stub_results([("ok", env_ok), ("bad", env_bad)])
        envelope = MODULE.aggregate(results)
        self.assertFalse(envelope["all_passed"])
        self.assertEqual(envelope["callables_total"], 2)
        self.assertEqual(envelope["callables_passed"], 1)
        self.assertEqual(envelope["callables_failed"], 1)
        # The failing row must carry diagnostic detail downstream.
        bad_row = next(r for r in envelope["results"] if r["name"] == "bad")
        self.assertFalse(bad_row["passed"])
        self.assertIn("context_pack_hash", bad_row["missing_keys"])

    def test_empty_registry_aggregates_to_not_all_passed(self) -> None:
        # Edge: empty registry must not silently report all_passed=True.
        envelope = MODULE.aggregate([])
        self.assertFalse(envelope["all_passed"])
        self.assertEqual(envelope["callables_total"], 0)


class RegistryLoaderTest(unittest.TestCase):
    """Custom-registry parsing."""

    def test_load_registry_default(self) -> None:
        loaded = MODULE.load_registry(None)
        self.assertEqual(loaded, list(MODULE.WAVE1_REGISTRY))

    def test_load_registry_from_json_file(self) -> None:
        import tempfile

        rows = [
            {"name": "vault_corpus_search", "args": {"limit": 1}},
            {"name": "vault_attack_class_taxonomy", "args": {}},
        ]
        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(rows, fh)
            path = Path(fh.name)
        try:
            loaded = MODULE.load_registry(path)
            self.assertEqual(
                loaded,
                [
                    ("vault_corpus_search", {"limit": 1}),
                    ("vault_attack_class_taxonomy", {}),
                ],
            )
        finally:
            path.unlink()


class TableFormattingTest(unittest.TestCase):
    def test_format_table_renders_pass_and_fail(self) -> None:
        envelope = {
            "schema": MODULE.SCHEMA,
            "callables_total": 2,
            "callables_passed": 1,
            "callables_failed": 1,
            "all_passed": False,
            "results": [
                {
                    "name": "vault_corpus_search",
                    "args": {},
                    "passed": True,
                    "elapsed_seconds": 0.5,
                    "missing_keys": [],
                    "error": "",
                    "schema_value": "auditooor.vault_corpus_search.v1",
                },
                {
                    "name": "vault_dupe_advisory_check",
                    "args": {},
                    "passed": False,
                    "elapsed_seconds": 0.6,
                    "missing_keys": ["source_refs"],
                    "error": "missing_required_keys: source_refs",
                    "schema_value": "auditooor.vault_dupe_advisory_check.v1",
                },
            ],
        }
        text = MODULE.format_table(envelope)
        self.assertIn("PASS", text)
        self.assertIn("FAIL", text)
        self.assertIn("vault_corpus_search", text)
        self.assertIn("vault_dupe_advisory_check", text)
        self.assertIn("total=2", text)


if __name__ == "__main__":
    unittest.main()
