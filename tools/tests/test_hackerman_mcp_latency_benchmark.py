"""Tests for the Wave-1 hackerman MCP latency benchmark.

The tool under test is at ``tools/hackerman-mcp-latency-benchmark.py``.
These tests exercise the pure-Python building blocks (percentile,
summariser, registry loader, aggregator, table formatter) plus the
``benchmark_callable()`` integration path via subprocess stubs.

Live end-to-end runs against ``tools/vault-mcp-server.py`` are out of
scope for the unit test (operator runs them on demand via
``make hackerman-mcp-latency-benchmark``).
"""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "tools" / "hackerman-mcp-latency-benchmark.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("hackerman_mcp_latency_benchmark", SCRIPT)
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


class SchemaPinTest(unittest.TestCase):
    """Schema string + required constants are pinned."""

    def test_schema_constant_is_pinned(self) -> None:
        # Downstream dashboards / Wave-2 perf-review tooling key off this
        # schema string; do not rename without coordinating.
        self.assertEqual(
            MODULE.SCHEMA, "auditooor.hackerman_mcp_latency_benchmark.v1"
        )
        self.assertEqual(MODULE.DEFAULT_RUNS, 3)
        self.assertGreaterEqual(MODULE.DEFAULT_TIMEOUT_SECONDS, 60)

    def test_default_args_covers_core_wave1_callables(self) -> None:
        # The fixture map must enumerate the Wave-1 surface so live runs
        # have non-trivial arguments where the callable needs them.
        for required in (
            "vault_corpus_search",
            "vault_attack_class_taxonomy",
            "vault_dupe_advisory_check",
            "vault_severity_calibration",
            "vault_attack_class_evidence_v2",
            "vault_attack_class_evidence_v3",
            "vault_hacker_brief_for_lane_v2",
            "vault_hacker_brief_for_lane_v3",
            "vault_resume_context",
            "vault_exploit_context",
        ):
            self.assertIn(required, MODULE.DEFAULT_ARGS, required)


class PercentileTest(unittest.TestCase):
    """``_percentile`` linear interpolation behaviour."""

    def test_percentile_empty_returns_zero(self) -> None:
        self.assertEqual(MODULE._percentile([], 99.0), 0.0)

    def test_percentile_single_value_returns_value(self) -> None:
        self.assertEqual(MODULE._percentile([2.5], 99.0), 2.5)

    def test_percentile_p99_of_three_returns_near_max(self) -> None:
        # With n=3 and pct=99, the linear-interp rank is 0.99 * 2 = 1.98,
        # which is between the 2nd and 3rd ordered values.
        out = MODULE._percentile([1.0, 2.0, 3.0], 99.0)
        self.assertGreater(out, 2.9)
        self.assertLessEqual(out, 3.0)

    def test_percentile_p50_of_three_equals_median(self) -> None:
        out = MODULE._percentile([1.0, 2.0, 3.0], 50.0)
        self.assertAlmostEqual(out, 2.0, places=6)

    def test_percentile_clamps_pct_to_range(self) -> None:
        ordered = [1.0, 2.0, 3.0]
        self.assertEqual(MODULE._percentile(ordered, -10.0), 1.0)
        self.assertEqual(MODULE._percentile(ordered, 110.0), 3.0)


class SummariseSamplesTest(unittest.TestCase):
    """`_summarise_samples` verdict + aggregate logic."""

    def test_summarise_ok_with_three_samples(self) -> None:
        row = MODULE._summarise_samples(
            "vault_corpus_search",
            {"limit": 1},
            runs=3,
            samples=[0.1, 0.2, 0.3],
            errors=[],
        )
        self.assertEqual(row.verdict, "ok")
        self.assertEqual(row.error_runs, 0)
        self.assertAlmostEqual(row.mean_seconds, 0.2, places=3)
        self.assertAlmostEqual(row.median_seconds, 0.2, places=3)
        self.assertGreater(row.p99_seconds, 0.29)
        self.assertEqual(row.min_seconds, 0.1)
        self.assertEqual(row.max_seconds, 0.3)

    def test_summarise_partial_errors_flags_verdict(self) -> None:
        row = MODULE._summarise_samples(
            "vault_corpus_search",
            {"limit": 1},
            runs=3,
            samples=[0.1, 0.2],
            errors=["nonzero_exit: rc=1 stderr=boom"],
        )
        self.assertEqual(row.verdict, "partial_errors")
        self.assertEqual(row.error_runs, 1)
        self.assertIn("nonzero_exit", row.last_error)

    def test_summarise_all_errors_flags_verdict(self) -> None:
        row = MODULE._summarise_samples(
            "vault_corpus_search",
            {"limit": 1},
            runs=2,
            samples=[],
            errors=["timeout_after_5s", "timeout_after_5s"],
        )
        self.assertEqual(row.verdict, "all_errors")
        self.assertEqual(row.error_runs, 2)
        self.assertEqual(row.mean_seconds, 0.0)
        self.assertEqual(row.p99_seconds, 0.0)

    def test_summarise_low_sample_flags_single_run(self) -> None:
        row = MODULE._summarise_samples(
            "vault_corpus_search",
            {"limit": 1},
            runs=1,
            samples=[0.5],
            errors=[],
        )
        self.assertEqual(row.verdict, "low_sample")

    def test_summarise_no_registered_args_flags_unknown_callable(self) -> None:
        # An unknown callable with empty args triggers the no_registered_args
        # verdict so the operator notices missing fixture coverage.
        row = MODULE._summarise_samples(
            "vault_does_not_exist_yet",
            {},
            runs=3,
            samples=[0.1, 0.2, 0.3],
            errors=[],
        )
        self.assertEqual(row.verdict, "no_registered_args")


class BenchmarkCallableTest(unittest.TestCase):
    """``benchmark_callable`` orchestrates N invocations via subprocess."""

    def _patch_invoke_once(self, side_effects):
        """Patch _invoke_once to return a sequence of (elapsed, error) tuples."""
        return patch.object(MODULE, "_invoke_once", side_effect=side_effects)

    def test_benchmark_callable_aggregates_three_runs(self) -> None:
        side_effects = [(0.10, ""), (0.20, ""), (0.30, "")]
        with self._patch_invoke_once(side_effects):
            row = MODULE.benchmark_callable("vault_corpus_search", {"limit": 1}, runs=3)
        self.assertEqual(row.verdict, "ok")
        self.assertEqual(len(row.samples_seconds), 3)
        self.assertAlmostEqual(row.mean_seconds, 0.2, places=3)
        self.assertEqual(row.error_runs, 0)

    def test_benchmark_callable_records_errors(self) -> None:
        side_effects = [
            (0.1, ""),
            (5.0, "nonzero_exit: rc=1 stderr=boom"),
            (0.2, ""),
        ]
        with self._patch_invoke_once(side_effects):
            row = MODULE.benchmark_callable("vault_corpus_search", {"limit": 1}, runs=3)
        self.assertEqual(row.verdict, "partial_errors")
        self.assertEqual(row.error_runs, 1)
        self.assertEqual(len(row.samples_seconds), 2)

    def test_benchmark_callable_falls_back_to_registered_args(self) -> None:
        # When args=None, the function looks up the fixture in DEFAULT_ARGS.
        side_effects = [(0.05, ""), (0.06, ""), (0.07, "")]
        with self._patch_invoke_once(side_effects):
            row = MODULE.benchmark_callable("vault_corpus_search", runs=3)
        self.assertEqual(row.args, {"attack_class": "reentrancy", "limit": 2})

    def test_benchmark_callable_rejects_zero_runs(self) -> None:
        with self.assertRaises(ValueError):
            MODULE.benchmark_callable("vault_corpus_search", {"limit": 1}, runs=0)


class DiscoverCallablesTest(unittest.TestCase):
    """``discover_callables`` parses the --call choice list from --help."""

    def test_discover_callables_parses_help_output(self) -> None:
        fake_help = (
            "usage: vault-mcp-server.py [-h]\n"
            "options:\n"
            "  --call {vault_search,vault_get,vault_corpus_search,not_a_vault_call}\n"
            "  --args ARGS\n"
        )
        with patch.object(
            MODULE.subprocess,
            "run",
            return_value=_FakeProc(stdout=fake_help, returncode=0),
        ):
            names = MODULE.discover_callables()
        self.assertIn("vault_search", names)
        self.assertIn("vault_corpus_search", names)
        # Non-vault_* names are filtered out by the discoverer.
        self.assertNotIn("not_a_vault_call", names)
        # Result is alphabetical / deduped.
        self.assertEqual(names, sorted(names))

    def test_discover_callables_raises_on_malformed_help(self) -> None:
        with patch.object(
            MODULE.subprocess,
            "run",
            return_value=_FakeProc(stdout="no choices here", returncode=0),
        ):
            with self.assertRaises(RuntimeError):
                MODULE.discover_callables()


class AggregateAndFormatTest(unittest.TestCase):
    """Aggregator + table formatter behaviour."""

    def _row(self, name: str, p99: float, verdict: str = "ok") -> "MODULE.CallableLatencyRow":
        return MODULE.CallableLatencyRow(
            name=name,
            args={},
            runs=3,
            samples_seconds=[p99 - 0.01, p99 - 0.005, p99],
            mean_seconds=p99 - 0.005,
            median_seconds=p99 - 0.005,
            p99_seconds=p99,
            min_seconds=p99 - 0.01,
            max_seconds=p99,
            error_runs=0,
            last_error="",
            verdict=verdict,
        )

    def test_aggregate_counts_verdicts(self) -> None:
        rows = [
            self._row("a", 0.5, "ok"),
            self._row("b", 1.5, "partial_errors"),
            self._row("c", 2.5, "all_errors"),
            self._row("d", 0.3, "no_registered_args"),
        ]
        envelope = MODULE.aggregate(rows, runs=3)
        self.assertEqual(envelope["callables_total"], 4)
        self.assertEqual(envelope["callables_ok"], 1)
        self.assertEqual(envelope["callables_partial_errors"], 1)
        self.assertEqual(envelope["callables_all_errors"], 1)
        self.assertEqual(envelope["callables_no_registered_args"], 1)
        self.assertEqual(envelope["schema"], MODULE.SCHEMA)
        self.assertEqual(envelope["runs_per_callable"], 3)

    def test_aggregate_top10_is_sorted_by_p99_desc(self) -> None:
        rows = [
            self._row("slow", 5.0, "ok"),
            self._row("fast", 0.5, "ok"),
            self._row("middle", 2.0, "ok"),
        ]
        envelope = MODULE.aggregate(rows, runs=3)
        top = envelope["top10_p99_seconds"]
        self.assertEqual(top[0]["name"], "slow")
        self.assertEqual(top[1]["name"], "middle")
        self.assertEqual(top[2]["name"], "fast")

    def test_format_table_renders_rows_and_top10(self) -> None:
        rows = [self._row("vault_corpus_search", 0.4), self._row("vault_get", 0.1)]
        envelope = MODULE.aggregate(rows, runs=3)
        text = MODULE.format_table(envelope)
        self.assertIn("vault_corpus_search", text)
        self.assertIn("vault_get", text)
        self.assertIn("Top-10 by p99", text)
        self.assertIn("total=2", text)


class RegistryLoaderTest(unittest.TestCase):
    """Custom-registry JSON parsing."""

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

    def test_load_registry_default_auto_discovers(self) -> None:
        # With path=None, the loader should call discover_callables and
        # merge with DEFAULT_ARGS. Stub discover_callables to a known set.
        with patch.object(
            MODULE, "discover_callables", return_value=["vault_corpus_search", "vault_get"]
        ):
            loaded = MODULE.load_registry(None)
        names = [n for (n, _a) in loaded]
        self.assertEqual(names, ["vault_corpus_search", "vault_get"])
        # vault_corpus_search has a fixture entry in DEFAULT_ARGS.
        first_args = dict(loaded[0][1])
        self.assertEqual(first_args.get("attack_class"), "reentrancy")

    def test_load_registry_rejects_non_list(self) -> None:
        import tempfile

        with tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump({"not": "a list"}, fh)
            path = Path(fh.name)
        try:
            with self.assertRaises(ValueError):
                MODULE.load_registry(path)
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()
