from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "pattern-compile.py"
RUNNER = REPO / "detectors" / "run_custom.py"
REGISTRY = REPO / "reference" / "detector_class_map_complete.yaml"

SEED_PATTERN = "vault-credit-capacity-stale"
SEED_DSL = REPO / "reference" / "patterns.dsl" / f"{SEED_PATTERN}.yaml"
SEED_VULN_FIXTURE = REPO / "patterns" / "fixtures" / "vault-credit-capacity-stale_vuln.sol"
SEED_CLEAN_FIXTURE = REPO / "patterns" / "fixtures" / "vault-credit-capacity-stale_clean.sol"

REUSABLE_PATTERN = "cached-accounting-read-without-refresh"
REUSABLE_DSL = REPO / "reference" / "patterns.dsl" / f"{REUSABLE_PATTERN}.yaml"
REUSABLE_VULN_FIXTURE = REPO / "patterns" / "fixtures" / "cached-accounting-read-without-refresh_vuln.sol"
REUSABLE_CLEAN_FIXTURE = REPO / "patterns" / "fixtures" / "cached-accounting-read-without-refresh_clean.sol"


def _load_pattern_compile():
    spec = importlib.util.spec_from_file_location("pattern_compile_cache_lift", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=REPO,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class CacheCoherenceRecallLiftTest(unittest.TestCase):
    def _hits(self, pattern: str, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), pattern],
            cwd=REPO,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(pattern, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_seed_dsl_tracks_cache_invalidation_invariant(self) -> None:
        data = yaml.safe_load(SEED_DSL.read_text(encoding="utf-8"))
        preconditions = data["preconditions"]
        matchers = data["match"]

        self.assertEqual(data["attack_class"], "cache-coherence-violation")
        self.assertIn("invalidate the cache", data["class_invariant"])

        state_var_regex = next(
            row["contract.has_state_var_matching"]
            for row in preconditions
            if "contract.has_state_var_matching" in row
        )
        helper_regex = next(
            row["contract.has_function_matching"]
            for row in preconditions
            if "contract.has_function_matching" in row
        )
        write_regex = next(
            row["function.writes_storage_matching"]
            for row in matchers
            if "function.writes_storage_matching" in row
        )
        fn_name_regex = next(
            row["function.name_matches"]
            for row in matchers
            if "function.name_matches" in row
        )

        self.assertIn("collateral", state_var_regex)
        self.assertIn("utilization", state_var_regex)
        self.assertIn("oracle", state_var_regex)
        self.assertIn("lastRefresh", state_var_regex)
        self.assertIn("checkpointCapacity", helper_regex)
        self.assertIn("refreshCapacity", helper_regex)
        self.assertIn("refreshAccounting", helper_regex)
        self.assertIn("invalidateCache", helper_regex)
        self.assertIn("collateral", write_regex)
        self.assertIn("utilization", write_regex)
        self.assertIn("cached", write_regex)
        self.assertIn("lastUpdated", write_regex)
        self.assertIn("withdraw", fn_name_regex)
        self.assertIn("liquidat", fn_name_regex)

    def test_reusable_dsl_tracks_cached_readers_without_refresh(self) -> None:
        data = yaml.safe_load(REUSABLE_DSL.read_text(encoding="utf-8"))
        preconditions = data["preconditions"]
        matchers = data["match"]

        self.assertEqual(data["attack_class"], "cache-coherence-violation")
        self.assertIn("consumes cached capacity", data["class_invariant"])

        state_var_regex = next(
            row["contract.has_state_var_matching"]
            for row in preconditions
            if "contract.has_state_var_matching" in row
        )
        helper_regex = next(
            row["contract.has_function_matching"]
            for row in preconditions
            if "contract.has_function_matching" in row
        )
        name_regex = next(
            row["function.name_matches"]
            for row in matchers
            if "function.name_matches" in row
        )
        read_regex = next(
            row["function.reads_storage_matching"]
            for row in matchers
            if "function.reads_storage_matching" in row
        )
        freshness_negation = [
            row["function.body_not_contains_regex"]
            for row in matchers
            if "function.body_not_contains_regex" in row
        ]

        self.assertIn("cached", state_var_regex)
        self.assertIn("oracle", state_var_regex)
        self.assertIn("lastRefresh", state_var_regex)
        self.assertIn("invalidate", helper_regex)
        self.assertIn("checkpoint", helper_regex)
        self.assertIn("quote", name_regex)
        self.assertIn("borrow", name_regex)
        self.assertIn("cached", read_regex)
        self.assertIn("accounting", read_regex)
        self.assertTrue(any("MAX_STALE" in regex for regex in freshness_negation))
        self.assertTrue(any("refresh" in regex for regex in freshness_negation))

    def test_compile_round_trip_keeps_cache_coherence_matchers(self) -> None:
        tool = _load_pattern_compile()
        with tempfile.TemporaryDirectory(dir=REPO) as tmp:
            out_dir = Path(tmp) / "wave99"
            ok_seed = tool.compile_pattern(
                SEED_DSL,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            ok_reusable = tool.compile_pattern(
                REUSABLE_DSL,
                out_dir,
                strict_yaml_shapes=True,
                strict_unsupported_keys=True,
            )
            self.assertTrue(ok_seed)
            self.assertTrue(ok_reusable)
            seed_text = (out_dir / "vault_credit_capacity_stale.py").read_text(encoding="utf-8")
            reusable_text = (out_dir / "cached_accounting_read_without_refresh.py").read_text(encoding="utf-8")

        self.assertIn("cache|cached|oracle|price|index|rate|lastUpdate|lastUpdated|updatedAt|lastRefresh|checkpoint", seed_text)
        self.assertIn("refreshAccounting|refreshOracle|syncOracle|invalidateCache|settleAccounting|accrue", seed_text)
        self.assertIn("quote|preview|max|available|capacity|credit|borrow|price|health|redeem|withdraw|convert", reusable_text)
        self.assertIn("MAX_STALE|staleness", reusable_text)

    def test_fixture_pairs_pin_mutation_and_reader_shapes(self) -> None:
        vuln = SEED_VULN_FIXTURE.read_text(encoding="utf-8")
        clean = SEED_CLEAN_FIXTURE.read_text(encoding="utf-8")
        reusable_vuln = REUSABLE_VULN_FIXTURE.read_text(encoding="utf-8")
        reusable_clean = REUSABLE_CLEAN_FIXTURE.read_text(encoding="utf-8")

        self.assertIn("function withdraw(uint256 amount) external", vuln)
        self.assertIn("collateral[msg.sender] -= amount;", vuln)
        self.assertIn("utilization -= amount;", vuln)

        vuln_withdraw = vuln.split("function withdraw(uint256 amount) external", 1)[1].split("}", 1)[0]
        clean_withdraw = clean.split("function withdraw(uint256 amount) external", 1)[1].split("}", 1)[0]

        self.assertNotIn("updateCreditCapacity", vuln_withdraw)
        self.assertIn("updateCreditCapacity(0);", clean_withdraw)

        self.assertIn("function quoteBorrowable() external view returns (uint256)", reusable_vuln)
        self.assertIn("uint256 capacity = cachedCreditCapacity;", reusable_vuln)
        self.assertNotIn("refreshAccounting();", reusable_vuln)
        self.assertNotIn("MAX_STALE", reusable_vuln)

        self.assertIn("function quoteBorrowable() external returns (uint256)", reusable_clean)
        self.assertIn("refreshAccounting();", reusable_clean)
        self.assertIn("block.timestamp - lastAccountingRefresh <= MAX_STALE", reusable_clean)

    def test_registry_maps_capacity_stale_family_to_cache_coherence(self) -> None:
        registry_text = REGISTRY.read_text(encoding="utf-8")
        self.assertIn("cached-accounting-read-without-refresh:\n    attack_class: cache-coherence-violation", registry_text)
        self.assertIn("sol-vault-credit-capacity-no-router-update:\n    attack_class: cache-coherence-violation", registry_text)
        self.assertIn("vault-credit-capacity-stale:\n    attack_class: cache-coherence-violation", registry_text)

    def test_existing_seed_pattern_smoke_fires_on_vuln_and_stays_quiet_on_clean(self) -> None:
        self.assertGreaterEqual(self._hits(SEED_PATTERN, SEED_VULN_FIXTURE), 1)
        self.assertEqual(self._hits(SEED_PATTERN, SEED_CLEAN_FIXTURE), 0)


if __name__ == "__main__":
    unittest.main()
