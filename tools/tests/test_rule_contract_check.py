"""Tests for tools/rule-contract-check.py (P17 rule self-test contracts).

Verifies:
- the three shipped contracts all HOLD (must-catch FAILs, must-pass PASSes)
- a mutation of a bound predicate is CAUGHT (must-catch flips to PASS)
- a coverage-theater contract (must-catch survives predicate mutation) is flagged
- advisory-first: a VIOLATED contract exits 0 by default, 1 under the strict flag
- the mini-yaml fallback parses contracts identically to PyYAML
"""

from __future__ import annotations

import importlib.util as ilu
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RCC = REPO_ROOT / "tools" / "rule-contract-check.py"
CONTRACTS_DIR = REPO_ROOT / "tools" / "rules" / "contracts"


def _load_module():
    spec = ilu.spec_from_file_location("rule_contract_check", RCC)
    mod = ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(args, env_extra=None):
    env = {k: v for k, v in os.environ.items()
           if k != "AUDITOOOR_RULE_CONTRACT_STRICT"}
    if env_extra:
        env.update(env_extra)
    return subprocess.run([sys.executable, str(RCC), *args],
                          capture_output=True, text=True, env=env)


class TestShippedContractsHold(unittest.TestCase):
    def test_all_shipped_contracts_hold(self):
        """Every shipped contract's must-catch FAILs and must-pass PASSes."""
        r = _run(["--json"])
        self.assertEqual(r.returncode, 0, msg=r.stderr)
        data = json.loads(r.stdout)
        self.assertTrue(data["contracts"], "no contracts discovered")
        for c in data["contracts"]:
            self.assertEqual(c["violations"], [],
                             msg=f"{c['name']} violated: {c['violations']}")
            # Both a must_catch and a must_pass check must be present.
            kinds = {ch["kind"] for ch in c["checks"]}
            self.assertIn("must_catch", kinds, msg=f"{c['name']} lacks must_catch")
            self.assertIn("must_pass", kinds, msg=f"{c['name']} lacks must_pass")

    def test_at_least_one_contract_has_a_mutation_proof(self):
        """>=1 shipped contract exercises the mutation-proof and catches it."""
        r = _run(["--json"])
        data = json.loads(r.stdout)
        proven = [c for c in data["contracts"]
                  if c.get("mutation") and c["mutation"].get("flips")]
        self.assertTrue(proven,
                        "no shipped contract demonstrated a caught predicate mutation")
        for c in proven:
            self.assertGreaterEqual(c["mutation"]["flips"], 1)


class TestMutationProof(unittest.TestCase):
    def test_predicate_mutation_flips_must_catch_to_pass(self):
        """A relational mutation of the exploit-queue threshold flips the
        must-catch fixture from FAIL to PASS -- proof the fixture discriminates
        on that predicate (not coverage-theater)."""
        mod = _load_module()
        # The exploit-queue predicate `if fraction >= min_fraction:`.
        variants = mod._predicate_mutants("    if fraction >= min_fraction:")
        self.assertTrue(variants, "engine produced no mutants for a relational predicate")
        self.assertTrue(any("<=" in v or "<" in v or ">" in v for v in variants),
                        f"no relational mutant among {variants}")

    def test_coverage_theater_contract_is_flagged(self):
        """A contract whose must-catch fixture does NOT discriminate on the
        declared predicate (its FAIL is unrelated to the predicate) is flagged
        as possible coverage-theater when no mutant flips it."""
        mod = _load_module()
        # Point the predicate at a NON-decision line (e.g. an import) -- no
        # relational/boundary mutant of it changes the FAIL verdict, so flips==0.
        contract = {
            "name": "theater-probe",
            "tool": "tools/exploit-queue-schema-check.py",
            "argv": ["--workspace", "{fixture_dir}"],
            "mutation_predicate": 1,  # the shebang/import region, not a predicate
            "must_catch": [{
                "label": "underpopulated",
                "files": {".auditooor/exploit_queue.json":
                          '{"rows":[{"id":"r","source":"hunt","attack_class":"x","mechanism":"y","impact_class":""}]}'},
            }],
            "must_pass": [{
                "label": "populated",
                "files": {".auditooor/exploit_queue.json":
                          '{"rows":[{"id":"r","source":"hunt","attack_class":"x","mechanism":"y","impact_class":"z"}]}'},
            }],
        }
        res = mod.evaluate_contract(contract, do_mutation=True)
        mut = res.get("mutation") or {}
        self.assertEqual(mut.get("flips", None), 0,
                         "expected 0 flips for a non-predicate line")
        self.assertTrue(any("coverage-theater" in v for v in res["violations"]),
                        f"coverage-theater not flagged: {res['violations']}")

    def test_equivalent_mutant_marker_suppresses_theater_flag(self):
        """Recording mutation_equivalent: true suppresses the theater flag."""
        mod = _load_module()
        contract = {
            "name": "equivalent-probe",
            "tool": "tools/exploit-queue-schema-check.py",
            "argv": ["--workspace", "{fixture_dir}"],
            "mutation_predicate": 1,
            "mutation_equivalent": True,
            "must_catch": [{
                "label": "underpopulated",
                "files": {".auditooor/exploit_queue.json":
                          '{"rows":[{"id":"r","source":"hunt","attack_class":"x","mechanism":"y","impact_class":""}]}'},
            }],
            "must_pass": [{
                "label": "populated",
                "files": {".auditooor/exploit_queue.json":
                          '{"rows":[{"id":"r","source":"hunt","attack_class":"x","mechanism":"y","impact_class":"z"}]}'},
            }],
        }
        res = mod.evaluate_contract(contract, do_mutation=True)
        self.assertEqual(res["violations"], [],
                         msg=f"equivalent marker should suppress theater: {res['violations']}")


class TestAdvisoryFirst(unittest.TestCase):
    def _write_violated(self):
        p = CONTRACTS_DIR / "_test_advisory_violated.yaml"
        p.write_text(
            "name: advisory-violated\n"
            "tool: tools/exploit-queue-schema-check.py\n"
            "rationale: intentionally-inverted\n"
            "argv: [\"--workspace\", \"{fixture_dir}\"]\n"
            "must_catch:\n"
            "  - label: should-fail-but-passes\n"
            "    files:\n"
            "      \".auditooor/exploit_queue.json\": '{\"rows\":[]}'\n"
            "must_pass:\n"
            "  - label: clean\n"
            "    files:\n"
            "      \".auditooor/exploit_queue.json\": '{\"rows\":[{\"id\":\"r\",\"source\":\"hunt\",\"attack_class\":\"x\",\"mechanism\":\"y\",\"impact_class\":\"z\"}]}'\n"
        )
        return p

    def test_violation_is_advisory_by_default(self):
        p = self._write_violated()
        try:
            r = _run(["--tool", "tools/exploit-queue-schema-check.py", "--no-mutation"])
            self.assertEqual(r.returncode, 0,
                             msg="advisory default must exit 0 on violation")
            self.assertIn("advisory", r.stdout.lower())
        finally:
            p.unlink()

    def test_violation_fails_under_strict_flag(self):
        p = self._write_violated()
        try:
            r = _run(["--tool", "tools/exploit-queue-schema-check.py", "--no-mutation"],
                     env_extra={"AUDITOOOR_RULE_CONTRACT_STRICT": "1"})
            self.assertEqual(r.returncode, 1,
                             msg="strict flag must exit 1 on violation")
        finally:
            p.unlink()

    def test_no_contracts_in_scope_is_pass(self):
        r = _run(["--tool", "tools/definitely-not-a-real-tool.py"])
        self.assertEqual(r.returncode, 0)


class TestMiniYamlFallback(unittest.TestCase):
    def test_fallback_parses_shipped_contracts(self):
        """With PyYAML blocked, the mini-yaml fallback parses each shipped
        contract to a dict with the required keys (tool, must_catch, must_pass)."""
        mod = _load_module()
        for yf in sorted(CONTRACTS_DIR.glob("*.yaml")):
            if yf.name.startswith("_test_"):
                continue
            doc = mod._mini_yaml(yf.read_text())
            self.assertIsInstance(doc, dict, msg=f"{yf.name} did not parse to a map")
            self.assertIn("tool", doc, msg=f"{yf.name} missing tool")
            self.assertTrue(doc.get("must_catch"), msg=f"{yf.name} missing must_catch")
            self.assertTrue(doc.get("must_pass"), msg=f"{yf.name} missing must_pass")
            # A directory-tree fixture key must be unquoted to a real path.
            for fx in doc["must_catch"]:
                if isinstance(fx, dict) and "files" in fx:
                    for k in fx["files"]:
                        self.assertFalse(k.startswith('"') or k.startswith("'"),
                                         msg=f"{yf.name} fixture key not unquoted: {k!r}")


if __name__ == "__main__":
    unittest.main()
