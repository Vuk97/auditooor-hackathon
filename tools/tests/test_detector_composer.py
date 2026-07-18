"""Tests for tools/detector-composer.py (Kimi 20/10 Step 3b).

Covers:
  * A-RACE drop when contracts share zero state-var names
    (the I-20 name-collision drop signal Kimi K11 named).
  * A-RACE keep when contracts share at least one state-var name.
  * A-AUTH demote_info when contracts are not callgraph-reachable.
  * A-ORACLE demote_info when callsite is detached from any pricer.
  * Conservative keep when the callgraph is missing.
  * Conservative keep when a referenced contract is not in callgraph.
  * Hit-format flexibility: list, results-key, hits-key, findings-key.
  * End-to-end on the cross-fn-reentrancy fixture: 4 fake A-RACE hits
    against an unrelated contract -> 4 drops, 0 kept.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
COMPOSER = REPO / "tools" / "detector-composer.py"
CCIA = REPO / "tools" / "ccia.py"
RULES = REPO / "reference" / "detector_precedence_rules.json"
FIXTURES = REPO / "detectors" / "test_fixtures"

# Make the composer importable for direct unit tests (avoids subprocess
# overhead for the fast assertions). The hyphen in the file name forces
# importlib.util loading.
import importlib.util as _ilu
_spec = _ilu.spec_from_file_location("detector_composer", str(COMPOSER))
detector_composer = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
assert _spec and _spec.loader
_spec.loader.exec_module(detector_composer)  # type: ignore[attr-defined]


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")


def _emit_callgraph(workspace: Path) -> None:
    proc = subprocess.run(
        [sys.executable, str(CCIA), str(workspace), "--emit-callgraph"],
        cwd=REPO, capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:  # pragma: no cover — diag aid
        raise AssertionError(proc.stdout + proc.stderr)


def _run_composer(workspace: Path, hits: list, *, rules_path: Path = RULES) -> dict:
    hits_path = workspace / "_hits.json"
    hits_path.write_text(json.dumps(hits), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(COMPOSER),
         "--workspace", str(workspace),
         "--hits", str(hits_path),
         "--rules", str(rules_path),
         "--quiet"],
        cwd=REPO, capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return json.loads((workspace / "composed_hits.json").read_text())


# ─────────────────────────────────────────────────────────────────────
# Direct (in-process) compose() tests — fast
# ─────────────────────────────────────────────────────────────────────


class ComposerARaceDirectTest(unittest.TestCase):
    """Direct calls to compose() with synthetic callgraphs."""

    def _rules(self) -> dict:
        return json.loads(RULES.read_text())

    def test_drop_when_no_shared_storage(self) -> None:
        cg = {
            "schema_version": 1,
            "nodes": [], "edges": [],
            "contract_storage": {"Foo": ["alpha"], "Bar": ["beta"]},
        }
        hits = [{"detector": "x", "category": "A-RACE",
                 "contracts": ["Foo", "Bar"], "severity": "medium"}]
        out = detector_composer.compose(hits, cg, self._rules())
        self.assertEqual(out["dropped_count"], 1)
        self.assertEqual(out["kept_count"], 0)
        self.assertEqual(out["actions"][0]["action"], "drop")
        self.assertIn("zero state-var names", out["actions"][0]["reason"])

    def test_keep_when_shared_storage(self) -> None:
        cg = {
            "schema_version": 1,
            "nodes": [], "edges": [],
            "contract_storage": {"Foo": ["alpha", "shared"],
                                 "Bar": ["shared", "beta"]},
        }
        hits = [{"detector": "x", "category": "A-RACE",
                 "contracts": ["Foo", "Bar"], "severity": "medium"}]
        out = detector_composer.compose(hits, cg, self._rules())
        self.assertEqual(out["kept_count"], 1)
        self.assertEqual(out["dropped_count"], 0)
        self.assertIn("shared", out["actions"][0]["reason"])

    def test_keep_when_contract_unknown(self) -> None:
        """If a contract named in the hit is not in callgraph
        contract_storage, the constraint is unprovable -> keep."""
        cg = {
            "schema_version": 1,
            "nodes": [], "edges": [],
            "contract_storage": {"Foo": ["alpha"]},
        }
        hits = [{"detector": "x", "category": "A-RACE",
                 "contracts": ["Foo", "NotInGraph"], "severity": "medium"}]
        out = detector_composer.compose(hits, cg, self._rules())
        self.assertEqual(out["kept_count"], 1)
        self.assertEqual(out["actions"][0]["action"], "keep")
        self.assertIn("unprovable", out["actions"][0]["reason"])

    def test_keep_when_no_callgraph(self) -> None:
        hits = [{"detector": "x", "category": "A-RACE",
                 "contracts": ["Foo", "Bar"]}]
        out = detector_composer.compose(hits, None, self._rules())
        self.assertEqual(out["kept_count"], 1)
        self.assertEqual(out["actions"][0]["action"], "keep")
        self.assertIn("no callgraph", out["actions"][0]["reason"])

    def test_keep_when_no_rule_matches(self) -> None:
        cg = {
            "schema_version": 1, "nodes": [], "edges": [],
            "contract_storage": {"Foo": [], "Bar": []},
        }
        hits = [{"detector": "x", "category": "A-UNKNOWN",
                 "contracts": ["Foo", "Bar"]}]
        out = detector_composer.compose(hits, cg, self._rules())
        self.assertEqual(out["kept_count"], 1)
        self.assertEqual(out["actions"][0]["action"], "keep")
        self.assertIn("no precedence rule matched", out["actions"][0]["reason"])


class ComposerAAuthDirectTest(unittest.TestCase):
    def _rules(self) -> dict:
        return json.loads(RULES.read_text())

    def test_demote_info_when_unreachable(self) -> None:
        cg = {
            "schema_version": 1,
            "nodes": [
                {"id": "Foo.f()", "contract": "Foo", "function": "f"},
                {"id": "Bar.g()", "contract": "Bar", "function": "g"},
            ],
            "edges": [],   # unreachable
            "contract_storage": {"Foo": [], "Bar": []},
        }
        hits = [{"detector": "x", "category": "A-AUTH",
                 "contracts": ["Foo", "Bar"], "severity": "high"}]
        out = detector_composer.compose(hits, cg, self._rules())
        self.assertEqual(out["dropped_count"], 0)
        self.assertEqual(out["demoted_count"], 1)
        self.assertEqual(out["actions"][0]["action"], "demote_info")
        # Demoted hit retains origin severity in composer_demoted_from
        kept = out["kept"][0]
        self.assertEqual(kept["severity"], "info")
        self.assertEqual(kept["composer_demoted_from"], "high")

    def test_keep_when_reachable_within_2_hops(self) -> None:
        cg = {
            "schema_version": 1,
            "nodes": [
                {"id": "Foo.f()", "contract": "Foo", "function": "f"},
                {"id": "Bar.g()", "contract": "Bar", "function": "g"},
            ],
            "edges": [
                {"src": "Foo.f()", "dst": "Bar.g()",
                 "kind": "external_call", "shared_storage_keys": []},
            ],
            "contract_storage": {"Foo": [], "Bar": []},
        }
        hits = [{"detector": "x", "category": "A-AUTH",
                 "contracts": ["Foo", "Bar"]}]
        out = detector_composer.compose(hits, cg, self._rules())
        self.assertEqual(out["kept_count"], 1)
        self.assertEqual(out["demoted_count"], 0)
        self.assertEqual(out["actions"][0]["action"], "keep")


class ComposerAOracleDirectTest(unittest.TestCase):
    def _rules(self) -> dict:
        return json.loads(RULES.read_text())

    def test_demote_info_when_callsite_far_from_pricer(self) -> None:
        cg = {
            "schema_version": 1,
            "nodes": [
                {"id": "App.swap()", "contract": "App", "function": "swap"},
                {"id": "Logic.run()", "contract": "Logic", "function": "run"},
                {"id": "Oracle.read()", "contract": "Oracle", "function": "read"},
            ],
            # App -> Logic only; Oracle is detached. Within 2 hops of
            # App.swap() we can reach Logic.run() but not Oracle.read().
            "edges": [
                {"src": "App.swap()", "dst": "Logic.run()",
                 "kind": "external_call", "shared_storage_keys": []},
            ],
            "contract_storage": {"App": [], "Logic": [], "Oracle": []},
        }
        hits = [{"detector": "x", "category": "A-ORACLE",
                 "callsite": "App.swap()", "severity": "high"}]
        out = detector_composer.compose(hits, cg, self._rules())
        self.assertEqual(out["demoted_count"], 1)
        self.assertEqual(out["actions"][0]["action"], "demote_info")

    def test_keep_when_callsite_near_pricer(self) -> None:
        cg = {
            "schema_version": 1,
            "nodes": [
                {"id": "App.swap()", "contract": "App", "function": "swap"},
                {"id": "Oracle.read()", "contract": "Oracle", "function": "read"},
            ],
            "edges": [
                {"src": "App.swap()", "dst": "Oracle.read()",
                 "kind": "external_call", "shared_storage_keys": []},
            ],
            "contract_storage": {"App": [], "Oracle": []},
        }
        hits = [{"detector": "x", "category": "A-ORACLE",
                 "callsite": "App.swap()"}]
        out = detector_composer.compose(hits, cg, self._rules())
        self.assertEqual(out["kept_count"], 1)
        self.assertEqual(out["demoted_count"], 0)


# ─────────────────────────────────────────────────────────────────────
# Hit-input shape flexibility
# ─────────────────────────────────────────────────────────────────────


class ComposerHitFormatTest(unittest.TestCase):
    """The composer accepts a bare list or any of {results, hits,
    findings} keys — covers run_custom.py-style outputs and curated
    files."""

    def _write_hits(self, ws: Path, payload: object) -> Path:
        p = ws / "h.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        return p

    def test_bare_list(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            p = self._write_hits(ws, [{"detector": "x", "category": "X"}])
            self.assertEqual(detector_composer.load_hits(p),
                             [{"detector": "x", "category": "X"}])

    def test_results_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            p = self._write_hits(ws, {"results": [{"detector": "x"}]})
            self.assertEqual(detector_composer.load_hits(p),
                             [{"detector": "x"}])

    def test_findings_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            p = self._write_hits(ws, {"findings": [{"detector": "x"}]})
            self.assertEqual(detector_composer.load_hits(p),
                             [{"detector": "x"}])


# ─────────────────────────────────────────────────────────────────────
# End-to-end on cross-fn-reentrancy fixture (the test the brief asks for)
# ─────────────────────────────────────────────────────────────────────


class ComposerCrossFnReentrancyEndToEndTest(unittest.TestCase):
    """The brief asks: 'count of hits dropped on cross-fn-reentrancy
    fixture'. We materialize a workspace with the fixture + an unrelated
    contract, emit the callgraph, run the composer with 4 synthetic
    A-RACE name-collision hits, and assert all 4 drop."""

    def test_four_arace_namecollision_hits_collapse_to_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            shutil.copy(
                FIXTURES / "cross_function_reentrancy_vulnerable.sol",
                ws / "src" / "Bank.sol",
            )
            _write(
                ws / "src" / "Other.sol",
                """
                pragma solidity ^0.8.20;
                contract OtherContract {
                    address public admin;
                    uint256 public counter;
                }
                """,
            )
            _emit_callgraph(ws)
            hits = [
                {"detector": "race-on-balances", "category": "A-RACE",
                 "title": "race vs balances",
                 "contracts": ["Bank", "OtherContract"], "severity": "medium"},
                {"detector": "race-on-admin", "category": "A-RACE",
                 "title": "race vs admin",
                 "contracts": ["Bank", "OtherContract"], "severity": "medium"},
                {"detector": "race-on-counter", "category": "A-RACE",
                 "title": "race vs counter",
                 "contracts": ["Bank", "OtherContract"], "severity": "low"},
                {"detector": "race-cross", "category": "A-RACE",
                 "title": "cross race",
                 "contracts": ["Bank", "OtherContract"], "severity": "high"},
            ]
            out = _run_composer(ws, hits)
            self.assertEqual(out["input_count"], 4)
            self.assertEqual(out["dropped_count"], 4,
                             f"expected 4 drops; got {out['dropped_count']} "
                             f"(actions={[a['action'] for a in out['actions']]})")
            self.assertEqual(out["kept_count"], 0)
            for action in out["actions"]:
                self.assertEqual(action["action"], "drop")
                self.assertEqual(action["rule_id"],
                                 "A-RACE.shared-storage-required")

    def test_arace_kept_when_storage_overlaps(self) -> None:
        """Inverse: if Other declares `balances` (matching Bank), the
        composer must KEEP all 4 hits — proving the drop signal is
        correctly contingent on the overlap."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            shutil.copy(
                FIXTURES / "cross_function_reentrancy_vulnerable.sol",
                ws / "src" / "Bank.sol",
            )
            _write(
                ws / "src" / "Other.sol",
                """
                pragma solidity ^0.8.20;
                contract OtherContract {
                    mapping(address => uint256) public balances;  // SHARED with Bank
                }
                """,
            )
            _emit_callgraph(ws)
            hits = [
                {"detector": "race-1", "category": "A-RACE",
                 "contracts": ["Bank", "OtherContract"], "severity": "medium"},
                {"detector": "race-2", "category": "A-RACE",
                 "contracts": ["Bank", "OtherContract"], "severity": "medium"},
            ]
            out = _run_composer(ws, hits)
            self.assertEqual(out["dropped_count"], 0)
            self.assertEqual(out["kept_count"], 2)


class ComposerPrecedenceRulesFileTest(unittest.TestCase):
    """The reference rules file must be valid JSON, declare its schema,
    and contain the three rule_ids the composer dispatches on. This
    test pins the contract between PR-B's rules file and the composer
    handlers above so a future edit can't accidentally rename a rule_id
    without updating the composer."""

    def test_rules_file_loads(self) -> None:
        data = json.loads(RULES.read_text())
        self.assertEqual(data["schema"], "auditooor.detector-precedence-rules.v1")
        rule_ids = {r["rule_id"] for r in data["rules"]}
        self.assertEqual(rule_ids, {
            "A-RACE.shared-storage-required",
            "A-AUTH.callgraph-reachability-required",
            "A-ORACLE.pricer-proximity-required",
        })


if __name__ == "__main__":
    unittest.main()
