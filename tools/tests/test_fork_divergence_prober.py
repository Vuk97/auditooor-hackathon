"""Tests for tools/fork-divergence-prober.py — HACKERMAN_V3 Lane G2.

All fixtures are synthesized in tempdirs; no network is touched and no
fixed repo files are needed. The four required scenarios:

  1. lagging pin + reachable in-scope path  -> actionable lead with a replay cmd
  2. lagging pin with NO reachable in-scope path -> classification not-a-finding
  3. current pin (no advisory, no ancestry-lag) -> no actionable lead
  4. offline run with no cache and no fetcher -> never errors, fork_missing=unknown
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "fork-divergence-prober.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("fork_divergence_prober", TOOL_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FDP = _load_tool()


def _mk_ws(tmp: Path, gomod: str, *, src: dict[str, str] | None = None,
           scope: dict | None = None) -> Path:
    ws = tmp / "ws"
    (ws / "x").mkdir(parents=True, exist_ok=True)
    (ws / "go.mod").write_text(gomod)
    for rel, body in (src or {}).items():
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    if scope is not None:
        (ws / "scope.json").write_text(json.dumps(scope))
    return ws


# A go.mod with a forked cometbft pin (dydx cometbft fork-lag anchor shape).
LAGGING_GOMOD = """\
module example.com/app

go 1.22

require (
\tgithub.com/cometbft/cometbft v0.38.0
)

replace github.com/cometbft/cometbft => github.com/dydxprotocol/cometbft v0.38.0-0.20240101000000-904204b11c9e
"""

CURRENT_GOMOD = """\
module example.com/clean

go 1.22

require (
\tgithub.com/cometbft/cometbft v0.38.22
)

replace github.com/cometbft/cometbft => github.com/cleanorg/cometbft v0.38.22-0.20250101000000-aaaaaaaaaaaa
"""

ADVISORY_CACHE = {
    "github.com/dydxprotocol/cometbft": [
        {
            "advisory_id": "GHSA-test-blocksync",
            "fixed_in": "v0.38.22",
            "fixed_sha": "deadbeefcafe",
            "vulnerable_paths": ["blocksync/reactor.go"],
            "summary": "blocksync verification hardening series",
        }
    ]
}


class TestLaggingReachable(unittest.TestCase):
    def test_lagging_pin_reachable_yields_actionable_lead(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # in-scope source actually imports the cometbft module + symbol.
            ws = _mk_ws(tmp, LAGGING_GOMOD, src={
                "node/sync.go": (
                    'package node\n'
                    'import "github.com/cometbft/cometbft/blocksync/reactor.go"\n'
                    'func Run() { reactor.go() }\n'
                ),
            })
            plan = FDP.probe(ws, ADVISORY_CACHE, None)
            self.assertEqual(plan["summary"]["actionable_leads"], 1)
            lead = next(l for l in plan["leads"] if l["actionable"])
            self.assertEqual(lead["fork_missing_status"], "lagging")
            self.assertEqual(lead["reachable_in_scope_code_path"], "reachable")
            self.assertEqual(lead["classification"], "actionable-lead")
            # stage 4: a concrete replay command, not prose.
            self.assertIn("git clone", lead["local_replay_or_harness_task"])
            self.assertIn("merge-base", lead["local_replay_or_harness_task"])
            # stage 1 cites the advisory.
            self.assertIn("GHSA-test-blocksync", lead["upstream_fix_or_advisory"])
            self.assertTrue(lead["reachability_evidence"])


class TestLaggingUnreachable(unittest.TestCase):
    def test_lagging_pin_no_inscope_path_is_not_a_finding(self):
        """Hyperbridge ibc-go anchor: version-vulnerable but unreachable."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # in-scope source never references cometbft at all.
            ws = _mk_ws(tmp, LAGGING_GOMOD, src={
                "node/unrelated.go": (
                    'package node\n'
                    'func DoSomethingElse() int { return 42 }\n'
                ),
            })
            plan = FDP.probe(ws, ADVISORY_CACHE, None)
            self.assertEqual(plan["summary"]["actionable_leads"], 0)
            self.assertEqual(plan["summary"]["not_a_finding"], 1)
            lead = plan["leads"][0]
            self.assertEqual(lead["fork_missing_status"], "lagging")
            self.assertEqual(lead["reachable_in_scope_code_path"], "not-reachable")
            self.assertEqual(lead["classification"], "not-a-finding")
            self.assertFalse(lead["actionable"])
            self.assertIn("NOT-A-FINDING", lead["rubric_impact_gate"])
            self.assertIn("Hyperbridge", lead["rubric_impact_gate"])

    def test_scope_json_filters_reachability(self):
        """A reference exists, but outside scope.json -> still not-a-finding."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _mk_ws(tmp, LAGGING_GOMOD, src={
                "outofscope/sync.go": (
                    'package x\nimport "github.com/cometbft/cometbft/blocksync/reactor.go"\n'
                ),
                "inscope/clean.go": 'package y\nfunc Ok() {}\n',
            }, scope={"in_scope": ["inscope/clean.go"]})
            plan = FDP.probe(ws, ADVISORY_CACHE, None,
                             in_scope_files=FDP.load_scope_files(ws, None))
            lead = plan["leads"][0]
            self.assertEqual(lead["reachable_in_scope_code_path"], "not-reachable")
            self.assertEqual(lead["classification"], "not-a-finding")


class TestCurrentPin(unittest.TestCase):
    def test_current_pin_no_advisory_no_lead(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _mk_ws(tmp, CURRENT_GOMOD, src={
                "node/sync.go": 'package node\nimport "github.com/cometbft/cometbft"\n',
            })
            # advisory cache has no entry for this fork repo.
            plan = FDP.probe(ws, ADVISORY_CACHE, None)
            self.assertEqual(plan["summary"]["actionable_leads"], 0)
            lead = plan["leads"][0]
            self.assertEqual(lead["fork_missing_status"], "current")
            self.assertEqual(lead["classification"], "current-pin")
            self.assertFalse(lead["actionable"])


class TestOfflineSafety(unittest.TestCase):
    def test_offline_no_cache_no_fetcher_never_errors(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _mk_ws(tmp, LAGGING_GOMOD, src={
                "node/sync.go": 'package node\n',
            })
            # no advisory cache, no fetcher.
            plan = FDP.probe(ws, {}, None)
            self.assertEqual(plan["advisory_mode"], "offline-no-cache")
            lead = plan["leads"][0]
            self.assertEqual(lead["fork_missing_status"], "unknown")
            self.assertEqual(lead["classification"], "blocked-needs-input")
            self.assertFalse(lead["actionable"])
            self.assertIn("plan_id", plan)

    def test_ancestry_report_seeds_lagging_status(self):
        """Consume a fork-ancestry-check JSON report instead of re-deriving."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _mk_ws(tmp, LAGGING_GOMOD, src={
                "node/sync.go": (
                    'package node\nimport "github.com/cometbft/cometbft"\n'
                ),
            })
            ancestry = {"forks": [{
                "fork_repo": "github.com/dydxprotocol/cometbft",
                "module": "github.com/cometbft/cometbft",
                "not_in_fork": ["v0.38.22", "v0.38.21"],
            }]}
            plan = FDP.probe(ws, {}, ancestry)
            lead = plan["leads"][0]
            # ancestry seeded lagging even with no advisory cache.
            self.assertEqual(lead["fork_missing_status"], "lagging")
            self.assertIn("fork-ancestry", lead["upstream_fix_or_advisory"])

    def test_pluggable_fetcher_is_used(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _mk_ws(tmp, LAGGING_GOMOD, src={
                "node/sync.go": (
                    'package node\nimport "github.com/cometbft/cometbft"\n'
                ),
            })

            def fake_fetcher(pin):
                return [{"advisory_id": "GHSA-plug", "fixed_in": "v9",
                         "fixed_sha": "abc", "vulnerable_paths": ["cometbft"],
                         "summary": "via fetcher"}]

            plan = FDP.probe(ws, {}, None, advisory_fetcher=fake_fetcher)
            self.assertEqual(plan["advisory_mode"], "live-fetcher")
            self.assertEqual(plan["leads"][0]["fork_missing_status"], "lagging")


class TestPinDiscovery(unittest.TestCase):
    def test_discovers_cargo_and_npm_pins(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "ws"
            ws.mkdir()
            (ws / "Cargo.toml").write_text(
                '[dependencies]\n'
                'frost = { git = "https://github.com/lightsparkdev/frost" }\n'
            )
            (ws / "package.json").write_text(json.dumps({
                "dependencies": {"pkg": "github.com/org/repo#abcdef1"}
            }))
            pins = FDP.discover_pins(ws)
            ecos = {p["ecosystem"] for p in pins}
            self.assertIn("cargo", ecos)
            self.assertIn("npm", ecos)


if __name__ == "__main__":
    unittest.main()
