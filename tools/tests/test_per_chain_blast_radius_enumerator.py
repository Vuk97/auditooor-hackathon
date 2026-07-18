"""Unit tests for per-chain blast-radius enumerator.

<!-- r36-rebuttal: build lane -->
"""

from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "per_chain_blast_radius_enumerator",
    ROOT / "tools" / "per-chain-blast-radius-enumerator.py",
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _make_ws() -> Path:
    return Path(tempfile.mkdtemp(prefix="blast_radius_"))


def _write(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


class ExtractPalletTests(unittest.TestCase):
    def test_extracts_substrate_pallet_backtick(self) -> None:
        text = "The affected component is `pallet_ismp` per audit pin."
        result = mod.extract_pallet_or_module(text)
        self.assertIsNotNone(result)
        ident, kind, _ = result
        self.assertEqual(ident, "pallet_ismp")
        self.assertEqual(kind, "substrate-pallet")

    def test_extracts_rust_module_path(self) -> None:
        text = "Component: `modules/ismp/clients/ismp-optimism` (Optimism consensus client)"
        result = mod.extract_pallet_or_module(text)
        self.assertIsNotNone(result)
        ident, kind, _ = result
        self.assertTrue(ident.startswith("modules/ismp"))
        self.assertEqual(kind, "rust-module")

    def test_extracts_go_module(self) -> None:
        text = "Affects `x/feegrant` revoke handler."
        result = mod.extract_pallet_or_module(text)
        self.assertIsNotNone(result)
        ident, kind, _ = result
        self.assertEqual(ident, "x/feegrant")
        self.assertEqual(kind, "go-module")

    def test_returns_none_when_no_identifier(self) -> None:
        text = "Plain narrative without any pallet or module mention."
        self.assertIsNone(mod.extract_pallet_or_module(text))


class GrepRegistrationsTests(unittest.TestCase):
    def test_finds_add_state_machine_call_sites(self) -> None:
        ws = _make_ws()
        _write(ws / "runtime" / "src" / "lib.rs", """
fn setup() {
    add_state_machine(Optimism);
    add_state_machine(Arbitrum);
    add_state_machine(Base);
}
""".lstrip())
        anchors, chains, _ = mod.grep_registrations(ws, None)
        self.assertEqual(len(anchors), 3)
        self.assertTrue(all(a["kind"] == "register_fn" for a in anchors))
        chain_names = {c["name"] for c in chains}
        self.assertIn("Optimism", chain_names)
        self.assertIn("Arbitrum", chain_names)
        self.assertIn("Base", chain_names)

    def test_finds_solidity_addClient(self) -> None:
        ws = _make_ws()
        _write(ws / "contracts" / "Registry.sol", """
contract Registry {
    function init() public {
        addClient(OPTIMISM);
        registerChain(POLYGON);
        setChain(ARBITRUM);
    }
}
""".lstrip())
        anchors, chains, _ = mod.grep_registrations(ws, None)
        self.assertEqual(len(anchors), 3)
        kinds = {a["kind"] for a in anchors}
        self.assertEqual(kinds, {"add_fn", "register_fn", "set_fn"})
        self.assertEqual({c["name"] for c in chains}, {"Optimism", "Polygon", "Arbitrum"})

    def test_skips_noise_directories(self) -> None:
        ws = _make_ws()
        # Noise dirs that must be skipped.
        _write(ws / "target" / "debug" / "build.rs", "add_state_machine(Skipped);")
        _write(ws / "node_modules" / "x" / "y.rs", "add_state_machine(AlsoSkipped);")
        _write(ws / ".auditooor" / "x.rs", "add_state_machine(StillSkipped);")
        _write(ws / "submissions" / "filed" / "x.rs", "add_state_machine(SkippedToo);")
        # Real source.
        _write(ws / "src" / "lib.rs", "add_state_machine(RealChain);")
        anchors, _, _ = mod.grep_registrations(ws, None)
        # Only the src/lib.rs hit counts.
        self.assertEqual(len(anchors), 1)
        self.assertIn("src/lib.rs", anchors[0]["file"])

    def test_missing_source_root_emits_warning(self) -> None:
        anchors, chains, warnings = mod.grep_registrations(Path("/no/such/path/exists/xyz"), None)
        self.assertEqual(anchors, [])
        self.assertEqual(chains, [])
        self.assertTrue(any("source_root_missing" in w for w in warnings))

    def test_chain_confidence_scoring(self) -> None:
        ws = _make_ws()
        _write(ws / "src" / "a.rs", """
add_state_machine(Optimism);
add_state_machine(Optimism);
add_state_machine(Arbitrum);
""".lstrip())
        _, chains, _ = mod.grep_registrations(ws, None)
        by_name = {c["name"]: c for c in chains}
        # Optimism cited twice on distinct file:line tuples -> high confidence.
        self.assertEqual(by_name["Optimism"]["confidence"], "high")
        # Arbitrum cited once -> low confidence.
        self.assertEqual(by_name["Arbitrum"]["confidence"], "low")


class RunEndToEndTests(unittest.TestCase):
    def test_full_run_writes_json(self) -> None:
        ws = _make_ws()
        finding = ws / "submissions" / "filed" / "demo-HIGH" / "demo-HIGH.md"
        _write(finding, """
# Demo finding

- Component: `modules/ismp/clients/ismp-optimism`
- Pallet: `pallet_ismp`

## Body

add_state_machine called with Optimism / Arbitrum chains.
""".lstrip())
        # Source files live OUTSIDE the submissions/ subtree (which is skipped).
        _write(ws / "runtime" / "src" / "lib.rs", """
add_state_machine(Optimism);
add_state_machine(Arbitrum);
add_state_machine(Base);
""".lstrip())
        rc, payload = mod.run(finding, ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["finding_slug"], "demo-HIGH")
        # Pallet pattern wins over module path per PALLET_PATTERNS priority.
        self.assertEqual(payload["pallet_or_module"]["identifier"], "pallet_ismp")
        self.assertEqual(payload["pallet_or_module"]["kind"], "substrate-pallet")
        # 3 chains found; blast_radius_count = 3 - 1 = 2 (the finding already names one).
        self.assertEqual(len(payload["registered_chains"]), 3)
        self.assertEqual(payload["blast_radius_count"], 2)
        self.assertEqual(payload["schema_version"], "auditooor.per_chain_blast_radius.v1")

    def test_finding_missing_returns_error(self) -> None:
        ws = _make_ws()
        rc, payload = mod.run(ws / "no-such-finding.md", ws)
        self.assertEqual(rc, 2)
        self.assertIn("error", payload)

    def test_finding_with_no_pallet_still_runs(self) -> None:
        ws = _make_ws()
        finding = ws / "submissions" / "filed" / "noP-HIGH" / "noP-HIGH.md"
        _write(finding, "# bland finding\nno identifiers here\n")
        rc, payload = mod.run(finding, ws)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["pallet_or_module"]["identifier"], "")
        self.assertEqual(payload["pallet_or_module"]["kind"], "unknown")
        self.assertEqual(payload["blast_radius_count"], 0)


class HyperbridgeRetroactiveTests(unittest.TestCase):
    """Retroactive: run the enumerator against the real filed Hyperbridge
    L2Oracle finding and confirm the tool extracts the affected component."""

    REAL_FINDING = Path(
        "/Users/wolf/audits/hyperbridge/submissions/filed/"
        "hb-optimism-l2oracle-unfinalized-output-HIGH/"
        "hb-optimism-l2oracle-unfinalized-output-HIGH.md"
    )

    def test_real_hyperbridge_finding_pallet_extraction(self) -> None:
        if not self.REAL_FINDING.exists():
            self.skipTest("Hyperbridge finding not present in this environment")
        ws = Path(tempfile.mkdtemp(prefix="hb_retro_"))
        rc, payload = mod.run(self.REAL_FINDING, ws, source_root=ws)
        self.assertEqual(rc, 0)
        # The first extracted identifier should be the Substrate pallet or
        # the Hyperbridge module path; both are acceptable affected components.
        ident = payload["pallet_or_module"]["identifier"]
        self.assertTrue(
            ident.startswith("pallet_") or "ismp" in ident or "modules/" in ident,
            f"unexpected affected-component identifier: {ident!r}",
        )
        # Tool ran without exception; output structure is correct.
        self.assertEqual(payload["schema_version"], "auditooor.per_chain_blast_radius.v1")
        self.assertIn("registration_anchors", payload)
        self.assertIn("registered_chains", payload)


if __name__ == "__main__":
    unittest.main()
