"""tests/test_pre_source_read_inject.py — smoke + subprocess tests for pre-source-read-inject.py

Coverage (8 PASS required):
  (a) .sol file  → Solidity rows returned in output
  (b) .go file   → Go rows returned in output
  (c) no match   → empty output, exit 0
  (d) missing index → exit 1
  (e) L29-Disc-5 mandate text present in non-empty output
  (f) JSON mode  → valid JSON with matched_rows key
  (g) .rs file   → Rust rows returned in output
  (h) --quiet flag → no stdout, exit 0
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import textwrap
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "pre-source-read-inject.py"

# ---------------------------------------------------------------------------
# Minimal fake index for hermetic tests
# ---------------------------------------------------------------------------

_FAKE_INDEX = textwrap.dedent("""\
    # Case studies & known patterns index

    Per L29-Disc-5, every worker brief MUST include recall BEFORE any source read.

    ## 1. Engagement-derived case studies (`case_study/`)

    | File | Engagement | Key lesson |
    |---|---|---|
    | `case_study/litecoin_mweb_dos_plus_protocol_bug.md` | Litecoin MWEB | DLT/consensus cross-version state-divergence Go chain. |
    | `case_study/centrifuge_v3_engagement.md` | Centrifuge V3 | Vault share-accounting erc4626 Solidity. |
    | `case_study/polymarket_cantina.md` | Polymarket Cantina | CLOB prediction-market Solidity erc20. |

    ## 2. Known bug families (`reference/`)

    | File | Use when | Notes |
    |---|---|---|
    | `reference/anti_patterns.md` | every audit | Known anti-patterns to grep against |
    | `reference/bug_family_atlas.md` | every audit | Atlas of bug families sol erc amm |

    ## 3. Invariant templates (`reference/invariant_class_templates/`)

    | File | Class |
    |---|---|
    | `reference/invariant_class_templates/amm.sol.template` | AMM swap Solidity |
    | `reference/invariant_class_templates/erc4626.sol.template` | ERC4626 vault Solidity |

    ## 4. Go / DLT patterns

    | File | Use when | Notes |
    |---|---|---|
    | `reference/cosmos_bank_patterns.go` | cosmos chain audits | Go cosmos SDK patterns cometbft |
    | `case_study/dydx_cometbft_fork_lag.md` | dydx go chain | cometbft fork-lag blocksync gap Go |

    ## 5. Rust patterns

    | File | Use when | Notes |
    |---|---|---|
    | `reference/rust_substrate_patterns.rs` | substrate polkadot | Rust-based chain patterns |
    | `case_study/near_rust_engagement.md` | NEAR protocol | Rust NEAR smart contract patterns |
""")


def _make_workspace(index_content: str) -> pathlib.Path:
    """Create a temp workspace dir with the fake index, return its path."""
    tmp = pathlib.Path(tempfile.mkdtemp())
    (tmp / "docs").mkdir()
    (tmp / "docs" / "CASE_STUDIES_AND_PATTERNS_INDEX.md").write_text(index_content)
    return tmp


def _run(source_path: str, workspace: pathlib.Path, *extra_args: str) -> tuple[int, str, str]:
    cmd = [
        sys.executable, str(TOOL),
        "--source-path", source_path,
        "--workspace", str(workspace),
        *extra_args,
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


class TestPreSourceReadInjectSubprocess(unittest.TestCase):

    def setUp(self):
        self.ws = _make_workspace(_FAKE_INDEX)

    # (a) .sol file → Solidity rows returned
    def test_a_sol_file_returns_solidity_rows(self):
        rc, stdout, stderr = _run("contracts/Vault.sol", self.ws)
        self.assertEqual(rc, 0, f"Expected exit 0; stderr={stderr}")
        self.assertGreater(len(stdout.strip()), 0, "Expected non-empty output for .sol file")
        # Should contain at least one Solidity-related row keyword
        lower = stdout.lower()
        self.assertTrue(
            any(kw in lower for kw in ["sol", "vault", "amm", "erc", "exchange"]),
            f"Expected Solidity-related content; got:\n{stdout[:400]}"
        )

    # (b) .go file → Go rows returned
    def test_b_go_file_returns_go_rows(self):
        rc, stdout, stderr = _run("detectors/cosmos/keeper.go", self.ws)
        self.assertEqual(rc, 0, f"Expected exit 0; stderr={stderr}")
        self.assertGreater(len(stdout.strip()), 0, "Expected non-empty output for .go file")
        lower = stdout.lower()
        self.assertTrue(
            any(kw in lower for kw in ["go", "cosmos", "cometbft", "dlt", "chain"]),
            f"Expected Go-related content; got:\n{stdout[:400]}"
        )

    # (c) no match → empty output, exit 0
    def test_c_no_match_empty_output_exit_0(self):
        rc, stdout, stderr = _run("totally/unknown_xyzzy_abc_zzz.xyz", self.ws)
        self.assertEqual(rc, 0, f"Expected exit 0 on no match; stderr={stderr}")
        self.assertEqual(stdout.strip(), "", f"Expected empty stdout on no match; got={stdout!r}")

    # (d) missing index → exit 1
    def test_d_missing_index_exit_1(self):
        with tempfile.TemporaryDirectory() as empty_dir:
            rc, stdout, stderr = _run("foo.sol", pathlib.Path(empty_dir))
        self.assertEqual(rc, 1, f"Expected exit 1 when index missing; rc={rc}")

    # (e) L29-Disc-5 mandate text present in non-empty output
    def test_e_l29_disc5_mandate_present_in_output(self):
        rc, stdout, _stderr = _run("contracts/Vault.sol", self.ws)
        self.assertEqual(rc, 0)
        self.assertIn("L29-Disc-5", stdout,
                      "L29-Disc-5 mandate must appear verbatim in non-empty output")
        # Verify the full mandate phrase
        self.assertIn("BEFORE any source read", stdout,
                      "Mandate phrase 'BEFORE any source read' must be present")

    # (f) JSON mode → valid JSON with matched_rows
    def test_f_json_mode_valid_json(self):
        rc, stdout, stderr = _run("contracts/Vault.sol", self.ws, "--json")
        self.assertEqual(rc, 0, f"Expected exit 0; stderr={stderr}")
        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as e:
            self.fail(f"JSON output is not valid: {e}\nstdout={stdout[:400]}")
        self.assertIn("matched_rows", data, "JSON output must have 'matched_rows' key")
        self.assertGreater(data["match_count"], 0, "match_count must be > 0 for .sol file")
        self.assertIn("l29_disc_5_mandate", data, "JSON output must have 'l29_disc_5_mandate' key")
        self.assertIn("L29-Disc-5", data["l29_disc_5_mandate"])

    # (g) .rs file → Rust rows returned
    def test_g_rs_file_returns_rust_rows(self):
        rc, stdout, stderr = _run("src/lib.rs", self.ws)
        self.assertEqual(rc, 0, f"Expected exit 0; stderr={stderr}")
        self.assertGreater(len(stdout.strip()), 0, "Expected non-empty output for .rs file")
        lower = stdout.lower()
        self.assertTrue(
            any(kw in lower for kw in ["rust", "rs", "substrate", "near"]),
            f"Expected Rust-related content; got:\n{stdout[:400]}"
        )

    # (h) --quiet flag → no stdout, exit 0
    def test_h_quiet_flag_no_stdout_exit_0(self):
        rc, stdout, stderr = _run("contracts/Vault.sol", self.ws, "--quiet")
        self.assertEqual(rc, 0, f"Expected exit 0; stderr={stderr}")
        self.assertEqual(stdout, "", f"--quiet must produce empty stdout; got={stdout!r}")


if __name__ == "__main__":
    unittest.main()
