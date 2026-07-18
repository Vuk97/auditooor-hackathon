#!/usr/bin/env python3
"""Tests for tools/anchor-detector-runner.py (Wave 2 capability uplift).

Stdlib-only. Synthetic Anchor-shaped fixtures in tempdirs — no
dependency on `~/audits/` or any external source root.

Coverage matrix:
  1. Workspace discovery: programs/<crate>/src/lib.rs preferred over
     contracts/<crate>/src.
  2. Workspace discovery: contracts/ fallback when programs/ is absent.
  3. Workspace discovery: missing programs/ AND contracts/ -> 0 files
     scanned, no crash.
  4. Region extraction: `#[program]` mod with `pub fn` -> handler region.
  5. Region extraction: `#[derive(Accounts)]` struct -> accounts_struct.
  6. Pattern fire (positive): handler missing #[account(mut)] on
     pool_state in a token-moving handler fires the
     anchor-mut-missing pattern.
  7. Pattern fire (negative): same shape WITH #[account(mut)] does NOT
     fire.
  8. function.is_anchor_handler distinguishes inside-#[program] vs
     outside.
  9. function.has_anchor_derive flips between accounts struct and a
     plain struct.
 10. function.not_source_matches_regex drops mock/test files.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "anchor-detector-runner.py"


def _load_runner_module():
    """Import tools/anchor-detector-runner.py despite the hyphen."""
    spec = importlib.util.spec_from_file_location("anchor_runner", TOOL)
    assert spec and spec.loader, f"could not load {TOOL}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(args: list) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def _make(root: Path, rel: str, body: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Synthetic Anchor program fixtures.
# ---------------------------------------------------------------------------

# A handler that moves tokens out of the pool vault but the accounts
# struct does NOT mark pool_state as mut. This is the Glow Finance #39
# shape from the DSL row.
ANCHOR_VULN_LIB_RS = textwrap.dedent("""\
    use anchor_lang::prelude::*;
    use anchor_spl::token;

    #[program]
    pub mod margin_pool {
        use super::*;

        pub fn withdraw_fees(ctx: Context<WithdrawFees>, amount: u64) -> Result<()> {
            let pool = &ctx.accounts.pool_state;
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    token::Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.fee_receiver.to_account_info(),
                        authority: ctx.accounts.authority.to_account_info(),
                    },
                ),
                amount,
            )?;
            Ok(())
        }
    }

    #[derive(Accounts)]
    pub struct WithdrawFees<'info> {
        pub pool_state: Account<'info, MarginPool>,
        pub vault: Account<'info, TokenAccount>,
        pub fee_receiver: Account<'info, TokenAccount>,
        pub authority: Signer<'info>,
        pub token_program: Program<'info, Token>,
    }

    #[account]
    pub struct MarginPool {
        pub deposit_tokens: u64,
        pub deposit_notes: u64,
    }
""")


# Same handler, but the accounts struct DOES mark pool_state with
# `#[account(mut)]` AND the handler calls `pool.withdraw(...)`. The
# anchor-mut-missing pattern must NOT fire.
ANCHOR_FIXED_LIB_RS = textwrap.dedent("""\
    use anchor_lang::prelude::*;
    use anchor_spl::token;

    #[program]
    pub mod margin_pool {
        use super::*;

        pub fn withdraw_fees(ctx: Context<WithdrawFees>, amount: u64) -> Result<()> {
            let pool = &mut ctx.accounts.pool_state;
            pool.withdraw(amount);
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    token::Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.fee_receiver.to_account_info(),
                        authority: ctx.accounts.authority.to_account_info(),
                    },
                ),
                amount,
            )?;
            Ok(())
        }
    }

    #[derive(Accounts)]
    pub struct WithdrawFees<'info> {
        #[account(mut)]
        pub pool_state: Account<'info, MarginPool>,
        #[account(mut)]
        pub vault: Account<'info, TokenAccount>,
        #[account(mut)]
        pub fee_receiver: Account<'info, TokenAccount>,
        pub authority: Signer<'info>,
        pub token_program: Program<'info, Token>,
    }

    #[account]
    pub struct MarginPool {
        pub deposit_tokens: u64,
        pub deposit_notes: u64,
    }
""")


# A small file with one #[program] handler and one plain pub fn
# helper outside any program mod — used for is_anchor_handler tests.
ANCHOR_MIXED_LIB_RS = textwrap.dedent("""\
    use anchor_lang::prelude::*;

    #[program]
    pub mod toy {
        use super::*;

        pub fn handler_inside(ctx: Context<X>, n: u64) -> Result<()> {
            let _ = n;
            Ok(())
        }
    }

    #[derive(Accounts)]
    pub struct X<'info> {
        pub user: Signer<'info>,
    }

    pub fn helper_outside(n: u64) -> u64 {
        n + 1
    }
""")


# Fixture-style file (file path includes 'mock').
ANCHOR_MOCK_LIB_RS = textwrap.dedent("""\
    use anchor_lang::prelude::*;
    use anchor_spl::token;

    #[program]
    pub mod mock_pool {
        use super::*;

        pub fn withdraw_fees(ctx: Context<WithdrawFees>, amount: u64) -> Result<()> {
            token::transfer(/* fixture */ amount.into(), 0);
            Ok(())
        }
    }

    #[derive(Accounts)]
    pub struct WithdrawFees<'info> {
        pub pool_state: Account<'info, MarginPool>,
        pub vault: Account<'info, TokenAccount>,
    }
""")


# Inline DSL rows we author for the test (so the test does not depend on
# the upstream DSL inventory).
DSL_ROW_ANCHOR_MUT_MISSING = textwrap.dedent("""\
    pattern: test-anchor-mut-missing
    severity: HIGH
    confidence: HIGH
    backend: anchor

    match:
      - function.kind: handler
      - function.name_matches: '(?i)withdraw_fees|claim_protocol_fees'
      - function.body_contains_regex: '(?i)token::transfer|transfer_checked|CpiContext'
      - function.body_contains_regex: '(?i)pub\\s+pool_state\\s*:\\s*Account<'
      - function.body_not_contains_regex: '(?i)#\\[account\\s*\\(\\s*mut.*pool_state|pool\\.withdraw\\b'
      - function.not_in_skip_list: true
      - function.not_source_matches_regex: '(?i)\\b(mock|test|fixture)'
""")


DSL_ROW_HAS_ANCHOR_DERIVE = textwrap.dedent("""\
    pattern: test-has-anchor-derive
    severity: LOW
    confidence: HIGH
    backend: anchor

    match:
      - function.has_anchor_derive: true
      - function.name_matches: '.+'
""")


DSL_ROW_IS_ANCHOR_HANDLER = textwrap.dedent("""\
    pattern: test-is-anchor-handler
    severity: LOW
    confidence: HIGH
    backend: anchor

    match:
      - function.is_anchor_handler: true
      - function.name_matches: '.+'
""")


DSL_ROW_SOLIDITY_BACKEND_IGNORED = textwrap.dedent("""\
    pattern: test-solidity-not-loaded
    severity: HIGH
    confidence: HIGH
    backend: solidity

    match:
      - function.kind: handler
      - function.name_matches: '.+'
""")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _setup_workspace(td: Path, lib_rs: str, *, layout: str = "programs",
                     crate: str = "demo",
                     extra_files: list = None) -> Path:
    """Build a synthetic Anchor workspace and return its root."""
    ws = td
    if layout == "programs":
        _make(ws, f"programs/{crate}/Cargo.toml", "[package]\nname=\"demo\"\n")
        _make(ws, f"programs/{crate}/src/lib.rs", lib_rs)
    elif layout == "contracts":
        _make(ws, f"contracts/{crate}/Cargo.toml", "[package]\nname=\"demo\"\n")
        _make(ws, f"contracts/{crate}/src/lib.rs", lib_rs)
    else:
        raise ValueError(layout)
    for rel, body in (extra_files or []):
        _make(ws, rel, body)
    return ws


def _setup_patterns(td: Path, *rows: str) -> Path:
    """Write inline DSL rows into a temp `patterns.dsl/` and return its path."""
    p_dir = td / "patterns_dsl"
    p_dir.mkdir(parents=True, exist_ok=True)
    for i, body in enumerate(rows):
        (p_dir / f"row_{i}.yaml").write_text(body, encoding="utf-8")
    return p_dir


def _scan(ws: Path, patterns: Path) -> dict:
    proc = _run([
        "--workspace", str(ws),
        "--patterns", str(patterns),
    ])
    assert proc.returncode == 0, proc.stderr
    out = ws / ".auditooor" / "anchor_findings.json"
    assert out.is_file(), f"expected findings file {out}"
    return json.loads(out.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAnchorDetectorRunner(unittest.TestCase):

    def test_workspace_discovery_programs_layout(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _setup_workspace(Path(td), ANCHOR_VULN_LIB_RS, layout="programs")
            patterns = _setup_patterns(Path(td), DSL_ROW_ANCHOR_MUT_MISSING)
            result = _scan(ws, patterns)
            self.assertEqual(result["_meta"]["files_scanned"], 1)

    def test_workspace_discovery_contracts_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _setup_workspace(Path(td), ANCHOR_VULN_LIB_RS, layout="contracts")
            patterns = _setup_patterns(Path(td), DSL_ROW_ANCHOR_MUT_MISSING)
            result = _scan(ws, patterns)
            self.assertEqual(result["_meta"]["files_scanned"], 1)

    def test_missing_programs_dir_skips_cleanly(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "README.md").write_text("# nothing here\n", encoding="utf-8")
            patterns = _setup_patterns(ws, DSL_ROW_ANCHOR_MUT_MISSING)
            result = _scan(ws, patterns)
            self.assertEqual(result["_meta"]["files_scanned"], 0)
            self.assertEqual(result["findings"], [])

    def test_handler_extraction_via_module(self):
        """Direct in-process region extraction sanity-check."""
        mod = _load_runner_module()
        with tempfile.TemporaryDirectory() as td:
            ws = _setup_workspace(Path(td), ANCHOR_MIXED_LIB_RS)
            files = mod.discover_anchor_files(ws)
            self.assertEqual(len(files), 1)
            regions = mod.extract_regions(files[0], ws)
            handler_names = {r.name for r in regions if r.kind == "handler"}
            self.assertIn("handler_inside", handler_names)
            # `helper_outside` must NOT be classified as handler.
            outside = next(r for r in regions if r.name == "helper_outside")
            self.assertEqual(outside.kind, "pub_fn")
            self.assertFalse(outside.inside_program_mod)
            # Accounts struct present.
            self.assertTrue(any(r.kind == "accounts_struct" and r.name == "X"
                                for r in regions))

    def test_positive_anchor_mut_missing_fires(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _setup_workspace(Path(td), ANCHOR_VULN_LIB_RS)
            patterns = _setup_patterns(Path(td), DSL_ROW_ANCHOR_MUT_MISSING)
            result = _scan(ws, patterns)
            findings = [f for f in result["findings"]
                        if f["pattern"] == "test-anchor-mut-missing"]
            self.assertTrue(findings,
                            f"expected at least one finding, got {result['findings']}")
            f = findings[0]
            self.assertEqual(f["severity"], "HIGH")
            self.assertEqual(f["evidence_class"], "scaffolded_unverified")
            self.assertEqual(f["region_kind"], "handler")
            self.assertEqual(f["region_name"], "withdraw_fees")
            # Path:line shape.
            self.assertRegex(f["file"], r".*\.rs:\d+$")

    def test_negative_anchor_mut_present_does_not_fire(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _setup_workspace(Path(td), ANCHOR_FIXED_LIB_RS)
            patterns = _setup_patterns(Path(td), DSL_ROW_ANCHOR_MUT_MISSING)
            result = _scan(ws, patterns)
            findings = [f for f in result["findings"]
                        if f["pattern"] == "test-anchor-mut-missing"]
            self.assertEqual(findings, [],
                             f"unexpected fire: {result['findings']}")

    def test_is_anchor_handler_predicate(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _setup_workspace(Path(td), ANCHOR_MIXED_LIB_RS)
            patterns = _setup_patterns(Path(td), DSL_ROW_IS_ANCHOR_HANDLER)
            result = _scan(ws, patterns)
            names = {f["region_name"] for f in result["findings"]
                     if f["pattern"] == "test-is-anchor-handler"}
            self.assertIn("handler_inside", names)
            self.assertNotIn("helper_outside", names)
            self.assertNotIn("X", names)

    def test_has_anchor_derive_predicate(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _setup_workspace(Path(td), ANCHOR_MIXED_LIB_RS)
            patterns = _setup_patterns(Path(td), DSL_ROW_HAS_ANCHOR_DERIVE)
            result = _scan(ws, patterns)
            names = {f["region_name"] for f in result["findings"]
                     if f["pattern"] == "test-has-anchor-derive"}
            self.assertIn("X", names)
            # `handler_inside` is a pub fn, not a #[derive(Accounts)] item,
            # so it must NOT match.
            self.assertNotIn("handler_inside", names)

    def test_solidity_backend_rows_are_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _setup_workspace(Path(td), ANCHOR_VULN_LIB_RS)
            patterns = _setup_patterns(
                Path(td),
                DSL_ROW_SOLIDITY_BACKEND_IGNORED,
            )
            result = _scan(ws, patterns)
            self.assertEqual(result["_meta"]["patterns_evaluated"], 0)
            self.assertEqual(result["findings"], [])

    def test_mock_files_are_dropped_by_not_source_matches(self):
        with tempfile.TemporaryDirectory() as td:
            # Workspace contains both a real handler and a mock-shaped file.
            ws = Path(td)
            _make(ws, "programs/real/Cargo.toml", "[package]\nname=\"real\"\n")
            _make(ws, "programs/real/src/lib.rs", ANCHOR_VULN_LIB_RS)
            _make(ws, "programs/mock_demo/Cargo.toml", "[package]\nname=\"mock_demo\"\n")
            _make(ws, "programs/mock_demo/src/lib.rs", ANCHOR_MOCK_LIB_RS)
            patterns = _setup_patterns(ws, DSL_ROW_ANCHOR_MUT_MISSING)
            result = _scan(ws, patterns)
            files = {f["file"].split(":")[0] for f in result["findings"]
                     if f["pattern"] == "test-anchor-mut-missing"}
            self.assertTrue(any("real" in f for f in files), files)
            self.assertFalse(any("mock_demo" in f for f in files),
                             f"mock file leaked through: {files}")

    def test_meta_schema_version_present(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _setup_workspace(Path(td), ANCHOR_VULN_LIB_RS)
            patterns = _setup_patterns(Path(td), DSL_ROW_ANCHOR_MUT_MISSING)
            result = _scan(ws, patterns)
            self.assertEqual(result["_meta"]["schema_version"],
                             "auditooor.anchor_findings.v1")


if __name__ == "__main__":
    unittest.main()
