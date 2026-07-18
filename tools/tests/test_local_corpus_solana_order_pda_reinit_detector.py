#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "local-corpus-solana-order-pda-reinit-detector.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("local_corpus_solana_order_pda_reinit_detector", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


VULNERABLE = """
use anchor_lang::prelude::*;

#[program]
pub mod fusion_swap {
    use super::*;

    pub fn create(ctx: Context<Create>, order: OrderConfig) -> Result<()> {
        ctx.accounts.escrow.id = order.id;
        Ok(())
    }

    pub fn cancel(ctx: Context<Cancel>, order_id: u32) -> Result<()> {
        close_escrow(
            ctx.accounts.src_token_program.to_account_info(),
            &ctx.accounts.escrow,
            ctx.accounts.escrow_src_ata.to_account_info(),
            ctx.accounts.maker.to_account_info(),
            order_id,
            ctx.bumps.escrow,
        )?;
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(order: OrderConfig)]
pub struct Create<'info> {
    #[account(mut, signer)]
    maker: Signer<'info>,
    #[account(
        init,
        payer = maker,
        space = 8 + Escrow::INIT_SPACE,
        seeds = [b"escrow", maker.key().as_ref(), order.id.to_be_bytes().as_ref()],
        bump,
    )]
    escrow: Account<'info, Escrow>,
}
"""


CLEAN_WITH_USED_ID_GUARD = """
use anchor_lang::prelude::*;

#[program]
pub mod fusion_swap {
    use super::*;

    pub fn create(ctx: Context<Create>, order: OrderConfig) -> Result<()> {
        require!(!ctx.accounts.used_order_ids.contains(order.id), EscrowError::UsedOrderId);
        ctx.accounts.used_order_ids.mark_used(order.id);
        Ok(())
    }

    pub fn cancel(ctx: Context<Cancel>, order_id: u32) -> Result<()> {
        close_escrow(ctx.accounts.maker.to_account_info(), &ctx.accounts.escrow, order_id)?;
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(order: OrderConfig)]
pub struct Create<'info> {
    #[account(mut, signer)]
    maker: Signer<'info>,
    #[account(
        init,
        payer = maker,
        space = 8 + Escrow::INIT_SPACE,
        seeds = [b"escrow", maker.key().as_ref(), order.id.to_be_bytes().as_ref()],
        bump,
    )]
    escrow: Account<'info, Escrow>,
}
"""


CLEAN_WITH_NON_ORDER_PDA = """
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CreatePool<'info> {
    #[account(mut, signer)]
    authority: Signer<'info>,
    #[account(
        init,
        payer = authority,
        seeds = [b"pool", authority.key().as_ref()],
        bump,
    )]
    pool: Account<'info, Pool>,
}
"""


CLEAN_WITHOUT_CLOSE = """
use anchor_lang::prelude::*;

#[program]
pub mod fusion_swap {
    use super::*;

    pub fn create(ctx: Context<Create>, order_id: u32) -> Result<()> {
        ctx.accounts.escrow.id = order_id;
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(order_id: u32)]
pub struct Create<'info> {
    #[account(mut, signer)]
    maker: Signer<'info>,
    #[account(
        init,
        payer = maker,
        seeds = [b"escrow", maker.key().as_ref(), order_id.to_be_bytes().as_ref()],
        bump,
    )]
    escrow: Account<'info, Escrow>,
}
"""


class LocalCorpusSolanaOrderPdaReinitDetectorTests(unittest.TestCase):
    def test_detects_reusable_order_pda_closed_without_id_guard(self) -> None:
        hits = MOD.detect_source(VULNERABLE, "programs/fusion-swap/src/lib.rs")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].packet_id, "LCCR-PKT-004")
        self.assertIn("order.id", hits[0].seed_snippet)

    def test_skips_when_used_order_id_guard_exists(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_WITH_USED_ID_GUARD, "lib.rs"), [])

    def test_skips_non_order_pda(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_WITH_NON_ORDER_PDA, "lib.rs"), [])

    def test_skips_order_pda_without_close_lifecycle(self) -> None:
        self.assertEqual(MOD.detect_source(CLEAN_WITHOUT_CLOSE, "lib.rs"), [])

    def test_cli_emits_packet_payload_and_nonzero_on_hit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = Path(tmp) / "lib.rs"
            fixture.write_text(VULNERABLE, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(fixture)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 1, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["selected_packet"], "LCCR-PKT-004")
            self.assertEqual(payload["hit_count"], 1)


if __name__ == "__main__":
    unittest.main()
