#!/usr/bin/env python3
"""Regression tests for go_ast_msgserver_missing_authority_sibling_asymmetry.

Positive fixture: a msg_server.go with a gated sibling AND an ungated mutating handler
  -> the ungated one MUST be flagged (mirrors the real NUVA CreateVault miss).
Negative fixtures:
  - every mutating handler is gated -> clean.
  - no sibling is gated (all-public server) -> clean (asymmetry oracle refutes).
  - ungated handler that does NOT mutate keeper state -> clean.
Real-CUT test: the live NUVA vault flags CreateVault while SetShareDenomMetadata is a
  gated sibling (skipped if the audit tree is absent).
"""
from __future__ import annotations

import importlib.util
import os
import pathlib

import pytest

_DET = (pathlib.Path(__file__).resolve().parents[1] / "detectors"
        / "go_ast_msgserver_missing_authority_sibling_asymmetry.py")
_spec = importlib.util.spec_from_file_location("msgserver_auth_asym", _DET)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# ---------------------------------------------------------------- fixtures ----

POSITIVE = '''\
package keeper

type msgServer struct{ *Keeper }

// SetShareDenomMetadata IS gated - this is the asymmetry oracle sibling.
func (k msgServer) SetShareDenomMetadata(goCtx context.Context, msg *types.MsgSetShareDenomMetadataRequest) (*types.MsgSetShareDenomMetadataResponse, error) {
	vault, err := k.getVault(ctx, vaultAddr)
	if err != nil {
		return nil, err
	}
	if err := vault.ValidateAdmin(msg.Admin); err != nil {
		return nil, err
	}
	k.BankKeeper.SetDenomMetaData(ctx, msg.Metadata)
	return &types.MsgSetShareDenomMetadataResponse{}, nil
}

// CreateVault is UNGATED and reaches k.Keeper.CreateVault - MUST be flagged.
func (k msgServer) CreateVault(goCtx context.Context, msg *types.MsgCreateVaultRequest) (*types.MsgCreateVaultResponse, error) {
	ctx := sdk.UnwrapSDKContext(goCtx)
	vault, err := k.Keeper.CreateVault(ctx, msg)
	if err != nil {
		return nil, err
	}
	return &types.MsgCreateVaultResponse{VaultAddress: vault.Address}, nil
}
'''

# every mutating handler is gated -> clean.
NEG_ALL_GATED = '''\
package keeper

type msgServer struct{ *Keeper }

func (k msgServer) CreateVault(goCtx context.Context, msg *types.MsgCreateVaultRequest) (*types.MsgCreateVaultResponse, error) {
	if err := vault.ValidateManagementAuthority(msg.Authority); err != nil {
		return nil, err
	}
	k.Keeper.CreateVault(ctx, msg)
	return nil, nil
}

func (k msgServer) SetThing(goCtx context.Context, msg *types.MsgSetThingRequest) (*types.MsgSetThingResponse, error) {
	if err := vault.ValidateAdmin(msg.Admin); err != nil {
		return nil, err
	}
	k.SetThing(ctx, msg)
	return nil, nil
}
'''

# NO sibling is gated -> asymmetry oracle refutes, clean even though CreateVault mutates.
NEG_NO_SIBLING_GATED = '''\
package keeper

type msgServer struct{ *Keeper }

func (k msgServer) CreateVault(goCtx context.Context, msg *types.MsgCreateVaultRequest) (*types.MsgCreateVaultResponse, error) {
	k.Keeper.CreateVault(ctx, msg)
	return nil, nil
}

func (k msgServer) RegisterThing(goCtx context.Context, msg *types.MsgRegisterThingRequest) (*types.MsgRegisterThingResponse, error) {
	k.RegisterThing(ctx, msg)
	return nil, nil
}
'''

# ungated handler that does NOT mutate keeper state (read-only) -> clean.
NEG_UNGATED_READONLY = '''\
package keeper

type msgServer struct{ *Keeper }

func (k msgServer) SetThing(goCtx context.Context, msg *types.MsgSetThingRequest) (*types.MsgSetThingResponse, error) {
	if err := vault.ValidateAdmin(msg.Admin); err != nil {
		return nil, err
	}
	k.SetThing(ctx, msg)
	return nil, nil
}

// ungated but only READS - no create/enqueue/set keeper mutate.
func (k msgServer) SwapQuote(goCtx context.Context, msg *types.MsgSwapQuoteRequest) (*types.MsgSwapQuoteResponse, error) {
	q, err := k.Keeper.GetQuote(ctx, msg)
	if err != nil {
		return nil, err
	}
	return &types.MsgSwapQuoteResponse{Quote: q}, nil
}
'''


def _write(tmp_path, name, content):
    d = tmp_path / "keeper"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(content, encoding="utf-8")
    return str(tmp_path)


# ---------------------------------------------------------------- tests ----

def test_positive_flags_ungated_mutator(tmp_path):
    root = _write(tmp_path, "msg_server.go", POSITIVE)
    rep = mod.scan_root(root)
    fns = {f["function"] for f in rep["findings"]}
    assert "CreateVault" in fns, rep
    assert rep["finding_count"] == 1, rep
    f = rep["findings"][0]
    assert f["severity_hint"] == "high"
    assert f["schema"] == mod.SCHEMA
    assert f["mechanism"] == mod.MECHANISM
    # every required schema key present
    for k in ("schema", "mechanism", "impact", "severity_hint", "file", "line",
              "function", "reason", "source_record_id"):
        assert k in f, (k, f)
    assert "SetShareDenomMetadata" in f["gated_siblings"]


def test_negative_all_gated_clean(tmp_path):
    root = _write(tmp_path, "msg_server.go", NEG_ALL_GATED)
    rep = mod.scan_root(root)
    assert rep["finding_count"] == 0, rep


def test_negative_no_sibling_gated_clean(tmp_path):
    root = _write(tmp_path, "msg_server.go", NEG_NO_SIBLING_GATED)
    rep = mod.scan_root(root)
    assert rep["finding_count"] == 0, rep


def test_negative_ungated_readonly_clean(tmp_path):
    root = _write(tmp_path, "msg_server.go", NEG_UNGATED_READONLY)
    rep = mod.scan_root(root)
    assert rep["finding_count"] == 0, rep


def test_only_scans_msg_server_files(tmp_path):
    # a non-msg_server file with the same shape must be ignored.
    d = tmp_path / "keeper"
    d.mkdir(parents=True, exist_ok=True)
    (d / "keeper.go").write_text(POSITIVE, encoding="utf-8")
    rep = mod.scan_root(str(tmp_path))
    assert rep["finding_count"] == 0, rep
    assert rep["files_scanned"] == []


_NUVA = "/Users/wolf/audits/nuva/src/vault"


@pytest.mark.skipif(not os.path.isdir(_NUVA), reason="NUVA audit tree absent")
def test_real_nuva_flags_createvault():
    rep = mod.scan_root(_NUVA)
    flagged = {f["function"] for f in rep["findings"]}
    assert "CreateVault" in flagged, rep
    cv = next(f for f in rep["findings"] if f["function"] == "CreateVault")
    # the gated sibling oracle names SetShareDenomMetadata (ValidateAdmin).
    assert "SetShareDenomMetadata" in cv["gated_siblings"], cv
    assert cv["file"].endswith("msg_server.go")
    assert cv["severity_hint"] == "high"
