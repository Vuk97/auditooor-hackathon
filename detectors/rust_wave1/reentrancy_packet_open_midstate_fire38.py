"""
reentrancy_packet_open_midstate_fire38.py

Rust detector for packet-open, NFT receiver, and reward-update callback
midstates.

Flags public Rust entrypoints that snapshot packet, card, reward, or
collateral state before an external receiver, hook, safe-mint, transfer, or
CPI boundary, then mint, mark opened, update rewards, or finalize related
accounting after that boundary without a shared lock or post-callback reload.

Source refs:
- reports/detector_lift_fire37_20260605/post_priorities_rust.md
- detectors/rust_wave1/reentrancy_callback_midstate_fire37.py
- detectors/rust_wave1/r94_loop_nft_packet_open_reentrancy_duplicate_card_mint.py
- detectors/rust_wave1/r94_loop_post_exec_check_reentrancy_bypass.py
- detectors/rust_wave1/r94_loop_rewards_update_after_external_transfer_reentrancy_steal.py
- reference/patterns.dsl/reentrancy-cross-contract-stale-state-callback.yaml

Provenance and evidence limits:
- R37: verification_tier: tier-3-synthetic-taxonomy-anchored.
- attack_class: reentrancy-cross-contract.
- R40: fixtures are detector smoke tests, not exploit PoCs.
- R76: candidate promotion must grep-verify any cited excerpt exists.
- R80: detector hits are not load-bearing exploit evidence.

Submission posture: NOT_SUBMIT_READY.
"""

from __future__ import annotations

import re

from _util import (
    body_text_nocomment,
    fn_body,
    fn_name,
    function_items,
    in_test_cfg,
    is_pub,
    line_col,
    snippet_of,
)


DETECTOR_ID = "rust_wave1.reentrancy_packet_open_midstate_fire38"

_SNAPSHOT_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\:[^=;]+)?=\s*(?P<rhs>[^;]{1,900});"
)

_PACKET_STATE_SOURCE_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\bself\s*\.|"
    r"\bctx\s*\.\s*accounts\s*\.|"
    r"\baccounts?\s*\.|"
    r"\bstate\s*\.|"
    r"\bledger\s*\.|"
    r"\bvault\s*\.|"
    r"\bpool\s*\.|"
    r"\bmarket\s*\.|"
    r"\bpacket[s]?\s*\.|"
    r"\bcard[s]?\s*\.|"
    r"\breward[s]?\s*\.|"
    r"\bcollateral\s*\.|"
    r"\bstorage\s*\(\s*\)|"
    r"\.get\s*\(|"
    r"\.load\s*\(|"
    r"\.borrow\s*\(|"
    r"\.try_borrow\s*\(|"
    r"\.balance_of\s*\(|"
    r"\.shares_of\s*\("
    r")"
)

_PACKET_FAMILY_RE = re.compile(
    r"(?i)"
    r"(packet|packets|pack|booster|card|cards|nft|token_id|tokenid|"
    r"mint|minted|open|opened|reward|rewards|reward_debt|claim|claims|"
    r"collateral|share|shares|escrow|vault|pool|accounting|status)"
)

_EXTERNAL_BOUNDARY_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"\benv\s*\.\s*(?:try_)?invoke_contract(?:\s*::\s*<[^>]+>)?\s*\(|"
    r"\b(?:try_)?invoke_contract\s*\(|"
    r"\bcall_contract\s*\(|"
    r"\binvoke_signed\s*\(|"
    r"\bprogram::invoke_signed\s*\(|"
    r"\binvoke\s*\(|"
    r"\bprogram::invoke\s*\(|"
    r"\banchor_spl::token::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\btoken::(?:transfer|transfer_checked|mint_to|burn)\s*\(|"
    r"\bcpi::[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"\b(?:_?safe_?mint|mint_to|safe_transfer_from|safeTransferFrom|"
    r"safe_transfer|transfer_from|transfer_checked)\s*\(|"
    r"\b(?:"
    r"(?:[A-Za-z_][A-Za-z0-9_\.]*)?"
    r"(?:callback|hook|receiver|recipient|program|callee|token|nft|"
    r"router|adapter|client|bridge)"
    r"[A-Za-z0-9_\.]*"
    r")\s*\.\s*(?:"
    r"before_[A-Za-z0-9_]+|after_[A-Za-z0-9_]+|on_[A-Za-z0-9_]+|"
    r"on_?erc721_?received|on_?erc1155_?received|on_?receive[A-Za-z0-9_]*|"
    r"callback|hook|receive_[A-Za-z0-9_]*|handle_[A-Za-z0-9_]*|"
    r"execute_[A-Za-z0-9_]*|invoke|call|call_contract|safe_mint|"
    r"safe_transfer_from|transfer_from|transfer|send"
    r")\s*\("
    r")"
)

_GUARD_RE = re.compile(
    r"(?is)"
    r"(#\[\s*non_reentrant\s*\]|non_reentrant|nonReentrant|"
    r"ReentrancyGuard|reentrancy_guard|reentrancy_lock|cpi_guard|"
    r"callback_lock|callback_guard|packet_lock|open_lock|mint_lock|"
    r"reward_lock|collateral_lock|enter_reentrancy|enter_guard|"
    r"guard\.enter|lock_reentrancy|acquire_reentrancy|"
    r"check_and_set|is_entered|guard_entered|in_callback\s*=\s*true|"
    r"in_reentrancy\s*=\s*true|reentrancy_[A-Za-z0-9_]*\s*=\s*true|"
    r"locked\s*=\s*true|entered\s*=\s*true|_entered\s*=\s*true|"
    r"(?:packet|open|mint|reward|collateral)_[A-Za-z0-9_]*lock\s*=\s*true)"
)

_REFRESH_RE = re.compile(
    r"(?i)"
    r"(reload|refresh|revalid|validate_after|post_callback|post_call|"
    r"after_callback|after_hook|ensure_current|check_current|current_|"
    r"latest_|fresh_|updated_|packet_after|card_after|reward_after|"
    r"collateral_after|shares_after|open_after|status_after)"
)

_STATE_WRITE_RE = re.compile(
    r"(?is)"
    r"(?:"
    r"\b(?:self|state|ledger|vault|pool|market|packet|packets|card|"
    r"cards|reward|rewards|claim|claims|collateral|share|shares|"
    r"escrow|ctx\s*\.\s*accounts|accounts)"
    r"[A-Za-z0-9_\.\[\]]*\s*(?:=|\+=|-=)|"
    r"\.(?:insert|set|update|save|remove|write|replace|push)\s*\(|"
    r"\bstorage\s*\(\s*\)[\s\S]{0,220}\."
    r"(?:set|update|remove)\s*\(|"
    r"\b(?:self\s*\.\s*)?(?:"
    r"update_account_rewards|updateAccountRewards|accrue_rewards_for|"
    r"distribute_rewards_for|sync_reward_checkpoint|claim_reward_debt_update|"
    r"mint_card|mint_reward|safe_mint_card|mark_packet_opened|"
    r"commit_packet_open|finalize_packet|finalise_packet|finalize_accounting|"
    r"finalise_accounting"
    r")\s*\("
    r")"
)

_FINALIZATION_RE = re.compile(
    r"(?i)"
    r"(packet|packets|pack|booster|card|cards|nft|token_id|tokenid|"
    r"mint|minted|open|opened|status|reward|rewards|reward_debt|claim|"
    r"claimed|collateral|share|shares|escrow|vault|pool|accounting|"
    r"finali[sz]e|processed|complete|owed|paid|amount|total|supply|"
    r"insert|set|update|save|remove|write|replace|push)"
)

_DERIVED_ASSIGN_RE = re.compile(
    r"(?is)\blet\s+(?:mut\s+)?(?P<var>[A-Za-z_][A-Za-z0-9_]*)"
    r"\s*(?:\:[^=;]+)?=\s*(?P<rhs>[^;]{1,700});"
)

_LOCAL_ONLY_RE = re.compile(
    r"(?i)\b(?:emit_event|publish_event|record_event|log_event|"
    r"record_metric|notify_only|view_only|read_only)\s*\("
)


def _line_for_offset(base_line: int, text: str, offset: int) -> int:
    return base_line + text[:offset].count("\n")


def _contains_var(text: str, var_name: str) -> bool:
    return re.search(rf"\b{re.escape(var_name)}\b", text) is not None


def _families(text: str) -> set[str]:
    return {match.group(1).lower() for match in _PACKET_FAMILY_RE.finditer(text)}


def _is_packet_snapshot(var_name: str, rhs: str) -> bool:
    combined = f"{var_name} {rhs}"
    return bool(_PACKET_FAMILY_RE.search(combined) and _PACKET_STATE_SOURCE_RE.search(rhs))


def _has_guard_before(header_prefix: str, body_text: str, offset: int) -> bool:
    return bool(_GUARD_RE.search(header_prefix + "\n" + body_text[:offset]))


def _statement_ranges(source: str, start: int) -> list[tuple[int, int, str]]:
    ranges: list[tuple[int, int, str]] = []
    stmt_start = start
    depth = 0
    for pos in range(start, len(source)):
        char = source[pos]
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
        elif char == ";" and depth == 0:
            ranges.append((stmt_start, pos + 1, source[stmt_start:pos + 1]))
            stmt_start = pos + 1
    tail = source[stmt_start:].strip()
    if tail:
        ranges.append((stmt_start, len(source), source[stmt_start:]))
    return ranges


def _statement_end_after(source: str, start: int) -> int:
    depth = 0
    for pos in range(start, len(source)):
        char = source[pos]
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
        elif char == ";" and depth == 0:
            return pos + 1
    return start


def _has_post_callback_refresh(region: str, snapshot_var: str, families: set[str]) -> bool:
    if not region.strip():
        return False

    if _REFRESH_RE.search(region):
        if _PACKET_STATE_SOURCE_RE.search(region):
            return True
        if any(family in region.lower() for family in families):
            return True

    same_var_reload = re.search(
        rf"(?is)\b(?:let\s+(?:mut\s+)?)?{re.escape(snapshot_var)}\s*=",
        region,
    )
    if same_var_reload and _PACKET_STATE_SOURCE_RE.search(region):
        return True

    for assign in _SNAPSHOT_ASSIGN_RE.finditer(region):
        name = assign.group("var")
        rhs = assign.group("rhs")
        combined = f"{name} {rhs}".lower()
        if not any(family in combined for family in families):
            continue
        if _PACKET_STATE_SOURCE_RE.search(rhs):
            return True

    return False


def _statement_finalizes_snapshot(stmt: str, tracked: set[str], families: set[str]) -> bool:
    if not _STATE_WRITE_RE.search(stmt):
        return False
    if not _FINALIZATION_RE.search(stmt):
        return False
    if any(_contains_var(stmt, var_name) for var_name in tracked):
        return True
    lowered = stmt.lower()
    return any(family in lowered for family in families)


def _first_post_callback_finalization(body_text: str, boundary_end: int, snapshot: dict):
    tracked = {snapshot["var"]}
    families = set(snapshot["families"])

    for start, end, stmt in _statement_ranges(body_text, boundary_end):
        prefix = body_text[boundary_end:start]
        if _has_post_callback_refresh(prefix, snapshot["var"], families):
            return None
        if _has_post_callback_refresh(stmt, snapshot["var"], families):
            return None

        derived = _DERIVED_ASSIGN_RE.search(stmt)
        if derived is not None and any(
            _contains_var(derived.group("rhs"), var_name) for var_name in tracked
        ):
            derived_name = derived.group("var")
            if _PACKET_FAMILY_RE.search(f"{derived_name} {derived.group('rhs')}"):
                tracked.add(derived_name)

        if _statement_finalizes_snapshot(stmt, tracked, families):
            return {
                "start": start,
                "end": end,
                "text": " ".join(stmt.split())[:160],
            }

    return None


def run(tree, source: bytes, filepath: str):
    hits = []
    source_text = source.decode("utf-8", errors="replace")

    for fn in function_items(tree.root_node):
        if in_test_cfg(fn, source):
            continue
        if not is_pub(fn, source):
            continue

        body = fn_body(fn)
        if body is None:
            continue

        body_text = body_text_nocomment(body, source)
        if _EXTERNAL_BOUNDARY_RE.search(body_text) is None:
            continue
        if _PACKET_FAMILY_RE.search(body_text) is None:
            continue

        header_prefix = source_text[max(0, fn.start_byte - 300):fn.start_byte]
        body_line, _ = line_col(body)
        name = fn_name(fn, source)
        emitted_for_fn = False

        for snapshot_match in _SNAPSHOT_ASSIGN_RE.finditer(body_text):
            snapshot_var = snapshot_match.group("var")
            snapshot_rhs = snapshot_match.group("rhs")
            if not _is_packet_snapshot(snapshot_var, snapshot_rhs):
                continue

            snapshot = {
                "var": snapshot_var,
                "families": _families(f"{snapshot_var} {snapshot_rhs}"),
            }
            if not snapshot["families"]:
                continue

            for boundary in _EXTERNAL_BOUNDARY_RE.finditer(
                body_text,
                snapshot_match.end(),
            ):
                if _LOCAL_ONLY_RE.search(boundary.group(0)):
                    continue
                if _has_guard_before(header_prefix, body_text, boundary.start()):
                    continue
                boundary_statement_end = _statement_end_after(body_text, boundary.start())

                finalization = _first_post_callback_finalization(
                    body_text,
                    boundary_statement_end,
                    snapshot,
                )
                if finalization is None:
                    continue

                snapshot_line = _line_for_offset(
                    body_line,
                    body_text,
                    snapshot_match.start(),
                )
                boundary_line = _line_for_offset(
                    body_line,
                    body_text,
                    boundary.start(),
                )
                final_line = _line_for_offset(
                    body_line,
                    body_text,
                    finalization["start"],
                )

                hits.append(
                    {
                        "detector_id": DETECTOR_ID,
                        "severity": "high",
                        "line": boundary_line,
                        "col": 0,
                        "snippet": snippet_of(body, source)[:220],
                        "message": (
                            f"fn `{name}` snapshots packet/card/reward/"
                            f"collateral state `{snapshot_var}` at line "
                            f"{snapshot_line}, transfers control through a "
                            f"receiver, hook, safe-mint, or CPI boundary at "
                            f"line {boundary_line}, then finalizes related "
                            f"state at line {final_line} without a shared "
                            "lock or post-callback reload. Commit opened/"
                            "minted/reward/collateral state before the "
                            "callback, or use a per-packet/per-account lock "
                            "and reload state after the callback before "
                            "using cached packet, card, reward, or collateral "
                            "values. NOT_SUBMIT_READY: this is source-state "
                            "candidate evidence only."
                        ),
                    }
                )
                emitted_for_fn = True
                break

            if emitted_for_fn:
                break

    return hits
