#!/usr/bin/env python3
"""
fork-replay-assert.py — evaluate delta assertions against fork-replay artifacts.

PR 104 companion to tools/fork-replay.sh. Given a pre-generated
`<tx>_manifest.json` and `<tx>_deltas.json`, evaluate one or more
`--assert-delta <selector>:<op>:<amount>` assertions and write the results
back into BOTH the manifest (`assertions` array) and the deltas file
(`assertions` field).

Selectors:
  <label>                         — a targeted_watches row (from PR 103).
  native:<address>                — native balance delta from per-address map.
  erc20:<token>:<holder>          — erc20 delta from per-address map.

Operators: eq, gt, gte, lt, lte, nonzero.
Amount: decimal integer string (may be negative). Ignored for op=nonzero.

Status is one of PASS | FAIL | INCONCLUSIVE. INCONCLUSIVE is reserved for:
  - no matching row for the selector
  - observed delta is null (balanceOf reverted)
  - native:<tx.from> (gas-aware semantics not supported yet)
  - amount not parseable (for numeric ops)

Impact-bound assertion binding (Codex capv3-iter1 T2, roadmap #1):
  When `--draft-claims <path>` is supplied, the tool additionally requires
  that at least one assertion reference one of the draft's claimed
  {victim, attacker, protocol} actor addresses. If no assertion is
  impact-bound, the tool emits a top-level error `assertion-not-impact-bound`
  on stderr and exits non-zero — preventing a replay where "some unrelated
  address gains Y" is miscounted as proof of "attacker drains X from victim".

  The `<path>` JSON schema:
      {
        "victim":        "0x...",    # optional
        "attacker":      "0x...",    # optional
        "protocol":      "0x...",    # optional
        "direction":     "gain"|"loss",  # currently informational
        "min_magnitude": "<decimal>"     # currently informational
      }

  At least one of victim/attacker/protocol must be present. Empty / absent
  values are skipped (you can bind against only a victim, say). Address
  comparison is case-insensitive.

  When `--draft-claims` is absent, behavior is UNCHANGED — this is
  backward compatible. Written artifacts never gain new top-level keys when
  the flag is off.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

NUMERIC_OPS = {"eq", "gt", "gte", "lt", "lte"}
VALID_OPS = NUMERIC_OPS | {"nonzero"}

# Codex capv3-iter1 T2, roadmap #1: the allowed actor roles in --draft-claims.
# Any claimed address keyed under one of these roles counts as an impact-bound
# target. Unknown keys are silently ignored (forward-compatible).
IMPACT_ACTOR_ROLES = ("victim", "attacker", "protocol")

# Codex PR-102 blocker 5: the assert tool is the last line of defense against
# a "green" PASS on artifacts whose replay never actually executed. Treat any
# manifest.status outside this whitelist as a hard short-circuit: emit
# INCONCLUSIVE for every requested assertion, regardless of what the deltas
# file happens to contain. fork-replay.sh emits "executed" on success,
# "failed" on cast-run failure; "success" is reserved for legacy manifests.
SUCCESSFUL_REPLAY_STATUSES = {"executed", "success"}


def _is_hex_address(candidate: str) -> bool:
    """Loose 0x40-hex check. The bound-check is case-insensitive on contents."""
    if not isinstance(candidate, str):
        return False
    if not candidate.startswith("0x") and not candidate.startswith("0X"):
        return False
    body = candidate[2:]
    return len(body) == 40 and all(c in "0123456789abcdefABCDEF" for c in body)


def load_draft_claims(path: Path) -> dict[str, Any]:
    """Load and validate a --draft-claims JSON file.

    Raises ValueError on any schema violation. The returned dict normalises
    addresses to lowercase and only retains actor roles in
    IMPACT_ACTOR_ROLES (+ the informational direction / min_magnitude fields).
    """
    try:
        payload = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"--draft-claims file unreadable: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(
            "--draft-claims must be a JSON object with victim/attacker/protocol keys"
        )

    claims: dict[str, Any] = {}
    for role in IMPACT_ACTOR_ROLES:
        val = payload.get(role)
        if val is None or val == "":
            continue
        if not _is_hex_address(val):
            raise ValueError(
                f"--draft-claims: role {role!r} must be a 0x-prefixed 40-hex address, "
                f"got {val!r}"
            )
        claims[role] = val.lower()

    if not any(role in claims for role in IMPACT_ACTOR_ROLES):
        raise ValueError(
            "--draft-claims: at least one of victim/attacker/protocol must be set"
        )

    # Informational fields — currently advisory. Round-trip them as-is so they
    # appear in the output artifact for later triager inspection.
    direction = payload.get("direction")
    if direction is not None:
        if direction not in ("gain", "loss"):
            raise ValueError(
                f"--draft-claims: direction must be 'gain' or 'loss', got {direction!r}"
            )
        claims["direction"] = direction
    min_magnitude = payload.get("min_magnitude")
    if min_magnitude is not None:
        # accept string or number — normalise to string for downstream round-trip
        claims["min_magnitude"] = str(min_magnitude)
    return claims


def selector_addresses(selector: str, matched_row: dict | None) -> list[str]:
    """Return every 0x address referenced by this assertion that is an ACTOR
    (wallet / EOA / vault-contract acting as a holder), lowercased.

    Actor-role distinction (Codex PR 104 blocker #6, Check #22): an ERC20 key
    like `erc20:<token>:<holder>` names TWO addresses, but only `<holder>`
    is an actor candidate. `<token>` is the ERC20 contract itself; treating
    it as an actor let a draft with `protocol=<TOKEN_ADDR>` falsely impact-
    bind on any unrelated holder's delta in that token. We therefore omit
    the token address from the actor-address list emitted here.

    Sources:
      - `native:<addr>`          → [addr]       (addr is the holder)
      - `erc20:<token>:<holder>` → [holder]     (token address is NOT an actor)
      - `<label>`                → addresses pulled from the matched
                                   targeted_watches row — `holder` / `address`
                                   fields only. `token` is skipped for the
                                   same role reason as above.
    """
    out: list[str] = []
    if selector.startswith("native:"):
        addr = selector[len("native:") :]
        if _is_hex_address(addr):
            out.append(addr.lower())
    elif selector.startswith("erc20:"):
        rest = selector[len("erc20:") :]
        if ":" in rest:
            _token, holder = rest.split(":", 1)
            # token intentionally omitted: it's a contract, not an actor.
            if _is_hex_address(holder):
                out.append(holder.lower())
    if matched_row:
        # `token` intentionally omitted from the actor-address list: a
        # targeted_watches row's `token` names the ERC20 contract, not an
        # actor. Only `holder` / `address` can be bound to a claimed actor.
        for key in ("holder", "address"):
            val = matched_row.get(key)
            if _is_hex_address(val):
                out.append(val.lower())
    return out


def assertion_is_impact_bound(
    result: dict[str, Any], claims: dict[str, Any]
) -> bool:
    """True if any address referenced by this assertion matches a claimed actor.

    Case-insensitive comparison. An assertion with no resolvable addresses
    (e.g. a bare label whose row never matched) is NOT impact-bound.
    """
    claim_addrs = {
        claims[role]
        for role in IMPACT_ACTOR_ROLES
        if role in claims
    }
    if not claim_addrs:
        return False
    addrs = selector_addresses(
        result.get("selector") or "", result.get("matched_row")
    )
    return any(a in claim_addrs for a in addrs)


def parse_assertion_spec(spec: str) -> dict[str, str]:
    """Parse `<selector>:<op>:<amount>`.

    The selector may itself contain colons (e.g. `erc20:<token>:<holder>`).
    We split from the RIGHT on ':' to pull off amount then op.
    """
    if spec.count(":") < 2:
        raise ValueError(
            f"--assert-delta must be <selector>:<op>:<amount>, got: {spec!r}"
        )
    head, amount = spec.rsplit(":", 1)
    selector, op = head.rsplit(":", 1)
    op = op.lower()
    if op not in VALID_OPS:
        raise ValueError(
            f"unknown op {op!r}; valid: {sorted(VALID_OPS)}"
        )
    return {"selector": selector, "op": op, "amount": amount}


def find_targeted_row(deltas: dict, label: str) -> dict | None:
    rows = deltas.get("targeted_watches") or []
    for row in rows:
        if row.get("label") == label:
            return row
    return None


def find_native_delta(deltas: dict, address: str) -> tuple[dict | None, str | None]:
    """Return (matched_row_dict, observed_delta_str_or_None).

    matched_row is a compact dict describing what was matched.
    """
    addr_map = deltas.get("addresses") or {}
    # case-insensitive match on address key
    want = address.lower()
    for key, entry in addr_map.items():
        if key.lower() == want:
            native = entry.get("nativeWei") or {}
            return (
                {
                    "kind": "native",
                    "address": key,
                    "pre": native.get("pre"),
                    "post": native.get("post"),
                    "delta": native.get("delta"),
                },
                native.get("delta"),
            )
    return None, None


def find_erc20_delta(
    deltas: dict, token: str, holder: str
) -> tuple[dict | None, str | None]:
    addr_map = deltas.get("addresses") or {}
    want_holder = holder.lower()
    want_token = token.lower()
    for key, entry in addr_map.items():
        if key.lower() != want_holder:
            continue
        erc20_map = entry.get("erc20") or {}
        for tkey, tentry in erc20_map.items():
            if tkey.lower() == want_token:
                return (
                    {
                        "kind": "erc20",
                        "token": tkey,
                        "holder": key,
                        "pre": tentry.get("pre"),
                        "post": tentry.get("post"),
                        "delta": tentry.get("delta"),
                    },
                    tentry.get("delta"),
                )
    return None, None


def evaluate_assertion(
    parsed: dict[str, str], deltas: dict, manifest: dict
) -> dict[str, Any]:
    selector = parsed["selector"]
    op = parsed["op"]
    amount = parsed["amount"]

    matched_row: dict | None = None
    observed: str | None = None

    # --- resolve selector -------------------------------------------------
    if selector.startswith("native:"):
        address = selector[len("native:") :]
        # Gas-aware semantics: if this is the tx.from, we cannot cleanly claim
        # the native delta without subtracting gas; PR 104 declines rather
        # than overclaims.
        tx_from = (manifest.get("from") or "").lower()
        if address.lower() == tx_from and tx_from:
            return {
                "selector": selector,
                "op": op,
                "amount": amount,
                "matched_row": None,
                "observed_delta": None,
                "status": "INCONCLUSIVE",
                "reason": "gas-aware semantics not supported yet",
            }
        matched_row, observed = find_native_delta(deltas, address)
    elif selector.startswith("erc20:"):
        rest = selector[len("erc20:") :]
        if rest.count(":") < 1:
            return {
                "selector": selector,
                "op": op,
                "amount": amount,
                "matched_row": None,
                "observed_delta": None,
                "status": "INCONCLUSIVE",
                "reason": "erc20 selector must be erc20:<token>:<holder>",
            }
        token, holder = rest.split(":", 1)
        matched_row, observed = find_erc20_delta(deltas, token, holder)
    else:
        # Bare label — targeted_watches row from PR 103.
        row = find_targeted_row(deltas, selector)
        if row is not None:
            matched_row = dict(row)
            observed = row.get("delta")

    # --- no matching row --------------------------------------------------
    if matched_row is None:
        return {
            "selector": selector,
            "op": op,
            "amount": amount,
            "matched_row": None,
            "observed_delta": None,
            "status": "INCONCLUSIVE",
            "reason": "no matching row",
        }

    # --- null observed delta (e.g. balanceOf reverted) --------------------
    if observed is None:
        return {
            "selector": selector,
            "op": op,
            "amount": amount,
            "matched_row": matched_row,
            "observed_delta": None,
            "status": "INCONCLUSIVE",
            "reason": "observed delta is null",
        }

    # --- nonzero op -------------------------------------------------------
    if op == "nonzero":
        try:
            observed_int = int(str(observed))
        except (TypeError, ValueError):
            return {
                "selector": selector,
                "op": op,
                "amount": amount,
                "matched_row": matched_row,
                "observed_delta": observed,
                "status": "INCONCLUSIVE",
                "reason": "observed delta is not a decimal integer",
            }
        status = "PASS" if observed_int != 0 else "FAIL"
        return {
            "selector": selector,
            "op": op,
            "amount": amount,
            "matched_row": matched_row,
            "observed_delta": str(observed_int),
            "status": status,
            "reason": None,
        }

    # --- numeric comparison ops ------------------------------------------
    try:
        observed_int = int(str(observed))
    except (TypeError, ValueError):
        return {
            "selector": selector,
            "op": op,
            "amount": amount,
            "matched_row": matched_row,
            "observed_delta": observed,
            "status": "INCONCLUSIVE",
            "reason": "observed delta is not a decimal integer",
        }
    try:
        amount_int = int(str(amount))
    except (TypeError, ValueError):
        return {
            "selector": selector,
            "op": op,
            "amount": amount,
            "matched_row": matched_row,
            "observed_delta": str(observed_int),
            "status": "INCONCLUSIVE",
            "reason": f"amount {amount!r} is not a decimal integer",
        }

    if op == "eq":
        passed = observed_int == amount_int
    elif op == "gt":
        passed = observed_int > amount_int
    elif op == "gte":
        passed = observed_int >= amount_int
    elif op == "lt":
        passed = observed_int < amount_int
    elif op == "lte":
        passed = observed_int <= amount_int
    else:  # pragma: no cover — VALID_OPS guards this.
        passed = False

    return {
        "selector": selector,
        "op": op,
        "amount": amount,
        "matched_row": matched_row,
        "observed_delta": str(observed_int),
        "status": "PASS" if passed else "FAIL",
        "reason": None,
    }


def run_assertions(
    manifest_path: Path,
    deltas_path: Path,
    specs: list[str],
    draft_claims: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text())
    deltas = json.loads(deltas_path.read_text())
    parsed_specs = [parse_assertion_spec(s) for s in specs]

    # Codex PR-102 blocker 5: short-circuit if the replay itself did not
    # succeed. A "failed" manifest (cast-run errored) or anything outside
    # SUCCESSFUL_REPLAY_STATUSES means the deltas file's observed values may
    # reflect an unexecuted / partial state. Emit INCONCLUSIVE for every
    # spec so a caller using --fail-on-fail cannot inadvertently mark such
    # a replay as PASS.
    manifest_status_raw = manifest.get("status")
    manifest_status = str(manifest_status_raw or "").lower()
    if manifest_status not in SUCCESSFUL_REPLAY_STATUSES:
        reason = (
            f"manifest.status={manifest_status_raw!r} is not in "
            f"{sorted(SUCCESSFUL_REPLAY_STATUSES)}"
        )
        results = [
            {
                "selector": p["selector"],
                "op": p["op"],
                "amount": p["amount"],
                "matched_row": None,
                "observed_delta": None,
                "status": "INCONCLUSIVE",
                "reason": reason,
            }
            for p in parsed_specs
        ]
    else:
        results = [evaluate_assertion(p, deltas, manifest) for p in parsed_specs]

    # --- impact-bound check (Codex capv3-iter1 T2, roadmap #1) -----------
    # When the caller supplied --draft-claims, augment each result with an
    # `impact_bound` boolean, and record a top-level claims echo in both
    # artifacts. The error-code emission (exit status) is left to `main()`,
    # so library callers can still drive the tool programmatically and
    # inspect the annotated `results` without a SystemExit.
    if draft_claims:
        for r in results:
            r["impact_bound"] = assertion_is_impact_bound(r, draft_claims)
        # Round-trip the claims into the artifacts so a reviewer can see
        # exactly what was asserted against. Preserving the same sort order
        # here keeps the persisted manifest + deltas byte-reproducible.
        claims_echo = dict(draft_claims)
        manifest["draft_claims"] = claims_echo
        deltas["draft_claims"] = claims_echo

    # write back into both files (round-tripped JSON)
    manifest["assertions"] = results
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )

    deltas["assertions"] = results
    deltas_path.write_text(
        json.dumps(deltas, indent=2, sort_keys=True) + "\n"
    )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate delta assertions against fork-replay artifacts."
    )
    parser.add_argument(
        "--manifest", required=True, help="path to <tx>_manifest.json"
    )
    parser.add_argument(
        "--deltas", required=True, help="path to <tx>_deltas.json"
    )
    parser.add_argument(
        "--assert-delta",
        dest="asserts",
        action="append",
        default=[],
        help="selector:op:amount — may repeat",
    )
    parser.add_argument(
        "--fail-on-fail",
        action="store_true",
        help="exit non-zero if any assertion is FAIL (INCONCLUSIVE does not).",
    )
    parser.add_argument(
        "--draft-claims",
        dest="draft_claims",
        default=None,
        help=(
            "path to a JSON file declaring the draft's claimed victim/attacker/"
            "protocol addresses. When set, at least one assertion must reference "
            "one of those actors or the tool exits non-zero with error code "
            "'assertion-not-impact-bound' (Codex capv3-iter1 T2)."
        ),
    )
    args = parser.parse_args(argv)

    if not args.asserts:
        print("no --assert-delta given; nothing to do", file=sys.stderr)
        return 0

    manifest_path = Path(args.manifest)
    deltas_path = Path(args.deltas)

    claims: dict[str, Any] | None = None
    if args.draft_claims:
        try:
            claims = load_draft_claims(Path(args.draft_claims))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    results = run_assertions(manifest_path, deltas_path, args.asserts, claims)

    for r in results:
        bound_tag = ""
        if claims is not None:
            bound_tag = (
                " impact_bound=yes" if r.get("impact_bound") else " impact_bound=no"
            )
        print(
            f"{r['status']:13s} selector={r['selector']} "
            f"op={r['op']} amount={r['amount']} "
            f"observed={r['observed_delta']} "
            f"reason={r['reason']}{bound_tag}"
        )

    exit_code = 0
    if args.fail_on_fail and any(r["status"] == "FAIL" for r in results):
        exit_code = 1

    # Codex capv3-iter1 T2 gate: when --draft-claims was supplied, require at
    # least one PASS that is also impact-bound to the claimed victim / attacker
    # / protocol. This is independent of --fail-on-fail; a replay whose only
    # PASS was "unrelated_addr gains Y" MUST NOT be treated as proof of
    # "attacker drained X from victim".
    if claims is not None:
        impact_bound_pass = any(
            r.get("status") == "PASS" and r.get("impact_bound") for r in results
        )
        if not impact_bound_pass:
            print(
                "error: assertion-not-impact-bound — no PASS assertion references "
                "the draft's claimed victim/attacker/protocol actors "
                f"({sorted(role for role in IMPACT_ACTOR_ROLES if role in claims)})",
                file=sys.stderr,
            )
            exit_code = exit_code or 3
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
