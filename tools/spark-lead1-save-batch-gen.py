#!/usr/bin/env python3
"""Spark LEAD 1 Critical-save mimo batch.

Targets the explicit acceptance-gate blocker: find a production receiver
path where claim is SKIPPED or DELAYED beyond sender old-refund maturity,
without manually disabling auto-claim.

Strategy: feed mimo strategic source-line slices and ask for specific
classes of bypass / delay / race / silent-failure paths.
"""
import json, pathlib

SPARK = "/Users/wolf/audits/spark"
SDK_WALLET = f"{SPARK}/external/spark/sdks/js/packages/spark-sdk/src/spark-wallet/spark-wallet.ts"
SDK_TRANSFER = f"{SPARK}/external/spark/sdks/js/packages/spark-sdk/src/services/transfer.ts"
SDK_COOP = f"{SPARK}/external/spark/sdks/js/packages/spark-sdk/src/services/coop-exit.ts"
SDK_CONN = f"{SPARK}/external/spark/sdks/js/packages/spark-sdk/src/services/connection"
SERVER_HANDLER = f"{SPARK}/external/spark/spark/so/handler/transfer_handler.go"
XHR_TRANSPORT = f"{SPARK}/external/spark/sdks/js/packages/spark-sdk/src/services/xhr-transport.ts"

OUT = "/tmp/spark_save_batch.jsonl"

# Read specific line ranges that matter
def read_lines(path, start, end):
    try:
        with open(path) as f:
            return "".join(f.readlines()[max(0,start-1):end])
    except Exception:
        return ""

# Define source slices to investigate
SLICES = []

# 1. Background stream setup + auto-claim handler
SLICES.append({
    "name": "spark_wallet_background_stream_setup",
    "context": "Background stream initialization (setupBackgroundStream calls claimTransfers on connect at line 783; event auto-claims at 548-551)",
    "content": read_lines(SDK_WALLET, 460, 600) + "\n... (snip) ...\n" + read_lines(SDK_WALLET, 770, 820),
    "focus": "Find any path where (a) setupBackgroundStream is NOT called, (b) it's called but fails silently, (c) the on-connect claimTransfers throws and is swallowed, (d) the event handler skips non-self transfers, (e) connection drops mid-stream and reconnection is delayed."
})

# 2. RN periodic claim
SLICES.append({
    "name": "spark_wallet_rn_periodic_claim",
    "context": "React Native periodic claim path (line 5986-6005)",
    "content": read_lines(SDK_WALLET, 5950, 6100) + "\n... (snip) ...\n" + read_lines(SDK_WALLET, 3300, 3400),
    "focus": "Find any path where periodic claim (a) doesn't fire when app backgrounded/locked/killed, (b) skips COOPERATIVE_EXIT under certain conditions, (c) has interval > TimeLockInterval/2, (d) is gated by RN AppState listener that fails in production"
})

# 3. claimTransfer RPC error handling
SLICES.append({
    "name": "spark_transfer_service_claim_rpc",
    "context": "Single claim_transfer RPC at services/transfer.ts:986-1028",
    "content": read_lines(SDK_TRANSFER, 950, 1100),
    "focus": "Find any path where claim_transfer (a) returns error but is retried with backoff that exceeds maturity, (b) is rate-limited by server, (c) fails with 'KEY_TWEAK_FAILED' or similar non-retryable error, (d) network timeout > maturity window"
})

# 4. Server-side claim handler
SLICES.append({
    "name": "spark_server_claim_handler",
    "context": "Server ClaimTransfer combines key tweak + refund signing + aggregation + finalization at transfer_handler.go:3505-3975",
    "content": read_lines(SERVER_HANDLER, 3490, 3700) + "\n... (snip) ...\n" + read_lines(SERVER_HANDLER, 3900, 4000),
    "focus": "Find server-side claim paths that (a) silently fail when refund-tx aggregation insufficient, (b) leave state half-committed if SO crashes mid-claim, (c) return success to client but don't actually broadcast receiver-payable refund, (d) skip key-tweak step under certain rejection paths"
})

# 5. Legacy ClaimTransferSignRefunds + DirectFromCpfpRefundTx
SLICES.append({
    "name": "spark_server_legacy_claim",
    "context": "Legacy ClaimTransferSignRefunds overwrites TreeNode.RawRefundTx/DirectFromCpfpRefundTx at transfer_handler.go:4457-4528",
    "content": read_lines(SERVER_HANDLER, 4440, 4570),
    "focus": "Find paths where (a) DirectFromCpfpRefundTx is NOT installed because flag is off, (b) raw refund is set but cpfp-direct is skipped, (c) installed refund-tx doesn't have receiver-payable timelock, (d) post-install validation rejects the refund silently"
})

# 6. Coop-exit handler
SLICES.append({
    "name": "spark_coop_exit_handler",
    "context": "JS SDK coop-exit service (the COOPERATIVE_EXIT lifecycle)",
    "content": (pathlib.Path(SDK_COOP).read_text(encoding="utf-8", errors="replace")[:8000] if pathlib.Path(SDK_COOP).exists() else ""),
    "focus": "Find any path where the receiver of a COOPERATIVE_EXIT (a) waits for sender confirmation before claiming and that wait exceeds maturity, (b) defers claim if connector-parent not yet visible, (c) checks an out-of-order condition that races sender refund maturity"
})

# 7. xhr-transport + connection retry
SLICES.append({
    "name": "spark_xhr_transport_retry",
    "context": "XHR transport layer (controls RPC retries + timeouts)",
    "content": (pathlib.Path(XHR_TRANSPORT).read_text(encoding="utf-8", errors="replace")[:6000] if pathlib.Path(XHR_TRANSPORT).exists() else ""),
    "focus": "Find paths where (a) retry backoff is exponential and exceeds TimeLockInterval (~6 blocks ~60 min), (b) retry budget is capped low so persistent server errors mean no claim ever, (c) timeout > some_threshold drops the connection silently"
})

# 8. Cross-protocol analogue mining
SLICES.append({
    "name": "cross_protocol_claim_skip_analogue",
    "context": "Compare to Lightning Network HTLC claim skip / channel-force-close races + Bitcoin sidechain Drivechain claim windows.",
    "content": """
Historical incidents to consider:
- Lightning channel force-close: counterparty must broadcast HTLC claim before refund timeout, else loses funds. Known incidents: stuck channels where claim wasn't broadcast due to LND/CLN bug.
- BLAST Lightning watchtower: missed-event causing claim skip.
- RGB watchtower: relies on receiver liveness to claim.
- Statechain (Mercury): receiver must rotate key before sender's pre-signed backup tx matures.
- Cooperative protocols where the user-side has to act in a time-bounded window or lose funds.
""",
    "focus": "Identify 5 production-realistic scenarios where Spark's receiver claim could be SKIPPED or DELAYED beyond maturity, analogous to known L2 watchtower / forwarder bugs in other protocols. Cite concrete failure modes that would happen on real production wallets in normal use (not user-disabled-auto-claim)."
})

# 9. Production-trigger conditions
SLICES.append({
    "name": "production_trigger_no_claim_conditions",
    "context": "Enumerate production conditions that result in NO receiver claim before maturity",
    "content": """
Recent runtime evidence (transcript.log + manifest.json from 20260526T084446Z run):
- No-claim/no-broadcast branch confirmed sender old refund at height 404
- Genuine lower-timelock receiver defense at height 203 (200-block difference)
- Same-timelock branch is fee/order dependent (not deterministic)

Receiver TimeLockInterval ~6 blocks/~60 min. Sender old refund matures at sender's pre-signed timelock.

JS SDK initialization paths:
- non-RN: spark-wallet.ts:471 -> setupBackgroundStream
- RN: spark-wallet.ts:468-469 -> periodic claiming
- Both fail if: app uninstalled, OS suspends process, network offline beyond retry window, server returns repeated error
""",
    "focus": "Build a TAXONOMY of 10 production-realistic conditions where receiver fails to claim before sender old-refund matures, with concrete source-line citations for each, ranked by likelihood-in-production (1=common, 5=rare). For each, identify the CRIT-1 attack path (how attacker triggers + how value transfers to attacker)."
})

# 10. Synthetic but realistic attack model: sender intentionally lags
SLICES.append({
    "name": "sender_lag_attack_model",
    "context": "Attack model: sender doesn't sign the post-coop-exit confirmation in a normal cadence, forcing receiver claim to occur slowly while sender's old refund matures.",
    "content": """
The cooperative-exit flow:
1. Sender + receiver agree to exit -> sign new lower-timelock refund (receiver-payable)
2. Receiver receives transfer in SENDER_KEY_TWEAKED state
3. Receiver wallet auto-claims via claim_transfer RPC
4. Server installs DirectFromCpfpRefundTx for receiver
5. Receiver can broadcast lower-timelock refund anytime
6. Sender's old refund matures later

If between steps 2-4 the receiver wallet is offline (app killed, OS sleep, network down), AND sender then deliberately delays/refuses any in-protocol step (e.g. doesn't push connector parent), receiver may not have a valid spendable refund tx.

If receiver is online but server has a transient error during claim (DB lock, validation rejection), and the SDK fails-silently or doesn't escalate fast enough, claim is delayed.

If receiver is online but the claim RPC succeeds at SDK level but the server returns success without actually installing the refund (legacy ClaimTransferSignRefunds path with flag-off), receiver thinks they're safe but aren't.
""",
    "focus": "Identify which of the 3 attack sub-models (offline receiver, transient server error, silent-success-no-install) is most production-likely + propose a regtest harness that proves it end-to-end. Map to Spark CRIT-1 ('Direct loss of funds' verbatim) rubric row."
})

# Build the batch
records = []
PROMPT_TEMPLATE = """You are a senior smart-contract / Lightning / sidechain security researcher analyzing the Spark cooperative-exit dispute.

Background: A LEAD 1 Critical alleging that a sender can race the receiver's claim with an old refund has been walked back to honest-concession because no production receiver path was found that SKIPS or DELAYS claim long enough for sender old refund to mature. The receiver normally auto-claims via background stream (non-RN) or periodic claim (RN), then server installs receiver-payable refund.

Your task: find ONE additional ESCAPE VECTOR that meets ALL 5 acceptance gates:
1. Attacker and receiver are separate actors
2. Receiver uses NORMAL production wallet behavior (no manual disable)
3. Receiver still fails to install receiver-payable refund bytes before sender old refund maturity
4. Sender refund confirms + creates non-self economic loss
5. Maps exactly to Spark CRIT-1 'Direct loss of funds' verbatim

Investigation slice:

  name: {name}
  context: {context}

  source/evidence:
{content}

Specific focus: {focus}

Output ONLY a JSON object:
- "escape_vector_found": "yes" | "partial" | "no"
- "vector_description": one paragraph (max 5 sentences)
- "production_realism_1_to_5": int (5=common-real-user-scenario, 1=adversarial-only)
- "source_line_anchors": list of 3-5 specific file:line citations supporting the vector
- "regtest_harness_steps": list of 5-8 step strings that would prove this end-to-end
- "matches_all_5_gates": "yes" | "no" with one-sentence reason for each gate
- "estimated_likelihood_to_save_critical_1_to_5": int
- "recommended_next_lane": short string describing what additional investigation would close this out

No prose outside JSON. No markdown fences."""

for i, slice_def in enumerate(SLICES, 1):
    if not slice_def["content"] or len(slice_def["content"]) < 50:
        continue
    task = {
        "task_id": f"spark_save_{i:02d}_{slice_def['name']}"[:80],
        "task_type": "spark_lead1_critical_save",
        "prompt": PROMPT_TEMPLATE.format(
            name=slice_def["name"],
            context=slice_def["context"],
            content=slice_def["content"][:10000],
            focus=slice_def["focus"],
        ),
        "max_input_tokens": 14000,
        "max_output_tokens": 2500,
        "verification_tier_target": "tier-3-synthetic-taxonomy-anchored",
        "meta": {
            "slice_name": slice_def["name"],
            "generator": "spark-lead1-critical-save",
            "version": "v1",
        },
    }
    records.append(task)

OUT_PATH = pathlib.Path(OUT)
OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
with open(OUT_PATH, "w") as fh:
    for r in records:
        fh.write(json.dumps(r) + "\n")
print(json.dumps({"records_emitted": len(records), "output_path": str(OUT_PATH)}))
