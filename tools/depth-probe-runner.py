#!/usr/bin/env python3
"""depth-probe-runner.py - Cheap-LLM negative-space probe step for R81 audit-depth.

Consumes <ws>/.auditooor/guard_probe_packets.jsonl (compact packets produced by
guard-context-extract.py) and emits one probe record per guard into a probes-dir,
with one *.jsonl file per batch.  depth-probe-ingest.py then reads the probes-dir
via --probes-dir to produce negative_space_gaps.jsonl.

The probe never re-reads source files.  Each packet is already a self-contained
~0.5-1.5 K-token snippet: guard line, enclosing-function window, invariant hint,
impl header, referenced constants.  Token cost is ~100x cheaper than per-guard
source reads.

Probe record shape emitted (one JSON object per line, per guard):
  {
    "guard_id":              str,   # from packet
    "file_line":             str,   # from packet
    "code_excerpt":          str,   # guard_line from packet (R76-verified by ingest)
    "gap_found":             bool,  # true iff a constructible input passes the guard
                                    #   yet violates the guarded invariant
    "why_no_gap_or_exploit": str,   # per-guard explanation (must be substantive;
                                    #   cite guard_line tokens or invariant terms)
    "probe_source":          str    # "depth-probe-runner-<provider>"
  }

Batching (truncation-proof write path):
  Packets are split into batches of --batch-size (default 20).  Each batch is
  sent as a single LLM call: the system prompt contains the task; the user
  message contains the JSON-serialised packet array.  The LLM must reply with
  a JSON array of probe records.  Each batch response is written to
  <probes-dir>/batch_NNN.jsonl so depth-probe-ingest.py --probes-dir can pick
  up partial results even if a later batch times out or fails.

Dry-run mode (no --live):
  When --live is not set the tool writes stub probe records (gap_found=false,
  why_no_gap_or_exploit="dry-run stub - no LLM call made") and exits 0.  This
  lets the Makefile recipe run without a live network, producing records that
  depth-probe-ingest.py can process (the anti-stub/R76 gates will drop the stubs,
  which is the correct behaviour for a mechanical-only run - the cert will then
  show stub rows, prompting the operator to run with --live).

Usage:
  depth-probe-runner.py --workspace <ws>
                        [--packets <path>]         default: <ws>/.auditooor/guard_probe_packets.jsonl
                        [--probes-dir <dir>]        default: <ws>/.auditooor/depth_probes/
                        [--batch-size N]            default: 20
                        [--provider auto|local-cli|kimi|minimax|anthropic|deepseek-flash]
                        [--model <model-id>]
                        [--max-tokens N]            default: 4096
                        [--live]                    actually call the LLM
                        [--skip-existing]           skip batches already on disk
                        [--json]

Environment overrides:
  AUDITOOOR_DEPTH_PROBE_BATCH_SIZE   override --batch-size
  AUDITOOOR_DEPTH_PROBE_PROVIDER     override --provider
  AUDITOOOR_DEPTH_PROBE_MODEL        override --model
  AUDITOOOR_DEPTH_PROBE_TIMEOUT_S    per-batch dispatcher timeout (default 180)
  AUDITOOOR_LOCAL_AGENT=codex|claude  backend selection for --provider local-cli
  AUDITOOOR_LLM_NETWORK_CONSENT=1    required for --live (or ADVERSARIAL_LIVE_CONSENT=1)

Exit codes:
  0  all batches completed (or dry-run)
  1  one or more batches failed (partial output written; re-run with --skip-existing)
  2  usage / setup error
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCHEMA = "auditooor.depth_probe_runner.v1"

# K3-deadend-injection: reuse the multi-store KDE file_line matcher from
# tools/lib/prior_lane_scan.py rather than reimplementing it here. Import is
# best-effort: if the lib is unavailable the runner behaves exactly as before
# (no injection, no drop) - completeness-safe.
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from lib import prior_lane_scan as _prior_lane_scan  # type: ignore
except Exception:  # noqa: BLE001 - any import failure -> disable KDE features
    _prior_lane_scan = None

_DEFAULT_BATCH_SIZE = int(os.environ.get("AUDITOOOR_DEPTH_PROBE_BATCH_SIZE", "20"))

_SYSTEM_PROMPT = """\
You are a smart-contract / systems security reviewer performing a
"negative-space" gap analysis on a set of code guards.

For EACH guard packet in the user message you must decide:
  gap_found=true  iff you can construct a concrete input that passes the guard
                  (does NOT trigger the revert / assertion) YET violates the
                  invariant the guard is meant to protect.
  gap_found=false otherwise.

Rules:
1. Only use information in the packet (guard_line, function_context,
   invariant_hint, impl_header, referenced_const_defs).  Do NOT hallucinate
   missing source.
2. Your why_no_gap_or_exploit explanation MUST be substantive:
   - Cite at least one specific identifier, operator, or constant from the
     guard_line or function_context (backtick-quoted) or reference invariant_hint.
   - Generic sentences like "every input passes the guard" are NOT acceptable.
3. code_excerpt MUST be the guard_line field verbatim from the packet.
4. If you cannot determine the invariant from the packet alone, state that and
   set gap_found=false with a reason explaining the context gap.

Output format: a JSON array, one object per guard, in the SAME ORDER as the
input.  Each object must have EXACTLY these keys:
  guard_id, file_line, code_excerpt, gap_found, why_no_gap_or_exploit, probe_source

probe_source must be the literal string given in the OUTPUT section of this
message; when no OUTPUT section overrides it, use "depth-probe-runner". (The
agent-dispatch batch appends an OUTPUT block that sets it to
"depth-probe-agent-claude" - that per-batch value is authoritative.)

Emit ONLY the JSON array, no markdown fences, no prose outside the array.\
"""

_DRY_RUN_STUB_REASON = (
    "dry-run stub - no LLM call made; re-run with --live to get real probe verdicts"
)


# ---------------------------------------------------------------------------
# Packet-shape normalization (FIX #P1-asym wiring, 2026-06-07).
#
# This runner consumes TWO packet shapes that both flow through the same
# extract -> probe -> ingest pipeline:
#
#   (A) GUARD packets (guard-context-extract.py, schema
#       auditooor.guard_probe_packet.v1): top-level keys guard_id + guard_line +
#       file_line. The probe asks "can an input pass this guard yet violate its
#       invariant?".
#
#   (B) ASYMMETRY packets (asymmetry-context-extract.py, schema
#       auditooor.asymmetry_probe_packet.v1): top-level keys asym_id +
#       candidate_gap_id + side_a{file_line,guard_line,context} +
#       side_b{...} + missing_on_a/missing_on_b + shared_invariant. The probe
#       asks "does the side that is MISSING a guard its sibling has admit an
#       input the sibling rejects?".
#
# Both shapes are projected to a uniform probe-id + code_excerpt + file_line so
# the downstream ingest (R76 grep on code_excerpt) and the cert (disposition
# keyed by asym_id/guard_id) work unchanged. For an asymmetry packet the
# load-bearing side is the one MISSING a guard (missing_on_b -> side_b is the
# under-guarded path; missing_on_a -> side_a). We anchor code_excerpt / file_line
# to that under-guarded side so R76 verifies real source and the cert disposes
# the right candidate_gap_id.
# ---------------------------------------------------------------------------
def _is_asymmetry_packet(pkt: dict) -> bool:
    if str(pkt.get("schema") or "").startswith("auditooor.asymmetry_probe_packet"):
        return True
    return bool(pkt.get("asym_id")) or (
        isinstance(pkt.get("side_a"), dict) and isinstance(pkt.get("side_b"), dict)
    )


def _asym_under_guarded_side(pkt: dict) -> dict:
    """Return the side that is MISSING a guard its sibling has (the candidate
    under-guarded path). Prefer the side named by missing_on_*; fall back to
    side_b then side_a."""
    side_a = pkt.get("side_a") if isinstance(pkt.get("side_a"), dict) else {}
    side_b = pkt.get("side_b") if isinstance(pkt.get("side_b"), dict) else {}
    # missing_on_b -> side_b lacks a guard that side_a enforces -> side_b is
    # the under-guarded candidate. Symmetric for missing_on_a.
    if pkt.get("missing_on_b"):
        return side_b or side_a
    if pkt.get("missing_on_a"):
        return side_a or side_b
    return side_b or side_a


def _packet_view(pkt: dict, idx: int) -> dict:
    """Project either packet shape to a uniform {probe_id, code_excerpt,
    file_line} the runner emits and the ingest/cert consume."""
    if _is_asymmetry_packet(pkt):
        pid = pkt.get("asym_id") or pkt.get("candidate_gap_id") or f"ASYM-unknown-{idx}"
        side = _asym_under_guarded_side(pkt)
        return {
            "probe_id": pid,
            "code_excerpt": str(side.get("guard_line") or ""),
            "file_line": str(side.get("file_line") or ""),
            "is_asymmetry": True,
        }
    pid = pkt.get("guard_id") or f"NS-unknown-{idx}"
    return {
        "probe_id": pid,
        "code_excerpt": str(pkt.get("guard_line") or ""),
        "file_line": str(pkt.get("file_line") or ""),
        "is_asymmetry": False,
    }


def _prompt_packet(pkt: dict, idx: int) -> dict:
    """Flatten a packet into a guard-like view the LLM reasons over. Asymmetry
    packets keep both sides + the missing-guard delta so the model can decide
    whether the under-guarded side admits an input its sibling rejects, but the
    keys the model must echo (guard_id, file_line, code_excerpt) are normalized
    so _parse_response can re-key the response uniformly."""
    view = _packet_view(pkt, idx)
    if not view["is_asymmetry"]:
        return pkt  # guard packets already carry guard_id/guard_line/file_line
    return {
        "guard_id": view["probe_id"],
        "file_line": view["file_line"],
        "guard_line": view["code_excerpt"],
        "kind": "sibling-asymmetry",
        "pair": pkt.get("pair"),
        "pair_kind": pkt.get("pair_kind"),
        "shared_invariant": pkt.get("shared_invariant"),
        "missing_on_under_guarded_side": (
            pkt.get("missing_on_b") if pkt.get("missing_on_b") else pkt.get("missing_on_a")
        ),
        "under_guarded_side": _asym_under_guarded_side(pkt),
        "sibling_side": (
            pkt.get("side_a") if pkt.get("missing_on_b") else pkt.get("side_b")
        ),
    }


def _tool_dir() -> Path:
    return Path(__file__).resolve().parent


def _llm_dispatch_path() -> Path:
    return _tool_dir() / "llm-dispatch.py"


def _build_dispatch_command(
    prompt_path: Path,
    *,
    provider: str,
    max_tokens: int,
    timeout_s: float = 180.0,
    workspace: Path,
    model: str | None = None,
) -> list[str]:
    """Build the canonical llm-dispatch invocation for a live probe.

    Provider and backend resolution intentionally remain owned by
    ``llm-dispatch.py``. In particular, ``local-cli`` is not expanded here
    into a Codex command, so the same routing and availability checks apply to
    every depth-probe caller.
    """
    cmd = [
        sys.executable, str(_llm_dispatch_path()),
        "--prompt-file", str(prompt_path),
        "--provider", provider,
        "--max-tokens", str(max_tokens),
        "--timeout", str(timeout_s),
        "--audit-dir", str(workspace / "agent_outputs"),
        "--operator-live-network-consent",
    ]
    if model:
        cmd += ["--model", model]
    return cmd


def _call_llm(
    user_message: str,
    *,
    provider: str,
    model: str | None,
    max_tokens: int,
    timeout_s: float,
    workspace: Path,
) -> str:
    """Shell out to llm-dispatch.py; return the response text."""
    dispatch = _llm_dispatch_path()
    if not dispatch.is_file():
        raise FileNotFoundError(f"llm-dispatch.py not found at {dispatch}")

    # llm-dispatch.py reads a single --prompt-file.  We prepend the system
    # prompt with a clear delimiter so the model sees the task instructions
    # before the packet array.
    with tempfile.NamedTemporaryFile(
        "w", suffix=".txt", prefix="depth_probe_prompt_",
        delete=False, encoding="utf-8",
    ) as pf:
        pf.write(_SYSTEM_PROMPT)
        pf.write("\n\n--- GUARD PACKETS ---\n\n")
        pf.write(user_message)
        prompt_path = Path(pf.name)

    cmd = _build_dispatch_command(
        prompt_path,
        provider=provider,
        model=model,
        max_tokens=max_tokens,
        timeout_s=timeout_s,
        workspace=workspace,
    )

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=max(180.0, timeout_s + 30.0)
        )
    finally:
        try:
            prompt_path.unlink()
        except OSError:
            pass

    if proc.returncode != 0:
        raise RuntimeError(
            f"llm-dispatch.py rc={proc.returncode}:\n{proc.stderr[:600]}"
        )
    return proc.stdout


def _live_provider_reachable(
    provider: str, workspace: Path, timeout_s: float = 90.0
) -> tuple[bool, str]:
    """Cheap preflight: is a headless LLM provider actually usable for --live?

    Returns (reachable, detail). When no provider has credentials (local-cli
    `no-api-key`) or a paid API rejects (`http-402`/`cannot-run`), --live would
    fail EVERY batch and write empty sentinels, permanently pinning the depth
    cert at depth-pending. Detecting this lets run() fall back to emitting agent
    batches for orchestrator (Agent-tool) dispatch - the documented no-headless
    path - instead of silently producing all-failed batches.
    """
    dispatch = _llm_dispatch_path()
    if not dispatch.is_file():
        return False, f"llm-dispatch.py not found at {dispatch}"
    with tempfile.NamedTemporaryFile(
        "w", suffix=".txt", prefix="depth_probe_preflight_",
        delete=False, encoding="utf-8",
    ) as pf:
        pf.write("preflight")
        prompt_path = Path(pf.name)
    cmd = _build_dispatch_command(
        prompt_path,
        provider=provider,
        max_tokens=1,
        timeout_s=timeout_s,
        workspace=workspace,
    )
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, f"preflight error: {exc}"
    finally:
        try:
            prompt_path.unlink()
        except OSError:
            pass
    if proc.returncode == 0:
        return True, "ok"
    blob = (proc.stderr or "") + (proc.stdout or "")
    return False, blob.strip()[:300]


def _parse_response(text: str, packets: list[dict]) -> list[dict]:
    """Extract the JSON array from the LLM response; fall back per-guard."""
    import re
    text = text.strip()
    # Strip optional markdown code fence
    if text.startswith("```"):
        lines = text.splitlines()
        inner: list[str] = []
        in_block = False
        for ln in lines:
            if ln.startswith("```") and not in_block:
                in_block = True
                continue
            if ln.startswith("```") and in_block:
                break
            if in_block:
                inner.append(ln)
        text = "\n".join(inner).strip()

    parsed: list[dict] = []
    try:
        obj = json.loads(text)
        parsed = obj if isinstance(obj, list) else []
    except json.JSONDecodeError:
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(0))
                parsed = obj if isinstance(obj, list) else []
            except json.JSONDecodeError:
                pass

    by_id = {r.get("guard_id"): r for r in parsed if isinstance(r, dict)}
    result = []
    for i, pkt in enumerate(packets):
        # Uniform probe-id + excerpt + file_line across BOTH packet shapes:
        # guard packets key on guard_id/guard_line; asymmetry packets key on
        # asym_id and anchor the excerpt to the under-guarded side. _packet_view
        # normalizes both so the response is re-keyed correctly and the emitted
        # record's guard_id == the cert's candidate_gap_id (asym_id) for
        # asymmetry packets.
        view = _packet_view(pkt, i)
        gid = view["probe_id"]
        rec = by_id.get(gid)
        if rec is None and i < len(parsed) and isinstance(parsed[i], dict):
            rec = parsed[i]
        if rec is None:
            rec = {
                "guard_id": gid,
                "file_line": view["file_line"],
                "code_excerpt": view["code_excerpt"],
                "gap_found": False,
                "why_no_gap_or_exploit": (
                    "response-parse-failure: LLM did not return a record for this guard"
                ),
                "probe_source": "depth-probe-runner-parse-fallback",
            }
        else:
            if not rec.get("code_excerpt"):
                rec["code_excerpt"] = view["code_excerpt"]
            rec.setdefault("probe_source", "depth-probe-runner")
            rec["guard_id"] = gid
            if not rec.get("file_line"):
                rec["file_line"] = view["file_line"]
        result.append(rec)
    return result


def _dry_run_batch(packets: list[dict], provider: str) -> list[dict]:
    out = []
    for i, p in enumerate(packets):
        view = _packet_view(p, i)
        out.append({
            "guard_id": view["probe_id"],
            "file_line": view["file_line"],
            "code_excerpt": view["code_excerpt"],
            "gap_found": False,
            "why_no_gap_or_exploit": _DRY_RUN_STUB_REASON,
            "probe_source": f"depth-probe-runner-dry-run-{provider}",
        })
    return out


# ---------------------------------------------------------------------------
# K3-deadend-injection: KNOWN-DEAD-END lookup + brief block + pre-emit filter.
#
# After the R76 rule and before the guard packets, the batch .md writer injects
# a "PRIOR DEAD-ENDS" block for the batch's file_lines so the dispatched agent
# does not re-derive a site already drilled to a NEGATIVE verdict. A pre-emit
# filter additionally DROPS a guard whose file_line already has a dead-end row
# at the current pin (no point probing a site we already killed).
#
# Completeness-safe: no prior_lane_scan lib OR no KDE store -> empty match set
# -> no injection, no drop (behaves exactly as today).
# ---------------------------------------------------------------------------
def _resolve_target_pin(workspace: Path) -> str:
    """Best-effort git HEAD of the workspace; '' on any failure (keep-all)."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(workspace), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=6,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return ""


def _kde_dead_ends_for(workspace: Path, file_lines, target_pin: str) -> list[dict]:
    """Return coalesced KDE rows whose file_line matches one of ``file_lines`` at
    ``target_pin``. Empty list when the lib is missing / store absent / no match."""
    if _prior_lane_scan is None:
        return []
    fls = [fl for fl in (file_lines or []) if fl]
    if not fls:
        return []
    try:
        return _prior_lane_scan.scan_file_line_dead_ends(
            workspace, fls, target_pin=target_pin, warnings=[],
        )
    except Exception:  # noqa: BLE001 - any failure -> keep-all, no drop
        return []


def _render_dead_end_block(dead_ends: list[dict]) -> str:
    """Markdown block listing {file_line, drop_class, reason} for a batch.
    Empty string when there are no dead-ends (nothing injected)."""
    if not dead_ends:
        return ""
    out = [
        "--- PRIOR DEAD-ENDS (do not re-derive; cite dead_end_id if you concur) ---",
        "",
        "These exact code sites were already investigated to a NEGATIVE / DROP "
        "verdict at this pin. Do NOT re-derive them; if a guard below sits at one "
        "of these sites, concur and cite the dead_end_id rather than re-probing.",
        "",
    ]
    for i, de in enumerate(dead_ends, 1):
        fl = str(de.get("file_line") or "(no file_line)")[:200]
        dc = str(de.get("drop_class") or "dead-end")[:80]
        did = str(de.get("dead_end_id") or "(unnamed-dead-end)")[:120]
        reason = str(de.get("reason") or "")[:300]
        out.append(f"{i}. `{fl}` - {dc} (dead_end_id: {did})")
        if reason:
            out.append(f"   reason: {reason}")
    out.append("")
    return "\n".join(out)


def _filter_dead_end_packets(batch: list[dict], dead_ends: list[dict]):
    """Split ``batch`` into (kept, dropped). A packet is DROPPED iff its
    file_line matches a dead-end row's file_line (same path AND, when both carry
    a line, same line). Completeness-safe: no dead_ends -> nothing dropped."""
    if not dead_ends or _prior_lane_scan is None:
        return batch, []
    norm = _prior_lane_scan._normalize_file_line
    de_sites = []
    for de in dead_ends:
        de_sites.append((str(de.get("norm_path") or ""), de.get("line"),
                         str(de.get("dead_end_id") or "")))
    kept: list[dict] = []
    dropped: list[dict] = []
    for i, pkt in enumerate(batch):
        view = _packet_view(pkt, i)
        ppath, pline = norm(view["file_line"])
        hit_id = None
        if ppath:
            for dpath, dline, did in de_sites:
                if dpath != ppath:
                    continue
                if dline is not None and pline is not None:
                    if dline == pline:
                        hit_id = did
                        break
                else:
                    hit_id = did
                    break
        if hit_id is not None:
            pkt = dict(pkt)
            pkt["_dropped_dead_end_id"] = hit_id
            dropped.append(pkt)
        else:
            kept.append(pkt)
    return kept, dropped


def run(
    workspace: Path,
    packets_path: Path,
    probes_dir: Path,
    *,
    batch_size: int = _DEFAULT_BATCH_SIZE,
    provider: str = "auto",
    model: str | None = None,
    max_tokens: int = 4096,
    timeout_s: float = 180.0,
    live: bool = False,
    skip_existing: bool = False,
    verbose: bool = False,
    emit_agent_batches: bool = False,
) -> dict:
    probes_dir.mkdir(parents=True, exist_ok=True)
    # emit-agent-batches: when no headless LLM provider is reachable (codex/kimi/claude
    # CLI all 401 in this environment), the canonical depth-probe step cannot call an
    # external API. Instead emit one Agent-ready prompt per batch into <probes-dir>/
    # _agent_plan/ for the orchestrator (Claude, via the Agent tool) to dispatch - the
    # same pattern the hunt step uses via haiku-fanout-dispatcher plan. Each dispatched
    # agent reads real source (R76) and writes batch_NNN.jsonl, which depth-probe-ingest
    # then consumes. This makes "audit per README" run end-to-end on the working path.
    plan_dir = probes_dir / "_agent_plan"
    if emit_agent_batches:
        plan_dir.mkdir(parents=True, exist_ok=True)

    packets: list[dict] = []
    for ln in packets_path.read_text(encoding="utf-8", errors="replace").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            packets.append(json.loads(ln))
        except json.JSONDecodeError:
            continue

    if not packets:
        return {
            "schema": SCHEMA,
            "workspace": str(workspace),
            "packets_read": 0,
            "batches_total": 0,
            "batches_ok": 0,
            "batches_failed": 0,
            "probes_emitted": 0,
            "probes_dir": str(probes_dir),
            "verdict": "no-packets",
        }

    batches: list[list[dict]] = []
    for start in range(0, len(packets), batch_size):
        batches.append(packets[start : start + batch_size])

    # Packet-set-signature invalidation: --skip-existing reuses batch_NNN.jsonl by
    # INDEX, which is only valid if the packet set is unchanged. When the candidate
    # set changes (e.g. the fork-scope keystone re-emits a smaller scoped manifest ->
    # guard-context-extract regenerates fewer packets), the old batch files now
    # correspond to DIFFERENT/dropped units and silently contaminate the cert with
    # stale (often unscoped) probes. Stamp a signature of (packets-content,
    # batch-size); if the probe dir was built under a different signature, CLEAR the
    # stale batch_*.jsonl so they are regenerated for the current set.
    if skip_existing and probes_dir.is_dir():
        import hashlib as _hl
        try:
            _sig = _hl.sha256(
                (packets_path.read_text(encoding="utf-8", errors="replace")
                 + f"\n#batch_size={batch_size}").encode("utf-8")
            ).hexdigest()
        except OSError:
            _sig = ""
        _sig_path = probes_dir / ".packets_signature"
        _prev = ""
        if _sig_path.is_file():
            try:
                _prev = _sig_path.read_text(encoding="utf-8").strip()
            except OSError:
                _prev = ""
        if _sig and _prev and _prev != _sig:
            _stale = sorted(probes_dir.glob("batch_*.jsonl"))
            for _b in _stale:
                try:
                    _b.unlink()
                except OSError:
                    pass
            print(
                f"[depth-probe-runner] candidate-set CHANGED (packet signature "
                f"differs); cleared {len(_stale)} stale batch file(s) so they are "
                f"regenerated for the current scoped set",
                file=sys.stderr,
            )
        if _sig:
            try:
                probes_dir.mkdir(parents=True, exist_ok=True)
                _sig_path.write_text(_sig, encoding="utf-8")
            except OSError:
                pass

    eff_provider = (
        os.environ.get("AUDITOOOR_DEPTH_PROBE_PROVIDER") or provider or "auto"
    )
    timeout_s = float(os.environ.get("AUDITOOOR_DEPTH_PROBE_TIMEOUT_S", timeout_s))
    if timeout_s <= 0:
        raise ValueError("depth probe timeout must be positive")
    eff_model = os.environ.get("AUDITOOOR_DEPTH_PROBE_MODEL") or model

    # No-headless-provider fallback: if --live was requested but no provider is
    # reachable (no API key / paid-API rejected), switch to emitting agent batches
    # for orchestrator Agent-tool dispatch rather than failing every batch and
    # pinning the cert at depth-pending. Opt out with
    # AUDITOOOR_DEPTH_PROBE_NO_AGENT_FALLBACK=1.
    live_fallback_reason = None
    # An explicitly requested local-cli backend is a hard requirement. If its
    # Codex/Claude CLI is unavailable, preserve the failed live result instead
    # of converting it into an agent plan that could be mistaken for execution.
    explicit_local_cli = eff_provider == "local-cli"
    if live and not emit_agent_batches and not explicit_local_cli and \
            os.environ.get("AUDITOOOR_DEPTH_PROBE_NO_AGENT_FALLBACK") != "1":
        reachable, detail = _live_provider_reachable(
            eff_provider, workspace, timeout_s=timeout_s
        )
        if not reachable:
            live_fallback_reason = detail
            emit_agent_batches = True
            live = False
            plan_dir.mkdir(parents=True, exist_ok=True)
            print(
                "[depth-probe-runner] --live requested but no headless provider "
                f"reachable ({detail[:160]}); falling back to --emit-agent-batches "
                "for orchestrator Agent dispatch",
                file=sys.stderr,
            )

    ok_count = 0
    fail_count = 0
    total_emitted = 0
    # K3-deadend-injection: resolve the workspace pin once for KDE file_line
    # matching (completeness-safe '' on failure -> keep-all in _pin_matches).
    target_pin = _resolve_target_pin(workspace)
    dropped_total = 0

    for bi, batch in enumerate(batches):
        out_path = probes_dir / f"batch_{bi:03d}.jsonl"
        if skip_existing and out_path.is_file() and out_path.stat().st_size > 0:
            existing_text = out_path.read_text(encoding="utf-8", errors="replace")
            existing_lines = [ln for ln in existing_text.splitlines() if ln.strip()]
            existing = len(existing_lines)
            # Content-aware skip: a batch on disk as DRY-RUN STUBS must NOT be
            # skipped when we are now running --live, or a partial dry-run from an
            # earlier pass permanently poisons the live cert (every stub fails the
            # anti-stub genuineness gate -> genuine=0 -> verdict stays depth-pending).
            # Only skip a batch that is already in the requested fidelity: under
            # --live, skip iff NO row is a dry-run stub; under dry-run, always skip.
            # "want real adjudication" = either a direct live run OR an emit-agent
            # -batches run (incl. the no-provider fallback that flipped live->False).
            # In both cases a dry-run stub on disk must NOT short-circuit the slot.
            want_real = live or emit_agent_batches
            stale_dry_run = False
            if want_real:
                for ln in existing_lines:
                    try:
                        if "dry-run" in (json.loads(ln).get("probe_source") or ""):
                            stale_dry_run = True
                            break
                    except ValueError:
                        continue
            if not stale_dry_run:
                if verbose:
                    print(
                        f"[depth-probe-runner] batch {bi} already on disk "
                        f"({existing} rows); skipping",
                        file=sys.stderr,
                    )
                ok_count += 1
                total_emitted += existing
                continue
            if verbose:
                print(
                    f"[depth-probe-runner] batch {bi} on disk is dry-run stubs "
                    f"({existing} rows) but --live requested; regenerating live",
                    file=sys.stderr,
                )

        # K3-deadend-injection: resolve KDE rows for THIS batch's file_lines,
        # then (a) DROP any guard whose file_line is already a pinned dead-end
        # and (b) inject a PRIOR DEAD-ENDS block into the agent prompt for the
        # surviving guards. Completeness-safe: no store / no match -> batch is
        # unchanged and no block injected.
        batch_file_lines = [_packet_view(p, i)["file_line"]
                            for i, p in enumerate(batch)]
        batch_dead_ends = _kde_dead_ends_for(workspace, batch_file_lines, target_pin)
        batch, batch_dropped = _filter_dead_end_packets(batch, batch_dead_ends)
        if batch_dropped:
            dropped_total += len(batch_dropped)
            if verbose:
                print(
                    f"[depth-probe-runner] batch {bi} dropped "
                    f"{len(batch_dropped)} guard(s) already at a pinned dead-end",
                    file=sys.stderr,
                )
        dead_end_block = _render_dead_end_block(batch_dead_ends)

        if not batch:
            # Every guard in this batch was a pinned dead-end: emit an empty
            # sentinel so the slot is visible (no probing needed) and advance.
            out_path.touch()
            ok_count += 1
            continue

        if verbose:
            print(
                f"[depth-probe-runner] batch {bi}/{len(batches)-1} "
                f"({len(batch)} guards) ...",
                file=sys.stderr,
            )

        try:
            if emit_agent_batches:
                prompt_batch = [_prompt_packet(p, i) for i, p in enumerate(batch)]
                bp = plan_dir / f"batch_{bi:03d}.md"
                bp.write_text(
                    _SYSTEM_PROMPT
                    + "\n\n--- R76 HARD RULE ---\n"
                    + "For EACH guard below, open the REAL source file at its file_line and READ "
                    + "the surrounding code before judging. Cite ONLY lines you actually read; "
                    + "file_line MUST be \"path:N\" with the real integer line number.\n\n"
                    + ("\n" + dead_end_block + "\n" if dead_end_block else "")
                    + "--- GUARD PACKETS (" + str(len(batch)) + ") ---\n\n"
                    + json.dumps(prompt_batch, indent=2)
                    + "\n\n--- OUTPUT ---\n"
                    + "Write a JSON array (one object per line) to EXACTLY this path:\n  "
                    + str(out_path) + "\n"
                    + "Each object keys EXACTLY: guard_id, file_line, code_excerpt, gap_found "
                    + "(bool), why_no_gap_or_exploit (substantive: cite the defense that closes "
                    + "it OR the concrete bypass), probe_source=\"depth-probe-agent-claude\".\n",
                    encoding="utf-8",
                )
                ok_count += 1
                continue
            if live:
                prompt_batch = [_prompt_packet(p, i) for i, p in enumerate(batch)]
                user_msg = json.dumps(prompt_batch, indent=2)
                response_text = _call_llm(
                    user_msg,
                    provider=eff_provider,
                    model=eff_model,
                    max_tokens=max_tokens,
                    timeout_s=timeout_s,
                    workspace=workspace,
                )
                records = _parse_response(response_text, batch)
            else:
                records = _dry_run_batch(batch, eff_provider)

            with out_path.open("w", encoding="utf-8") as fh:
                for rec in records:
                    fh.write(json.dumps(rec) + "\n")
            ok_count += 1
            total_emitted += len(records)

        except Exception as exc:  # noqa: BLE001
            print(
                f"[depth-probe-runner] batch {bi} FAILED: {exc}",
                file=sys.stderr,
            )
            fail_count += 1
            out_path.touch()  # empty sentinel so the slot is visible

    if emit_agent_batches:
        verdict = "agent-batches-emitted"
    elif not live:
        verdict = "dry-run-stubs"
    else:
        verdict = (
            "all-batches-ok"
            if fail_count == 0
            else ("all-batches-failed" if ok_count == 0 else "partial")
        )

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "packets_read": len(packets),
        "batches_total": len(batches),
        "batches_ok": ok_count,
        "batches_failed": fail_count,
        "probes_emitted": total_emitted,
        "probes_dir": str(probes_dir),
        "agent_plan_dir": str(probes_dir / "_agent_plan") if emit_agent_batches else None,
        "verdict": verdict,
        "live_fallback_to_agent_batches": live_fallback_reason,
        "dead_ends_dropped": dropped_total,
        "target_pin": target_pin,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--workspace", required=True, type=Path)
    ap.add_argument(
        "--packets",
        type=Path,
        default=None,
        help="guard_probe_packets.jsonl path; "
        "default: <ws>/.auditooor/guard_probe_packets.jsonl",
    )
    ap.add_argument(
        "--probes-dir",
        type=Path,
        default=None,
        help="output dir for per-batch *.jsonl files; "
        "default: <ws>/.auditooor/depth_probes/",
    )
    ap.add_argument(
        "--batch-size",
        type=int,
        default=_DEFAULT_BATCH_SIZE,
        help=f"guards per LLM call (default {_DEFAULT_BATCH_SIZE}; "
        "env AUDITOOOR_DEPTH_PROBE_BATCH_SIZE)",
    )
    ap.add_argument(
        "--provider",
        default=os.environ.get("AUDITOOOR_DEPTH_PROBE_PROVIDER", "auto"),
        help="LLM provider: auto|local-cli|kimi|minimax|anthropic|deepseek-flash "
             "(default auto); local-cli uses llm-dispatch backend routing",
    )
    ap.add_argument(
        "--model",
        default=os.environ.get("AUDITOOOR_DEPTH_PROBE_MODEL"),
        help="model ID override passed to llm-dispatch.py --model",
    )
    ap.add_argument(
        "--max-tokens",
        type=int,
        default=4096,
        help="max_tokens per LLM call (default 4096)",
    )
    ap.add_argument(
        "--timeout-s",
        type=float,
        default=float(os.environ.get("AUDITOOOR_DEPTH_PROBE_TIMEOUT_S", "180")),
        help="per-batch local/API dispatcher timeout in seconds (default 180)",
    )
    ap.add_argument(
        "--live",
        action="store_true",
        help="actually call the LLM via llm-dispatch.py "
        "(requires AUDITOOOR_LLM_NETWORK_CONSENT=1 or ADVERSARIAL_LIVE_CONSENT=1); "
        "without this flag the tool writes dry-run stub records",
    )
    ap.add_argument(
        "--skip-existing",
        action="store_true",
        help="skip batch_NNN.jsonl files already present in --probes-dir",
    )
    ap.add_argument(
        "--emit-agent-batches",
        action="store_true",
        help="when no headless LLM provider is reachable (codex/kimi/claude CLI all 401), "
        "emit one Agent-ready prompt per batch into <probes-dir>/_agent_plan/ for the "
        "orchestrator (Claude, via the Agent tool) to dispatch - the canonical Claude path. "
        "Each agent reads real source (R76) and writes batch_NNN.jsonl; depth-probe-ingest "
        "then consumes them.",
    )
    ap.add_argument("--json", action="store_true", help="emit JSON report to stdout")
    args = ap.parse_args(argv)

    ws = args.workspace.expanduser().resolve()
    if not ws.is_dir():
        print(f"[depth-probe-runner] ERR workspace not found: {ws}", file=sys.stderr)
        return 2

    packets_path = (
        args.packets.expanduser().resolve()
        if args.packets
        else ws / ".auditooor" / "guard_probe_packets.jsonl"
    )
    if not packets_path.is_file():
        print(
            f"[depth-probe-runner] NOTE no guard_probe_packets.jsonl at {packets_path}; "
            "nothing to probe (guard-context-extract has not run yet)",
            file=sys.stderr,
        )
        if args.json:
            print(
                json.dumps(
                    {
                        "schema": SCHEMA,
                        "verdict": "no-packets-file",
                        "packets_path": str(packets_path),
                    }
                )
            )
        return 0

    probes_dir = (
        args.probes_dir.expanduser().resolve()
        if args.probes_dir
        else ws / ".auditooor" / "depth_probes"
    )

    out = run(
        ws,
        packets_path,
        probes_dir,
        batch_size=args.batch_size,
        provider=args.provider,
        model=args.model,
        max_tokens=args.max_tokens,
        timeout_s=args.timeout_s,
        live=args.live,
        skip_existing=args.skip_existing,
        verbose=not args.json,
        emit_agent_batches=args.emit_agent_batches,
    )

    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(
            f"[depth-probe-runner] {out['verdict']}: "
            f"{out['packets_read']} packets | "
            f"{out['batches_total']} batches "
            f"({out['batches_ok']} ok / {out['batches_failed']} failed) | "
            f"{out['probes_emitted']} probe records -> {probes_dir}"
        )

    return 1 if out.get("batches_failed", 0) > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
