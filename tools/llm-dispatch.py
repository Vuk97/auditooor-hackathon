#!/usr/bin/env python3
"""llm-dispatch.py — stdlib-only Anthropic-compatible Messages API wrapper.

capability-v3 iter-v3-5 T1 (+ FIX-7B provider abstraction). Ships a thin,
hermetic, no-third-party-deps LLM caller that `tools/swarm-orchestrator.py
--dispatch` can shell out to when `SWARM_REAL_DISPATCH=1` is set in the
environment. Default orchestrator behaviour (printer stdout) is preserved
byte-for-byte.

Usage
-----
    python3 tools/llm-dispatch.py \\
        --prompt-file <path> \\
        [--model <id>] \\
        [--max-tokens N] \\
        [--timeout SECONDS] \\
        [--retry-on-429 N] \\
        [--provider {auto,kimi,minimax,mimo,anthropic}] \\
        [--input-is-truncated]

`--input-is-truncated` is a caller-supplied signal that the prompt is a
truncated diff/document. When set AND the provider resolved on a given
hop is `minimax`, dispatch prepends a one-line absence-hallucination
notice to the user message (foot-gun #13d closure, queue iter 17).
No-op for Kimi/Anthropic.

Providers (Anthropic Messages API-compatible)
---------------------------------------------
- Kimi      : env `KIMI_API_KEY`,     `KIMI_ANTHROPIC_BASE_URL`,
              `KIMI_MODEL` (default `kimi-for-coding`).
              Fallback chain (no env):
                1. `~/.kimi/credentials/kimi-code.json` (managed-Kimi CLI
                   OAuth token; override path via `AUDITOOOR_KIMI_OAUTH_FILE`)
                2. `~/.claude/settings.json` env.KIMI_API_KEY
                3. `~/.claude/settings.json` env.ANTHROPIC_AUTH_TOKEN
              Step 1 closes the HTTP 401 on managed-Kimi setups where the
              CLI binary owns auth. Steps 2-3 match the Minimax convention
              used by `tools/llm-pr-review.py`.
- MiniMax   : env `MINIMAX_API_KEY`,  `MINIMAX_ANTHROPIC_BASE_URL`,
              `MINIMAX_MODEL` (default `MiniMax-M2.7`).
              Fallback (no env): `~/.claude/settings.json`
              env.MINIMAX_API_KEY, then env.ANTHROPIC_AUTH_TOKEN.
- Anthropic : env `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN`),
              `ANTHROPIC_BASE_URL` (default `https://api.anthropic.com`),
              `ANTHROPIC_MODEL`.

The final API URL is always `<base_url>/v1/messages` (trailing slashes on
the base URL are stripped). `AUDITOOOR_LLM_PROVIDER=kimi|minimax|anthropic`
overrides the `--provider` CLI flag. `AUDITOOOR_LLM_AUTH_HEADER=bearer|
x-api-key` chooses the auth header (default `x-api-key`).

Auto mode resolution (default):
1. Try Kimi      if `KIMI_API_KEY` set.
2. Fall back to MiniMax on Kimi 5xx / 429 / transport error.
3. Fall back to Anthropic on MiniMax 5xx / 429 / transport error.

4xx (other than 429) or a malformed 200 response does NOT fall back: it is
a legitimate failure and exits 3.

Explicit `--provider <name>` with no matching key → exit 2 (`cannot-run:
no-api-key`). No fallback.

Consent boundary
----------------
Before any `urlopen` call, `llm-dispatch.py` requires one of:
  - `--operator-live-network-consent`
  - `AUDITOOOR_LLM_NETWORK_CONSENT=1`
  - `ADVERSARIAL_LIVE_CONSENT=1`
Missing consent → exit 2 with `cannot-run: no-consent` stderr JSON. This
is the hard stop — direct driver usage cannot bypass it.

Audit trail
-----------
Every invocation writes a short JSON record to
`agent_outputs/llm_dispatch_<uuid>.json` containing: timestamp, provider,
model, api_url_host, prompt file path, response length, HTTP status,
retry count, timing_ms, network_consent_source. **API keys, request
bodies, and response bodies are NEVER persisted.**

Hard rules
----------
- Stdlib only: `argparse, datetime, json, os, pathlib, re, socket,
  subprocess, sys, time, urllib.request, urllib.error, urllib.parse,
  uuid`. No `requests`, `anthropic`, `httpx`.
- No writes to `submissions/`, no shelling out to git, gh, shutil
  mutators, file removers, or anything else that mutates repo state.
  Only reads the prompt file, POSTs to the configured Messages API,
  writes one audit-trail JSON, writes response to stdout.
"""
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import os
import pathlib
import tempfile
import re  # noqa: F401  # part of the agreed stdlib surface; keep import for auditors
import shutil  # I9: kimi CLI lookup for OAuth refresh
import socket  # noqa: F401  # advertised stdlib surface; used transitively via urlopen
import subprocess  # I9: kimi CLI invocation for OAuth refresh
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


# Default base URLs (do not embed API keys here; these are public routing
# endpoints chosen per Codex provider-smoke results).
# NOTE: `api.anthropic.com` appears below strictly as the documented
# default Anthropic fallback — never hardcoded to the request path.
#
# DEEPSEEK-INTEGRATION-CORE (2026-05-26): DeepSeek Flash + Pro added.
# R36 declaration: lane-DEEPSEEK-INTEGRATION-CORE pathspec entry in
# .auditooor/agent_pathspec.json (tools/agent-pathspec-register.py).
# Both DeepSeek variants use the Anthropic-compatible endpoint
# (`https://api.deepseek.com/anthropic`) so the existing request body
# shape works without modification. Model IDs resolved via
# tools/deepseek-model-probe.py and pinned in
# reference/deepseek_model_aliases.json.
_DEFAULT_BASE_URLS = {
    "kimi": "https://api.kimi.com/coding",
    "minimax": "https://api.minimax.io/anthropic",
    "anthropic": "https://api.anthropic.com",
    "deepseek-flash": "https://api.deepseek.com/anthropic",
    "deepseek-pro": "https://api.deepseek.com/anthropic",
    # <!-- r36-rebuttal: lane claude-mimo-add-2026-05-27 registered -->
    # Xiaomi MiMo Token Plan CN endpoint (Anthropic-compatible).
    # Operator-provisioned 2026-05-27, budget-unmetered per operator.
    # Auth: Authorization: Bearer <tp-key> (forced below regardless of env).
    # NOTE: SGP endpoint returns 401 for tp- keys; CN endpoint works.
    # Verified via curl on 2026-05-27.
    "mimo": "https://token-plan-cn.xiaomimimo.com/anthropic/v1",
}
_DEFAULT_MODELS = {
    "kimi": "kimi-for-coding",
    "minimax": "MiniMax-M2.7",
    "anthropic": "claude-opus-4-5",
    "deepseek-flash": "deepseek-v4-flash",
    "deepseek-pro": "deepseek-v4-pro",
    # MiMo primary; 1M context variant: mimo-v2.5-pro[1m].
    "mimo": "mimo-v2.5-pro",
}

# DeepSeek pricing per operator table (2026-05-26). USD per 1M tokens.
# Used by the audit trail to record per-call cost estimates and by the
# budget tracker in tools/provider-capacity-report.py to compute the
# rolling $100/mo cap + $80 alert. cache_hit pricing is only realised
# when the provider returns a `cache_read_input_tokens` field; otherwise
# the full cache_miss rate is used.
_DEEPSEEK_PRICING_USD_PER_M_TOKENS = {
    "deepseek-flash": {
        "input_cache_miss": 0.14,
        "input_cache_hit": 0.0028,
        "output": 0.28,
        "context_window": 1_000_000,
        "max_output_tokens": 384_000,
        "concurrency_limit": 2500,
    },
    "deepseek-pro": {
        "input_cache_miss": 0.435,
        "input_cache_hit": 0.003625,
        "output": 0.87,
        "context_window": 200_000,
        "max_output_tokens": 64_000,
        "concurrency_limit": 500,
    },
}

# DeepSeek mock-mode: when --mock is passed OR
# AUDITOOOR_DEEPSEEK_MOCK=1 is set, dispatch skips the network call and
# emits a synthetic Anthropic-compatible response. Used by tests and by
# operator-driven smoke runs when the account has insufficient balance.
DEEPSEEK_MOCK_ENV_VAR = "AUDITOOOR_DEEPSEEK_MOCK"
# Default verification tier for advisory LLM dispatch (R37). DeepSeek
# Flash + Pro ship as tier-3 (synthetic / advisory) by default; the
# --verified-by flag stamps an upgrade attestation into the audit
# record so consumers can decide whether the output should be trusted
# as tier-2 (corroborated) or higher.
DEFAULT_VERIFICATION_TIER = "tier-3-synthetic-taxonomy-anchored"
ANTHROPIC_VERSION = "2023-06-01"
MESSAGES_PATH = "/v1/messages"
CACHE_CONTROL_EPHEMERAL = {"type": "ephemeral"}
ANTHROPIC_PROMPT_CACHING_ENV_VAR = "AUDITOOOR_ANTHROPIC_PROMPT_CACHING"

_CACHEABLE_PROMPT_MARKER_PAIRS = (
    (
        "<!-- BEGIN dispatch-agent-with-prebriefing META-1 block -->",
        "<!-- END dispatch-agent-with-prebriefing META-1 block -->",
    ),
    (
        "<!-- BEGIN agent-brief-prefetch META-1 block -->",
        "<!-- END agent-brief-prefetch META-1 block -->",
    ),
    (
        "<!-- BEGIN codified_rules_digest -->",
        "<!-- END codified_rules_digest -->",
    ),
    (
        "<!-- BEGIN vault_codified_rules_digest -->",
        "<!-- END vault_codified_rules_digest -->",
    ),
)

_CACHEABLE_PROMPT_SECTION_BOUNDARIES = (
    "\n## Section 15b",
    "\n## Section 1",
    "\n## Original prompt",
    "\n# Task",
    "\n## Task",
)

EXIT_OK = 0
EXIT_CANNOT_RUN = 2
EXIT_ERROR = 3

# V5 P0-01 (Gap 1, Gap 12): the previous 4000-token default truncates
# long-context Kimi/Minimax responses to a thinking trace + a clipped
# answer. Long-context source-mining and PR-review packets observed in
# the queue burned tokens before producing a usable response, forcing
# operators to manually pass `--max-tokens 16000` on every campaign.
# The new default is 16000 — large enough for the long-context paths
# both providers handle without manual override. Smoke tests (small
# prompts that expect a single "OK") select the lower budget by passing
# `--smoke-test` (which sets max_tokens to SMOKE_TEST_MAX_TOKENS) so the
# guardrail stays cheap for hello-world checks.
DEFAULT_MAX_TOKENS = 16000
SMOKE_TEST_MAX_TOKENS = 200

# V5 P0-01 (Gap 7): When a provider returns a content[] list that
# contains only `type:"thinking"` blocks (no usable text), retry the
# request EXACTLY ONCE with the same prompt before raising. Many of
# the observed thinking-only responses on Kimi/Minimax during long
# campaigns recovered cleanly on the second attempt; an unbounded
# retry loop, by contrast, would silently burn the token budget when
# a model is genuinely stuck. One retry is the minimum useful budget.
THINKING_ONLY_RETRY_LIMIT = 1

# Truncation notice prepended to the user message when callers pass
# `--input-is-truncated` AND the resolved provider is `minimax`. Closes
# foot-gun #13d (queue iter 17): MiniMax-M2.7 has been observed
# hallucinating "missing files" / "missing sections" when the
# diff/document handed to it was truncated by the caller (e.g.
# llm-pr-review.py truncating large diffs to a token budget). The notice
# instructs the model to flag only inconsistencies it can directly see
# rather than asserting absence. Kept narrow to MiniMax — Kimi and
# Anthropic models have not exhibited this failure mode in the
# calibration log, and prepending the notice unconditionally would
# pollute prompts they handle correctly.
MINIMAX_TRUNCATION_NOTICE = (
    "NOTE: The diff/document above is truncated. Do NOT claim missing "
    "files or sections based on absence — only flag inconsistencies you "
    "can directly observe in the visible content. This rule extends to "
    "missing-function, missing-check, missing-require, and "
    "missing-feature classes: do not claim a function/check/require/"
    "feature is missing based on its absence in the truncated content. "
    "State INDETERMINATE if you cannot see it."
)

# Opt-OUT env var that wires `tools/llm-budget-guard.py` into dispatch.
# V5-P0-03 (Gap 39 + Gap 43): the guard is now ENABLED by default.
# Operators must explicitly set `AUDITOOOR_LLM_BUDGET_GUARD=0` to disable
# it; any other value (including unset, "1", or empty string) leaves the
# guard active. The disable path emits a loud stderr warn line so the
# operator decision is visible in logs, and each dispatch's audit trail
# records `budget_guard_disabled: true` when the guard was bypassed.
#
# Rationale: forever-loops and large source-mining campaigns repeatedly
# burned token budget because the prior opt-in default left the guard
# off in practice. Codex V5 P0 wave-1 mandate is "default-safe" — the
# unsafe path requires a deliberate operator action.
BUDGET_GUARD_ENV_VAR = "AUDITOOOR_LLM_BUDGET_GUARD"
BUDGET_GUARD_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parent / "llm-budget-guard.py"
)
LLM_CALIBRATION_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parent / "llm-calibration-log.py"
)

# V5 PR 6 (campaign telemetry): when a dispatch is happening inside a
# campaign context, the wrapper sets ``AUDITOOOR_CAMPAIGN_ID`` (and
# optionally ``AUDITOOOR_CAMPAIGN_LANE`` / ``AUDITOOOR_CAMPAIGN_ROLE`` /
# ``AUDITOOOR_CAMPAIGN_WORKSPACE``) so dispatch can append a row to
# ``tools/calibration/campaign_dispatch_log.jsonl`` linking the call to
# the campaign that asked for it. The hook is best-effort: a missing
# tools/campaign-telemetry.py file or a write failure must NEVER break
# dispatch — graceful degradation, structured stderr warn.
CAMPAIGN_ID_ENV_VAR = "AUDITOOOR_CAMPAIGN_ID"
CAMPAIGN_LANE_ENV_VAR = "AUDITOOOR_CAMPAIGN_LANE"
CAMPAIGN_ROLE_ENV_VAR = "AUDITOOOR_CAMPAIGN_ROLE"
CAMPAIGN_WORKSPACE_ENV_VAR = "AUDITOOOR_CAMPAIGN_WORKSPACE"
CAMPAIGN_TELEMETRY_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parent / "campaign-telemetry.py"
)

# V5-P0-22 (Gap 42): strategic-LLM policy gate. Some prompts ask the
# model for "strategic" output (roadmap drafting, prioritization,
# architecture decisions) — work that is operator-policy territory, not
# routine review/mining. Such prompts must be opted-in explicitly via
# the `--strategic-llm-allowed` CLI flag, otherwise dispatch refuses.
#
# The detection is deliberately conservative: false-positives are
# acceptable (operator can pass the override), false-negatives are not.
# Heuristic substrings are matched case-insensitively against the prompt
# body. Keep this list short and focused on phrases that consistently
# correlate with strategic-output asks rather than every word that
# co-occurs with planning.
STRATEGIC_LLM_HEURISTICS = (
    "roadmap",
    "30-of-10",
    "30 of 10",
    "next strategic step",
    "what should we build next",
    "what should our roadmap",
    "prioritize our",
    "prioritise our",
    "what to build next",
    "long-term plan",
    "architecture decision",
    "strategic direction",
    "strategic priorities",
    # Kimi pre-review (2026-04-27) flagged false-negatives for
    # auditooor-internal "what to deprecate / decommission / sunset"
    # framings that ask for strategic prioritization without using the
    # word "roadmap" or "prioritize". Add the most concrete cases the
    # operator could phrase in a workspace packet:
    "should we deprecate",
    "should we decommission",
    "should we sunset",
    "should we build",  # "should we build X in-house" / "should we build vs buy"
    "what to deprecate",
    "what to decommission",
    "what to sunset",
    "next quarter plan",
    "north star metric",
)


def _is_budget_guard_enabled() -> bool:
    """V5-P0-03: budget guard defaults to ON.

    Off only when the env var is set to the literal string "0". Any other
    value — including unset, empty string, "1", "true", or whitespace —
    leaves the guard ENABLED. The empty-string case is a common shell
    foot-gun (`export AUDITOOOR_LLM_BUDGET_GUARD=`); we treat it as
    "operator did not deliberately disable" rather than off.
    """
    val = os.environ.get(BUDGET_GUARD_ENV_VAR)
    if val is None:
        return True
    if val.strip() == "0":
        return False
    return True


def _emit_budget_guard_disabled_warning() -> None:
    """Emit the loud stderr line documenting an operator's explicit opt-out."""
    sys.stderr.write(json.dumps({
        "warn": (
            "AUDITOOOR_LLM_BUDGET_GUARD=0 — operator explicitly disabled "
            "budget guard. Token-burn unbounded."
        )
    }) + "\n")
    sys.stderr.flush()


def _detect_strategic_prompt(prompt_text: str) -> str | None:
    """Return the matched heuristic substring if the prompt looks strategic.

    Conservative: case-insensitive substring match. Returns the first hit
    so the refusal message can cite it.
    """
    if not isinstance(prompt_text, str):
        return None
    haystack = prompt_text.lower()
    for needle in STRATEGIC_LLM_HEURISTICS:
        if needle.lower() in haystack:
            return needle
    return None


# -----------------------------------------------------------------------------
# Structured error + audit helpers
# -----------------------------------------------------------------------------

def _emit_structured_error(reason: str, **fields) -> None:
    """Print a single-line JSON error document to stderr."""
    payload = {"reason": reason}
    payload.update(fields)
    sys.stderr.write(json.dumps(payload) + "\n")
    sys.stderr.flush()


def _load_memory_context_loader():
    loader_path = pathlib.Path(__file__).resolve().parent / "memory-context-load.py"
    spec = importlib.util.spec_from_file_location("memory_context_load_for_dispatch", loader_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {loader_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _hostname_from_url(url: str) -> str:
    """Extract hostname from URL; never includes auth or query params."""
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""


# R36: declaration via tools/agent-pathspec-register.py (lane-DEEPSEEK-
# INTEGRATION-CORE), entry in agent_pathspec.json.
def _write_audit_trail(
    audit_dir: pathlib.Path,
    *,
    provider: str,
    model: str,
    api_url_host: str,
    prompt_file: pathlib.Path,
    response_length: int,
    http_status: int,
    retry_count: int,
    timing_ms: int,
    outcome: str,
    budget_guard_disabled: bool = False,
    task_type: str | None = None,
    routing_status: dict | None = None,
    network_consent_source: str | None = None,
    verification_tier: str | None = None,
    verified_by: str | None = None,
    cost_estimate: dict | None = None,
    mock_mode: bool = False,
    tokens_used: int | None = None,
) -> pathlib.Path:
    """Write a short telemetry record. Never includes prompt/response bodies or keys.

    V5-P0-03: when ``budget_guard_disabled`` is True, the manifest records
    that the operator explicitly bypassed the budget guard for this
    dispatch. The field is always written (False by default) so audit
    consumers can rely on the schema.

    DEEPSEEK-INTEGRATION-CORE (2026-05-26):
    - ``verification_tier`` (R37) stamps the default tier-3 advisory tier
      onto every dispatch. Operators can pass --verified-by to record an
      upgrade attestation; the stamp is consumed by downstream
      tier-stratification tooling.
    - ``cost_estimate`` carries the per-call DeepSeek USD breakdown so
      tools/provider-capacity-report.py can compute the rolling $100/mo
      cap + $80 alert without re-parsing prompts.
    - ``mock_mode`` flips the record into ok-mocked outcomes so the
      report can filter live vs. synthetic calls.
    """
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = audit_dir / f"llm_dispatch_{uuid.uuid4().hex}.json"
    record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "provider": provider,
        "model": model,
        "api_url_host": api_url_host,
        "prompt_file": str(prompt_file),
        "response_length": response_length,
        "http_status": http_status,
        "retry_count": retry_count,
        "timing_ms": timing_ms,
        "outcome": outcome,
        "budget_guard_disabled": bool(budget_guard_disabled),
        "verification_tier": (
            verification_tier or DEFAULT_VERIFICATION_TIER
        ),
        "mock_mode": bool(mock_mode),
    }
    if network_consent_source is not None:
        record["network_consent_source"] = network_consent_source
    if task_type is not None:
        record["task_type"] = task_type
    if routing_status is not None:
        record["routing_status"] = routing_status
    if verified_by is not None and isinstance(verified_by, str) and verified_by.strip():
        record["verified_by"] = verified_by.strip()
    if cost_estimate is not None:
        record["cost_estimate"] = cost_estimate
    if tokens_used is not None:
        record["tokens_used"] = int(tokens_used)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _load_llm_calibration_module():
    """Best-effort import of the calibration ledger helper."""
    if not LLM_CALIBRATION_MODULE_PATH.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "auditooor_llm_calibration_log",
            LLM_CALIBRATION_MODULE_PATH,
        )
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception as e:
        sys.stderr.write(json.dumps({
            "warn": f"llm-calibration-routing-unavailable: {e}"
        }) + "\n")
        sys.stderr.flush()
        return None


def _calibration_provider(provider: str) -> str:
    """Map dispatch provider names to calibration-ledger provider names."""
    if provider == "anthropic":
        return "claude"
    return provider


def _routing_decision(provider: str, task_type: str | None) -> dict | None:
    """Return provider × task routing status, failing closed on no helper."""
    if not task_type:
        return None
    calibration = _load_llm_calibration_module()
    calibration_provider = _calibration_provider(provider)
    if calibration is None:
        return {
            "provider": calibration_provider,
            "task_type": task_type,
            "primary_allowed": False,
            "advisory_only": True,
            "reason": "calibration-helper-unavailable",
        }
    return calibration.routing_status(calibration_provider, task_type)


# -----------------------------------------------------------------------------
# Budget guard integration (default-on; AUDITOOOR_LLM_BUDGET_GUARD=0 opts out)
# -----------------------------------------------------------------------------
#
# The budget-guard library lives at `tools/llm-budget-guard.py`. The hyphen
# in the filename means we cannot `import` it directly — we use the
# `importlib.util.spec_from_file_location` pattern (the same pattern the
# library's own docstring documents). The load is lazy and best-effort:
# if the module is missing or fails to import we log a structured warning
# to stderr and proceed without gating (graceful degradation — dispatch
# must keep working even if the guard is removed/broken).

def _load_budget_guard_module():
    """Import `tools/llm-budget-guard.py` via spec_from_file_location.

    Returns the loaded module, or None if the file is missing or cannot
    be loaded. Never raises — graceful degradation for callers that opt
    into the env var on a workstation where the guard isn't installed.
    """
    if not BUDGET_GUARD_MODULE_PATH.is_file():
        sys.stderr.write(json.dumps({
            "warn": (
                "budget-guard-unavailable: "
                f"{BUDGET_GUARD_MODULE_PATH} not found"
            )
        }) + "\n")
        sys.stderr.flush()
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "llm_budget_guard", BUDGET_GUARD_MODULE_PATH
        )
        if spec is None or spec.loader is None:
            raise ImportError("spec_from_file_location returned None")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:  # broad on purpose — graceful-degrade contract
        sys.stderr.write(json.dumps({
            "warn": f"budget-guard-unavailable: {e}"
        }) + "\n")
        sys.stderr.flush()
        return None


def _maybe_make_budget_guard():
    """Construct an `LlmBudgetGuard` instance or return None.

    Used once per `main()` invocation — the guard caches the budget
    config in-memory but re-reads the on-disk log on each `may_call` /
    `record_call` so multiple processes can share the same budget. None
    is returned when the module is unavailable (graceful degradation)
    OR when construction fails (e.g. missing config file).
    """
    module = _load_budget_guard_module()
    if module is None:
        return None
    try:
        return module.LlmBudgetGuard()
    except Exception as e:  # graceful degradation on missing config etc.
        sys.stderr.write(json.dumps({
            "warn": f"budget-guard-unavailable: {e}"
        }) + "\n")
        sys.stderr.flush()
        return None


# -----------------------------------------------------------------------------
# Campaign telemetry hook (V5 PR 6)
# -----------------------------------------------------------------------------

def _load_campaign_telemetry_module():
    """Load tools/campaign-telemetry.py. Best-effort, never raises.

    The hyphenated filename means we cannot ``import`` it directly — we
    use the same ``importlib.util.spec_from_file_location`` pattern as
    the budget-guard loader. A missing module is treated as a structured
    stderr warn and graceful-degrade: dispatch still works without
    telemetry, just like it works without budget-guard.
    """
    if not CAMPAIGN_TELEMETRY_MODULE_PATH.is_file():
        sys.stderr.write(json.dumps({
            "warn": (
                "campaign-telemetry-unavailable: "
                f"{CAMPAIGN_TELEMETRY_MODULE_PATH} not found"
            )
        }) + "\n")
        sys.stderr.flush()
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "campaign_telemetry", CAMPAIGN_TELEMETRY_MODULE_PATH
        )
        if spec is None or spec.loader is None:
            raise ImportError("spec_from_file_location returned None")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:  # graceful degradation
        sys.stderr.write(json.dumps({
            "warn": f"campaign-telemetry-unavailable: {e}"
        }) + "\n")
        sys.stderr.flush()
        return None


def _maybe_record_campaign_dispatch(
    *,
    provider: str,
    model: str,
    tokens_used: int,
    outcome: str,
    audit_path: str | None,
    budget_guard_disabled: bool,
) -> None:
    """If a campaign id is set in the environment, append a row to the
    campaign-telemetry ledger linking this dispatch to the campaign.

    Best-effort: any error raises a structured ``warn`` to stderr and
    swallows so dispatch's stdout response is never blocked by a
    telemetry write failure. This mirrors the contract used for the
    audit-trail and budget-guard writes elsewhere in this file.
    """
    campaign_id = os.environ.get(CAMPAIGN_ID_ENV_VAR)
    if not campaign_id:
        return
    module = _load_campaign_telemetry_module()
    if module is None:
        return
    try:
        module.record_dispatch(
            campaign_id=campaign_id,
            provider=provider,
            model=model,
            tokens_used=int(tokens_used),
            outcome=outcome,
            audit_path=audit_path,
            role=os.environ.get(CAMPAIGN_ROLE_ENV_VAR) or None,
            workspace=os.environ.get(CAMPAIGN_WORKSPACE_ENV_VAR) or None,
            lane=os.environ.get(CAMPAIGN_LANE_ENV_VAR) or None,
            budget_guard_disabled=bool(budget_guard_disabled),
        )
    except Exception as e:  # graceful degradation
        sys.stderr.write(json.dumps({
            "warn": f"campaign-telemetry-write-failed: {e}"
        }) + "\n")
        sys.stderr.flush()


# -----------------------------------------------------------------------------
# Provider resolution
# -----------------------------------------------------------------------------

def _settings_json_env() -> dict:
    """Read the `env` map from `~/.claude/settings.json`.

    Returns an empty dict when the file is missing, unreadable, malformed,
    or the `env` key is absent / not a mapping. Never raises.

    Used as a credential fallback for Kimi and MiniMax: the user's Claude
    harness stores the routed Anthropic-compat key as
    `env.ANTHROPIC_AUTH_TOKEN`, and may also store provider-specific
    `KIMI_API_KEY` / `MINIMAX_API_KEY` keys. Mirrors the pattern in
    `tools/llm-pr-review.py::_settings_minimax_token`, but generalised so
    the dispatch tool itself (the canonical wrapper) does not depend on
    its consumer to populate the env.
    """
    path = pathlib.Path.home() / ".claude" / "settings.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    env = data.get("env")
    if not isinstance(env, dict):
        return {}
    return env


# Path to the OAuth credentials file written by the managed `kimi` CLI.
# Overridable via the `AUDITOOOR_KIMI_OAUTH_FILE` env var so tests can
# point at a tempdir copy. The file is JSON with an `access_token` field
# (JWT-style). Lives outside `~/.claude/` because the kimi CLI owns it.
_KIMI_OAUTH_FILE_DEFAULT = pathlib.Path.home() / ".kimi" / "credentials" / "kimi-code.json"

# I9: refresh slack. The OAuth `access_token` lifetime is ~900s by
# default. We treat a token as "expired" when it has fewer than 60s
# remaining so a campaign that takes minutes doesn't hit the wall in
# the middle of a multi-domain run.
_KIMI_OAUTH_REFRESH_SLACK_S = 60

# I9: refresh subprocess timeout. The managed `kimi` CLI's first run
# performs a quick auth handshake; in normal conditions it's <5s.
# 30s leaves room for a slow first-byte network without blocking the
# dispatcher indefinitely.
_KIMI_OAUTH_REFRESH_TIMEOUT_S = 30


def _kimi_oauth_expires_at(path: pathlib.Path) -> float | None:
    """Return the OAuth token's `expires_at` (Unix seconds) from the
    credentials file, or None when missing/malformed.

    Used by the refresh helper to decide whether we need to invoke the
    `kimi` CLI to roll the token. Never raises; logs nothing — the
    caller decides whether the absence-of-expires_at is interesting."""
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    expires_at = data.get("expires_at")
    if isinstance(expires_at, (int, float)):
        return float(expires_at)
    return None


def _kimi_oauth_refresh_via_cli(path: pathlib.Path) -> bool:
    """Invoke the managed `kimi` CLI to refresh its OAuth token in place.

    Background: the kimi CLI auto-refreshes when invoked interactively.
    The dispatcher previously only READ the credentials file; it never
    triggered a refresh. When the token expired between dispatcher
    invocations, every API call returned HTTP 401 and the campaign
    rolled them up as 0/0 silently (foot-gun #15-class — same shape
    as the no-consent silent-zero from PR #313).

    This helper runs `kimi --print --input-format text` against a
    no-op prompt with a short timeout. The CLI's internal refresh logic
    fires on first call when `expires_at < now()`. We then re-read the
    credentials file to verify the rewrite succeeded.

    Returns True iff the refresh produced a credentials file whose new
    `expires_at` is strictly in the future. False on any failure
    (CLI missing, subprocess timeout, file unchanged, etc.). Never
    raises; emits a one-line stderr `{"warn": ...}` on failure so the
    operator sees the cause.

    Idempotent: a running CLI session that ALREADY has a fresh token
    will still write the file (with the same token), and we still
    succeed. The slack window in `_kimi_oauth_token_from_file` keeps
    us from refreshing on every call.

    Test override: when AUDITOOOR_KIMI_OAUTH_REFRESH_DISABLED=1 is
    set, this helper returns False without invoking the CLI. Tests
    use this to exercise the "refresh failed" branch deterministically."""
    if os.environ.get("AUDITOOOR_KIMI_OAUTH_REFRESH_DISABLED") == "1":
        return False
    cli = shutil.which("kimi")
    if cli is None:
        sys.stderr.write(json.dumps({
            "warn": "kimi-oauth-refresh-failed: kimi-cli-not-on-path",
        }) + "\n")
        sys.stderr.flush()
        return False
    try:
        proc = subprocess.run(
            [cli, "--print", "--input-format", "text"],
            input="noop\n",
            capture_output=True,
            text=True,
            timeout=_KIMI_OAUTH_REFRESH_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        sys.stderr.write(json.dumps({
            "warn": (
                f"kimi-oauth-refresh-failed: cli-timeout-after-"
                f"{_KIMI_OAUTH_REFRESH_TIMEOUT_S}s"
            ),
        }) + "\n")
        sys.stderr.flush()
        return False
    except OSError as e:
        sys.stderr.write(json.dumps({
            "warn": f"kimi-oauth-refresh-failed: cli-spawn-failed: {e}",
        }) + "\n")
        sys.stderr.flush()
        return False
    if proc.returncode != 0:
        # CLI may print interactive prompts to stdout even when refresh
        # succeeds; rely on the post-refresh expires_at check, not the
        # rc. But surface non-zero rc to stderr so it's visible.
        sys.stderr.write(json.dumps({
            "warn": (
                f"kimi-oauth-refresh: cli-nonzero-rc={proc.returncode} "
                "(may still have refreshed; checking credentials file)"
            ),
        }) + "\n")
        sys.stderr.flush()
    new_expires = _kimi_oauth_expires_at(path)
    if new_expires is None:
        return False
    if new_expires <= time.time():
        sys.stderr.write(json.dumps({
            "warn": (
                "kimi-oauth-refresh-failed: token-still-expired-after-"
                "cli-invocation"
            ),
        }) + "\n")
        sys.stderr.flush()
        return False
    return True


def _kimi_oauth_token_from_file() -> str | None:
    """Return the OAuth access_token from the managed `kimi` CLI's
    credentials file, or None when the file is missing / unreadable.

    Background: the `kimi` CLI binary uses an OAuth flow and writes the
    resulting access token (a short-lived JWT) to
    `~/.kimi/credentials/kimi-code.json`. Operators on managed-Kimi
    setups never set `KIMI_API_KEY` directly — they expect the token
    file to be the source of truth. Without this fallback, dispatch
    returned HTTP 401 even when a valid OAuth session was active (see
    /tmp/poly_v4_run/ campaign — Kimi=0 findings, lost the cross-check).

    Behaviour:
      - File missing / unreadable: return None silently. Caller falls
        through to the next link in the chain (settings.json → skip).
      - File present but malformed JSON or missing `access_token`: emit
        a one-line stderr `{"warn": "kimi-credentials-malformed: ..."}`
        and return None so the provider is skipped (not silently
        bypassed — the operator should know).
      - File present + valid: emit a one-line stderr
        `{"info": "kimi: using OAuth token from <path>"}` so logs make
        it obvious which credential path won, and return the token.

    Path can be overridden via `AUDITOOOR_KIMI_OAUTH_FILE` for tests.
    Never raises.
    """
    override = os.environ.get("AUDITOOOR_KIMI_OAUTH_FILE")
    path = pathlib.Path(override) if override else _KIMI_OAUTH_FILE_DEFAULT
    if not path.is_file():
        return None
    # I9: pre-flight refresh. If the file's expires_at is within the
    # slack window (or already past), fire the CLI's refresh flow so we
    # don't ship an expired token into the dispatcher only to get a 401.
    # Skip this for tests that supply their own credentials file
    # (AUDITOOOR_KIMI_OAUTH_FILE override) — the refresh helper relies
    # on the real ~/.kimi/ layout and the kimi CLI binary.
    if not override:
        expires_at = _kimi_oauth_expires_at(path)
        if expires_at is None or expires_at < time.time() + _KIMI_OAUTH_REFRESH_SLACK_S:
            sys.stderr.write(json.dumps({
                "info": (
                    "kimi: oauth token expired or near-expiry; "
                    "invoking kimi CLI to refresh"
                )
            }) + "\n")
            sys.stderr.flush()
            _kimi_oauth_refresh_via_cli(path)
            # Continue regardless: if the refresh failed, the existing
            # 401 path produces a clear error. We just gave it a chance.
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        sys.stderr.write(json.dumps({
            "warn": f"kimi-credentials-malformed: read-failed: {e}"
        }) + "\n")
        sys.stderr.flush()
        return None
    try:
        data = json.loads(raw)
    except ValueError as e:
        sys.stderr.write(json.dumps({
            "warn": f"kimi-credentials-malformed: invalid-json: {e}"
        }) + "\n")
        sys.stderr.flush()
        return None
    if not isinstance(data, dict):
        sys.stderr.write(json.dumps({
            "warn": "kimi-credentials-malformed: not-an-object"
        }) + "\n")
        sys.stderr.flush()
        return None
    token = data.get("access_token")
    if not isinstance(token, str) or not token:
        sys.stderr.write(json.dumps({
            "warn": "kimi-credentials-malformed: missing-or-empty-access_token"
        }) + "\n")
        sys.stderr.flush()
        return None
    sys.stderr.write(json.dumps({
        "info": f"kimi: using OAuth token from {path}"
    }) + "\n")
    sys.stderr.flush()
    return token


# DEEPSEEK-INTEGRATION-CORE (2026-05-26) — model alias resolver.
# R36 pathspec declared via tools/agent-pathspec-register.py.
_DEEPSEEK_ALIASES_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "reference"
    / "deepseek_model_aliases.json"
)


def _resolve_deepseek_model_alias(provider: str) -> str | None:
    """Return the resolved API model_id for a DeepSeek logical alias.

    Looks up `reference/deepseek_model_aliases.json` for the canonical
    mapping operator-cited-name -> probed API model_id. The file is
    produced by `tools/deepseek-model-probe.py`. If the file is absent
    or unreadable, returns None and the caller falls through to the
    `_DEFAULT_MODELS[provider]` default.

    The alias file path can be overridden via
    AUDITOOOR_DEEPSEEK_ALIASES_FILE (used by tests). Never raises.
    """
    override = os.environ.get("AUDITOOOR_DEEPSEEK_ALIASES_FILE")
    path = pathlib.Path(override) if override else _DEEPSEEK_ALIASES_PATH
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    aliases = data.get("aliases")
    if not isinstance(aliases, dict):
        return None
    entry = aliases.get(provider)
    if isinstance(entry, dict):
        api_id = entry.get("api_model_id")
        if isinstance(api_id, str) and api_id.strip():
            return api_id.strip()
    elif isinstance(entry, str) and entry.strip():
        return entry.strip()
    return None


def _deepseek_cost_estimate(
    *,
    provider: str,
    input_tokens: int,
    output_tokens: int,
    cache_hit_input_tokens: int = 0,
) -> dict:
    """Return per-call USD cost estimate for a DeepSeek invocation.

    Cost rows are sourced from `_DEEPSEEK_PRICING_USD_PER_M_TOKENS`.
    `cache_hit_input_tokens` is subtracted from the cache-miss bucket
    before applying the discounted rate. Returns a dict with the
    breakdown so the audit trail can record it verbatim.
    """
    pricing = _DEEPSEEK_PRICING_USD_PER_M_TOKENS.get(provider)
    if not pricing:
        return {
            "provider": provider,
            "applicable": False,
            "reason": "non-deepseek-provider",
        }
    cache_hit = max(0, int(cache_hit_input_tokens))
    cache_miss = max(0, int(input_tokens) - cache_hit)
    output_tok = max(0, int(output_tokens))
    cost_cache_miss = cache_miss * pricing["input_cache_miss"] / 1_000_000
    cost_cache_hit = cache_hit * pricing["input_cache_hit"] / 1_000_000
    cost_output = output_tok * pricing["output"] / 1_000_000
    total = cost_cache_miss + cost_cache_hit + cost_output
    return {
        "provider": provider,
        "applicable": True,
        "input_cache_miss_tokens": cache_miss,
        "input_cache_hit_tokens": cache_hit,
        "output_tokens": output_tok,
        "cost_input_cache_miss_usd": round(cost_cache_miss, 6),
        "cost_input_cache_hit_usd": round(cost_cache_hit, 6),
        "cost_output_usd": round(cost_output, 6),
        "cost_total_usd": round(total, 6),
        "pricing_table_version": "2026-05-26-operator-cited",
    }


def _resolve_api_key(provider: str) -> str | None:
    """Return the API key for `provider`, walking the documented fallback chain.

    Resolution order per provider:
      kimi      : env.KIMI_API_KEY
                  → ~/.kimi/credentials/kimi-code.json (managed CLI OAuth)
                  → settings.json env.KIMI_API_KEY
                  → settings.json env.ANTHROPIC_AUTH_TOKEN
      minimax   : env.MINIMAX_API_KEY
                  → settings.json env.MINIMAX_API_KEY
                  → settings.json env.ANTHROPIC_AUTH_TOKEN
      anthropic : env.ANTHROPIC_API_KEY
                  → env.ANTHROPIC_AUTH_TOKEN
                  (settings.json fallback intentionally omitted — the
                  Anthropic key is workstation-global and should live in
                  process env.)

    The settings.json fallback exists because the user's Claude harness
    stores `ANTHROPIC_AUTH_TOKEN` as the routed Anthropic-compatible key
    and that is the working pattern proven by `tools/llm-pr-review.py`
    and the `/tmp/forever_overnight.sh` loop. The Kimi OAuth fallback
    (step 2) covers the managed-Kimi setup where the `kimi` CLI binary
    owns auth and writes a JWT to its credentials file. Returns None
    when no key is found at any layer.
    """
    if provider == "kimi":
        key = os.environ.get("KIMI_API_KEY")
        if key:
            return key
        oauth_token = _kimi_oauth_token_from_file()
        if oauth_token:
            return oauth_token
        sj = _settings_json_env()
        return sj.get("KIMI_API_KEY") or sj.get("ANTHROPIC_AUTH_TOKEN") or None
    if provider == "minimax":
        key = os.environ.get("MINIMAX_API_KEY")
        if key:
            return key
        sj = _settings_json_env()
        return sj.get("MINIMAX_API_KEY") or sj.get("ANTHROPIC_AUTH_TOKEN") or None
    if provider == "anthropic":
        return (
            os.environ.get("ANTHROPIC_API_KEY")
            or os.environ.get("ANTHROPIC_AUTH_TOKEN")
            or None
        )
    if provider in ("deepseek-flash", "deepseek-pro"):
        # Both DeepSeek variants share the same API key. R36 pathspec
        # entry: agent_pathspec.json registered via
        # tools/agent-pathspec-register.py.
        key = os.environ.get("DEEPSEEK_API_KEY")
        if key:
            return key
        sj = _settings_json_env()
        return sj.get("DEEPSEEK_API_KEY") or None
    if provider == "mimo":
        # Xiaomi MiMo Token Plan. Operator-provisioned 2026-05-27.
        # Env var: MIMO_API_KEY (tp- prefix). Settings.json fallback for
        # parity with other providers but L33 expects shell-rc export.
        key = os.environ.get("MIMO_API_KEY")
        if key:
            return key
        sj = _settings_json_env()
        return sj.get("MIMO_API_KEY") or None
    return None


# -----------------------------------------------------------------------------
# Local coding-agent CLI provider (no API key). Rides the operator's Claude or
# Codex subscription via the installed CLI, so every llm-dispatch consumer works
# under whichever agent the operator is driving with zero API keys: the tool
# builds the guard-railed prompt, the local CLI runs it on the subscription.
# Preferred ahead of the HTTP API providers in `auto` mode.
# -----------------------------------------------------------------------------

_LOCAL_CLI_AGENT_ENV = "AUDITOOOR_LOCAL_AGENT"      # force "codex" | "claude"
_LOCAL_CLI_MODEL_ENV = "AUDITOOOR_LOCAL_CLI_MODEL"  # override model id


def _find_codex_bin() -> str | None:
    """Locate the REAL codex CLI, skipping the auditooor MCP-gate wrapper
    (~/.auditooor/bin/codex) which would re-gate a background dispatch."""
    for cand in (
        "/opt/homebrew/bin/codex",
        "/usr/local/bin/codex",
        str(pathlib.Path.home() / ".npm-global" / "bin" / "codex"),
    ):
        p = pathlib.Path(cand)
        if p.exists() and "auditooor-codex-wrapper" not in str(p.resolve()):
            return str(p)
    found = shutil.which("codex")
    if found and "auditooor-codex-wrapper" not in str(pathlib.Path(found).resolve()):
        return found
    return None


def _resolve_local_cli_config() -> dict | None:
    """Local-CLI provider config, or None if no usable CLI is present.

    Backend selection (refined per the dispatch-architecture audit):
    ``AUDITOOOR_LOCAL_AGENT=codex|claude`` FORCES that backend. In AUTO mode
    (unset) selects Codex only when Codex is installed and the Claude CLI is
    unavailable. This provides an agentic GPT/Codex fallback without silently
    replacing an available Claude route. The ``claude`` CLI 401s headlessly in
    many environments, so it remains explicit-only. When no eligible local CLI
    exists, callers fall through to the HTTP providers (kimi/mimo/anthropic).
    The canonical SONNET path is NOT this
    CLI - it is the Agent(model='sonnet') orchestrator route (hunt-scoped ->
    haiku-fanout-dispatcher.py default model=sonnet -> agent_batch_*.md ->
    Agent(sonnet) -> 'sonnet-via-agent' sidecars), which runs inside the live
    OAuth session and needs no headless auth."""
    forced = (os.environ.get(_LOCAL_CLI_AGENT_ENV) or "").strip().lower()
    model = (os.environ.get(_LOCAL_CLI_MODEL_ENV) or "").strip()
    cb = _find_codex_bin()
    clb = shutil.which("claude")
    ordered: list[tuple[str, str]] = []
    if forced == "codex" and cb:
        ordered = [("codex", cb)]
    elif forced == "claude" and clb:
        ordered = [("claude", clb)]
    # AUTO mode: use Codex only when Claude is unavailable. Claude remains
    # explicit-only because its headless auth is unreliable.
    elif not forced and cb and not clb:
        ordered = [("codex", cb)]
    if not ordered:
        return None
    backend, binpath = ordered[0]
    return {
        "name": "local-cli",
        "backend": backend,
        "bin": binpath,
        "model": model or ("sonnet" if backend == "claude" else ""),
        "all_candidates": ordered,
        # Present so the audit-trail writer (which expects an api_url) does not
        # KeyError; never used for an HTTP request.
        "api_url": f"local-cli://{backend}",
        "base_url": "local-cli",
    }


def _local_cli_extract_prompt(body_bytes: bytes) -> str:
    """Reconstruct one prompt string from the Anthropic Messages request body
    (system + every text message block), so the local CLI receives the same
    guard-railed prompt the HTTP providers would."""
    try:
        doc = json.loads(body_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return body_bytes.decode("utf-8", errors="replace")
    parts: list[str] = []
    sys_p = doc.get("system")
    if isinstance(sys_p, str) and sys_p.strip():
        parts.append(sys_p)
    for m in doc.get("messages", []) if isinstance(doc, dict) else []:
        c = m.get("content") if isinstance(m, dict) else None
        if isinstance(c, str):
            parts.append(c)
        elif isinstance(c, list):
            for blk in c:
                if isinstance(blk, dict) and blk.get("type") == "text":
                    parts.append(str(blk.get("text", "")))
    return "\n\n".join(p for p in parts if p)


def _parse_codex_stdout(stdout: str) -> str:
    """Pull the final agent_message text out of `codex exec --json` JSONL."""
    last = ""
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            evt = json.loads(line)
        except ValueError:
            continue
        item = evt.get("item") if isinstance(evt, dict) else None
        if isinstance(item, dict) and item.get("type") == "agent_message":
            t = item.get("text")
            if isinstance(t, str):
                last = t
    return last.strip()


def _local_cli_one_backend(backend: str, binpath: str, model: str,
                           prompt: str, timeout: float) -> tuple[bool, str, str]:
    """Run one backend. Returns (ok, text, err). Never raises."""
    env = dict(os.environ)
    for k in ("AUDITOOOR_MCP_REQUIRED", "AUDITOOOR_MCP_SESSION_TOKEN"):
        env.pop(k, None)
    try:
        with tempfile.TemporaryDirectory(prefix="local_cli_") as td:
            if backend == "codex":
                out_file = pathlib.Path(td) / "last_message.txt"
                # --skip-git-repo-check: the tempdir cwd is untrusted; without
                # it codex refuses to run. stdin=DEVNULL: stop codex waiting on
                # "additional input from stdin" when the prompt is positional.
                cmd = [binpath, "exec", "--skip-git-repo-check", "-o", str(out_file)]
                if model:
                    cmd += ["-m", model]
                cmd += [prompt]
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=timeout, env=env, cwd=td,
                                      stdin=subprocess.DEVNULL)
                text = ""
                if out_file.is_file():
                    text = out_file.read_text(encoding="utf-8", errors="replace").strip()
                if not text:
                    text = _parse_codex_stdout(proc.stdout)
            else:  # claude
                cmd = [binpath, "-p", prompt, "--output-format", "text"]
                if model:
                    cmd += ["--model", model]
                proc = subprocess.run(cmd, capture_output=True, text=True,
                                      timeout=timeout, env=env, cwd=td,
                                      stdin=subprocess.DEVNULL)
                text = (proc.stdout or "").strip()
            if proc.returncode != 0 and not text:
                return False, "", (((proc.stderr or "") + (proc.stdout or ""))[:400])
            if not text:
                return False, "", "empty-response"
            return True, text, ""
    except subprocess.TimeoutExpired:
        return False, "", f"timeout after {timeout}s"
    except OSError as e:
        return False, "", f"spawn-error: {e}"


def _local_cli_once(provider_cfg: dict, body_bytes: bytes,
                    timeout: float) -> tuple[str, int, int, int]:
    """Dispatch via the local coding-agent CLI (no API key). Tries each detected
    backend in order; on total failure raises ProviderFallback so auto-mode
    falls through to the HTTP API providers. Token usage is reported as 0 (the
    budget guard treats that as a call-count slot)."""
    prompt = _local_cli_extract_prompt(body_bytes)
    errs: list[str] = []
    for backend, binpath in provider_cfg.get("all_candidates") or [
        (provider_cfg["backend"], provider_cfg["bin"])
    ]:
        model = provider_cfg.get("model") or ("sonnet" if backend == "claude" else "")
        ok, text, err = _local_cli_one_backend(backend, binpath, model, prompt, timeout)
        if ok:
            return text, 200, 0, 0
        errs.append(f"{backend}: {err}")
    raise ProviderFallback("local-cli: " + " | ".join(errs), status=0)


def _resolve_provider_config(provider: str) -> dict | None:
    """Build a provider config dict from environment, or return None if the
    provider has no API key configured.

    Keys in the returned dict:
      - name          : provider name (kimi / minimax / anthropic)
      - api_key       : resolved API key (never logged or audited)
      - base_url      : resolved base URL (no trailing slash)
      - api_url       : `<base_url>/v1/messages`
      - model         : resolved model ID
      - auth_header   : `x-api-key` (default) or `authorization` (bearer)
      - auth_value    : header value (`<key>` or `Bearer <key>`)
    """
    if provider == "local-cli":
        # No API key: rides the local coding-agent CLI subscription.
        return _resolve_local_cli_config()
    if provider == "kimi":
        api_key = _resolve_api_key("kimi")
        base_url = os.environ.get("KIMI_ANTHROPIC_BASE_URL") or _DEFAULT_BASE_URLS["kimi"]
        model = os.environ.get("KIMI_MODEL") or _DEFAULT_MODELS["kimi"]
    elif provider == "minimax":
        api_key = _resolve_api_key("minimax")
        base_url = (
            os.environ.get("MINIMAX_ANTHROPIC_BASE_URL")
            or _DEFAULT_BASE_URLS["minimax"]
        )
        model = os.environ.get("MINIMAX_MODEL") or _DEFAULT_MODELS["minimax"]
    elif provider == "anthropic":
        api_key = _resolve_api_key("anthropic")
        base_url = os.environ.get("ANTHROPIC_BASE_URL") or _DEFAULT_BASE_URLS["anthropic"]
        model = os.environ.get("ANTHROPIC_MODEL") or _DEFAULT_MODELS["anthropic"]
    elif provider == "deepseek-flash":
        # R36 declaration: lane-DEEPSEEK-INTEGRATION-CORE pathspec in
        # agent_pathspec.json. Both DeepSeek variants share the
        # DEEPSEEK_API_KEY environment variable but resolve to distinct
        # model_ids via the alias file produced by deepseek-model-probe.py.
        api_key = _resolve_api_key("deepseek-flash")
        base_url = (
            os.environ.get("DEEPSEEK_BASE_URL")
            or _DEFAULT_BASE_URLS["deepseek-flash"]
        )
        model = (
            os.environ.get("DEEPSEEK_FLASH_MODEL")
            or _resolve_deepseek_model_alias("deepseek-flash")
            or _DEFAULT_MODELS["deepseek-flash"]
        )
    elif provider == "deepseek-pro":
        api_key = _resolve_api_key("deepseek-pro")
        base_url = (
            os.environ.get("DEEPSEEK_BASE_URL")
            or _DEFAULT_BASE_URLS["deepseek-pro"]
        )
        model = (
            os.environ.get("DEEPSEEK_PRO_MODEL")
            or _resolve_deepseek_model_alias("deepseek-pro")
            or _DEFAULT_MODELS["deepseek-pro"]
        )
    elif provider == "mimo":
        # <!-- r36-rebuttal: lane claude-mimo-add-2026-05-27 registered -->
        # Xiaomi MiMo Anthropic-compatible at /anthropic. Token Plan
        # keys (tp-*) require Authorization: Bearer header (forced below).
        api_key = _resolve_api_key("mimo")
        base_url = os.environ.get("MIMO_BASE_URL") or _DEFAULT_BASE_URLS["mimo"]
        model = os.environ.get("MIMO_MODEL") or _DEFAULT_MODELS["mimo"]
    else:
        return None

    if not api_key:
        return None

    base_url = base_url.rstrip("/")
    # Smart join: if the operator already included `/v1` in the base URL,
    # don't double it. Per Codex test #6: base_url ending in `/v1` should
    # resolve to `<base_url>/messages`.
    if base_url.endswith("/v1"):
        api_url = base_url + "/messages"
    else:
        api_url = base_url + MESSAGES_PATH

    auth_header_choice = (
        os.environ.get("AUDITOOOR_LLM_AUTH_HEADER") or "x-api-key"
    ).strip().lower()
    # <!-- r36-rebuttal: lane claude-mimo-add-2026-05-27 registered -->
    # Xiaomi MiMo Token Plan keys (tp-*) require bearer regardless of env.
    if provider == "mimo" or auth_header_choice == "bearer":
        auth_header = "authorization"
        auth_value = f"Bearer {api_key}"
    else:
        auth_header = "x-api-key"
        auth_value = api_key

    return {
        "name": provider,
        "api_key": api_key,
        "base_url": base_url,
        "api_url": api_url,
        "model": model,
        "auth_header": auth_header,
        "auth_value": auth_value,
    }


def _resolve_provider_chain(requested: str, cli_model: str | None) -> tuple[list[dict], str | None]:
    """Resolve the ordered list of provider configs to attempt.

    Returns (chain, explicit_name).
      - In auto mode the chain is Kimi → MiniMax → MiMo → Anthropic (only those
        with keys). `explicit_name` is None.
      - In explicit mode the chain has exactly one entry. If its key is
        missing the chain is empty and `explicit_name` holds the name so
        the caller can emit `cannot-run: no-api-key`.

    `cli_model`, if given, overrides the env-resolved model on the first
    (and in explicit mode the only) provider in the chain.
    """
    env_override = os.environ.get("AUDITOOOR_LLM_PROVIDER")
    if env_override:
        env_override = env_override.strip().lower()
        if env_override in ("local-cli", "kimi", "minimax", "mimo", "anthropic"):
            requested = env_override

    # OPERATOR-DISABLED PROVIDERS (fail-fast enforcement). A provider whose
    # creds FILE exists but whose account is dead (e.g. Kimi membership expired
    # -> http-402, DeepSeek/MiMo key revoked -> 401, or a provider that HANGS
    # with no server-side timeout) otherwise stays in the auto-chain and the
    # funnel wastes minutes-to-hours hanging/retrying on it. Set
    # AUDITOOOR_LLM_DISABLED_PROVIDERS=kimi,minimax,mimo,deepseek-flash,deepseek-pro,anthropic
    # (comma list) to drop them from the auto-chain entirely; when no provider
    # survives, the chain is empty and the caller fails FAST (clean
    # "no-provider" skip) instead of hanging, and the orchestrator runs the
    # canonical Tier-2 in-session Agent(model=sonnet) hunt instead. Clear an
    # entry the moment its key/membership goes live again.
    _disabled = {
        p.strip().lower()
        for p in (os.environ.get("AUDITOOOR_LLM_DISABLED_PROVIDERS") or "").split(",")
        if p.strip()
    }

    if requested == "auto":
        chain: list[dict] = []
        # local-cli first: no API key, rides the operator's Claude/Codex
        # subscription. Falls through to the HTTP providers if no CLI is present
        # or the CLI dispatch errors (ProviderFallback).
        for name in ("local-cli", "kimi", "minimax", "mimo", "anthropic"):
            if name in _disabled:
                continue
            cfg = _resolve_provider_config(name)
            if cfg is not None:
                chain.append(cfg)
        # A caller-supplied --model is an Anthropic-format id; only apply it to
        # an HTTP provider, never to the local-cli entry (its model is its own).
        if cli_model and chain and chain[0].get("name") != "local-cli":
            chain[0] = dict(chain[0], model=cli_model)
        return chain, None

    # Explicit mode: an operator-disabled provider fails fast (empty chain ->
    # caller emits cannot-run: no-provider) rather than attempting a dead key.
    if requested in _disabled:
        return [], requested
    cfg = _resolve_provider_config(requested)
    if cfg is None:
        return [], requested
    if cli_model:
        cfg = dict(cfg, model=cli_model)
    return [cfg], requested


# -----------------------------------------------------------------------------
# Request-body construction
# -----------------------------------------------------------------------------

def _anthropic_prompt_caching_enabled(provider_name: str) -> bool:
    """Return True when Anthropic-only prompt-cache annotations are allowed."""
    if provider_name != "anthropic":
        return False
    value = os.environ.get(ANTHROPIC_PROMPT_CACHING_ENV_VAR, "")
    return value.strip() != "0"


def _with_cache_control(block: dict) -> dict:
    """Return a shallow-copied block with Anthropic ephemeral cache_control."""
    copied = dict(block)
    copied.setdefault("cache_control", dict(CACHE_CONTROL_EPHEMERAL))
    return copied


def _cache_last_dict_block(blocks: list) -> list:
    """Copy a list and add cache_control to its last dict element, if any."""
    copied = [dict(item) if isinstance(item, dict) else item for item in blocks]
    for idx in range(len(copied) - 1, -1, -1):
        if isinstance(copied[idx], dict):
            copied[idx] = _with_cache_control(copied[idx])
            break
    return copied


def _split_cacheable_prompt_prefix(prompt_text: str) -> tuple[list[str], str]:
    """Split stable prompt prebrief/rules prefixes from the task body.

    dispatch-preflight and related wrappers prepend long META-1 / codified
    rules blocks before the actual worker prompt. Anthropic can cache those
    stable prefixes when represented as content blocks carrying
    ``cache_control``; Kimi and MiniMax still receive the original string.
    """
    cacheable: list[str] = []
    rest = prompt_text

    while rest:
        matched = False
        leading_len = len(rest) - len(rest.lstrip())
        search_from = leading_len
        for begin, end in _CACHEABLE_PROMPT_MARKER_PAIRS:
            if not rest.startswith(begin, search_from):
                continue
            end_pos = rest.find(end, search_from + len(begin))
            if end_pos < 0:
                continue
            block_end = end_pos + len(end)
            while block_end < len(rest) and rest[block_end] == "\n":
                block_end += 1
            cacheable.append(rest[:block_end])
            rest = rest[block_end:]
            matched = True
            break
        if not matched:
            break

    leading_len = len(rest) - len(rest.lstrip())
    section_start = leading_len
    section_probe = rest[section_start:]
    cache_section = False
    if section_probe.startswith("## Section 15a") and (
        "vault_codified_rules_digest" in section_probe[:2000]
        or "Codified rules" in section_probe[:200]
        or "R-rules" in section_probe[:200]
    ):
        cache_section = True
    elif section_probe.startswith(
        "## Section 0 (MCP-injected) - Codified rules this lane MUST address"
    ):
        cache_section = True

    if cache_section:
        boundary_positions = [
            rest.find(boundary, section_start + 1)
            for boundary in _CACHEABLE_PROMPT_SECTION_BOUNDARIES
            if rest.find(boundary, section_start + 1) >= 0
        ]
        if boundary_positions:
            block_end = min(boundary_positions)
            cacheable.append(rest[:block_end])
            rest = rest[block_end:]

    return cacheable, rest


def _anthropic_user_content_with_cache_control(user_content: str) -> str | list[dict]:
    cacheable_blocks, rest = _split_cacheable_prompt_prefix(user_content)
    if not cacheable_blocks:
        return user_content

    blocks: list[dict] = [
        {
            "type": "text",
            "text": block,
            "cache_control": dict(CACHE_CONTROL_EPHEMERAL),
        }
        for block in cacheable_blocks
        if block
    ]
    if rest:
        blocks.append({"type": "text", "text": rest})
    return blocks


def _apply_anthropic_prompt_cache_control(body: dict) -> dict:
    """Add Anthropic Messages prompt-cache annotations without mutating input."""
    cached = dict(body)

    system_content = cached.get("system")
    if isinstance(system_content, str) and system_content:
        cached["system"] = [
            {
                "type": "text",
                "text": system_content,
                "cache_control": dict(CACHE_CONTROL_EPHEMERAL),
            }
        ]
    elif isinstance(system_content, list) and system_content:
        cached["system"] = _cache_last_dict_block(system_content)

    tools = cached.get("tools")
    if isinstance(tools, list) and tools:
        cached["tools"] = _cache_last_dict_block(tools)

    messages = cached.get("messages")
    if isinstance(messages, list):
        copied_messages: list = []
        for message in messages:
            if not isinstance(message, dict):
                copied_messages.append(message)
                continue
            copied_message = dict(message)
            content = copied_message.get("content")
            if isinstance(content, str):
                copied_message["content"] = _anthropic_user_content_with_cache_control(
                    content
                )
            copied_messages.append(copied_message)
        cached["messages"] = copied_messages

    return cached


def _build_messages_body(
    provider_cfg: dict,
    *,
    max_tokens: int,
    user_content: str,
    system_content: str | list[dict] | None = None,
    tools: list[dict] | None = None,
) -> dict:
# r36-rebuttal: lane CLAUDE-MIMO-THINKING-FIX registered 2026-05-27 for mimo thinking-disable
    body: dict = {
        "model": provider_cfg["model"],
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": user_content}],
    }
    if system_content is not None:
        body["system"] = system_content
    if tools is not None:
        body["tools"] = tools

    # 2026-05-27 mimo SGP thinking-disable: mimo models default to
    # extended-thinking which consumes max_tokens before producing a
    # text block, causing thinking-only-response failures. Disable when
    # AUDITOOOR_LLM_DISABLE_THINKING=1 OR provider==mimo (unless operator
    # explicitly sets AUDITOOOR_MIMO_DISABLE_THINKING=0).
    pname = str(provider_cfg.get("name", "")).lower()
    _disable_thinking_env = os.environ.get("AUDITOOOR_LLM_DISABLE_THINKING", "").strip()
    _mimo_keep_thinking = os.environ.get("AUDITOOOR_MIMO_DISABLE_THINKING", "").strip() == "0"
    if _disable_thinking_env == "1" or (pname == "mimo" and not _mimo_keep_thinking):
        body["thinking"] = {"type": "disabled"}

    if _anthropic_prompt_caching_enabled(str(provider_cfg.get("name", ""))):
        return _apply_anthropic_prompt_cache_control(body)
    return body


# -----------------------------------------------------------------------------
# HTTP call
# -----------------------------------------------------------------------------

def _post_once(
    provider_cfg: dict,
    body_bytes: bytes,
    timeout: float,
) -> tuple[int, bytes]:
    """Perform a single HTTPS POST. Returns (status_code, body_bytes).

    Distinguishes HTTP errors (surfaces status + body) from transport
    failures (re-raised). 429 is returned as status=429 so the retry
    loop can decide; non-retryable HTTP errors are also returned with
    their status so the caller emits a single structured error.
    """
    headers = {
        provider_cfg["auth_header"]: provider_cfg["auth_value"],
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    req = urllib.request.Request(
        provider_cfg["api_url"],
        data=body_bytes,
        method="POST",
        headers=headers,
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        status = getattr(resp, "status", None) or resp.getcode()
        data = resp.read()
        try:
            resp.close()
        except Exception:
            pass
        return status, data
    except urllib.error.HTTPError as e:
        # HTTPError is an HTTP response; preserve status + body.
        try:
            err_body = e.read()
        except Exception:
            err_body = b""
        return e.code, err_body


class ProviderFallback(Exception):
    """Raised internally when a provider attempt should trigger fallback.

    Carries the reason (5xx / 429 / transport error) so the caller can
    log a non-fatal audit hop. Only used in auto-mode.
    """

    def __init__(self, reason: str, status: int = 0):
        super().__init__(reason)
        self.reason = reason
        self.status = status


class _ThinkingOnlyResponse(Exception):
    """Raised internally when a 200 response carries only thinking blocks.

    Caught and acted on by ``_call_once_with_fallback_classification``
    (V5 P0-01 / Gap 7) so the same prompt is retried EXACTLY ONCE before
    surfacing as a hard failure. Carries the ``types_seen`` list so the
    eventual RuntimeError can include the diagnostic detail.

    NOT a public exception. Lives next to ProviderFallback to keep the
    classification surface in one place.
    """

    def __init__(self, types_seen: list[str]):
        super().__init__(f"thinking-only (types_seen={types_seen})")
        self.types_seen = types_seen


def _call_once_with_fallback_classification(
    provider_cfg: dict,
    body_bytes: bytes,
    timeout: float,
    retry_on_429: int,
) -> tuple[str, int, int, int]:
    """Invoke a single provider with the full 429-retry loop, plus one
    auto-retry on a thinking-only response (V5 P0-01 / Gap 7).

    Returns (response_text, http_status, retry_count, tokens_used) on
    success. ``tokens_used`` is the sum of
    ``usage.input_tokens + usage.output_tokens`` parsed from the
    Anthropic-Messages-shaped response, with a safe ``.get(..., 0)``
    default per field so a provider that omits ``usage`` does not break
    the success path (the budget guard simply records 0 tokens for
    that hop).

    Raises ProviderFallback on 5xx / 429-budget-exhausted / transport
    error (auto-mode fallback signal).
    Raises RuntimeError on 4xx (non-429) or malformed 200 (hard failure;
    no fallback). When the response carries only thinking blocks the
    helper retries the same body EXACTLY ONCE before raising
    ``RuntimeError("malformed-response: thinking-only-after-retry ...")``.
    The retry budget is bounded by ``THINKING_ONLY_RETRY_LIMIT`` so a
    genuinely-stuck model cannot burn the operator's token budget.
    """
    thinking_only_attempts = 0
    while True:
        try:
            return _call_once_inner(
                provider_cfg,
                body_bytes,
                timeout=timeout,
                retry_on_429=retry_on_429,
            )
        except _ThinkingOnlyResponse as exc:
            if thinking_only_attempts >= THINKING_ONLY_RETRY_LIMIT:
                # Bounded retry exhausted — surface as a hard failure so
                # the caller does NOT silently fall back. The caller's
                # audit-trail row records this as the terminal outcome.
                raise RuntimeError(
                    "malformed-response: thinking-only-after-retry "
                    f"(types_seen={exc.types_seen})"
                ) from exc
            thinking_only_attempts += 1
            sys.stderr.write(json.dumps({
                "info": (
                    "thinking-only-response: retrying once "
                    f"(provider={provider_cfg.get('name')}, "
                    f"types_seen={exc.types_seen})"
                )
            }) + "\n")
            sys.stderr.flush()
            continue


def _call_once_inner(
    provider_cfg: dict,
    body_bytes: bytes,
    timeout: float,
    retry_on_429: int,
) -> tuple[str, int, int, int]:
    """Single dispatch attempt with the 429-retry loop only.

    Split out from ``_call_once_with_fallback_classification`` so the
    thinking-only retry shim (V5 P0-01 / Gap 7) can wrap it without
    duplicating the 429/transport/4xx/5xx classification matrix. Raises
    ``_ThinkingOnlyResponse`` on the specific shape that should retry
    once; all other RuntimeError / ProviderFallback semantics match the
    caller contract verbatim.
    """
    retry_count = 0
    backoff_s = 1.0
    if provider_cfg.get("name") == "local-cli":
        # Local coding-agent CLI dispatch: no HTTP, no 429-retry loop. Raises
        # ProviderFallback on failure so auto-mode falls through to HTTP providers.
        return _local_cli_once(provider_cfg, body_bytes, timeout)
    while True:
        try:
            status, data = _post_once(provider_cfg, body_bytes, timeout)
        except urllib.error.URLError as e:
            # Transport failure — auto-mode should try the next provider.
            # `URLError` is the most common timeout shape: urlopen wraps
            # `socket.timeout` (alias of `TimeoutError` in py3.10+) into
            # `URLError(reason=TimeoutError(...))` for connection-stage
            # timeouts and DNS failures.
            raise ProviderFallback(f"transport-error: {e}", status=0) from e
        except TimeoutError as e:
            # py3.10+ read-stage timeouts on the response body can
            # propagate a bare `TimeoutError` (== `socket.timeout`)
            # without `URLError` wrapping. Surfaced by V5 Wave 1 PR-A
            # (#279): long-timeout MiniMax dispatch retries broke
            # auto-fallback to Anthropic because this exception was
            # uncaught here. Map to the same transport-error shape so
            # auto-mode falls through.
            raise ProviderFallback(
                f"transport-error: timeout after {timeout}s: {e}",
                status=0,
            ) from e
        except (ConnectionError, BrokenPipeError) as e:
            # Defensive belt-and-suspenders: TCP-level resets / aborted
            # connections / refused connections / broken pipes are all
            # transient transport failures from the dispatcher's
            # perspective and should trigger the same fallback path.
            # `ConnectionError` is the stdlib parent of
            # `ConnectionResetError`, `ConnectionAbortedError`,
            # `ConnectionRefusedError`. `BrokenPipeError` is listed
            # explicitly (it is also a `ConnectionError` subclass on
            # all currently-supported Pythons, but the spec requires
            # the named match — keep the alias for clarity and
            # forward-compat).
            raise ProviderFallback(
                f"transport-error: {type(e).__name__}: {e}",
                status=0,
            ) from e

        if status == 429 and retry_count < retry_on_429:
            time.sleep(backoff_s)
            backoff_s *= 2.0
            retry_count += 1
            continue
        if status == 429:
            # Retry budget exhausted — auto-mode falls back.
            raise ProviderFallback(
                f"http-429-retry-budget-exhausted: after {retry_count} retries",
                status=429,
            )
        if 500 <= status < 600:
            raise ProviderFallback(f"http-{status}", status=status)
        if status < 200 or status >= 300:
            # 4xx non-429 — legitimate failure, no fallback.
            tail = data[:400].decode("utf-8", errors="replace")
            raise RuntimeError(f"http-{status}: {tail}")

        # 2xx — parse.
        try:
            doc = json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise RuntimeError(f"malformed-response-json: {e}") from e
        content = doc.get("content")
        if not isinstance(content, list) or not content:
            raise RuntimeError("malformed-response: missing-content")
        # Anthropic Messages API returns `content[]` as a heterogeneous list
        # of blocks: typically one or more `{type: "text", text: ...}` plus
        # optional `{type: "thinking", ...}` (extended thinking) and
        # `{type: "tool_use", ...}`. MiniMax in particular places a
        # `type:"thinking"` block at content[0] and the actual answer at
        # content[1] (foot-gun #13d in feedback_recurring_agent_mistakes.md).
        # We must therefore iterate the list and return the FIRST block whose
        # `type == "text"` carries a string `text` field — never assume
        # `content[0]` is the answer.
        text: str | None = None
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") != "text":
                continue
            candidate = block.get("text")
            if isinstance(candidate, str):
                text = candidate
                break
        if text is None:
            # No usable text block. Surface a precise reason so callers
            # can distinguish "thinking-only" responses (graceful failure,
            # not a parser crash) from genuinely empty content.
            types_seen = sorted({
                str(b.get("type")) for b in content
                if isinstance(b, dict) and b.get("type") is not None
            })
            # V5 P0-01 (Gap 7): when the only block-type observed is
            # `thinking`, give the model exactly one more attempt at the
            # same prompt before failing. The wrapper
            # ``_call_once_with_fallback_classification`` enforces the
            # one-retry budget — this inner helper just signals the
            # specific shape via a typed exception. Any OTHER missing-
            # text shape (e.g. tool_use only, content but no text field)
            # is still an immediate hard failure: those have not been
            # observed to recover on retry and we do not want to mask
            # them.
            if types_seen == ["thinking"]:
                raise _ThinkingOnlyResponse(types_seen)
            raise RuntimeError(
                "malformed-response: no-text-block "
                f"(types_seen={types_seen})"
            )
        # Parse Anthropic Messages `usage` block for the budget-guard
        # post-call accounting. Safe-defaults to 0 when the provider
        # omits the field — the guard treats 0-token records as
        # call-count entries (still consumes a slot in the rolling
        # window, which is the conservative choice).
        usage = doc.get("usage")
        if isinstance(usage, dict):
            input_tokens = usage.get("input_tokens", 0) or 0
            output_tokens = usage.get("output_tokens", 0) or 0
            try:
                tokens_used = int(input_tokens) + int(output_tokens)
            except (TypeError, ValueError):
                tokens_used = 0
            if tokens_used < 0:
                tokens_used = 0
        else:
            tokens_used = 0
        return text, status, retry_count, tokens_used


# -----------------------------------------------------------------------------
# CLI entry
# -----------------------------------------------------------------------------

def _network_consent_source(cli_operator_consent: bool = False) -> str | None:
    if cli_operator_consent:
        return "cli:--operator-live-network-consent"
    if os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1":
        return "env:AUDITOOOR_LLM_NETWORK_CONSENT"
    if os.environ.get("ADVERSARIAL_LIVE_CONSENT") == "1":
        return "env:ADVERSARIAL_LIVE_CONSENT"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Stdlib-only Anthropic-compatible Messages API wrapper. Invoked "
            "by swarm-orchestrator.py --dispatch when SWARM_REAL_DISPATCH=1. "
            "Supports Kimi, MiniMax, MiMo, and Anthropic providers with explicit "
            "opt-in network consent."
        ),
    )
    parser.add_argument(
        "--prompt-file",
        required=True,
        help="Path to the prompt text file (UTF-8). Content is sent verbatim "
             "as a single user-role message.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Override provider model ID. Defaults to <PROVIDER>_MODEL env "
             "(kimi-for-coding / MiniMax-M2.7 / claude-opus-4-5).",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help=(
            "max_tokens for the completion (default: "
            f"{DEFAULT_MAX_TOKENS}). V5 P0-01 (Gap 1, Gap 12) bumped this "
            "from 4000 because the previous default truncated long-context "
            "Kimi/Minimax responses, forcing operators to manually pass a "
            "larger budget on every long-context campaign. Use "
            "`--smoke-test` for hello-world / cheap auth checks where a "
            f"single-line response is enough ({SMOKE_TEST_MAX_TOKENS} "
            "tokens)."
        ),
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help=(
            "Select the smoke-test token budget "
            f"({SMOKE_TEST_MAX_TOKENS} tokens). Mutually exclusive with "
            "an explicit `--max-tokens` value: if both are provided, "
            "`--smoke-test` wins so cheap dry-runs cannot accidentally "
            "spend long-context budget. Use this for provider preflight, "
            "OAuth verification, or any prompt that expects a one-line "
            "acknowledgement."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Per-request HTTP timeout in seconds (default: 60).",
    )
    parser.add_argument(
        "--retry-on-429",
        type=int,
        default=2,
        help="Max retries on HTTP 429 with exponential backoff (default: 2).",
    )
    parser.add_argument(
        "--provider",
        choices=(
            "auto",
            "local-cli",
            "kimi",
            "minimax",
            "anthropic",
            "deepseek-flash",
            "deepseek-pro",
            # <!-- r36-rebuttal: lane claude-mimo-add-2026-05-27 registered -->
            "mimo",
        ),
        default="auto",
        help="LLM provider. `auto` prefers Kimi → MiniMax → MiMo → Anthropic with "
             "5xx/429/transport fallback. DeepSeek variants are explicit-"
             "only - they do not participate in `auto` fallback (separate "
             "cost-budget envelope). Explicit provider with no key exits "
             "2 (no fallback). Override via AUDITOOOR_LLM_PROVIDER env. "
             "R36 pathspec via tools/agent-pathspec-register.py.",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help=(
            "Skip the network call and emit a synthetic Anthropic-"
            "compatible response. Required for tests; safe to use in "
            "operator-driven smoke runs when the DeepSeek account has "
            "insufficient balance. The mock-mode audit record carries "
            "outcome=ok-mocked so downstream consumers can filter it. "
            "Equivalent to setting AUDITOOOR_DEEPSEEK_MOCK=1."
        ),
    )
    parser.add_argument(
        "--verified-by",
        default=None,
        help=(
            "R37 verification-tier upgrade attestation. The default "
            "tier for advisory LLM dispatch is "
            "tier-3-synthetic-taxonomy-anchored; passing this flag "
            "stamps a verified-by attestation into the audit record so "
            "downstream consumers can upgrade the verification tier. "
            "Example: --verified-by claude-second-pass."
        ),
    )
    parser.add_argument(
        "--audit-dir",
        default=None,
        help="Override audit-trail directory (default: ./agent_outputs).",
    )
    parser.add_argument(
        "--operator-live-network-consent",
        action="store_true",
        help=(
            "Explicit operator consent for this invocation to make outbound "
            "LLM provider network calls. Equivalent to the existing "
            "AUDITOOOR_LLM_NETWORK_CONSENT=1 boundary, but command-local "
            "and recorded in dispatch audit records."
        ),
    )
    parser.add_argument(
        "--input-is-truncated",
        action="store_true",
        help=(
            "Signal that the prompt content is a TRUNCATED diff/document "
            "(callers like llm-pr-review.py truncate large diffs to fit a "
            "token budget). When set AND the resolved provider is "
            "`minimax`, dispatch prepends a one-line system-instruction "
            "notice to the user message instructing the model not to "
            "claim missing files/sections based on absence (foot-gun "
            "#13d). No-op for kimi/anthropic — only MiniMax-M2.7 has "
            "exhibited the absence-hallucination failure mode."
        ),
    )
    parser.add_argument(
        "--strategic-llm-allowed",
        action="store_true",
        help=(
            "Override the V5-P0-22 strategic-LLM policy gate. By default, "
            "prompts containing heuristic strategic-output markers (e.g. "
            "'roadmap', 'next strategic step', 'what should we build next') "
            "are refused — strategic LLM use is operator-policy territory "
            "and should not happen in routine review/mining loops. Pass "
            "this flag to acknowledge the policy and proceed."
        ),
    )
    parser.add_argument(
        "--task-type",
        default=None,
        help=(
            "Calibration task class for provider-routing decisions "
            "(e.g. source-extraction, adversarial-kill, poc-wiring, "
            "docs-integration, factory-config-liveness-extraction, "
            "factory-config-liveness-kill, pr-review). When supplied, "
            "dispatch stamps the provider × task routing status into the "
            "audit trail."
        ),
    )
    parser.add_argument(
        "--routing-purpose",
        choices=("advisory", "promotion"),
        default="advisory",
        help=(
            "Use `promotion` when the model output would be treated as a "
            "primary lane result. Promotion dispatch fails closed unless "
            "the calibration ledger has enough verified precision for "
            "provider × task-type. Default `advisory` never blocks but "
            "records advisory-only status in the audit trail."
        ),
    )
    parser.add_argument(
        "--require-mcp-receipt",
        action="store_true",
        help=(
            "Lane 12 (PR #658). Refuse dispatch unless a fresh MCP session "
            "token (AUDITOOOR_MCP_SESSION_TOKEN env var) is present and "
            "verifies with write scope via tools/auditooor_mcp_token.py. "
            "Closes provider-bypass surface for non-Claude providers that "
            "bypass the PreToolUse hook. Exit code 3 on missing/invalid token."
        ),
    )
    args = parser.parse_args(argv)

    # Lane 12 (PR #658) — MCP-receipt enforcement gate
    if args.require_mcp_receipt:
        token = os.environ.get("AUDITOOOR_MCP_SESSION_TOKEN", "")
        if not token:
            _emit_structured_error(
                "cannot-run: mcp-receipt-missing",
                detail=(
                    "--require-mcp-receipt set but AUDITOOOR_MCP_SESSION_TOKEN "
                    "env var not present. Issue a token: "
                    "python3 tools/auditooor_mcp_token.py issue --workspace $PWD --scope write"
                ),
            )
            return 3
        # Verify via auditooor_mcp_token (best-effort import)
        try:
            sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
            from auditooor_mcp_token import verify_token  # type: ignore
            valid, err, payload = verify_token(token, require_scope="write")
            if not valid:
                _emit_structured_error(
                    "cannot-run: mcp-receipt-invalid",
                    detail=f"token verification failed: {err}",
                )
                return 3
            workspace = str((payload or {}).get("ws") or "")
            if not workspace:
                _emit_structured_error(
                    "cannot-run: mcp-receipt-workspace-missing",
                    detail="token is valid but does not bind a workspace path",
                )
                return 3
            try:
                memory_context_load = _load_memory_context_loader()
                rc, receipt_status = memory_context_load.check_receipt(
                    pathlib.Path(workspace),
                    strict=True,
                    require_proof=True,
                )
            except Exception as exc:
                _emit_structured_error(
                    "cannot-run: mcp-receipt-tooling-error",
                    detail=f"receipt check failed to run: {exc}",
                    workspace=workspace,
                )
                return 3
            if rc != 0:
                _emit_structured_error(
                    "cannot-run: mcp-receipt-incomplete",
                    detail=f"receipt check failed: {receipt_status.get('status')}",
                    workspace=workspace,
                    receipt_path=receipt_status.get("receipt_path"),
                    requirements_path=receipt_status.get("requirements_path"),
                    next_command=receipt_status.get("next_command"),
                    invalid_contexts=receipt_status.get("invalid_contexts", []),
                    missing_contexts=receipt_status.get("missing_contexts", []),
                    stale_contexts=receipt_status.get("stale_contexts", []),
                )
                return 3
        except ImportError:
            _emit_structured_error(
                "cannot-run: mcp-receipt-tooling-missing",
                detail="auditooor_mcp_token module not importable",
            )
            return 3

    # V5 P0-01: `--smoke-test` always wins over `--max-tokens`. The
    # rationale is operator safety — a cheap dry-run must never get
    # promoted into a long-context spend by an unrelated default. The
    # opposite collision (an explicit large `--max-tokens` plus
    # `--smoke-test`) is a misconfiguration: prefer the smaller budget
    # so the test does not silently swap into a real call.
    effective_max_tokens = (
        SMOKE_TEST_MAX_TOKENS if args.smoke_test else int(args.max_tokens)
    )

    if args.routing_purpose == "promotion" and not args.task_type:
        _emit_structured_error(
            "cannot-run: promotion-routing-needs-task-type",
            detail=(
                "Pass --task-type so dispatch can check provider precision "
                "before allowing promotion-grade model output."
            ),
        )
        return EXIT_CANNOT_RUN

    prompt_path = pathlib.Path(args.prompt_file)
    if not prompt_path.is_file():
        _emit_structured_error(
            "cannot-run: prompt-file-missing",
            prompt_file=str(prompt_path),
        )
        return EXIT_CANNOT_RUN

    # Consent gate — MUST be enforced before any urlopen call below.
    network_consent_source = _network_consent_source(
        args.operator_live_network_consent
    )
    if network_consent_source is None:
        _emit_structured_error(
            "cannot-run: no-consent",
            detail=(
                "Pass --operator-live-network-consent, set "
                "AUDITOOOR_LLM_NETWORK_CONSENT=1, or set "
                "ADVERSARIAL_LIVE_CONSENT=1 to permit outbound network calls."
            ),
        )
        return EXIT_CANNOT_RUN

    # PR #535 — mandatory dispatch-preflight gate. If the caller supplied
    # `--task-type` matching one of the 5 expensive task types, we refuse
    # the dispatch unless either:
    #   (a) the call came through tools/dispatch-preflight.py (which
    #       sets AUDITOOOR_DISPATCH_PREFLIGHT_OK=<task-type>), OR
    #   (b) the operator explicitly set BYPASS_DISPATCH_PREFLIGHT=1.
    # Both paths are audited by dispatch-preflight.py when used as the
    # entry point. Direct invocation without either env is the only path
    # that gets rejected here.
    _MANDATORY_TASK_TYPES = (
        "source-extract",
        "factory-config-liveness-extraction",
        "adversarial-kill",
        "factory-config-liveness-kill",
        "harness-plan",
        "fixture-map",
        "paste-ready-review",
    )
    if (args.task_type or "").strip() in _MANDATORY_TASK_TYPES:
        preflight_ok = (
            os.environ.get("AUDITOOOR_DISPATCH_PREFLIGHT_OK", "").strip()
            == args.task_type
        )
        bypass = os.environ.get("BYPASS_DISPATCH_PREFLIGHT", "").strip() == "1"
        bypass_reason = os.environ.get(
            "BYPASS_DISPATCH_PREFLIGHT_REASON", ""
        ).strip()
        if bypass and not bypass_reason:
            _emit_structured_error(
                "cannot-run: dispatch-preflight-bypass-reason-required",
                task_type=args.task_type,
                detail=(
                    "BYPASS_DISPATCH_PREFLIGHT=1 requires "
                    "BYPASS_DISPATCH_PREFLIGHT_REASON=<text> so emergency "
                    "provider dispatches remain auditable."
                ),
            )
            return EXIT_CANNOT_RUN
        if not (preflight_ok or bypass):
            _emit_structured_error(
                "cannot-run: dispatch-preflight-required",
                task_type=args.task_type,
                detail=(
                    f"task-type '{args.task_type}' requires going through "
                    "tools/dispatch-preflight.py (PR #535). Use `make "
                    "dispatch-preflight TEMPLATE=<name> PROMPT=<file>`, "
                    "or set BYPASS_DISPATCH_PREFLIGHT=1 with "
                    "BYPASS_DISPATCH_PREFLIGHT_REASON=<text> for "
                    "audited emergency override."
                ),
            )
            return EXIT_CANNOT_RUN

    # Resolve provider chain.
    chain, explicit_name = _resolve_provider_chain(args.provider, args.model)
    if not chain:
        if explicit_name is not None:
            _emit_structured_error(
                "cannot-run: no-api-key",
                provider=explicit_name,
            )
        else:
            _emit_structured_error(
                "cannot-run: no-api-key",
                detail="auto mode found no provider API keys in env",
            )
        return EXIT_CANNOT_RUN

    try:
        prompt_text = prompt_path.read_text(encoding="utf-8")
    except OSError as e:
        _emit_structured_error("error: prompt-read-failed", detail=str(e))
        return EXIT_ERROR

    # V5-P0-22 strategic-LLM policy gate. Refuse before any network call
    # if the prompt looks strategic and the operator did not opt in. This
    # is intentionally before audit-dir setup so the refusal is uniform
    # regardless of which provider would have been used. The matched
    # heuristic is surfaced in the structured error so operators can see
    # which substring tripped the gate and decide whether to add the
    # `--strategic-llm-allowed` override or rephrase the prompt.
    if not args.strategic_llm_allowed:
        matched = _detect_strategic_prompt(prompt_text)
        if matched is not None:
            _emit_structured_error(
                "cannot-run: strategic-llm-disallowed",
                matched_marker=matched,
                detail=(
                    "prompt contains a strategic-output marker; pass "
                    "--strategic-llm-allowed to override (see "
                    "docs/STRATEGIC_LLM_POLICY.md)."
                ),
            )
            return EXIT_CANNOT_RUN

    audit_dir = (
        pathlib.Path(args.audit_dir).resolve()
        if args.audit_dir
        else pathlib.Path("agent_outputs").resolve()
    )

    # Budget-guard wiring (V5-P0-03 default-on, V4 plan §A measurement):
    # by default, dispatch consults the per-provider rolling-window
    # budget before each provider attempt and records token usage on
    # success. The guard is constructed lazily on first use and cached
    # for the rest of this invocation. Operators can opt out by setting
    # `AUDITOOOR_LLM_BUDGET_GUARD=0` — that path emits a loud stderr
    # warn line and stamps `budget_guard_disabled: true` on each audit
    # record so the operator decision is visible downstream.
    budget_guard_enabled = _is_budget_guard_enabled()
    budget_guard_disabled_flag = not budget_guard_enabled
    if budget_guard_disabled_flag:
        _emit_budget_guard_disabled_warning()
    budget_guard = None  # constructed lazily on first opt-in use

    last_fatal: str | None = None
    last_fatal_provider: str | None = None
    fallback_reasons: list[str] = []
    for cfg in chain:
        # Foot-gun #13d (queue iter 17): when the caller flagged the input
        # as truncated AND we're routing to MiniMax, prepend the
        # absence-hallucination notice so MiniMax doesn't fabricate
        # "missing file" findings based on what isn't visible in the
        # truncated diff. Done per-provider so the auto-mode chain still
        # only modifies the prompt on the MiniMax hop.
        user_content = prompt_text
        if args.input_is_truncated and cfg["name"] == "minimax":
            user_content = MINIMAX_TRUNCATION_NOTICE + "\n\n" + prompt_text

        current_routing_status = _routing_decision(cfg["name"], args.task_type)
        if (
            args.routing_purpose == "promotion"
            and current_routing_status is not None
            and current_routing_status.get("advisory_only")
        ):
            reason = current_routing_status.get("reason", "advisory-only")
            fallback_reasons.append(
                f"{cfg['name']}: routing-skip: {reason}"
            )
            audit_path_str = None
            try:
                audit_path = _write_audit_trail(
                    audit_dir,
                    provider=cfg["name"],
                    model=cfg["model"],
                    api_url_host=_hostname_from_url(cfg["api_url"]),
                    prompt_file=prompt_path,
                    response_length=0,
                    http_status=0,
                    retry_count=0,
                    timing_ms=0,
                    outcome=f"routing-skip: {reason}",
                    budget_guard_disabled=budget_guard_disabled_flag,
                    task_type=args.task_type,
                    routing_status=current_routing_status,
                    network_consent_source=network_consent_source,
                )
                audit_path_str = str(audit_path)
            except Exception:
                pass
            _maybe_record_campaign_dispatch(
                provider=cfg["name"],
                model=cfg["model"],
                tokens_used=0,
                outcome=f"hold: routing-skip: {reason}",
                audit_path=audit_path_str,
                budget_guard_disabled=budget_guard_disabled_flag,
            )
            continue

        # Pre-call budget gate. Only consulted when the env var is set.
        # Lazy-construct on first hop where gating is enabled. When the
        # guard module is unavailable (graceful degradation) we proceed
        # without gating — the structured warn was already written by
        # `_load_budget_guard_module`.
        if budget_guard_enabled and budget_guard is None:
            budget_guard = _maybe_make_budget_guard()
        if budget_guard_enabled and budget_guard is not None:
            try:
                allowed, reason = budget_guard.may_call(
                    cfg["name"], soft=False
                )
            except KeyError:
                # Provider not in budget config (e.g. "anthropic" while
                # the config only knows kimi/minimax/claude/codex). Treat
                # as "no budget configured for this provider" and let
                # the call through without recording — symmetrical to
                # the graceful-degradation contract above. A structured
                # warn lets operators notice and update their config.
                sys.stderr.write(json.dumps({
                    "warn": (
                        "budget-guard-skip-unknown-provider: "
                        f"{cfg['name']}"
                    )
                }) + "\n")
                sys.stderr.flush()
                allowed, reason = True, None
            if not allowed:
                # Budget exhausted — synthesize a fallback hop so auto
                # mode tries the next provider and explicit mode emits
                # a clean error. Status 429 is the closest semantic
                # match (over-quota) and matches the spec.
                timing_ms = 0
                fallback_reasons.append(
                    f"{cfg['name']}: budget-skip: {reason}"
                )
                audit_path_str: str | None = None
                try:
                    audit_path = _write_audit_trail(
                        audit_dir,
                        provider=cfg["name"],
                        model=cfg["model"],
                        api_url_host=_hostname_from_url(cfg["api_url"]),
                        prompt_file=prompt_path,
                        response_length=0,
                        http_status=429,
                        retry_count=0,
                        timing_ms=timing_ms,
                        outcome=f"budget-skip: {reason}",
                        budget_guard_disabled=budget_guard_disabled_flag,
                        task_type=args.task_type,
                        routing_status=current_routing_status,
                        network_consent_source=network_consent_source,
                    )
                    audit_path_str = str(audit_path)
                except Exception:
                    pass
                # Campaign telemetry: budget-skip is a "hold" outcome —
                # we record it so the report can surface that the gate
                # actually fired (Codex test #1: budget-guard cannot
                # silently disable).
                _maybe_record_campaign_dispatch(
                    provider=cfg["name"],
                    model=cfg["model"],
                    tokens_used=0,
                    outcome=f"budget-skip: {reason}",
                    audit_path=audit_path_str,
                    budget_guard_disabled=budget_guard_disabled_flag,
                )
                continue  # try next provider in chain (or exhaust)

        # DEEPSEEK-INTEGRATION-CORE (2026-05-26): mock-mode short-circuit.
        # R36 pathspec: lane-DEEPSEEK-INTEGRATION-CORE entry in
        # agent_pathspec.json. When --mock is passed (or
        # AUDITOOOR_DEEPSEEK_MOCK=1 is set), skip the network call and
        # emit a synthetic Anthropic-compatible response. The audit
        # record carries outcome=ok-mocked + mock_mode=true so consumers
        # can filter it out of cost / capacity calculations.
        mock_active = bool(getattr(args, "mock", False)) or (
            os.environ.get(DEEPSEEK_MOCK_ENV_VAR, "").strip() == "1"
        )
        if mock_active:
            t_start = time.monotonic()
            synthetic_text = (
                f"[mock-mode {cfg['name']}/{cfg['model']}] "
                "Synthetic dispatch response; no live API call was made. "
                "Set --mock=false (omit flag) + ensure DEEPSEEK_API_KEY "
                "has positive balance for a real call."
            )
            sys.stdout.write(synthetic_text + "\n")
            sys.stdout.flush()
            timing_ms = int((time.monotonic() - t_start) * 1000)
            cost_estimate = None
            if cfg["name"] in _DEEPSEEK_PRICING_USD_PER_M_TOKENS:
                # Mock-mode cost estimate uses input_tokens ~ char/4
                # heuristic so the budget tracker can still rehearse
                # cap-vs-actual without a live call.
                est_input_tokens = max(0, len(prompt_text) // 4)
                est_output_tokens = max(0, len(synthetic_text) // 4)
                cost_estimate = _deepseek_cost_estimate(
                    provider=cfg["name"],
                    input_tokens=est_input_tokens,
                    output_tokens=est_output_tokens,
                )
            audit_path_str = None
            try:
                audit_path = _write_audit_trail(
                    audit_dir,
                    provider=cfg["name"],
                    model=cfg["model"],
                    api_url_host=_hostname_from_url(cfg["api_url"]),
                    prompt_file=prompt_path,
                    response_length=len(synthetic_text),
                    http_status=200,
                    retry_count=0,
                    timing_ms=timing_ms,
                    outcome="ok-mocked",
                    budget_guard_disabled=budget_guard_disabled_flag,
                    task_type=args.task_type,
                    routing_status=current_routing_status,
                    network_consent_source=network_consent_source,
                    verification_tier=DEFAULT_VERIFICATION_TIER,
                    verified_by=args.verified_by,
                    cost_estimate=cost_estimate,
                    mock_mode=True,
                    tokens_used=0,
                )
                audit_path_str = str(audit_path)
            except Exception as e:
                sys.stderr.write(json.dumps({
                    "warn": f"audit-write-failed-mock: {e}"
                }) + "\n")
            _maybe_record_campaign_dispatch(
                provider=cfg["name"],
                model=cfg["model"],
                tokens_used=0,
                outcome="ok-mocked",
                audit_path=audit_path_str,
                budget_guard_disabled=budget_guard_disabled_flag,
            )
            return EXIT_OK

        body = _build_messages_body(
            cfg,
            max_tokens=effective_max_tokens,
            user_content=user_content,
        )
        body_bytes = json.dumps(body).encode("utf-8")
        t_start = time.monotonic()
        try:
            text, http_status, retry_count, tokens_used = (
                _call_once_with_fallback_classification(
                    cfg,
                    body_bytes,
                    timeout=args.timeout,
                    retry_on_429=args.retry_on_429,
                )
            )
        except ProviderFallback as pf:
            timing_ms = int((time.monotonic() - t_start) * 1000)
            fallback_reasons.append(f"{cfg['name']}: {pf.reason}")
            audit_path_str = None
            try:
                audit_path = _write_audit_trail(
                    audit_dir,
                    provider=cfg["name"],
                    model=cfg["model"],
                    api_url_host=_hostname_from_url(cfg["api_url"]),
                    prompt_file=prompt_path,
                    response_length=0,
                    http_status=pf.status,
                    retry_count=0,
                    timing_ms=timing_ms,
                    outcome=f"fallback: {pf.reason}",
                    budget_guard_disabled=budget_guard_disabled_flag,
                    task_type=args.task_type,
                    routing_status=current_routing_status,
                    network_consent_source=network_consent_source,
                )
                audit_path_str = str(audit_path)
            except Exception:
                pass
            # Campaign telemetry: ProviderFallback covers transport
            # errors (incl. PR #285's TimeoutError classification) — we
            # record it as a hold artifact rather than a successful
            # dispatch (Codex test #2: provider timeout creates a hold,
            # not success).
            _maybe_record_campaign_dispatch(
                provider=cfg["name"],
                model=cfg["model"],
                tokens_used=0,
                outcome=f"hold: {pf.reason}",
                audit_path=audit_path_str,
                budget_guard_disabled=budget_guard_disabled_flag,
            )
            continue  # try next provider in chain
        except RuntimeError as e:
            # Hard failure — do NOT fall back.
            timing_ms = int((time.monotonic() - t_start) * 1000)
            last_fatal = str(e)
            last_fatal_provider = cfg["name"]
            audit_path_str = None
            try:
                audit_path = _write_audit_trail(
                    audit_dir,
                    provider=cfg["name"],
                    model=cfg["model"],
                    api_url_host=_hostname_from_url(cfg["api_url"]),
                    prompt_file=prompt_path,
                    response_length=0,
                    http_status=0,
                    retry_count=0,
                    timing_ms=timing_ms,
                    outcome=f"error: {e}",
                    budget_guard_disabled=budget_guard_disabled_flag,
                    task_type=args.task_type,
                    routing_status=current_routing_status,
                    network_consent_source=network_consent_source,
                )
                audit_path_str = str(audit_path)
            except Exception:
                pass
            _maybe_record_campaign_dispatch(
                provider=cfg["name"],
                model=cfg["model"],
                tokens_used=0,
                outcome=f"error: {e}",
                audit_path=audit_path_str,
                budget_guard_disabled=budget_guard_disabled_flag,
            )
            break

        # Success — audit + emit + return.
        # DEEPSEEK-INTEGRATION-CORE (R36 pathspec lane-DEEPSEEK-INTEGRATION-
        # CORE in agent_pathspec.json): for DeepSeek providers, compute the
        # per-call cost estimate from the recovered tokens_used and stamp it
        # into the audit record so the rolling $100/mo cap + $80 alert in
        # tools/provider-capacity-report.py can be computed without
        # re-parsing prompts.
        timing_ms = int((time.monotonic() - t_start) * 1000)
        live_cost_estimate = None
        if cfg["name"] in _DEEPSEEK_PRICING_USD_PER_M_TOKENS:
            # The dispatch path returns tokens_used as the sum input+output.
            # We don't have a clean split here without parsing the provider
            # response, but tokens_used is treated as the upper-bound and
            # billed under the cache-miss rate for safety. cache_hit
            # accounting requires the provider response to expose a
            # `cache_read_input_tokens` field; until that wiring lands we
            # treat all input as cache-miss.
            try:
                inferred_input = max(0, int(tokens_used) - len(text) // 4)
                inferred_output = max(0, len(text) // 4)
            except Exception:
                inferred_input = int(tokens_used or 0)
                inferred_output = 0
            live_cost_estimate = _deepseek_cost_estimate(
                provider=cfg["name"],
                input_tokens=inferred_input,
                output_tokens=inferred_output,
            )
        audit_path_str = None
        try:
            audit_path = _write_audit_trail(
                audit_dir,
                provider=cfg["name"],
                model=cfg["model"],
                api_url_host=_hostname_from_url(cfg["api_url"]),
                prompt_file=prompt_path,
                response_length=len(text),
                http_status=http_status,
                retry_count=retry_count,
                timing_ms=timing_ms,
                outcome="ok",
                budget_guard_disabled=budget_guard_disabled_flag,
                task_type=args.task_type,
                routing_status=current_routing_status,
                network_consent_source=network_consent_source,
                verification_tier=DEFAULT_VERIFICATION_TIER,
                verified_by=args.verified_by,
                cost_estimate=live_cost_estimate,
                mock_mode=False,
                tokens_used=int(tokens_used),
            )
            audit_path_str = str(audit_path)
        except Exception as e:
            # Audit write is best-effort; it must not break stdout delivery.
            sys.stderr.write(json.dumps({"warn": f"audit-write-failed: {e}"}) + "\n")

        # Campaign telemetry hook on success (V5 PR 6).
        _maybe_record_campaign_dispatch(
            provider=cfg["name"],
            model=cfg["model"],
            tokens_used=int(tokens_used),
            outcome="ok",
            audit_path=audit_path_str,
            budget_guard_disabled=budget_guard_disabled_flag,
        )

        # Post-call budget accounting. Recorded AFTER the audit write so
        # an audit-write failure does not also break budget tracking.
        # `record_call` raises KeyError on unknown providers (mirrors
        # the may_call code path); we swallow it the same way and emit
        # a structured warn so the missed accounting is visible.
        if budget_guard_enabled and budget_guard is not None:
            try:
                budget_guard.record_call(
                    cfg["name"], tokens_used, success=True
                )
            except KeyError:
                sys.stderr.write(json.dumps({
                    "warn": (
                        "budget-guard-skip-unknown-provider: "
                        f"{cfg['name']}"
                    )
                }) + "\n")
                sys.stderr.flush()
            except Exception as e:
                # record_call writes to disk; never let a write failure
                # break stdout delivery. Surface a structured warn.
                sys.stderr.write(json.dumps({
                    "warn": f"budget-record-failed: {e}"
                }) + "\n")
                sys.stderr.flush()

        sys.stdout.write(text)
        sys.stdout.flush()
        return EXIT_OK

    # All providers tried.
    if last_fatal is not None:
        _emit_structured_error(
            "error: dispatch-failed",
            provider=last_fatal_provider,
            detail=last_fatal,
        )
        return EXIT_ERROR
    if fallback_reasons and all("routing-skip:" in r for r in fallback_reasons):
        # The seed calibration matrix (reference/llm_calibration_seed.json)
        # may emit two refusal classes that are now first-class in the
        # routing helper: ``cannot-route: insufficient-data`` (row exists
        # but sample_count is below the seed threshold or precision_pct
        # is the literal sentinel) and ``cannot-route: no-calibration``
        # (no row for this provider × task_type). Both paths surface here
        # via fallback_reasons. We pass them through so callers can see
        # whether the lane is missing entirely or simply not yet measured.
        _emit_structured_error(
            "cannot-run: advisory-only-routing",
            detail=(
                "promotion-grade dispatch refused because no resolved "
                "provider has enough verified precision for this task type "
                "(includes seed-driven cannot-route: insufficient-data and "
                "cannot-route: no-calibration refusals)"
            ),
            fallback_reasons=fallback_reasons,
        )
        return EXIT_CANNOT_RUN
    _emit_structured_error(
        "error: dispatch-failed",
        detail="all providers exhausted",
        fallback_reasons=fallback_reasons,
    )
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
