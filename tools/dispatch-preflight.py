#!/usr/bin/env python3
"""dispatch-preflight.py — MANDATORY pre-dispatch validator + dispatcher.

PR #535 (Wave 8 §8 — "Provider Dispatch Becomes Mandatory For Expensive
Model Work"). Closes the gap left open by PR #531 (ZZ2): that PR shipped
``tools/dispatch-template.py`` + 5 templates + ``make dispatch-validate``,
but validation remained OPTIONAL — operators could (and did) dispatch
sloppy prompts to Kimi/Minimax without going through the validator.

This tool is a **wrapper** that turns validation into a hard gate for
the 5 expensive task types:

  - ``source-extract``       (Kimi long-context source/spec mining)
  - ``adversarial-kill``     (Minimax FP/dupe/OOS killer)
  - ``harness-plan``         (Plan harness before writing code)
  - ``fixture-map``          (Kimi invariant -> fixture map)
  - ``paste-ready-review``   (Minimax pre-submission review)

Behaviour
---------

1. Load the named template via ``dispatch-template.py``'s ``load_template``.
2. Run ``validate_prompt`` against the candidate prompt file.
3. If validation FAILS:
     * Emit a loud, clearly-formatted refusal to stderr (every missing
       required input + the template's refusal_message + the
       template-level refusal_rules).
     * Do NOT dispatch.
     * Append a ``status: REFUSED`` row to the workspace audit log.
     * Exit non-zero (``1``).
4. If validation PASSES:
     * Shell out to ``tools/llm-dispatch.py --prompt-file <prompt> ...``,
       passing through ``--task-type`` as the template name by default
       (or a compatible calibration sublane such as
       ``factory-config-liveness-extraction``) so the calibration ledger
       learns provider × task-type performance.
     * Append a ``status: DISPATCHED`` row to the workspace audit log
       carrying the prompt-hash, template id, provider output path, and
       dispatch return-code.
     * Exit with the dispatch return-code.
5. ``BYPASS_DISPATCH_PREFLIGHT=1`` is an emergency override:
     * Skips the validator (still LOADS the template so the audit log
       knows which one was bypassed).
     * Dispatches directly via ``tools/llm-dispatch.py``.
     * Appends a ``status: BYPASSED`` row with the bypass reason.
     * Loud stderr warning.
     * The bypass is itself audited — there is no silent path.

Audit log shape (JSONL, one row per dispatch attempt)
-----------------------------------------------------

Each row contains:

```
{
  "ts": "2026-04-29T12:34:56.789Z",
  "tool": "dispatch-preflight.py",
  "template_id": "source-extract",
  "prompt_path": "/abs/path/to/prompt.md",
  "prompt_sha256": "<64 hex chars>",
  "status": "DISPATCHED" | "REFUSED" | "BYPASSED" | "ERROR",
  "missing_inputs": [<input names>] (only on REFUSED),
  "bypass_reason": "<from env>" (only on BYPASSED),
  "provider_output_path": "/abs/path/to/output.txt" (only on DISPATCHED/BYPASSED),
  "dispatch_rc": <int> (only on DISPATCHED/BYPASSED),
  "dispatcher": "tools/llm-dispatch.py",
  "argv": [...]  # the full argv handed to the underlying dispatcher
}
```

Audit log path
--------------

``<workspace>/.auditooor/dispatch_audit.jsonl`` — created on first write.
The workspace is determined in this priority order:

  1. ``--workspace`` CLI flag
  2. ``AUDITOOOR_WORKSPACE`` env var
  3. The current working directory (last resort; emits a stderr warning)

Operators MAY override the audit path via ``--audit-log <path>``.

Mock-friendly
-------------

For tests, ``--mock-dispatcher <cmd>`` is forwarded as the dispatcher
binary instead of ``tools/llm-dispatch.py``. The wrapper logs the same
JSONL row regardless. This is the path used by
``tools/tests/test_dispatch_preflight.py`` so we never burn real tokens
in CI.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DISPATCH_TEMPLATE_PATH = REPO_ROOT / "tools" / "dispatch-template.py"
DEFAULT_DISPATCHER = REPO_ROOT / "tools" / "llm-dispatch.py"
TEMPLATE_DIR = REPO_ROOT / "reference" / "dispatch-templates"
IMPACT_MAPPING_LIB_PATH = REPO_ROOT / "tools" / "lib" / "program_impact_mapping.py"
PREBRIEFING_WRAPPER_PATH = (
    REPO_ROOT / "tools" / "dispatch-agent-with-prebriefing.py"
)
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from lib.mcp_evidence_receipt import validate_receipt_file  # noqa: E402

EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_USAGE = 2
EXIT_ERROR = 3
CANDIDATE_JUDGMENT_SCHEMA = "auditooor.candidate_judgment_packet.v1"
HIGH_CRITICAL_SEVERITIES = {"high", "critical"}

# Five mandatory templates. These match the YAML template names in
# reference/dispatch-templates/. Compatible calibration sublanes can reuse
# these templates through TASK_TYPE_TEMPLATE_ALIASES below.
MANDATORY_TASK_TYPES = (
    "source-extract",
    "adversarial-kill",
    "harness-plan",
    "fixture-map",
    "paste-ready-review",
)

# Calibration-only aliases that deliberately reuse an existing prompt
# template. The template controls input validation; the task type controls
# provider-routing/calibration accounting in llm-dispatch.py.
TASK_TYPE_TEMPLATE_ALIASES = {
    # Historical calibration rows and llm-calibration-log.py use
    # "source-extraction"; the mandatory dispatch template is named
    # "source-extract". Keep both accepted so provider-assist loops can use the
    # canonical calibration bucket without bypassing preflight.
    "source-extraction": "source-extract",
    "factory-config-liveness-extraction": "source-extract",
    "factory-config-liveness-kill": "adversarial-kill",
}

# Explicitly allowed pre-contract task types. These lanes exist to discover or
# lock scope/impact, so requiring an already-proved impact contract would be a
# circular gate.
IMPACT_CONTRACT_EXEMPT_TASK_TYPES = (
    "scope_only",
    "impact_analysis",
)

CONTRACT_ALWAYS_REQUIRED_TASK_TYPES = (
    "harness-plan",
    "fixture-map",
    "paste-ready-review",
)

BYPASS_ENV_VAR = "BYPASS_DISPATCH_PREFLIGHT"
BYPASS_REASON_ENV_VAR = "BYPASS_DISPATCH_PREFLIGHT_REASON"
WORKSPACE_ENV_VAR = "AUDITOOOR_WORKSPACE"
# Env-var fallbacks for High/Critical judgment-bundle gate.
# The v3-provider-fanout-runner.py builds dispatch-preflight CLI commands
# per queue row via _build_command() and passes them to subprocess; it does
# not (and should not) parse severity from row fields itself.  Instead the
# coordinator wires these two env vars into _make_child_env() so that the
# gate fires even when --severity / --require-local-judgment-bundle are not
# on the CLI.  dispatch-preflight reads the env fallback ONLY if the
# corresponding CLI flag is absent, preserving backward-compat with callers
# that always pass both CLI flags.
DISPATCH_SEVERITY_ENV_VAR = "AUDITOOOR_DISPATCH_SEVERITY"
LOCAL_JUDGMENT_BUNDLE_ENV_VAR = "AUDITOOOR_LOCAL_JUDGMENT_BUNDLE"
# Lane 12 (Wave-6, 2026-05-19) — fail-closed MCP context prerequisites gate.
# When --require-mcp-context is passed, dispatch is refused unless a fresh
# context pack receipt is present in <workspace>/.auditooor/last_mcp_recall.json
# (written by vault-mcp-server.py --call vault_resume_context) with
# recall_ts within MCP_CONTEXT_FRESHNESS_WINDOW_SECONDS, OR the explicit
# bypass env var MCP_CONTEXT_BYPASS=1 is set with a reason.
MCP_CONTEXT_BYPASS_ENV_VAR = "MCP_CONTEXT_BYPASS"
MCP_CONTEXT_BYPASS_REASON_ENV_VAR = "MCP_CONTEXT_BYPASS_REASON"
MCP_CONTEXT_FRESHNESS_WINDOW_SECONDS = 3600  # 1 hour


def _check_mcp_context_prerequisites(
    workspace: pathlib.Path,
) -> Tuple[bool, Optional[str]]:
    """Lane 12: Check that a fresh MCP context pack receipt is present.

    Returns (ok, error_message).  ok=True means dispatch may proceed.
    error_message is set when ok=False, describing what is missing and how
    to fix it.

    The receipt file is ``<workspace>/.auditooor/last_mcp_recall.json``
    written by ``vault-mcp-server.py --call vault_resume_context``.  It must
    contain a ``recall_ts`` (UNIX timestamp) within
    MCP_CONTEXT_FRESHNESS_WINDOW_SECONDS of now.
    """
    receipt_path = workspace / ".auditooor" / "last_mcp_recall.json"
    if not receipt_path.is_file():
        return (
            False,
            (
                f"MCP context receipt not found at {receipt_path}. "
                "Run the Layer-1 recall sequence first:\n"
                "  python3 tools/vault-mcp-server.py --call vault_resume_context "
                "--args '{\"workspace_path\":\"<ws>\"}'\n"
                "Or bypass: MCP_CONTEXT_BYPASS=1 "
                "MCP_CONTEXT_BYPASS_REASON=<reason>"
            ),
        )
    try:
        data = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return (
            False,
            f"MCP context receipt at {receipt_path} could not be parsed: {exc}. "
            "Re-run vault_resume_context to refresh it.",
        )
    recall_ts = data.get("recall_ts")
    if not isinstance(recall_ts, (int, float)):
        return (
            False,
            f"MCP context receipt at {receipt_path} is missing recall_ts field. "
            "Re-run vault_resume_context to refresh it.",
        )
    age_seconds = datetime.datetime.now(datetime.timezone.utc).timestamp() - float(recall_ts)
    if age_seconds > MCP_CONTEXT_FRESHNESS_WINDOW_SECONDS:
        age_min = int(age_seconds / 60)
        return (
            False,
            (
                f"MCP context receipt at {receipt_path} is stale "
                f"({age_min}m old, limit {MCP_CONTEXT_FRESHNESS_WINDOW_SECONDS // 60}m). "
                "Re-run vault_resume_context:\n"
                "  python3 tools/vault-mcp-server.py --call vault_resume_context "
                "--args '{\"workspace_path\":\"<ws>\"}'\n"
                "Or bypass: MCP_CONTEXT_BYPASS=1 MCP_CONTEXT_BYPASS_REASON=<reason>"
            ),
        )
    return True, None


def _check_mcp_evidence_receipt_path(
    receipt_arg: str,
    workspace: pathlib.Path,
) -> Tuple[bool, Optional[str]]:
    raw = pathlib.Path(receipt_arg).expanduser()
    receipt_path = raw if raw.is_absolute() else workspace / raw
    workspace_resolved = workspace.expanduser().resolve(strict=False)
    receipt_path = receipt_path.resolve(strict=False)
    try:
        receipt_path.relative_to(workspace_resolved)
    except ValueError:
        return (
            False,
            (
                f"MCP evidence receipt path is outside workspace: {receipt_path}. "
                "Use a sidecar under <workspace>/.auditooor/worker_packets/."
            ),
        )
    ok, errors, _receipt = validate_receipt_file(receipt_path, workspace=workspace_resolved)
    if not ok:
        return (
            False,
            (
                f"MCP evidence receipt at {receipt_path} is invalid: "
                + ", ".join(errors)
                + ". Build one with: make v3-worker-packet WS=<workspace> SEVERITY=High STRICT=1"
            ),
        )
    return True, None


def _check_local_judgment_bundle_path(
    bundle_arg: str,
    workspace: pathlib.Path,
) -> Tuple[bool, Optional[str]]:
    raw = pathlib.Path(bundle_arg).expanduser()
    bundle_path = raw if raw.is_absolute() else workspace / raw
    workspace_resolved = workspace.expanduser().resolve(strict=False)
    bundle_path = bundle_path.resolve(strict=False)
    try:
        bundle_path.relative_to(workspace_resolved)
    except ValueError:
        return (
            False,
            (
                f"Local judgment bundle path is outside workspace: {bundle_path}. "
                "Use <workspace>/.auditooor/prove_top_leads_candidate_judgment_packet.json."
            ),
        )
    try:
        payload = json.loads(bundle_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False, f"Local judgment bundle not found: {bundle_path}"
    except json.JSONDecodeError as exc:
        return False, f"Local judgment bundle at {bundle_path} is not valid JSON: {exc}"
    except OSError as exc:
        return False, f"Local judgment bundle at {bundle_path} could not be read: {exc}"

    if not isinstance(payload, dict):
        return False, f"Local judgment bundle at {bundle_path} must be a JSON object"
    schema = str(payload.get("schema") or "").strip()
    if schema != CANDIDATE_JUDGMENT_SCHEMA:
        return (
            False,
            (
                f"Local judgment bundle at {bundle_path} has schema {schema!r}; "
                f"expected {CANDIDATE_JUDGMENT_SCHEMA!r}."
            ),
        )
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    if summary.get("strict_poc_planning_allowed") is not True:
        return (
            False,
            (
                f"Local judgment bundle at {bundle_path} does not allow strict PoC planning. "
                "Run make prove-top-leads and resolve candidate judgment blockers first."
            ),
        )
    packets_emitted = summary.get("packets_emitted")
    if not isinstance(packets_emitted, int) or packets_emitted <= 0:
        return (
            False,
            f"Local judgment bundle at {bundle_path} emitted no candidate packets.",
        )
    strict_blockers = payload.get("strict_blockers")
    if strict_blockers:
        return (
            False,
            f"Local judgment bundle at {bundle_path} has strict_blockers; resolve them before dispatch.",
        )
    return True, None


def _severity_requires_local_judgment_bundle(severity: Optional[str]) -> bool:
    return str(severity or "").strip().lower() in HIGH_CRITICAL_SEVERITIES


def _prompt_claims_direct_submit(text: str) -> bool:
    lowered = text.lower()
    return any(
        token in lowered
        for token in (
            "in_scope_direct_submit",
            "direct-submit",
            "direct submit",
            "submit-ready",
            "submit ready",
            "paste-ready",
            "paste ready",
        )
    )


def _load_impact_mapping_lib():
    spec = importlib.util.spec_from_file_location(
        "dispatch_preflight_impact_mapping", IMPACT_MAPPING_LIB_PATH
    )
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    try:
        sys.modules["dispatch_preflight_impact_mapping"] = module
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    except Exception:
        sys.modules.pop("dispatch_preflight_impact_mapping", None)
        return None
    return module


def _load_dispatch_template_module():
    """Load tools/dispatch-template.py as a module (the file has a hyphen)."""
    spec = importlib.util.spec_from_file_location(
        "dispatch_template_module", DISPATCH_TEMPLATE_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"could not load {DISPATCH_TEMPLATE_PATH} — preflight depends on it"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _utc_now_iso() -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        now.strftime("%Y-%m-%dT%H:%M:%S.")
        + f"{now.microsecond // 1000:03d}Z"
    )


# Lane-7 GAP-2 fix: resolve a best-effort model name for the dispatch audit
# row without importing llm-dispatch.py (which would pull in its heavy deps).
# We mirror the same env-var logic llm-dispatch.py uses at runtime so the
# audit row is populated for any non-"auto" provider.  When provider is "auto"
# or unresolvable, we write "unknown" explicitly rather than omitting the key.
_DISPATCH_DEFAULT_MODELS: Dict[str, str] = {
    "kimi": "kimi-for-coding",
    "minimax": "MiniMax-M2.7",
    "anthropic": "claude-opus-4-5",
}
_DISPATCH_MODEL_ENV_VARS: Dict[str, str] = {
    "kimi": "KIMI_MODEL",
    "minimax": "MINIMAX_MODEL",
    "anthropic": "ANTHROPIC_MODEL",
}


def _resolve_model_hint(provider: Optional[str]) -> str:
    """Return a best-effort model ID for the audit row.

    Mirrors the env-var resolution in ``tools/llm-dispatch.py`` without
    importing it. Returns ``"unknown"`` when the provider is ``"auto"`` or
    not in the known-providers list, so the audit key is always present.
    """
    if not provider or provider.lower() in ("", "auto"):
        return "unknown"
    p = provider.lower()
    env_var = _DISPATCH_MODEL_ENV_VARS.get(p)
    if env_var:
        resolved = os.environ.get(env_var, "").strip()
        if resolved:
            return resolved
    default = _DISPATCH_DEFAULT_MODELS.get(p)
    if default:
        return default
    return "unknown"


def _sha256_of_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _resolve_workspace(cli_value: Optional[str]) -> Tuple[pathlib.Path, str]:
    """Return (workspace, source) where source is one of cli|env|cwd."""
    if cli_value:
        return pathlib.Path(cli_value).expanduser().resolve(), "cli"
    env_val = os.environ.get(WORKSPACE_ENV_VAR)
    if env_val:
        return pathlib.Path(env_val).expanduser().resolve(), "env"
    return pathlib.Path.cwd().resolve(), "cwd"


def _audit_log_path(workspace: pathlib.Path, override: Optional[str]) -> pathlib.Path:
    if override:
        return pathlib.Path(override).expanduser().resolve()
    return workspace / ".auditooor" / "dispatch_audit.jsonl"


def _append_audit_row(audit_path: pathlib.Path, row: Dict) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(row, sort_keys=True, separators=(",", ":"))
    with audit_path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def _print_refusal(template: Dict, missing: List[Dict], prompt_path: pathlib.Path) -> None:
    """Print a loud, formatted refusal to stderr."""
    sys.stderr.write("\n")
    sys.stderr.write("=" * 72 + "\n")
    sys.stderr.write(
        f"DISPATCH REFUSED — prompt {prompt_path} fails template "
        f"'{template['name']}' ({template.get('provider', '?')})\n"
    )
    sys.stderr.write("=" * 72 + "\n")
    sys.stderr.write(f"Missing {len(missing)} required input(s):\n")
    for entry in missing:
        sys.stderr.write(f"  - {entry['input']}: {entry['refusal_message']}\n")
    rules = template.get("refusal_rules", [])
    if rules:
        sys.stderr.write("\nTemplate refusal rules:\n")
        for rule in rules:
            sys.stderr.write(f"  * {rule}\n")
    sys.stderr.write(
        "\nFix the prompt and re-run, or pass BYPASS_DISPATCH_PREFLIGHT=1 "
        "with BYPASS_DISPATCH_PREFLIGHT_REASON=<text> if this is a real\n"
        "emergency (every bypass is audited).\n"
    )
    sys.stderr.write("=" * 72 + "\n\n")


def _build_dispatcher_argv(
    dispatcher: pathlib.Path,
    prompt_path: pathlib.Path,
    template_name: str,
    task_type: str,
    provider: Optional[str],
    extra_args: List[str],
) -> List[str]:
    argv = [
        sys.executable,
        str(dispatcher),
        "--prompt-file",
        str(prompt_path),
        "--task-type",
        task_type,
    ]
    if provider:
        argv += ["--provider", provider]
    if extra_args:
        argv += list(extra_args)
    return argv


# Sentinel env var: when set, ``tools/llm-dispatch.py`` knows the call
# was made via the preflight wrapper and trusts the validation. Any
# direct call to llm-dispatch.py with --task-type in the mandatory set
# must either go through preflight (which sets this) or set the bypass
# env explicitly.
PREFLIGHT_OK_ENV_VAR = "AUDITOOOR_DISPATCH_PREFLIGHT_OK"

# ---------------------------------------------------------------------------
# Phase -1 B / WF-7 #1 (iter18, 2026-05-23) — META-1 auto-invoke.
#
# Background: WF-7 verified that ``dispatch-preflight.py`` at HEAD contained
# ZERO references to ``prebriefing`` or ``vault_dispatch_brief_skeleton``,
# even though HACKERMAN_WORKER_PROMPT_TEMPLATE STEP 1b documented the
# wrapper as if it had shipped here. iter16 FFFFF only wired validation;
# the operator-side prefetch discipline remained the META-1 shelfware trap.
#
# This block adds auto-invoke of ``tools/dispatch-agent-with-prebriefing.py``
# (lane XXXX iter15) when the dispatch is High/Critical severity OR the
# rule set carries R28+ markers. The enriched prompt (Section 15a/15b/15c/15d
# BEGIN/END markers prepended) is what reaches the downstream dispatcher.
#
# Opt-out: --no-prebriefing CLI flag OR AUDITOOOR_DISPATCH_NO_PREBRIEFING=1.
# Default: ON for High/Critical severities.
#
# Failure mode: graceful. If the wrapper import fails, returns None, or
# raises, we audit-log ``prebriefing_status=skipped-error`` with the error
# and dispatch the ORIGINAL prompt (we never block a valid dispatch on a
# prefetch failure — META-1 is best-effort enrichment, not a hard gate).
PREBRIEFING_OPT_OUT_ENV_VAR = "AUDITOOOR_DISPATCH_NO_PREBRIEFING"
PREBRIEFING_AUTO_SEVERITIES = {"high", "critical"}
# Rule markers that force prebriefing regardless of severity. R28+ matches
# any rule of the form R<NN> where NN >= 28 (R28, R29, R30, ... R56, ...).
# These rules are the gates that benefit most from the lane-specific
# skeleton injection (R29 commitment analysis, R43 load-bearing bytes,
# R45 designed-as-intended precheck, etc.).
PREBRIEFING_RULE_AUTO_TRIGGER_RE = re.compile(
    r"\bR(?:2[89]|[3-9][0-9]|[1-9][0-9]{2,})\b"
)


def _load_prebriefing_module():
    """Dynamically load ``tools/dispatch-agent-with-prebriefing.py``.

    Returns the module on success, or None on any import failure. We never
    raise from this function — META-1 prefetch is best-effort.

    The module is cached in ``sys.modules`` under
    ``dispatch_preflight_prebriefing`` so repeat callers (and tests that
    patch attributes on the loaded module) see a stable instance instead
    of a fresh re-execution that resets monkey-patches.
    """
    if not PREBRIEFING_WRAPPER_PATH.is_file():
        return None
    cached = sys.modules.get("dispatch_preflight_prebriefing")
    if cached is not None:
        return cached
    try:
        spec = importlib.util.spec_from_file_location(
            "dispatch_preflight_prebriefing", PREBRIEFING_WRAPPER_PATH
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules["dispatch_preflight_prebriefing"] = module
        spec.loader.exec_module(module)
        return module
    except Exception:
        sys.modules.pop("dispatch_preflight_prebriefing", None)
        return None


def _severity_triggers_prebriefing(severity: Optional[str]) -> bool:
    """Returns True if severity sits at HIGH or CRITICAL (case-insensitive)."""
    return str(severity or "").strip().lower() in PREBRIEFING_AUTO_SEVERITIES


def _prompt_triggers_prebriefing_via_rules(prompt_text: str) -> bool:
    """Returns True if the prompt body cites any R-rule >= R28."""
    if not prompt_text:
        return False
    return bool(PREBRIEFING_RULE_AUTO_TRIGGER_RE.search(prompt_text))


def _should_auto_invoke_prebriefing(
    *,
    severity: Optional[str],
    prompt_text: str,
    no_prebriefing_cli: bool,
) -> Tuple[bool, str]:
    """Decide whether to auto-invoke prebriefing for this dispatch.

    Returns (decision, reason) where decision is True/False and reason is
    a short string explaining the trigger (or skip cause) so the audit
    row can record it for forensic replay.

    Precedence (first match wins):
    1. ``--no-prebriefing`` CLI flag -> skip.
    2. ``AUDITOOOR_DISPATCH_NO_PREBRIEFING=1`` env var -> skip.
    3. Severity in {High, Critical} -> auto-invoke.
    4. Prompt cites R28+ rule -> auto-invoke.
    5. Default -> skip (low/medium without R28+ rule citation).
    """
    if no_prebriefing_cli:
        return False, "skip-no-prebriefing-cli"
    if os.environ.get(PREBRIEFING_OPT_OUT_ENV_VAR, "").strip() == "1":
        return False, "skip-env-opt-out"
    if _severity_triggers_prebriefing(severity):
        return True, "severity-high-or-critical"
    if _prompt_triggers_prebriefing_via_rules(prompt_text):
        return True, "rule-r28-plus-cited"
    return False, "skip-not-triggered"


def _invoke_prebriefing(
    *,
    prompt_text: str,
    severity: Optional[str],
    workspace: pathlib.Path,
    mcp_caller=None,
) -> Tuple[Optional[str], Dict[str, object]]:
    """Auto-invoke the prebriefing wrapper to enrich the prompt.

    Returns ``(enriched_text, meta)``. On any failure ``enriched_text`` is
    None and ``meta`` carries ``status=skipped-error`` plus an error
    description; callers fall back to the original prompt without crashing.
    On success ``enriched_text`` is the original prompt with the Section
    15a/15b/15c/15d BEGIN/END block prepended, and ``meta`` carries
    ``status=invoked`` plus the prebriefing wrapper's own meta block
    (pack id, inferred fields, fallback details).

    ``mcp_caller`` is an injection point for tests so they can stub the
    skeleton without spawning a real MCP server subprocess.
    """
    module = _load_prebriefing_module()
    if module is None:
        return None, {
            "status": "skipped-error",
            "error": "prebriefing_wrapper_unavailable",
            "wrapper_path": str(PREBRIEFING_WRAPPER_PATH),
        }
    try:
        enriched, meta = module.build_enriched_prompt(
            prompt_text=prompt_text,
            severity=str(severity).upper() if severity else None,
            workspace_path=workspace,
            mcp_caller=mcp_caller,
        )
    except Exception as exc:  # noqa: BLE001
        return None, {
            "status": "skipped-error",
            "error": f"build_enriched_prompt_raised: {type(exc).__name__}: {exc}",
        }
    # Mark META-1 as invoked even when the upstream skeleton call was
    # unavailable; the wrapper still emits a warn-stub BEGIN/END block so
    # the worker can see that prebriefing was attempted.
    out_meta: Dict[str, object] = {
        "status": "invoked",
        "skeleton_pack_id": meta.get("skeleton_pack_id"),
        "skeleton_unavailable": bool(meta.get("skeleton_unavailable")),
        "phase_a_context_pack_ids": meta.get("phase_a_context_pack_ids"),
        "phase_a_context_pack_hashes": meta.get("phase_a_context_pack_hashes"),
        "live_target_report_staleness": meta.get("live_target_report_staleness"),
        "lane_type": meta.get("lane_type"),
        "severity": meta.get("severity"),
        "prefix_chars": meta.get("prefix_chars"),
    }
    return enriched, out_meta


def _write_enriched_prompt_tmpfile(
    enriched_text: str,
    workspace: pathlib.Path,
) -> Optional[pathlib.Path]:
    """Write enriched prompt to a workspace-local temp file.

    Returns the path on success, or None on failure (caller falls back
    to original prompt path). We anchor under
    ``<workspace>/.auditooor/dispatch_prebriefed/`` so the artifact is
    co-located with the audit log and easy to inspect post-hoc.
    """
    out_dir = workspace / ".auditooor" / "dispatch_prebriefed"
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            prefix="prompt-",
            suffix=".md",
            dir=str(out_dir),
        )
    except OSError:
        return None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(enriched_text)
    except OSError:
        return None
    return pathlib.Path(tmp_path)


def _run_dispatcher(
    argv: List[str],
    output_path: Optional[pathlib.Path],
    timeout: Optional[float],
    template_name: Optional[str] = None,
) -> Tuple[int, Optional[str]]:
    """Run the underlying dispatcher and capture stdout to ``output_path``.

    Returns (rc, stderr_tail). On error returns (EXIT_ERROR, str(exc)).
    """
    env = os.environ.copy()
    if template_name:
        env[PREFLIGHT_OK_ENV_VAR] = template_name
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        return EXIT_ERROR, f"dispatcher timed out after {exc.timeout}s"
    except FileNotFoundError as exc:
        return EXIT_ERROR, f"dispatcher not found: {exc}"
    except OSError as exc:
        return EXIT_ERROR, f"dispatcher exec failed: {exc}"

    if output_path is not None:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(proc.stdout, encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(
                f"dispatch-preflight: WARN: could not write provider output "
                f"to {output_path}: {exc}\n"
            )

    if proc.stderr:
        # Forward dispatcher stderr verbatim so the operator sees provider errors.
        sys.stderr.write(proc.stderr)
    return proc.returncode, (proc.stderr or None)


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="dispatch-preflight.py",
        description=(
            "Mandatory pre-dispatch validator + dispatcher wrapper. "
            "Refuses sloppy prompts loudly. Audits every attempt "
            "(DISPATCHED / REFUSED / BYPASSED / ERROR) to "
            "<workspace>/.auditooor/dispatch_audit.jsonl."
        ),
    )
    parser.add_argument(
        "--template",
        required=True,
        choices=MANDATORY_TASK_TYPES + IMPACT_CONTRACT_EXEMPT_TASK_TYPES,
        help=(
            "Template/task type. The 5 mandatory task types are validated "
            "against dispatch templates; scope_only and impact_analysis are "
            "explicitly impact-contract-exempt discovery lanes."
        ),
    )
    parser.add_argument(
        "--task-type",
        default=None,
        help=(
            "Calibration task type forwarded to llm-dispatch.py. Defaults "
            "to --template. Factory/config/liveness lanes may reuse the "
            "source-extract or adversarial-kill templates while recording "
            "as factory-config-liveness-extraction or "
            "factory-config-liveness-kill."
        ),
    )
    parser.add_argument(
        "--prompt-file",
        required=True,
        help="Path to the candidate prompt file (UTF-8 text).",
    )
    parser.add_argument(
        "--provider",
        default=None,
        help=(
            "Provider override forwarded to llm-dispatch.py "
            "(auto / kimi / minimax / anthropic). Default: let "
            "llm-dispatch.py pick from --provider auto."
        ),
    )
    parser.add_argument(
        "--workspace",
        default=None,
        help=(
            "Workspace dir for the audit log. Defaults to "
            f"${WORKSPACE_ENV_VAR} or cwd."
        ),
    )
    parser.add_argument(
        "--audit-log",
        default=None,
        help=(
            "Override audit log path. Default: "
            "<workspace>/.auditooor/dispatch_audit.jsonl"
        ),
    )
    parser.add_argument(
        "--output-file",
        default=None,
        help=(
            "Capture provider response stdout to this path. Default: "
            "<workspace>/.auditooor/dispatch_outputs/<sha8>-<template>.txt"
        ),
    )
    parser.add_argument(
        "--template-dir",
        default=str(TEMPLATE_DIR),
        help=f"Directory of dispatch templates (default: {TEMPLATE_DIR}).",
    )
    parser.add_argument(
        "--mock-dispatcher",
        default=None,
        help=(
            "Use this command as the dispatcher binary instead of "
            "tools/llm-dispatch.py. Tests pass an echo-script here so "
            "the wrapper round-trips without burning tokens."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Per-dispatch timeout (seconds). Default: no timeout.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Validate-and-log only. Do not invoke the underlying "
            "dispatcher. Audit row gets status DRY_RUN."
        ),
    )
    parser.add_argument(
        "--forward",
        dest="extra_args",
        default=None,
        help=(
            "Extra argv (single shell-quoted string) forwarded to "
            "llm-dispatch.py verbatim, e.g. "
            "--forward '--max-tokens 8000 --smoke-test'."
        ),
    )
    parser.add_argument(
        "--require-mcp-context",
        action="store_true",
        help=(
            "Lane 12 (Wave-6): fail-closed MCP context prerequisites gate. "
            "Refuses dispatch unless a fresh MCP context-pack receipt is "
            "present in <workspace>/.auditooor/last_mcp_recall.json "
            "(written by vault-mcp-server.py --call vault_resume_context) "
            "with recall_ts within the last hour. "
            "Override: set MCP_CONTEXT_BYPASS=1 with MCP_CONTEXT_BYPASS_REASON=<text>. "
            "Every bypass is audited."
        ),
    )
    parser.add_argument(
        "--require-mcp-evidence-receipt",
        default=None,
        metavar="PATH",
        help=(
            "Fail closed unless PATH is a valid auditooor.mcp_evidence_receipt.v1 "
            "sidecar under the workspace. This proves a worker packet is bound "
            "to actual MCP context-pack ids/hashes, not just prompt text."
        ),
    )
    parser.add_argument(
        "--severity",
        default=None,
        help=(
            "Optional severity hint for the dispatch. High/Critical dispatches "
            "must provide --require-local-judgment-bundle so provider work is "
            "gated by local OOS/dupe/severity/evidence judgment first."
        ),
    )
    parser.add_argument(
        "--require-local-judgment-bundle",
        default=None,
        metavar="PATH",
        help=(
            "Fail closed unless PATH is a passing "
            "auditooor.candidate_judgment_packet.v1 bundle under the workspace. "
            "Required for High/Critical dispatch; generated by make prove-top-leads."
        ),
    )
    parser.add_argument(
        "--no-prebriefing",
        action="store_true",
        help=(
            "Phase -1 B / WF-7 #1 (iter18). Opt out of the META-1 auto-invoke "
            "of tools/dispatch-agent-with-prebriefing.py. By default, when "
            "severity sits at High/Critical OR the prompt cites any R-rule "
            "at R28 or above, dispatch-preflight prepends the Section "
            "15a/15b/15c/15d skeleton block (sourced from "
            "vault_dispatch_brief_skeleton) to the prompt BEFORE handing "
            "off to llm-dispatch.py. Pass --no-prebriefing (or set "
            "AUDITOOOR_DISPATCH_NO_PREBRIEFING=1) to send the raw prompt "
            "untouched. Every prebriefing attempt is audited."
        ),
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)

    template_dir = pathlib.Path(args.template_dir).resolve()
    prompt_path = pathlib.Path(args.prompt_file).expanduser().resolve()

    if not prompt_path.is_file():
        sys.stderr.write(
            f"dispatch-preflight: prompt file not found: {prompt_path}\n"
        )
        return EXIT_USAGE

    workspace, ws_source = _resolve_workspace(args.workspace)
    if ws_source == "cwd":
        sys.stderr.write(
            "dispatch-preflight: WARN: no --workspace and no "
            f"{WORKSPACE_ENV_VAR} env; auditing under cwd ({workspace}).\n"
        )

    audit_path = _audit_log_path(workspace, args.audit_log)

    # ------------------------------------------------------------------
    # Lane 12 — fail-closed MCP context prerequisites gate.
    # Runs BEFORE template validation and bypass handling so that even
    # bypass calls need either a fresh receipt or the explicit MCP bypass.
    # ------------------------------------------------------------------
    if getattr(args, "require_mcp_context", False):
        mcp_bypass_active = os.environ.get(MCP_CONTEXT_BYPASS_ENV_VAR, "").strip() == "1"
        mcp_bypass_reason = os.environ.get(MCP_CONTEXT_BYPASS_REASON_ENV_VAR, "").strip() or None
        if mcp_bypass_active:
            if not mcp_bypass_reason:
                sys.stderr.write(
                    f"dispatch-preflight: REFUSED {MCP_CONTEXT_BYPASS_ENV_VAR}=1 without "
                    f"{MCP_CONTEXT_BYPASS_REASON_ENV_VAR}; every MCP bypass needs a reason.\n"
                )
                _append_audit_row(
                    audit_path,
                    {
                        "ts": _utc_now_iso(),
                        "tool": "dispatch-preflight.py",
                        "status": "REFUSED",
                        "missing_inputs": [MCP_CONTEXT_BYPASS_REASON_ENV_VAR],
                        "gate": "mcp_context_prerequisites",
                        "workspace": str(workspace),
                    },
                )
                return EXIT_REFUSED
            sys.stderr.write(
                "\n"
                + ("!" * 72) + "\n"
                + f"MCP CONTEXT GATE BYPASSED ({MCP_CONTEXT_BYPASS_ENV_VAR}=1)\n"
                + f"Reason: {mcp_bypass_reason}\n"
                + "Every bypass is recorded in the audit log.\n"
                + ("!" * 72) + "\n\n"
            )
            _append_audit_row(
                audit_path,
                {
                    "ts": _utc_now_iso(),
                    "tool": "dispatch-preflight.py",
                    "status": "MCP_CONTEXT_BYPASSED",
                    "bypass_reason": mcp_bypass_reason,
                    "gate": "mcp_context_prerequisites",
                    "workspace": str(workspace),
                },
            )
        else:
            mcp_ok, mcp_error = _check_mcp_context_prerequisites(workspace)
            if not mcp_ok:
                sys.stderr.write("\n")
                sys.stderr.write("=" * 72 + "\n")
                sys.stderr.write(
                    "DISPATCH REFUSED — MCP context prerequisites not met\n"
                )
                sys.stderr.write("=" * 72 + "\n")
                sys.stderr.write(f"{mcp_error}\n")
                sys.stderr.write("=" * 72 + "\n\n")
                _append_audit_row(
                    audit_path,
                    {
                        "ts": _utc_now_iso(),
                        "tool": "dispatch-preflight.py",
                        "status": "REFUSED",
                        "missing_inputs": ["mcp_context_pack_receipt"],
                        "gate": "mcp_context_prerequisites",
                        "workspace": str(workspace),
                        "error_detail": mcp_error,
                    },
                )
                return EXIT_REFUSED

    if getattr(args, "require_mcp_evidence_receipt", None):
        receipt_ok, receipt_error = _check_mcp_evidence_receipt_path(
            args.require_mcp_evidence_receipt,
            workspace,
        )
        if not receipt_ok:
            sys.stderr.write("\n")
            sys.stderr.write("=" * 72 + "\n")
            sys.stderr.write(
                "DISPATCH REFUSED — MCP evidence receipt prerequisites not met\n"
            )
            sys.stderr.write("=" * 72 + "\n")
            sys.stderr.write(f"{receipt_error}\n")
            sys.stderr.write("=" * 72 + "\n\n")
            _append_audit_row(
                audit_path,
                {
                    "ts": _utc_now_iso(),
                    "tool": "dispatch-preflight.py",
                    "status": "REFUSED",
                    "missing_inputs": ["mcp_evidence_receipt"],
                    "gate": "mcp_evidence_receipt",
                    "workspace": str(workspace),
                    "error_detail": receipt_error,
                },
            )
            return EXIT_REFUSED

    # Resolve severity and judgment bundle from CLI flags first, then env-var
    # fallbacks.  The env-var path lets v3-provider-fanout-runner.py (and any
    # future orchestrator that builds the dispatch-preflight CLI command per
    # queue row) wire the gate WITHOUT modifying the per-row _build_command()
    # call site.  The coordinator must add these two env vars to
    # _make_child_env() in tools/v3-provider-fanout-runner.py:
    #   env["AUDITOOOR_DISPATCH_SEVERITY"] = str(row.get("claimed_severity") or "")
    #   bundle = str(manifest.get("local_judgment_bundle_path") or "")
    #   if bundle:
    #       env["AUDITOOOR_LOCAL_JUDGMENT_BUNDLE"] = bundle
    effective_severity = args.severity or os.environ.get(DISPATCH_SEVERITY_ENV_VAR, "").strip() or None
    effective_bundle = getattr(args, "require_local_judgment_bundle", None) or os.environ.get(LOCAL_JUDGMENT_BUNDLE_ENV_VAR, "").strip() or None

    severity_requires_judgment = _severity_requires_local_judgment_bundle(effective_severity)
    if severity_requires_judgment and not effective_bundle:
        judgment_error = (
            "Local judgment bundle is required for High/Critical dispatch. "
            "Run make prove-top-leads WS=<workspace> STRICT=1 JSON=1 and pass "
            "--require-local-judgment-bundle "
            "<workspace>/.auditooor/prove_top_leads_candidate_judgment_packet.json."
        )
        sys.stderr.write("\n")
        sys.stderr.write("=" * 72 + "\n")
        sys.stderr.write(
            "DISPATCH REFUSED — Local judgment bundle prerequisites not met\n"
        )
        sys.stderr.write("=" * 72 + "\n")
        sys.stderr.write(f"{judgment_error}\n")
        sys.stderr.write("=" * 72 + "\n\n")
        _append_audit_row(
            audit_path,
            {
                "ts": _utc_now_iso(),
                "tool": "dispatch-preflight.py",
                "status": "REFUSED",
                "missing_inputs": ["local_judgment_bundle"],
                "gate": "local_judgment_bundle",
                "severity": effective_severity,
                "workspace": str(workspace),
                "error_detail": judgment_error,
            },
        )
        return EXIT_REFUSED

    if effective_bundle:
        judgment_ok, judgment_error = _check_local_judgment_bundle_path(
            effective_bundle,
            workspace,
        )
        if not judgment_ok:
            sys.stderr.write("\n")
            sys.stderr.write("=" * 72 + "\n")
            sys.stderr.write(
                "DISPATCH REFUSED — Local judgment bundle prerequisites not met\n"
            )
            sys.stderr.write("=" * 72 + "\n")
            sys.stderr.write(f"{judgment_error}\n")
            sys.stderr.write("=" * 72 + "\n\n")
            _append_audit_row(
                audit_path,
                {
                    "ts": _utc_now_iso(),
                    "tool": "dispatch-preflight.py",
                    "status": "REFUSED",
                    "missing_inputs": ["local_judgment_bundle"],
                    "gate": "local_judgment_bundle",
                    "severity": effective_severity,
                    "workspace": str(workspace),
                    "error_detail": judgment_error,
                },
            )
            return EXIT_REFUSED

    is_exempt_task = args.template in IMPACT_CONTRACT_EXEMPT_TASK_TYPES
    dispatch_task_type = args.task_type or args.template
    expected_template = TASK_TYPE_TEMPLATE_ALIASES.get(dispatch_task_type)
    if expected_template is not None and expected_template != args.template:
        sys.stderr.write(
            "dispatch-preflight: task type "
            f"{dispatch_task_type!r} must use template "
            f"{expected_template!r}, got {args.template!r}\n"
        )
        return EXIT_USAGE
    if expected_template is None and dispatch_task_type != args.template:
        sys.stderr.write(
            "dispatch-preflight: unsupported task-type/template pair: "
            f"task_type={dispatch_task_type!r}, template={args.template!r}\n"
        )
        return EXIT_USAGE
    dt_module = None
    template: Dict = {
        "name": args.template,
        "provider": args.provider or "auto",
        "refusal_rules": [],
    }
    if not is_exempt_task:
        try:
            dt_module = _load_dispatch_template_module()
        except RuntimeError as exc:
            sys.stderr.write(f"dispatch-preflight: {exc}\n")
            return EXIT_ERROR

        try:
            template = dt_module.load_template(args.template, template_dir)
        except (FileNotFoundError, ValueError) as exc:
            sys.stderr.write(f"dispatch-preflight: {exc}\n")
            return EXIT_USAGE

    try:
        prompt_sha = _sha256_of_file(prompt_path)
    except OSError as exc:
        sys.stderr.write(f"dispatch-preflight: cannot read prompt: {exc}\n")
        return EXIT_ERROR

    # Resolve provider output path (used by both DISPATCHED + BYPASSED rows).
    if args.output_file:
        output_path: Optional[pathlib.Path] = (
            pathlib.Path(args.output_file).expanduser().resolve()
        )
    else:
        sha8 = prompt_sha[:8]
        output_path = (
            workspace
            / ".auditooor"
            / "dispatch_outputs"
            / f"{sha8}-{dispatch_task_type}.txt"
        )

    bypass_active = os.environ.get(BYPASS_ENV_VAR, "").strip() == "1"
    bypass_reason = os.environ.get(BYPASS_REASON_ENV_VAR, "").strip() or None

    base_row: Dict = {
        "ts": _utc_now_iso(),
        "tool": "dispatch-preflight.py",
        "template_id": args.template,
        "task_type": dispatch_task_type,
        "model": _resolve_model_hint(args.provider),
        "prompt_path": str(prompt_path),
        "prompt_sha256": prompt_sha,
        "workspace": str(workspace),
        "workspace_source": ws_source,
    }

    # ------------------------------------------------------------------
    # Path 1 — BYPASS active. Loud warning, but proceed.
    # ------------------------------------------------------------------
    if bypass_active:
        if not bypass_reason:
            sys.stderr.write(
                f"dispatch-preflight: REFUSED {BYPASS_ENV_VAR}=1 without "
                f"{BYPASS_REASON_ENV_VAR}; every bypass needs an operator "
                "reason.\n"
            )
            row = dict(base_row)
            row.update(
                {
                    "status": "REFUSED",
                    "missing_inputs": [BYPASS_REASON_ENV_VAR],
                }
            )
            _append_audit_row(audit_path, row)
            return EXIT_REFUSED
        reason_text = bypass_reason
        sys.stderr.write(
            "\n"
            + ("!" * 72) + "\n"
            + f"DISPATCH PREFLIGHT BYPASSED ({BYPASS_ENV_VAR}=1) — "
            + f"template '{args.template}', prompt {prompt_path}\n"
            + f"Reason: {reason_text}\n"
            + "Every bypass is recorded in the audit log.\n"
            + ("!" * 72) + "\n\n"
        )
        if args.dry_run:
            row = dict(base_row)
            row.update({"status": "BYPASSED_DRY_RUN", "bypass_reason": bypass_reason})
            _append_audit_row(audit_path, row)
            return EXIT_OK

        dispatcher_path = (
            pathlib.Path(args.mock_dispatcher).expanduser().resolve()
            if args.mock_dispatcher
            else DEFAULT_DISPATCHER
        )
        extra_args = (
            shlex.split(args.extra_args) if args.extra_args else []
        )
        argv_full = _build_dispatcher_argv(
            dispatcher_path,
            prompt_path,
            args.template,
            dispatch_task_type,
            args.provider,
            extra_args,
        )
        # Bypass DOES NOT set the preflight-ok sentinel. The downstream
        # dispatcher will see the bypass env directly.
        rc, _stderr = _run_dispatcher(
            argv_full, output_path, args.timeout, template_name=None
        )
        row = dict(base_row)
        row.update(
            {
                "status": "BYPASSED",
                "bypass_reason": bypass_reason,
                "provider_output_path": str(output_path) if output_path else None,
                "dispatch_rc": rc,
                "dispatcher": str(dispatcher_path),
                "argv": argv_full[1:],  # drop python interpreter
            }
        )
        _append_audit_row(audit_path, row)
        return rc

    # ------------------------------------------------------------------
    # Path 2 — Normal flow. Validate first.
    # ------------------------------------------------------------------
    try:
        prompt_text = prompt_path.read_text(encoding="utf-8")
    except OSError as exc:
        sys.stderr.write(f"dispatch-preflight: cannot read prompt: {exc}\n")
        return EXIT_ERROR

    if is_exempt_task:
        ok, missing = True, []
    else:
        try:
            ok, missing = dt_module.validate_prompt(template, prompt_text)
        except ValueError as exc:
            sys.stderr.write(f"dispatch-preflight: template error: {exc}\n")
            return EXIT_USAGE

    if not ok:
        _print_refusal(template, missing, prompt_path)
        row = dict(base_row)
        row.update(
            {
                "status": "REFUSED",
                "missing_inputs": [m["input"] for m in missing],
            }
        )
        _append_audit_row(audit_path, row)
        return EXIT_REFUSED

    impact_lib = _load_impact_mapping_lib()
    contract_required = (
        not is_exempt_task
        and (
            args.template in CONTRACT_ALWAYS_REQUIRED_TASK_TYPES
            or (
                impact_lib is not None
                and (
                    _prompt_claims_direct_submit(prompt_text)
                    if args.template in {"source-extract", "adversarial-kill"}
                    else impact_lib.prompt_claims_reportable_or_direct(prompt_text)
                )
            )
        )
    )
    if contract_required:
        if impact_lib is None:
            contract_report = {
                "ok": False,
                "reasons": ["impact_contract_validator_missing"],
            }
        else:
            contract_report = impact_lib.validate_impact_contract_text(
                prompt_text,
                workspace=workspace,
                require_contract=True,
            )
        if not contract_report.get("ok"):
            reasons = [str(r) for r in contract_report.get("reasons", [])]
            sys.stderr.write("\n")
            sys.stderr.write("=" * 72 + "\n")
            sys.stderr.write(
                f"DISPATCH REFUSED — impact contract is not locked for "
                f"task '{args.template}'\n"
            )
            sys.stderr.write("=" * 72 + "\n")
            for reason in reasons:
                sys.stderr.write(f"  - {reason}\n")
            sys.stderr.write(
                "\nBefore harness/dispatch/report work, lock an Impact "
                "Contract with an exact listed impact sentence, matching "
                "severity_tier, listed_impact_proven: true, evidence_class, "
                "oos_traps, and a concrete stop_condition. Keep proof_contract "
                "and downgrade_clauses in the packet when they materially "
                "bound the claim. Use task_type scope_only or impact_analysis "
                "only when the task is explicitly to lock scope/impact.\n"
            )
            sys.stderr.write("=" * 72 + "\n\n")
            row = dict(base_row)
            row.update(
                {
                    "status": "REFUSED",
                    "missing_inputs": reasons,
                    "impact_contract": contract_report,
                }
            )
            _append_audit_row(audit_path, row)
            return EXIT_REFUSED

    # ------------------------------------------------------------------
    # Phase -1 B / WF-7 #1 (iter18, 2026-05-23) - META-1 auto-invoke.
    # Runs AFTER validation + impact-contract checks (so we never enrich
    # a prompt that is about to be refused) and BEFORE dispatcher invocation
    # (so the enriched prompt is what reaches llm-dispatch.py).
    # ------------------------------------------------------------------
    no_prebriefing_cli = bool(getattr(args, "no_prebriefing", False))
    prebriefing_decision, prebriefing_reason = _should_auto_invoke_prebriefing(
        severity=effective_severity,
        prompt_text=prompt_text,
        no_prebriefing_cli=no_prebriefing_cli,
    )
    prebriefing_meta: Dict[str, object] = {
        "invoked": False,
        "trigger_reason": prebriefing_reason,
    }
    effective_prompt_path = prompt_path
    if prebriefing_decision:
        enriched_text, invoke_meta = _invoke_prebriefing(
            prompt_text=prompt_text,
            severity=effective_severity,
            workspace=workspace,
        )
        prebriefing_meta.update(invoke_meta)
        prebriefing_meta["invoked"] = bool(enriched_text is not None)
        if enriched_text is not None:
            tmp_path = _write_enriched_prompt_tmpfile(
                enriched_text, workspace
            )
            if tmp_path is not None:
                effective_prompt_path = tmp_path
                prebriefing_meta["enriched_prompt_path"] = str(tmp_path)
            else:
                # Fall back to original prompt; record the write failure
                # so post-hoc analysis can spot the disk-space / perms
                # issue.
                prebriefing_meta["status"] = "skipped-write-error"
                prebriefing_meta["invoked"] = False

    # Validation passed - dispatch.
    if args.dry_run:
        row = dict(base_row)
        row.update({"status": "DRY_RUN", "prebriefing": prebriefing_meta})
        _append_audit_row(audit_path, row)
        sys.stderr.write(
            f"dispatch-preflight: OK (dry-run) - template '{args.template}' "
            f"validated; not dispatching.\n"
        )
        return EXIT_OK

    dispatcher_path = (
        pathlib.Path(args.mock_dispatcher).expanduser().resolve()
        if args.mock_dispatcher
        else DEFAULT_DISPATCHER
    )
    extra_args = (
        shlex.split(args.extra_args) if args.extra_args else []
    )
    argv_full = _build_dispatcher_argv(
        dispatcher_path,
        effective_prompt_path,
        args.template,
        dispatch_task_type,
        args.provider,
        extra_args,
    )
    # Validation passed - set the sentinel so llm-dispatch.py knows it
    # was invoked through the preflight gate.
    rc, _stderr = _run_dispatcher(
        argv_full, output_path, args.timeout, template_name=dispatch_task_type
    )
    row = dict(base_row)
    row.update(
        {
            "status": "DISPATCHED",
            "provider_output_path": str(output_path) if output_path else None,
            "dispatch_rc": rc,
            "dispatcher": str(dispatcher_path),
            "argv": argv_full[1:],
            "prebriefing": prebriefing_meta,
        }
    )
    _append_audit_row(audit_path, row)
    return rc


if __name__ == "__main__":
    sys.exit(main())
