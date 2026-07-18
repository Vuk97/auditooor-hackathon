#!/usr/bin/env python3
"""
Build fail-closed review bundles from staging drafts under `submissions/packaged/`.

Takes a staging draft, runs the close-out gates, and produces a fail-closed
review bundle under submissions/packaged/. This step does not render the final
triager-clean markdown; it preserves the source draft plus the gate artifacts
that justify operator review.

Usage:
    submission-packager.py <workspace> <draft.md>
    submission-packager.py ~/audits/<project> ~/audits/<project>/submissions/staging/<draft>.md

Quality gates:
  1. Variant detector (dupe risk)
  2. Finding quality scorer (acceptance likelihood)
  3. Pre-submit check (hard gate; no in-place edits)
  4. Scope review (heuristic)

Output:
  ~/audits/<ws>/submissions/packaged/<slug>/
    source-draft.md   — Source staging draft
    poc.t.sol         — PoC test
    variant-report.json
    quality-report.json
    manifest.json
    pre-submit.log
    scope-review.md
"""

import argparse
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

AUDITOOOR_DIR = Path(__file__).parent.parent


# V4 Phase P1 (Workstream A2): import the shared production-path helper. The
# library lives at ``tools/lib/production_path.py`` and is the single source
# of truth used by both the pre-submit gate (Check #27) and the packager
# manifest. Loaded via importlib so the absence of an ``__init__.py`` in
# ``tools/lib`` does not block discovery.
#
# NOTE: Python 3.14's dataclass decorator requires the module to be present
# in ``sys.modules`` BEFORE ``exec_module`` is called, otherwise dataclass
# field-type introspection raises an AttributeError. We register the module
# under the cache key first.
_PRODUCTION_PATH_LIB_CACHE_KEY = "_production_path_lib"


def _load_production_path_lib() -> Optional[Any]:
    cached = sys.modules.get(_PRODUCTION_PATH_LIB_CACHE_KEY)
    if cached is not None:
        return cached
    spec_path = AUDITOOOR_DIR / "tools" / "lib" / "production_path.py"
    if not spec_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            _PRODUCTION_PATH_LIB_CACHE_KEY, spec_path
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[_PRODUCTION_PATH_LIB_CACHE_KEY] = module
        spec.loader.exec_module(module)
        return module
    except Exception:
        sys.modules.pop(_PRODUCTION_PATH_LIB_CACHE_KEY, None)
        return None


_PRODUCTION_PATH_LIB = _load_production_path_lib()


# PR #535 PR 1: shared Program Impact Mapping summary helper. Same
# load-into-sys.modules-first idiom as the production-path lib above to
# avoid Python 3.14 dataclass-introspection breakage.
_IMPACT_MAPPING_LIB_CACHE_KEY = "_packager_impact_mapping_lib"


def _load_impact_mapping_lib() -> Optional[Any]:
    cached = sys.modules.get(_IMPACT_MAPPING_LIB_CACHE_KEY)
    if cached is not None:
        return cached
    spec_path = AUDITOOOR_DIR / "tools" / "lib" / "program_impact_mapping.py"
    if not spec_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            _IMPACT_MAPPING_LIB_CACHE_KEY, spec_path
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[_IMPACT_MAPPING_LIB_CACHE_KEY] = module
        spec.loader.exec_module(module)
        return module
    except Exception:
        sys.modules.pop(_IMPACT_MAPPING_LIB_CACHE_KEY, None)
        return None


_IMPACT_MAPPING_LIB = _load_impact_mapping_lib()


def build_impact_mapping_manifest(
    draft_path: Path,
    workspace: Optional[Path] = None,
) -> Dict[str, Any]:
    """Return the ``impact_mapping`` block for the packager manifest.

    PR #535 PR 1 promotion contract: every packaged Critical/High/
    paste-ready draft carries a parsed ``Program Impact Mapping`` summary
    in ``manifest.json``. Default policy is advisory; refusal is gated on
    ``REQUIRE_PROGRAM_IMPACT_MAPPING=1`` (see
    ``packager_should_refuse``).

    Fail-open contract: when the helper module is missing the manifest
    field still appears with ``status=advisory_no_rubric`` so downstream
    consumers do not crash on a stripped checkout.
    """
    if _IMPACT_MAPPING_LIB is None:
        return {
            "schema_version": "auditooor.impact_mapping_summary.v1",
            "status": "advisory_no_rubric",
            "requires_mapping": False,
            "severity_claim": "",
            "paste_ready": False,
            "has_mapping_block": False,
            "selected_impact": "",
            "severity_implied": "",
            "proof_artifact": "",
            "not_proven_impacts": [],
            "errors": ["impact_mapping helper not loadable"],
            "warnings": [],
            "rubric_found": False,
        }
    return _IMPACT_MAPPING_LIB.packager_metadata(draft_path, workspace=workspace)


def _impact_mapping_packager_refusal(
    metadata: Dict[str, Any],
    draft_path: Path,
) -> Tuple[bool, str]:
    """Fail closed on reportable/direct-submit drafts without exact mapping.

    The shared helper still owns parsing and exact rubric matching. The
    packager adds the promotion policy: once a draft is reportable or presented
    as direct-submit/paste-ready, missing or non-exact Program Impact Mapping
    evidence is a packaging blocker, not a quiet manifest advisory.
    """
    if _IMPACT_MAPPING_LIB is None:
        return False, ""

    status = str(metadata.get("status") or "")
    if not _IMPACT_MAPPING_LIB.is_clean(status):
        return True, (
            f"impact_mapping_status={status} "
            "(reportable/direct-submit packaging requires an exact listed "
            "program-impact mapping plus proof artifact)"
        )

    if status == "not_required":
        try:
            text = draft_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        claims_direct = False
        try:
            claims_direct = bool(
                _IMPACT_MAPPING_LIB.prompt_claims_reportable_or_direct(text)
            )
        except Exception:
            claims_direct = False
        if claims_direct:
            return True, (
                "impact_mapping_status=missing_mapping "
                "(direct-submit/reportable posture requires an exact "
                "Program Impact Mapping or Impact Contract before packaging)"
            )

    return _IMPACT_MAPPING_LIB.packager_should_refuse(metadata)


def build_production_path_manifest(
    draft_path: Path,
    *,
    severity: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the V4 §2 A2 ``production_path`` manifest entry for a draft.

    Wraps ``tools/lib/production_path.build_manifest`` with a fail-open
    contract: if the helper is unavailable (corrupted checkout, broken
    import) the returned dict reports ``section_present=False`` and an
    ``error`` field so a reviewer can spot the degradation without the
    packager crashing on every draft.

    The schema mirrors V4 §2 A2 verbatim:

        {
          "section_present": bool,
          "scope_asset": str,
          "affected_code": str,
          "attacker_controlled_inputs": [str, ...],
          "privileged_preconditions": [str, ...],
          "mock_components": [str, ...],
          "real_component_replacements": [str, ...],
          "oos_clauses_checked": [str, ...],
          "impact_mapping": str
        }

    Plus ancillary fields (``severity``, ``mock_triggers_detected``,
    ``prose_triggers_detected``, ``missing_items``, ``local_paths_in_poc``,
    ``gate_status``, ``gate_reasons``) that mirror the gate's view of the
    draft so a reviewer can see WHY the gate decided what it did without
    re-running the gate. ``gate_status`` is one of ``PASS|WARN|FAIL`` and
    matches the rc the pre-submit Check #27 emitted.
    """
    if _PRODUCTION_PATH_LIB is None:
        return {
            "section_present": False,
            "error": "production_path library unavailable",
            "scope_asset": "",
            "affected_code": "",
            "attacker_controlled_inputs": [],
            "privileged_preconditions": [],
            "mock_components": [],
            "real_component_replacements": [],
            "oos_clauses_checked": [],
            "impact_mapping": "",
        }
    try:
        text = draft_path.read_text(errors="replace")
    except OSError as exc:
        return {
            "section_present": False,
            "error": f"draft read failed: {exc}",
            "scope_asset": "",
            "affected_code": "",
            "attacker_controlled_inputs": [],
            "privileged_preconditions": [],
            "mock_components": [],
            "real_component_replacements": [],
            "oos_clauses_checked": [],
            "impact_mapping": "",
        }
    sev = (severity or _PRODUCTION_PATH_LIB.detect_severity(text) or "").upper()
    manifest = _PRODUCTION_PATH_LIB.build_manifest(text, severity=sev)
    gate = _PRODUCTION_PATH_LIB.evaluate_gate(text, sev)
    manifest["gate_status"] = gate.status
    manifest["gate_reasons"] = list(gate.reasons)
    return manifest
ALLOWED_SCOPE_VERDICTS = {"NOVEL", "SAME-CLASS-DIFFERENT-VECTOR"}
SKIP_DRAFT_SUFFIXES = (".block.md", ".notes.md")
_COMMAND_LIKE_PREFIXES = (
    "go",
    "cargo",
    "make",
    "just",
    "bash",
    "sh",
    "./",
    "python",
    "python3",
    "cd ",
)
_PROSE_COMMAND_PREFIXES = {
    "check",
    "compile",
    "confirm",
    "execute",
    "inspect",
    "open",
    "re-run",
    "rerun",
    "review",
    "run",
    "see",
    "verify",
}
_GO_DLT_EXPLICIT_MARKERS = (r"\bgo/dlt\b",)
_GO_DLT_LANGUAGE_MARKERS = (
    r"\bgolang\b",
    r"\bgo\s+test\b",
    r"\bgo\s+run\b",
    r"\bcosmos[- ]sdk\b",
    r"\bcometbft\b",
    r"\btendermint\b",
    r"\bibc\b",
    r"\bkeeper\.go\b",
    r"\b[a-zA-Z0-9_./-]+\.go\b",
)
_HARNESS_CONTRACT_RE = re.compile(
    r"^\s*contract\s+([A-Za-z_][A-Za-z0-9_]*)\b",
    re.MULTILINE,
)
BUNDLE_EXECUTION_CONTRACT_SCHEMA = "auditooor.submission_bundle_execution_contract.v1"


def slugify(title: str) -> str:
    """Create a URL-safe slug from title."""
    slug = re.sub(r'[^\w\s-]', '', title).strip().lower()
    slug = re.sub(r'[-\s]+', '-', slug)
    return slug[:80]


def run_tool(name: str, cmd: List[str], cwd: Optional[Path] = None) -> Tuple[int, str]:
    """Run a tool and return (rc, output)."""
    result = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=120)
    return result.returncode, result.stdout + result.stderr


def find_poc_for_draft(draft_path: Path, ws: Path) -> Optional[Path]:
    """Find the Solidity/Foundry PoC test associated with a draft."""
    text = draft_path.read_text()
    poc_refs = re.findall(r'`?([a-zA-Z0-9_/-]+\.t\.sol)`?', text)
    for ref in poc_refs:
        poc_path = ws / "poc-tests" / Path(ref).name
        if poc_path.exists():
            return poc_path
        poc_path = ws / ref
        if poc_path.exists():
            return poc_path
    return None


def draft_is_go_dlt_submission(draft_path: Path) -> bool:
    """Return true when a draft is shaped like a Go Blockchain/DLT finding."""
    try:
        text = draft_path.read_text(errors="replace")
    except Exception:
        return False
    explicit = any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in _GO_DLT_EXPLICIT_MARKERS)
    language = any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in _GO_DLT_LANGUAGE_MARKERS)
    return explicit or language


def _clean_candidate_command(raw: str) -> str:
    """Normalize one candidate command string without inventing content."""
    candidate = raw.strip().strip("`")
    candidate = re.sub(r"^\s*(?:\$|%|>)\s+", "", candidate)
    candidate = re.sub(r"\s+#.*$", "", candidate).strip()
    return candidate


def _looks_like_env_assignment(token: str) -> bool:
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*=.*", token))


def _shell_segments(command: str) -> List[str]:
    """Split a small shell command into candidate executable segments."""
    return [part.strip() for part in re.split(r"\s*(?:&&|;|\|\|)\s*", command) if part.strip()]


def _is_exact_executable_segment(segment: str) -> Tuple[bool, str]:
    """Classify one command segment as rerunnable command text or prose."""
    segment = _clean_candidate_command(segment)
    if not segment:
        return False, "empty"
    try:
        tokens = shlex.split(segment)
    except ValueError:
        return False, "shell-parse-error"
    while tokens and _looks_like_env_assignment(tokens[0]):
        tokens.pop(0)
    if not tokens:
        return False, "env-only"
    first = tokens[0].lower()
    if first in _PROSE_COMMAND_PREFIXES:
        return False, "prose-leading-verb"
    if first == "cd":
        return False, "directory-change-only"
    if first == "go" and len(tokens) >= 2 and tokens[1] in {"test", "run"}:
        return True, "go-command"
    if first == "cargo" and len(tokens) >= 2 and tokens[1] in {"test", "run"}:
        return True, "cargo-command"
    if first in {"make", "just"} and len(tokens) >= 2:
        return True, f"{first}-target"
    if first in {"bash", "sh"} and len(tokens) >= 2 and tokens[1].endswith((".sh", ".bash")):
        return True, "shell-script"
    if first in {"python", "python3"} and len(tokens) >= 2:
        return True, "python-command"
    if first.startswith("./"):
        return True, "relative-executable"
    return False, "unrecognized-command-prefix"


def classify_gating_test_value(raw: str) -> Dict[str, Any]:
    """Classify a gating-test value as exact executable command or prose.

    This is rerunability metadata only. A command can be exact and still fail;
    exploit validity remains with the proof/harness gates.
    """
    value = raw.strip()
    inline_code = [match.strip() for match in re.findall(r"`([^`\n]+)`", value)]
    candidates = inline_code if inline_code else [value]
    for candidate in candidates:
        cleaned = _clean_candidate_command(candidate)
        if not cleaned:
            continue
        if not inline_code:
            parts = cleaned.split(None, 1)
            first_word = parts[0].lower() if parts else ""
            if (
                first_word not in _PROSE_COMMAND_PREFIXES
                and not cleaned.startswith(_COMMAND_LIKE_PREFIXES)
                and not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", cleaned)
            ):
                continue
        for segment in _shell_segments(cleaned):
            ok, reason = _is_exact_executable_segment(segment)
            if ok:
                return {
                    "classification": "exact-command",
                    "executable": True,
                    "command": cleaned,
                    "reason": reason,
                }
    return {
        "classification": "prose-unclear",
        "executable": False,
        "command": "",
        "reason": "no exact executable command detected",
    }


def extract_gating_test_values(draft_path: Path) -> List[Dict[str, str]]:
    """Extract explicit gating-test / execution-evidence values from a draft."""
    try:
        text = draft_path.read_text(errors="replace")
    except Exception:
        return []
    values: List[Dict[str, str]] = []
    seen: set[Tuple[str, str]] = set()

    def add(source: str, raw: str) -> None:
        value = raw.strip()
        if not value:
            return
        key = (source, value)
        if key in seen:
            return
        seen.add(key)
        values.append({"source": source, "raw": value})

    field_pattern = (
        r"(?im)^\s*(?:[-*]\s*)?(?:`)?"
        r"(?:gating[_ -]?test|execution[_ -]?evidence|rerun[_ -]?command|repro(?:duction)?[_ -]?command)"
        r"(?:`)?\s*[:=]\s*(.+)$"
    )
    for match in re.finditer(field_pattern, text):
        add("field", match.group(1))

    fenced = re.findall(r"```(?:bash|sh|shell|console)?\s*\n(.*?)```", text, flags=re.IGNORECASE | re.DOTALL)
    for block in fenced:
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            cleaned = _clean_candidate_command(line)
            if classify_gating_test_value(cleaned).get("executable"):
                add("code-fence", cleaned)

    return values


def summarize_execution_evidence(draft_path: Path) -> Dict[str, Any]:
    """Summarize Go/DLT rerun-command evidence for packager JSON output."""
    applies = draft_is_go_dlt_submission(draft_path)
    summary: Dict[str, Any] = {
        "schema_version": 1,
        "applies": applies,
        "asset_family": "go/dlt" if applies else "not-applicable",
        "status": "not-applicable",
        "gating_tests": [],
        "warnings": [],
        "blockers": [],
        "notes": "Rerun-command exactness check only; does not prove exploit validity.",
    }
    if not applies:
        return summary

    entries: List[Dict[str, Any]] = []
    for value in extract_gating_test_values(draft_path):
        entries.append({**value, **classify_gating_test_value(value["raw"])})
    summary["gating_tests"] = entries

    if any(entry.get("executable") for entry in entries):
        summary["status"] = "executable"
        return summary

    if entries:
        code = "go_dlt_gating_test_not_executable"
        message = (
            "Go/DLT gating_test or execution evidence is prose/unclear; provide an exact rerunnable command "
            "such as `go test ./path -run TestName -count=1`."
        )
    else:
        code = "go_dlt_gating_test_missing"
        message = (
            "Go/DLT draft has no explicit gating_test or execution evidence command; provide an exact "
            "rerunnable command for reviewer/operator rerun."
        )
    summary["status"] = "blocked"
    summary["blockers"].append({"code": code, "severity": "blocker", "message": message})
    return summary


def _resolve_workspace_ref(ref: str, ws: Path) -> Optional[Path]:
    """Resolve a draft-cited workspace path without escaping the workspace."""
    ref = ref.strip().strip("`'\"")
    if not ref:
        return None
    raw = Path(ref).expanduser()
    if raw.is_absolute():
        candidate = raw.resolve()
    else:
        candidate = (ws / raw).resolve()
    try:
        candidate.relative_to(ws.resolve())
    except ValueError:
        return None
    return candidate if candidate.exists() else None


def _extract_draft_scalar_field(text: str, field_name: str) -> str:
    """Return a simple `field: value` scalar from draft prose/YAML blocks."""
    pattern = rf"(?im)^\s*{re.escape(field_name)}\s*:\s*[\"']?(.+?)[\"']?\s*$"
    match = re.search(pattern, text)
    if not match:
        return ""
    return match.group(1).strip().strip("\"'")


def _extract_command_prerequisites(command: str) -> Tuple[Optional[str], Dict[str, str]]:
    """Extract a leading `cd ... &&` and env assignments from a harness command."""
    remainder = command.strip()
    working_directory: Optional[str] = None
    environment: Dict[str, str] = {}

    cd_match = re.match(r"^cd\s+(.+?)\s*&&\s*(.+)$", remainder)
    if cd_match:
        working_directory = cd_match.group(1).strip().strip("\"'")
        remainder = cd_match.group(2).strip()

    env_pattern = re.compile(
        r"^([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|[^\s]+)\s+(.*)$"
    )
    while remainder:
        env_match = env_pattern.match(remainder)
        if not env_match:
            break
        key = env_match.group(1)
        value = env_match.group(2).strip().strip("\"'")
        environment[key] = value
        remainder = env_match.group(3).strip()

    return working_directory, environment


def _build_reproducibility_hints(poc_evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Summarize rerun context for non-Forge harnesses without changing claims."""
    harness_command = str(poc_evidence.get("harness_command") or "").strip()
    gating_test = str(poc_evidence.get("gating_test") or "").strip()
    runtime_evidence_log = str(poc_evidence.get("runtime_evidence_log") or "").strip()
    working_directory, prerequisite_env = _extract_command_prerequisites(harness_command)

    missing_clarity: List[str] = []
    if harness_command and "./" in harness_command and not working_directory:
        missing_clarity.append("working_directory")
    if harness_command and not runtime_evidence_log:
        missing_clarity.append("runtime_evidence_log")

    return {
        "rerun_command": harness_command or None,
        "verification_hint": gating_test or None,
        "working_directory": working_directory,
        "prerequisite_env": prerequisite_env,
        "runtime_evidence_log": runtime_evidence_log or None,
        "missing_clarity": missing_clarity,
    }


def find_poc_evidence_for_draft(draft_path: Path, ws: Path) -> Dict[str, Any]:
    """Find PoC evidence cited by a draft.

    Historically the package matrix only recognized a copied ``poc.t.sol``.
    Rust/DLT findings, however, often prove exploitability through cargo-test
    harnesses and replayable evidence manifests under ``poc-tests/``. Return a
    small evidence descriptor so the filing bundle can treat those harnesses as
    first-class PoC evidence without weakening the existing Solidity path.
    """
    text = draft_path.read_text(errors="replace")
    solidity_poc = find_poc_for_draft(draft_path, ws)
    if solidity_poc is not None:
        return {
            "present": True,
            "kind": "forge",
            "label": "Forge PoC",
            "paths": [str(solidity_poc)],
            "notes": "PoC file copied into bundle",
        }

    harness_command = _extract_draft_scalar_field(text, "harness_command")
    gating_test = _extract_draft_scalar_field(text, "gating_test")
    runtime_evidence_log = _extract_draft_scalar_field(text, "runtime_evidence_log")

    if not re.search(r"\b(Rust|Go|DLT|cargo\s+test|go\s+test|Engine API|reth|base-[a-z-]+)\b", text, re.I):
        return {"present": False, "kind": "none", "label": "PoC / exploit harness", "paths": []}

    candidate_refs = re.findall(r"`([^`]+poc-tests/[^`]+)`", text)
    evidence_paths: List[str] = []
    for ref in candidate_refs:
        path = _resolve_workspace_ref(ref, ws)
        if path is None:
            continue
        if path.is_file():
            evidence_paths.append(str(path.relative_to(ws.resolve())))
            continue
        if path.is_dir():
            for name in (
                "fn7_evidence_manifest.json",
                "FN7_EVIDENCE_MANIFEST.md",
                "Cargo.toml",
                "verdict.txt",
                "VERDICT_IN_PROCESS.md",
                "PROPAGATION_VERDICT.md",
            ):
                child = path / name
                if child.exists():
                    evidence_paths.append(str(child.resolve().relative_to(ws.resolve())))
    # Cargo commands in drafts often cite the harness directory and Cargo.toml
    # across multiple lines; ensure those references count even if the regex
    # above only captured the parent directory.
    for ref in re.findall(r"(?m)(poc-tests/[A-Za-z0-9_./-]+)", text):
        path = _resolve_workspace_ref(ref.rstrip(".,;)"), ws)
        if path is None or not path.exists():
            continue
        if path.is_file():
            evidence_paths.append(str(path.relative_to(ws.resolve())))
        elif (path / "Cargo.toml").exists():
            evidence_paths.append(str((path / "Cargo.toml").resolve().relative_to(ws.resolve())))

    deduped = list(dict.fromkeys(evidence_paths))
    return {
        "present": bool(deduped),
        "kind": "rust_go_dlt_harness" if deduped else "none",
        "label": "PoC / exploit harness",
        "paths": deduped,
        "notes": (
            f"Rust/Go/DLT harness evidence cited ({len(deduped)} artifact(s))"
            if deduped
            else "No PoC or Rust/DLT harness evidence discovered for this draft"
        ),
        "harness_command": harness_command,
        "gating_test": gating_test,
        "runtime_evidence_log": runtime_evidence_log,
    }


# Bundle-local symbolic harness for PR 207 live-mode (iter12-T1).
def detect_attack_angles(draft_path: Path) -> List[str]:
    """Scan a draft for attack-angle tokens (`A-[A-Z-]+`).

    Returns a deduplicated, order-preserving list of matched angle ids. The
    live-mode orchestration (PR 207) looks up each angle in `angle_map.json`
    to decide whether to emit a symbolic harness alongside the PoC.
    """
    try:
        text = draft_path.read_text(errors="replace")
    except Exception:
        return []
    raw_hits = re.findall(r"\bA-[A-Z][A-Z0-9-]+\b", text)
    seen: Dict[str, None] = {}
    for token in raw_hits:
        # Drop trailing hyphens and all-cap noise that isn't an angle-shaped id.
        clean = token.rstrip("-")
        if len(clean) < 3 or "-" not in clean[2:]:
            continue
        if clean not in seen:
            seen[clean] = None
    return list(seen.keys())


def load_angle_map(angle_map_path: Optional[Path] = None) -> Dict[str, str]:
    """Load the angle->family mapping from `tools/angle_map.json`.

    Returns an empty dict if the file is absent or unreadable (fail-open:
    packager silently skips harness emission when no authoritative mapping
    is available).
    """
    if angle_map_path is None:
        angle_map_path = AUDITOOOR_DIR / "tools" / "angle_map.json"
    if not angle_map_path.is_file():
        return {}
    try:
        data = json.loads(angle_map_path.read_text())
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    # Normalize: only keep string->string entries.
    return {str(k): str(v) for k, v in data.items() if isinstance(v, str)}


def _pick_family_harness(invariants_dir: Path, family: str) -> Optional[Path]:
    """Return the first lex-sorted `*.t.sol` under the given family dir.

    No fabrication: returns None if the family directory is missing or
    contains no `*.t.sol` file.
    """
    family_dir = invariants_dir / family
    if not family_dir.is_dir():
        return None
    candidates = sorted(family_dir.glob("*.t.sol"))
    return candidates[0] if candidates else None


def _parse_harness_contract_name(path: Path) -> Optional[str]:
    """Return the first Solidity contract name in `path`, if any."""
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return None
    match = _HARNESS_CONTRACT_RE.search(text)
    return match.group(1) if match else None


def _repo_relative_harness_source(path: Path) -> str:
    """Render a stable source-harness path for the binding manifest."""
    try:
        return str(path.relative_to(AUDITOOOR_DIR))
    except ValueError:
        return str(path)


def _build_harness_execution_contract(angle: str) -> Dict[str, Any]:
    """Return the machine-readable command contract for one harness binding."""
    return {
        "tool": "econ-simulator",
        "argv": [
            "python3",
            "${AUDITOOOR_DIR}/tools/econ-simulator.py",
            "--bundle",
            "${BUNDLE_ROOT}",
            "--angle",
            angle,
        ],
        "requires": ["AUDITOOOR_DIR", "BUNDLE_ROOT"],
    }


def bundle_symbolic_harness(
    out_dir: Path,
    angles: List[str],
    invariants_dir: Path,
    angle_map: Dict[str, str],
) -> List[Path]:
    """Copy an invariant-family harness into `<bundle>/harnesses/<angle>.t.sol`.

    Also writes `<bundle>/harness-binding-manifest.json` so downstream tools
    can resolve the exact contract selector for each angle-keyed harness.

    Manifest contract:
      - Unmapped angle / missing family / missing contract name → unresolved row.
      - Destination exists already (operator-authored) → preserve, never clobber.
      - `angle_map` empty (absent/malformed `angle_map.json`) → unresolved rows only.

    Returns the list of harness files written (new copies only; not preserved
    operator-authored files).
    """
    written: List[Path] = []
    ordered_angles = list(dict.fromkeys(angles))
    if not ordered_angles:
        return written
    harnesses_dir = out_dir / "harnesses"
    entries: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, str]] = []
    for angle in ordered_angles:
        family = angle_map.get(angle)
        if not family:
            unresolved.append({"angle_id": angle, "reason": "angle-unmapped"})
            continue
        source = _pick_family_harness(invariants_dir, family)
        if source is None:
            unresolved.append(
                {
                    "angle_id": angle,
                    "reason": f"family-harness-missing:{family}",
                }
            )
            continue
        dest = harnesses_dir / f"{angle}.t.sol"
        selected_path = dest if dest.exists() else source
        contract_name = _parse_harness_contract_name(selected_path)
        if not contract_name:
            unresolved.append(
                {
                    "angle_id": angle,
                    "reason": f"missing-contract-name:{selected_path.name}",
                }
            )
            continue
        origin = "preserved" if dest.exists() else "copied"
        if not dest.exists():
            harnesses_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, dest)
            written.append(dest)
        entries.append(
            {
                "angle_id": angle,
                "family": family,
                "source_harness": _repo_relative_harness_source(source),
                "bundle_harness": str(dest.relative_to(out_dir)),
                "contract_name": contract_name,
                "origin": origin,
                "execution_contract": _build_harness_execution_contract(angle),
            }
        )
    manifest = {
        "schema_version": 1,
        "generator": "tools/submission-packager.py",
        "draft_angle_ids": ordered_angles,
        "entries": entries,
        "unresolved_angles": unresolved,
    }
    (out_dir / "harness-binding-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )
    return written


def build_bundle_execution_contract(out_dir: Path, poc_evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Describe bundle run-readiness without treating artifacts as execution.

    A copied `poc.t.sol`, cited Rust/DLT harness, or symbolic harness is useful
    local evidence, but it is not a runnable contract unless the bundle also
    carries an exact command/gate pair. The packager does not synthesize those
    commands, so artifact-only bundles fail closed as `blocked_harness`.
    """
    harness_artifacts: List[str] = []
    if (out_dir / "poc.t.sol").is_file():
        harness_artifacts.append("poc.t.sol")
    harnesses_dir = out_dir / "harnesses"
    if harnesses_dir.is_dir():
        for path in sorted(harnesses_dir.glob("*.t.sol")):
            harness_artifacts.append(str(path.relative_to(out_dir)))
    for item in poc_evidence.get("paths") or []:
        text = str(item)
        if text and text not in harness_artifacts:
            harness_artifacts.append(text)

    has_artifact = bool(harness_artifacts)
    harness_command = str(poc_evidence.get("harness_command") or "").strip()
    gating_test = str(poc_evidence.get("gating_test") or "").strip()
    if has_artifact and harness_command and gating_test:
        return {
            "schema": BUNDLE_EXECUTION_CONTRACT_SCHEMA,
            "claim": "runnable_harness",
            "status": "ready",
            "runnable": True,
            "advisory_only": False,
            "fail_closed": True,
            "harness_artifacts": harness_artifacts,
            "commands": {
                "harness_command": harness_command,
                "gating_test": gating_test,
            },
            "missing_inputs": [],
            "blockers": [],
            "evidence_boundary": "exact local harness command and gate are packaged",
            "reproducibility_hints": _build_reproducibility_hints(poc_evidence),
        }
    claim = "blocked_harness" if has_artifact else "advisory_only"
    status = "blocked_missing_execution_command" if has_artifact else "advisory_only"
    missing_inputs = ["harness_command", "gating_test"] if has_artifact else []
    return {
        "schema": BUNDLE_EXECUTION_CONTRACT_SCHEMA,
        "claim": claim,
        "status": status,
        "runnable": False,
        "advisory_only": not has_artifact,
        "fail_closed": True,
        "harness_artifacts": harness_artifacts,
        "commands": {
            "harness_command": None,
            "gating_test": None,
        },
        "missing_inputs": missing_inputs,
        "blockers": (
            ["exact local harness execution command not packaged"]
            if has_artifact
            else []
        ),
        "reproducibility_hints": _build_reproducibility_hints(poc_evidence),
        "evidence_boundary": (
            "harness artifacts are present but not execution-ready"
            if has_artifact
            else "no runnable harness artifact packaged; advisory/status bundle only"
        ),
    }


def draft_requires_live_proof(draft_path: Path) -> bool:
    """Heuristic: does this draft rely on live deployment/config truth?"""
    text = draft_path.read_text(errors="replace")
    patterns = [
        r"0x[a-fA-F0-9]{40}",
        r"\bon[- ]chain\b",
        r"\bpolygon mainnet\b",
        r"\bmainnet\b",
        r"\bdeployed\b",
        r"\blive[- ]state\b",
        r"\bdeployment topology\b",
        r"\bowner\(\)",
        r"\bpaused\(\)",
        r"\brolesOf\(",
        r"\bhasAnyRole\(",
        r"\bFEE_DENOMINATOR\(\)",
        r"\bDELAY_PERIOD\(\)",
        r"\bgetMaxFeeRate\(\)",
        r"\boracle\(\)",
    ]
    hits = sum(1 for pattern in patterns if re.search(pattern, text, flags=re.IGNORECASE))
    return hits >= 2


_LIVE_PROOF_OVERRIDE_PHRASES = (
    "live proof evidence: n/a",
    "live-proof evidence: n/a",
    "live proof evidence: na",
    "live-proof evidence: na",
    "source-only rationale",
    "source-only justification",
    "source only rationale",
    "source only justification",
    "no live proof required",
    "live proof not required",
    "pre-mainnet",
    "pre mainnet",
    "no l1 deployment",
    "no live deployment",
)


def draft_has_live_proof_override(draft_path: Path) -> bool:
    """Return true for explicit source-only/pre-mainnet live-proof opt-outs."""
    try:
        text = draft_path.read_text(errors="replace").lower()
    except Exception:
        return False
    return any(phrase in text for phrase in _LIVE_PROOF_OVERRIDE_PHRASES)


def extract_draft_focus_tokens(draft_path: Path) -> List[str]:
    """Extract contract/title-ish tokens to match against workspace narrative files."""
    text = draft_path.read_text(errors="replace")
    title = ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            title = stripped.lstrip("#").strip()
            break
    seed = "\n".join(
        part for part in [
            title,
            draft_path.stem.replace("_", " ").replace("-", " "),
            "\n".join(text.splitlines()[:80]),
        ] if part
    )
    raw_tokens = re.findall(r"\b[A-Z][A-Za-z0-9]{3,}\b", seed)
    raw_tokens.extend(re.findall(r"`([A-Za-z][A-Za-z0-9]{3,})`", seed))
    raw_tokens.extend(re.findall(r"\b[a-z][a-z0-9_-]{4,}\b", draft_path.stem.lower()))
    stopwords = {
        "draft", "submission", "title", "impact", "severity", "summary",
        "issue", "finding", "proof", "live", "state", "check", "notes",
        "staging", "source", "result", "results", "package", "review",
        "block", "report", "final", "operator", "vector", "novel",
        "cantina", "high", "medium", "low", "critical", "likelihood",
        "standardized", "smart", "contract", "originality", "scope",
        "target", "same", "copy", "fork", "dupe", "polygon", "rubric",
        "every",
    }
    tokens: List[str] = []
    seen = set()
    for token in raw_tokens:
        norm = token.strip("`").strip().lower()
        if len(norm) < 4 or norm in stopwords:
            continue
        if norm not in seen:
            seen.add(norm)
            tokens.append(norm)
    return tokens[:20]


def narrative_conflict_details(ws: Path, draft_path: Path) -> Dict[str, Any]:
    """Scan narrative workspace artifacts for likely contradictions to this draft."""
    draft_tokens = extract_draft_focus_tokens(draft_path)
    details: Dict[str, Any] = {
        "draft_tokens": draft_tokens,
        "scanned_files": [],
        "matches": [],
    }
    if not draft_tokens:
        return details

    candidates: List[Path] = []
    for path in (ws / "STATUS.md", ws / "FINAL_REPORT.md"):
        if path.exists():
            candidates.append(path)
    notes_dir = ws / "notes"
    if notes_dir.is_dir():
        for pattern in ("*verdict*.md", "*no_bug*.md"):
            candidates.extend(sorted(notes_dir.glob(pattern)))

    phrase_specs = [
        ("no-bug", re.compile(r"\bno (?:bug|exploitable bug|exploitable issue)\b", re.IGNORECASE)),
        ("cleared", re.compile(r"\bcleared\b|\bclose[sd]-?(?:as)?-(?:fp|oos|na)\b", re.IGNORECASE)),
        ("dead-code", re.compile(r"\bdead code\b", re.IGNORECASE)),
        ("deployment-only", re.compile(r"\bdeployment-only\b|\bdeployment only\b|\bconfig(?:uration)?-only\b", re.IGNORECASE)),
        ("not-affected", re.compile(r"\bnot affected\b|\bnot vulnerable\b|\bfalse positive\b|\bnot reproducible\b", re.IGNORECASE)),
    ]

    for path in candidates:
        details["scanned_files"].append(str(path))
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        text_lower = text.lower()
        matched_tokens = [token for token in draft_tokens if token in text_lower]
        if not matched_tokens:
            continue
        matched_phrases: List[str] = []
        excerpt = ""
        for label, pattern in phrase_specs:
            match = pattern.search(text)
            if not match:
                continue
            matched_phrases.append(label)
            if not excerpt:
                start = max(0, match.start() - 120)
                end = min(len(text), match.end() + 120)
                excerpt = " ".join(text[start:end].split())
        if not matched_phrases:
            continue
        details["matches"].append(
            {
                "path": str(path),
                "matched_tokens": matched_tokens[:5],
                "matched_phrases": matched_phrases,
                "excerpt": excerpt[:400],
            }
        )
    return details


def extract_live_proof_metadata(draft_path: Path, known_ids: set[str]) -> Dict[str, List[str]]:
    """Extract explicitly cited live-proof row IDs and angle IDs from a draft."""
    text = draft_path.read_text(errors="replace")
    lines = text.splitlines()
    ids: List[str] = []
    angle_ids: List[str] = []
    in_section = False
    for line in lines:
        stripped = line.strip()
        if re.match(r"^##+\s+Live Proof\b", stripped, flags=re.IGNORECASE):
            in_section = True
            continue
        if in_section and re.match(r"^##+\s+", stripped):
            break
        if not in_section and not re.search(r"live[- ]?proof", stripped, flags=re.IGNORECASE):
            continue
        candidates = re.findall(r"\b[A-Za-z0-9][A-Za-z0-9._-]{4,}\b", stripped)
        for candidate in candidates:
            if candidate in known_ids and candidate not in ids:
                ids.append(candidate)
        for angle_id in re.findall(r"\bA-[A-Z0-9-]+\b", stripped):
            if angle_id not in angle_ids:
                angle_ids.append(angle_id)
    return {"referenced_ids": ids, "draft_angle_ids": angle_ids}


def summarize_live_proof(ws: Path, draft_path: Path) -> Dict[str, Any]:
    """Summarize whether the workspace has actionable live-proof evidence for this draft."""
    summary: Dict[str, Any] = {
        "draft_requires_live_proof": draft_requires_live_proof(draft_path),
        "deployment_topology_present": (ws / "deployment_topology.json").exists(),
        "live_check_dossier_present": (ws / "live_topology_checks.json").exists(),
        "matching_live_rows": 0,
        "matched_ids": [],
        "referenced_ids": [],
        "draft_angle_ids": [],
        "missing_references": [],
        "blocks": [],
        "missing_block_for_executed": [],
        "statuses": {},
        "angle_linked_rows": 0,
        "angle_linked_ids": [],
        "rows_missing_angle_binding": [],
        "proof_status": "not-required",
    }
    if not summary["draft_requires_live_proof"]:
        return summary
    if draft_has_live_proof_override(draft_path):
        summary["proof_status"] = "source-only"
        summary["override"] = "source-only/pre-mainnet"
        return summary

    dossier_path = ws / "live_topology_checks.json"
    if not dossier_path.exists():
        summary["proof_status"] = "missing"
        return summary

    try:
        payload = json.loads(dossier_path.read_text())
    except json.JSONDecodeError:
        summary["proof_status"] = "malformed"
        return summary

    results = payload.get("results", [])
    if not isinstance(results, list):
        summary["proof_status"] = "malformed"
        return summary

    known_ids = {
        str(result.get("id") or "").strip()
        for result in results
        if isinstance(result, dict) and str(result.get("id") or "").strip()
    }
    proof_meta = extract_live_proof_metadata(draft_path, known_ids)
    referenced_ids = proof_meta["referenced_ids"]
    draft_angle_ids = proof_meta["draft_angle_ids"]
    summary["referenced_ids"] = referenced_ids
    summary["draft_angle_ids"] = draft_angle_ids

    text = draft_path.read_text(errors="replace")
    text_lower = text.lower()
    addresses = {match.lower() for match in re.findall(r"0x[a-fA-F0-9]{40}", text)}

    matched: List[Dict[str, Any]] = []
    for result in results:
        if not isinstance(result, dict):
            continue
        result_id = str(result.get("id") or "").strip()
        contract = str(result.get("contract") or "").strip()
        address = str(result.get("address") or "").strip().lower()
        explicit_ref = result_id and result_id in referenced_ids
        heuristic_match = (contract and contract.lower() in text_lower) or (address and address in addresses)
        if explicit_ref or heuristic_match:
            matched.append(result)

    summary["matching_live_rows"] = len(matched)
    summary["matched_ids"] = [
        str(result.get("id") or "").strip()
        for result in matched
        if str(result.get("id") or "").strip()
    ]
    angle_linked_rows = []
    rows_missing_angle_binding = []
    if draft_angle_ids:
        wanted = set(draft_angle_ids)
        for result in matched:
            row_angles = [
                str(item).strip()
                for item in result.get("related_angle_ids", [])
                if str(item).strip()
            ]
            if row_angles and wanted.intersection(row_angles):
                angle_linked_rows.append(result)
            elif not row_angles:
                row_id = str(result.get("id") or "").strip()
                if row_id:
                    rows_missing_angle_binding.append(row_id)
    summary["angle_linked_rows"] = len(angle_linked_rows)
    summary["angle_linked_ids"] = [
        str(result.get("id") or "").strip()
        for result in angle_linked_rows
        if str(result.get("id") or "").strip()
    ]
    summary["rows_missing_angle_binding"] = rows_missing_angle_binding
    summary["blocks"] = sorted(
        {
            str(result.get("block") or "").strip()
            for result in matched
            if str(result.get("block") or "").strip()
        }
    )
    missing_references = [ref for ref in referenced_ids if ref not in summary["matched_ids"]]
    summary["missing_references"] = missing_references
    if not referenced_ids:
        summary["proof_status"] = "missing-refs"
        return summary
    if missing_references:
        summary["proof_status"] = "missing-refs"
        return summary
    if not matched:
        summary["proof_status"] = "no-matching-rows"
        return summary

    statuses: Dict[str, int] = {}
    for result in matched:
        status = str(result.get("status") or "unknown")
        statuses[status] = statuses.get(status, 0) + 1
    summary["statuses"] = statuses
    if statuses.get("pass") or statuses.get("fail"):
        summary["missing_block_for_executed"] = [
            str(result.get("id") or "").strip()
            for result in matched
            if str(result.get("status") or "") in {"pass", "fail"}
            and not str(result.get("block") or "").strip()
        ]

    if statuses.get("error"):
        summary["proof_status"] = "error"
    elif summary["missing_block_for_executed"]:
        summary["proof_status"] = "executed-unpinned"
    elif statuses.get("pass") or statuses.get("fail"):
        summary["proof_status"] = "executed"
    elif statuses.get("dry_run"):
        summary["proof_status"] = "dry-run-only"
    elif statuses.get("blocked_missing_rpc") or statuses.get("blocked_unresolved_address"):
        summary["proof_status"] = "blocked"
    else:
        summary["proof_status"] = "unknown"
    return summary


def build_replay_command(row: Dict[str, Any]) -> List[str]:
    """Build a stable replay command for one live-proof row."""
    command = [
        "python3",
        "${AUDITOOOR_DIR}/tools/live-state-checker.py",
        "--workspace",
        "${WORKSPACE_ROOT}",
        "--address",
        str(row.get("address") or ""),
        "--network",
        str(row.get("network") or "mainnet"),
    ]
    block = str(row.get("block") or row.get("check", {}).get("block") or "").strip()
    if block:
        command.extend(["--block", block])
    check = row.get("check", {}) if isinstance(row.get("check"), dict) else {}
    call = str(check.get("call") or "").strip()
    if call:
        command.extend(["--call", call])
    args = check.get("args")
    if isinstance(args, list) and args:
        command.extend(["--args", ",".join(str(arg) for arg in args)])
    expect = check.get("expect")
    if expect is not None and str(expect).strip():
        command.extend(["--expect", str(expect)])
    slot = str(check.get("slot") or "").strip()
    if slot:
        command.extend(["--slot", slot])
    balance_min = check.get("balance_min")
    if balance_min is not None and str(balance_min).strip():
        command.extend(["--balance-min", str(balance_min)])
    command.append("--json")
    return command


def quote_replay_part(part: str) -> str:
    """Quote a shell token while allowing replay env vars to expand safely."""
    if (
        part in {"${AUDITOOOR_DIR}", "${WORKSPACE_ROOT}"}
        or part.startswith("${AUDITOOOR_DIR}/")
        or part.startswith("${WORKSPACE_ROOT}/")
    ):
        return f'"{part}"'
    return shlex.quote(part)


def replay_output_name(row: Dict[str, Any]) -> str:
    """Return a stable output filename for one replay row."""
    row_id = str(row.get("id") or "live-proof")
    return f"{slugify(row_id) or 'live-proof'}.json"


def write_replay_bundle(live_proof_dir: Path, manifest: Dict[str, Any]) -> None:
    """Write a replay.sh helper and README for referenced live-proof rows."""
    rows = manifest.get("referenced_rows", [])
    if not isinstance(rows, list):
        rows = []
    replay_outputs = manifest.setdefault("replay_outputs", [])
    if not isinstance(replay_outputs, list):
        replay_outputs = []
        manifest["replay_outputs"] = replay_outputs

    replay_lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        'SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"',
        'AUDITOOOR_DIR="${AUDITOOOR_DIR:-'"${PWD}"'}"',
        'WORKSPACE_ROOT="${WORKSPACE_ROOT:-'"${PWD}"'}"',
        'OUTPUT_DIR="${OUTPUT_DIR:-${SCRIPT_DIR}/outputs}"',
        "",
        'if [ ! -f "${AUDITOOOR_DIR}/tools/live-state-checker.py" ]; then',
        '  echo "[replay] Set AUDITOOOR_DIR to the auditooor repo root." >&2',
        "  exit 1",
        "fi",
        "",
        'if [ ! -d "${WORKSPACE_ROOT}" ]; then',
        '  echo "[replay] Set WORKSPACE_ROOT to the audit workspace root." >&2',
        "  exit 1",
        "fi",
        "",
        'mkdir -p "${OUTPUT_DIR}"',
        "",
    ]
    readme_lines = [
        "# Live Proof Replay",
        "",
        "This bundle preserves the exact live-proof rows cited by the draft.",
        "",
        "Replay usage:",
        "```bash",
        "AUDITOOOR_DIR=/path/to/auditooor \\",
        "WORKSPACE_ROOT=/path/to/workspace \\",
        "OUTPUT_DIR=/tmp/live-proof-replay \\",
        "./replay.sh",
        "```",
        "",
        "Replay outputs:",
        "- `outputs/<row-id>.json` captures one replayed checker result per cited row.",
        "",
        "Referenced rows:",
    ]

    imported_manual_rows = [
        row for row in rows
        if isinstance(row, dict) and str(row.get("manual_proof_source") or "").strip()
    ]
    if imported_manual_rows:
        readme_lines.extend([
            "",
            "Imported manual proofs:",
        ])
        for row in imported_manual_rows:
            row_id = str(row.get("id") or "unknown-proof")
            source = str(row.get("manual_proof_source") or "").strip()
            manual_status = str(row.get("manual_proof_status") or row.get("status") or "unknown")
            pair_id = str(row.get("proof_pair_id") or row.get("pair_id") or "").strip()
            pair_bits: List[str] = []
            if pair_id:
                pair_bits.append(f"pair `{pair_id}`")
            if row.get("pair_complete") is not None:
                pair_bits.append(f"complete `{bool(row.get('pair_complete'))}`")
            if row.get("same_block") is not None:
                pair_bits.append(f"same_block `{bool(row.get('same_block'))}`")
            pair_blocks = row.get("pair_blocks")
            if isinstance(pair_blocks, list) and pair_blocks:
                pair_bits.append("blocks " + ", ".join(f"`{block}`" for block in pair_blocks if str(block).strip()))
            pair_suffix = f" ({'; '.join(pair_bits)})" if pair_bits else ""
            readme_lines.append(f"- `{row_id}` — `{manual_status}` from `{source}`{pair_suffix}")

    specs = manifest.get("specs", [])
    if isinstance(specs, list) and specs:
        readme_lines.extend(["", "Bundled specs:"])
        for spec in specs:
            if not isinstance(spec, dict):
                continue
            source_path = str(spec.get("source_path") or "unknown")
            bundle_path = str(spec.get("bundle_path") or "missing")
            status = str(spec.get("status") or "unknown")
            readme_lines.append(f"- `{bundle_path}` — `{status}` from `{source_path}`")

    if not rows:
        replay_lines.append('echo "[replay] No exact live-proof rows were bundled for replay." >&2')
        readme_lines.append("- No exact live-proof rows were bundled for replay.")

    for row in rows:
        if not isinstance(row, dict):
            continue
        row_id = str(row.get("id") or "unknown-proof")
        block = str(row.get("block") or row.get("check", {}).get("block") or "").strip() or "untracked"
        status = str(row.get("status") or "unknown")
        manual_source = str(row.get("manual_proof_source") or "").strip()
        manual_status = str(row.get("manual_proof_status") or "").strip()
        pair_id = str(row.get("proof_pair_id") or row.get("pair_id") or "").strip()
        pair_complete = row.get("pair_complete")
        same_block = row.get("same_block")
        pair_blocks = row.get("pair_blocks")
        output_name = replay_output_name(row)
        replay_outputs.append({
            "id": row_id,
            "path": f"outputs/{output_name}",
            "status": status,
            "block": block,
        })
        replay_lines.append(f'echo "[replay] {row_id} @ block {block}"')
        replay_lines.append(
            " ".join(quote_replay_part(part) for part in build_replay_command(row))
            + f' | tee "${{OUTPUT_DIR}}/{output_name}"'
        )
        replay_lines.append("")
        row_bits = [f"status `{status}` @ block `{block}`"]
        if manual_source:
            row_bits.append(f"manual `{manual_status or status}` from `{manual_source}`")
        if pair_id:
            row_bits.append(f"pair `{pair_id}`")
        if pair_complete is not None:
            row_bits.append(f"complete `{bool(pair_complete)}`")
        if same_block is not None:
            row_bits.append(f"same_block `{bool(same_block)}`")
        if isinstance(pair_blocks, list) and pair_blocks:
            row_bits.append("blocks " + ", ".join(f"`{block}`" for block in pair_blocks if str(block).strip()))
        readme_lines.append(
            f"- `{row_id}` — " + "; ".join(row_bits) + f" → `outputs/{output_name}`"
        )

    replay_path = live_proof_dir / "replay.sh"
    replay_path.write_text("\n".join(replay_lines).rstrip() + "\n")
    os.chmod(replay_path, 0o755)
    (live_proof_dir / "REPLAY.md").write_text("\n".join(readme_lines).rstrip() + "\n")


def bundle_live_proof_specs(live_proof_dir: Path, payload: Dict[str, Any]) -> List[Dict[str, str]]:
    """Copy the live-check spec(s) that produced the dossier into the package."""
    specs_dir = live_proof_dir / "specs"
    bundled: List[Dict[str, str]] = []
    seen: set[str] = set()
    for raw_path in [payload.get("spec")]:
        source_path = str(raw_path or "").strip()
        if not source_path or source_path in seen:
            continue
        seen.add(source_path)
        entry = {"source_path": source_path, "bundle_path": "", "status": "missing"}
        source = Path(source_path)
        if source.exists() and source.is_file():
            specs_dir.mkdir(exist_ok=True)
            dest = specs_dir / source.name
            shutil.copy2(source, dest)
            entry["bundle_path"] = f"specs/{dest.name}"
            entry["status"] = "copied"
        bundled.append(entry)
    return bundled


def bundle_manual_proof_sources(live_proof_dir: Path, referenced_rows: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Copy cited manual proof source files into the package when available."""
    manual_dir = live_proof_dir / "manual-proofs"
    bundled: List[Dict[str, str]] = []
    seen: set[str] = set()
    for row in referenced_rows:
        if not isinstance(row, dict):
            continue
        source_path = str(row.get("manual_proof_source") or "").strip()
        if not source_path or source_path in seen:
            continue
        seen.add(source_path)
        entry = {
            "row_id": str(row.get("id") or "").strip(),
            "source_path": source_path,
            "bundle_path": "",
            "status": "missing",
        }
        source = Path(source_path)
        if source.exists() and source.is_file():
            manual_dir.mkdir(exist_ok=True)
            dest = manual_dir / source.name
            shutil.copy2(source, dest)
            entry["bundle_path"] = f"manual-proofs/{dest.name}"
            entry["status"] = "copied"
        bundled.append(entry)
    return bundled


def build_proof_pairs(
    draft_angle_ids: List[str],
    referenced_rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Build explicit edge/authority proof pairs for cross-contract topology claims."""
    pair_angles = {"A-RACE", "A-AUTH", "A-ORACLE"}
    draft_wanted = [angle_id for angle_id in draft_angle_ids if angle_id in pair_angles]
    topology_rows = [
        row for row in referenced_rows
        if isinstance(row, dict) and str(row.get("evidence_class") or "").strip() == "topology-relation"
    ]
    pairs: List[Dict[str, Any]] = []
    for angle_id in draft_wanted:
        matching = [
            row for row in topology_rows
            if angle_id in {
                str(item).strip()
                for item in row.get("related_angle_ids", [])
                if str(item).strip()
            }
        ]
        if not matching:
            continue
        distinct_contracts: List[str] = []
        pair_rows: List[Dict[str, Any]] = []
        for row in matching:
            contract = str(row.get("contract") or "").strip()
            if contract and contract not in distinct_contracts:
                distinct_contracts.append(contract)
                pair_rows.append(row)
            if len(pair_rows) >= 2:
                break
        blocks = sorted(
            {
                str(row.get("block") or "").strip()
                for row in pair_rows
                if str(row.get("block") or "").strip()
            }
        )
        pair: Dict[str, Any] = {
            "pair_id": f"{slugify(angle_id)}-topology-pair",
            "angle_id": angle_id,
            "pair_complete": len(pair_rows) >= 2,
            "edge_row_id": "",
            "authority_row_id": "",
            "edge_row": None,
            "authority_row": None,
            "pair_blocks": blocks,
            "same_block": len(blocks) == 1 if blocks else False,
            "missing_half": None,
            "pair_rationale": "Cross-contract topology claims should preserve both the live edge and its controlling authority/wiring proof.",
        }
        if pair_rows:
            pair["edge_row_id"] = str(pair_rows[0].get("id") or "").strip()
            pair["edge_row"] = pair_rows[0]
        if len(pair_rows) > 1:
            pair["authority_row_id"] = str(pair_rows[1].get("id") or "").strip()
            pair["authority_row"] = pair_rows[1]
        else:
            pair["missing_half"] = "authority-or-counterparty"
        pairs.append(pair)
    return pairs


def summarize_proof_pair_integrity(proof_pairs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarize whether packaged topology proof pairs are complete and same-block."""
    summary: Dict[str, Any] = {
        "declared": len(proof_pairs),
        "complete": 0,
        "same_block": 0,
        "incomplete": 0,
        "cross_block": 0,
        "incomplete_pair_ids": [],
        "cross_block_pair_ids": [],
    }
    for pair in proof_pairs:
        if not isinstance(pair, dict):
            continue
        pair_id = str(pair.get("pair_id") or pair.get("id") or "").strip()
        pair_complete = bool(pair.get("pair_complete"))
        same_block = bool(pair.get("same_block"))
        if pair_complete:
            summary["complete"] += 1
        else:
            summary["incomplete"] += 1
            if pair_id:
                summary["incomplete_pair_ids"].append(pair_id)
        if same_block:
            summary["same_block"] += 1
        elif pair_complete:
            summary["cross_block"] += 1
            if pair_id:
                summary["cross_block_pair_ids"].append(pair_id)
    return summary


def canonical_check_value(value: Any) -> str:
    """Return a stable string form for replay-relevant check values."""
    if isinstance(value, list):
        return json.dumps([str(item) for item in value], separators=(",", ":"))
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    return str(value or "").strip()


def find_executed_live_proof_contradictions(
    referenced_rows: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Detect same-claim, same-block pass/fail contradictions in cited proof rows."""
    buckets: Dict[Tuple[str, str, str, str, str, str], List[Dict[str, Any]]] = {}
    for row in referenced_rows:
        if not isinstance(row, dict):
            continue
        status = str(row.get("status") or "").strip()
        if status not in {"pass", "fail"}:
            continue
        block = str(row.get("block") or row.get("check", {}).get("block") or "").strip()
        if not block:
            continue
        check = row.get("check", {}) if isinstance(row.get("check"), dict) else {}
        claim_key = (
            str(row.get("evidence_class") or "").strip(),
            str(row.get("contract") or "").strip(),
            str(row.get("address") or "").strip().lower(),
            str(row.get("network") or "").strip(),
            str(check.get("call") or check.get("slot") or "balance_min").strip(),
            "|".join(
                [
                    canonical_check_value(check.get("args")),
                    canonical_check_value(check.get("expect")),
                    canonical_check_value(check.get("slot")),
                    canonical_check_value(check.get("balance_min")),
                ]
            ),
        )
        buckets.setdefault((block, *claim_key), []).append(row)

    contradictions: List[Dict[str, Any]] = []
    for bucket_key, rows in buckets.items():
        statuses = {str(row.get("status") or "").strip() for row in rows}
        if not {"pass", "fail"}.issubset(statuses):
            continue
        block, evidence_class, contract, address, network, check_kind, check_signature = bucket_key
        pass_rows = [
            {
                "id": str(row.get("id") or "").strip(),
                "status": "pass",
                "manual_proof_source": str(row.get("manual_proof_source") or "").strip(),
            }
            for row in rows
            if str(row.get("status") or "").strip() == "pass"
        ]
        fail_rows = [
            {
                "id": str(row.get("id") or "").strip(),
                "status": "fail",
                "manual_proof_source": str(row.get("manual_proof_source") or "").strip(),
            }
            for row in rows
            if str(row.get("status") or "").strip() == "fail"
        ]
        contradictions.append(
            {
                "claim_key": {
                    "evidence_class": evidence_class,
                    "contract": contract,
                    "address": address,
                    "network": network,
                    "check_kind": check_kind,
                    "check_signature": check_signature,
                },
                "block": block,
                "pass_rows": pass_rows,
                "fail_rows": fail_rows,
                "row_ids": [
                    item["id"]
                    for item in [*pass_rows, *fail_rows]
                    if item.get("id")
                ],
            }
        )
    contradictions.sort(
        key=lambda item: (
            str(item.get("claim_key", {}).get("contract") or ""),
            str(item.get("claim_key", {}).get("check_kind") or ""),
            str(item.get("block") or ""),
        )
    )
    return contradictions


# ----------------------------------------------------------------------------
# PR 101 — Fork-replay packaging
#
# `tools/fork-replay.sh` emits per-tx artifacts under <ws>/fork_replay/:
#     <tx>_replay.yaml        human-readable summary
#     <tx>_pre_state.json     watched-address state at fork block
#     <tx>_post_state.json    watched-address state after replay
#     <tx>_deltas.json        per-address native + ERC20 balance deltas
#     <tx>_manifest.json      {schema_version, status, tx, block, fork_block,
#                              from, to, artifacts{pre/post/deltas/trace/...}}
#     <tx>_trace.json         mainnet debug_traceTransaction
#     (optional) replay trace
#
# A High+ draft proving economic impact should cite one of these artifacts
# by path, typically the manifest or deltas. Packaging copies the manifest,
# summary YAML, pre-state, post-state, deltas, replay trace, and mainnet
# trace into <out_dir>/fork-replay/, and records the metadata in the root
# manifest so a triager can open one bundle and see the economic proof.
#
# Kept separate from live-proof/: fork replay proves economic deltas, live
# proof proves deployment/config facts.
# ----------------------------------------------------------------------------

FORK_REPLAY_REF_PATTERN = re.compile(
    r"(?:^|[\s(`\"'\[<])"
    r"(?P<rel>(?:<poc-dir>/|workspace/|./|)?fork_replay/[A-Za-z0-9_./-]+"
    r"(?:_manifest\.json|_deltas\.json|_replay\.yaml))"
)


def _resolve_fork_replay_ref(ws: Path, rel: str) -> Optional[Path]:
    """Resolve a cited `fork_replay/...` path strictly under the workspace root.

    Rejects absolute paths and traversal attempts. Returns the resolved Path
    iff it exists and lives under <ws>/fork_replay/.
    """
    if not rel:
        return None
    # Strip common prose prefixes the draft-render pipeline sometimes leaves.
    for prefix in ("<poc-dir>/", "workspace/", "./"):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
    if rel.startswith("/") or ".." in Path(rel).parts:
        return None
    if not rel.startswith("fork_replay/"):
        return None
    candidate = (ws / rel).resolve()
    fork_replay_root = (ws / "fork_replay").resolve()
    try:
        candidate.relative_to(fork_replay_root)
    except ValueError:
        return None
    return candidate if candidate.exists() else None


def extract_fork_replay_references(ws: Path, draft_path: Path) -> List[str]:
    """Return distinct `fork_replay/...` paths explicitly referenced in the draft."""
    try:
        text = draft_path.read_text(errors="replace")
    except Exception:
        return []
    seen: List[str] = []
    for match in FORK_REPLAY_REF_PATTERN.finditer(text):
        rel = match.group("rel").strip()
        for prefix in ("<poc-dir>/", "workspace/", "./"):
            if rel.startswith(prefix):
                rel = rel[len(prefix):]
        if rel and rel not in seen and rel.startswith("fork_replay/"):
            seen.append(rel)
    return seen


def _load_fork_replay_manifest(path: Path) -> Dict[str, Any]:
    """Load a fork-replay _manifest.json; return {} on parse failure."""
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def _load_fork_replay_deltas(path: Path) -> Dict[str, Any]:
    """Load a fork-replay _deltas.json; return {} on parse failure."""
    try:
        payload = json.loads(path.read_text())
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}
    return payload


def summarize_fork_replay(ws: Path, draft_path: Path) -> Dict[str, Any]:
    """Summarize fork-replay evidence explicitly cited by the draft.

    The summary feeds both the root package manifest (so a reviewer can see
    which replays back the draft) and the fail-closed gate on malformed cites.

    Returns:
        {
            "referenced": [<rel>, ...],                # strings exactly as cited
            "resolved": [<rel>, ...],                  # valid, under-workspace
            "missing": [<rel>, ...],                   # cited but unresolvable
            "malformed": [<rel>, ...],                 # resolved but unparsable
            "entries": [
                {
                    "reference": <rel>,
                    "kind": "manifest" | "deltas" | "summary",
                    "tx": str | None,
                    "block": int | None,
                    "fork_block": int | None,
                    "status": str | None,
                    "assertions": list | None,
                    "watched_addresses": [str],
                    "erc20_tokens": [str],
                    "manifest": <rel> | None,
                    "deltas": <rel> | None,
                    "summary": <rel> | None,
                    "pre_state": <rel> | None,
                    "post_state": <rel> | None,
                    "mainnet_trace": <rel> | None,
                    "replay_trace": <rel> | None,
                    "copied_files": [<bundle-relative-name>],
                },
                ...
            ],
        }

    `entries` is keyed by the resolved `<tx>_manifest.json` file where
    possible; cites that point at a deltas/summary file without a sibling
    manifest still produce an entry (kind=deltas|summary).
    """
    summary: Dict[str, Any] = {
        "referenced": [],
        "resolved": [],
        "missing": [],
        "malformed": [],
        "entries": [],
    }
    references = extract_fork_replay_references(ws, draft_path)
    summary["referenced"] = references
    if not references:
        return summary

    # Group cites by their tx stem so manifest + deltas for the same tx
    # collapse into one entry.
    entry_by_stem: Dict[str, Dict[str, Any]] = {}

    for rel in references:
        resolved = _resolve_fork_replay_ref(ws, rel)
        if resolved is None:
            summary["missing"].append(rel)
            continue

        # Derive the tx stem, e.g. "fork_replay/0xabc..._manifest.json"
        # -> "fork_replay/0xabc..."
        name = resolved.name
        stem = None
        for suffix in ("_manifest.json", "_deltas.json", "_replay.yaml"):
            if name.endswith(suffix):
                stem = str(Path("fork_replay") / name[: -len(suffix)])
                break
        if stem is None:
            summary["malformed"].append(rel)
            continue

        kind = (
            "manifest" if name.endswith("_manifest.json")
            else "deltas" if name.endswith("_deltas.json")
            else "summary"
        )

        entry = entry_by_stem.setdefault(stem, {
            "reference": rel,
            "kind": kind,
            "tx": None,
            "block": None,
            "fork_block": None,
            "status": None,
            "assertions": None,
            "watched_addresses": [],
            "erc20_tokens": [],
            "manifest": None,
            "deltas": None,
            "summary": None,
            "pre_state": None,
            "post_state": None,
            "mainnet_trace": None,
            "replay_trace": None,
            "copied_files": [],
        })

        summary["resolved"].append(rel)

        if kind == "manifest":
            payload = _load_fork_replay_manifest(resolved)
            if not payload:
                summary["malformed"].append(rel)
                continue
            entry["manifest"] = rel
            entry["tx"] = payload.get("tx")
            entry["status"] = payload.get("status")
            entry["assertions"] = payload.get("assertions")
            block = payload.get("block")
            fork_block = payload.get("fork_block")
            try:
                entry["block"] = int(block) if block is not None else None
            except (TypeError, ValueError):
                entry["block"] = None
            try:
                entry["fork_block"] = int(fork_block) if fork_block is not None else None
            except (TypeError, ValueError):
                entry["fork_block"] = None
            artifacts = payload.get("artifacts", {}) if isinstance(payload.get("artifacts"), dict) else {}
            for sibling_key, entry_key in (
                ("pre_state", "pre_state"),
                ("post_state", "post_state"),
                ("deltas", "deltas"),
                ("mainnet_trace", "mainnet_trace"),
                ("replay_trace", "replay_trace"),
                ("summary", "summary"),
            ):
                sibling_path = artifacts.get(sibling_key)
                if not sibling_path:
                    continue
                # Convert absolute manifest paths back to workspace-relative.
                sibling_resolved = Path(str(sibling_path))
                try:
                    if sibling_resolved.is_absolute():
                        rel_sibling = sibling_resolved.resolve().relative_to(ws.resolve())
                    else:
                        rel_sibling = Path(sibling_path)
                except (ValueError, OSError):
                    # Sibling lives outside the workspace — skip it rather than
                    # silently copy arbitrary files.
                    continue
                entry[entry_key] = str(rel_sibling)

        elif kind == "deltas":
            entry["deltas"] = rel
            deltas_payload = _load_fork_replay_deltas(resolved)
            if not deltas_payload:
                summary["malformed"].append(rel)
                continue
            # Harvest watched addresses + ERC20 tokens from the deltas so we
            # can surface them even when only deltas are cited.
            addresses = deltas_payload.get("addresses", {})
            if isinstance(addresses, dict):
                entry["watched_addresses"] = sorted(
                    {str(addr) for addr in addresses.keys()}
                )
                erc20 = set()
                for addr_data in addresses.values():
                    if not isinstance(addr_data, dict):
                        continue
                    tokens = addr_data.get("erc20", {})
                    if isinstance(tokens, dict):
                        for token_addr in tokens.keys():
                            erc20.add(str(token_addr))
                entry["erc20_tokens"] = sorted(erc20)

        else:
            # kind == "summary" — the YAML summary. Keep the reference but
            # don't parse YAML to avoid adding a runtime dep.
            entry["summary"] = rel

    # Codex PR-102 blocker 6: when a draft only cites deltas (or only the
    # YAML summary), discover sibling manifest/YAML/pre/post/trace files by
    # shared stem so the bundler can copy the full replay evidence, and the
    # evidence-matrix can read manifest.status/block/fork_block. Without
    # this, a deltas-only citation bundles nothing but the deltas file and
    # the reviewer cannot verify pin/status/block anchoring.
    _SIBLING_MAP: Tuple[Tuple[str, str], ...] = (
        ("_manifest.json",     "manifest"),
        ("_replay.yaml",       "summary"),
        ("_pre_state.json",    "pre_state"),
        ("_post_state.json",   "post_state"),
        ("_deltas.json",       "deltas"),
        ("_trace.json",        "mainnet_trace"),
        ("_replay_trace.json", "replay_trace"),
    )
    for stem, entry in entry_by_stem.items():
        # `stem` is a workspace-relative path like "fork_replay/0xabc...".
        for suffix, field in _SIBLING_MAP:
            if entry.get(field):
                # already populated (manifest branch filled this, or the
                # cite itself is this file)
                continue
            sibling_rel = f"{stem}{suffix}"
            sibling_path = _resolve_fork_replay_ref(ws, sibling_rel)
            if sibling_path is None:
                continue
            entry[field] = sibling_rel
            # If we just found a sibling manifest, back-fill status / block /
            # fork_block / tx from it so the evidence-matrix and Check #22
            # have semantic ground-truth even when only deltas were cited.
            if field == "manifest":
                payload = _load_fork_replay_manifest(sibling_path)
                if payload:
                    if entry.get("tx") is None:
                        entry["tx"] = payload.get("tx")
                    if entry.get("status") is None:
                        entry["status"] = payload.get("status")
                    if entry.get("assertions") is None:
                        entry["assertions"] = payload.get("assertions")
                    for k in ("block", "fork_block"):
                        if entry.get(k) is None:
                            raw = payload.get(k)
                            try:
                                entry[k] = int(raw) if raw is not None else None
                            except (TypeError, ValueError):
                                entry[k] = None

    summary["entries"] = list(entry_by_stem.values())
    return summary


def bundle_fork_replay(out_dir: Path, ws: Path, fork_replay_summary: Dict[str, Any]) -> Dict[str, Any]:
    """Copy fork-replay artifacts into the package bundle.

    Mirrors the `live-proof/` pattern. Creates `<out_dir>/fork-replay/` only
    if there is at least one resolved entry to bundle. Returns a manifest
    fragment suitable for the root package manifest's `fork_replay` key.

    Copied files per entry (existence-gated; absent files are recorded as None):
        <tx>_manifest.json
        <tx>_replay.yaml
        <tx>_pre_state.json
        <tx>_post_state.json
        <tx>_deltas.json
        <tx>_trace.json (mainnet)
        <tx>_replay_trace.json
    """
    manifest_fragment: Dict[str, Any] = {
        "referenced": list(fork_replay_summary.get("referenced", [])),
        "resolved": list(fork_replay_summary.get("resolved", [])),
        "missing": list(fork_replay_summary.get("missing", [])),
        "malformed": list(fork_replay_summary.get("malformed", [])),
        "entries": [],
    }

    entries = fork_replay_summary.get("entries", [])
    if not entries:
        return manifest_fragment

    fork_replay_dir = out_dir / "fork-replay"
    fork_replay_dir.mkdir(parents=True, exist_ok=True)

    # Bundle-local fork_replay/<rel> nested layout for pre-submit Check #22
    # offline review. See iter5-T2. The workspace-relative path already
    # starts with "fork_replay/" (that's the only prefix _resolve_fork_replay_ref
    # accepts), so we root the nested copy directly at the bundle root.
    # No top-level <bundle>/fork_replay/ directory is materialized when
    # no entries need nested copies.
    ws_resolved = ws.resolve()

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        copied: List[str] = []
        nested_copied: List[str] = []
        nested_skipped: List[Dict[str, str]] = []
        sibling_keys = (
            "manifest", "summary", "pre_state", "post_state",
            "deltas", "mainnet_trace", "replay_trace",
        )
        for key in sibling_keys:
            rel = entry.get(key)
            if not rel:
                continue
            resolved = _resolve_fork_replay_ref(ws, rel) if isinstance(rel, str) else None
            if resolved is None or not resolved.exists():
                continue
            target = fork_replay_dir / resolved.name
            try:
                shutil.copy2(resolved, target)
                copied.append(resolved.name)
            except (OSError, shutil.Error):
                continue

            # Bundle-local fork_replay/<rel> nested layout for pre-submit
            # Check #22 offline review. See iter5-T2.
            try:
                rel_from_ws = resolved.resolve().relative_to(ws_resolved)
            except ValueError:
                # Resolved file lives outside the workspace — record the
                # skip reason explicitly rather than synthesizing a path.
                nested_skipped.append({
                    "key": key,
                    "reason": "out-of-ws",
                })
                continue
            # rel_from_ws starts with "fork_replay/<...>" because
            # _resolve_fork_replay_ref gates on that prefix. Write the
            # bundle-local mirror at <out_dir>/<rel_from_ws> so
            # pre-submit Check #22's "_FR_WS/<rel>" lookup resolves.
            rel_str = str(rel_from_ws)
            if not rel_str.startswith("fork_replay/"):
                # Defensive: resolved file was inside the workspace but
                # not under fork_replay/ — this should be unreachable given
                # _resolve_fork_replay_ref's gate, but record and skip
                # rather than writing an arbitrary nested path.
                nested_skipped.append({
                    "key": key,
                    "reason": "out-of-fork-replay",
                })
                continue
            nested_target = out_dir / rel_from_ws
            try:
                nested_target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(resolved, nested_target)
                nested_copied.append(rel_str)
            except (OSError, shutil.Error):
                continue

        entry_fragment = dict(entry)
        entry_fragment["copied_files"] = copied
        entry_fragment["nested_copied_files"] = nested_copied
        if nested_skipped:
            entry_fragment["nested_copy_skipped"] = nested_skipped
        manifest_fragment["entries"].append(entry_fragment)

    return manifest_fragment


def validate_draft_path(ws: Path, draft_path: Path) -> Optional[str]:
    """Return an error string if draft_path is not an eligible staging draft."""
    staging_dir = (ws / "submissions" / "staging").resolve()
    clean_dir = (ws / "submissions" / "clean").resolve()
    engage_candidates_dir = (ws / "submissions" / "engage_candidates").resolve()
    try:
        draft_path.relative_to(staging_dir)
    except ValueError:
        try:
            draft_path.relative_to(clean_dir)
            return (
                "triager-clean renders under submissions/clean/ are not packageable; "
                f"use the source staging draft under {staging_dir}"
            )
        except ValueError:
            pass
        try:
            draft_path.relative_to(engage_candidates_dir)
            return (
                "engage-candidate drafts are not packageable here; "
                f"promote a concrete finding into {staging_dir} first"
            )
        except ValueError:
            pass
        return (
            "only concrete markdown drafts under "
            f"{staging_dir} are packageable review inputs"
        )
    if not draft_path.name.endswith(".md"):
        return "draft must be a markdown file"
    if draft_path.name.upper() in {"README.MD", "INDEX.MD"}:
        return "draft must be a concrete submission candidate, not an index/readme"
    if any(draft_path.name.endswith(suffix) for suffix in SKIP_DRAFT_SUFFIXES):
        return f"draft suffix is excluded from packaging: {draft_path.name}"
    return None


def scope_review_artifact(ws: Path, draft_path: Path) -> Path:
    """Return the expected heuristic review output path for a draft."""
    exact = ws / "scope_review" / f"{draft_path.stem}.heuristic-review.md"
    if exact.exists():
        return exact
    match = re.match(r"^(FN\d+)-draft$", draft_path.stem, flags=re.IGNORECASE)
    if match:
        aliases = sorted((ws / "scope_review").glob(f"{match.group(1)}-*.heuristic-review.md"))
        if aliases:
            return aliases[0]
    return exact


def scope_review_artifact_agent(ws: Path, draft_path: Path) -> Path:
    """Return the expected LLM-dispatched agent-review output path for a draft.

    Mirrors `scope_review_artifact` but targets the `.agent-review.md`
    sibling produced by `tools/scope-review.sh`. See iter5-T1.
    """
    exact = ws / "scope_review" / f"{draft_path.stem}.agent-review.md"
    if exact.exists():
        return exact
    match = re.match(r"^(FN\d+)-draft$", draft_path.stem, flags=re.IGNORECASE)
    if match:
        aliases = sorted((ws / "scope_review").glob(f"{match.group(1)}-*.agent-review.md"))
        if aliases:
            return aliases[0]
    return exact


# ---------------------------------------------------------------------------
# iter3-T1 — packager/pre-submit scope-review filename reconciliation.
#
# The packager copies the staging draft into the bundle as `source-draft.md`
# (see `package_submission`). `tools/pre-submit-check.sh` Check #11 derives
# its scope-review lookup from the draft basename:
#
#     _BASENAME=$(basename "$SUB" .md)
#     _REVIEW_HEU="$_WS/scope_review/${_BASENAME}.heuristic-review.md"
#
# When pre-submit is run against `<bundle>/source-draft.md`, `_BASENAME`
# becomes `source-draft` — and `_WS` is discovered by walking up the
# ancestors until an `OOS_CHECKLIST.md` / `SCOPE.md` anchor is found. The
# naive bundle layout therefore either (a) re-roots `_WS` to the audit
# workspace and misses the renamed review file, or (b) fails to find
# any anchor at all.
#
# Fix: the packager mirrors the scope-review artifact under the packager's
# `source-draft` basename AND drops a bundle-local `OOS_CHECKLIST.md` stub
# so pre-submit's ancestor walk terminates at the bundle root. This keeps
# pre-submit semantics unchanged (no edits to `tools/pre-submit-check.sh`)
# and preserves the reviewer-friendly `scope-review.md` alias we already
# wrote for human eyes. See `docs/LOOP_ITER_003_PLAN.md` §T1.
# ---------------------------------------------------------------------------


BUNDLE_OOS_CHECKLIST_CONTENT = (
    "<!-- Bundle-local scope-review anchor for pre-submit Check #11."
    " See iter3-T1. -->\n"
    "# Bundle-local OOS checklist anchor\n"
    "This file exists so pre-submit's `_WS` ancestor walk terminates at"
    " the bundle root.\n"
)


def bundle_scope_review(
    out_dir: Path,
    review_path: Optional[Path] = None,
    agent_review_path: Optional[Path] = None,
) -> None:
    """Write the bundle-local scope-review artifact(s) pre-submit Check #11 expects.

    In addition to the legacy reviewer-friendly ``scope-review.md`` copy
    (written by the caller), we mirror the source artifact(s) under
    ``<out_dir>/scope_review/source-draft.heuristic-review.md`` and/or
    ``<out_dir>/scope_review/source-draft.agent-review.md`` — this matches
    pre-submit Check #11's derivation verbatim when the packager has
    renamed the draft to ``source-draft.md``. We also drop an
    ``OOS_CHECKLIST.md`` stub at the bundle root so Check #11's workspace
    ancestor walk terminates at the bundle (not at the audit workspace).

    Either review_path or agent_review_path may be ``None`` / absent on
    disk. Fail-open: missing source files are silently skipped; no stub
    is ever synthesized. Check #11 accepts either flavor (iter5-T1).

    Idempotent: safe to call repeatedly on the same bundle.
    """
    bundle_review_dir = out_dir / "scope_review"
    bundle_review_dir.mkdir(parents=True, exist_ok=True)
    if review_path is not None and review_path.exists():
        shutil.copy2(review_path, bundle_review_dir / "source-draft.heuristic-review.md")
    # Bundle-local .agent-review.md mirror for pre-submit Check #11 (agent-review preferred over heuristic-review). See iter5-T1.
    if agent_review_path is not None and agent_review_path.exists():
        shutil.copy2(agent_review_path, bundle_review_dir / "source-draft.agent-review.md")

    checklist_path = out_dir / "OOS_CHECKLIST.md"
    # Idempotent: overwrite is safe because content is a fixed stub.
    checklist_path.write_text(BUNDLE_OOS_CHECKLIST_CONTENT)


# ---------------------------------------------------------------------------
# iter4-T1 — packager/pre-submit live-topology filename reconciliation.
#
# Post iter3-T1, pre-submit's `_WS` resolves to the bundle root (the
# `OOS_CHECKLIST.md` anchor above terminates the ancestor walk there).
# `tools/pre-submit-check.sh` Check #21 reads `$_WS/live_topology_checks.json`
# for drafts whose text trips `_live_proof_depends`. The packager already
# copies the workspace's `live_topology_checks.json` into
# `<bundle>/live-proof/` (for reviewer legibility) — but NOT to the bundle
# root where Check #21 now looks. Iter3 T2 surfaced the twin bug: `❌ 21.
# Draft appears deployment/live-state dependent, but <bundle>/live_topology
# _checks.json is missing`.
#
# Fix (mirrors iter3-T1 pattern): also mirror the workspace source file to
# `<bundle>/live_topology_checks.json` at the bundle root. The legacy
# `<bundle>/live-proof/live_topology_checks.json` copy stays put for
# reviewers. Pre-submit semantics unchanged (zero edits to
# `tools/pre-submit-check.sh`). See `docs/LOOP_ITER_004_PLAN.md` §T1.
#
# Fail-closed behavior is preserved by `summarize_live_proof` +
# `main()`'s existing gate at line ~1683: when a draft requires live proof
# but `<ws>/live_topology_checks.json` does not exist, packager already
# returns non-zero with "Live-proof artifact missing or invalid for
# deployment/config-dependent draft". The bundle-local copy helper below
# never synthesizes a stub; it only copies what already exists on disk.
# ---------------------------------------------------------------------------


def bundle_live_topology_anchor(out_dir: Path, ws: Path) -> None:
    """Mirror `<ws>/live_topology_checks.json` to `<out_dir>/live_topology_checks.json`.

    Called after the `<bundle>/live-proof/` subdirectory has been populated.
    The bundle-root copy exists solely so pre-submit Check #21's lookup
    (`$_WS/live_topology_checks.json`, with `_WS` resolving to the bundle
    root post iter3-T1) resolves without re-rooting `_WS` to the audit
    workspace.

    Idempotent: safe to call repeatedly on the same bundle (overwrites the
    existing file byte-for-byte with the current source). NEVER synthesizes
    a stub — missing-source handling lives in the caller's gates path and
    produces an explicit fail-closed error ("Live-proof artifact missing").
    """
    source = ws / "live_topology_checks.json"
    if not source.exists():
        # Caller's responsibility to decide whether missing-source is fatal.
        # Under `--skip-gates`, missing-source is acceptable (gates skip means
        # caller took responsibility); under gates-run, `summarize_live_proof`
        # already returns `proof_status="missing"` and `main()` fails closed
        # before this helper is called for live-proof-dependent drafts.
        return
    # Bundle-local live-topology anchor for pre-submit Check #21. See iter4-T1.
    shutil.copy2(source, out_dir / "live_topology_checks.json")


def extract_scope_verdict(output: str) -> str:
    """Extract the scope-review verdict from tool output."""
    match = re.search(r"VERDICT:\s*([A-Z-]+)", output)
    return match.group(1) if match else ""


# ---------------------------------------------------------------------------
# PR 108 — High+ Evidence Matrix
# ---------------------------------------------------------------------------

_HIGH_PLUS_SEVERITIES = {"HIGH", "CRITICAL", "HIGH+"}
_SOURCE_ONLY_PHRASES = (
    "source-only justification",
    "source only justification",
    "source-only evidence",
    "fork replay not applicable",
    "fork-replay not applicable",
    "source-only finding",
)


def _extract_severity_from_draft(draft_path: Path) -> str:
    """Best-effort severity sniff from the draft's front matter or body."""
    try:
        text = draft_path.read_text(errors="replace")
    except Exception:
        return "UNKNOWN"
    # Common patterns: "Severity: High", "**Severity**: High",
    # "**Severity (RECOMMENDED)**: **High**", YAML "severity: High".
    for pat in (
        r"(?mi)^\s*(?:[-*]\s*)?\**\s*severity(?:\s*\([^)]*\))?\s*\**\s*[:=]\s*\**\s*([A-Za-z+]+)",
        r"(?mi)^severity\s*:\s*([A-Za-z+]+)",
    ):
        m = re.search(pat, text)
        if m:
            return m.group(1).strip().upper()
    return "UNKNOWN"


def _draft_cites_source_only(draft_path: Path) -> bool:
    try:
        text = draft_path.read_text(errors="replace").lower()
    except Exception:
        return False
    return any(phrase in text for phrase in _SOURCE_ONLY_PHRASES)


_FR_GOOD_STATUSES = {"executed", "success"}


def _positive_intish(value: Any) -> bool:
    try:
        return int(value) > 0
    except (TypeError, ValueError):
        return False


def _fork_replay_entry_semantic_errors(entry: Dict[str, Any]) -> List[str]:
    """Return fail-closed replay proof errors for a summarized entry."""
    errors: List[str] = []
    status = str(entry.get("status") or "").lower()
    if status not in _FR_GOOD_STATUSES:
        errors.append(f"status-not-successful:{entry.get('status')!r}")
    for key in ("block", "fork_block"):
        if not _positive_intish(entry.get(key)):
            errors.append(f"missing-or-invalid-pin:{key}")
    assertions = entry.get("assertions")
    if assertions is None:
        errors.append("assertions-missing")
    elif not isinstance(assertions, list):
        errors.append("assertions-not-list")
    elif not assertions:
        errors.append("assertions-empty")
    else:
        statuses = [
            str(a.get("status") or "").upper()
            for a in assertions
            if isinstance(a, dict)
        ]
        if "FAIL" in statuses:
            errors.append("assertion-FAIL-present")
        if "INCONCLUSIVE" in statuses:
            errors.append("assertion-INCONCLUSIVE-present")
        if "PASS" not in statuses:
            errors.append("no-assertion-PASS")
    return errors


def _latest_fuzz_run_status(ws: Path) -> Tuple[str, List[str], str]:
    """Return (status, evidence_paths, notes) for the most recent fuzz run.

    status in {"PRESENT", "MISSING"}. "PRESENT" requires a manifest.json
    inside a dated run directory under <ws>/fuzz_runs/.
    """
    runs_root = ws / "fuzz_runs"
    if not runs_root.exists() or not runs_root.is_dir():
        return "MISSING", [], "No <ws>/fuzz_runs/ directory"
    candidates = [d for d in runs_root.iterdir() if d.is_dir()]
    if not candidates:
        return "MISSING", [], "fuzz_runs/ exists but is empty"
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    manifest = latest / "manifest.json"
    if not manifest.exists():
        return "MISSING", [], f"Latest run {latest.name} has no manifest.json"
    run_status = "unknown"
    try:
        payload = json.loads(manifest.read_text())
        if isinstance(payload, dict):
            run_status = str(payload.get("status") or payload.get("result") or "unknown")
    except Exception:
        pass
    return "PRESENT", [str(manifest)], f"Latest fuzz run: {latest.name} (status={run_status})"


def _classify_factory_header_line(first_line: Optional[str]) -> Optional[str]:
    """Classify a ``cantina_ready.md`` first-line header string into the
    internal vocabulary used by Row-7.

    Extracted so ``package_submission`` (FIX-8B) can cache the header
    line BEFORE ``shutil.rmtree`` wipes the bundle, and
    ``_read_factory_triager_header`` can share the exact same
    classification rules.

    Returns the same values as ``_read_factory_triager_header``.
    """
    if first_line is None:
        return None
    stripped = first_line.strip()
    if stripped == "<!-- triager-risk: markers present -->":
        return "markers_present"
    if stripped == "<!-- triager-risk: no-known-class -->":
        return "no_known_class"
    return None


def _read_factory_triager_header(bundle_dir: Optional[Path]) -> Optional[str]:
    """Read the `<!-- triager-risk: ... -->` first-line header written by
    `tools/submission-factory.py::build_cantina_ready` (capv3 iter-v3-7 T1).

    Returns:
        - ``"markers_present"`` if header reads ``markers present``
        - ``"no_known_class"`` if header reads ``no-known-class``
        - ``None`` if the bundle has no ``cantina_ready.md`` yet or the
          first line does not match the factory vocabulary.

    capv3 iter-v3-8 T4: consumer hook only. The producer (factory) is
    unchanged; this reader simply surfaces the factory's vocabulary into
    the evidence-matrix Row-7 ``notes`` string when both sources are
    available. Pre-submit Check #20 output continues to take precedence
    — this is a supplementary signal for the honest-zero case.

    FIX-8B: prefer the pre-cached header threaded through by
    ``package_submission`` (see ``build_evidence_matrix``'s
    ``factory_header`` kwarg). This on-disk reader is still used by
    callers that supply ``bundle_dir`` but no cached header (e.g. the
    hermetic T4 unit tests) and as a fallback inside
    ``build_evidence_matrix`` when the cache is empty.
    """
    if bundle_dir is None:
        return None
    try:
        cantina_path = bundle_dir / "cantina_ready.md"
        if not cantina_path.exists():
            return None
        with cantina_path.open("r", encoding="utf-8", errors="replace") as fh:
            first = fh.readline()
    except OSError:
        return None
    return _classify_factory_header_line(first)


def build_evidence_matrix(
    results: Dict[str, Any],
    *,
    draft_path: Optional[Path] = None,
    ws: Optional[Path] = None,
    poc_found: Optional[bool] = None,
    poc_evidence: Optional[Dict[str, Any]] = None,
    severity_override: Optional[str] = None,
    bundle_dir: Optional[Path] = None,
    factory_header: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a per-draft evidence matrix from the in-flight `results` dict.

    See PR 108 in docs/ROADMAP_10_OF_10.md for row semantics.

    ``bundle_dir`` (capv3 iter-v3-8 T4): optional path to the packaged
    bundle. When supplied and the bundle contains a factory-rendered
    ``cantina_ready.md``, Row-7 ("Triager-risk rules") supplements its
    notes with the factory's ``<!-- triager-risk: ... -->`` header state.
    Pre-submit Check #20 output still wins; factory header is advisory.

    ``factory_header`` (FIX-8B): optional pre-classified header value
    (``"markers_present"``, ``"no_known_class"``, or ``None``) cached by
    ``package_submission`` *before* it calls ``shutil.rmtree(out_dir)``.
    In the real packaging lifecycle the factory-rendered
    ``cantina_ready.md`` that lived in the *previous* packaged bundle is
    destroyed by that rmtree before Row-7 gets a chance to read it, so
    any caller that cannot re-emit the factory file into the rebuilt
    bundle must instead cache the header and thread it through here.
    Precedence: cached value wins; fall back to reading
    ``bundle_dir/cantina_ready.md`` only if no cached value was
    supplied. This keeps T4's hermetic unit tests (which pre-populate
    ``bundle_dir`` and pass ``factory_header=None`` implicitly) unchanged.
    """
    if severity_override:
        severity = severity_override.upper()
    elif draft_path is not None:
        severity = _extract_severity_from_draft(draft_path)
    else:
        severity = "UNKNOWN"
    is_high_plus = severity in _HIGH_PLUS_SEVERITIES

    rows: List[Dict[str, Any]] = []

    # --- Row 1: PoC / exploit harness ------------------------------------
    if poc_found is None:
        # Fall back to inspecting results: package_submission records no explicit
        # flag, but the presence of a copied poc file is determinable later.
        poc_found = bool(results.get("poc_present"))
    if poc_evidence is None:
        raw_evidence = results.get("poc_evidence")
        poc_evidence = raw_evidence if isinstance(raw_evidence, dict) else {}
    evidence_paths = [
        str(item)
        for item in (poc_evidence.get("paths") or [])
        if str(item).strip()
    ]
    poc_present = bool(poc_found or poc_evidence.get("present"))
    poc_label = str(poc_evidence.get("label") or "Forge PoC")
    if poc_found and not evidence_paths:
        evidence_paths = ["poc.t.sol"]
    poc_notes = str(
        poc_evidence.get("notes")
        or ("PoC file copied into bundle" if poc_present else "No PoC discovered for this draft")
    )
    rows.append({
        "key": "forge_poc",
        "label": poc_label,
        "status": "PRESENT" if poc_present else "MISSING",
        "evidence": evidence_paths,
        "notes": poc_notes,
    })

    # --- Row 2: Fork replay ----------------------------------------------
    fr = results.get("fork_replay") or {}
    fr_entries = fr.get("entries") or []
    fr_missing = fr.get("missing") or []
    fr_malformed = fr.get("malformed") or []
    semantic_errors: List[str] = []
    good_entries: List[Dict[str, Any]] = []
    for entry in fr_entries:
        if not isinstance(entry, dict):
            continue
        errors = _fork_replay_entry_semantic_errors(entry)
        if errors:
            ref = str(entry.get("reference") or entry.get("manifest") or "fork-replay-entry")
            semantic_errors.append(f"{ref}: {', '.join(errors)}")
        else:
            good_entries.append(entry)
    if fr_missing or fr_malformed:
        fr_status = "MISSING"
        fr_notes = f"Cited fork-replay artifact(s) unresolved: {fr_missing + fr_malformed}"
    elif good_entries:
        fr_status = "PRESENT"
        fr_notes = f"{len(good_entries)} fork-replay entry(ies) with semantic replay proof"
    elif fr_entries:
        fr_status = "PARTIAL"
        sample = "; ".join(semantic_errors[:3])
        if len(semantic_errors) > 3:
            sample += f"; ... {len(semantic_errors) - 3} more"
        fr_notes = f"Fork-replay entries failed semantic validation: {sample}"
    else:
        # No citations in the draft.
        # Codex PR-102 blocker 7: if the High+ draft explicitly asserts
        # source-only justification (and references a Forge PoC that the
        # pre-submit check has validated — see packager's `gates.pre_submit`
        # wiring in caller), the fork-replay row should be N/A so the
        # SOURCE_ONLY verdict path (below) is reachable. Previously this
        # branch always set PARTIAL for High+, which collapsed into BLOCKED
        # via required_for_high_plus and made SOURCE_ONLY impossible.
        source_only_claim = bool(
            draft_path is not None and _draft_cites_source_only(draft_path)
        )
        if is_high_plus and source_only_claim:
            fr_status = "N/A"
            fr_notes = (
                "Source-only High+ justification — fork replay not applicable "
                "(requires pre-submit Check #22 + Forge PoC PASS to ship)"
            )
        elif is_high_plus:
            fr_status = "PARTIAL"
            fr_notes = "High+ draft did not cite a fork-replay artifact"
        else:
            fr_status = "N/A"
            fr_notes = "Fork replay advisory for Medium/Low severity"
    rows.append({
        "key": "fork_replay",
        "label": "Fork replay (economic delta)",
        "status": fr_status,
        "evidence": [str(e.get("reference") or e.get("manifest") or "")
                     for e in fr_entries if isinstance(e, dict)],
        "notes": fr_notes,
    })

    # --- Row 3: Live topology proof --------------------------------------
    lp = results.get("live_proof") or {}
    lp_status_key = str(lp.get("proof_status") or "unknown")
    if lp_status_key in {"not-required", "source-only"}:
        live_status = "N/A"
    elif lp_status_key in {"executed", "executed-pass"}:
        live_status = "PRESENT"
    elif lp_status_key in {"dry-run-only", "blocked", "no-matching-rows"}:
        live_status = "PARTIAL"
    elif lp_status_key in {"missing", "missing-refs", "executed-unpinned", "malformed", "error"}:
        live_status = "MISSING"
    else:
        live_status = "PARTIAL"
    rows.append({
        "key": "live_proof",
        "label": "Live topology proof",
        "status": live_status,
        "evidence": list(lp.get("referenced_ids") or []),
        "notes": f"proof_status={lp_status_key}",
    })

    # --- Row 4: Fuzz / invariant run -------------------------------------
    if ws is not None:
        fuzz_status, fuzz_paths, fuzz_notes = _latest_fuzz_run_status(ws)
    else:
        fuzz_status, fuzz_paths, fuzz_notes = "MISSING", [], "No workspace provided"
    if fuzz_status == "MISSING" and is_high_plus:
        fuzz_row_status = "PARTIAL"
    elif fuzz_status == "MISSING":
        fuzz_row_status = "N/A"
        fuzz_notes = fuzz_notes + " (advisory for non-High+)"
    else:
        fuzz_row_status = "PRESENT"
    rows.append({
        "key": "fuzz_run",
        "label": "Fuzz / invariant run",
        "status": fuzz_row_status,
        "evidence": fuzz_paths,
        "notes": fuzz_notes,
    })

    # --- Row 5: Symbolic result (PR 109 pending) --------------------------
    rows.append({
        "key": "symbolic",
        "label": "Symbolic counterexample",
        "status": "N/A",
        "evidence": [],
        "notes": "Phase C — PR 109 pending",
    })

    # --- Row 6: Duplicate risk check -------------------------------------
    variant = (results.get("gates") or {}).get("variant") or {}
    dupe_risk = str(variant.get("risk_level") or "").upper()
    if dupe_risk in {"LOW", "MEDIUM", "HIGH"}:
        dupe_status = "PRESENT"
        dupe_notes = f"variant-detector risk_level={dupe_risk}"
    else:
        dupe_status = "MISSING"
        dupe_risk = "UNKNOWN"
        dupe_notes = "variant-detector did not report a risk_level"
    rows.append({
        "key": "dupe_check",
        "label": "Duplicate risk",
        "status": dupe_status,
        "risk": dupe_risk,
        "evidence": [],
        "notes": dupe_notes,
    })

    # --- Row 7: Triager-risk (pre-submit check #20 + factory header) -----
    # capv3 iter-v3-8 T4: supplement the pre-submit-check.sh Check #20 signal
    # with the factory's ``<!-- triager-risk: markers present -->`` /
    # ``<!-- triager-risk: no-known-class -->`` header (emitted by
    # ``tools/submission-factory.py::build_cantina_ready``, iter-v3-7 T1).
    #
    # Precedence:
    #   * pre-submit present + factory header present →
    #       "pre-submit #20 executed; factory header confirms <state>"
    #   * pre-submit present + factory header missing →
    #       (preserved byte-for-byte) "pre-submit check #20 executed"
    #   * pre-submit absent  + factory header present →
    #       "factory header only: <state> (advisory)"
    #   * pre-submit absent  + factory header missing →
    #       (preserved byte-for-byte) "pre-submit output did not include check #20 line"
    #
    # Status still derives solely from pre-submit Check #20 — the factory
    # header is notes-only; it cannot flip PRESENT/MISSING on its own.
    pre_submit = (results.get("gates") or {}).get("pre_submit") or {}
    ps_output = str(pre_submit.get("output") or "")
    # Match the glyphs used by pre-submit-check.sh for check 20.
    triager_present = bool(re.search(r"(?m)^\s*[✅⚠️❌⏭]\s*20\.", ps_output))
    # FIX-8B: prefer the pre-cached header threaded through by
    # ``package_submission`` (which reads it before ``shutil.rmtree``).
    # Only fall back to reading the bundle when no cached value was
    # supplied — e.g. T4's hermetic unit tests that invoke this
    # function directly with a synthetic ``bundle_dir``.
    if factory_header is None:
        factory_header = _read_factory_triager_header(bundle_dir)
    _factory_human = {
        "markers_present": "markers present",
        "no_known_class": "no-known-class",
    }
    if triager_present and factory_header:
        triager_notes = (
            f"pre-submit #20 executed; factory header confirms "
            f"{_factory_human[factory_header]}"
        )
    elif triager_present:
        triager_notes = "pre-submit check #20 executed"
    elif factory_header:
        triager_notes = (
            f"factory header only: {_factory_human[factory_header]} (advisory)"
        )
    else:
        triager_notes = "pre-submit output did not include check #20 line"
    rows.append({
        "key": "triager_risk",
        "label": "Triager-risk rules",
        "status": "PRESENT" if triager_present else "MISSING",
        "evidence": [],
        "notes": triager_notes,
    })

    # --- Summary + verdict -----------------------------------------------
    counts = {"PRESENT": 0, "MISSING": 0, "PARTIAL": 0, "N/A": 0}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    required_for_high_plus = ["forge_poc", "fork_replay", "live_proof"]
    by_key = {row["key"]: row for row in rows}

    # Verdict precedence (top wins):
    # 1. DUPE_RISK — any HIGH dupe risk regardless of other rows.
    # 2. SOURCE_ONLY — High+ source-only claim only when PoC/live proof are sane.
    # 3. BLOCKED — any High+-required row not PRESENT/N/A.
    # 4. READY — all required rows PRESENT or N/A, dupe risk LOW.
    # 5. UNKNOWN — everything else (e.g. Medium with no concerning issues).
    verdict = "UNKNOWN"
    if dupe_risk == "HIGH":
        verdict = "DUPE_RISK"
    elif (
        is_high_plus
        and by_key["fork_replay"]["status"] == "N/A"
        and by_key["forge_poc"]["status"] == "PRESENT"
        and by_key["live_proof"]["status"] in {"PRESENT", "N/A"}
        and draft_path is not None
        and _draft_cites_source_only(draft_path)
    ):
        verdict = "SOURCE_ONLY"
    elif is_high_plus and any(
        by_key[k]["status"] not in {"PRESENT", "N/A"} for k in required_for_high_plus
    ):
        verdict = "BLOCKED"
    elif (
        all(by_key[k]["status"] in {"PRESENT", "N/A"} for k in required_for_high_plus)
        and dupe_risk == "LOW"
    ):
        verdict = "READY"
    elif not is_high_plus and dupe_risk in {"LOW", "UNKNOWN"}:
        # Medium/Low advisory path: READY as long as no High+-required row is
        # explicitly MISSING (fork_replay N/A is acceptable for these tiers).
        if not any(by_key[k]["status"] == "MISSING" for k in required_for_high_plus):
            verdict = "READY"

    matrix = {
        "schema_version": 1,
        "severity": severity,
        "required_for_high_plus": required_for_high_plus,
        "rows": rows,
        "summary": {
            "total": len(rows),
            "present": counts["PRESENT"],
            "missing": counts["MISSING"],
            "partial": counts["PARTIAL"],
            "n_a": counts["N/A"],
            "ready_verdict": verdict,
        },
    }
    return matrix


def render_evidence_matrix_md(matrix: Dict[str, Any]) -> str:
    """Render a human-readable markdown table for the evidence matrix."""
    lines = [
        "# Evidence Matrix",
        "",
        f"- Schema: v{matrix.get('schema_version', 1)}",
        f"- Severity: {matrix.get('severity', 'UNKNOWN')}",
        f"- Verdict: **{matrix['summary']['ready_verdict']}** "
        f"({matrix['summary']['present']}/{matrix['summary']['total']} rows present)",
        "",
        "| Row | Label | Status | Notes |",
        "| --- | ----- | ------ | ----- |",
    ]
    for row in matrix.get("rows", []):
        label = row.get("label", row.get("key", "?"))
        status = row.get("status", "?")
        notes = str(row.get("notes") or "").replace("|", "\\|")
        extra = ""
        if row.get("key") == "dupe_check" and row.get("risk"):
            extra = f" (risk={row['risk']})"
        lines.append(f"| `{row['key']}` | {label} | **{status}**{extra} | {notes} |")
    lines.append("")
    return "\n".join(lines)


def package_submission(
    ws: Path, draft_path: Path,
) -> Optional[Tuple[Path, Optional[str]]]:
    """Package a draft into a review bundle directory.

    FIX-8B: returns ``(out_dir, cached_factory_header)``.

    ``cached_factory_header`` is the classified first-line header of
    any ``cantina_ready.md`` that lived in the *previous* bundle at
    ``out_dir`` — ``"markers_present"``, ``"no_known_class"``, or
    ``None``. This cache is captured BEFORE ``shutil.rmtree(out_dir)``
    wipes the previous bundle, because the rebuilt ``out_dir`` is
    assembled from ``tmp_dir`` which does not contain the factory's
    output (the factory runs against a prior packaged bundle and writes
    into it; it never participates in the tmp_dir assembly here).

    Without this cache T4's Row-7 consumer is inert in the real
    lifecycle: ``build_evidence_matrix`` is handed a ``bundle_dir``
    that has been newly rebuilt and therefore has no
    ``cantina_ready.md``, so the factory-header branch of Row-7 never
    fires. Threading ``cached_factory_header`` into
    ``build_evidence_matrix`` via its ``factory_header`` kwarg restores
    the contract.
    """
    title = ""
    for line in draft_path.read_text().splitlines()[:5]:
        if line.startswith("# "):
            title = line.lstrip("# ").strip()
            break
    if not title:
        title = draft_path.stem

    slug = slugify(title)
    packaged_root = ws / "submissions" / "packaged"
    out_dir = packaged_root / slug
    packaged_root.mkdir(parents=True, exist_ok=True)

    # FIX-8B: cache factory-header first line BEFORE rmtree wipes it.
    # The read is conditional on the file existing, so this adds zero
    # I/O in the normal first-run case. If the file exists but is
    # unreadable (permission, encoding), ``_read_factory_triager_header``
    # already swallows ``OSError`` and returns ``None`` — i.e. same
    # behavior as no cache.
    cached_factory_header: Optional[str] = _read_factory_triager_header(out_dir)

    tmp_dir = Path(tempfile.mkdtemp(prefix=f"{slug}-", dir=packaged_root))

    # Copy source draft
    shutil.copy2(draft_path, tmp_dir / "source-draft.md")

    # Copy PoC if found
    poc_path = find_poc_for_draft(draft_path, ws)
    if poc_path:
        shutil.copy2(poc_path, tmp_dir / "poc.t.sol")

    # Bundle-local symbolic harness for PR 207 live-mode (iter12-T1).
    # Fail-open: missing `angle_map.json` or unmapped angle → skip silently.
    try:
        angles = detect_attack_angles(draft_path)
        angle_map = load_angle_map()
        invariants_dir = AUDITOOOR_DIR / "tools" / "invariants" / "families"
        bundle_symbolic_harness(tmp_dir, angles, invariants_dir, angle_map)
    except Exception:
        # Harness emission is advisory and must never break the package step.
        pass

    if out_dir.exists():
        shutil.rmtree(out_dir)
    tmp_dir.replace(out_dir)
    # Return out_dir + cached factory header (FIX-8B); caller threads
    # the cache into ``build_evidence_matrix`` so Row-7 sees factory
    # vocabulary even though the on-disk ``cantina_ready.md`` was
    # destroyed by the rmtree above.
    return out_dir, cached_factory_header


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a fail-closed review bundle for one staging draft."
    )
    parser.add_argument("workspace", help="Workspace directory")
    parser.add_argument("draft", help="Path to a markdown draft under submissions/staging/")
    parser.add_argument("--skip-gates", action="store_true", help="Skip dupe/quality/pre-submit/scope gates")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable bundle metadata")
    args = parser.parse_args()

    ws = Path(args.workspace).expanduser().resolve()
    draft_path = Path(args.draft).expanduser().resolve()
    
    emit_logs = not args.json

    def log(message: str) -> None:
        if emit_logs:
            print(message)

    def fail(message: str) -> int:
        results["error"] = message
        if emit_logs:
            print(message)
        if args.json:
            print(json.dumps(results, indent=2))
        return 1

    results = {
        "draft": str(draft_path),
        "workspace": ws.name,
        "gates": {},
        "package_dir": None,
        "warnings": [],
        "blockers": [],
        "narrative_contradictions": {},
        "fork_replay": {},
        "execution_evidence": {},
    }

    if not ws.exists():
        return fail(f"[package] Workspace not found: {ws}")
    if not draft_path.exists():
        return fail(f"[package] Draft not found: {draft_path}")
    draft_error = validate_draft_path(ws, draft_path)
    if draft_error:
        return fail(f"[package] Invalid draft path: {draft_error}")

    live_proof = summarize_live_proof(ws, draft_path)
    results["live_proof"] = live_proof
    execution_evidence = summarize_execution_evidence(draft_path)
    results["execution_evidence"] = execution_evidence
    # V4 Phase P1 (Workstream A2): populate the production-path manifest field
    # alongside live_proof so reviewers can see the gate's view of the draft
    # without re-running pre-submit Check #27. The manifest is advisory in
    # the packager (the hard gate is in pre-submit-check.sh), but the field
    # is always present so downstream telemetry (outcome correlation, etc.)
    # can key off ``production_path.section_present`` / ``gate_status``.
    results["production_path"] = build_production_path_manifest(draft_path)
    # PR #535 PR 1: embed Program Impact Mapping summary in the package
    # manifest. Default policy is advisory (the field always appears). Under
    # REQUIRE_PROGRAM_IMPACT_MAPPING=1 a non-clean status refuses packaging.
    results["impact_mapping"] = build_impact_mapping_manifest(draft_path, workspace=ws)
    if _IMPACT_MAPPING_LIB is not None:
        refuse, reason = _impact_mapping_packager_refusal(
            results["impact_mapping"], draft_path
        )
        if refuse:
            return fail(
                "[package] Program Impact Mapping promotion contract refused packaging: "
                + reason
            )
        # Advisory warning when status is non-clean but strict mode is off.
        status = str(results["impact_mapping"].get("status") or "")
        if not _IMPACT_MAPPING_LIB.is_clean(status):
            warning = (
                f"[package] impact_mapping_status={status} (advisory; "
                f"set {_IMPACT_MAPPING_LIB.STRICT_ENV_VAR}=1 to refuse packaging)"
            )
            results["warnings"].append(warning)
            log(warning)
    narrative_contradictions = narrative_conflict_details(ws, draft_path)
    results["narrative_contradictions"] = narrative_contradictions

    # PR 101: summarize fork-replay evidence cited by the draft. Fails closed
    # below if a cited deltas file is explicitly present-but-malformed.
    fork_replay_summary = summarize_fork_replay(ws, draft_path)
    results["fork_replay"] = fork_replay_summary

    log(f"[package] Packaging: {draft_path.name}")
    log(f"[package] Workspace: {ws.name}")
    if execution_evidence.get("applies"):
        log(f"[package] Execution evidence: {execution_evidence.get('status')}")
        blockers = [item for item in execution_evidence.get("blockers") or [] if isinstance(item, dict)]
        if blockers:
            results["blockers"].extend(blockers)
            return fail("[package] Go/DLT gating_test is not an exact executable rerun command")
    if narrative_contradictions.get("matches"):
        for match in narrative_contradictions["matches"]:
            match_path = str(match.get("path") or "")
            rel_path = match_path
            try:
                rel_path = str(Path(match_path).resolve().relative_to(ws.resolve()))
            except Exception:
                pass
            tokens = ", ".join(match.get("matched_tokens") or [])
            phrases = ", ".join(match.get("matched_phrases") or [])
            warning = (
                f"[package] Workspace narrative may contradict this draft: {rel_path} "
                f"mentions {phrases} for token(s) {tokens}"
            )
            results["warnings"].append(warning)
            log(warning)
    if live_proof["draft_requires_live_proof"]:
        status = live_proof["proof_status"]
        log(f"[package] Live proof: {status}")
        if status in {"missing", "malformed", "error"}:
            return fail("[package] Live-proof artifact missing or invalid for deployment/config-dependent draft")
        if status == "executed-unpinned":
            return fail("[package] Live-proof rows executed without pinned block metadata")
        if status == "missing-refs":
            return fail("[package] Draft requires live proof but does not cite exact live-proof row IDs")
        if status == "source-only":
            warning = "[package] Live-proof override present (source-only/pre-mainnet); reviewer should verify it is justified"
            results["warnings"].append(warning)
            log(warning)
        if status in {"dry-run-only", "blocked", "no-matching-rows", "unknown"}:
            warning = f"[package] Live-proof dossier is not yet executable proof ({status})"
            results["warnings"].append(warning)
            log(warning)

    # PR 101: fail closed when a draft explicitly cites a fork-replay
    # artifact that doesn't exist OR whose JSON can't be parsed. Drafts that
    # cite no fork-replay artifacts at all are unaffected.
    missing_fork_replay = fork_replay_summary.get("missing") or []
    if missing_fork_replay:
        return fail(
            "[package] Cited fork-replay artifact(s) not found under workspace: "
            + ", ".join(missing_fork_replay)
        )
    malformed_fork_replay = fork_replay_summary.get("malformed") or []
    if malformed_fork_replay:
        return fail(
            "[package] Cited fork-replay artifact(s) failed to parse: "
            + ", ".join(malformed_fork_replay)
        )
    semantic_fork_replay_errors: List[str] = []
    for entry in fork_replay_summary.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        errors = _fork_replay_entry_semantic_errors(entry)
        if errors:
            ref = str(entry.get("reference") or entry.get("manifest") or "fork-replay-entry")
            semantic_fork_replay_errors.append(f"{ref} ({'; '.join(errors)})")
    if semantic_fork_replay_errors:
        return fail(
            "[package] Cited fork-replay artifact(s) failed semantic validation: "
            + ", ".join(semantic_fork_replay_errors)
        )
    if fork_replay_summary.get("entries"):
        log(
            f"[package] Fork replay: {len(fork_replay_summary['entries'])} "
            f"cited tx artifact(s)"
        )

    if not args.skip_gates:
        # Gate 1: Variant detector
        log("\n[package] Gate 1/4: Variant detector ...")
        rc, output = run_tool("variant-detector", [
            sys.executable, str(AUDITOOOR_DIR / "tools" / "variant-detector.py"),
            str(ws), str(draft_path), "--json"
        ])
        try:
            var_result = json.loads(output)
        except Exception:
            var_result = {"error": output, "rc": rc}
        results["gates"]["variant"] = var_result
        if rc not in {0, 1, 2}:
            return fail("[package] Variant detector failed — aborting packaging")
        risk = var_result.get("risk_level", "UNKNOWN")
        log(f"[package] Variant risk: {risk}")
        if risk == "HIGH":
            return fail("[package] HIGH dupe risk — aborting packaging")
        if risk == "MEDIUM":
            warning = "[package] MEDIUM dupe risk — package created for operator review only"
            results["warnings"].append(warning)
            log(warning)
        
        # Gate 2: Quality scorer
        log("\n[package] Gate 2/4: Quality scorer ...")
        rc, output = run_tool("quality-scorer", [
            sys.executable, str(AUDITOOOR_DIR / "tools" / "finding-quality-scorer.py"),
            str(ws), str(draft_path), "--json"
        ])
        try:
            qual_result = json.loads(output)
        except Exception:
            qual_result = {"error": output, "rc": rc}
        results["gates"]["quality"] = qual_result
        if rc != 0:
            return fail("[package] Quality scorer failed — aborting packaging")
        score = qual_result.get("total_score", 0)
        log(f"[package] Quality score: {score}/100")
        if score < 40:
            return fail("[package] Quality score too low — aborting packaging")
        
        # Gate 3: Pre-submit check
        log("\n[package] Gate 3/4: Pre-submit check ...")
        rc, output = run_tool("pre-submit", [
            "bash", str(AUDITOOOR_DIR / "tools" / "pre-submit-check.sh"),
            str(draft_path)
        ])
        results["gates"]["pre_submit"] = {"rc": rc, "output": output}
        log(f"[package] Pre-submit exit code: {rc}")
        if rc != 0:
            return fail("[package] Pre-submit check failed — aborting packaging")
        
        # Gate 4: Scope review (heuristic)
        log("\n[package] Gate 4/4: Scope review ...")
        rc, output = run_tool("scope-review", [
            "bash", str(AUDITOOOR_DIR / "tools" / "scope-review-inline.sh"),
            str(ws), str(draft_path)
        ])
        verdict = extract_scope_verdict(output)
        results["gates"]["scope_review"] = {
            "rc": rc,
            "output": output,
            "verdict": verdict or "UNKNOWN",
        }
        if rc != 0:
            return fail("[package] Scope review failed — aborting packaging")
        if verdict not in ALLOWED_SCOPE_VERDICTS:
            return fail(f"[package] Scope review verdict {verdict or 'UNKNOWN'} is not packageable")
        log(f"[package] Scope review verdict: {verdict}")
    
    # Package
    log("\n[package] Creating package ...")
    # FIX-8B: ``package_submission`` now returns
    # ``(out_dir, cached_factory_header)`` — the cache captures any
    # factory-rendered ``cantina_ready.md`` first-line header from the
    # previous bundle *before* ``shutil.rmtree`` wipes it. We thread
    # the cache into ``build_evidence_matrix`` below so Row-7 sees the
    # factory vocabulary even after the on-disk file is gone.
    pkg_result = package_submission(ws, draft_path)
    if pkg_result is not None:
        out_dir, cached_factory_header = pkg_result
    else:
        out_dir, cached_factory_header = None, None
    if out_dir:
        results["package_dir"] = str(out_dir)
        
        # Write reports
        if "variant" in results["gates"]:
            (out_dir / "variant-report.json").write_text(json.dumps(results["gates"]["variant"], indent=2))
        if "quality" in results["gates"]:
            (out_dir / "quality-report.json").write_text(json.dumps(results["gates"]["quality"], indent=2))
        if "pre_submit" in results["gates"]:
            (out_dir / "pre-submit.log").write_text(results["gates"]["pre_submit"]["output"])
        if "scope_review" in results["gates"]:
            review_path = scope_review_artifact(ws, draft_path)
            if not review_path.exists():
                return fail(f"[package] Scope review artifact missing: {review_path}")
            # Legacy reviewer-friendly copy (unchanged — human-readable alias).
            shutil.copy2(review_path, out_dir / "scope-review.md")
            # iter3-T1: mirror the artifact under the packager's `source-draft`
            # basename so pre-submit Check #11 resolves bundle-local, and
            # drop an OOS_CHECKLIST.md anchor so the `_WS` walk terminates at
            # the bundle root. See `bundle_scope_review` for rationale.
            # iter5-T1: also mirror `.agent-review.md` sibling if present so
            # Check #11's LLM-path lookup resolves bundle-local (fail-open if
            # absent — Check #11 already falls back to heuristic-review).
            agent_review_path = scope_review_artifact_agent(ws, draft_path)
            bundle_scope_review(out_dir, review_path, agent_review_path)
        else:
            # iter3-T1: even under --skip-gates, if a scope-review artifact
            # exists on disk we mirror it into the bundle so downstream
            # pre-submit runs against the bundle are self-contained. Missing
            # artifact here is not an error (gates were explicitly skipped);
            # the fail-closed behavior lives in the gates-run branch above.
            review_path = scope_review_artifact(ws, draft_path)
            # iter5-T1: agent-review sibling mirrors independently of heuristic
            # presence (Check #11 accepts either; plan forbids coupling).
            agent_review_path = scope_review_artifact_agent(ws, draft_path)
            if review_path.exists():
                shutil.copy2(review_path, out_dir / "scope-review.md")
            if review_path.exists() or agent_review_path.exists():
                bundle_scope_review(
                    out_dir,
                    review_path if review_path.exists() else None,
                    agent_review_path if agent_review_path.exists() else None,
                )
        live_proof_dir = out_dir / "live-proof"
        live_proof_dir.mkdir(exist_ok=True)
        for artifact_name in (
            "deployment_topology.json",
            "deployment_topology.md",
            "live_topology_checks.json",
            "LIVE_TOPOLOGY.md",
        ):
            artifact_path = ws / artifact_name
            if artifact_path.exists():
                shutil.copy2(artifact_path, live_proof_dir / artifact_name)
        # iter4-T1: also anchor the live-topology JSON at the bundle root so
        # pre-submit Check #21 resolves bundle-local (see
        # `bundle_live_topology_anchor` for rationale). Legacy
        # `<bundle>/live-proof/live_topology_checks.json` copy above is
        # preserved for reviewer legibility.
        bundle_live_topology_anchor(out_dir, ws)
        live_proof_manifest = {
            "summary": results["live_proof"],
            "draft_angle_ids": results["live_proof"].get("draft_angle_ids", []),
            "referenced_rows": [],
            "rows_by_angle": {},
            "rows_missing_angle_binding": [],
            "angle_relevance_summary": {},
            "manual_import_summary": {},
            "proof_contradictions": [],
            "proof_pairs": [],
            "proof_pair_integrity_summary": {},
            "specs": [],
            "manual_proof_sources": [],
            "replay_outputs": [],
        }
        dossier_path = ws / "live_topology_checks.json"
        payload: Dict[str, Any] = {}
        if dossier_path.exists():
            try:
                payload = json.loads(dossier_path.read_text())
            except json.JSONDecodeError:
                payload = {}
            referenced = set(results["live_proof"].get("referenced_ids", []))
            for row in payload.get("results", []) if isinstance(payload, dict) else []:
                if not isinstance(row, dict):
                    continue
                row_id = str(row.get("id") or "").strip()
                if row_id and row_id in referenced:
                    live_proof_manifest["referenced_rows"].append(row)
                    row_angles = [
                        str(item).strip()
                        for item in row.get("related_angle_ids", [])
                        if str(item).strip()
                    ]
                    if row_angles:
                        for angle_id in row_angles:
                            live_proof_manifest["rows_by_angle"].setdefault(angle_id, []).append(row)
                    else:
                        live_proof_manifest["rows_missing_angle_binding"].append(row_id)
        if payload:
            live_proof_manifest["specs"] = bundle_live_proof_specs(live_proof_dir, payload)
        draft_angles = set(live_proof_manifest["draft_angle_ids"])
        linked_row_ids = set()
        covered_angles = set()
        for angle_id, rows in live_proof_manifest["rows_by_angle"].items():
            if draft_angles and angle_id not in draft_angles:
                continue
            covered_angles.add(angle_id)
            for row in rows:
                if isinstance(row, dict):
                    row_id = str(row.get("id") or "").strip()
                    if row_id:
                        linked_row_ids.add(row_id)
        live_proof_manifest["angle_relevance_summary"] = {
            "draft_angle_ids": live_proof_manifest["draft_angle_ids"],
            "angles_covered": len(covered_angles) if draft_angles else len(live_proof_manifest["rows_by_angle"]),
            "referenced_rows": len(live_proof_manifest["referenced_rows"]),
            "angle_linked_rows": len(linked_row_ids),
            "unbound_rows": len(live_proof_manifest["rows_missing_angle_binding"]),
        }
        topology_rows = [
            row for row in live_proof_manifest["referenced_rows"]
            if isinstance(row, dict) and str(row.get("evidence_class") or "").strip() == "topology-relation"
        ]
        topology_contracts = sorted(
            {
                str(row.get("contract") or "").strip()
                for row in topology_rows
                if str(row.get("contract") or "").strip()
            }
        )
        live_proof_manifest["paired_topology_summary"] = {
            "required": bool(draft_angles.intersection({"A-RACE", "A-AUTH", "A-ORACLE"}) and topology_rows),
            "topology_row_ids": [
                str(row.get("id") or "").strip()
                for row in topology_rows
                if str(row.get("id") or "").strip()
            ],
            "topology_contracts": topology_contracts,
            "satisfied": len(topology_rows) >= 2 and len(topology_contracts) >= 2,
        }
        live_proof_manifest["proof_pairs"] = build_proof_pairs(
            live_proof_manifest["draft_angle_ids"],
            live_proof_manifest["referenced_rows"],
        )
        live_proof_manifest["proof_pair_integrity_summary"] = summarize_proof_pair_integrity(
            live_proof_manifest["proof_pairs"],
        )
        pair_integrity = live_proof_manifest["proof_pair_integrity_summary"]
        if live_proof_manifest["paired_topology_summary"].get("required"):
            if pair_integrity.get("incomplete"):
                warning = (
                    "[package] Required topology proof pair is incomplete: "
                    + ", ".join(pair_integrity.get("incomplete_pair_ids", [])[:6])
                )
                results["warnings"].append(warning)
                log(warning)
            if pair_integrity.get("cross_block"):
                warning = (
                    "[package] Required topology proof pair is not same-block: "
                    + ", ".join(pair_integrity.get("cross_block_pair_ids", [])[:6])
                )
                results["warnings"].append(warning)
                log(warning)
        manual_rows = [
            row for row in live_proof_manifest["referenced_rows"]
            if isinstance(row, dict) and str(row.get("manual_proof_source") or "").strip()
        ]
        manual_source_paths = sorted(
            {
                str(row.get("manual_proof_source") or "").strip()
                for row in manual_rows
                if str(row.get("manual_proof_source") or "").strip()
            }
        )
        live_proof_manifest["manual_import_summary"] = {
            "has_manual_imports": bool(manual_rows),
            "imported_row_count": len(manual_rows),
            "imported_ids": [
                str(row.get("id") or "").strip()
                for row in manual_rows
                if str(row.get("id") or "").strip()
            ],
            "source_paths": manual_source_paths,
        }
        for pair in live_proof_manifest["proof_pairs"]:
            if not isinstance(pair, dict):
                continue
            row_ids = {
                str(row_id).strip()
                for row_id in [
                    *(pair.get("row_ids", []) if isinstance(pair.get("row_ids"), list) else []),
                    pair.get("edge_row_id"),
                    pair.get("authority_row_id"),
                ]
                if str(row_id).strip()
            }
            pair["manual_import_involved"] = any(
                str(row.get("id") or "").strip() in row_ids
                for row in manual_rows
                if isinstance(row, dict)
            )
        live_proof_manifest["manual_proof_sources"] = bundle_manual_proof_sources(
            live_proof_dir,
            manual_rows,
        )
        live_proof_manifest["proof_contradictions"] = find_executed_live_proof_contradictions(
            live_proof_manifest["referenced_rows"],
        )
        if live_proof_manifest["proof_contradictions"]:
            contradiction_count = len(live_proof_manifest["proof_contradictions"])
            contradiction_rows = sorted(
                {
                    row_id
                    for item in live_proof_manifest["proof_contradictions"]
                    if isinstance(item, dict)
                    for row_id in item.get("row_ids", [])
                    if str(row_id).strip()
                }
            )
            warning = (
                "[package] Referenced executed live-proof rows contain contradictory pass/fail "
                f"evidence for {contradiction_count} claim(s): {', '.join(contradiction_rows[:6])}"
            )
            results["warnings"].append(warning)
            log(warning)
        write_replay_bundle(live_proof_dir, live_proof_manifest)
        (live_proof_dir / "manifest.json").write_text(json.dumps(live_proof_manifest, indent=2))

        # PR 101: copy cited fork-replay artifacts into <pkg>/fork-replay/ and
        # record them in the package root manifest. Kept separate from
        # live-proof/ because fork replay proves economic deltas while live
        # proof proves deployment/config facts.
        fork_replay_bundle = bundle_fork_replay(out_dir, ws, fork_replay_summary)
        results["fork_replay"] = {
            **results.get("fork_replay", {}),
            **fork_replay_bundle,
        }

        # PR 108: Evidence matrix (machine-readable + markdown).
        poc_present = (out_dir / "poc.t.sol").exists()
        poc_evidence = find_poc_evidence_for_draft(draft_path, ws)
        if poc_present:
            poc_evidence = {
                **poc_evidence,
                "present": True,
                "kind": "forge",
                "label": "Forge PoC",
                "paths": ["poc.t.sol"],
                "notes": "PoC file copied into bundle",
            }
        results["poc_present"] = bool(poc_evidence.get("present"))
        results["poc_evidence"] = poc_evidence
        results["execution_contract"] = build_bundle_execution_contract(out_dir, poc_evidence)
        matrix = build_evidence_matrix(
            results,
            draft_path=draft_path,
            ws=ws,
            poc_found=bool(poc_evidence.get("present")),
            poc_evidence=poc_evidence,
            # capv3 iter-v3-8 T4: hand the bundle dir to the matrix so the
            # Row-7 consumer can read factory's cantina_ready.md header
            # when a prior factory run has already written it into this
            # bundle. Absent cantina_ready.md → existing behavior.
            bundle_dir=out_dir,
            # FIX-8B: prefer the header we cached BEFORE ``rmtree`` wiped
            # the previous bundle. Falls through to ``bundle_dir`` read
            # inside ``build_evidence_matrix`` when no prior bundle
            # existed (first-time packaging run).
            factory_header=cached_factory_header,
        )
        results["evidence_matrix"] = matrix
        (out_dir / "evidence-matrix.json").write_text(json.dumps(matrix, indent=2))
        (out_dir / "EVIDENCE_MATRIX.md").write_text(render_evidence_matrix_md(matrix))
        log(
            f"[package] Evidence matrix: {matrix['summary']['ready_verdict']} "
            f"({matrix['summary']['present']}/{matrix['summary']['total']} rows present)"
        )

        (out_dir / "manifest.json").write_text(json.dumps(results, indent=2))

        log(f"[package] ✅ Package created: {out_dir}")
        log("[package] Files:")
        for f in sorted(out_dir.iterdir()):
            log(f"  - {f.name}")
    
    if args.json:
        print(json.dumps(results, indent=2))
    log("\n[package] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
