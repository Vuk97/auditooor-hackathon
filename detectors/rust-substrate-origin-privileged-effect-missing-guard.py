"""Substrate origin authorization bypass detector.

Flags Substrate FRAME dispatchables that accept `origin: OriginFor<T>` and
perform privileged effects without a visible privileged-origin guard.

Class invariant:
  A dispatchable that changes runtime configuration, authority sets, bridge
  routing, code, or privileged storage must bind `origin` to the intended
  authority before the effect. `ensure_signed(origin)?` proves only that some
  account signed. It is insufficient for admin/root/governance effects unless
  the signer is then checked against a role, membership map, owner, or custom
  `EnsureOrigin` implementation.

Corpus anchors:
  - substrate_cosmwasm_frost dispatchable-permission-bypass records where
    `admin_action(origin: OriginFor<T>, ...)` used the wrong origin class.
  - rust_substrate anti-pattern `xcm-origin-location-converted-without-filter`.
  - rust_substrate anti-pattern
    `unsigned-extrinsic-validate-dispatch-logic-divergence`.

Detector contract: call `run_text(source, filepath)` and inspect returned
hit dictionaries. This file is not wired into shared registries by design for
the 2026-06-02 lane; smoke tests import it directly by path.
"""

from __future__ import annotations

import re
from typing import Any


DETECTOR_ID = "rust-substrate-origin-privileged-effect-missing-guard"


_COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.M | re.S)
_FN_RE = re.compile(r"\b(?:pub\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(", re.M)

_SUBSTRATE_HINT_RE = re.compile(
    r"\b(OriginFor\s*<|frame_support|frame_system|#\s*\[\s*pallet::call|"
    r"ensure_root\s*\(|ensure_signed\s*\(|RawOrigin|DispatchResult)\b"
)

_PRIVILEGED_NAME_RE = re.compile(
    r"^(force_|sudo_|root_|admin_|governance_|set_|update_|upgrade_|"
    r"register_|remove_|add_|open_|close_|cancel_|pause_|unpause_|"
    r"configure_|change_)",
    re.I,
)

_PRIVILEGED_EFFECT_RE = re.compile(
    r"("
    r"::\s*<\s*T\s*>\s*::\s*(?:put|insert|mutate|try_mutate|remove|kill|take)\s*\(|"
    r"\bStorage(Value|Map|DoubleMap)?\s*::|"
    r"\bset_code\s*\(|"
    r"\bframe_system::Pallet\s*::\s*set_code\s*\(|"
    r"\bdispatch_bypass_filter\s*\(|"
    r"\bforce_[A-Za-z0-9_]*\s*\(|"
    r"\bT::(?:Currency|Assets|Fungibles)::(?:transfer|mint_into|burn_from)\s*\(|"
    r"\bdeposit_event\s*\("
    r")"
)

_ROOT_ORIGIN_RE = re.compile(
    r"("
    r"ensure_root\s*\(\s*origin\s*\)\s*\?|"
    r"Root\s*::\s*ensure_origin\s*\(\s*origin\s*\)|"
    r"EnsureRoot\s*<[^>]*>\s*::\s*ensure_origin\s*\(\s*origin\s*\)|"
    r"T::[A-Za-z0-9_]*Origin\s*::\s*ensure_origin\s*\(\s*origin\s*\)|"
    r"RawOrigin\s*::\s*Root"
    r")"
)

_SIGNED_ORIGIN_RE = re.compile(r"\bensure_signed\s*\(\s*origin\s*\)\s*\?")

_ROLE_PROOF_RE = re.compile(
    r"("
    r"ensure!\s*\([^;]*(?:contains|contains_key|is_admin|is_owner|owner|members|"
    r"has_role|Authorized|Authority|Council|Root|Governance|Admin)|"
    r"Self::ensure_[A-Za-z0-9_]*\s*\(|"
    r"T::[A-Za-z0-9_]*Origin\s*::\s*ensure_origin\s*\(|"
    r"ensure_origin\s*\(\s*origin\s*\)|"
    r"(?:Admins|Members|Authorities|Allowed|Whitelist|Owners)"
    r"\s*::\s*<\s*T\s*>\s*::\s*(?:contains|contains_key)\s*\("
    r")",
    re.I | re.S,
)

_XCM_CONVERSION_RE = re.compile(
    r"(ConvertOrigin|EnsureXcmOrigin|SovereignSignedViaLocation|"
    r"convert_origin\s*\(|OriginKind|MultiLocation)"
)
_XCM_PRIV_EFFECT_RE = re.compile(r"(dispatch_bypass_filter\s*\(|RuntimeCall|OriginKind::SovereignAccount)")
_XCM_FILTER_RE = re.compile(
    r"(match\s+[^{}]*(?:MultiLocation|location)|matches!\s*\(|"
    r"LocationFilter|ContainsPair|Parent|Parachain|AccountId32|Junction|"
    r"ensure!\s*\([^;]*(?:location|origin)|"
    r"contains\s*\([^;]*(?:location|origin))",
    re.I | re.S,
)


def _strip_comments(source: str) -> str:
    return _COMMENT_RE.sub(lambda m: " " * (m.end() - m.start()), source)


def _line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    last_nl = source.rfind("\n", 0, offset)
    col = offset + 1 if last_nl < 0 else offset - last_nl
    return line, col


def _block_end(source: str, open_brace: int) -> int:
    depth = 0
    for idx in range(open_brace, len(source)):
        ch = source[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx + 1
    return len(source)


def _iter_origin_functions(source: str):
    for match in _FN_RE.finditer(source):
        name = match.group("name")
        brace = source.find("{", match.end())
        if brace < 0:
            continue
        signature = source[match.start() : brace]
        if "OriginFor" not in signature and "origin:" not in signature:
            continue
        end = _block_end(source, brace)
        yield name, match.start(), signature, source[brace + 1 : end - 1]


def _has_privileged_shape(name: str, body: str) -> bool:
    return bool(_PRIVILEGED_NAME_RE.search(name) and _PRIVILEGED_EFFECT_RE.search(body))


def _guard_state(body: str) -> str:
    if _ROOT_ORIGIN_RE.search(body):
        return "root-or-custom-origin"
    if _SIGNED_ORIGIN_RE.search(body):
        if _ROLE_PROOF_RE.search(body):
            return "signed-with-role-proof"
        return "signed-only"
    if _ROLE_PROOF_RE.search(body):
        return "custom-role-proof"
    return "missing"


def run_text(source: str, filepath: str) -> list[dict[str, Any]]:
    if not _SUBSTRATE_HINT_RE.search(source):
        return []

    stripped = _strip_comments(source)
    hits: list[dict[str, Any]] = []

    for name, offset, signature, body in _iter_origin_functions(stripped):
        line, col = _line_col(source, offset)
        first_line = source[offset : source.find("\n", offset) if "\n" in source[offset:] else offset + 160]
        guard = _guard_state(body)

        if _has_privileged_shape(name, body) and guard in {"missing", "signed-only"}:
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "file": filepath,
                    "line": line,
                    "col": col,
                    "severity": "high",
                    "message": (
                        f"Substrate dispatchable `{name}` accepts `origin: OriginFor<T>` "
                        f"and performs privileged storage/runtime effects, but guard state "
                        f"is `{guard}`. Use `ensure_root`, a custom `EnsureOrigin`, or "
                        "prove the signed account is an admin/member/owner before the effect."
                    ),
                    "snippet": first_line.strip()[:220],
                }
            )
            continue

        if (
            _XCM_CONVERSION_RE.search(signature + body)
            and _XCM_PRIV_EFFECT_RE.search(body)
            and not _XCM_FILTER_RE.search(body)
        ):
            hits.append(
                {
                    "detector_id": DETECTOR_ID,
                    "file": filepath,
                    "line": line,
                    "col": col,
                    "severity": "high",
                    "message": (
                        f"Substrate dispatchable `{name}` converts an XCM/MultiLocation "
                        "origin into a dispatch origin and reaches privileged dispatch "
                        "without a visible location or junction filter. Bind accepted "
                        "locations explicitly before calling converted-origin dispatch."
                    ),
                    "snippet": first_line.strip()[:220],
                }
            )

    return hits


def scan_file(path: str) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return run_text(handle.read(), path)


if __name__ == "__main__":
    import json
    import sys

    all_hits: list[dict[str, Any]] = []
    for arg in sys.argv[1:]:
        all_hits.extend(scan_file(arg))
    print(json.dumps({"detector_id": DETECTOR_ID, "hits": all_hits}, indent=2))
    raise SystemExit(1 if all_hits else 0)
