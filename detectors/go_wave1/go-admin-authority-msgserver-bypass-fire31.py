"""
go-admin-authority-msgserver-bypass-fire31.py

Detects Cosmos-style MsgServer or keeper handlers that perform privileged
state mutation before proving the caller-controlled Msg authority is the
module authority or expected governance address.

Source refs:
- reports/detector_lift_fire30_20260605/post_priorities_go.md
- detectors/go_wave1/test_fixtures/cosmos_msgserver_missing_authority_check_positive.go

The target miss is an admin-bypass shape: a Msg handler reads or accepts
`Authority`, `Admin`, `Owner`, or signer-like Msg fields, then writes params,
module config, admin routes, oracle config, roles, fees, or other privileged
state without comparing that caller value to `keeper.GetAuthority()`,
`keeper.authority`, or the governance module address.

This detector is narrower than the older generic authority detector. It keeps
the positive source fixture covered, but its default boundary is:
- Msg-shaped function or method only.
- Privileged handler name or privileged write sink required.
- Authority helper or module-authority source must appear before the first
  privileged write sink.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go-admin-authority-msgserver-bypass-fire31"

_MSG_PARAM_RE = re.compile(
    r"(?:^|[,(]\s*)([A-Za-z_][A-Za-z0-9_]*)\s+\*?Msg[A-Za-z0-9_]*\b",
    re.MULTILINE,
)

_PRIVILEGED_OBJECT = (
    r"(?:Params?|Config|Authority|Admin|Owner|Module|Market|Asset|Oracle|"
    r"Route|Denom|Fees?|Limit|Cap|Rate|Whitelist|Allowlist|Role|Signer|"
    r"Validator|Governance|Gov)"
)

_PRIVILEGED_NAME_RE = re.compile(
    rf"^(?:Update|Set|Apply|Configure|Add|Register|Remove|Delete|Grant|"
    rf"Revoke|Enable|Disable|Pause|Unpause|Migrate|Replace)"
    rf"[A-Za-z0-9_]*{_PRIVILEGED_OBJECT}[A-Za-z0-9_]*$",
    re.IGNORECASE,
)

_PRIVILEGED_WRITE_RE = re.compile(
    rf"\b(?:Set|Store|Put|Update|Apply|Configure|Add|Register|Remove|"
    rf"Delete|Grant|Revoke|Enable|Disable|Pause|Unpause|Migrate|Replace|"
    rf"set|store|put|update|apply|configure|add|register|remove|delete|"
    rf"grant|revoke|enable|disable|pause|unpause|migrate|replace)"
    rf"[A-Za-z0-9_]*{_PRIVILEGED_OBJECT}[A-Za-z0-9_]*\s*\("
    rf"|(?:ParamStore|ParamsStore|paramStore|paramsStore)"
    rf"[\s\S]{{0,160}}\.\s*Set\s*\(",
    re.IGNORECASE,
)

_CALLER_AUTH_FIELD = (
    r"(?:Authority|Admin|Owner|Signer|SignerAddress|Creator|Proposer|Sender)"
)

_USER_HANDLER_RE = re.compile(
    r"^(?:Send|Transfer|Deposit|Withdraw|Claim|Swap|PlaceOrder|CancelOrder|"
    r"Vote|Delegate|Undelegate|Stake|Unstake|UpdateProfile|SetProfile)$",
    re.IGNORECASE,
)

_MODULE_AUTHORITY_RE = re.compile(
    r"(?:\b(?:k|m|ms|keeper|Keeper|msgServer)\b(?:\.[A-Za-z0-9_]+)*"
    r"\.GetAuthority\s*\("
    r"|\b(?:k|m|ms|keeper|Keeper|msgServer)\b(?:\.[A-Za-z0-9_]+)*"
    r"\.authority\b"
    r"|authtypes\.NewModuleAddress\s*\("
    r"|NewModuleAddress\s*\("
    r"|govtypes\.ModuleName\b"
    r"|types\.ModuleName\b"
    r"|govModuleAddress\b"
    r"|governanceAuthority\b)",
    re.IGNORECASE,
)

_AUTHORITY_HELPER_RE = re.compile(
    r"\b(?:Ensure|Assert|Check|Validate|Require|Verify)"
    r"(?:Admin|Authority|Gov|Governance|Owner|Signer)\b"
    r"|\b(?:Has|Is)(?:Admin|Authority|Gov|Governance|Owner|Signer|Role)\b"
    r"|\bOnly(?:Admin|Authority|Gov|Governance|Owner)\b",
    re.IGNORECASE,
)


def _blank_comment(match: re.Match[str]) -> str:
    return "".join("\n" if ch == "\n" else " " for ch in match.group(0))


def _strip_comments(src: str) -> str:
    src = re.sub(r"//.*", _blank_comment, src)
    return re.sub(r"/\*.*?\*/", _blank_comment, src, flags=re.S)


def _msg_var_names(fn_text: str) -> tuple[str, ...]:
    names = []
    for match in _MSG_PARAM_RE.finditer(fn_text):
        name = match.group(1)
        if name not in names:
            names.append(name)
    return tuple(names)


def _caller_auth_re(msg_vars: tuple[str, ...]) -> re.Pattern[str]:
    var_alt = "|".join(re.escape(name) for name in msg_vars)
    return re.compile(
        rf"\b(?:{var_alt})\.(?:{_CALLER_AUTH_FIELD})\b"
        rf"|\b(?:{var_alt})\.Get(?:Authority|Admin|Owner|Signer|Signers)"
        rf"\s*\(",
        re.IGNORECASE,
    )


def _first_write(body_text: str) -> re.Match[str] | None:
    return _PRIVILEGED_WRITE_RE.search(body_text)


def _has_authority_guard_before(body_text: str, write_idx: int) -> bool:
    prefix = body_text[:write_idx]
    if _AUTHORITY_HELPER_RE.search(prefix):
        return True
    if _MODULE_AUTHORITY_RE.search(prefix):
        return True
    return False


def _is_privileged_context(name: str, body_text: str) -> bool:
    if _PRIVILEGED_NAME_RE.match(name):
        return True
    return _PRIVILEGED_WRITE_RE.search(body_text) is not None


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue

        body = engine.fn_body(fn)
        if body is None:
            continue

        fn_text = _strip_comments(engine.text(fn))
        body_text = _strip_comments(engine.text(body))
        msg_vars = _msg_var_names(fn_text)
        if not msg_vars:
            continue

        if _USER_HANDLER_RE.match(name) and not _PRIVILEGED_NAME_RE.match(name):
            continue

        if not _is_privileged_context(name, body_text):
            continue

        write = _first_write(body_text)
        if write is None:
            continue

        if _has_authority_guard_before(body_text, write.start()):
            continue

        caller_auth_re = _caller_auth_re(msg_vars)
        reads_caller_auth = bool(caller_auth_re.search(fn_text))
        reason = (
            "trusts a caller-controlled Msg authority field"
            if reads_caller_auth
            else "accepts a privileged Msg without an authority check"
        )
        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"`{name}` {reason} before `{write.group(0).strip()}`. "
                f"Compare Msg Authority/Admin/Owner/signer to keeper "
                f"authority or the governance module address before "
                f"mutating privileged state. (class: admin-bypass)"
            ),
        })
    return hits
