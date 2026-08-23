"""Ruff adapter.

Two facts about ruff's JSON output shape this adapter:

* ``ruff check`` exits 1 when it finds violations and 2 on an internal error
  (bad config, unparseable file).  Conflating them would turn "ruff could not
  run" into "ruff found nothing", so exit 2 is an ``error`` while exit 1 is a
  perfectly ``ok`` run that happens to have findings.
* ruff has no notion of "warning" vs "error" severity.  Rather than invent
  one, findings are split on whether the rule is in the repository's
  *blocking* selection: those are ``errors``, the rest are ``warnings``.  The
  split rule is recorded in the snapshot so the number stays interpretable.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Any

from .base import ToolRun, run, tool_version, which

#: Rule prefixes whose violations block CI.  Deliberately narrow to start:
#: pyflakes correctness (F), the syntax/runtime-error subset of pycodestyle
#: (E4/E7/E9) -- the same selection mirarun already gates on -- and McCabe
#: complexity (C901), which is only ever *reported* here because the threshold
#: is configured permissively.  Everything else is measured, not enforced.
BLOCKING_PREFIXES: tuple[str, ...] = ("F", "E4", "E7", "E9")


def _is_blocking(code: str | None) -> bool:
    return bool(code) and code.startswith(BLOCKING_PREFIXES)


def _within(filename: str, gate_paths: list[str], cwd: str | None) -> bool:
    """Is this finding inside one of the gated paths?

    ruff reports absolute filenames, so the comparison is made on paths
    resolved against the analysis root rather than on string prefixes -- a
    prefix test would let ``origo_extra/`` match a gate on ``origo``.
    """
    root = os.path.abspath(cwd or ".")
    try:
        relative = os.path.relpath(os.path.abspath(filename), root)
    except ValueError:  # different drive on Windows
        return False
    parts = relative.split(os.sep)
    for gate in gate_paths:
        gate_parts = [p for p in gate.strip("/").split("/") if p not in ("", ".")]
        if parts[: len(gate_parts)] == gate_parts:
            return True
    return False


def collect(
    paths: list[str],
    *,
    cwd: str | None = None,
    gate_paths: list[str] | None = None,
) -> tuple[dict[str, Any], ToolRun]:
    """Run ruff and normalize its findings.

    ``gate_paths`` narrows which blocking findings count toward the CI gate,
    without narrowing what is *measured*.  Measuring test-suite lint while
    gating only the shipped package is a deliberate split: the trend is worth
    recording everywhere, but failing the build on a pre-existing finding in a
    path nobody agreed to gate would force exactly the unrelated cleanup this
    lane is meant not to cause.
    """
    executable = which("ruff") or "ruff"
    argv = [executable, "check", "--output-format", "json", "--exit-zero", *paths]
    tool = ToolRun(name="ruff", command=argv)
    tool.version = tool_version([executable, "--version"])
    if tool.version is None:
        tool.status = "unavailable"
        tool.error = "ruff is not installed"
        return _empty(), tool

    # --exit-zero keeps findings out of the exit code so that a non-zero exit
    # unambiguously means "ruff itself failed".  Blocking is a policy decision
    # made later, from the normalized counts, not from this process's status.
    result = run(argv, cwd=cwd)
    tool.exit_code = result.returncode
    tool.duration_seconds = result.duration
    if result.returncode != 0:
        tool.status = "error"
        tool.error = (result.stderr or result.stdout).strip()[:2000]
        return _empty(), tool

    try:
        findings = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        tool.status = "error"
        tool.error = f"could not parse ruff JSON: {exc}"
        return _empty(), tool

    by_rule: Counter[str] = Counter()
    errors = warnings = 0
    fixable = 0
    gate_errors = 0
    for finding in findings:
        code = finding.get("code")
        # A syntax error has code=None in ruff's JSON.  It is unambiguously
        # blocking and must not be silently dropped by a prefix test.
        rule = code or "syntax-error"
        by_rule[rule] += 1
        if code is None or _is_blocking(code):
            errors += 1
            if gate_paths is None or _within(finding.get("filename", ""), gate_paths, cwd):
                gate_errors += 1
        else:
            warnings += 1
        if (finding.get("fix") or {}).get("applicability") in {"safe", "always"}:
            fixable += 1

    return (
        {
            "status": "ok",
            "tool": "ruff",
            "errors": errors,
            "warnings": warnings,
            "total": len(findings),
            "fixable": fixable,
            # The subset of `errors` inside `gate_paths`; this is what blocks.
            "gate_errors": gate_errors,
            "gate_paths": gate_paths,
            "blocking_rule_prefixes": list(BLOCKING_PREFIXES),
            # Bounded by the number of rules ruff has, and genuinely useful for
            # longitudinal work ("which rule class grew?").  Stays in the JSON
            # artifact and the structured event; never becomes a metric label.
            "by_rule": dict(sorted(by_rule.items(), key=lambda kv: (-kv[1], kv[0]))),
        },
        tool,
    )


def _empty() -> dict[str, Any]:
    """Findings are unknown, not zero."""
    return {
        "status": "error",
        "tool": "ruff",
        "errors": None,
        "warnings": None,
        "total": None,
        "fixable": None,
        "gate_errors": None,
        "gate_paths": None,
        "blocking_rule_prefixes": list(BLOCKING_PREFIXES),
        "by_rule": {},
    }
