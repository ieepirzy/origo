"""Explicit, trusted code provenance.

The point of this module is what it refuses to do.  Authorship is never
inferred from commit-message text, co-author trailers written by anyone who can
push, author names, or "this looks like an agent wrote it".  Those are
guesses, and a dataset built to compare human and AI-assisted development
cannot be built on guesses -- a heuristic that is 90% accurate produces a 10%
mislabel rate that is *correlated with the thing being measured*, which is
worse than no data at all.

So provenance is only ever populated from sources that are explicit about
themselves, each recorded with the source that supplied it:

``workflow_input``
    A ``workflow_dispatch`` input, or an explicit environment variable set by
    the workflow.  The strongest signal: a human or an agent runner declared it.
``mirarun``
    Agent execution metadata injected by the MiraRun control plane
    (``MIRARUN_RUN_ID`` and friends).  MiraRun knows what it launched.
``pr_label``
    A label on the pull request, from the repository's declared label
    vocabulary.  Trusted because applying one requires write access.
``ci_environment``
    Facts the CI provider asserts about itself, used only for identity and
    never to classify authoring mode.

When nothing trustworthy is available the authoring mode is ``None``.  That is
a first-class, expected value -- "we do not know" -- and it must never be
silently coerced to ``human``.  Backfilling unknowns as human would
systematically bias every future comparison in exactly the direction the
research question is about.
"""

from __future__ import annotations

import os
from typing import Any

from .schema import AUTHORING_MODES

#: PR labels that declare an authoring mode.  Applying a label requires repo
#: write access, which is what makes this trustworthy.
LABEL_TO_MODE: dict[str, str] = {
    "authoring:human": "human",
    "authoring:human-assisted": "human_assisted",
    "authoring:agent-supervised": "agent_supervised",
    "authoring:agent-autonomous": "agent_autonomous",
    "authoring:mixed": "mixed",
}

#: Precedence, most trusted first.  An explicit workflow input beats a label
#: because it is set per-run by whoever launched the run; a label describes the
#: change and can be edited after the fact.
SOURCE_PRECEDENCE: tuple[str, ...] = ("workflow_input", "mirarun", "pr_label")


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _split_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.replace("\n", ",").split(",") if item.strip()]


def collect(env: dict[str, str] | None = None) -> dict[str, Any]:
    """Build the provenance block from explicit metadata only."""
    env = dict(os.environ if env is None else env)

    candidates: dict[str, str] = {}

    declared = _clean(env.get("CODE_HEALTH_AUTHORING_MODE"))
    if declared:
        # An unrecognised value is recorded as a rejection rather than being
        # coerced to something plausible: a typo'd mode must not silently
        # become a data point.
        if declared in AUTHORING_MODES:
            candidates["workflow_input"] = declared

    agents = _collect_agents(env)
    if "workflow_input" not in candidates and agents:
        # MiraRun launched this and said which agent ran, but nobody declared
        # supervision level.  "an agent was involved" is knowable; whether a
        # human reviewed it is not, so this stays out of the binary and is
        # represented as the honest middle value only when MiraRun itself
        # asserts the supervision level.
        mirarun_mode = _clean(env.get("MIRARUN_AUTHORING_MODE"))
        if mirarun_mode in AUTHORING_MODES:
            candidates["mirarun"] = mirarun_mode

    label_modes = sorted(
        {LABEL_TO_MODE[label] for label in _split_list(env.get("CODE_HEALTH_PR_LABELS")) if label in LABEL_TO_MODE}
    )
    if len(label_modes) == 1:
        candidates["pr_label"] = label_modes[0]
    elif len(label_modes) > 1:
        # Two contradictory declarations.  "mixed" is a real category here, not
        # a fudge: the change genuinely carries more than one authoring claim.
        candidates["pr_label"] = "mixed"

    authoring_mode: str | None = None
    source: str | None = None
    for candidate_source in SOURCE_PRECEDENCE:
        if candidate_source in candidates:
            authoring_mode = candidates[candidate_source]
            source = candidate_source
            break

    return {
        "authoring_mode": authoring_mode,
        "authoring_mode_source": source,
        # Every declaration seen, not just the winner.  If a label and a
        # workflow input disagree, that disagreement is itself data.
        "declared_modes": candidates,
        "conflict": len(set(candidates.values())) > 1,
        "human_authors": _collect_human_authors(env),
        "agents": agents,
        # Flattened for convenience of downstream queries; derived from
        # `agents`, never populated independently.
        "agent_run_ids": [a["run_id"] for a in agents if a.get("run_id")],
        "models": sorted({a["model"] for a in agents if a.get("model")}),
        # Granularity actually achieved by this run.  The schema is designed
        # for commit/change/file/symbol provenance; v1 populates change level
        # only, and says so rather than implying more.
        "granularity": "change",
        "review": _collect_review(env),
    }


def _collect_agents(env: dict[str, str]) -> list[dict[str, Any]]:
    """Agent records from MiraRun or an explicit workflow declaration."""
    agents: list[dict[str, Any]] = []

    run_id = _clean(env.get("MIRARUN_RUN_ID"))
    if run_id:
        agents.append(
            {
                "name": _clean(env.get("MIRARUN_AGENT_NAME")),
                "provider": _clean(env.get("MIRARUN_AGENT_PROVIDER")),
                "model": _clean(env.get("MIRARUN_MODEL")),
                "run_id": run_id,
                "source": "mirarun",
                # MiraRun's own identifiers, kept so a snapshot can be joined
                # back to the control plane's record of the run.
                "environment_id": _clean(env.get("MIRARUN_ENVIRONMENT_ID")),
                "routine_id": _clean(env.get("MIRARUN_ROUTINE_ID")),
            }
        )

    declared_agent = _clean(env.get("CODE_HEALTH_AGENT_NAME"))
    if declared_agent:
        agents.append(
            {
                "name": declared_agent,
                "provider": _clean(env.get("CODE_HEALTH_AGENT_PROVIDER")),
                "model": _clean(env.get("CODE_HEALTH_AGENT_MODEL")),
                "run_id": _clean(env.get("CODE_HEALTH_AGENT_RUN_ID")),
                "source": "workflow_input",
                "environment_id": None,
                "routine_id": None,
            }
        )
    return agents


def _collect_human_authors(env: dict[str, str]) -> list[dict[str, Any]]:
    """Stable internal IDs only.

    Deliberately *not* email addresses or display names.  A longitudinal
    dataset that accumulates personal data for years is a liability, and the
    analyses this is built for -- does authoring mode correlate with
    complexity -- need a stable pseudonymous key, not an identity.
    """
    return [
        {"id": author_id, "source": "workflow_input"}
        for author_id in _split_list(env.get("CODE_HEALTH_HUMAN_AUTHOR_IDS"))
    ]


def _collect_review(env: dict[str, str]) -> dict[str, Any]:
    """Whether the change passed human review, when CI can know it.

    Needed for "does code-review intervention improve agent-generated code
    quality?".  Populated only from explicit values; unknown stays ``None``.
    """
    approvals = _clean(env.get("CODE_HEALTH_REVIEW_APPROVALS"))
    reviewed: bool | None = None
    approval_count: int | None = None
    if approvals is not None:
        try:
            approval_count = int(approvals)
        except ValueError:
            approval_count = None
        else:
            reviewed = approval_count > 0
    return {
        "human_reviewed": reviewed,
        "approval_count": approval_count,
        "review_source": "workflow_input" if approval_count is not None else None,
    }
