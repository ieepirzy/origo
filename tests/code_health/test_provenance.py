"""Provenance: what it records, and what it refuses to guess."""

from tools.code_health import provenance


def test_nothing_declared_yields_unknown_not_human():
    """The single most important behaviour in this module.

    Defaulting an unknown to `human` would bias every future human-vs-agent
    comparison in exactly the direction being measured.
    """
    result = provenance.collect({})
    assert result["authoring_mode"] is None
    assert result["authoring_mode_source"] is None


def test_commit_message_is_never_consulted():
    """Explicit metadata only -- no heuristics, however tempting."""
    env = {
        "GIT_COMMIT_MESSAGE": "Generated with Claude Code\n\nCo-Authored-By: Claude <noreply@anthropic.com>",
        "GITHUB_ACTOR": "claude-bot",
    }
    assert provenance.collect(env)["authoring_mode"] is None


def test_workflow_input_is_trusted():
    result = provenance.collect({"CODE_HEALTH_AUTHORING_MODE": "agent_supervised"})
    assert result["authoring_mode"] == "agent_supervised"
    assert result["authoring_mode_source"] == "workflow_input"


def test_an_invalid_mode_is_rejected_not_coerced():
    """A typo must not silently become a data point."""
    result = provenance.collect({"CODE_HEALTH_AUTHORING_MODE": "agent-supervised"})
    assert result["authoring_mode"] is None


def test_pr_label_populates_the_mode():
    result = provenance.collect({"CODE_HEALTH_PR_LABELS": "size/M,authoring:agent-autonomous"})
    assert result["authoring_mode"] == "agent_autonomous"
    assert result["authoring_mode_source"] == "pr_label"


def test_contradictory_labels_become_mixed_not_a_coin_flip():
    result = provenance.collect(
        {"CODE_HEALTH_PR_LABELS": "authoring:human,authoring:agent-autonomous"}
    )
    assert result["authoring_mode"] == "mixed"


def test_workflow_input_outranks_a_label_and_the_conflict_is_recorded():
    """Disagreement is itself data; it must not be silently dropped."""
    result = provenance.collect(
        {"CODE_HEALTH_AUTHORING_MODE": "agent_supervised", "CODE_HEALTH_PR_LABELS": "authoring:human"}
    )
    assert result["authoring_mode"] == "agent_supervised"
    assert result["authoring_mode_source"] == "workflow_input"
    assert result["conflict"] is True
    assert result["declared_modes"] == {"workflow_input": "agent_supervised", "pr_label": "human"}


def test_mirarun_metadata_populates_agents():
    result = provenance.collect(
        {
            "MIRARUN_RUN_ID": "run_123",
            "MIRARUN_AGENT_NAME": "claude-code",
            "MIRARUN_AGENT_PROVIDER": "anthropic",
            "MIRARUN_MODEL": "claude-opus-5",
            "MIRARUN_ENVIRONMENT_ID": "env_9",
        }
    )
    assert result["agents"][0]["run_id"] == "run_123"
    assert result["agents"][0]["source"] == "mirarun"
    assert result["agent_run_ids"] == ["run_123"]
    assert result["models"] == ["claude-opus-5"]


def test_an_agent_running_does_not_by_itself_imply_supervision_level():
    """MiraRun knows an agent ran; it does not know whether a human reviewed."""
    result = provenance.collect({"MIRARUN_RUN_ID": "run_123", "MIRARUN_MODEL": "m"})
    assert result["agents"], "the agent must still be recorded"
    assert result["authoring_mode"] is None


def test_mirarun_may_assert_the_mode_explicitly():
    result = provenance.collect(
        {"MIRARUN_RUN_ID": "run_1", "MIRARUN_AUTHORING_MODE": "agent_autonomous"}
    )
    assert result["authoring_mode"] == "agent_autonomous"
    assert result["authoring_mode_source"] == "mirarun"


def test_human_authors_are_stable_ids_not_personal_data():
    result = provenance.collect({"CODE_HEALTH_HUMAN_AUTHOR_IDS": "u_17, u_22"})
    assert [a["id"] for a in result["human_authors"]] == ["u_17", "u_22"]


def test_review_state_is_recorded_when_ci_knows_it():
    assert provenance.collect({"CODE_HEALTH_REVIEW_APPROVALS": "2"})["review"] == {
        "human_reviewed": True,
        "approval_count": 2,
        "review_source": "workflow_input",
    }
    assert provenance.collect({"CODE_HEALTH_REVIEW_APPROVALS": "0"})["review"]["human_reviewed"] is False
    assert provenance.collect({})["review"]["human_reviewed"] is None


def test_granularity_is_declared_honestly():
    """v1 records change-level provenance and says so, rather than implying more."""
    assert provenance.collect({})["granularity"] == "change"
