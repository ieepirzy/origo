"""The collector against this repository, for real.

Guards the wiring that unit tests cannot: that the analyzers actually run, that
the artifact validates, and that the exit code encodes policy correctly.
"""

import json
import os
import shutil
import subprocess
import sys

import pytest

from tools.code_health import schema

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HAS_RADON = shutil.which("radon") is not None or subprocess.run(
    [sys.executable, "-m", "radon", "--version"], capture_output=True, check=False
).returncode == 0

pytestmark = pytest.mark.skipif(not HAS_RADON, reason="radon is not installed")


@pytest.fixture(scope="module")
def snapshot(tmp_path_factory):
    output = tmp_path_factory.mktemp("ch") / "code-health.json"
    result = subprocess.run(
        [sys.executable, "-m", "tools.code_health", "--output", str(output), "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"collector failed: {result.stderr[-2000:]}"
    with open(output, encoding="utf-8") as handle:
        return json.load(handle)


def test_the_artifact_validates(snapshot):
    schema.validate(snapshot)


def test_the_artifact_measures_this_package(snapshot):
    assert snapshot["target"]["paths"] == ["origo"]
    assert snapshot["summary"]["files"] == 7
    assert snapshot["summary"]["functions"] > 50


def test_per_symbol_detail_is_preserved(snapshot):
    """Aggregates alone cannot answer the questions this dataset is for."""
    assert len(snapshot["symbols"]) == snapshot["summary"]["functions"]
    token = [s for s in snapshot["symbols"] if s["symbol"] == "token"]
    assert token, "the token endpoint should appear in the symbol table"
    assert token[0]["path"] == "origo/endpoints.py"
    assert token[0]["cyclomatic_complexity"] > 20


def test_unavailable_metrics_are_null_not_fabricated(snapshot):
    """radon reports MI per file and no nesting depth at all."""
    for symbol in snapshot["symbols"]:
        assert symbol["maintainability_index"] is None
        assert symbol["nesting_depth"] is None


def test_class_blocks_are_not_in_the_symbol_table(snapshot):
    """The double-count trap, asserted against real radon output."""
    assert {s["symbol_type"] for s in snapshot["symbols"]} <= {"function", "method"}


def test_the_aggregate_equals_the_sum_of_the_symbols(snapshot):
    """The headline number must be reproducible from the preserved detail."""
    total = sum(s["cyclomatic_complexity"] for s in snapshot["symbols"])
    assert snapshot["complexity"]["aggregate"] == total


def test_tool_versions_are_recorded(snapshot):
    radon = snapshot["tools"]["radon"]
    assert radon["status"] == "ok"
    assert radon["version"], "a metric without its tool version is not comparable over time"
    assert "WARNING" not in (radon["version"] or "")


def test_unconfigured_sections_are_skipped_not_zero(snapshot):
    assert snapshot["tests"]["status"] == "skipped"
    assert snapshot["tests"]["passed"] is None
    assert snapshot["tests"]["coverage_percent"] is None


def test_deltas_without_a_baseline_are_unavailable(snapshot):
    assert snapshot["deltas"]["status"] == "unavailable"
    assert all(value is None for value in snapshot["deltas"]["values"].values())


def test_provenance_is_undeclared_by_default(snapshot):
    assert snapshot["provenance"]["authoring_mode"] is None


def test_a_pr_run_is_not_marked_canonical(snapshot, tmp_path):
    """Default-branch runs are the historical series; proposals are not."""
    output = tmp_path / "pr.json"
    env = {
        **os.environ,
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_HEAD_REF": "feature/x",
        "GITHUB_BASE_REF": "main",
        "GITHUB_REPOSITORY": "ieepirzy/origo",
    }
    subprocess.run(
        [sys.executable, "-m", "tools.code_health", "--output", str(output), "--quiet"],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, check=True,
    )
    with open(output, encoding="utf-8") as handle:
        document = json.load(handle)
    assert document["run"]["canonical"] is False
    assert document["run"]["ref_class"] == "other"
    assert document["run"]["is_default_branch"] is False


def test_the_same_commit_produces_the_same_observation_id(snapshot, tmp_path):
    """Repeated analysis must be dedupable by the backend."""
    output = tmp_path / "again.json"
    subprocess.run(
        [sys.executable, "-m", "tools.code_health", "--output", str(output), "--quiet"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    )
    with open(output, encoding="utf-8") as handle:
        assert json.load(handle)["run"]["observation_id"] == snapshot["run"]["observation_id"]
