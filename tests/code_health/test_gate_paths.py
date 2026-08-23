"""Lint gating is narrower than lint measurement, and exactly so."""

from tools.code_health.analyzers import base, ruff_lint


def _fake_findings(monkeypatch, findings_json):
    monkeypatch.setattr(ruff_lint, "tool_version", lambda command: "ruff 0.15.8")
    monkeypatch.setattr(
        ruff_lint,
        "run",
        lambda command, cwd=None: base.Completed(returncode=0, stdout=findings_json, stderr="", duration=0.1),
    )


def test_a_finding_inside_the_gated_path_blocks(monkeypatch, tmp_path):
    _fake_findings(monkeypatch, f'[{{"code":"F401","filename":"{tmp_path}/origo/endpoints.py"}}]')
    data, _ = ruff_lint.collect(["origo"], cwd=str(tmp_path), gate_paths=["origo"])
    assert data["errors"] == 1
    assert data["gate_errors"] == 1


def test_a_finding_outside_the_gated_path_is_measured_but_does_not_block(monkeypatch, tmp_path):
    """The real origo situation: 12 findings, all in tests/, gate on origo/."""
    _fake_findings(monkeypatch, f'[{{"code":"F401","filename":"{tmp_path}/tests/test_endpoints.py"}}]')
    data, _ = ruff_lint.collect(["origo", "tests"], cwd=str(tmp_path), gate_paths=["origo"])
    assert data["errors"] == 1, "still measured"
    assert data["gate_errors"] == 0, "but not gated"


def test_gating_is_not_a_string_prefix_match(monkeypatch, tmp_path):
    """`origo_extra/` must not be gated by a gate on `origo`."""
    _fake_findings(monkeypatch, f'[{{"code":"F401","filename":"{tmp_path}/origo_extra/thing.py"}}]')
    data, _ = ruff_lint.collect(["."], cwd=str(tmp_path), gate_paths=["origo"])
    assert data["gate_errors"] == 0


def test_nested_gate_paths_are_matched(monkeypatch, tmp_path):
    _fake_findings(monkeypatch, f'[{{"code":"F401","filename":"{tmp_path}/src/app/main.py"}}]')
    data, _ = ruff_lint.collect(["src"], cwd=str(tmp_path), gate_paths=["src/app"])
    assert data["gate_errors"] == 1


def test_without_gate_paths_everything_blocking_gates(monkeypatch, tmp_path):
    """Default is the safe one: no configured narrowing means no narrowing."""
    _fake_findings(monkeypatch, f'[{{"code":"F401","filename":"{tmp_path}/anywhere.py"}}]')
    data, _ = ruff_lint.collect(["."], cwd=str(tmp_path), gate_paths=None)
    assert data["gate_errors"] == 1


def test_non_blocking_rules_never_gate(monkeypatch, tmp_path):
    _fake_findings(monkeypatch, f'[{{"code":"D100","filename":"{tmp_path}/origo/a.py"}}]')
    data, _ = ruff_lint.collect(["origo"], cwd=str(tmp_path), gate_paths=["origo"])
    assert data["warnings"] == 1
    assert data["gate_errors"] == 0


def test_lint_blocking_false_measures_without_failing(snapshot_factory):
    from tools.code_health.cli import _gate
    from tools.code_health.config import Config

    document = snapshot_factory()
    document["lint"] = {"status": "ok", "gate_errors": 19, "gate_paths": ["app"],
                        "blocking_rule_prefixes": ["F"], "errors": 19}
    document["tests"] = {"status": "ok", "failed": 0, "errors": 0}
    violations = _gate(document, Config(lint_blocking=False), lambda *a: None)
    assert violations == []


def test_lint_blocking_true_does_fail(snapshot_factory):
    from tools.code_health.cli import _gate
    from tools.code_health.config import Config

    document = snapshot_factory()
    document["lint"] = {"status": "ok", "gate_errors": 19, "gate_paths": ["app"],
                        "blocking_rule_prefixes": ["F"], "errors": 19}
    document["tests"] = {"status": "ok", "failed": 0, "errors": 0}
    violations = _gate(document, Config(lint_blocking=True), lambda *a: None)
    assert len(violations) == 1
