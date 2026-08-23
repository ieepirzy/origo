"""Repository configuration."""

from tools.code_health.config import Config, load


def test_defaults_do_not_narrow_the_gate():
    """An unconfigured repository gates everything it measures."""
    config = Config(paths=["pkg"])
    assert config.effective_lint_paths == ["pkg"]
    assert config.effective_lint_gate_paths == ["pkg"]
    assert config.effective_typecheck_paths == ["pkg"]


def test_widening_lint_paths_does_not_widen_the_gate():
    config = Config(paths=["pkg"], lint_paths=["pkg", "tests"])
    assert config.effective_lint_paths == ["pkg", "tests"]
    assert config.effective_lint_gate_paths == ["pkg"], "measuring tests must not start gating them"


def test_this_repository_is_configured_as_documented():
    """origo's own settings, asserted so a silent edit is caught."""
    config = load(".")
    assert config.paths == ["origo"]
    assert config.lint_paths == ["origo", "tests", "tools"]
    assert config.lint_gate_paths == ["origo", "tools"]
    assert config.type_checker == "pyright"
    assert config.typecheck_blocking is False, "no baseline yet; measured, not gated"


def test_a_repository_without_configuration_still_works(tmp_path):
    config = load(str(tmp_path))
    assert config.paths == ["."]
    assert config.language == "python"
