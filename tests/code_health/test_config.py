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


def test_a_standalone_code_health_toml_is_read(tmp_path):
    """For repositories with no pyproject.toml."""
    (tmp_path / "code-health.toml").write_text(
        'paths = ["app"]\nlint_paths = ["app", "tests"]\ntype_checker = "mypy"\n'
    )
    config = load(str(tmp_path))
    assert config.paths == ["app"]
    assert config.type_checker == "mypy"
    assert config.source == "code-health.toml"


def test_a_standalone_file_wins_over_pyproject(tmp_path):
    (tmp_path / "code-health.toml").write_text('paths = ["chosen"]\n')
    (tmp_path / "pyproject.toml").write_text('[tool.code_health]\npaths = ["ignored"]\n')
    assert load(str(tmp_path)).paths == ["chosen"]


def test_pyproject_is_used_when_there_is_no_standalone_file(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.code_health]\npaths = ["pkg"]\n')
    config = load(str(tmp_path))
    assert config.paths == ["pkg"]
    assert config.source == "pyproject.toml"


def test_a_pyproject_without_our_table_falls_through_to_defaults(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n')
    config = load(str(tmp_path))
    assert config.paths == ["."]
    assert config.source is None


def test_unknown_settings_are_ignored_not_fatal(tmp_path):
    (tmp_path / "code-health.toml").write_text('paths = ["a"]\nfuture_setting = 3\n')
    assert load(str(tmp_path)).paths == ["a"]
