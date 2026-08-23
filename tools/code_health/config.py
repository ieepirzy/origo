"""Per-repository configuration.

A repository declares its own analysis target in a file it owns, rather than in
workflow YAML.  That is what lets the same collector run unchanged across
repositories: CI orchestrates, the repository configures, and neither contains
the data model.

Two sources, in precedence order:

``code-health.toml``
    A standalone file with the settings at the top level.  For repositories
    with no ``pyproject.toml`` -- several of ours are ``requirements.txt``
    applications rather than packages, and adding a ``pyproject.toml`` purely
    to hold four settings changes how build and packaging tools see the
    repository, which is a bigger change than it looks.
``pyproject.toml``
    ``[tool.code_health]``, for repositories that already have one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

try:  # Python 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.10 and older
    tomllib = None  # type: ignore[assignment]


@dataclass
class Config:
    #: Paths measured for complexity, LOC and maintainability -- normally the
    #: shipped package, not the test suite: test complexity is a different
    #: quantity and mixing them makes both series uninterpretable.
    paths: list[str] = field(default_factory=lambda: ["."])
    #: Paths linted.  Usually wider than `paths`.
    lint_paths: list[str] = field(default_factory=list)
    #: The subset of lint findings that block the build.  Starts narrow.
    lint_gate_paths: list[str] = field(default_factory=list)
    #: Paths type-checked.
    typecheck_paths: list[str] = field(default_factory=list)
    type_checker: str = "pyright"
    #: Whether the type checker blocks.  Off until a repository's baseline is
    #: at zero; measured from day one either way.
    typecheck_blocking: bool = False
    language: str = "python"
    hotspot_limit: int = 20
    max_detail_events: int = 50
    #: Which file supplied the settings, recorded in the snapshot's target
    #: block so a reader knows what governed the run.
    source: str | None = None

    @property
    def effective_lint_paths(self) -> list[str]:
        return self.lint_paths or self.paths

    @property
    def effective_typecheck_paths(self) -> list[str]:
        return self.typecheck_paths or self.paths

    @property
    def effective_lint_gate_paths(self) -> list[str]:
        """Which paths' lint findings block.

        Defaults to the measured paths rather than to *everything* linted: a
        repository that widens `lint_paths` to include its test suite should
        not thereby start gating it.
        """
        return self.lint_gate_paths or self.paths


#: Where configuration may live, most specific first.  The second element of
#: each pair is the path to the settings table inside that file.
CONFIG_SOURCES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("code-health.toml", ()),
    ("pyproject.toml", ("tool", "code_health")),
)


def _read_table(path: str, keys: tuple[str, ...]) -> dict[str, Any] | None:
    if tomllib is None or not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as handle:
            payload: Any = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        # A malformed pyproject.toml is not this tool's problem to report, and
        # falling back to defaults silently would hide a real misconfiguration
        # -- so it is surfaced by the caller failing on the resulting analysis,
        # not swallowed into a wrong config.
        raise
    for key in keys:
        if not isinstance(payload, dict):
            return None
        payload = payload.get(key)
        if payload is None:
            return None
    return payload if isinstance(payload, dict) else None


def load(repo_root: str = ".") -> Config:
    """Load repository configuration, falling back to sane defaults.

    An unconfigured repository gets ``paths = ["."]``, which measures and gates
    everything.  That is the safe default: a repository that forgot to
    configure the lane is over-measured, never silently under-measured.
    """
    config = Config()
    for filename, keys in CONFIG_SOURCES:
        section = _read_table(os.path.join(repo_root, filename), keys)
        if section is None:
            continue
        for key, value in section.items():
            if hasattr(config, key):
                setattr(config, key, value)
        config.source = filename
        break
    return config
