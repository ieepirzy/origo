"""Per-repository configuration.

Read from ``[tool.code_health]`` in ``pyproject.toml`` so a repository declares
its own analysis target in the file it already uses for tooling, rather than in
workflow YAML.  That is what lets the same collector run unchanged across
repositories: CI orchestrates, the repository configures, and neither contains
the data model.
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


def load(repo_root: str = ".") -> Config:
    """Load ``[tool.code_health]``, falling back to sane defaults."""
    path = os.path.join(repo_root, "pyproject.toml")
    if tomllib is None or not os.path.exists(path):
        return Config()
    with open(path, "rb") as handle:
        payload: dict[str, Any] = tomllib.load(handle)
    section = payload.get("tool", {}).get("code_health", {})
    config = Config()
    for key, value in section.items():
        if hasattr(config, key):
            setattr(config, key, value)
    return config
