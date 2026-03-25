#!/usr/bin/env python3
"""Scans default project directories and global Python installations for litellm.

This is the fleet-scanning wrapper around :mod:`safe_litellm_detector`.  It
walks ``~/projects``, ``~/work``, Windows workspace directories (``C:\\ws``
and ``C:\\ws_*`` in any capitalisation), any extra CLI paths, and every global
Python installation, then feeds discovered ``site-packages`` directories into
the detector's filesystem-only inspection engine.

Usage::

    python3 audit_litellm.py [EXTRA_DIR ...]
    python3 audit_litellm.py --json
    python3 audit_litellm.py ~/src --strict-1827 --json
"""

from __future__ import annotations

import abc
import argparse
import glob
import os
import sys
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Iterable, Sequence

from safe_litellm_detector import (
    Classification,
    SitePackagesFinding,
    discover_global_site_packages,
    inspect_site_packages,
    EXIT_ERROR,
    _c,
    _BOLD,
    _RED,
    _RESET,
    _YELLOW,
    _CLS_COLORS,
    _CLS_ICONS,
    _safe_resolve as _safe_resolve_path,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_VENV_DIR_NAMES: tuple[str, ...] = (
    ".venv", "venv", "env", ".env", "ENV", "virtenv", ".virtenv",
)

# ---------------------------------------------------------------------------
# Domain models
# ---------------------------------------------------------------------------


class EnvKind(Enum):
    """Classification of a discovered environment's origin."""

    REPOSITORY = auto()
    GLOBAL = auto()


@dataclass(frozen=True)
class AuditFinding:
    """Pairs an environment label with the detector's finding for one site-packages."""

    label: str
    kind: EnvKind
    detail: SitePackagesFinding


@dataclass
class AuditReport:
    """Aggregated results across all environments."""

    findings: list[AuditFinding] = field(default_factory=list)

    @property
    def worst_classification(self) -> Classification:
        """Returns the most severe classification across all findings."""
        worst = Classification.CLEAN
        for f in self.findings:
            if f.detail.classification == Classification.COMPROMISED_CANDIDATE:
                return Classification.COMPROMISED_CANDIDATE
            if f.detail.classification == Classification.SUSPICIOUS:
                worst = Classification.SUSPICIOUS
        return worst

    @property
    def total_checked(self) -> int:
        """Number of site-packages directories inspected."""
        return len(self.findings)

    def by_kind(self, kind: EnvKind) -> list[AuditFinding]:
        """Returns findings filtered by *kind*."""
        return [f for f in self.findings if f.kind == kind]


# ---------------------------------------------------------------------------
# Environment discovery
# ---------------------------------------------------------------------------


class EnvironmentDiscovery(abc.ABC):
    """Yields ``(label, site_packages_path, kind)`` tuples."""

    @abc.abstractmethod
    def discover(self) -> Iterable[tuple[str, Path, EnvKind]]:
        """Generates ``site-packages`` directories to inspect."""


class RepoVenvDiscovery(EnvironmentDiscovery):
    """Finds ``site-packages`` inside virtual environments in Git repos.

    Searches the entire subtree of each repo for recognised venv directory
    names, so nested venvs (e.g. ``monorepo/services/svc/.venv``) are found
    too.
    """

    def __init__(self, root_dirs: Sequence[Path]) -> None:
        self._root_dirs = root_dirs

    def discover(self) -> Iterable[tuple[str, Path, EnvKind]]:
        for root in self._root_dirs:
            if not root.is_dir():
                continue
            for repo in self._git_repos(root):
                for sp in self._find_venv_site_packages(repo):
                    yield f"{repo.name} (venv)", sp, EnvKind.REPOSITORY

    @staticmethod
    def _git_repos(root: Path) -> list[Path]:
        """Returns de-duplicated Git repo paths under *root*."""
        repos: list[Path] = []
        try:
            for git_dir in sorted(root.rglob(".git")):
                repo = git_dir.parent
                if not any(repo.is_relative_to(r) for r in repos):
                    repos.append(repo)
        except (PermissionError, OSError):
            pass
        return repos

    @staticmethod
    def _find_venv_site_packages(repo: Path) -> list[Path]:
        """Returns every ``site-packages`` directory inside recognised venvs.

        Walks the entire *repo* tree so that nested venvs (e.g. inside
        sub-projects or service directories) are discovered.
        """
        results: list[Path] = []
        seen: set[Path] = set()

        def _add_from_venv(venv: Path) -> None:
            for sp in sorted(venv.glob("lib/python*/site-packages")):
                try:
                    resolved = sp.resolve()
                except OSError:
                    continue
                if resolved not in seen and sp.is_dir():
                    seen.add(resolved)
                    results.append(sp)
            lib_sp = venv / "Lib" / "site-packages"
            if lib_sp.is_dir():
                try:
                    resolved = lib_sp.resolve()
                except OSError:
                    return
                if resolved not in seen:
                    seen.add(resolved)
                    results.append(lib_sp)

        # Walk the repo tree for any recognised venv directory name.
        try:
            for dirpath, dirnames, _ in os.walk(repo, followlinks=False):
                current = Path(dirpath)
                matched: list[str] = []
                for name in dirnames:
                    if name in _VENV_DIR_NAMES:
                        _add_from_venv(current / name)
                        matched.append(name)
                # Don't descend into the matched venv dirs themselves.
                for name in matched:
                    dirnames.remove(name)
        except (PermissionError, OSError):
            pass

        return results


class StandaloneVenvDiscovery(EnvironmentDiscovery):
    """Finds ``site-packages`` inside virtual environments that live outside
    Git repositories (e.g. JetBrains/IDE caches, standalone venvs)."""

    def __init__(self, root_dirs: Sequence[Path]) -> None:
        self._root_dirs = root_dirs

    def discover(self) -> Iterable[tuple[str, Path, EnvKind]]:
        for root in self._root_dirs:
            if not root.is_dir():
                continue
            try:
                for sp in sorted(root.rglob("site-packages")):
                    if sp.is_dir():
                        yield self._label_for(sp), sp, EnvKind.REPOSITORY
            except (PermissionError, OSError):
                continue

    @staticmethod
    def _label_for(sp: Path) -> str:
        """Derives a human-readable label from a ``site-packages`` path."""
        # Walk up to the venv root: lib/pythonX.Y/site-packages → 3 up,
        # Lib/site-packages → 2 up.
        parent = sp.parent
        if parent.name.startswith("python"):
            env_root = parent.parent.parent
        else:
            env_root = parent.parent
        return f"{env_root.name} (venv)"


class GlobalPythonDiscovery(EnvironmentDiscovery):
    """Discovers ``site-packages`` for system-wide Python interpreters.

    Delegates to :func:`safe_litellm_detector.discover_global_site_packages`
    so the discovery logic lives in one place.
    """

    def discover(self) -> Iterable[tuple[str, Path, EnvKind]]:
        for label, sp in discover_global_site_packages():
            yield label, sp, EnvKind.GLOBAL


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------


class Auditor:
    """Orchestrates discovery, detection (via the detector), and deduplication."""

    def __init__(
        self,
        discoveries: Sequence[EnvironmentDiscovery],
        *,
        strict_1827: bool = False,
    ) -> None:
        self._discoveries = discoveries
        self._strict_1827 = strict_1827

    def run(self) -> AuditReport:
        """Executes the full audit and returns a report."""
        report = AuditReport()
        seen: set[Path] = set()

        for discovery in self._discoveries:
            for label, site_packages, kind in discovery.discover():
                resolved = _safe_resolve_path(site_packages)
                if resolved is None or resolved in seen:
                    continue
                seen.add(resolved)

                detail = inspect_site_packages(
                    site_packages, strict_1827=self._strict_1827,
                )
                report.findings.append(AuditFinding(
                    label=label, kind=kind, detail=detail,
                ))
        return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def print_report(report: AuditReport) -> None:
    """Prints a human-readable audit report to stdout."""
    _banner("AUDIT SUMMARY")

    if not report.findings:
        print(f"{_c(_YELLOW)}No environments found to check.{_c(_RESET)}\n")
    else:
        for kind, heading in (
            (EnvKind.REPOSITORY, "Repository Virtual Environments"),
            (EnvKind.GLOBAL, "Global Python Installations"),
        ):
            group = report.by_kind(kind)
            if not group:
                continue
            print(f"{_c(_BOLD)}{heading}:{_c(_RESET)}")
            for af in group:
                _print_finding(af)
            print()

        print(
            f"{_c(_BOLD)}Total environments checked: "
            f"{report.total_checked}{_c(_RESET)}"
        )

    _banner("FINAL VERDICT")
    worst = report.worst_classification
    color = _CLS_COLORS[worst]
    verdicts = {
        Classification.CLEAN: "no issues found",
        Classification.SUSPICIOUS: "suspicious — review needed",
        Classification.COMPROMISED_CANDIDATE: "possibly compromised",
    }
    print(f"{_c(color)}{_c(_BOLD)}{verdicts[worst]}{_c(_RESET)}")


def _banner(title: str) -> None:
    """Prints a section banner line."""
    sep = "=" * 70
    print(f"\n{_c(_BOLD)}{sep}\n{title}\n{sep}{_c(_RESET)}\n")


def _print_finding(af: AuditFinding) -> None:
    """Prints a single environment finding."""
    f = af.detail
    color = _CLS_COLORS[f.classification]
    icon = _CLS_ICONS[f.classification]

    print(f"\n  {_c(color)}{icon}{_c(_RESET)} {af.label}")
    print(f"      site-packages: {f.path}")
    print(f"      Status: {_c(color)}{_c(_BOLD)}{f.classification.value}{_c(_RESET)}")

    if f.reasons:
        for reason in f.reasons:
            print(f"        - {reason}")

    if f.pth_present:
        print(
            f"      {_c(_RED)}{_c(_BOLD)}"
            f"litellm_init.pth BACKDOOR PRESENT{_c(_RESET)}"
        )
    if f.record_mentions_pth:
        print(f"      {_c(_RED)}RECORD references litellm_init.pth{_c(_RESET)}")


def print_json_report(report: AuditReport) -> None:
    """Prints findings as JSON to stdout."""
    import json

    data = [
        {
            "label": af.label,
            "kind": af.kind.name.lower(),
            **af.detail.to_dict(),
        }
        for af in report.findings
    ]
    print(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Constructs the argument parser."""
    parser = argparse.ArgumentParser(
        prog="audit_litellm",
        description=(
            "Scans project directories and global Python installations for "
            "litellm.  On Windows, C:\\ws and C:\\ws_* (all caps variants) "
            "are included automatically.  Uses filesystem-only inspection — "
            "never executes a suspect interpreter."
        ),
    )
    parser.add_argument(
        "extra_dirs",
        nargs="*",
        type=Path,
        metavar="DIR",
        help="Additional directories to scan (beyond ~/projects, ~/work, and C:\\ws* on Windows).",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=False,
        help="Emit JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--strict-1827",
        action="store_true",
        default=False,
        help="Treat version 1.82.7 as compromised-candidate.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="Suppress output; exit code only.",
    )
    return parser


_EXIT_FOR_CLASSIFICATION: dict[Classification, int] = {
    Classification.CLEAN: 0,
    Classification.SUSPICIOUS: 1,
    Classification.COMPROMISED_CANDIDATE: 2,
}


def _discover_windows_workspace_dirs() -> list[Path]:
    """Returns Windows workspace directories matching ``C:\\ws`` and ``C:\\ws_*``.

    On Windows, all drive-letter / prefix capitalization variants are checked:
    ``C:\\ws``, ``C:\\WS``, ``C:\\Ws``, ``C:\\wS``, ``C:\\ws_foo``, etc.
    The glob pattern ``C:\\[wW][sS]`` plus ``C:\\[wW][sS]_*`` covers every
    combination.

    Returns an empty list on non-Windows platforms.
    """
    if sys.platform != "win32":
        return []

    dirs: list[Path] = []
    seen: set[Path] = set()

    for pattern in (r"C:\[wW][sS]", r"C:\[wW][sS]_*"):
        for match in glob.glob(pattern):
            p = Path(match)
            try:
                resolved = p.resolve()
            except OSError:
                continue
            if resolved not in seen and p.is_dir():
                seen.add(resolved)
                dirs.append(p)

    return dirs


def main(argv: Sequence[str] | None = None) -> int:
    """Runs the fleet audit and returns an exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    home = Path.home()
    root_dirs = [home / "projects", home / "work"]
    root_dirs.extend(_discover_windows_workspace_dirs())
    if args.extra_dirs:
        root_dirs.extend(p.expanduser() for p in args.extra_dirs)

    # StandaloneVenvDiscovery scans the entire home directory to catch
    # environments that live outside Git repos (IDE caches, standalone
    # venvs, etc.).  The Auditor deduplicates resolved paths, so overlap
    # with RepoVenvDiscovery is harmless.
    discoveries: list[EnvironmentDiscovery] = [
        RepoVenvDiscovery(root_dirs),
        StandaloneVenvDiscovery([home] + root_dirs),
        GlobalPythonDiscovery(),
    ]

    auditor = Auditor(discoveries, strict_1827=args.strict_1827)
    report = auditor.run()

    if not args.quiet:
        if args.json_output:
            print_json_report(report)
        else:
            print_report(report)

    return _EXIT_FOR_CLASSIFICATION.get(
        report.worst_classification, EXIT_ERROR,
    )


if __name__ == "__main__":
    sys.exit(main())
