#!/usr/bin/env python3
"""Unit tests for audit_litellm.py (fleet-scanning wrapper)."""

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

from safe_litellm_detector import Classification, inspect_site_packages
from audit_litellm import (
    Auditor,
    AuditFinding,
    AuditReport,
    EnvKind,
    EverythingDiscovery,
    GlobalPythonDiscovery,
    RepoVenvDiscovery,
    StandaloneVenvDiscovery,
    _build_parser,
    _discover_windows_workspace_dirs,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_repo_with_venv(base: Path, name: str = "my_repo") -> Path:
    """Creates a minimal repo directory with a venv containing site-packages."""
    repo = base / name
    sp = repo / ".venv" / "lib" / "python3.12" / "site-packages"
    (repo / ".git").mkdir(parents=True)
    sp.mkdir(parents=True)
    return sp


def _plant_litellm(site_packages: Path, *, version: str = "1.82.6") -> None:
    """Plants a fake litellm footprint into *site_packages*."""
    (site_packages / "litellm").mkdir(exist_ok=True)
    dist = site_packages / f"litellm-{version}.dist-info"
    dist.mkdir(exist_ok=True)
    (dist / "METADATA").write_text(
        textwrap.dedent(f"""\
            Metadata-Version: 2.1
            Name: litellm
            Version: {version}
        """)
    )


def _plant_pth_backdoor(site_packages: Path) -> None:
    """Creates the malicious ``litellm_init.pth`` file."""
    (site_packages / "litellm_init.pth").write_text("import os\n")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

class TestRepoVenvDiscovery(unittest.TestCase):
    """Tests for Git repository and venv site-packages discovery."""

    def test_finds_git_repos(self):
        """Detects a ``.git`` directory as a repository root."""
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "my_repo"
            (repo / ".git").mkdir(parents=True)
            repos = RepoVenvDiscovery._git_repos(Path(d))
            self.assertEqual(len(repos), 1)
            self.assertEqual(repos[0], repo)

    def test_finds_venv_site_packages(self):
        """Locates ``site-packages`` inside a ``.venv`` directory."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_repo_with_venv(Path(d))
            found = RepoVenvDiscovery._find_venv_site_packages(Path(d) / "my_repo")
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0], sp)

    def test_returns_empty_when_no_venv(self):
        """Returns nothing when no virtual environment exists."""
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "bare_repo"
            (repo / ".git").mkdir(parents=True)
            found = RepoVenvDiscovery._find_venv_site_packages(repo)
            self.assertEqual(found, [])

    def test_discover_yields_site_packages(self):
        """End-to-end: discover yields site-packages paths."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_repo_with_venv(Path(d))
            discovery = RepoVenvDiscovery([Path(d)])
            results = list(discovery.discover())
            self.assertEqual(len(results), 1)
            label, path, kind = results[0]
            self.assertEqual(path, sp)
            self.assertEqual(kind, EnvKind.REPOSITORY)
            self.assertIn("my_repo", label)

    def test_finds_nested_venvs(self):
        """Discovers venvs inside subdirectories of a repo (e.g. monorepo)."""
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "monorepo"
            (repo / ".git").mkdir(parents=True)
            # Top-level venv
            top_sp = repo / ".venv" / "lib" / "python3.12" / "site-packages"
            top_sp.mkdir(parents=True)
            # Nested sub-project venv
            nested_sp = repo / "services" / "api" / ".venv" / "lib" / "python3.12" / "site-packages"
            nested_sp.mkdir(parents=True)

            discovery = RepoVenvDiscovery([Path(d)])
            results = list(discovery.discover())
            paths = [r[1] for r in results]
            self.assertEqual(len(paths), 2)
            self.assertIn(top_sp, paths)
            self.assertIn(nested_sp, paths)


class TestStandaloneVenvDiscovery(unittest.TestCase):
    """Tests for standalone (non-repo) venv discovery."""

    def test_finds_standalone_venv(self):
        """Discovers a venv that is not inside a Git repository."""
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d) / "some_env" / "lib" / "python3.12" / "site-packages"
            sp.mkdir(parents=True)
            discovery = StandaloneVenvDiscovery([Path(d)])
            results = list(discovery.discover())
            self.assertEqual(len(results), 1)
            _, path, kind = results[0]
            self.assertEqual(path, sp)
            self.assertEqual(kind, EnvKind.REPOSITORY)

    def test_finds_deeply_nested_site_packages(self):
        """Discovers site-packages in a deeply nested path (e.g. IDE cache)."""
        with tempfile.TemporaryDirectory() as d:
            sp = (Path(d) / "Library" / "Caches" / "IDE" / "project"
                  / ".venv" / "lib" / "python3.12" / "site-packages")
            sp.mkdir(parents=True)
            discovery = StandaloneVenvDiscovery([Path(d)])
            results = list(discovery.discover())
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0][1], sp)

    def test_returns_empty_for_no_envs(self):
        """Returns nothing when no site-packages exists."""
        with tempfile.TemporaryDirectory() as d:
            discovery = StandaloneVenvDiscovery([Path(d)])
            results = list(discovery.discover())
            self.assertEqual(results, [])


class TestWindowsWorkspaceDirs(unittest.TestCase):
    """Tests for Windows workspace directory discovery."""

    @patch("audit_litellm.sys")
    @patch("audit_litellm.glob.glob")
    def test_returns_empty_on_non_windows(self, mock_glob, mock_sys):
        """Should return nothing on non-Windows platforms."""
        mock_sys.platform = "darwin"
        result = _discover_windows_workspace_dirs()
        self.assertEqual(result, [])
        mock_glob.assert_not_called()

    @patch("audit_litellm.sys")
    @patch("audit_litellm.glob.glob")
    def test_discovers_ws_directories_on_windows(self, mock_glob, mock_sys):
        """Should discover C:\\ws and C:\\ws_* directories on Windows."""
        mock_sys.platform = "win32"
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d) / "ws"
            ws_foo = Path(d) / "ws_foo"
            ws.mkdir()
            ws_foo.mkdir()

            def _fake_glob(pattern):
                if pattern == r"C:\[wW][sS]":
                    return [str(ws)]
                if pattern == r"C:\[wW][sS]_*":
                    return [str(ws_foo)]
                return []

            mock_glob.side_effect = _fake_glob
            result = _discover_windows_workspace_dirs()
            self.assertEqual(len(result), 2)
            self.assertIn(ws, result)
            self.assertIn(ws_foo, result)

    @patch("audit_litellm.sys")
    @patch("audit_litellm.glob.glob")
    def test_deduplicates_resolved_paths(self, mock_glob, mock_sys):
        """Should not return the same resolved directory twice."""
        mock_sys.platform = "win32"
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d) / "ws"
            ws.mkdir()

            # Both patterns return the same directory
            mock_glob.return_value = [str(ws)]
            result = _discover_windows_workspace_dirs()
            # Called twice (two patterns), but same dir → deduplicated
            self.assertEqual(len(result), 1)

    @patch("audit_litellm.sys")
    @patch("audit_litellm.glob.glob")
    def test_skips_non_directory_matches(self, mock_glob, mock_sys):
        """Should skip matches that are not directories."""
        mock_sys.platform = "win32"
        with tempfile.TemporaryDirectory() as d:
            ws_file = Path(d) / "ws"
            ws_file.write_text("not a directory")

            mock_glob.return_value = [str(ws_file)]
            result = _discover_windows_workspace_dirs()
            self.assertEqual(result, [])

    @patch("audit_litellm.sys")
    @patch("audit_litellm.glob.glob")
    def test_returns_empty_when_no_matches(self, mock_glob, mock_sys):
        """Should return nothing when no matching directories exist."""
        mock_sys.platform = "win32"
        mock_glob.return_value = []
        result = _discover_windows_workspace_dirs()
        self.assertEqual(result, [])


class TestGlobalPythonDiscovery(unittest.TestCase):
    """Tests for system Python site-packages discovery."""

    def test_discovers_at_least_one_environment(self):
        """At least one global site-packages directory should be found."""
        discovery = GlobalPythonDiscovery()
        results = list(discovery.discover())
        self.assertGreater(len(results), 0)

    def test_all_results_are_global_kind(self):
        """Every result should have ``EnvKind.GLOBAL``."""
        discovery = GlobalPythonDiscovery()
        for _, _, kind in discovery.discover():
            self.assertEqual(kind, EnvKind.GLOBAL)


class TestEverythingDiscovery(unittest.TestCase):
    """Tests for Everything HTTP result integration."""

    @patch("audit_litellm.discover_everything_targets")
    def test_wraps_everything_targets_as_repository_findings(self, mock_discover):
        """Everything results should become discovery items for auditor dedup."""
        mock_discover.return_value = [
            Path(r"C:\env\Lib\site-packages"),
            Path(r"C:\other\Lib\site-packages"),
        ]

        discovery = EverythingDiscovery("http://127.0.0.1/?search=litellm")
        results = list(discovery.discover())

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0][1], Path(r"C:\env\Lib\site-packages"))
        self.assertEqual(results[0][2], EnvKind.REPOSITORY)
        self.assertIn("Everything", results[0][0])


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------

class TestAuditReport(unittest.TestCase):
    """Tests for the AuditReport data model."""

    def _make_finding(self, sp: Path, *, installed: bool = False,
                      version: str | None = None,
                      kind: EnvKind = EnvKind.GLOBAL) -> AuditFinding:
        """Helper to build an AuditFinding from a real inspection."""
        if installed and version:
            _plant_litellm(sp, version=version)
        detail = inspect_site_packages(sp)
        return AuditFinding(label="test", kind=kind, detail=detail)

    def test_worst_compromised(self):
        """Report surfaces compromised-candidate as worst."""
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d) / "sp"
            sp.mkdir()
            _plant_litellm(sp, version="1.82.8")
            _plant_pth_backdoor(sp)
            af = AuditFinding(
                label="x", kind=EnvKind.REPOSITORY,
                detail=inspect_site_packages(sp),
            )
            report = AuditReport(findings=[af])
            self.assertEqual(
                report.worst_classification,
                Classification.COMPROMISED_CANDIDATE,
            )

    def test_worst_clean(self):
        """Clean findings → clean worst classification."""
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d)
            af = AuditFinding(
                label="x", kind=EnvKind.GLOBAL,
                detail=inspect_site_packages(sp),
            )
            report = AuditReport(findings=[af])
            self.assertEqual(report.worst_classification, Classification.CLEAN)

    def test_by_kind_filters(self):
        """``by_kind`` returns only findings matching the requested kind."""
        with tempfile.TemporaryDirectory() as d:
            sp = Path(d)
            detail = inspect_site_packages(sp)
            report = AuditReport(findings=[
                AuditFinding("repo", EnvKind.REPOSITORY, detail),
                AuditFinding("sys", EnvKind.GLOBAL, detail),
            ])
            self.assertEqual(len(report.by_kind(EnvKind.REPOSITORY)), 1)
            self.assertEqual(len(report.by_kind(EnvKind.GLOBAL)), 1)

    def test_empty_report(self):
        """Empty report has clean worst classification."""
        report = AuditReport()
        self.assertEqual(report.worst_classification, Classification.CLEAN)
        self.assertEqual(report.total_checked, 0)


# ---------------------------------------------------------------------------
# Auditor (end-to-end)
# ---------------------------------------------------------------------------

class TestAuditor(unittest.TestCase):
    """Tests for the Auditor orchestrator."""

    def test_deduplicates_site_packages(self):
        """The same resolved ``site-packages`` is only checked once."""
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            _make_repo_with_venv(base, "repo_a")
            repo_b = base / "repo_b"
            (repo_b / ".git").mkdir(parents=True)
            try:
                (repo_b / ".venv").symlink_to(base / "repo_a" / ".venv")
            except OSError as exc:
                self.skipTest(f"当前环境不允许创建符号链接: {exc}")

            discovery = RepoVenvDiscovery([base])
            report = Auditor([discovery]).run()
            self.assertEqual(report.total_checked, 1)

    def test_detects_planted_litellm(self):
        """Auditor correctly identifies a planted litellm installation."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_repo_with_venv(Path(d))
            _plant_litellm(sp, version="1.82.8")
            _plant_pth_backdoor(sp)

            discovery = RepoVenvDiscovery([Path(d)])
            report = Auditor([discovery]).run()

            self.assertEqual(
                report.worst_classification,
                Classification.COMPROMISED_CANDIDATE,
            )
            f = report.findings[0].detail
            self.assertTrue(f.litellm_present)
            self.assertEqual(f.version, "1.82.8")
            self.assertTrue(f.pth_present)

    def test_clean_environment(self):
        """Auditor reports clean for an environment without litellm."""
        with tempfile.TemporaryDirectory() as d:
            _make_repo_with_venv(Path(d))
            discovery = RepoVenvDiscovery([Path(d)])
            report = Auditor([discovery]).run()

            self.assertEqual(report.worst_classification, Classification.CLEAN)
            self.assertEqual(report.total_checked, 1)
            self.assertFalse(report.findings[0].detail.litellm_present)

    def test_strict_1827_propagates(self):
        """--strict-1827 flag reaches the classifier."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_repo_with_venv(Path(d))
            _plant_litellm(sp, version="1.82.7")

            discovery = RepoVenvDiscovery([Path(d)])
            report = Auditor([discovery], strict_1827=True).run()

            self.assertEqual(
                report.worst_classification,
                Classification.COMPROMISED_CANDIDATE,
            )

    def test_dedup_between_repo_and_standalone(self):
        """Same site-packages found by both RepoVenv and Standalone is checked once."""
        with tempfile.TemporaryDirectory() as d:
            _make_repo_with_venv(Path(d), "my_repo")
            discoveries = [
                RepoVenvDiscovery([Path(d)]),
                StandaloneVenvDiscovery([Path(d)]),
            ]
            report = Auditor(discoveries).run()
            self.assertEqual(report.total_checked, 1)

    def test_realtime_callback_receives_each_finding(self):
        """Auditor should emit each finding as soon as it is scanned."""
        with tempfile.TemporaryDirectory() as d:
            sp = _make_repo_with_venv(Path(d))
            _plant_litellm(sp, version="1.82.8")
            callbacks: list[AuditFinding] = []

            report = Auditor([RepoVenvDiscovery([Path(d)])]).run(
                on_finding=callbacks.append,
            )

            self.assertEqual(report.total_checked, 1)
            self.assertEqual(len(callbacks), 1)
            self.assertEqual(
                callbacks[0].detail.classification,
                Classification.COMPROMISED_CANDIDATE,
            )


class TestCliParser(unittest.TestCase):
    """Tests for CLI flags."""

    def test_accepts_eve_flag(self):
        """Parser should expose the Everything integration flag."""
        args = _build_parser().parse_args(["--eve"])
        self.assertTrue(args.eve)


if __name__ == "__main__":
    unittest.main()
