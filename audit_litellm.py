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
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum, auto
from html import escape
from pathlib import Path
from typing import Callable, Iterable, Sequence

from safe_litellm_detector import (
    Classification,
    SitePackagesFinding,
    classification_label,
    classification_priority,
    discover_everything_targets,
    discover_global_site_packages,
    inspect_site_packages,
    prompt_everything_url,
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
            yield label.replace("System", "系统环境"), sp, EnvKind.GLOBAL


class EverythingDiscovery(EnvironmentDiscovery):
    """Discovers additional targets from an Everything HTTP result page."""

    def __init__(self, url: str) -> None:
        self._url = url

    def discover(self) -> Iterable[tuple[str, Path, EnvKind]]:
        for sp in discover_everything_targets(self._url):
            yield f"Everything 结果 ({sp})", sp, EnvKind.REPOSITORY


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

    def run(
        self,
        on_finding: Callable[[AuditFinding], None] | None = None,
    ) -> AuditReport:
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
                finding = AuditFinding(
                    label=label, kind=kind, detail=detail,
                )
                report.findings.append(finding)
                if on_finding is not None:
                    on_finding(finding)
        return report


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def print_report(report: AuditReport) -> None:
    """Prints a human-readable audit report to stdout."""
    _banner("扫描汇总")

    if not report.findings:
        print(f"{_c(_YELLOW)}没有发现可检查的环境。{_c(_RESET)}\n")
    else:
        for kind, heading in (
            (EnvKind.REPOSITORY, "项目环境"),
            (EnvKind.GLOBAL, "全局 Python 环境"),
        ):
            group = report.by_kind(kind)
            if not group:
                continue
            print(f"{_c(_BOLD)}{heading}:{_c(_RESET)}")
            for af in group:
                _print_finding(af)
            print()

        print(
            f"{_c(_BOLD)}已检查环境总数: "
            f"{report.total_checked}{_c(_RESET)}"
        )

    _banner("最终结论")
    worst = report.worst_classification
    color = _CLS_COLORS[worst]
    verdicts = {
        Classification.CLEAN: "未发现异常",
        Classification.SUSPICIOUS: "发现可疑项，建议人工复核",
        Classification.COMPROMISED_CANDIDATE: "发现高风险疑似受污染环境",
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
    print(
        f"      状态: {_c(color)}{_c(_BOLD)}"
        f"{classification_label(f.classification)}{_c(_RESET)}"
    )

    if f.reasons:
        for reason in f.reasons:
            print(f"        - {reason}")

    if f.pth_present:
        print(
            f"      {_c(_RED)}{_c(_BOLD)}"
            f"检测到 litellm_init.pth 后门文件{_c(_RESET)}"
        )
    if f.record_mentions_pth:
        print(f"      {_c(_RED)}RECORD 引用了 litellm_init.pth{_c(_RESET)}")


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


def print_realtime_finding(af: AuditFinding) -> None:
    """Prints a finding immediately when it is scanned."""
    kind_label = {
        EnvKind.REPOSITORY: "项目环境",
        EnvKind.GLOBAL: "全局环境",
    }[af.kind]
    print(f"\n{_c(_BOLD)}[{kind_label}]{_c(_RESET)}", flush=True)
    _print_finding(af)


def print_summary(report: AuditReport, html_path: Path) -> None:
    """Prints the final non-JSON summary."""
    _banner("最终汇总")
    print(f"已检查环境总数: {report.total_checked}")
    verdicts = {
        Classification.CLEAN: "未发现异常",
        Classification.SUSPICIOUS: "发现可疑项，建议人工复核",
        Classification.COMPROMISED_CANDIDATE: "发现高风险疑似受污染环境",
    }
    worst = report.worst_classification
    print(
        f"最终结论: {_c(_CLS_COLORS[worst])}{_c(_BOLD)}"
        f"{verdicts[worst]}{_c(_RESET)}"
    )
    print(f"HTML 报告已生成: {html_path}")


def format_audit_report_html(report: AuditReport) -> str:
    """Renders the audit report as HTML, sorted by severity."""
    rows = sorted(
        report.findings,
        key=lambda finding: (
            classification_priority(finding.detail.classification),
            finding.label.lower(),
            str(finding.detail.path).lower(),
        ),
    )
    counts = {
        Classification.COMPROMISED_CANDIDATE: 0,
        Classification.SUSPICIOUS: 0,
        Classification.CLEAN: 0,
    }
    for finding in rows:
        counts[finding.detail.classification] += 1

    body_rows = []
    for finding in rows:
        reason_html = "<br>".join(
            escape(reason) for reason in finding.detail.reasons
        ) or "无"
        source_label = {
            EnvKind.REPOSITORY: "项目环境",
            EnvKind.GLOBAL: "全局环境",
        }[finding.kind]
        body_rows.append(
            "<tr>"
            f"<td>{escape(classification_label(finding.detail.classification))}</td>"
            f"<td>{escape(finding.label)}</td>"
            f"<td>{escape(source_label)}</td>"
            f"<td>{escape(str(finding.detail.path))}</td>"
            f"<td>{escape(finding.detail.version or '未知')}</td>"
            f"<td>{reason_html}</td>"
            "</tr>"
        )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <title>litellm 审计报告</title>
  <style>
    body {{ font-family: "Microsoft YaHei", "PingFang SC", sans-serif; margin: 24px; color: #1f2937; }}
    .summary {{ display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 12px; margin: 20px 0; }}
    .card {{ border: 1px solid #d1d5db; border-radius: 10px; padding: 14px; background: #f9fafb; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
    th, td {{ border: 1px solid #d1d5db; padding: 10px; vertical-align: top; text-align: left; }}
    th {{ background: #f3f4f6; }}
  </style>
</head>
<body>
  <h1>litellm 审计报告</h1>
  <div class="summary">
    <div class="card"><strong>高风险</strong><br>{counts[Classification.COMPROMISED_CANDIDATE]}</div>
    <div class="card"><strong>可疑</strong><br>{counts[Classification.SUSPICIOUS]}</div>
    <div class="card"><strong>正常</strong><br>{counts[Classification.CLEAN]}</div>
    <div class="card"><strong>总计</strong><br>{report.total_checked}</div>
  </div>
  <table>
    <thead>
      <tr>
        <th>状态</th>
        <th>标签</th>
        <th>来源</th>
        <th>site-packages</th>
        <th>版本</th>
        <th>原因</th>
      </tr>
    </thead>
    <tbody>
      {''.join(body_rows) or '<tr><td colspan="6">没有可展示的扫描结果。</td></tr>'}
    </tbody>
  </table>
</body>
</html>"""


def write_audit_report_html(report: AuditReport) -> Path:
    """Writes the audit HTML report to the current working directory."""
    output = Path.cwd() / f"litellm-audit-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
    output.write_text(format_audit_report_html(report), encoding="utf-8")
    return output


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Constructs the argument parser."""
    parser = argparse.ArgumentParser(
        prog="audit_litellm",
        description=(
            "扫描项目目录和全局 Python 安装中的 litellm。"
            "在 Windows 上会自动包含 C:\\ws 和 C:\\ws_*。"
            "整个过程只读取文件系统，不执行任何可疑解释器。"
        ),
    )
    parser.add_argument(
        "extra_dirs",
        nargs="*",
        type=Path,
        metavar="DIR",
        help="额外要扫描的目录（默认还会扫描 ~/projects、~/work 和 Windows 的 C:\\ws*）。",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=False,
        help="输出 JSON，而不是中文文本报告。",
    )
    parser.add_argument(
        "--strict-1827",
        action="store_true",
        default=False,
        help="把 1.82.7 也按疑似已被植入后门处理。",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="静默模式，不输出文本，只保留退出码。",
    )
    parser.add_argument(
        "--eve",
        action="store_true",
        default=False,
        help="额外读取 Everything 搜索结果页中的路径，并去重后加入扫描。",
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
    if args.eve:
        try:
            discoveries.append(EverythingDiscovery(prompt_everything_url()))
        except Exception as exc:
            if not args.quiet:
                print(f"读取 Everything 结果失败: {exc}", file=sys.stderr)
            return EXIT_ERROR

    auditor = Auditor(discoveries, strict_1827=args.strict_1827)
    report = auditor.run(
        on_finding=print_realtime_finding
        if (not args.quiet and not args.json_output)
        else None,
    )
    html_path = write_audit_report_html(report)

    if not args.quiet:
        if args.json_output:
            print_json_report(report)
        else:
            print_summary(report, html_path)

    return _EXIT_FOR_CLASSIFICATION.get(
        report.worst_classification, EXIT_ERROR,
    )


if __name__ == "__main__":
    sys.exit(main())
