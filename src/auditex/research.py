from __future__ import annotations

import argparse
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DOCS_DIR = REPO_ROOT / "docs" / "research"


def default_workspace() -> Path:
    libs_root = Path(os.environ.get("BOLYKI_DEV_LIBS", Path.home() / "dev" / "library"))
    return libs_root / "auditex" / "competitors" / "repos"


@dataclass(frozen=True)
class PortSlice:
    title: str
    landing_zone: str
    priority: str
    summary: str


@dataclass(frozen=True)
class RepoTarget:
    owner: str
    repo: str
    stack: str
    license_name: str
    strongest_fit: str
    weak_fit: str
    steal_notes: tuple[str, ...]
    avoid_notes: tuple[str, ...]
    exact_paths: tuple[str, ...]
    immediate_ports: tuple[PortSlice, ...]

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.slug}.git"

    @property
    def local_dir(self) -> str:
        return f"{self.owner}__{self.repo}"


RESEARCH_TARGETS: tuple[RepoTarget, ...] = (
    RepoTarget(
        owner="cisagov",
        repo="ScubaGear",
        stack="PowerShell + OPA/Rego + YAML",
        license_name="CC0-1.0",
        strongest_fit="Waiver model, control mapping, final result envelope, tri-format reports.",
        weak_fit="Too baseline-specific and too PowerShell/OPA-heavy for Auditex core runtime.",
        steal_notes=(
            "YAML risk acceptance with annotation, omission, and exclusion fields.",
            "Single final result envelope with action-plan style fail export.",
            "Control mapping from finding IDs to external frameworks.",
        ),
        avoid_notes=(
            "Do not port the GUI or the OPA runtime into Auditex core.",
            "Do not force baseline-only semantics onto evidence-first collectors.",
        ),
        exact_paths=(
            "PowerShell/ScubaGear/Modules/Orchestrator.psm1",
            "docs/execution/reports.md",
            "docs/configuration/configuration.md",
            "PowerShell/ScubaGear/Modules/ScubaConfigApp/ScubaConfigAppHelpers/ScubaConfigAppImportHelper.psm1",
            "PowerShell/ScubaGear/Sample-Config-Files/scuba_compliance.yaml",
            "docs/misc/tooloutputschema.md",
            "PowerShell/ScubaGear/Sample-Reports/ScubaResults_dfd70a15-3042-4bc9.json",
            "PowerShell/ScubaGear/Sample-Reports/BaselineReports.html",
            "Testing/Functional/Products/TestPlans",
        ),
        immediate_ports=(
            PortSlice(
                title="Policy waiver file",
                landing_zone="Auditex findings and report policy layer",
                priority="now",
                summary="Add annotation, omission, expiration, and per-policy exclusion fields for accepted risk.",
            ),
            PortSlice(
                title="Consolidated result envelope",
                landing_zone="Auditex reports bundle",
                priority="now",
                summary="Emit one stable top-level result file plus fail-only action-plan export.",
            ),
            PortSlice(
                title="Mapped control registry",
                landing_zone="Auditex finding metadata",
                priority="next",
                summary="Attach CIS, NIST, or ATT&CK mapping keys to findings without changing raw evidence.",
            ),
        ),
    ),
    RepoTarget(
        owner="maester365",
        repo="maester",
        stack="PowerShell + Pester + React report UI",
        license_name="MIT",
        strongest_fit="Check-pack discovery, report merge flow, multi-view result UI, notifications.",
        weak_fit="Test harness first, not collector runtime first.",
        steal_notes=(
            "Test inventory and tag discovery can become Auditex rule-pack inventory.",
            "Merged result model supports multi-tenant and historical comparison cleanly.",
            "Report views reuse one result set in markdown, print, excel, and config modes.",
        ),
        avoid_notes=(
            "Do not turn Auditex into a Pester clone.",
            "Do not adopt React report UI before the canonical result schema is stable.",
        ),
        exact_paths=(
            "powershell/public/Get-MtTestInventory.ps1",
            "tests/maester-config.json",
            "powershell/public/core/Get-MtHtmlReport.ps1",
            "powershell/public/core/Import-MtMaesterResult.ps1",
            "powershell/public/core/Merge-MtMaesterResult.ps1",
            "powershell/public/Compare-MtTestResult.ps1",
            "report/src/pages/MarkdownPage.tsx",
            "report/src/pages/ExcelPage.tsx",
            "report/src/pages/PrintPage.tsx",
            "report/src/components/TestResultsTable.jsx",
        ),
        immediate_ports=(
            PortSlice(
                title="Rule-pack inventory",
                landing_zone="Auditex rules namespace",
                priority="now",
                summary="Discover checks by path and tag and export a machine-readable inventory.",
            ),
            PortSlice(
                title="Merged run compare model",
                landing_zone="Auditex diffing and report compare",
                priority="next",
                summary="Load one or many run bundles and compare by tenant and execution time.",
            ),
            PortSlice(
                title="Notification sinks",
                landing_zone="Auditex post-run hooks",
                priority="later",
                summary="Add optional Teams, mail, or Slack summary emitters after the run bundle is final.",
            ),
        ),
    ),
    RepoTarget(
        owner="microsoft",
        repo="EntraExporter",
        stack="PowerShell module + Graph + JSON export",
        license_name="MIT",
        strongest_fit="Scoped export presets, stable ordered JSON, batch request helpers.",
        weak_fit="Export-only. No real findings layer.",
        steal_notes=(
            "Export types map well to Auditex collector presets.",
            "Ordered dictionaries make diffs stable and readable.",
            "Batch helpers can reduce request overhead on Graph-heavy surfaces.",
        ),
        avoid_notes=(
            "Do not adopt export-only framing as the product surface.",
        ),
        exact_paths=(
            "src/Export-Entra.ps1",
            "src/Get-EEFlattenedSchema.ps1",
            "src/Get-EERequiredScopes.ps1",
            "src/internal/ConvertTo-OrderedDictionary.ps1",
            "src/internal/New-GraphBatchRequest.ps1",
            "src/internal/Invoke-GraphBatchRequest.ps1",
        ),
        immediate_ports=(
            PortSlice(
                title="Collector preset exports",
                landing_zone="Auditex profile and preset planning",
                priority="now",
                summary="Add named export sets like config-only, identity-only, or full with include and exclude switches.",
            ),
            PortSlice(
                title="Stable ordered snapshots",
                landing_zone="Auditex normalized and diff outputs",
                priority="now",
                summary="Sort keys and flatten schema output so git diffs stay clean across runs.",
            ),
            PortSlice(
                title="Graph batch helper",
                landing_zone="Auditex transport layer",
                priority="next",
                summary="Add 20-item batch chunking and nextLink handling for safe batched reads.",
            ),
        ),
    ),
    RepoTarget(
        owner="dirkjanm",
        repo="ROADtools",
        stack="Python library + async gatherer + offline DB + plugin CLI",
        license_name="MIT",
        strongest_fit="Thin CLI, offline store, async gatherer, plugin exports.",
        weak_fit="Too much offensive auth and token tradecraft outside Auditex scope.",
        steal_notes=(
            "Core library plus thin CLI split matches Auditex direction well.",
            "Async gather and offline query plugins fit large-tenant evidence work.",
            "Generated metadata model hints at future schema automation.",
        ),
        avoid_notes=(
            "Do not import roadtx flows or offensive token exchange logic.",
            "Do not ship the Angular UI inside Auditex.",
        ),
        exact_paths=(
            "roadrecon/roadtools/roadrecon/main.py",
            "roadrecon/roadtools/roadrecon/gather.py",
            "roadrecon/roadtools/roadrecon/server.py",
            "roadrecon/roadtools/roadrecon/plugins/xlsexport.py",
            "roadrecon/roadtools/roadrecon/plugins/road2timeline.py",
            "roadlib/roadtools/roadlib/dbgen.py",
            "roadlib/roadtools/roadlib/metagen.py",
            "roadlib/roadtools/roadlib/metadef/database.py",
        ),
        immediate_ports=(
            PortSlice(
                title="Offline evidence database",
                landing_zone="Auditex snapshots and diff engine",
                priority="next",
                summary="Persist normalized records into a queryable local store for cross-run analysis.",
            ),
            PortSlice(
                title="Plugin export contract",
                landing_zone="Auditex report and export adapters",
                priority="next",
                summary="Define plugin entrypoints with description, args, and main function for offline exports.",
            ),
            PortSlice(
                title="Thin CLI shell",
                landing_zone="Auditex product CLI",
                priority="later",
                summary="Keep command dispatch thin and move business logic into reusable modules.",
            ),
        ),
    ),
    RepoTarget(
        owner="ThomasKur",
        repo="M365Documentation",
        stack="PowerShell 7 + MSAL + multi-renderer documentation",
        license_name="GPLv3+",
        strongest_fit="Section registry, name translation, one-writer-per-format renderers, backup replay.",
        weak_fit="Word-first docs product, not evidence-first audit runtime.",
        steal_notes=(
            "Section selection maps well to Auditex report sections.",
            "Translation maps solve ugly GUID and ID output.",
            "Renderer-per-format split keeps report logic clean.",
        ),
        avoid_notes=(
            "Do not make DOCX or Word templates part of the critical path.",
        ),
        exact_paths=(
            "PSModule/M365Documentation/Functions/Connect-M365Doc.ps1",
            "PSModule/M365Documentation/Functions/Get-M365Doc.ps1",
            "PSModule/M365Documentation/Functions/Get-M365DocValidSection.ps1",
            "PSModule/M365Documentation/Functions/Optimize-M365Doc.ps1",
            "PSModule/M365Documentation/Functions/Write-M365DocHTML.ps1",
            "PSModule/M365Documentation/Functions/Write-M365DocMD.ps1",
            "PSModule/M365Documentation/Functions/Write-M365DocCsv.ps1",
            "PSModule/M365Documentation/Functions/Write-M365DocJson.ps1",
            "PSModule/M365Documentation/Data/LabelTranslation",
        ),
        immediate_ports=(
            PortSlice(
                title="Friendly-name translation map",
                landing_zone="Auditex normalize and ai_safe layers",
                priority="now",
                summary="Resolve GUIDs, policy IDs, and role IDs into stable human labels with missing-map warnings.",
            ),
            PortSlice(
                title="Section registry",
                landing_zone="Auditex report generation",
                priority="next",
                summary="Let reports select include and exclude sections by stable IDs.",
            ),
            PortSlice(
                title="Format-split writers",
                landing_zone="Auditex report renderers",
                priority="next",
                summary="Keep html, markdown, csv, and json writers isolated behind one report contract.",
            ),
        ),
    ),
    RepoTarget(
        owner="System-Admins",
        repo="m365assessment",
        stack="PowerShell module + HTML zip reports",
        license_name="No obvious license",
        strongest_fit="Operator flow, typed review templates, HTML overview-detail split.",
        weak_fit="Requires broad admin rights and undocumented APIs.",
        steal_notes=(
            "Install, connect, run, disconnect flow is simple and readable.",
            "Typed review templates fit finding authoring well.",
            "HTML overview and per-review drilldown split is useful for operator reports.",
        ),
        avoid_notes=(
            "Do not copy undocumented API dependencies.",
            "Do not require Global Administrator or user_impersonation-level behavior.",
        ),
        exact_paths=(
            "src/SystemAdmins.M365Assessment/public/Install-M365Dependency.ps1",
            "src/SystemAdmins.M365Assessment/public/Connect-M365Tenant.ps1",
            "src/SystemAdmins.M365Assessment/public/Invoke-M365Assessment.ps1",
            "src/SystemAdmins.M365Assessment/public/Disconnect-M365Tenant.ps1",
            "src/SystemAdmins.M365Assessment/private/helper/html/Get-HtmlReport.ps1",
            "src/SystemAdmins.M365Assessment/private/helper/html/Get-HtmlOverviewTable.ps1",
            "src/SystemAdmins.M365Assessment/private/helper/html/Get-HtmlReview.ps1",
            "src/SystemAdmins.M365Assessment/private/class/class.review.ps1",
        ),
        immediate_ports=(
            PortSlice(
                title="Review template registry",
                landing_zone="Auditex findings content",
                priority="next",
                summary="Store one template per finding ID with category, impact, and remediation text.",
            ),
            PortSlice(
                title="Overview-detail HTML split",
                landing_zone="Auditex HTML reporting",
                priority="later",
                summary="Keep one overview table with links into detailed finding sections.",
            ),
        ),
    ),
    RepoTarget(
        owner="CompliantSec",
        repo="M365SAT",
        stack="PowerShell + inspector folders + HTML/CSV reports",
        license_name="MIT",
        strongest_fit="Inspector folder contract, local-vs-remote mode, result schema, packaging.",
        weak_fit="Product and commercial split may drift hard from repo state.",
        steal_notes=(
            "Inspector folders by product, license, and level are easy to reason about.",
            "Local mode, skip login, and skip checks fit Auditex operator UX.",
            "Rich fixed result schema can tighten Auditex findings output.",
        ),
        avoid_notes=(
            "Do not depend on remote inspector zip fetches for core runtime.",
        ),
        exact_paths=(
            "M365SAT.psm1",
            "core/Connect-M365SAT.ps1",
            "core/Get-M365SATChecks.ps1",
            "core/Get-M365SATHTMLReport.ps1",
            "core/Get-M365SATCSVReport.ps1",
            "core/m365connectors",
            "inspectors",
        ),
        immediate_ports=(
            PortSlice(
                title="Finding result schema",
                landing_zone="Auditex findings and reports",
                priority="now",
                summary="Standardize fields like title, expected value, returned value, risk, impact, remediation, and references.",
            ),
            PortSlice(
                title="Inspector folder routing",
                landing_zone="Auditex rule-pack loader",
                priority="next",
                summary="Route checks by product family, license tier, and audit level.",
            ),
            PortSlice(
                title="Operator mode flags",
                landing_zone="Auditex guided-run and report UX",
                priority="later",
                summary="Expose local mode, skip login, skip checks, and report type flags in a controlled way.",
            ),
        ),
    ),
)


def _run_git(args: list[str]) -> None:
    subprocess.run(args, check=True)


def _git_output(args: list[str]) -> str:
    return subprocess.check_output(args, text=True).strip()


def _ensure_repo_checkout(spec: RepoTarget, workspace: Path) -> dict[str, str]:
    dest = workspace / spec.local_dir
    if dest.exists():
        _run_git(["git", "-C", str(dest), "fetch", "--all", "--tags"])
        action = "fetched"
    else:
        _run_git(["git", "clone", spec.clone_url, str(dest)])
        action = "cloned"
    head = _git_output(["git", "-C", str(dest), "rev-parse", "HEAD"])
    return {"repo": spec.slug, "path": str(dest), "action": action, "head": head}


def sync_competitor_repos(
    workspace: Path | None = None,
    targets: Iterable[RepoTarget] | None = None,
) -> dict[str, object]:
    workspace = Path(workspace) if workspace is not None else default_workspace()
    workspace.mkdir(parents=True, exist_ok=True)
    selected = tuple(targets or RESEARCH_TARGETS)
    results = [_ensure_repo_checkout(spec, workspace) for spec in selected]
    return {"workspace": str(workspace), "repos": results}


def _repo_head(spec: RepoTarget, workspace: Path) -> str | None:
    checkout = workspace / spec.local_dir
    if not checkout.exists():
        return None
    try:
        return _git_output(["git", "-C", str(checkout), "rev-parse", "HEAD"])
    except subprocess.CalledProcessError:
        return None


def _matched_paths(spec: RepoTarget, workspace: Path) -> list[str]:
    checkout = workspace / spec.local_dir
    matches: list[str] = []
    for rel_path in spec.exact_paths:
        if (checkout / rel_path).exists():
            matches.append(rel_path)
    return matches


def _render_index(workspace: Path, docs_dir: Path, pack: dict[str, object]) -> str:
    targets = pack["targets"]
    lines = [
        "# Competitor Research Pack",
        "",
        "Auditex keeps the cloned upstream repos outside git and keeps the analysis pack in-tree.",
        "",
        f"- Local mirror root: `{workspace}`",
        f"- Docs root: `{docs_dir}`",
        "",
        "Refresh commands:",
        "",
        "```bash",
        "auditex research competitors sync",
        "auditex research competitors pack",
        "```",
        "",
        "Target repos:",
        "",
    ]
    for target in targets:
        lines.append(f"- `{target['repo']}` at `{target['head'] or 'not mirrored yet'}`")
    lines.extend(
        [
            "",
            "Pack contents:",
            "",
            "- `competitor-matrix.md`: one-row matrix per upstream.",
            "- `repo-cards.md`: exact paths and direct port slices per upstream.",
            "- `steal-backlog.md`: ranked `now`, `next`, `later`, and `avoid` backlog.",
        ]
    )
    return "\n".join(lines) + "\n"


def _render_matrix(pack: dict[str, object]) -> str:
    lines = [
        "# Competitor Matrix",
        "",
        "| Repo | Stack | Strongest steal | Weak fit | First port |",
        "| --- | --- | --- | --- | --- |",
    ]
    for target in pack["targets"]:
        first_port = target["ports"][0]["title"] if target["ports"] else "-"
        lines.append(
            f"| `{target['repo']}` | {target['stack']} | {target['strongest_fit']} | {target['weak_fit']} | {first_port} |"
        )
    return "\n".join(lines) + "\n"


def _render_repo_cards(pack: dict[str, object]) -> str:
    lines = ["# Repo Cards", ""]
    for target in pack["targets"]:
        lines.extend(
            [
                f"## {target['repo']}",
                "",
                f"- Head: `{target['head'] or 'not mirrored yet'}`",
                f"- Stack: {target['stack']}",
                f"- License: {target['license']}",
                f"- Best fit: {target['strongest_fit']}",
                f"- Weak fit: {target['weak_fit']}",
                "",
                "Worth stealing:",
                "",
            ]
        )
        for item in target["steal_notes"]:
            lines.append(f"- {item}")
        lines.extend(["", "Avoid:", ""])
        for item in target["avoid_notes"]:
            lines.append(f"- {item}")
        lines.extend(["", "Exact upstream paths:", ""])
        for path in target["matched_paths"]:
            lines.append(f"- `{path}`")
        if not target["matched_paths"]:
            lines.append("- No mirrored path matches found yet.")
        lines.extend(["", "Direct port slices:", ""])
        for port in target["ports"]:
            lines.append(
                f"- `{port['priority']}`: {port['title']} -> {port['landing_zone']}. {port['summary']}"
            )
        lines.append("")
    return "\n".join(lines)


def _render_backlog(pack: dict[str, object]) -> str:
    priorities = ("now", "next", "later")
    groups: dict[str, list[tuple[str, dict[str, str]]]] = {priority: [] for priority in priorities}
    for target in pack["targets"]:
        for port in target["ports"]:
            if port["priority"] in groups:
                groups[port["priority"]].append((target["repo"], port))

    lines = [
        "# Steal Backlog",
        "",
        "## Now",
        "",
    ]
    for repo, port in groups["now"]:
        lines.append(f"- `{repo}`: {port['title']} -> {port['landing_zone']}. {port['summary']}")
    lines.extend(["", "## Next", ""])
    for repo, port in groups["next"]:
        lines.append(f"- `{repo}`: {port['title']} -> {port['landing_zone']}. {port['summary']}")
    lines.extend(["", "## Later", ""])
    for repo, port in groups["later"]:
        lines.append(f"- `{repo}`: {port['title']} -> {port['landing_zone']}. {port['summary']}")
    lines.extend(
        [
            "",
            "## Avoid",
            "",
            "- `ROADtools`: no roadtx or offensive token flows.",
            "- `ScubaGear`: no GUI and no OPA runtime in Auditex core.",
            "- `m365assessment`: no undocumented API dependency and no admin-only assumption.",
            "- `M365Documentation`: no DOCX-heavy path in the critical audit flow.",
        ]
    )
    return "\n".join(lines) + "\n"


def build_analysis_pack(
    workspace: Path | None = None,
    docs_dir: Path | None = None,
    targets: Iterable[RepoTarget] | None = None,
) -> dict[str, object]:
    workspace = Path(workspace) if workspace is not None else default_workspace()
    docs_dir = Path(docs_dir) if docs_dir is not None else DEFAULT_DOCS_DIR
    selected = tuple(targets or RESEARCH_TARGETS)
    docs_dir.mkdir(parents=True, exist_ok=True)

    pack_targets: list[dict[str, object]] = []
    for spec in selected:
        pack_targets.append(
            {
                "repo": spec.slug,
                "stack": spec.stack,
                "license": spec.license_name,
                "head": _repo_head(spec, workspace),
                "strongest_fit": spec.strongest_fit,
                "weak_fit": spec.weak_fit,
                "steal_notes": list(spec.steal_notes),
                "avoid_notes": list(spec.avoid_notes),
                "matched_paths": _matched_paths(spec, workspace),
                "ports": [
                    {
                        "title": port.title,
                        "landing_zone": port.landing_zone,
                        "priority": port.priority,
                        "summary": port.summary,
                    }
                    for port in spec.immediate_ports
                ],
            }
        )

    pack = {"workspace": str(workspace), "docs_dir": str(docs_dir), "targets": pack_targets}
    documents = {
        "README.md": _render_index(workspace, docs_dir, pack),
        "competitor-matrix.md": _render_matrix(pack),
        "repo-cards.md": _render_repo_cards(pack),
        "steal-backlog.md": _render_backlog(pack),
    }
    for name, content in documents.items():
        (docs_dir / name).write_text(content, encoding="utf-8")
    return {"workspace": str(workspace), "docs_dir": str(docs_dir), "documents": sorted(documents)}


def _build_competitors_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auditex research competitors",
        description="Mirror and analyze competitor repos outside the tracked source tree.",
    )
    subparsers = parser.add_subparsers(dest="research_competitors_command", required=True)
    for name in ("sync", "pack", "all"):
        command = subparsers.add_parser(name)
        command.add_argument("--workspace", default=None, help="Override the local mirror root.")
        command.add_argument("--docs-dir", default=None, help="Override the analysis pack directory.")
    return parser


def run_research_command(argv: list[str]) -> int:
    if not argv or argv[0] != "competitors":
        print("usage: auditex research competitors <sync|pack|all>", file=os.sys.stderr)
        return 2
    parser = _build_competitors_parser()
    args = parser.parse_args(argv)
    workspace = Path(args.workspace) if args.workspace else None
    docs_dir = Path(args.docs_dir) if args.docs_dir else None
    if args.research_competitors_command == "sync":
        print(json.dumps(sync_competitor_repos(workspace=workspace), indent=2))
        return 0
    if args.research_competitors_command == "pack":
        print(json.dumps(build_analysis_pack(workspace=workspace, docs_dir=docs_dir), indent=2))
        return 0
    if args.research_competitors_command == "all":
        payload = {
            "sync": sync_competitor_repos(workspace=workspace),
            "pack": build_analysis_pack(workspace=workspace, docs_dir=docs_dir),
        }
        print(json.dumps(payload, indent=2))
        return 0
    return 2
