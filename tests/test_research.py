from __future__ import annotations

import json
from pathlib import Path

from auditex import cli as auditex_cli
from auditex import research


def test_sync_competitor_repos_clones_missing_repo(tmp_path: Path, monkeypatch) -> None:
    calls: list[list[str]] = []

    def _fake_run_git(args: list[str]) -> None:
        calls.append(args)
        if args[:2] == ["git", "clone"]:
            Path(args[-1]).mkdir(parents=True)

    monkeypatch.setattr(research, "_run_git", _fake_run_git)
    monkeypatch.setattr(research, "_git_output", lambda _args: "deadbeef")

    result = research.sync_competitor_repos(workspace=tmp_path, targets=[research.RESEARCH_TARGETS[0]])

    assert result["repos"][0]["action"] == "cloned"
    assert calls[0][:2] == ["git", "clone"]


def test_sync_competitor_repos_fetches_existing_repo(tmp_path: Path, monkeypatch) -> None:
    checkout = tmp_path / research.RESEARCH_TARGETS[0].local_dir
    checkout.mkdir(parents=True)
    calls: list[list[str]] = []

    monkeypatch.setattr(research, "_run_git", lambda args: calls.append(args))
    monkeypatch.setattr(research, "_git_output", lambda _args: "feedface")

    result = research.sync_competitor_repos(workspace=tmp_path, targets=[research.RESEARCH_TARGETS[0]])

    assert result["repos"][0]["action"] == "fetched"
    assert calls[0][:4] == ["git", "-C", str(checkout), "fetch"]


def test_build_analysis_pack_writes_docs(tmp_path: Path, monkeypatch) -> None:
    workspace = tmp_path / "repos"
    docs_dir = tmp_path / "docs"
    checkout = workspace / research.RESEARCH_TARGETS[0].local_dir
    matched = checkout / research.RESEARCH_TARGETS[0].exact_paths[0]
    matched.parent.mkdir(parents=True, exist_ok=True)
    matched.write_text("x", encoding="utf-8")

    monkeypatch.setattr(research, "_git_output", lambda _args: "cafebabe")

    result = research.build_analysis_pack(
        workspace=workspace,
        docs_dir=docs_dir,
        targets=[research.RESEARCH_TARGETS[0]],
    )

    assert sorted(result["documents"]) == [
        "README.md",
        "competitor-matrix.md",
        "repo-cards.md",
        "steal-backlog.md",
    ]
    assert "ScubaGear" in (docs_dir / "competitor-matrix.md").read_text(encoding="utf-8")
    assert "deadbeef" not in (docs_dir / "repo-cards.md").read_text(encoding="utf-8")
    assert "cafebabe" in (docs_dir / "repo-cards.md").read_text(encoding="utf-8")


def test_auditex_research_all_dispatches(monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        "auditex.cli.run_research_command",
        lambda argv: print(json.dumps({"argv": argv})) or 0,
    )

    rc = auditex_cli.main(["research", "competitors", "all"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["argv"] == ["competitors", "all"]
