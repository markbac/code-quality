"""Git history: one pass, exact file names, mailmap, shallow clones, visible failures (#65)."""

import subprocess
from pathlib import Path

import pytest

from fwlens import git_history as gh


@pytest.fixture(autouse=True)
def _fresh_state():
    gh.reset_history_state()
    yield
    gh.reset_history_state()


def git(root: Path, *args: str, env=None) -> None:
    subprocess.run(["git", "-C", str(root), "-c", "commit.gpgsign=false", *args], check=True,
                   capture_output=True, env=env)


def commit(root: Path, message: str, author: str = "Alice <alice@example.com>") -> None:
    name, _, email = author.partition(" <")
    git(root, "add", "-A")
    git(root, "-c", f"user.name={name}", "-c", f"user.email={email.rstrip('>')}", "commit", "-q", "-m", message)


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q")
    return root


def test_names_are_preserved_exactly(repo):
    names = ["café ü.c", " lead.c", '"quoted".c', "trail .c"]
    for n in names:
        (repo / n).write_text("x")
    commit(repo, "add files")

    (commit_,) = gh.load_history(repo, None)
    assert {p.name for p in commit_.files} == set(names)
    assert gh._commit_counts(repo, None)[(repo / " lead.c").resolve()] == 1


def test_mailmap_merges_author_identities(repo):
    (repo / "a.c").write_text("1")
    commit(repo, "one", "Old Name <old@example.com>")
    (repo / "a.c").write_text("2")
    commit(repo, "two", "New Name <new@example.com>")
    (repo / ".mailmap").write_text("New Name <new@example.com> <old@example.com>\n")

    assert {c.author for c in gh.load_history(repo, None)} == {"New Name"}


def test_history_is_walked_once(repo, monkeypatch):
    (repo / "a.c").write_text("1")
    commit(repo, "one")
    calls = []
    real = gh._git

    def counting(root, args, timeout, what):
        calls.append(args[0])
        return real(root, args, timeout, what)

    monkeypatch.setattr(gh, "_git", counting)
    for fn in (gh._commit_counts, gh._commits_file_lists, gh._commits_with_dates, gh._commits_with_authors):
        fn(repo, None)
    assert calls.count("log") == 1


def test_shallow_clone_is_detected_and_reported(repo, tmp_path, capsys):
    for i in range(3):
        (repo / "a.c").write_text(str(i))
        commit(repo, f"c{i}")
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--depth", "1", repo.resolve().as_uri(), str(clone)], check=True,
                   capture_output=True)

    assert gh._is_shallow_repo(clone) is True
    assert gh._is_shallow_repo(repo) is False
    assert len(gh.load_history(clone, None)) == 1
    assert any("shallow" in w for w in gh.history_warnings())


def test_shallow_detected_in_linked_worktree(repo, tmp_path):
    (repo / "a.c").write_text("1")
    commit(repo, "c")
    linked = tmp_path / "linked"
    git(repo, "worktree", "add", "-q", str(linked))
    assert (linked / ".git").is_file()  # the old `.git/shallow` check cannot work here
    assert gh._is_shallow_repo(linked) is False


def test_git_failure_is_a_visible_warning(tmp_path):
    assert gh._git(tmp_path, ["log"], 10, "git log") is None
    assert any("git log failed" in w for w in gh.history_warnings())


def test_timeout_is_a_visible_warning(repo, monkeypatch):
    (repo / "a.c").write_text("1")
    commit(repo, "c")

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="git", timeout=1)

    monkeypatch.setattr(gh.subprocess, "run", boom)
    assert gh.load_history(repo, None) == []
    assert any("timed out" in w for w in gh.history_warnings())


def test_solo_commits_count_towards_coupling_denominator(repo):
    from types import SimpleNamespace
    from fwlens.model.project import ProjectModel
    import cparse

    for i in range(3):  # a.c and b.c always change together
        (repo / "a.c").write_text(f"a{i}")
        (repo / "b.c").write_text(f"b{i}")
        commit(repo, f"both {i}")
    for i in range(3):  # a.c also changes alone
        (repo / "a.c").write_text(f"solo{i}")
        commit(repo, f"solo {i}")

    config = cparse.make_config(repo)
    model = ProjectModel(ewp_path=repo, configuration="Debug")
    model.modules = [SimpleNamespace(path=repo / "a.c", first_party=True), SimpleNamespace(path=repo / "b.c", first_party=True)]
    model.first_party_modules = lambda: model.modules
    gh.compute_change_coupling(model, config)

    (pair,) = model.change_coupling
    assert (pair.co_changes, pair.changes_a, pair.changes_b) == (3, 6, 3)
    assert pair.coupling == round(3 / 6, 3)


def test_fix_commit_names_are_preserved(repo):
    from fwlens.reliability import fetch_fix_commits

    (repo / " spécial.c").write_text("1")
    commit(repo, "fix: crash in parser")
    (commit_,) = fetch_fix_commits(repo, None, ["fix"])
    assert [p.name for p in commit_["files"]] == [" spécial.c"]
