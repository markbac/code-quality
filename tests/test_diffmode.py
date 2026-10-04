"""--changed-since: findings limited to changed code, totals intact, shallow fallback (#73)."""

import subprocess

from click.testing import CliRunner

import main as fwlens_main
from fwlens import diffmode


def branchy(name: str, n: int = 20) -> str:
    body = "".join(f"  if (a == {i}) {{ return {i}; }}\n" for i in range(n))
    return f"int {name}(int a) {{\n{body}  return 0;\n}}\n"


def git(root, *args):
    subprocess.run(["git", "-C", str(root), "-c", "user.name=T", "-c", "user.email=t@x", "-c", "commit.gpgsign=false",
                    *args], check=True, capture_output=True)


def make_repo(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "old.c").write_text(branchy("old_fn"))
    (tmp_path / "src" / "new.c").write_text("int small(void) { return 1; }\n")
    (tmp_path / "config.yaml").write_text("project:\n  source_dir: src\ntool:\n  target: native\n")
    git(tmp_path, "init", "-q", "-b", "main")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    git(tmp_path, "checkout", "-q", "-b", "feature")
    (tmp_path / "src" / "new.c").write_text(branchy("new_fn"))
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "change")
    return tmp_path


def analyze(monkeypatch, root, *args):
    monkeypatch.chdir(root)
    return CliRunner().invoke(fwlens_main.cli, ["analyze", "--config", str(root / "config.yaml"),
                                                "--findings-json", str(root / "f.json"), *args])


def findings(root):
    import json
    return json.loads((root / "f.json").read_text())


def files_in(root):
    data = findings(root)
    items = data.get("findings", data) if isinstance(data, dict) else data
    return {i["file"] for i in items}


def test_only_changed_files_are_reported(tmp_path, monkeypatch):
    root = make_repo(tmp_path)
    full = analyze(monkeypatch, root)
    assert full.exit_code == 0, full.output
    assert files_in(root) == {"src/old.c", "src/new.c"}

    diff = analyze(monkeypatch, root, "--changed-since", "main")
    assert diff.exit_code == 0, diff.output
    assert files_in(root) == {"src/new.c"}
    assert "Diff mode vs" in diff.output


def test_environment_base_is_detected(monkeypatch):
    monkeypatch.delenv("CI_MERGE_REQUEST_DIFF_BASE_SHA", raising=False)
    monkeypatch.setenv("GITHUB_BASE_REF", "main")
    assert diffmode.detect_base(None) == "origin/main"
    monkeypatch.setenv("CI_MERGE_REQUEST_DIFF_BASE_SHA", "abc123")
    assert diffmode.detect_base(None) == "abc123"
    assert diffmode.detect_base("dev") == "dev"


def test_function_scope_needs_an_overlapping_hunk(tmp_path):
    root = make_repo(tmp_path)
    (root / "src" / "new.c").write_text(branchy("new_fn") + branchy("untouched_fn"))
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "add second function")
    changes, problem = diffmode.changed_lines(root, "main")
    assert problem is None and "src/new.c" in changes.files
    from fwlens.baseline import Breach
    a = Breach("a", "function", "src/new.c", "cyclomatic_complexity", 21, 15, line=1, function="new_fn")
    b = Breach("b", "function", "src/new.c", "cyclomatic_complexity", 21, 15, line=24, function="untouched_fn")
    # both functions are new in this diff, so both overlap; shrink the hunk to the second function
    changes.files["src/new.c"] = [(25, 26)]
    kept = diffmode.filter_breaches([a, b], changes, "function", {("src/new.c", "new_fn"): 23, ("src/new.c", "untouched_fn"): 23})
    assert [x.id for x in kept] == ["b"]


def test_missing_base_falls_back_with_a_message(tmp_path, monkeypatch):
    root = make_repo(tmp_path)
    result = analyze(monkeypatch, root, "--changed-since", "no-such-ref")
    assert result.exit_code == 0, result.output
    assert "cannot find a merge base" in result.output
    assert files_in(root) == {"src/old.c", "src/new.c"}


def test_shallow_clone_without_base_explains_how_to_fix(tmp_path):
    (tmp_path / "origin").mkdir()
    origin = make_repo(tmp_path / "origin")
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", "feature", "--single-branch",
                    origin.resolve().as_uri(), str(clone)], check=True, capture_output=True)
    changes, problem = diffmode.changed_lines(clone, "origin/main")
    assert changes is None
    assert "shallow" in problem and "fetch" in problem


def test_update_baseline_is_refused_in_diff_mode(tmp_path, monkeypatch):
    root = make_repo(tmp_path)
    result = analyze(monkeypatch, root, "--changed-since", "main", "--baseline", str(root / "b.json"),
                     "--update-baseline", "--accept-all")
    assert result.exit_code == 2
