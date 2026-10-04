"""Match settings in config.yaml, and module findings that follow a renamed file (#85)."""

from __future__ import annotations

import subprocess

import pytest

from fwlens.baseline import Breach, classify_against_baseline
from fwlens.config import ConfigError, MatchConfig, load_config
from fwlens.identity import make_key, match_findings
from fwlens.pr_check import git_rename_hints
from tests.test_identity import FUNC, base_of, fn_breach

EDITED = FUNC.replace("total -= 1;", "total -= 1;\n            total ^= 3;\n            total += 7;")


def module_breach(file, value=0.5):
    return Breach(make_key(file, None, "main_sequence_distance"), "module", file,
                  "main_sequence_distance", value, 0.3)


def _cfg(tmp_path, body):
    f = tmp_path / "config.yaml"
    f.write_text("project:\n  source_dir: .\n" + body)
    return load_config(f)


def test_match_section_is_read_and_defaults_hold(tmp_path):
    assert _cfg(tmp_path, "").match == MatchConfig(0.85, True)
    cfg = _cfg(tmp_path, "match:\n  similarity: 0.7\n  report_uncertain: false\n")
    assert cfg.match == MatchConfig(0.7, False)


@pytest.mark.parametrize("value", ["0", "1.5", "high", "-0.1"])
def test_bad_similarity_is_rejected(tmp_path, value):
    with pytest.raises(ConfigError, match="match.similarity"):
        _cfg(tmp_path, f"match:\n  similarity: {value}\n")


def test_similarity_threshold_changes_the_outcome():
    base = base_of(fn_breach(file="src/a.c"))
    cur = [fn_breach(file="src/b.c", source=EDITED)]
    strict = match_findings(cur, base, similarity=0.99, edit_containment=1.1, containment=1.1)
    loose = match_findings(cur, base, similarity=0.3)
    assert strict.matches[0].status == "new"
    assert loose.matches[0].status == "uncertain"


def test_report_uncertain_false_turns_loose_matches_into_new_and_resolved():
    base = base_of(fn_breach(file="src/a.c"))
    cur = [fn_breach(file="src/a.c", name="process", source=EDITED, line=40)]
    assert classify_against_baseline(cur, {e["id"]: e for e in base}).matches[0].status in ("unchanged", "uncertain")
    # a renamed-and-edited function can only be matched loosely
    cur = [fn_breach(file="src/a.c", name="renamed", source=EDITED)]
    base_map = {e["id"]: e for e in base}
    assert classify_against_baseline(cur, base_map).matches[0].status == "uncertain"
    off = classify_against_baseline(cur, base_map, match=MatchConfig(report_uncertain=False))
    assert off.matches[0].status == "new" and len(off.resolved) == 1


def test_module_breach_follows_a_file_inferred_from_moved_functions():
    base = base_of(fn_breach(file="src/old.c"), module_breach("src/old.c"))
    cur = [fn_breach(file="src/new.c"), module_breach("src/new.c")]
    res = match_findings(cur, base)
    module = next(m for m in res.matches if m.current.kind == "module")
    assert module.status == "moved" and module.tier == "rename" and "src/old.c" in module.note
    assert res.resolved == []


def test_module_breach_is_new_without_any_rename_evidence():
    res = match_findings([module_breach("src/new.c")], base_of(module_breach("src/old.c")))
    assert res.matches[0].status == "new"


def test_explicit_rename_hint_matches_a_module_with_no_functions():
    res = match_findings([module_breach("src/new.c")], base_of(module_breach("src/old.c")),
                         renames={"src/old.c": "src/new.c"})
    assert res.matches[0].status == "moved"


def test_git_rename_hints_report_renames_only(tmp_path):
    def git(*args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
                       cwd=tmp_path, check=True, capture_output=True)
    git("init", "-b", "main")
    (tmp_path / "old.c").write_text(FUNC * 3)
    (tmp_path / "keep.c").write_text("int k;\n")
    git("add", "-A")
    git("commit", "-m", "base")
    git("checkout", "-b", "feature")
    git("mv", "old.c", "new.c")
    (tmp_path / "keep.c").write_text("int k2;\n")
    git("add", "-A")
    git("commit", "-m", "rename")
    assert git_rename_hints(tmp_path, "main") == {"old.c": "new.c"}
    assert git_rename_hints(tmp_path, "no-such-ref") == {}
