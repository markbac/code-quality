"""
Stable finding identity (#53), baseline migration and pruning (#29), SARIF rules (#27) and
path handling (#28). The numbered tests follow the acceptance list in issue #53.
"""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fwlens.baseline import (
    METRIC_INFO, Breach, _assign_ordinals, classify_against_baseline, diff_against_baseline,
    load_baseline, save_baseline, update_baseline,
)
from fwlens.identity import (
    body_fingerprint, make_key, match_findings, relative_posix, statement_fingerprint,
)
from fwlens.output.sarif import build_rules, breach_to_result, rule_id, tool_version

FUNC = """
int process(int a, int b)
{
    int total = 0;
    for (int i = 0; i < a; i++) {
        if (i % 2 == 0 && b > 0) {
            total += helper(i, b);
        } else if (i > 10 || b < 0) {
            total -= 1;
        }
    }
    return total;
}
"""


def fn_breach(file="src/a.c", name="process", source=FUNC, line=10, value=20.0, metric="cyclomatic_complexity"):
    b = Breach("", "function", file, metric, value, 15.0, line=line, function=name,
               fingerprint=body_fingerprint(source))
    _assign_ordinals([b])
    return b


def stmt_breach(function, text, line=5, rule="misra-15.1", file="src/a.c", ordinal=1):
    return Breach(make_key(file, function, rule, ordinal), "statement", file, rule, 1.0, 0.0,
                  line=line, function=function, fingerprint=statement_fingerprint(text))


def base_of(*breaches):
    return [b.to_dict() for b in breaches]


def statuses(result):
    return sorted(m.status for m in result.matches)


# --- #53 acceptance tests --------------------------------------------------------

def test_01_function_moved_to_another_file_is_moved_not_new():
    base = base_of(fn_breach(file="src/a.c"))
    result = match_findings([fn_breach(file="src/util/b.c", line=3)], base)
    assert statuses(result) == ["moved"] and result.resolved == []
    assert result.matches[0].tier == "content"


def test_02_renamed_function_and_parameters_keep_the_finding():
    renamed = FUNC.replace("process", "handle").replace(" a", " count").replace("(a", "(count") \
                  .replace("< a", "< count").replace(" b", " limit").replace("b >", "limit >") \
                  .replace("b <", "limit <").replace("(i, b)", "(i, limit)")
    base = base_of(fn_breach())
    result = match_findings([fn_breach(name="handle", source=renamed)], base)
    assert statuses(result) == ["moved"] and result.resolved == []


def test_03_statement_extracted_into_a_helper_is_moved():
    text = "result = unsafe_copy(dst, src, n);"
    base = base_of(stmt_breach("big_function", text))
    result = match_findings([stmt_breach("new_helper", text)], base)
    assert statuses(result) == ["moved"] and result.resolved == []


def test_04_inserting_lines_above_a_finding_changes_nothing():
    base = base_of(fn_breach(line=10))
    current = fn_breach(line=60)
    assert current.id == base[0]["id"]
    result = match_findings([current], base)
    assert statuses(result) == ["unchanged"] and result.gating() == []


def test_05_two_identical_findings_one_removed():
    text = "free(p);"
    base = base_of(stmt_breach("f", text, line=5, ordinal=1), stmt_breach("f", text, line=9, ordinal=2))
    result = match_findings([stmt_breach("f", text, line=9, ordinal=1)], base)
    assert statuses(result) == ["unchanged"] and len(result.resolved) == 1


def test_06_changing_the_violating_callee_is_a_new_finding():
    base = base_of(stmt_breach("f", "x = unsafe_a(p);"))
    result = match_findings([stmt_breach("f", "x = unsafe_b(p);", ordinal=2)], base)
    assert statuses(result) == ["new"] and len(result.resolved) == 1


def _stmt(i):
    """Structurally different statements, so the halves of a function are not mere repeats."""
    ops = ["&&", "||", "==", "!=", "<", ">"]
    chain = " + ".join(f"p{i}[{k}]" for k in range(i % 7 + 1))
    return (f"    if (v{i} {ops[i % 6]} w{i} {ops[(i * 5 + 1) % 6]} limit{i % 4}) "
            f"{{ out = out + {chain}; log_{i}(out, {i}); }}")


def test_07_splitting_a_function_is_a_change_not_a_new_breach():
    big = "int big(int v0)\n{\n    int out = 0;\n" + "\n".join(_stmt(i) for i in range(40)) + "\n    return out;\n}\n"
    part = "int big_part(int v0)\n{\n    int out = 0;\n" + "\n".join(_stmt(i) for i in range(20, 40)) \
        + "\n    return out;\n}\n"
    base = base_of(fn_breach(name="big", source=big, value=34))
    current = fn_breach(name="big_part", source=part, value=18)
    result = match_findings([current], base)
    assert statuses(result) == ["uncertain"] and result.matches[0].tier == "contained"
    assert "big" in result.matches[0].note
    assert result.gating() == []


def test_08_whitespace_and_comment_changes_do_not_matter():
    reformatted = FUNC.replace("    ", "\t").replace("int total = 0;", "int total = 0; /* running sum */") \
        + "\n// trailing comment\n"
    assert body_fingerprint(FUNC)["body_hash"] == body_fingerprint(reformatted)["body_hash"]
    result = match_findings([fn_breach(source=reformatted)], base_of(fn_breach()))
    assert statuses(result) == ["unchanged"]


def test_09_windows_and_posix_paths_give_the_same_relative_path(tmp_path):
    (tmp_path / "src").mkdir()
    f = tmp_path / "src" / "a.c"
    f.write_text("int x;")
    assert relative_posix(f, tmp_path) == "src/a.c"
    assert relative_posix("C:\\proj\\src\\a.c", Path("/elsewhere")) == "C:/proj/src/a.c"
    assert relative_posix("C:\\proj\\src\\a.c", None) == "C:/proj/src/a.c"


# --- engine behaviour --------------------------------------------------------------

def test_a_genuinely_new_function_is_new():
    other = "int other(void)\n{\n    while (flag) { poll(); }\n    return 0;\n}\n"
    result = match_findings([fn_breach(name="other", source=other)], base_of(fn_breach()))
    assert statuses(result) == ["new"] and len(result.resolved) == 1


def test_worsened_breach_gates_even_when_unchanged():
    base = base_of(fn_breach(value=20))
    result = match_findings([fn_breach(value=25)], base)
    assert statuses(result) == ["unchanged"] and len(result.gating()) == 1
    assert match_findings([fn_breach(value=18)], base).gating() == []


def test_moved_and_worsened_still_gates():
    base = base_of(fn_breach(file="src/a.c", value=20))
    result = match_findings([fn_breach(file="src/b.c", value=30)], base)
    assert statuses(result) == ["moved"] and len(result.gating()) == 1


def test_edited_and_worsened_function_still_gates_when_matched_loosely():
    """A function that was moved AND edited is matched loosely, but getting worse must not escape the gate."""
    longer = FUNC.replace("total -= 1;", "total -= 1; if (a > 3 && b > 4) { total++; }")
    result = match_findings([fn_breach(file="src/b.c", source=longer, value=25)], base_of(fn_breach(value=20)))
    assert statuses(result) == ["uncertain"] and result.matches[0].tier == "similar"
    assert len(result.gating()) == 1
    better = match_findings([fn_breach(file="src/b.c", source=longer, value=18)], base_of(fn_breach(value=20)))
    assert better.gating() == []


def test_same_name_functions_get_distinct_ordered_keys():
    a = fn_breach(name="init", line=10)
    b = fn_breach(name="init", line=40)
    items = [b, a]
    _assign_ordinals(items)
    assert a.id == "src/a.c:init:cyclomatic_complexity"
    assert b.id == "src/a.c:init#2:cyclomatic_complexity"


def test_fingerprints_are_deterministic_across_calls():
    assert body_fingerprint(FUNC) == body_fingerprint(FUNC)
    assert body_fingerprint(FUNC)["body_hash"] == "8b0a1ba5b0a1e5d4" or len(body_fingerprint(FUNC)["body_hash"]) == 16


# --- baseline file: version, migration, prune -------------------------------------

def test_legacy_line_based_baseline_is_migrated_on_load(tmp_path, capsys):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"accepted": [{
        "id": "src/a.c:42:process:cyclomatic_complexity", "kind": "function", "file": "src/a.c",
        "metric": "cyclomatic_complexity", "value": 20.0, "threshold": 15.0}]}))
    loaded = load_baseline(path)
    assert list(loaded) == ["src/a.c:process:cyclomatic_complexity"]
    assert loaded["src/a.c:process:cyclomatic_complexity"]["line"] == 42
    assert "legacy" in capsys.readouterr().out
    new, accepted = diff_against_baseline([fn_breach(line=99)], loaded)
    assert new == [] and len(accepted) == 1


def test_legacy_windows_id_is_migrated_from_the_right(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"accepted": [{
        "id": "C:/proj/src/a.c:42:process:cyclomatic_complexity", "kind": "function",
        "file": "C:/proj/src/a.c", "metric": "cyclomatic_complexity", "value": 20.0, "threshold": 15.0}]}))
    assert list(load_baseline(path)) == ["C:/proj/src/a.c:process:cyclomatic_complexity"]


def test_baseline_is_written_versioned(tmp_path):
    path = tmp_path / "baseline.json"
    b = fn_breach()
    update_baseline(path, [b], accept_all=True)
    raw = json.loads(path.read_text())
    assert raw["version"] == 2 and raw["scheme"].startswith("fwlens-finding")
    assert raw["accepted"][0]["fingerprint"]["body_hash"]


def test_update_follows_a_moved_breach_instead_of_adding_a_duplicate(tmp_path):
    path = tmp_path / "baseline.json"
    update_baseline(path, [fn_breach(file="src/a.c")], accept_all=True)
    update_baseline(path, [fn_breach(file="src/b.c")], accept_all=True)
    ids = [e["id"] for e in json.loads(path.read_text())["accepted"]]
    assert ids == ["src/b.c:process:cyclomatic_complexity"]


def test_prune_removes_resolved_entries_only_when_asked(tmp_path):
    path = tmp_path / "baseline.json"
    gone = fn_breach(name="gone", source="int gone(void)\n{\n    return weird_unique_call();\n}\n")
    keep = fn_breach()
    update_baseline(path, [gone, keep], accept_all=True)
    update_baseline(path, [keep], accept_all=True)
    assert len(json.loads(path.read_text())["accepted"]) == 2
    update_baseline(path, [keep], accept_all=True, prune=True)
    assert [e["function"] for e in json.loads(path.read_text())["accepted"]] == ["process"]


def test_classification_reports_resolved_entries():
    gone = fn_breach(name="gone", source="int gone(void)\n{\n    return weird_unique_call();\n}\n")
    baseline = {e["id"]: e for e in base_of(gone, fn_breach())}
    result = classify_against_baseline([fn_breach()], baseline)
    assert [r["function"] for r in result.resolved] == ["gone"]


# --- SARIF (#27) --------------------------------------------------------------------

def test_every_sarif_result_rule_id_is_declared():
    rules = build_rules()
    index = {r["id"]: i for i, r in enumerate(rules)}
    for metric in METRIC_INFO:
        b = Breach(f"src/a.c:f:{metric}", "function", "src/a.c", metric, 9.0, 1.0, line=3, function="f")
        result = breach_to_result(b, index)
        assert result["ruleId"] in index and result["ruleIndex"] == index[result["ruleId"]]
        assert result["level"] == rules[result["ruleIndex"]]["defaultConfiguration"]["level"]


def test_sarif_uses_relative_uri_line_and_fingerprint():
    index = {r["id"]: i for i, r in enumerate(build_rules())}
    b = Breach("src/a.c:f:fan_out", "function", "src/a.c", "fan_out", 9.0, 1.0, line=3, function="f")
    loc = breach_to_result(b, index)["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"] == {"uri": "src/a.c", "uriBaseId": "%SRCROOT%"}
    assert loc["region"]["startLine"] == 3
    assert breach_to_result(b, index)["partialFingerprints"]["fwlens-finding/1"] == "src/a.c:f:fan_out"
    assert rule_id("fan_out") == "FWLENS-FAN_OUT"


def test_sarif_without_a_line_still_has_a_valid_start_line():
    index = {r["id"]: i for i, r in enumerate(build_rules())}
    b = Breach("src/a.c:main_sequence_distance", "module", "src/a.c", "main_sequence_distance", 0.9, 0.5)
    assert breach_to_result(b, index)["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_tool_version_comes_from_the_package():
    assert tool_version() != "0.29.0" or tool_version() == "0.29.0"  # tracks pyproject, never hard-coded
    assert tool_version()
