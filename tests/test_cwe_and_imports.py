"""CWE mapping (#98) and the extra analyser imports (#102)."""

import json

import pytest
from test_sarif_cli import run, validate

from fwlens.output.supply_chain import sarif_view
from fwlens.standards import load_standards
from fwlens.standards.cwe import TOP25, load_map, normalise
from fwlens.standards.importers import RawFinding, map_to_rule, read_import

# --- CWE map ---------------------------------------------------------------------------------------


def test_every_rule_in_the_cwe_map_exists():
    standards = load_standards()
    for std_id, rules in load_map().items():
        assert std_id in standards, std_id
        for rid in rules:
            assert rid in standards[std_id].rules, (std_id, rid)


def test_cwe_ids_are_added_to_rules_and_keep_the_ones_a_rule_lists():
    standards = load_standards()
    assert "CWE-252" in standards["misra-c-2012"].rules["17.7"].cwe
    assert standards["misra-c-2012"].rules["17.7"].cwe == standards["misra-c-2023"].rules["17.7"].cwe
    assert standards["cert-c"].rules["EXP34-C"].cwe[0] == "CWE-476"
    assert standards["fwlens"].rules["SEC-1"].cwe == ["CWE-259", "CWE-798"]
    for std in standards.values():
        for rule in std.rules.values():
            assert all(c.startswith("CWE-") and c[4:].isdigit() for c in rule.cwe), (rule.key, rule.cwe)


def test_normalise_accepts_the_usual_spellings():
    assert normalise(476) == normalise("cwe-476") == normalise(" CWE-476 ") == "CWE-476"
    assert len(TOP25) == 25 and len(set(TOP25)) == 25


def test_sarif_carries_cwe_tags_taxonomy_and_top25_summary(tmp_path, monkeypatch):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.c").write_text('const char *key = "AKIAIOSFODNN7EXAMPLE";\n')
    (tmp_path / "config.yaml").write_text(
        "project:\n  source_dir: src\ntool:\n  target: native\n"
        "standards:\n  enabled:\n    - standard: fwlens\n      include_ids: [SEC-3]\n")
    out = tmp_path / "out.sarif"
    result = run(monkeypatch, tmp_path, "analyze", "--config", str(tmp_path / "config.yaml"), "--sarif", str(out))
    assert result.exit_code == 0, result.output
    document = validate(out)
    run0 = document["runs"][0]
    rule = next(r for r in run0["tool"]["driver"]["rules"] if r["id"] == "fwlens:SEC-3")
    assert rule["properties"]["tags"] == ["external/cwe/cwe-798"]
    assert rule["relationships"][0]["target"] == {"id": "798", "toolComponent": {"name": "CWE"}}
    assert [t["name"] for t in run0["taxonomies"]] == ["CWE"] and run0["taxonomies"][0]["taxa"][0]["id"] == "798"
    cwe = run0["properties"]["fwlens"]["cwe"]
    assert cwe["findingsByCwe"] == {"CWE-798": 1} and cwe["top25WithFindings"] == ["CWE-798"]
    assert "CWE-798" in cwe["top25CheckedByRules"]


def test_sarif_view_lists_the_cwe_summary():
    doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "FWLens", "rules": []}}, "results": [],
           "properties": {"fwlens": {"cwe": {"top25Edition": "2024", "top25": TOP25, "top25CheckedByRules": ["CWE-476"],
                                             "top25WithFindings": ["CWE-476"], "findingsByCwe": {"CWE-476": 3}}}}}]}
    view = sarif_view(doc)
    assert view["cwe"]["rows"] == [{"cwe": "CWE-476", "count": 3}] and view["cwe"]["top25_size"] == 25


# --- imports ---------------------------------------------------------------------------------------


def test_clang_tidy_yaml_gives_the_line_from_the_offset(tmp_path):
    src = tmp_path / "a.c"
    src.write_text("int a;\nint b;\nint c;\n")
    yml = tmp_path / "fixes.yaml"
    yml.write_text(json.dumps({"MainSourceFile": str(src), "Diagnostics": [
        {"DiagnosticName": "bugprone-x", "DiagnosticMessage": {"Message": "m", "FilePath": str(src), "FileOffset": 9}}]}))
    found = read_import("clang-tidy-yaml", yml)
    assert [(f.tool, f.tool_id, f.line) for f in found] == [("clang-tidy", "bugprone-x", 2)]


def test_clang_analyzer_plist_is_reported_as_a_clang_analyzer_check(tmp_path):
    import plistlib
    plist = tmp_path / "r.plist"
    plist.write_bytes(plistlib.dumps({"files": ["/p/a.c"], "diagnostics": [
        {"check_name": "core.NullDereference", "description": "Dereference of null pointer",
         "location": {"line": 12, "col": 3, "file": 0}}]}))
    found = read_import("clang-analyzer", plist)
    assert [(f.tool, f.tool_id, f.file, f.line) for f in found] == [
        ("clang-tidy", "clang-analyzer-core.NullDereference", "/p/a.c", 12)]


def test_wildcard_tool_map_catches_what_nothing_else_maps():
    standards = load_standards()
    fw = [standards["fwlens"]]
    got = map_to_rule(RawFinding("clang-tidy", "clang-analyzer-alpha.unix.Foo", "a.c", 1, "m"), fw)
    assert got is not None and got.id == "IMP-1"
    assert map_to_rule(RawFinding("cppcheck", "anything", "a.c", 1, "m"), fw).id == "IMP-2"
    # an exact entry in a standard that is listed first wins over the wildcard
    both = [standards["cert-c"], standards["fwlens"]]
    assert map_to_rule(RawFinding("clang-tidy", "clang-analyzer-core.NullDereference", "a.c", 1, "m"), both).id == "EXP34-C"
    assert map_to_rule(RawFinding("cppcheck", "nullPointer", "a.c", 1, "m"), both).id == "EXP34-C"


@pytest.mark.parametrize("tool", ["clang-tidy-yaml", "clang-analyzer"])
def test_new_import_tools_are_known(tool):
    from fwlens.standards.importers import PARSERS
    assert tool in PARSERS
