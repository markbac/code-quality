"""
Coding-standard support (#49): YAML rule files, native engines, imports, deviations and the
compliance matrix.
"""

import json
import shutil
from datetime import date
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

import main as fwlens_main
from fwlens.baseline import Breach, _assign_ordinals, compute_breaches
from fwlens.config import StandardSelection, StandardsConfig, ToolConfig
from fwlens.identity import match_findings
from fwlens.output.reporters import severity_for, to_codequality
from fwlens.output.sarif import build_rules, breach_to_result, rule_id
from fwlens.standards import run_standards, select_rules
from fwlens.standards.deviations import apply_deviations, load_deviations
from fwlens.standards.importers import RawFinding, candidate_ids, map_to_rule, read_import
from fwlens.standards.matrix import DISCLAIMER, build_matrix, render_json, render_markdown
from fwlens.standards.rules import BUILTIN_DIR, RuleFileError, load_standard_file, load_standards, parse_standard


# --- rule files ---------------------------------------------------------------------

def minimal(**over):
    doc = {
        "schema_version": 1,
        "standard": {"id": "acme", "name": "Acme", "categories": ["must", "should"], "undeviable_categories": ["must"]},
        "rules": [{"id": "A1", "kind": "rule", "title": "t", "category": "must", "decidable": True,
                   "scope": "single-tu", "check": {"type": "native", "engine": "ast",
                                                   "match": {"cursor": "CALL_EXPR", "callee_in": ["bad"]}}}],
    }
    doc.update(over)
    return doc


def test_builtin_rule_files_are_valid():
    standards = load_standards([])
    assert {"misra-c-2012", "cert-c"} <= set(standards)
    misra = standards["misra-c-2012"]
    assert misra.rules["15.1"].category == "advisory" and misra.rules["9.1"].undeviable
    assert not misra.rules["17.2"].decidable and misra.rules["17.2"].scope == "system"
    assert standards["cert-c"].rules["ENV33-C"].check_type == "native"


def test_builtin_files_carry_no_guideline_text():
    for f in BUILTIN_DIR.glob("*.yaml"):
        assert yaml.safe_load(f.read_text())["standard"]["guideline_text"] in ("user-supplied", "https://wiki.sei.cmu.edu/confluence/display/c")
        for rule in yaml.safe_load(f.read_text())["rules"]:
            assert len(rule["title"]) < 90   # short paraphrase, not a pasted paragraph


@pytest.mark.parametrize("mutate, message", [
    (lambda d: d.update(schema_version=2), "schema_version"),
    (lambda d: d["rules"][0].pop("title"), "rule A1: missing required field 'title'"),
    (lambda d: d["rules"][0].update(category="nope"), "category 'nope'"),
    (lambda d: d["rules"][0]["check"].update(engine="magic"), "check.engine"),
    (lambda d: d["rules"][0]["check"].update(match={}), "check.match.cursor"),
    (lambda d: d["rules"][0].update(scope="galaxy"), "scope must be"),
    (lambda d: d["rules"].append(dict(d["rules"][0])), "duplicate rule id"),
    (lambda d: d.update(tool_map={"cppcheck": {"x": "ZZ"}}), "unknown rule 'ZZ'"),
])
def test_invalid_rule_files_give_precise_errors(mutate, message):
    doc = minimal()
    mutate(doc)
    with pytest.raises(RuleFileError, match=message):
        parse_standard(doc, Path("acme.yaml"))


def test_extra_rule_dir_adds_and_overrides(tmp_path):
    (tmp_path / "acme.yaml").write_text(yaml.safe_dump(minimal()))
    override = yaml.safe_load((BUILTIN_DIR / "cert-c.yaml").read_text())
    override["rules"] = override["rules"][:1]
    override["tool_map"] = {}
    (tmp_path / "cert.yaml").write_text(yaml.safe_dump(override))
    standards = load_standards([tmp_path])
    assert "acme" in standards and len(standards["cert-c"].rules) == 1
    with pytest.raises(RuleFileError, match="not a directory"):
        load_standards([tmp_path / "missing"])


def test_select_rules_filters():
    standards = load_standards([])
    only_required = select_rules(standards, [StandardSelection("misra-c-2012", include_categories=["required"])])
    assert only_required and all(r.category == "required" for r in only_required)
    picked = select_rules(standards, [StandardSelection("cert-c", include_ids=["ENV33-C"])])
    assert [r.id for r in picked] == ["ENV33-C"]
    skipped = select_rules(standards, [StandardSelection("misra-c-2012", exclude_rules=["15.1"])])
    assert "15.1" not in {r.id for r in skipped}
    with pytest.raises(RuleFileError, match="unknown standard"):
        select_rules(standards, [StandardSelection("nope")])


# --- native engines (real libclang) ---------------------------------------------------

C_SOURCE = """\
#include <stdlib.h>
#include <stdio.h>

int fact(int n)
{
    if (n <= 1) return 1;
    return n * fact(n - 1);
}

int ping(int n);
int pong(int n) { return n > 0 ? ping(n - 1) : 0; }
int ping(int n) { return n > 0 ? pong(n - 1) : 0; }

int fine(int a)
{
    if (a) { a++; } else if (a > 3) { a--; } else { a = 0; }
    for (int i = 0; i < 3; i++) { a += i; }
    return a;
}

void run(int mode)
{
    char *buf = malloc(16);
    if (mode == 1)
        goto out;
    printf("mode %d\\n", mode);
    while (mode > 0) mode--;
    do mode++; while (mode < 3);
    if (mode) { mode = 1; } else mode = 2;
    for (;;) mode++;
out:
    free(buf);
}
"""


@pytest.fixture
def parsed(tmp_path):
    """A parsed model for C_SOURCE using the bundled libclang and the host headers."""
    cindex = pytest.importorskip("clang.cindex")
    if not any(shutil.which(c) for c in ("gcc", "cc", "clang")):
        pytest.skip("no host compiler for system headers")
    from test_p0_regressions import _config
    from fwlens.parser.pipeline import run_pipeline

    (tmp_path / "app.c").write_text(C_SOURCE)
    (tmp_path / "config.yaml").write_text("tool:\n  target: native\nproject:\n  source_dir: .\n")
    config = _config(tmp_path)
    config.tool = ToolConfig(libclang_path=None, target="native")
    model = run_pipeline(config)
    if model.parse_stats["parsed_ok"] != 1:
        pytest.skip("libclang could not parse the fixture")
    return model, config, tmp_path


def enable(config, *selections, **kw):
    config.standards = StandardsConfig(enabled=list(selections), **kw)


def by_rule(result):
    out = {}
    for f in result.findings:
        out.setdefault(f.metric, []).append(f)
    return out


def test_native_engines_find_the_expected_violations(parsed):
    model, config, _ = parsed
    enable(config, StandardSelection("misra-c-2012"), StandardSelection("cert-c"))
    found = by_rule(run_standards(model, config))
    assert [f.function for f in found["misra-c-2012:15.1"]] == ["run"]
    assert {f.function for f in found["misra-c-2012:21.3"]} == {"run"} and len(found["misra-c-2012:21.3"]) == 2
    assert len(found["misra-c-2012:21.6"]) == 1
    assert {f.function for f in found["misra-c-2012:17.2"]} == {"fact", "ping", "pong"}
    # 15.6: `if (n<=1) return`, `if (mode==1) goto`, while, do, else branch, for(;;) -- but not `fine`
    lines = sorted(f.line for f in found["misra-c-2012:15.6"])
    assert len(lines) == 6 and all(f.function != "fine" for f in found["misra-c-2012:15.6"])
    assert "misra-c-2012:21.7" not in found


def test_findings_carry_line_function_category_and_fingerprint(parsed):
    model, config, _ = parsed
    enable(config, StandardSelection("misra-c-2012", include_ids=["15.1"]))
    f = run_standards(model, config).findings[0]
    assert (f.kind, f.file, f.function, f.category) == ("rule", "app.c", "run", "advisory")
    assert f.line == 25 and f.fingerprint["body_hash"] and f.description


def test_a_new_rule_in_yaml_needs_no_code_change(parsed, tmp_path):
    model, config, work = parsed
    rules = work / "rules"
    rules.mkdir()
    doc = minimal()
    doc["rules"][0]["check"]["match"] = {"cursor": "CALL_EXPR", "callee_in": ["printf"]}
    (rules / "acme.yaml").write_text(yaml.safe_dump(doc))
    enable(config, StandardSelection("acme"), extra_rule_dirs=[rules])
    found = run_standards(model, config).findings
    assert [f.metric for f in found] == ["acme:A1"] and found[0].function == "run"


def test_rule_findings_join_the_breach_list_only_when_enabled(parsed):
    model, config, _ = parsed
    assert not [b for b in compute_breaches(model, config) if b.kind == "rule"]
    enable(config, StandardSelection("misra-c-2012", include_ids=["15.1"]))
    model._standards_result = None
    rule_breaches = [b for b in compute_breaches(model, config) if b.kind == "rule"]
    assert len(rule_breaches) == 1 and rule_breaches[0].id == "app.c:run:misra-c-2012:15.1"


def test_same_statement_in_same_function_gets_ordinals(parsed):
    model, config, _ = parsed
    enable(config, StandardSelection("misra-c-2012", include_ids=["21.3"]))
    ids = sorted(b.id for b in compute_breaches(model, config) if b.kind == "rule")
    assert ids == ["app.c:run#2:misra-c-2012:21.3", "app.c:run:misra-c-2012:21.3"]


# --- identity for statement findings ------------------------------------------------------

def rule_finding(function, text, line, ordinal=1):
    from fwlens.identity import make_key, statement_fingerprint
    return Breach(make_key("src/a.c", function, "misra-c-2012:21.3", ordinal), "rule", "src/a.c",
                  "misra-c-2012:21.3", 1.0, 0.0, line=line, function=function,
                  fingerprint=statement_fingerprint(text), category="required", description="t")


def test_a_rule_finding_moved_into_a_helper_is_not_new():
    base = [rule_finding("big", "buf = malloc(16);", 40).to_dict()]
    result = match_findings([rule_finding("helper", "buf = malloc(16);", 5)], base)
    assert [m.status for m in result.matches] == ["moved"] and result.gating() == []


def test_a_changed_statement_is_new():
    base = [rule_finding("f", "buf = malloc(16);", 5).to_dict()]
    result = match_findings([rule_finding("f", "buf = calloc(16, 1);", 5, ordinal=2)], base)
    assert [m.status for m in result.matches] == ["new"] and len(result.resolved) == 1


# --- importers -----------------------------------------------------------------------------

def test_candidate_ids_for_common_tool_shapes():
    assert candidate_ids("misra-c2012-15.1") == ["15.1"]
    assert candidate_ids("misra-c2012-dir-4.1") == ["D4.1"]
    assert candidate_ids("premium-misra-c-2012-21.3") == ["21.3"]
    assert candidate_ids("cert-env33-c") == ["ENV33-C"]
    assert candidate_ids("bugprone-foo") == []


def test_import_parsers(tmp_path):
    xml = tmp_path / "c.xml"
    xml.write_text('<results><errors><error id="misra-c2012-15.1" msg="m"><location file="a.c" line="7"/></error>'
                   '<error id="x" msg="no location"/></errors></results>')
    assert [(f.tool_id, f.file, f.line) for f in read_import("cppcheck", xml)] == [("misra-c2012-15.1", "a.c", 7)]
    txt = tmp_path / "t.txt"
    txt.write_text("src/a.c:9:3: warning: msg [cert-env33-c,bugprone-x]\nnoise line\n")
    assert [f.tool_id for f in read_import("clang-tidy", txt)] == ["cert-env33-c", "bugprone-x"]
    sarif = tmp_path / "s.sarif"
    sarif.write_text(json.dumps({"runs": [{"results": [{"ruleId": "misra-c2012-15.1", "message": {"text": "m"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "file:///p/a.c"}, "region": {"startLine": 4}}}]}]}]}))
    assert [(f.file, f.line) for f in read_import("sarif", sarif)] == [("/p/a.c", 4)]
    with pytest.raises(ValueError):
        read_import("lint", sarif)


def test_mapping_uses_tool_map_then_patterns():
    standards = list(load_standards([]).values())
    assert map_to_rule(RawFinding("cppcheck", "misra-c2012-21.3", "a.c", 1, ""), standards).key == "misra-c-2012:21.3"
    assert map_to_rule(RawFinding("clang-tidy", "cert-env33-c", "a.c", 1, ""), standards).key == "cert-c:ENV33-C"
    assert map_to_rule(RawFinding("cppcheck", "unusedFunction", "a.c", 1, ""), standards) is None


def test_imports_end_to_end_with_dedupe_and_unmapped(parsed):
    model, config, work = parsed
    (work / "cppcheck.xml").write_text(
        '<results><errors>'
        '<error id="misra-c2012-15.1" msg="m"><location file="app.c" line="25"/></error>'   # same as native
        '<error id="misra-c2012-9.1" msg="m"><location file="app.c" line="23"/></error>'
        '<error id="unusedFunction" msg="m"><location file="app.c" line="1"/></error>'
        '</errors></results>')
    enable(config, StandardSelection("misra-c-2012"), imports=[("cppcheck", work / "cppcheck.xml")])
    result = run_standards(model, config)
    found = by_rule(result)
    assert len(found["misra-c-2012:15.1"]) == 1                      # not counted twice
    nine = found["misra-c-2012:9.1"][0]
    assert nine.function == "run" and nine.fingerprint["body_hash"]
    assert result.unmapped == {"cppcheck": 1}
    assert result.sources["misra-c-2012:9.1"] == {"imported"}


# --- deviations -------------------------------------------------------------------------------

def dev_file(tmp_path, *devs):
    p = tmp_path / "dev.yaml"
    p.write_text(yaml.safe_dump({"deviations": list(devs)}))
    return p


def base_dev(**kw):
    d = {"id": "DEV-1", "standard": "misra-c-2012", "rule": "21.3", "type": "project", "justification": "because"}
    d.update(kw)
    return d


def finding(rule="misra-c-2012:21.3", file="src/a.c", function="f"):
    return Breach("", "rule", file, rule, 1.0, 0.0, line=3, function=function, category="required", description="t")


def test_project_and_specific_deviations_apply_by_scope(tmp_path):
    standards = load_standards([])
    devs = load_deviations(dev_file(tmp_path,
        base_dev(id="P", type="project", scope={"paths": ["src/platform/*"]}),
        base_dev(id="S", type="specific", scope={"functions": ["init"]})), standards)
    out = apply_deviations([finding(file="src/platform/alloc.c"), finding(function="init"), finding()], devs, standards)
    assert len(out.deviated) == 2 and len(out.active) == 1
    assert {d.id for _, d in out.deviated} == {"P", "S"}


def test_expired_deviation_does_not_apply_and_is_a_problem(tmp_path):
    standards = load_standards([])
    devs = load_deviations(dev_file(tmp_path, base_dev(expires="2020-01-01")), standards)
    out = apply_deviations([finding()], devs, standards, today=date(2026, 10, 3))
    assert len(out.active) == 1 and out.problems and "expired" in out.problems[0][1]
    ok = apply_deviations([finding()], devs, standards, today=date(2019, 1, 1))
    assert len(ok.deviated) == 1


def test_mandatory_rules_cannot_be_deviated(tmp_path):
    standards = load_standards([])
    devs = load_deviations(dev_file(tmp_path, base_dev(rule="9.1")), standards)
    out = apply_deviations([finding(rule="misra-c-2012:9.1")], devs, standards)
    assert len(out.active) == 1 and "cannot be deviated" in out.problems[0][1]


@pytest.mark.parametrize("dev, message", [
    (base_dev(rule="99.9"), "unknown rule"),
    (base_dev(type="maybe"), "type must be"),
    (base_dev(type="specific"), "needs scope"),
    (base_dev(justification=""), "missing required field 'justification'"),
    (base_dev(expires="soon"), "expires must be a date"),
])
def test_invalid_deviations_are_rejected(tmp_path, dev, message):
    with pytest.raises(RuleFileError, match=message):
        load_deviations(dev_file(tmp_path, dev), load_standards([]))


def test_a_broken_deviation_becomes_a_gating_finding(parsed, tmp_path):
    model, config, work = parsed
    enable(config, StandardSelection("misra-c-2012", include_ids=["21.3"]),
           deviations_file=dev_file(work, base_dev(expires="2020-01-01")))
    result = run_standards(model, config)
    assert any(f.metric.startswith("deviation:") for f in result.findings)
    assert len(result.findings) == 3          # 2 malloc/free + the expired deviation


# --- matrix and outputs -------------------------------------------------------------------------

def test_matrix_statuses_and_disclaimer(parsed, tmp_path):
    model, config, work = parsed
    enable(config, StandardSelection("misra-c-2012"), deviations_file=dev_file(work, base_dev(scope={"functions": ["run"]})))
    result = run_standards(model, config)
    rows = {r["id"]: r for r in build_matrix(result)}
    assert rows["15.1"]["status"] == "violated" and rows["15.1"]["checked_by"] == "native"
    assert rows["21.3"]["status"] == "deviated" and rows["21.3"]["deviations"] == ["DEV-1"]
    assert rows["21.7"]["status"] == "no findings"
    assert rows["D4.1"]["status"] == "manual review"
    assert rows["9.1"]["status"] == "not assessed" and "no results" in rows["9.1"]["checked_by"]
    md = render_markdown(result)
    assert DISCLAIMER in md and "| 15.1 | advisory |" in md
    assert json.loads(render_json(result))["summary"]["violated"] >= 3


def test_sarif_declares_rule_findings_with_category_levels():
    f = Breach("a:b:misra-c-2012:15.1", "rule", "src/a.c", "misra-c-2012:15.1", 1, 0, line=2, function="f",
               category="advisory", description="Avoid the goto statement")
    rules = build_rules([f])
    index = {r["id"]: i for i, r in enumerate(rules)}
    res = breach_to_result(f, index)
    assert res["ruleId"] == "misra-c-2012:15.1" == rule_id(f.metric) and res["level"] == "note"
    assert rules[res["ruleIndex"]]["shortDescription"]["text"] == "Avoid the goto statement"
    assert "Avoid the goto statement" in res["message"]["text"]


def test_gitlab_severity_follows_the_category():
    for cat, sev in (("mandatory", "critical"), ("required", "major"), ("advisory", "minor")):
        f = Breach("x", "rule", "a.c", "misra-c-2012:1.1", 1, 0, category=cat, description="d")
        assert severity_for(f) == sev
    entry = to_codequality([Breach("x", "rule", "a.c", "misra-c-2012:15.1", 1, 0, line=4, function="f",
                                   category="advisory", description="Avoid goto")])[0]
    assert entry["description"] == "misra-c-2012:15.1: Avoid goto in f"


# --- CLI ------------------------------------------------------------------------------------------

def test_standards_validate_command(tmp_path):
    runner = CliRunner()
    assert runner.invoke(fwlens_main.cli, ["standards", "validate"]).exit_code == 0
    good = tmp_path / "good.yaml"
    good.write_text(yaml.safe_dump(minimal()))
    assert runner.invoke(fwlens_main.cli, ["standards", "validate", str(good)]).exit_code == 0
    bad = tmp_path / "bad.yaml"
    bad_doc = minimal()
    bad_doc["rules"][0]["check"]["engine"] = "magic"
    bad.write_text(yaml.safe_dump(bad_doc))
    res = runner.invoke(fwlens_main.cli, ["standards", "validate", str(bad)])
    assert res.exit_code == 1 and "check.engine" in res.output
    devs = dev_file(tmp_path, base_dev(rule="99.9"))
    assert runner.invoke(fwlens_main.cli, ["standards", "validate", str(devs)]).exit_code == 1


def test_standards_list_command_shows_check_types():
    res = CliRunner().invoke(fwlens_main.cli, ["standards", "list"])
    assert res.exit_code == 0 and "native" in res.output and "import" in res.output and "manual" in res.output
