"""Message triage and guideline recategorisation records (#88)."""

import csv

import pytest
import yaml

from fwlens.baseline import compute_breaches
from fwlens.config import StandardSelection
from fwlens.standards import RuleFileError, run_standards
from fwlens.standards.matrix import build_matrix, render_json, render_markdown
from fwlens.standards.rules import load_standards
from fwlens.standards.triage import load_recategorisations, load_triage
from tests.test_standards import enable, parsed  # noqa: F401  (fixture)

FINDING = "app.c:run:misra-c-2012:15.1"


def _write(path, doc):
    path.write_text(yaml.safe_dump(doc))
    return path


def _triage(tmp_path, outcome, extra=()):
    return _write(tmp_path / "triage.yaml", {"triage": [
        {"id": FINDING, "outcome": outcome, "reason": "reviewed", "owner": "AD", "date": "2026-10-08"}, *extra]})


def _run(parsed, **kw):  # noqa: F811
    model, config, work = parsed
    enable(config, StandardSelection("misra-c-2012", include_ids=["15.1", "21.3"]), **kw)
    return model, config, [b for b in compute_breaches(model, config) if b.kind == "rule"]


def test_a_false_positive_leaves_the_gate_and_is_listed(parsed, tmp_path):  # noqa: F811
    model, config, work = parsed
    findings = _run(parsed, triage_file=_triage(work, "false_positive"))[2]
    assert FINDING not in [b.id for b in findings] and any(b.metric == "misra-c-2012:21.3" for b in findings)
    result = run_standards(model, config)
    assert [(f.id, e.outcome, e.owner) for f, e in result.triaged] == [(FINDING, "false_positive", "AD")]
    row = next(r for r in build_matrix(result) if r["id"] == "15.1")
    assert (row["triaged"], row["false_positive"]) == (1, 1)


@pytest.mark.parametrize("outcome", ["true_positive", "accepted"])
def test_other_outcomes_are_recorded_but_still_count(parsed, outcome):  # noqa: F811
    work = parsed[2]
    findings = _run(parsed, triage_file=_triage(work, outcome))[2]
    assert FINDING in [b.id for b in findings]


def test_a_triage_entry_with_no_finding_is_reported_stale(parsed):  # noqa: F811
    work = parsed[2]
    stale = {"id": "gone.c:f:misra-c-2012:15.1", "outcome": "accepted", "reason": "r", "owner": "o"}
    model, config, _f = _run(parsed, triage_file=_triage(work, "accepted", [stale]))
    assert run_standards(model, config).stale_triage == ["gone.c:f:misra-c-2012:15.1"]
    assert "Stale triage entries" in render_markdown(run_standards(model, config))


def test_recategorisation_changes_the_finding_category_and_shows_the_original(parsed):  # noqa: F811
    work = parsed[2]
    recat = _write(work / "recat.yaml", {"recategorisations": [
        {"standard": "misra-c-2012", "rule": "15.1", "category": "required", "reason": "stricter here",
         "approved_by": "Lead"}]})
    model, config, findings = _run(parsed, recategorisation_file=recat)
    assert next(b for b in findings if b.metric == "misra-c-2012:15.1").category == "required"
    result = run_standards(model, config)
    row = next(r for r in build_matrix(result) if r["id"] == "15.1")
    assert (row["category"], row["original_category"]) == ("required", "advisory")
    text = render_markdown(result)
    assert "Recategorised guidelines" in text and "not a MISRA Compliance claim" in text
    assert render_json(result).count("stricter here") == 1


def test_a_mandatory_guideline_cannot_be_made_weaker(tmp_path):
    standards = load_standards([])
    rule = next(r for r in standards["misra-c-2012"].rules.values() if r.category == "mandatory")
    path = _write(tmp_path / "r.yaml", {"recategorisations": [
        {"standard": "misra-c-2012", "rule": rule.id, "category": "required", "reason": "no"}]})
    with pytest.raises(RuleFileError, match="weaker"):
        load_recategorisations(path, standards)


@pytest.mark.parametrize("entry,message", [
    ({"id": "x", "outcome": "maybe", "reason": "r", "owner": "o"}, "outcome"),
    ({"id": "x", "outcome": "accepted", "owner": "o"}, "reason"),
    ({"id": "x", "outcome": "accepted", "reason": "r", "owner": "o", "date": "yesterday"}, "date"),
])
def test_bad_triage_entries_are_rejected(tmp_path, entry, message):
    with pytest.raises(RuleFileError, match=message):
        load_triage(_write(tmp_path / "t.yaml", {"triage": [entry]}))


def test_standards_csv_has_the_new_columns(parsed):  # noqa: F811
    from fwlens.output.exports import export_csv
    work = parsed[2]
    model, config, _f = _run(parsed, triage_file=_triage(work, "false_positive"))
    config.output.exports_dir = work / "exports"
    export_csv(model, config)
    rows = list(csv.DictReader((work / "exports" / "standards.csv").open()))
    row = next(r for r in rows if r["id"] == "15.1")
    assert row["triaged"] == "1" and row["false_positive"] == "1" and row["original_category"] == ""
