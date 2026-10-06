"""SBOM, CBOM and SARIF shown as readable tabs in the HTML report (#97)."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

import main as fwlens_main

FIXTURE = Path(__file__).parent / "fixtures" / "components_example.yaml"

SOURCES = {
    "src/main.c": '#include "app.h"\nint main(void) { return app(); }\n',
    "src/app.c": ('#include "app.h"\n#include "mbedtls/aes.h"\n'
                  "int app(void) { int a = 0; if (a) { a = 1; } mbedtls_aes_init(0); return a; }\n"),
    "Inc/app.h": "int app(void);\n",
    "Lib/mbedtls/mbedtls/aes.h": "/* SPDX-License-Identifier: Apache-2.0 */\nvoid mbedtls_aes_init(void *c);\n",
    "Lib/mbedtls/aes.c": "/* SPDX-License-Identifier: Apache-2.0 */\n#include \"mbedtls/aes.h\"\nvoid mbedtls_aes_init(void *c) { (void)c; }\n",
}


@pytest.fixture
def report(tmp_path, monkeypatch):
    for name, text in SOURCES.items():
        f = tmp_path / name
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text)

    def build(formats, extra=""):
        cfg = tmp_path / "config.yaml"
        cfg.write_text("project:\n  source_dir: .\nscope:\n  first_party: [src, Inc]\n  third_party_lib: [Lib]\n"
                       f"tool:\n  target: native\noutput:\n  formats: {formats}\n" + extra)
        monkeypatch.chdir(tmp_path)
        result = CliRunner().invoke(fwlens_main.cli, ["report", "--config", str(cfg)])
        assert result.exit_code == 0, result.output
        return (tmp_path / "output" / "reports" / "fwlens_report.html").read_text(encoding="utf-8")
    return build


def test_each_format_adds_its_own_tab(report):
    html = report("[html, sbom, cbom, sarif]")
    for key in ("sbom", "cbom", "sarif"):
        assert f'id="tab-{key}"' in html and f'id="pane-{key}"' in html
    assert "Software bill of materials" in html and "Cryptographic bill of materials" in html
    assert "SARIF results" in html and "Key metrics carried in the file" in html


def test_tabs_are_absent_when_the_format_is_not_requested(report):
    html = report("[html]")
    assert 'id="tab-sbom"' not in html and 'id="tab-cbom"' not in html and 'id="tab-sarif"' not in html
    html = report("[html, sarif]")
    assert 'id="tab-sarif"' in html and 'id="tab-sbom"' not in html


def test_sbom_tab_lists_components_and_gaps_from_the_components_file(report):
    html = report("[html, sbom]", f"sbom:\n  components_file: {FIXTURE}\n  application_version: '2.0.1'\n")
    assert "Acme Smart Meter" in html and "Example Cellular Modem Firmware" in html
    assert "Needs attention" in html and "Confirm ExampleCrypto version" in html
    assert "components_example.yaml" in html


def test_cbom_tab_names_the_algorithm_found(report):
    html = report("[html, cbom]")
    assert "AES" in html and "Algorithms and protocols" in html


def test_views_read_the_same_documents_the_exports_write():
    from fwlens.output.supply_chain import cbom_view, sarif_view, sbom_view
    sbom = sbom_view({"specVersion": "1.6", "metadata": {"component": {"name": "x"}},
                      "components": [{"name": "a", "type": "library", "bom-ref": "a",
                                      "licenses": [{"license": {"name": "Proprietary"}}]},
                                     {"name": "b", "type": "library", "bom-ref": "b"}]})
    assert sbom["total"] == 2 and sbom["licence_kinds"] == {"proprietary": 1, "unknown": 1}
    assert sbom["missing_version"] == ["a", "b"]
    cbom = cbom_view({"metadata": {}, "components": [
        {"type": "cryptographic-asset", "name": "DES", "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "block-cipher"}},
         "properties": [{"name": "fwlens:weak", "value": "broken"}]}]})
    assert cbom["algorithms"] == 1 and cbom["weak"][0]["name"] == "DES"
    sarif = sarif_view({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "FWLens", "rules": [
        {"id": "R1", "shortDescription": {"text": "t"}, "defaultConfiguration": {"level": "warning"}}]}},
        "results": [{"ruleId": "R1", "level": "warning", "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.c"}}}]}]}]})
    assert sarif["total"] == 1 and sarif["rule_rows"][0]["count"] == 1 and sarif["file_rows"] == [{"file": "a.c", "count": 1}]
