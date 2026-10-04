import pytest
from pathlib import Path
from pydoclint import DocLinter

def test_linter_glossary(tmp_path):
    md_file = tmp_path / "test.md"
    md_file.write_text("We use lwm2m over dtls for communications in order to save power.")

    linter = DocLinter()
    issues = linter.lint_file(md_file)
    
    # Should catch lwm2m (LwM2M), dtls (DTLS), and 'in order to'
    assert len(issues) >= 3
    categories = [i.category for i in issues]
    assert "Glossary" in categories
    assert "Style" in categories
