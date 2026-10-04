import pytest
from pathlib import Path
from pydoc2slides import SlidesConverter

def test_slides_conversion(tmp_path):
    md_file = tmp_path / "deck.md"
    md_file.write_text("# Project Architecture\nOverview of the system.\n\n---\n\n## Core Modules\n- Module A\n- Module B\n\n```python\nimport sys\n```")

    out_file = tmp_path / "deck.pptx"
    converter = SlidesConverter()
    res = converter.convert_file(md_file, out_file)
    
    assert res.exists()
    assert res.stat().st_size > 0
