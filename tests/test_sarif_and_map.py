"""
Tests for SARIF 2.1.0 exporter and Linker mapfile parser.
"""

import tempfile
from pathlib import Path
from fwlens.parser.mapfile import parse_linker_mapfile
from fwlens.output.sarif import generate_sarif_report
from fwlens.config import FwLensConfig, ProjectConfig, ScopeConfig, ToolConfig, ThresholdConfig, OutputConfig
from fwlens.model.project import ProjectModel


def test_linker_mapfile_parsing():
    with tempfile.TemporaryDirectory() as tmp_dir:
        map_path = Path(tmp_dir) / "project.map"
        map_path.write_text("""
 .text          0x08000000        0x100 main.o
 .rodata        0x08000100         0x50 main.o
 .data          0x20000000         0x20 main.o
 .bss           0x20000020         0x80 main.o
""")

        metrics = parse_linker_mapfile(map_path)
        assert "main.o" in metrics
        m = metrics["main.o"]
        assert m.text_size == 0x100
        assert m.rodata_size == 0x50
        assert m.data_size == 0x20
        assert m.bss_size == 0x80
        assert m.total_flash == 0x170
        assert m.total_ram == 0xA0
