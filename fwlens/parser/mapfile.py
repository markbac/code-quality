"""
Linker .map file parser for IAR and GCC memory footprint analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class MemorySectionMetrics:
    file_name: str
    text_size: int = 0
    rodata_size: int = 0
    data_size: int = 0
    bss_size: int = 0

    @property
    def total_flash(self) -> int:
        return self.text_size + self.rodata_size + self.data_size

    @property
    def total_ram(self) -> int:
        return self.data_size + self.bss_size


def parse_linker_mapfile(map_path: Path) -> dict[str, MemorySectionMetrics]:
    """
    Parse IAR or GCC linker .map file and extract memory footprint per object file.
    """
    if not map_path.exists():
        return {}

    content = map_path.read_text(encoding="utf-8", errors="ignore")
    metrics: dict[str, MemorySectionMetrics] = {}

    # Regex patterns for GCC/IAR map file summary lines
    # Example:  .text   0x08000100   0x250   main.o
    pattern = re.compile(r'^\s*(\.(?:text|rodata|data|bss))\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)\s+(\S+)', re.MULTILINE)

    for match in pattern.finditer(content):
        sec_name, size_hex, obj_name = match.groups()
        size_bytes = int(size_hex, 16)
        obj_key = Path(obj_name).name

        if obj_key not in metrics:
            metrics[obj_key] = MemorySectionMetrics(file_name=obj_key)

        m = metrics[obj_key]
        if sec_name == ".text":
            m.text_size += size_bytes
        elif sec_name == ".rodata":
            m.rodata_size += size_bytes
        elif sec_name == ".data":
            m.data_size += size_bytes
        elif sec_name == ".bss":
            m.bss_size += size_bytes

    return metrics
