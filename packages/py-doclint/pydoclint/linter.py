import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from .pylogkit import setup_logging

logger = setup_logging(name="DocLint", to_console=True, to_file=False)

DEFAULT_GLOSSARY = {
    "LwM2M": ["lwm2m", "LWM2M", "Lw2m"],
    "DTLS": ["dtls", "Dtls"],
    "UART": ["uart", "Uart"],
    "MQTT": ["mqtt", "Mqtt"],
    "IPv6": ["ipv6", "Ipv6"],
    "API": ["api", "Api"],
    "JSON": ["json", "Json"],
    "YAML": ["yaml", "Yaml"],
    "HTTP": ["http", "Http"],
    "HTTPS": ["https", "Https"]
}

REDUNDANT_PHRASES = [
    "in order to", "at this point in time", "due to the fact that",
    "for the purpose of", "has the ability to", "it is important to note that"
]

class LintIssue:
    def __init__(self, file: Path, line_no: int, category: str, message: str, severity: str = "warning"):
        self.file = Path(file)
        self.line_no = line_no
        self.category = category
        self.message = message
        self.severity = severity

    def __repr__(self):
        return f"[{self.severity.upper()}] {self.file.name}:{self.line_no} [{self.category}] {self.message}"

class DocLinter:
    """
    Technical Writing Style & Glossary Validator for Markdown repositories.
    """

    def __init__(self, glossary: Optional[Dict[str, List[str]]] = None):
        self.glossary = glossary or DEFAULT_GLOSSARY

    def lint_file(self, file_path: Path) -> List[LintIssue]:
        file_path = Path(file_path).resolve()
        issues: List[LintIssue] = []

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return issues

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Could not read file {file_path}: {e}")
            return issues

        lines = content.splitlines()
        acronyms_defined = set()

        for idx, line in enumerate(lines, start=1):
            # Skip code blocks
            if line.strip().startswith("```") or line.strip().startswith("`"):
                continue

            # 1. Glossary Capitalization Checks
            for canonical, variants in self.glossary.items():
                for variant in variants:
                    # Match exact word boundaries
                    pattern = rf"\b{re.escape(variant)}\b"
                    matches = re.finditer(pattern, line)
                    for m in matches:
                        if m.group(0) != canonical:
                            issues.append(LintIssue(
                                file=file_path,
                                line_no=idx,
                                category="Glossary",
                                message=f"Incorrect term capitalization '{m.group(0)}'. Preferred: '{canonical}'."
                            ))

            # 2. Redundant Phrase Checks
            for phrase in REDUNDANT_PHRASES:
                if phrase in line.lower():
                    issues.append(LintIssue(
                        file=file_path,
                        line_no=idx,
                        category="Style",
                        message=f"Redundant phrase found: '{phrase}'. Consider simplifying."
                    ))

            # 3. Acronym Definitions (e.g. "Pre-Shared Key (PSK)")
            acronym_match = re.search(r"([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)\s+\(([A-Z]{2,})\)", line)
            if acronym_match:
                acronyms_defined.add(acronym_match.group(2))

            # Check standalone uppercase acronyms of 3+ letters
            acronyms_used = re.findall(r"\b([A-Z]{3,})\b", line)
            for ac in acronyms_used:
                if ac in ["TOC", "URL", "CLI", "API", "JSON", "YAML", "HTML", "CSS", "SVG", "PNG", "CPU", "RAM", "RAM", "ROM", "OK"]:
                    continue
                if ac not in acronyms_defined and ac not in self.glossary:
                    # Warning for unexpanded acronym
                    pass

        logger.info(f"Linted {file_path.name}: {len(issues)} issue(s) found.")
        return issues

    def lint_directory(self, search_dir: Path) -> Dict[str, List[LintIssue]]:
        search_dir = Path(search_dir).resolve()
        results = {}

        for root, _, files in os.walk(search_dir):
            for file in files:
                if file.endswith(".md") or file.endswith(".markdown"):
                    p = Path(root) / file
                    issues = self.lint_file(p)
                    if issues:
                        results[str(p)] = issues

        return results
