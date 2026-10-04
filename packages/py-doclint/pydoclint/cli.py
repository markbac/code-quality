import argparse
import sys
from pathlib import Path
from .linter import DocLinter

def main():
    parser = argparse.ArgumentParser(
        prog="py-doclint",
        description="Technical Writing Style & Glossary Validator for Markdown"
    )
    parser.add_argument("target", type=str, nargs="?", default=".", help="Path to markdown file or documentation directory")
    parser.add_argument("--strict", action="store_true", help="Exit with code 1 if any style or glossary issues are found")

    args = parser.parse_args()

    linter = DocLinter()
    target_path = Path(args.target).resolve()

    total_issues = 0

    if target_path.is_file():
        issues = linter.lint_file(target_path)
        total_issues = len(issues)
        for issue in issues:
            print(issue)
    else:
        results = linter.lint_directory(target_path)
        for path, issues in results.items():
            total_issues += len(issues)
            for issue in issues:
                print(issue)

    print(f"\n[SUMMARY] Linting completed. {total_issues} issue(s) reported across documentation.")
    if args.strict and total_issues > 0:
        sys.exit(1)

if __name__ == "__main__":
    main()
