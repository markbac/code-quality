import os
import argparse
import sys
from pathlib import Path
from .converter import SlidesConverter

def main():
    parser = argparse.ArgumentParser(
        prog="py-doc2slides",
        description="Convert Markdown technical documentation to PowerPoint (.pptx) presentation decks"
    )
    parser.add_argument("input", type=str, help="Input Markdown (.md) file or directory")
    parser.add_argument("-o", "--output", type=str, help="Output PowerPoint (.pptx) file path or directory")
    parser.add_argument("-r", "--reference", type=str, help="Optional reference PowerPoint (.pptx) template (e.g., Template.pptx)")

    args = parser.parse_args()

    converter = SlidesConverter(template_path=Path(args.reference) if args.reference else None)
    input_path = Path(args.input).resolve()

    if input_path.is_file():
        out_path = Path(args.output) if args.output else input_path.with_suffix(".pptx")
        converter.convert_file(input_path, out_path)
    elif input_path.is_dir():
        out_dir = Path(args.output) if args.output else input_path
        for root, _, files in os.walk(input_path):
            for f in files:
                if f.endswith(".md"):
                    src = Path(root) / f
                    dst = out_dir / src.relative_to(input_path).with_suffix(".pptx")
                    converter.convert_file(src, dst)
    else:
        print(f"Error: Path not found: {input_path}")
        sys.exit(1)

if __name__ == "__main__":
    main()
