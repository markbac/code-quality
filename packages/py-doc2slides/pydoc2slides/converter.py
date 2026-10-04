import os
import re
from pathlib import Path
from typing import Optional, List, Dict, Any

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

from .pylogkit import setup_logging

logger = setup_logging(name="Doc2Slides", to_console=True, to_file=False)

class SlidesConverter:
    """
    Converts Markdown technical documentation into PowerPoint (.pptx) presentation decks.
    Improved functioning based on createdocs learnings.
    """

    def __init__(self, template_path: Optional[Path] = None):
        self.template_path = Path(template_path) if template_path else None

    def _split_into_slides(self, md_content: str) -> List[Dict[str, Any]]:
        """
        Splits Markdown content into individual slides using '---' rules or '#' headers.
        """
        raw_slides = re.split(r"\n---\n", md_content)
        slides_data = []

        for idx, raw in enumerate(raw_slides):
            raw = raw.strip()
            if not raw:
                continue

            lines = raw.splitlines()
            title = f"Slide {idx + 1}"
            body_lines = []

            # Extract title if present
            for i, line in enumerate(lines):
                if line.startswith("#"):
                    title = re.sub(r"^#+\s*", "", line).strip()
                    body_lines = lines[i+1:]
                    break
            else:
                body_lines = lines

            slides_data.append({
                "title": title,
                "lines": body_lines,
                "is_title_slide": (idx == 0)
            })

        return slides_data

    def convert_file(self, md_path: Path, output_path: Path) -> Path:
        md_path = Path(md_path).resolve()
        output_path = Path(output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if not md_path.exists():
            raise FileNotFoundError(f"Markdown file not found: {md_path}")

        logger.info(f"Converting Markdown '{md_path.name}' -> PowerPoint '{output_path.name}'...")

        if self.template_path and self.template_path.exists():
            prs = Presentation(str(self.template_path))
            logger.info(f"Loaded reference PowerPoint template: {self.template_path.name}")
        else:
            prs = Presentation()

        md_content = md_path.read_text(encoding="utf-8")
        slides = self._split_into_slides(md_content)

        blank_slide_layout = prs.slide_layouts[6] if len(prs.slide_layouts) > 6 else prs.slide_layouts[0]
        title_slide_layout = prs.slide_layouts[0]
        content_slide_layout = prs.slide_layouts[1] if len(prs.slide_layouts) > 1 else prs.slide_layouts[0]

        for s_idx, slide_info in enumerate(slides):
            title_text = slide_info["title"]
            lines = slide_info["lines"]

            if s_idx == 0:
                # Title slide
                slide = prs.slides.add_slide(title_slide_layout)
                title = slide.shapes.title
                subtitle = slide.placeholders[1] if len(slide.placeholders) > 1 else None

                if title:
                    title.text = title_text
                if subtitle:
                    subtitle.text = "\n".join([l.strip() for l in lines if l.strip()][:3])
            else:
                # Content slide
                slide = prs.slides.add_slide(content_slide_layout)
                title = slide.shapes.title
                if title:
                    title.text = title_text

                # Body text box / code fence check
                content_shape = slide.placeholders[1] if len(slide.placeholders) > 1 else None
                if content_shape:
                    tf = content_shape.text_frame
                    tf.word_wrap = True
                    tf.clear()

                    in_code = False
                    code_buf = []

                    for line in lines:
                        stripped = line.strip()

                        if stripped.startswith("```"):
                            if in_code:
                                # End code
                                p = tf.add_paragraph()
                                p.text = "\n".join(code_buf)
                                p.font.name = "Consolas"
                                p.font.size = Pt(11)
                                p.font.color.rgb = RGBColor(30, 41, 59)
                                code_buf = []
                                in_code = False
                            else:
                                in_code = True
                                code_buf = []
                            continue

                        if in_code:
                            code_buf.append(line)
                            continue

                        if stripped.startswith("- ") or stripped.startswith("* "):
                            p = tf.add_paragraph()
                            p.text = stripped[2:]
                            p.level = 0
                        elif stripped:
                            p = tf.add_paragraph()
                            p.text = stripped
                            p.level = 0

        prs.save(str(output_path))
        logger.info(f"Successfully generated PowerPoint presentation ({len(slides)} slides): {output_path}")
        return output_path
