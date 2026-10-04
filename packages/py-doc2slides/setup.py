from setuptools import setup, find_packages

setup(
    name="py-doc2slides",
    version="0.1.0",
    description="Convert Markdown Technical Documentation to PowerPoint (.pptx) Presentation Decks",
    author="Mark Bacon",
    packages=find_packages(),
    install_requires=[
        "python-pptx>=1.0.0",
        "colorlog>=6.7.0"
    ],
    entry_points={
        "console_scripts": [
            "py-doc2slides=pydoc2slides.cli:main",
        ],
    },
    python_requires=">=3.9",
)
