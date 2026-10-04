from setuptools import setup, find_packages

setup(
    name="py-doclint",
    version="0.1.0",
    description="Technical Writing Style & Glossary Validator Toolkit",
    author="Mark Bacon",
    packages=find_packages(),
    install_requires=[
        "colorlog>=6.7.0"
    ],
    entry_points={
        "console_scripts": [
            "py-doclint=pydoclint.cli:main",
        ],
    },
    python_requires=">=3.9",
)
