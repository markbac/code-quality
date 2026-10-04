"""
main.py -- CLI entrypoint wrapper for fwlens
"""

import sys
from fwlens import __version__
import fwlens.cli.commands as _commands

cli = _commands.cli
main = _commands.main

def __getattr__(name: str):
    return getattr(_commands, name)

def __setattr__(name: str, value):
    setattr(_commands, name, value)

if __name__ == "__main__":
    cli()