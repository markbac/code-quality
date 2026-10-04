"""
main.py -- CLI entrypoint wrapper for fwlens
"""

from fwlens import __version__
from fwlens.cli.commands import (
    cli,
    main,
    _run_pipeline,
    _handle_baseline,
    _parse_health_failed,
    emit_github_annotations,
)

if __name__ == "__main__":
    cli()