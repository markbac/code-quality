"""pytest hooks shared by the whole suite."""

import os


def pytest_sessionfinish(session, exitstatus):
    """FWLENS_FAIL_ON_SKIP=1 (set in CI) turns any skipped test into a failed run.

    A parser test that skips silently stops guarding anything (#70). Skips in CI must be a
    deliberate decision, so they fail the job instead of staying green.
    """
    if not os.environ.get("FWLENS_FAIL_ON_SKIP"):
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    skipped = reporter.stats.get("skipped", []) if reporter else []
    if skipped and session.exitstatus == 0:
        session.exitstatus = 1
        if reporter:
            reporter.write_line(f"FWLENS_FAIL_ON_SKIP: {len(skipped)} test(s) were skipped", red=True)
