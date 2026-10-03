"""
PR / MR quality check (#52): comparison, Markdown and posting to GitHub and GitLab.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from click.testing import CliRunner

import main as fwlens_main
from fwlens.baseline import Breach, _assign_ordinals
from fwlens.identity import body_fingerprint
from fwlens.pr_check import (
    MARKER, PostError, breaches_from_entries, compare, detect_platform, load_reference, no_reference,
    post_github, post_gitlab, render_markdown, write_findings, write_github_step_summary,
)

BODY = """
int f(int a, int b)
{
    int t = 0;
    for (int i = 0; i < a; i++) {
        if (i % 2 == 0 && b > 0) { t += helper(i, b); } else if (i > 10 || b < 0) { t -= 1; }
    }
    return t;
}
"""


def fb(file="src/a.c", name="f", value=20.0, source=BODY, metric="cyclomatic_complexity", line=3):
    b = Breach("", "function", file, metric, value, 15.0, line=line, function=name,
               fingerprint=body_fingerprint(source))
    _assign_ordinals([b])
    return b


def entries(*bs):
    return [b.to_dict() for b in bs]


# --- comparison and Markdown ------------------------------------------------------

def test_new_finding_fails_and_is_listed():
    other = "int g(void)\n{\n    while (flag) { poll_unique_device(); }\n    return 0;\n}\n"
    c = compare([fb(), fb(name="g", source=other)], entries(fb()))
    assert not c.passed and len(c.new) == 1 and len(c.unchanged) == 1
    md = render_markdown(c)
    assert md.startswith(MARKER) and "FWLens quality check: FAIL" in md
    assert "| `src/a.c:3` | g | cyclomatic_complexity | 20 | 15 | new |" in md


def test_refactor_move_is_not_reported_as_new_or_resolved():
    c = compare([fb(file="src/util/b.c")], entries(fb(file="src/a.c")))
    assert c.passed and len(c.moved) == 1 and c.new == [] and c.resolved == []
    md = render_markdown(c)
    assert "PASS" in md and "Moved or renamed (not counted as new) (1)" in md
    assert "in src/a.c" in md and "in src/util/b.c" in md


def test_worsened_and_improved_and_resolved_are_reported():
    gone = fb(name="gone", source="int gone(void)\n{\n    return rare_unique_thing();\n}\n")
    c = compare([fb(value=30)], entries(fb(value=20), gone))
    assert len(c.worsened) == 1 and len(c.resolved) == 1 and not c.passed
    better = compare([fb(value=17)], entries(fb(value=20)))
    assert len(better.improved) == 1 and better.passed
    assert "Resolved (1)" in render_markdown(c)


def test_delta_row_and_item_limit():
    many = [fb(name=f"fn{i}", source=f"int fn{i}(void)\n{{\n    return unique_call_{i}({i});\n}}\n") for i in range(30)]
    md = render_markdown(compare(many, []), max_items=5)
    assert "| Findings | 0 -> 30 (+30) |" in md and "... and 25 more." in md


def test_missing_reference_is_a_clear_non_failing_comment():
    c = no_reference([fb()])
    assert c.passed
    md = render_markdown(c)
    assert "no comparison" in md and "--findings-json" in md and md.startswith(MARKER)


def test_findings_file_roundtrip_and_baseline_format(tmp_path):
    path = tmp_path / "findings.json"
    write_findings(path, [fb()])
    loaded = load_reference(path)
    assert loaded[0]["fingerprint"]["body_hash"] and loaded[0]["function"] == "f"
    assert breaches_from_entries(loaded)[0].line == 3
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"accepted": entries(fb())}))
    assert load_reference(baseline)[0]["id"] == "src/a.c:f:cyclomatic_complexity"
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    with pytest.raises(ValueError):
        load_reference(bad)


def test_report_url_is_linked():
    assert "[Full report](https://ci/x)" in render_markdown(compare([fb()], entries(fb())), report_url="https://ci/x")


# --- posting against a local fake API ----------------------------------------------

class Api:
    def __init__(self, existing=None, status=200):
        self.calls, self.existing, self.status = [], existing or [], status
        api = self

        class Handler(BaseHTTPRequestHandler):
            def _do(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length)) if length else None
                api.calls.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}, body))
                code = api.status
                payload = api.existing if self.command == "GET" else {"id": 99}
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PATCH = do_PUT = _do

            def log_message(self, *a):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()


@pytest.fixture
def api():
    made = []

    def make(**kw):
        a = Api(**kw)
        made.append(a)
        return a
    yield make
    for a in made:
        a.close()


def gh_env(api):
    return {"GITHUB_TOKEN": "tok", "GITHUB_REPOSITORY": "o/r", "GITHUB_API_URL": api.url}


def test_github_creates_a_comment_when_none_exists(api):
    a = api()
    assert post_github(MARKER + "\nbody", pr=7, env=gh_env(a)) == "created"
    verbs = [(c[0], c[1].split("?")[0]) for c in a.calls]
    assert verbs == [("GET", "/repos/o/r/issues/7/comments"), ("POST", "/repos/o/r/issues/7/comments")]
    assert a.calls[1][2]["authorization"] == "Bearer tok"


def test_github_updates_the_existing_marked_comment(api):
    a = api(existing=[{"id": 1, "body": "someone else"}, {"id": 42, "body": MARKER + "\nold"}])
    assert post_github(MARKER + "\nnew", pr=7, env=gh_env(a)) == "updated"
    assert a.calls[-1][0] == "PATCH" and a.calls[-1][1] == "/repos/o/r/issues/comments/42"
    assert a.calls[-1][3] == {"body": MARKER + "\nnew"}


def test_github_pr_number_comes_from_the_event_file(api, tmp_path):
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 12}}))
    a = api()
    post_github("x", env={**gh_env(a), "GITHUB_EVENT_PATH": str(event)})
    assert a.calls[-1][1] == "/repos/o/r/issues/12/comments"


def test_github_no_update_always_creates(api):
    a = api(existing=[{"id": 42, "body": MARKER}])
    assert post_github("x", pr=7, update_existing=False, env=gh_env(a)) == "created"
    assert [c[0] for c in a.calls] == ["POST"]


def test_missing_credentials_are_reported_not_crashed():
    with pytest.raises(PostError, match="GITHUB_TOKEN"):
        post_github("x", pr=7, env={})
    with pytest.raises(PostError, match="CI_API_V4_URL"):
        post_gitlab("x", mr=3, env={})


def test_gitlab_create_and_update(api):
    a = api()
    env = {"CI_API_V4_URL": a.url + "/api/v4", "CI_PROJECT_ID": "5", "CI_MERGE_REQUEST_IID": "3",
           "GITLAB_TOKEN": "glpat"}
    assert post_gitlab("x", env=env) == "created"
    assert a.calls[-1][1] == "/api/v4/projects/5/merge_requests/3/notes"
    assert a.calls[-1][2]["private-token"] == "glpat"
    b = api(existing=[{"id": 8, "body": MARKER + " old"}])
    env["CI_API_V4_URL"] = b.url + "/api/v4"
    assert post_gitlab("y", env=env) == "updated"
    assert b.calls[-1][0] == "PUT" and b.calls[-1][1].endswith("/notes/8")


def test_gitlab_job_token_is_used_when_no_private_token(api):
    a = api()
    env = {"CI_API_V4_URL": a.url + "/api/v4", "CI_PROJECT_ID": "5", "CI_MERGE_REQUEST_IID": "3",
           "CI_JOB_TOKEN": "jt"}
    post_gitlab("x", env=env)
    assert a.calls[-1][2]["job-token"] == "jt"


def test_http_failure_surfaces_status(api):
    a = api(status=403)
    with pytest.raises(PostError) as exc:
        post_github("x", pr=7, env=gh_env(a))
    assert exc.value.status == 403


def test_platform_detection_and_step_summary(tmp_path):
    assert detect_platform({"GITHUB_ACTIONS": "true"}) == "github"
    assert detect_platform({"GITLAB_CI": "true"}) == "gitlab"
    assert detect_platform({}) is None
    target = tmp_path / "summary.md"
    assert write_github_step_summary("hello", {"GITHUB_STEP_SUMMARY": str(target)}) is True
    assert "hello" in target.read_text()
    assert write_github_step_summary("hello", {}) is False


# --- CLI ------------------------------------------------------------------------------

def _files(tmp_path, base, current):
    b, c = tmp_path / "base.json", tmp_path / "current.json"
    write_findings(b, base)
    write_findings(c, current)
    cfg = tmp_path / "config.yaml"
    cfg.write_text("project:\n  source_dir: .\n")
    return ["--config", str(cfg), "--base", str(b), "--current", str(c)]


def test_compare_command_gates_only_when_asked(tmp_path):
    other = "int g(void)\n{\n    while (flag) { poll_unique_device(); }\n    return 0;\n}\n"
    args = _files(tmp_path, [fb()], [fb(), fb(name="g", source=other)])
    runner = CliRunner()
    assert runner.invoke(fwlens_main.cli, ["compare", *args]).exit_code == 0
    res = runner.invoke(fwlens_main.cli, ["compare", *args, "--fail-on-new", "--markdown", str(tmp_path / "c.md")])
    assert res.exit_code == 1 and "FAIL" in res.output
    assert (tmp_path / "c.md").read_text().startswith(MARKER)


def test_compare_command_with_a_missing_base_does_not_fail(tmp_path):
    args = _files(tmp_path, [fb()], [fb()])
    args[3] = str(tmp_path / "does-not-exist.json")
    res = CliRunner().invoke(fwlens_main.cli, ["compare", *args, "--fail-on-new"])
    assert res.exit_code == 0 and "no comparison" in res.output


def test_pr_comment_dry_run_posts_nothing(tmp_path, api):
    a = api()
    args = _files(tmp_path, [fb()], [fb()])
    env = {**gh_env(a), "GITHUB_ACTIONS": "true"}
    res = CliRunner().invoke(fwlens_main.cli, ["pr-comment", *args, "--dry-run", "--pr", "4"], env=env)
    assert res.exit_code == 0 and "FWLens quality check" in res.output and a.calls == []


def test_pr_comment_posts_to_github(tmp_path, api):
    a = api()
    args = _files(tmp_path, [fb()], [fb()])
    env = {**gh_env(a), "GITHUB_ACTIONS": "true"}
    res = CliRunner().invoke(fwlens_main.cli, ["pr-comment", *args, "--pr", "4"], env=env)
    assert res.exit_code == 0, res.output
    assert a.calls[-1][0] == "POST" and a.calls[-1][1] == "/repos/o/r/issues/4/comments"


def test_pr_comment_falls_back_to_the_job_summary_when_the_token_is_read_only(tmp_path, api):
    a = api(status=403)
    summary = tmp_path / "summary.md"
    args = _files(tmp_path, [fb()], [fb()])
    env = {**gh_env(a), "GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": str(summary)}
    res = CliRunner().invoke(fwlens_main.cli, ["pr-comment", *args, "--pr", "4"], env=env)
    assert res.exit_code == 0 and "Could not post" in res.output
    assert MARKER in summary.read_text()
