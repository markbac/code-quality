"""
PR / MR quality check (issue #52).

Compare the findings of the current checkout with a reference (usually the target branch),
classify each as new, worsened, unchanged, moved, uncertain or resolved using the stable
identity in fwlens.identity, and render one Markdown comment. The same comparison and
Markdown are used for GitHub and GitLab, only the posting differs.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from fwlens.baseline import Breach
from fwlens.identity import SCHEME, MatchResult, match_findings, migrate_legacy_id

MARKER = "<!-- fwlens-pr-check -->"
FINDINGS_VERSION = 1


# ---------------------------------------------------------------------------
# Findings files (the reference format)
# ---------------------------------------------------------------------------

def write_findings(path: Path, breaches: list[Breach], footprint: dict | None = None) -> None:
    """Write current findings with fingerprints, for use as a reference by a later run."""
    try:
        from importlib.metadata import version
        tool_version = version("fwlens")
    except Exception:
        tool_version = "unknown"
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": FINDINGS_VERSION,
        "scheme": SCHEME,
        "tool_version": tool_version,
        "findings": [b.to_dict() for b in breaches],
    }
    if footprint:
        payload["footprint"] = {"flash_bytes": footprint.get("flash_bytes", 0),
                                "ram_bytes": footprint.get("ram_bytes", 0)}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")


def load_reference(path: Path) -> list[dict]:
    """Read a findings file, or a baseline.json (its ``accepted`` list), as reference entries."""
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    entries = raw.get("findings")
    if entries is None:
        entries = raw.get("accepted")
    if entries is None:
        raise ValueError(f"{path} is neither a findings file nor a baseline (no 'findings' or 'accepted')")
    return [migrate_legacy_id(e) for e in entries]


def load_footprint(path: Path) -> dict | None:
    """The {flash_bytes, ram_bytes} recorded in a findings file, or None."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f).get("footprint")
    except (OSError, ValueError, AttributeError):
        return None


def breaches_from_entries(entries: list[dict]) -> list[Breach]:
    out = []
    for e in entries:
        out.append(Breach(e["id"], e.get("kind", "function"), e["file"], e["metric"], e["value"],
                          e["threshold"], line=e.get("line"), function=e.get("function"),
                          fingerprint=e.get("fingerprint", {}), category=e.get("category"),
                          description=e.get("description")))
    return out


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

@dataclass
class Comparison:
    result: MatchResult
    base_total: int
    current_total: int
    gating: list = field(default_factory=list)      # Match objects that fail the check
    uncertain_gates: bool = False
    reference_missing: bool = False                 # no reference results: nothing to compare with
    base_footprint: dict | None = None              # {flash_bytes, ram_bytes} of the reference, if recorded
    current_footprint: dict | None = None
    max_flash_growth: int | None = None
    max_ram_growth: int | None = None

    @property
    def new(self):
        return [m for m in self.result.matches if m.status == "new"]

    @property
    def worsened(self):
        return [m for m in self.result.matches if m.status != "new" and m.worsened]

    @property
    def improved(self):
        return [m for m in self.result.matches if m.base is not None and m.improved and m.tier != "contained"]

    @property
    def moved(self):
        return [m for m in self.result.matches if m.status == "moved"]

    @property
    def uncertain(self):
        return [m for m in self.result.matches if m.status == "uncertain"]

    @property
    def unchanged(self):
        return [m for m in self.result.matches if m.status == "unchanged"]

    @property
    def resolved(self):
        return self.result.resolved

    def growth(self, key: str) -> int | None:
        if not self.base_footprint or not self.current_footprint:
            return None
        return self.current_footprint.get(key, 0) - self.base_footprint.get(key, 0)

    @property
    def footprint_failures(self) -> list[str]:
        out = []
        for key, label, limit in (("flash_bytes", "Flash", self.max_flash_growth),
                                  ("ram_bytes", "RAM", self.max_ram_growth)):
            g = self.growth(key)
            if limit is not None and g is not None and g > limit:
                out.append(f"{label} grew by {g} B, over the limit of {limit} B")
        return out

    @property
    def passed(self) -> bool:
        return not self.gating and not self.footprint_failures


def no_reference(current: list[Breach]) -> Comparison:
    return Comparison(result=MatchResult(), base_total=0, current_total=len(current), reference_missing=True)


def compare(current: list[Breach], reference: list[dict], *, uncertain_gates: bool = False,
            similarity: float = 0.85) -> Comparison:
    result = match_findings(current, reference, similarity=similarity)
    return Comparison(
        result=result, base_total=len(reference), current_total=len(current),
        gating=result.gating(uncertain_gates), uncertain_gates=uncertain_gates,
    )


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _delta(base: int, cur: int) -> str:
    d = cur - base
    return f"{base} -> {cur} ({'+' if d > 0 else ''}{d})"


def _loc(b) -> str:
    where = b.file + (f":{b.line}" if getattr(b, "line", None) else "")
    return f"`{where}`"


def _name(b) -> str:
    return getattr(b, "function", None) or b.file


def render_markdown(c: Comparison, *, max_items: int = 20, report_url: str | None = None,
                    base_label: str = "base") -> str:
    if c.reference_missing:
        out = [MARKER, "## FWLens quality check: no comparison", "",
               (f"No reference results were found for {base_label}, so this change cannot be compared "
               f"and the check does not fail. The current checkout has {c.current_total} finding(s)."),
               "", ("Publish a findings file from the target branch pipeline "
               "(`fwlens analyze --findings-json findings.json`) and pass it with `--base`.")]
        if report_url:
            out += ["", f"[Full report]({report_url})"]
        return "\n".join(out) + "\n"
    lines = [MARKER, f"## FWLens quality check: {'PASS' if c.passed else 'FAIL'}", ""]
    if not c.gating:
        lines.append("No new or worsened findings compared with " + base_label + ".")
    else:
        lines.append(f"{len(c.gating)} new or worsened finding(s) compared with {base_label}.")
    for failure in c.footprint_failures:
        lines.append(f"**{failure}.**")
    lines += ["", "| | |", "|---|---|",
              f"| Findings | {_delta(c.base_total, c.current_total)} |",
              f"| New | {len(c.new)} |",
              f"| Worsened | {len(c.worsened)} |",
              f"| Improved | {len(c.improved)} |",
              f"| Resolved | {len(c.resolved)} |",
              f"| Moved or renamed | {len(c.moved)} |",
              f"| Matched loosely | {len(c.uncertain)} |"]
    for key, label in (("flash_bytes", "Flash (bytes)"), ("ram_bytes", "RAM (bytes)")):
        if c.growth(key) is not None:
            lines.append(f"| {label} | {_delta(c.base_footprint[key], c.current_footprint[key])} |")
    lines.append("")

    gating = c.gating
    if gating:
        lines += ["### New and worsened", "", "| Where | Function | Metric | Value | Threshold | Was |",
                  "|---|---|---|---|---|---|"]
        for m in gating[:max_items]:
            b = m.current
            was = f"{m.base['value']:g}" if m.base else "new"
            if b.kind == "rule":
                lines.append(f"| {_loc(b)} | {_name(b)} | {b.metric} ({b.category}) | violation | - | {was if m.base else 'new'} |")
            else:
                lines.append(f"| {_loc(b)} | {_name(b)} | {b.metric} | {b.value:g} | {b.threshold:g} | {was} |")
        if len(gating) > max_items:
            lines.append(f"\n... and {len(gating) - max_items} more.")
        lines.append("")

    def details(title: str, rows: list[str]) -> None:
        if rows:
            lines.append(f"<details><summary>{title} ({len(rows)})</summary>\n")
            lines.extend(rows[:max_items * 2])
            if len(rows) > max_items * 2:
                lines.append(f"- ... and {len(rows) - max_items * 2} more")
            lines.append("\n</details>\n")

    details("Resolved", [f"- {e.get('file')} `{e.get('function') or e.get('metric')}` {e.get('metric')}"
                         for e in c.resolved])
    details("Moved or renamed (not counted as new)",
            [f"- {m.current.metric} `{m.base.get('function') or ''}` in {m.base['file']}"
             f" -> `{_name(m.current)}` in {m.current.file}" for m in c.moved])
    details("Matched loosely (edited or split, gated only if worse)",
            [f"- {m.current.metric} `{_name(m.current)}`: {m.note}" for m in c.uncertain])

    if report_url:
        lines.append(f"[Full report]({report_url})")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Posting
# ---------------------------------------------------------------------------

class PostError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


Request = Callable[[str, str, dict, dict | None], tuple[int, object]]


def _http(method: str, url: str, headers: dict, body: dict | None) -> tuple[int, object]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in {**headers, "Content-Type": "application/json", "User-Agent": "fwlens"}.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raise PostError(f"{method} {url} failed: HTTP {e.code}", e.code) from e
    except urllib.error.URLError as e:
        raise PostError(f"{method} {url} failed: {e.reason}") from e


def _find_marked(request: Request, list_url: str, headers: dict, body_key: str) -> dict | None:
    page = 1
    while True:
        _status, items = request("GET", f"{list_url}{'&' if '?' in list_url else '?'}per_page=100&page={page}",
                                headers, None)
        if not items:
            return None
        for item in items:
            if MARKER in (item.get(body_key) or ""):
                return item
        if len(items) < 100:
            return None
        page += 1


def post_github(markdown: str, *, update_existing: bool = True, pr: int | None = None,
                env=None, request: Request = _http) -> str:
    env = os.environ if env is None else env
    token, repo = env.get("GITHUB_TOKEN"), env.get("GITHUB_REPOSITORY")
    api = env.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    if pr is None:
        event = env.get("GITHUB_EVENT_PATH")
        if event and Path(event).exists():
            pr = (json.loads(Path(event).read_text()).get("pull_request") or {}).get("number")
    if not (token and repo and pr):
        raise PostError("GitHub posting needs GITHUB_TOKEN, GITHUB_REPOSITORY and a pull request number")
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    base = f"{api}/repos/{repo}/issues"
    existing = _find_marked(request, f"{base}/{pr}/comments", headers, "body") if update_existing else None
    if existing:
        request("PATCH", f"{base}/comments/{existing['id']}", headers, {"body": markdown})
        return "updated"
    request("POST", f"{base}/{pr}/comments", headers, {"body": markdown})
    return "created"


def post_gitlab(markdown: str, *, update_existing: bool = True, mr: int | None = None,
                env=None, request: Request = _http) -> str:
    env = os.environ if env is None else env
    api, project = env.get("CI_API_V4_URL"), env.get("CI_PROJECT_ID")
    mr = mr or (int(env["CI_MERGE_REQUEST_IID"]) if env.get("CI_MERGE_REQUEST_IID") else None)
    if env.get("GITLAB_TOKEN"):
        headers = {"PRIVATE-TOKEN": env["GITLAB_TOKEN"]}
    elif env.get("CI_JOB_TOKEN"):
        headers = {"JOB-TOKEN": env["CI_JOB_TOKEN"]}
    else:
        headers = {}
    if not (api and project and mr and headers):
        raise PostError("GitLab posting needs CI_API_V4_URL, CI_PROJECT_ID, a merge request IID "
                        "and GITLAB_TOKEN (or CI_JOB_TOKEN)")
    base = f"{api.rstrip('/')}/projects/{project}/merge_requests/{mr}/notes"
    existing = _find_marked(request, base, headers, "body") if update_existing else None
    if existing:
        request("PUT", f"{base}/{existing['id']}", headers, {"body": markdown})
        return "updated"
    request("POST", base, headers, {"body": markdown})
    return "created"


def post_status(state_ok: bool, description: str, *, env=None, request: Request = _http) -> str:
    """Set a commit status named 'fwlens' on the PR head (GitHub) or the pipeline commit (GitLab)."""
    env = os.environ if env is None else env
    platform = detect_platform(env)
    description = description[:140]
    if platform == "github":
        token, repo = env.get("GITHUB_TOKEN"), env.get("GITHUB_REPOSITORY")
        sha = env.get("GITHUB_SHA")
        event = env.get("GITHUB_EVENT_PATH")
        if event and Path(event).exists():
            sha = ((json.loads(Path(event).read_text()).get("pull_request") or {}).get("head") or {}).get("sha") or sha
        if not (token and repo and sha):
            raise PostError("GitHub status needs GITHUB_TOKEN (statuses: write), GITHUB_REPOSITORY and a commit sha")
        api = env.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
        request("POST", f"{api}/repos/{repo}/statuses/{sha}",
                {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"},
                {"state": "success" if state_ok else "failure", "context": "fwlens", "description": description})
        return "github"
    if platform == "gitlab":
        api, project, sha = env.get("CI_API_V4_URL"), env.get("CI_PROJECT_ID"), env.get("CI_COMMIT_SHA")
        token = env.get("GITLAB_TOKEN")
        if not (api and project and sha and token):
            raise PostError("GitLab status needs CI_API_V4_URL, CI_PROJECT_ID, CI_COMMIT_SHA and GITLAB_TOKEN")
        request("POST", f"{api.rstrip('/')}/projects/{project}/statuses/{sha}",
                {"PRIVATE-TOKEN": token},
                {"state": "success" if state_ok else "failed", "name": "fwlens", "description": description})
        return "gitlab"
    raise PostError("A commit status can only be set from GitHub Actions or GitLab CI")


def detect_platform(env=None) -> str | None:
    env = os.environ if env is None else env
    if env.get("GITHUB_ACTIONS", "").lower() == "true":
        return "github"
    if env.get("GITLAB_CI", "").lower() == "true":
        return "gitlab"
    return None


def write_github_step_summary(markdown: str, env=None) -> bool:
    env = os.environ if env is None else env
    target = env.get("GITHUB_STEP_SUMMARY")
    if not target:
        return False
    with open(target, "a", encoding="utf-8") as f:
        f.write(markdown + "\n")
    return True


# ---------------------------------------------------------------------------
# Reference from a git ref (fallback when no artifact is available)
# ---------------------------------------------------------------------------

def findings_at_ref(config_path: Path, ref: str, repo_root: Path) -> list[dict]:
    """Run FWLens on the merge-base of HEAD and ``ref`` in a temporary worktree."""
    def git(*args: str) -> str:
        out = subprocess.run(["git", "-C", str(repo_root), *args], capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {out.stderr.strip()}")
        return out.stdout.strip()

    base_sha = git("merge-base", "HEAD", ref)
    tmp = Path(tempfile.mkdtemp(prefix="fwlens-base-"))
    worktree = tmp / "wt"
    git("worktree", "add", "--detach", str(worktree), base_sha)
    try:
        rel = Path(config_path).resolve().relative_to(Path(repo_root).resolve())
        out_file = tmp / "findings.json"
        proc = subprocess.run(
            # -I keeps the project's own files (cwd) off the import path, and the installed
            # FWLens (this version) analyses the old source, not the old FWLens.
            [sys.executable, "-I", "-m", "fwlens", "analyze", "--config", str(worktree / rel),
             "--findings-json", str(out_file)],
            cwd=worktree, capture_output=True, text=True,
        )
        if not out_file.exists():
            raise RuntimeError(f"analysis of merge-base {base_sha[:10]} produced no findings:\n"
                               f"{proc.stdout[-800:]}\n{proc.stderr[-800:]}")
        return load_reference(out_file)
    finally:
        subprocess.run(["git", "-C", str(repo_root), "worktree", "remove", "--force", str(worktree)],
                       capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)
