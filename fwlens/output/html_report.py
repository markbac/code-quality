"""
HTML report generator for fwlens.

Produces a self-contained tabbed HTML report using an inline Jinja2 template.
No external assets required -- everything is inlined.

Tabs:
  Overview     -- summary stats, exceedance probability bars
  Functions    -- sortable/filterable function metrics table
  Modules      -- coupling, instability, zone classification
  Architecture -- layer violation list + stable abstractions scatter plot
  Distributions-- per-metric distribution bars with percentile markers
  Dead Code    -- zero-caller function candidates
  ISR Risk     -- ISR latency risk scores
  Coupling/Cohesion -- high coupling, low cohesion, and both combined
"""

from __future__ import annotations

import base64
import json
import zlib
from pathlib import Path

from jinja2 import Environment, BaseLoader

from fwlens.config import FwLensConfig
from fwlens.model.project import FunctionMetrics, ModuleMetrics, ProjectModel
from fwlens.output.diagrams import (
    generate_architecture_svg_inline, generate_rtos_object_graph_svg_inline,
    generate_state_machine_svg_inline,
)

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>fwlens Report -- {{ meta.ewp }}</title>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a;
    --fg: #d0d4e8;
    --accent: #4f9cf9; --red: #e05c5c; --yellow: #e0b85c;
    --green: #5ce07a; --text: #d0d4e8; --dim: #6b7280;
    --font: 'Segoe UI', system-ui, sans-serif;
    --canvas-bg: #1a1d27;
  }
  :root.light {
    --bg: #f5f6fa; --surface: #ffffff; --border: #dde1ed;
    --fg: #1a1d27;
    --accent: #2563eb; --red: #dc2626; --yellow: #d97706;
    --green: #16a34a; --text: #1e2133; --dim: #6b7280;
    --canvas-bg: #f0f2f8;
  }
  .theme-toggle {
    margin-left: auto; background: var(--surface); border: 1px solid var(--border);
    color: var(--dim); padding: 5px 12px; border-radius: 4px; cursor: pointer;
    font-size: 12px; font-family: var(--font); display: flex; align-items: center; gap: 6px;
  }
  .theme-toggle:hover { color: var(--text); border-color: var(--accent); }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 13px; }
  header { background: var(--surface); border-bottom: 1px solid var(--border);
           padding: 16px 24px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 18px; color: var(--accent); }
  header span { color: var(--dim); font-size: 12px; }
  .topbar { position: sticky; top: 0; z-index: 50; }
  .tabs { display: flex; gap: 0; border-bottom: 1px solid var(--border);
          background: var(--surface); padding: 0 24px; overflow-x: auto; }
  .tab { padding: 10px 18px; cursor: pointer; border-bottom: 2px solid transparent;
         color: var(--dim); font-size: 13px; white-space: nowrap; }
  .tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .tab:hover { color: var(--text); }
  .report-layout { display: flex; align-items: flex-start; }
  .side-nav { width: 200px; flex-shrink: 0; position: sticky;
              top: var(--topbar-h, 96px); max-height: calc(100vh - var(--topbar-h, 96px));
              overflow-y: auto; border-right: 1px solid var(--border);
              padding: 16px 12px; display: none; }
  .side-nav.has-links { display: block; }
  .side-nav-title { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em;
                     color: var(--dim); margin-bottom: 8px; padding: 0 8px; }
  .side-nav a { display: block; padding: 5px 8px; border-radius: 4px; font-size: 12px;
                color: var(--dim); text-decoration: none; line-height: 1.4;
                border-left: 2px solid transparent; }
  .side-nav a:hover { color: var(--text); background: var(--bg); }
  .side-nav a.side-nav-active { color: var(--accent); border-left-color: var(--accent);
                                 background: var(--bg); }
  .pane-wrap { flex: 1; min-width: 0; }
  .pane { display: none; padding: 24px; }
  .pane.active { display: block; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { background: var(--surface); color: var(--dim); text-align: left;
       padding: 7px 10px; border-bottom: 1px solid var(--border); white-space: nowrap; cursor: pointer; }
  th:hover { color: var(--text); }
  td { padding: 6px 10px; border-bottom: 1px solid var(--border); }
  .heatmap-table td, .heatmap-table th { padding: 3px 6px; }
  .score-bar { display: flex; align-items: center; gap: 6px; }
  .score-bar-track { width: 44px; height: 6px; border-radius: 3px; background: var(--border);
                      overflow: hidden; flex-shrink: 0; }
  .score-bar-fill { height: 100%; border-radius: 3px; }
  /* Deepest Include Chains: click a row to expand the actual path */
  .chain-table .chain-toggle { width: 16px; padding-right: 0; }
  .chain-table tr.has-chain { cursor: pointer; }
  .chain-table tr.has-chain:hover td { color: var(--text); }
  .chain-arrow { display: inline-block; font-size: 10px; color: var(--dim); transition: transform 0.15s; }
  .chain-table tr.expanded .chain-arrow { transform: rotate(90deg); }
  tr.chain-detail { display: none; }
  tr.chain-row.expanded + tr.chain-detail { display: table-row; }
  .chain-path { padding: 6px 0 10px; font-size: 11px; line-height: 1.9; color: var(--dim); }
  .chain-hop { color: var(--text); }
  .chain-sep { color: var(--dim); margin: 0 6px; }
  tr:hover td { background: rgba(79,156,249,0.05); }
  .red { color: var(--red); }
  .yellow { color: var(--yellow); }
  .green { color: var(--green); }
  .dim { color: var(--dim); }
  .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 11px; }
  .badge-red    { background: rgba(224,92,92,0.2);   color: var(--red); }
  .badge-yellow { background: rgba(224,184,92,0.2);  color: var(--yellow); }
  .badge-green  { background: rgba(92,224,122,0.2);  color: var(--green); }
  .badge-blue   { background: rgba(79,156,249,0.2);  color: var(--accent); }
  .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
               gap: 12px; margin-bottom: 24px; }
  .stat-card { background: var(--surface); border: 1px solid var(--border);
               border-radius: 6px; padding: 14px; }
  .stat-card .label { color: var(--dim); font-size: 11px; margin-bottom: 4px; }
  .stat-card .value { font-size: 22px; font-weight: 600; color: var(--accent); }
  .footer-etiquette { max-width: 1100px; margin: 24px auto 40px; padding: 14px 18px;
               background: var(--surface); border: 1px solid var(--border); border-radius: 6px;
               font-size: 11px; line-height: 1.7; color: var(--dim); }
  .footer-etiquette strong { color: var(--text); }
  .overview-header { display: flex; align-items: baseline; gap: 16px; margin-bottom: 20px; }
  .overview-project { font-size: 15px; font-weight: 600; color: var(--accent); }
  .overview-config, .overview-scale { font-size: 12px; }
  .issue-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 16px; margin-bottom: 28px; }
  .issue-section { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 14px; }
  .issue-section-title { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--dim); margin-bottom: 10px; }
  .issue-row { display: flex; align-items: center; gap: 8px; padding: 6px 4px; border-radius: 4px; cursor: pointer; font-size: 13px; margin-bottom: 2px; }
  .issue-row:hover { background: var(--border); }
  .issue-icon { width: 16px; text-align: center; flex-shrink: 0; }
  .issue-label { flex: 1; color: var(--fg); }
  .issue-count { font-weight: 600; font-size: 14px; min-width: 28px; text-align: right; }
  .issue-red .issue-icon, .issue-red .issue-count { color: var(--red); }
  .issue-yellow .issue-icon, .issue-yellow .issue-count { color: var(--yellow); }
  .issue-ok .issue-icon, .issue-ok .issue-count { color: var(--green); }
  .issue-info .issue-icon, .issue-info .issue-count { color: var(--dim); }
  .section-title { font-size: 14px; font-weight: 600; margin: 20px 0 10px; color: var(--accent); }
  .exceedance-bar { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
  .bar-track { flex: 1; background: var(--border); border-radius: 3px; height: 8px; }
  .bar-fill { height: 8px; border-radius: 3px; }
  .filter-row { display: flex; gap: 8px; margin-bottom: 12px; }
  input[type=text] { background: var(--surface); border: 1px solid var(--border);
                     color: var(--text); padding: 5px 10px; border-radius: 4px;
                     font-size: 12px; width: 260px; }
  input[type=text]::placeholder { color: var(--dim); }
  /* Scatter plot */
  .scatter-wrap { display: flex; gap: 24px; align-items: flex-start; flex-wrap: wrap; }
  .scatter-container { position: relative; }
  canvas { border: 1px solid var(--border); border-radius: 6px; background: var(--canvas-bg); }
  /* Distribution bars */
  .dist-metric { margin-bottom: 20px; }
  .dist-label { font-size: 12px; color: var(--dim); margin-bottom: 6px; }
  .dist-bar-row { display: flex; align-items: center; gap: 8px; margin-bottom: 3px; }
  .dist-bar-label { width: 40px; font-size: 11px; color: var(--dim); text-align: right; }
  .dist-bar-track { flex: 1; background: var(--border); border-radius: 2px; height: 14px;
                    position: relative; }
  .dist-bar-fill { height: 14px; border-radius: 2px; position: absolute; left: 0; top: 0; }
  .dist-threshold { position: absolute; top: 0; bottom: 0; width: 2px;
                    background: var(--red); opacity: 0.8; }
  .dist-stats { font-size: 11px; color: var(--dim); margin-top: 4px; }
  /* Zone legend */
  .zone-legend { display: flex; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
  .zone-item { display: flex; align-items: center; gap: 6px; font-size: 12px; }
  .zone-dot { width: 10px; height: 10px; border-radius: 50%; }
  .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }
  @media (max-width: 900px) { .two-col { grid-template-columns: 1fr; } }
  /* Metric info panels -- sticky so the legend stays reachable regardless of scroll
     position within a tab. Only the FIRST metric-info panel in the active pane gets
     pinned (see buildSideNav() in the script below, which toggles this class) --
     several panes have more than one of these at different depths, and pinning all
     of them at the same offset would just stack them on top of each other as you
     scroll, not keep each one visible in place. Capped + internally scrollable when
     open so an expanded panel can't grow taller than the viewport and swallow the page. */
  details.metric-info { background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; margin-bottom: 20px; }
  details.metric-info.sticky-info { position: sticky; top: var(--topbar-h, 96px); z-index: 40; }
  details.metric-info summary { padding: 9px 14px; cursor: pointer; color: var(--dim);
    font-size: 12px; list-style: none; display: flex; align-items: center; gap: 6px; }
  details.metric-info summary::before { content: '\25B6'; font-size: 9px; transition: transform 0.15s; }
  details.metric-info[open] summary::before { transform: rotate(90deg); }
  details.metric-info summary:hover { color: var(--text); }
  details.metric-info.sticky-info[open] .metric-info-body { max-height: calc(100vh - var(--topbar-h, 96px) - 44px);
    overflow-y: auto; }
  .metric-info-body { padding: 4px 14px 14px; }
  .metric-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; margin-top: 8px; }
  .metric-card { background: var(--bg); border: 1px solid var(--border); border-radius: 5px; padding: 10px 12px; }
  .metric-card .mc-name { font-size: 12px; font-weight: 600; color: var(--accent); margin-bottom: 4px; }
  .metric-card .mc-abbr { font-size: 11px; color: var(--dim); margin-bottom: 5px; }
  .metric-card .mc-desc { font-size: 12px; color: var(--text); line-height: 1.5; }
  .metric-card .mc-thresh { font-size: 11px; color: var(--yellow); margin-top: 5px; }
  .glossary-group { margin-bottom: 28px; }
  .glossary-group-title { font-size: 13px; font-weight: 600; color: var(--text);
    border-bottom: 1px solid var(--border); padding-bottom: 6px; margin-bottom: 12px; }
  /* Code modal */
  .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7);
    z-index: 100; align-items: center; justify-content: center; }
  .modal-overlay.open { display: flex; }
  .modal-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    width: 85vw; max-width: 1100px; height: 80vh; display: flex; flex-direction: column;
    overflow: hidden; }
  .modal-header { display: flex; align-items: center; justify-content: space-between;
    padding: 10px 16px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
  .modal-title { font-size: 13px; color: var(--accent); font-weight: 600; }
  .modal-close { background: none; border: none; color: var(--dim); font-size: 18px;
    cursor: pointer; padding: 0 4px; line-height: 1; }
  .modal-close:hover { color: var(--text); }
  .modal-body { overflow: auto; flex: 1; padding: 0; }
  .code-table { width: 100%; border-collapse: collapse; font-family: 'Cascadia Code','Consolas',monospace;
    font-size: 12px; }
  .code-table td { padding: 1px 0; border: none; white-space: pre; }
  .code-table .ln { width: 48px; min-width: 48px; text-align: right; padding-right: 12px;
    color: var(--dim); user-select: none; border-right: 1px solid var(--border); padding-left: 8px; }
  .code-table .lc { padding-left: 12px; color: var(--text); }
  .code-table tr.hl td { background: rgba(79,156,249,0.12); }
  .code-table tr:hover td { background: rgba(79,156,249,0.07); }
  /* Syntax token colours */
  .tk-kw  { color: #c792ea; }
  .tk-cm  { color: #546e7a; font-style: italic; }
  .tk-str { color: #c3e88d; }
  .tk-num { color: #f78c6c; }
  .tk-pp  { color: #89ddff; }
  .tk-fn  { color: #82aaff; }
  /* Scatter tooltip */
  #scatter-tip { position: fixed; pointer-events: none; display: none;
    background: var(--surface); border: 1px solid var(--border); border-radius: 5px;
    padding: 7px 10px; font-size: 12px; color: var(--text); z-index: 50;
    white-space: nowrap; box-shadow: 0 4px 12px rgba(0,0,0,0.4); }
  #scatter-tip .tip-name { font-weight: 600; color: var(--accent); margin-bottom: 3px; }
  #scatter-tip .tip-row  { color: var(--dim); }
  /* Zone tables below scatter */
  .zone-tables { margin-top: 28px; }
  .clickable { cursor: pointer; color: var(--accent); text-decoration: underline dotted; }
  .clickable:hover { color: var(--text); }
</style>
</head>
<body>
<!-- Code viewer modal -->
<div class="modal-overlay" id="code-modal" onclick="if(event.target===this)closeModal()">
  <div class="modal-box">
    <div class="modal-header">
      <span class="modal-title" id="modal-title"></span>
      <button class="modal-close" onclick="closeModal()">&#10005;</button>
    </div>
    <div class="modal-body"><table class="code-table" id="modal-code"></table></div>
  </div>
</div>
<!-- Scatter hover tooltip -->
<div id="scatter-tip">
  <div class="tip-name" id="tip-name"></div>
  <div class="tip-row" id="tip-vals"></div>
  <div class="tip-row" id="tip-zone"></div>
</div>
<div class="topbar">
<header>
  <h1>fwlens</h1>
  <span>{{ meta.ewp }} &bull; {{ meta.configuration }} &bull;
        {{ meta.module_count }} modules &bull; {{ meta.function_count }} functions &bull;
        {{ meta.total_loc }} LOC</span>
  <button class="theme-toggle" onclick="toggleTheme()" id="theme-btn" title="Toggle light/dark mode">&#9788; Light</button>
</header>
<div class="tabs">
  <div class="tab active" onclick="show('overview', this)">Overview</div>
  <div class="tab" onclick="show('architecture', this)">Architecture</div>
  <div class="tab" onclick="show('modules', this)">Modules</div>
  <div class="tab" onclick="show('functions', this)">Functions</div>
  <div class="tab" onclick="show('fnptrs', this)">Function Pointers</div>
  <div class="tab" onclick="show('distributions', this)">Distributions</div>
  <div class="tab" onclick="show('risk', this)">Risk</div>
  <div class="tab" onclick="show('coupling', this)">Coupling / Cohesion</div>
  <div class="tab" onclick="show('rtos', this)">RTOS &amp; Concurrency</div>
  <div class="tab" onclick="show('gittrends', this)">Change History</div>
  <div class="tab" onclick="show('techdebt', this)">Tech Debt</div>
  <div class="tab" onclick="show('defects', this)">Defects &amp; Estimation</div>
  <div class="tab" onclick="show('parsediag', this)">Parse Diagnostics</div>
  <div class="tab" onclick="show('reference', this)">Metrics Reference</div>
</div>
</div>
<div class="report-layout">
<nav class="side-nav" id="side-nav">
  <div class="side-nav-title">On this page</div>
</nav>
<div class="pane-wrap">

<!-- OVERVIEW -->
<div class="pane active" id="pane-overview">

  {% if meta.diag_error_module_count > 0 %}
  <div style="background:rgba(224,92,92,0.12);border:1px solid var(--red);border-radius:6px;padding:14px 16px;margin-bottom:20px">
    <div style="font-weight:600;color:var(--red);margin-bottom:4px">
      &#9888; Parse Diagnostics: {{ meta.diag_fatal_count }} fatal, {{ meta.diag_error_count }} error(s) across {{ meta.diag_error_module_count }} file(s)
      {% if meta.diag_warning_count > 0 %}<span style="font-weight:400;color:var(--dim)"> -- plus {{ meta.diag_warning_count }} warning(s), see the <span class="clickable" onclick="show('parsediag',document.querySelector('[onclick*=parsediag]'))" style="color:var(--accent)">Parse Diagnostics</span> tab</span>{% endif %}
    </div>
    <div style="font-size:12px;color:var(--dim)">
      A file can report a plausible function count while one specific construct silently failed to parse (a missing
      header, an unresolved macro) -- check the files below before trusting results derived from them. Full detail in
      <code>parse_diagnostics.csv</code>, the JSON export's per-module <code>parse_diagnostics</code> field, or the
      <span class="clickable" onclick="show('parsediag',document.querySelector('[onclick*=parsediag]'))" style="color:var(--accent)">Parse Diagnostics</span> tab.
    </div>
    <table style="margin-top:10px">
      <thead><tr><th>File</th><th>Severity</th><th>Line</th><th>Message</th></tr></thead>
      <tbody>
      {% for d in diagnostic_rows %}
      <tr>
        <td class="dim">{{ d.file_short }}</td>
        <td class="{{ 'red' if d.severity in ['fatal','error'] else 'yellow' }}">{{ d.severity }}</td>
        <td>{{ d.line }}</td>
        <td class="dim">{{ d.message }}{% if d.extra_count > 0 %} <span style="color:var(--dim)">(+{{ d.extra_count }} more)</span>{% endif %}</td>
      </tr>
      {% endfor %}
      </tbody>
    </table>
    {% if meta.diag_error_module_count > diagnostic_rows|length %}
    <div style="font-size:11px;color:var(--dim);margin-top:6px">... and {{ meta.diag_error_module_count - diagnostic_rows|length }} more file(s) -- see parse_diagnostics.csv</div>
    {% endif %}
  </div>
  {% elif meta.diag_warning_count > 0 %}
  <div style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:10px 16px;margin-bottom:20px;font-size:12px;color:var(--dim)">
    &#10003; No parse errors. {{ meta.diag_warning_count }} warning(s) across {{ meta.diag_module_count }} file(s) --
    see the <span class="clickable" onclick="show('parsediag',document.querySelector('[onclick*=parsediag]'))" style="color:var(--accent)">Parse Diagnostics</span> tab.
  </div>
  {% endif %}

  <!-- About fwlens intro -->
  <details class="metric-info" open>
    <summary>About fwlens &mdash; what it does and how to read this report</summary>
    <div class="metric-info-body">

      <p style="margin:8px 0 16px;line-height:1.7;color:var(--text);max-width:900px">
        <strong style="color:var(--accent)">fwlens</strong> is a static analysis platform for embedded C firmware.
        It uses <strong>libclang</strong> to parse your IAR EWP project -- computing structural metrics,
        building a full call graph, and analysing your architecture -- without modifying source or running a build.
        Output is this self-contained HTML report plus CSV and JSON exports.
      </p>

      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:20px 28px;margin-bottom:16px">

        <div>
          <div style="font-size:11px;font-weight:600;color:var(--accent);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.04em">libclang &amp; the AST</div>
          <p style="font-size:12px;line-height:1.7;color:var(--text)">
            libclang is the <strong>Clang compiler front-end</strong> -- the same parser used by Xcode,
            clang-tidy, and VS Code IntelliSense. It produces an <strong>Abstract Syntax Tree (AST)</strong>:
            a structured, typed representation of every construct in your code.
          </p>
          <p style="font-size:12px;line-height:1.7;color:var(--text);margin-top:6px">
            fwlens walks every AST node (<em>cursor</em>) and classifies it by its <em>cursor kind</em>.
            Cyclomatic complexity counts <code>IF_STMT</code> cursor nodes -- not the word <code>if</code>.
            A macro that expands to a branch is counted; a comment containing <code>if</code> is not.
            Halstead operators and operands are derived the same way.
            This is why results differ from text-scanning tools like lizard or ccccc.
          </p>
        </div>

        <div>
          <div style="font-size:11px;font-weight:600;color:var(--accent);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.04em">Call graph &amp; scope</div>
          <p style="font-size:12px;line-height:1.7;color:var(--text)">
            The call graph is built from <code>CALL_EXPR</code> nodes (direct calls) plus synthetic edges
            recovered from function pointer detection (see below).
            Only <code>first_party</code> files appear in metric tables. SDK, RTOS, and library files
            are parsed for type resolution and call edges but not analysed.
            <strong>Fan-in is a lower bound</strong> -- calls from SDK code are not counted.
          </p>
          <p style="font-size:12px;line-height:1.7;color:var(--text);margin-top:6px">
            IAR EWP defines and include paths are fed to libclang via <code>iar_compat_defines</code>
            in the config so it sees exactly what the IAR compiler sees -- including <code>__interrupt</code>,
            <code>__intrinsic</code>, <code>__weak</code>, CMSIS intrinsics, and inline assembly.
            Run <code>.\Run-FwLens.ps1 debug-parse</code> to detect and stub missing headers.
            <strong>Zero parse errors = fully reliable metrics.</strong>
          </p>
        </div>

        <div>
          <div style="font-size:11px;font-weight:600;color:var(--accent);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.04em">Function pointers</div>
          <p style="font-size:12px;line-height:1.7;color:var(--text)">
            A function pointer (<code>table[i].fn(args)</code>) calls a function whose address is stored
            in a variable. The callee is unknown until runtime. Naive analysers cannot build call graph
            edges through them -- functions stored in tables appear to have <strong>zero callers</strong>
            (false dead code).
          </p>
          <p style="font-size:12px;line-height:1.7;color:var(--text);margin-top:6px">
            fwlens recovers these edges by walking global variable initialisers for
            <code>DECL_REF_EXPR&nbsp;&rarr;&nbsp;FUNCTION_DECL</code> references.
            Three patterns are detected:
          </p>
          <ul style="font-size:12px;line-height:1.7;color:var(--text);margin:5px 0 5px 14px">
            <li><strong>Dispatch tables</strong> -- functions in array initialisers
                (e.g. <code>ATCommandTable[]</code>, <code>cmdReadRegisterData[]</code>)</li>
            <li><strong>Vtable structs</strong> -- struct field assignment
                (<code>socket-&gt;ops = &amp;NET_SOCKET_VTABLE</code>)</li>
            <li><strong>Registration chains</strong> -- VAR embedded in VAR
                (<code>UIBatteryChange &rarr; emBatteryChange &rarr; serviceMenuStates[]</code>)</li>
          </ul>
          <p style="font-size:12px;line-height:1.7;color:var(--text);margin-top:4px">
            <strong>Indirect call sites</strong> (<code>CALL_EXPR</code> with no named callee) are counted
            separately. ISR latency estimates are marked <strong>~</strong> when any reachable function
            contains them. Function pointers assigned at <em>runtime</em> cannot be detected.
            See the <span class="clickable" onclick="show('fnptrs',document.querySelector('[onclick*=fnptrs]'))">Function Pointers tab</span>
            for what was detected.
          </p>
        </div>

        <div>
          <div style="font-size:11px;font-weight:600;color:var(--accent);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.04em">Architecture layers</div>
          <p style="font-size:12px;line-height:1.7;color:var(--text)">
            Layers are matched to IAR project group names in <code>fwlens_config.yaml</code>.
            A violation occurs when a module calls into an equal or lower layer in the wrong direction.
            The IAR group tree is the source of truth -- VS Code shows only the filesystem.
            Run <code>.\Run-FwLens.ps1 debug</code> to see how every module is classified.
          </p>
          <p style="font-size:12px;line-height:1.7;color:var(--text);margin-top:6px">
            Unmatched modules are <strong>Unknown</strong> and excluded from violation detection.
            A high Unknown count inflates dead code and suppresses violations --
            resolve these before acting on those results.
          </p>
        </div>

        <div>
          <div style="font-size:11px;font-weight:600;color:var(--accent);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.04em">Dead code &amp; ISRs</div>
          <p style="font-size:12px;line-height:1.7;color:var(--text)">
            Functions with zero in-project callers are flagged as dead code candidates after
            excluding entry points and ISRs. Functions called from SDK code, via OS callbacks,
            linker-retained symbols, or runtime-assigned function pointers will appear dead.
            <strong>Always verify before removing.</strong>
          </p>
          <p style="font-size:12px;line-height:1.7;color:var(--text);margin-top:6px">
            ISR latency risk is a structural estimate: <code>own_CC + transitive_CC_sum + call_depth &times; 2</code>.
            It is not a timing measurement -- it ranks which ISRs have the most complex reachable
            call chains. Non-estimable chains (containing indirect calls) are marked <strong>~</strong>.
          </p>
        </div>

        <div>
          <div style="font-size:11px;font-weight:600;color:var(--accent);margin-bottom:6px;text-transform:uppercase;letter-spacing:0.04em">Risk &amp; Zone of Pain</div>
          <p style="font-size:12px;line-height:1.7;color:var(--text)">
            The <strong>Risk</strong> tab ranks functions by <code>fan_in &times; SDI</code> -- the product
            of blast radius and structural complexity. These are the functions where a defect is both
            hardest to avoid introducing and most damaging when it occurs.
          </p>
          <p style="font-size:12px;line-height:1.7;color:var(--text);margin-top:6px">
            <strong>Zone of Pain</strong> modules score high on a weighted composite of fan-in (35%),
            avg CC (23%), avg Halstead effort (18%), dependency cycles (14%), indirect call sites (7%),
            and magic number density (5%). All components are percentile ranks within the codebase,
            so the score is self-calibrating regardless of project size.
          </p>
        </div>

      </div>

      <div style="background:var(--bg);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:5px;padding:10px 16px;font-size:12px;line-height:1.9">
        <strong style="color:var(--accent)">Where to start &rarr;</strong>
        &nbsp;
        <span class="clickable" onclick="show('risk',document.querySelector('[onclick*=risk]'))"><strong>Risk</strong></span>
        for highest-priority defect risks.
        &nbsp;&bull;&nbsp;
        <span class="clickable" onclick="show('architecture',document.querySelector('[onclick*=architecture]'))"><strong>Architecture</strong></span>
        for layer violations and cycles.
        &nbsp;&bull;&nbsp;
        <span class="clickable" onclick="show('functions',document.querySelector('[onclick*=functions]'))"><strong>Functions</strong></span>
        /
        <span class="clickable" onclick="show('modules',document.querySelector('[onclick*=modules]'))"><strong>Modules</strong></span>
        for detailed drill-down.
        &nbsp;&bull;&nbsp;
        <span class="clickable" onclick="show('fnptrs',document.querySelector('[onclick*=fnptrs]'))"><strong>Function Pointers</strong></span>
        for dispatch tables and indirect chains.
        &nbsp;&bull;&nbsp;
        <span class="clickable" onclick="show('reference',document.querySelector('[onclick*=reference]'))"><strong>Metrics Reference</strong></span>
        explains every column. All names link to source.
      </div>

    </div>
  </details>


  <div class="overview-header">
    <span class="overview-project">{{ meta.ewp }}</span>
    <span class="overview-config dim">{{ meta.configuration }}</span>
    <span class="overview-scale dim">{{ meta.module_count }} modules &bull; {{ meta.function_count }} functions &bull; {{ meta.total_loc }} LOC</span>
  </div>

  <div class="issue-grid">
    <div class="issue-section">
      <div class="issue-section-title">Code Quality</div>
      <div class="issue-row {% if meta.cc_breaches > 0 %}issue-red{% else %}issue-ok{% endif %}" onclick="show('functions', document.querySelector('[onclick*=functions]'))">
        <span class="issue-icon">{% if meta.cc_breaches > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">CC breaches</span>
        <span class="issue-count">{{ meta.cc_breaches }}</span>
      </div>
      <div class="issue-row {% if meta.magic_breaches > 0 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('functions', document.querySelector('[onclick*=functions]'))">
        <span class="issue-icon">{% if meta.magic_breaches > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Magic number density</span>
        <span class="issue-count">{{ meta.magic_breaches }}</span>
      </div>
      <div class="issue-row issue-info" onclick="show('functions', document.querySelector('[onclick*=functions]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Dead candidates</span>
        <span class="issue-count">{{ meta.dead_count }}</span>
      </div>
      <div class="issue-row issue-info" onclick="show('fnptrs', document.querySelector('[onclick*=fnptrs]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Functions with indirect calls</span>
        <span class="issue-count">{{ functions | selectattr('indirect_call_count', 'gt', 0) | list | length }}</span>
      </div>
    </div>

    <div class="issue-section">
      <div class="issue-section-title">Architecture</div>
      <div class="issue-row {% if meta.arch_violations > 0 %}issue-red{% else %}issue-ok{% endif %}" onclick="show('architecture', document.querySelector('[onclick*=architecture]'))">
        <span class="issue-icon">{% if meta.arch_violations > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Layer violations</span>
        <span class="issue-count">{{ meta.arch_violations }}</span>
      </div>
      <div class="issue-row {% if meta.cyclic_modules > 0 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('architecture', document.querySelector('[onclick*=architecture]'))">
        <span class="issue-icon">{% if meta.cyclic_modules > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Cyclic modules</span>
        <span class="issue-count">{{ meta.cyclic_modules }}</span>
      </div>
      <div class="issue-row {% if meta.zone_pain > 10 %}issue-yellow{% else %}issue-info{% endif %}" onclick="show('architecture', document.querySelector('[onclick*=architecture]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Zone of Pain modules</span>
        <span class="issue-count">{{ meta.zone_pain }}</span>
      </div>
      <div class="issue-row {% if meta.unknown_layers > 0 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('modules', document.querySelector('[onclick*=modules]'))">
        <span class="issue-icon">{% if meta.unknown_layers > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Unclassified modules</span>
        <span class="issue-count">{{ meta.unknown_layers }}</span>
      </div>
      <div class="issue-row {% if meta.include_cycle_count > 0 %}issue-red{% else %}issue-ok{% endif %}" onclick="show('architecture', document.querySelector('[onclick*=architecture]'))">
        <span class="issue-icon">{% if meta.include_cycle_count > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Circular / self includes</span>
        <span class="issue-count">{{ meta.include_cycle_count }}</span>
      </div>
      <div class="issue-row {% if meta.missing_guard_count > 0 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('architecture', document.querySelector('[onclick*=architecture]'))">
        <span class="issue-icon">{% if meta.missing_guard_count > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Missing include guards</span>
        <span class="issue-count">{{ meta.missing_guard_count }}</span>
      </div>
      <div class="issue-row issue-info" onclick="show('architecture', document.querySelector('[onclick*=architecture]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Possibly unused includes</span>
        <span class="issue-count">{{ meta.unused_include_count }}</span>
      </div>
    </div>

    <div class="issue-section">
      <div class="issue-section-title">Risk</div>
      <div class="issue-row issue-info" onclick="show('risk', document.querySelector('[onclick*=risk]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Critical functions (fan-in &times; SDI)</span>
        <span class="issue-count">{{ critical_funcs|length }}</span>
      </div>
      <div class="issue-row {% if meta.assert_coverage < 10 %}issue-red{% elif meta.assert_coverage < 30 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('risk', document.querySelector('[onclick*=risk]'))">
        <span class="issue-icon">{% if meta.assert_coverage < 10 %}&#9888;{% else %}&#9432;{% endif %}</span>
        <span class="issue-label">Assert coverage</span>
        <span class="issue-count">{{ meta.assert_coverage }}%</span>
      </div>
      <div class="issue-row {% if meta.stack_over50 > 0 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('risk', document.querySelector('[onclick*=risk]'))">
        <span class="issue-icon">{% if meta.stack_over50 > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Deep call chains (&gt;50 levels)</span>
        <span class="issue-count">{{ meta.stack_over50 }}</span>
      </div>
    </div>

    <div class="issue-section">
      <div class="issue-section-title">Structure</div>
      <div class="issue-row {% if meta.group_dir_mismatches > 0 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('modules', document.querySelector('[onclick*=modules]'))">
        <span class="issue-icon">{% if meta.group_dir_mismatches > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Group/dir mismatches</span>
        <span class="issue-count">{{ meta.group_dir_mismatches }}</span>
      </div>
    </div>

    <div class="issue-section">
      <div class="issue-section-title">Estimation &amp; Trends</div>
      <div class="issue-row {% if meta.reliability_trend == 'climbing' %}issue-red{% elif meta.reliability_trend in ('flattening','plateaued') %}issue-ok{% else %}issue-info{% endif %}" onclick="show('defects', document.querySelector('[onclick*=defects]'))">
        <span class="issue-icon">{% if meta.reliability_trend == 'climbing' %}&#9888;{% elif meta.reliability_trend in ('flattening','plateaued') %}&#10003;{% else %}&#9432;{% endif %}</span>
        <span class="issue-label">Reliability trend</span>
        <span class="issue-count" style="text-transform:capitalize;font-size:14px">{{ meta.reliability_trend.replace('_',' ') }}</span>
      </div>
      <div class="issue-row issue-info" onclick="show('defects', document.querySelector('[onclick*=defects]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Metrics correlated to defects</span>
        <span class="issue-count">{{ meta.defect_correlation_count }}</span>
      </div>
      {% if meta.cost_benefit_savings > 0 %}
      <div class="issue-row issue-info" onclick="show('defects', document.querySelector('[onclick*=defects]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Potential savings (static vs. field)</span>
        <span class="issue-count" style="font-size:14px">${{ "{:,.0f}".format(meta.cost_benefit_savings) }}</span>
      </div>
      {% endif %}
    </div>

    <div class="issue-section">
      <div class="issue-section-title">Tech Debt</div>
      <div class="issue-row {% if meta.todo_count > 0 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('techdebt', document.querySelector('[onclick*=techdebt]'))">
        <span class="issue-icon">{% if meta.todo_count > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">TODO / FIXME / HACK markers</span>
        <span class="issue-count">{{ meta.todo_count }}</span>
      </div>
      <div class="issue-row {% if meta.commented_code_count > 0 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('techdebt', document.querySelector('[onclick*=techdebt]'))">
        <span class="issue-icon">{% if meta.commented_code_count > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Commented-out code blocks</span>
        <span class="issue-count">{{ meta.commented_code_count }}</span>
      </div>
      <div class="issue-row {% if meta.clone_pair_count > 0 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('techdebt', document.querySelector('[onclick*=techdebt]'))">
        <span class="issue-icon">{% if meta.clone_pair_count > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Near-duplicate function pairs</span>
        <span class="issue-count">{{ meta.clone_pair_count }}</span>
      </div>
      <div class="issue-row {% if meta.race_risk_count > 0 %}issue-red{% else %}issue-ok{% endif %}" onclick="show('rtos', document.querySelector('[onclick*=rtos]'))">
        <span class="issue-icon">{% if meta.race_risk_count > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">ISR/main-loop race risk vars</span>
        <span class="issue-count">{{ meta.race_risk_count }}</span>
      </div>
    </div>

    <div class="issue-section">
      <div class="issue-section-title">Change History</div>
      <div class="issue-row issue-info" onclick="show('gittrends', document.querySelector('[onclick*=gittrends]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Hotspots (churn x debt)</span>
        <span class="issue-count">{{ meta.hotspot_count }}</span>
      </div>
      <div class="issue-row issue-info" onclick="show('gittrends', document.querySelector('[onclick*=gittrends]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Bug-fix-weighted hotspots</span>
        <span class="issue-count">{{ meta.bugfix_hotspot_count }}</span>
      </div>
      <div class="issue-row issue-info" onclick="show('gittrends', document.querySelector('[onclick*=gittrends]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Ownership risk</span>
        <span class="issue-count">{{ meta.ownership_risk_count }}</span>
      </div>
      <div class="issue-row issue-info" onclick="show('gittrends', document.querySelector('[onclick*=gittrends]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Change-coupled file pairs</span>
        <span class="issue-count">{{ meta.change_coupling_count }}</span>
      </div>
      <div class="issue-row issue-info" onclick="show('gittrends', document.querySelector('[onclick*=gittrends]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Cross-layer coupled pairs</span>
        <span class="issue-count">{{ meta.layer_coupling_count }}</span>
      </div>
    </div>

    {% if meta.rtos_kind != 'none' %}
    <div class="issue-section">
      <div class="issue-section-title">RTOS ({{ meta.rtos_kind }})</div>
      <div class="issue-row issue-info" onclick="show('rtos', document.querySelector('[onclick*=rtos]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Tasks</span>
        <span class="issue-count">{{ meta.rtos_task_count }}</span>
      </div>
      <div class="issue-row {% if meta.rtos_collision_count > 0 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('rtos', document.querySelector('[onclick*=rtos]'))">
        <span class="issue-icon">{% if meta.rtos_collision_count > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Priority collisions</span>
        <span class="issue-count">{{ meta.rtos_collision_count }}</span>
      </div>
      <div class="issue-row {% if meta.rtos_inversion_count > 0 %}issue-red{% else %}issue-ok{% endif %}" onclick="show('rtos', document.querySelector('[onclick*=rtos]'))">
        <span class="issue-icon">{% if meta.rtos_inversion_count > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Priority inversion candidates</span>
        <span class="issue-count">{{ meta.rtos_inversion_count }}</span>
      </div>
      <div class="issue-row {% if meta.rtos_unused_count > 0 %}issue-yellow{% else %}issue-ok{% endif %}" onclick="show('rtos', document.querySelector('[onclick*=rtos]'))">
        <span class="issue-icon">{% if meta.rtos_unused_count > 0 %}&#9888;{% else %}&#10003;{% endif %}</span>
        <span class="issue-label">Unused sync objects</span>
        <span class="issue-count">{{ meta.rtos_unused_count }}</span>
      </div>
    </div>
    {% endif %}

    {% if meta.state_machine_count > 0 %}
    <div class="issue-section">
      <div class="issue-section-title">State Machines</div>
      <div class="issue-row issue-info" onclick="show('rtos', document.querySelector('[onclick*=rtos]'))">
        <span class="issue-icon">&#9432;</span>
        <span class="issue-label">Detected</span>
        <span class="issue-count">{{ meta.state_machine_count }}</span>
      </div>
    </div>
    {% endif %}
  </div>

  <!-- Top worst functions quick view -->
  {% if critical_funcs %}
  <div class="section-title" style="margin-top:8px">Top Risk Functions
    <span style="font-size:11px;font-weight:400;color:var(--dim)"> &mdash; highest fan-in &times; SDI &mdash;
      <span class="clickable" onclick="show('risk',document.querySelector('[onclick*=risk]'))">see all in Risk tab &#8594;</span>
    </span>
  </div>
  <table style="max-width:900px">
    <thead><tr>
      <th>Function</th><th>File</th>
      <th title="fan_in × SDI">Risk</th>
      <th title="Number of callers">Fan-in</th>
      <th title="Cyclomatic Complexity">CC</th>
      <th title="Structural Debt Index">SDI</th>
      <th title="Halstead estimated latent bugs">Bugs~</th>
      <th title="Assert calls in this function">Asserts</th>
    </tr></thead>
    <tbody>
    {% for f in critical_funcs[:8] %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td class="red">{{ f.risk_score }}</td>
      <td>{{ f.fan_in }}</td>
      <td class="{{ 'red' if f.cyclomatic_complexity > 15 else 'yellow' if f.cyclomatic_complexity > 8 else '' }}">{{ f.cyclomatic_complexity }}</td>
      <td class="{{ 'red' if f.structural_debt_index > 0.8 else 'yellow' if f.structural_debt_index > 0.6 else '' }}">{{ "%.2f"|format(f.structural_debt_index) }}</td>
      <td class="dim">{{ f.halstead_bugs }}</td>
      <td class="{{ 'dim' if f.assert_count == 0 else 'green' }}">{{ f.assert_count }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <details class="metric-info" style="margin-top:24px">
    <summary>Known limitations &amp; sanity notes -- read this before trusting a number</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card">
          <div class="mc-name">Fan-in is a lower bound</div>
          <div class="mc-desc">Call edges are resolved by matching callee names to functions defined <em>within the analysed scope</em>. A function called only from SDK or Lib code (registered as a boundary stub, not parsed) shows fan_in = 0 even if it's heavily used there. Treat fan-in as "known usage from first-party code," not total usage.</div>
        </div>
        <div class="metric-card">
          <div class="mc-name">Halstead differs from lizard/ccccc</div>
          <div class="mc-desc">fwlens classifies AST cursor kinds for Halstead operators/operands rather than scanning tokens lexically -- more accurate through macro expansion, but the absolute numbers won't match line-counting tools. The <em>relative ranking</em> between your own functions is reliable; don't compare absolute Halstead values against published external benchmarks.</div>
        </div>
        <div class="metric-card">
          <div class="mc-name">MI = 100 can be misleading</div>
          <div class="mc-desc">If Halstead collection fails for a function (parse error in the body, inline-assembly-only function, etc.) volume defaults to 0 and the MI formula resolves to 100 -- technically correct per the formula, but reads as "perfectly maintainable" for a function fwlens actually couldn't analyse. Treat mi_woc = 100 on a large or complex-looking function with suspicion rather than as a genuine top score.</div>
        </div>
        <div class="metric-card">
          <div class="mc-name">Cognitive complexity is an undercount</div>
          <div class="mc-desc">Penalises structural nesting depth, but doesn't currently add penalty for <code>break</code>, <code>continue</code>, <code>goto</code>, or recursion -- all genuinely add reading effort. Treat the reported score as a floor on true cognitive load, not a ceiling.</div>
        </div>
        <div class="metric-card">
          <div class="mc-name">A large dead-code count is normal for RTOS firmware</div>
          <div class="mc-desc">Functions registered in dispatch tables, called only via function pointer, passed as library callbacks, or invoked only from SDK code all show as "dead" from fwlens's in-project-only view even though they're genuinely called at runtime. A high count is expected in this style of codebase -- filter the list manually against these patterns rather than treating the raw count as a defect count. Add confirmed entry points (RTOS task functions, registered callbacks fwlens can't trace) to <code>entry_points</code> in config.yaml to reduce false positives.</div>
        </div>
        <div class="metric-card">
          <div class="mc-name">Layer violations need correct layer config first</div>
          <div class="mc-desc">Detection is only as good as the <code>layers</code> definitions in config.yaml. Wrong or incomplete IAR group names or path fragments push modules into <code>Unknown</code>, which is excluded from violation detection entirely -- a wrong config doesn't just miscount violations, it can silently hide all of them. Run <code>.\Run-FwLens.ps1 debug</code> to check every module's classification before trusting this tab.</div>
        </div>
      </div>
    </div>
  </details>

</div>

<!-- FUNCTIONS -->


<!-- ARCHITECTURE -->
<div class="pane" id="pane-architecture">
  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Layer Violations</div><div class="mc-desc">Dependencies that cross layer boundaries incorrectly, based on the layer rules in arch.yaml. An <strong>upward</strong> violation is a lower-layer module calling or including a higher-layer one. A <strong>skipped</strong> violation is a dependency that jumps more than one layer.</div></div>
        <div class="metric-card"><div class="mc-name">Stable Abstractions Plot</div><div class="mc-desc">Each module is plotted with Instability (I) on the x-axis and Abstractness (A) on the y-axis. The ideal position is the main sequence line I + A = 1. The further a module is from this line, the higher its Main Sequence Distance.</div></div>
        <div class="metric-card"><div class="mc-name">Abstractness (A)</div><div class="mc-desc">Ratio of abstract types (interfaces, pure-virtual classes, opaque structs used only by pointer) to total types declared in the module. In C, estimated from the ratio of type declarations that are incomplete or only forward-declared.</div></div>
        <div class="metric-card"><div class="mc-name">Zone of Pain</div><div class="mc-desc">Bottom-left of the plot. Low I (stable) and low A (concrete). The module is hard to change and hard to extend. Typical culprits are utility modules that everything depends on but that have no abstract interface.</div></div>
        <div class="metric-card"><div class="mc-name">Zone of Uselessness</div><div class="mc-desc">Top-right of the plot. High I (unstable) and high A (abstract). The module is abstract but nothing depends on it -- it provides no value in its current form.</div></div>
        <div class="metric-card"><div class="mc-name">Why is A near 0 for most modules?</div><div class="mc-desc">IAR .ewp files list only .c files -- headers aren't separate modules, so abstractness is computed from type declarations <em>inside the .c file only</em>. Most implementation files define few or no structs/enums/typedefs (those live in headers), so A is genuinely low for most files, and Zone of Pain often just means "stable and concrete," not "problematic." A module that genuinely belongs in the zone of pain is one that frequently <em>needs</em> to change but can't without breaking many callers -- not merely one with A=0.</div></div>
        <div class="metric-card"><div class="mc-name">Common causes of layer violations</div><div class="mc-desc">State-machine modules (Services) reaching directly into UI (Product) to trigger display updates -- prefer an observer/callback pattern. Connectivity modules calling into business logic (Product) directly -- should be mediated through a Services interface. RTOS modules calling into Connectivity code -- usually indicates a missing abstraction in the RTOS layer itself. "Skipped" violations (jumping more than one layer) are more severe than "upward" ones since they bypass an intended mediation layer entirely.</div></div>
      </div>
    </div>
  </details>

  <div class="section-title">Architecture Diagram
    <span style="font-size:11px;font-weight:400;color:var(--dim)">
      modules grouped by layer, coloured by zone -- click a module to view source
    </span>
  </div>
  <div style="margin-bottom:24px">
    {{ architecture_svg | safe }}
    <div style="display:flex;gap:16px;margin-top:8px;font-size:11px;color:var(--dim)">
      <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#dc2626;margin-right:4px"></span>Zone of Pain</span>
      <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#ca8a04;margin-right:4px"></span>Zone of Uselessness</span>
      <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#d97706;margin-right:4px"></span>Warning (cyclic)</span>
      <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#16a34a;margin-right:4px"></span>Main Sequence</span>
      <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#6b7280;margin-right:4px"></span>Unknown</span>
    </div>
  </div>

  <div class="two-col">
    <div>
      <div class="section-title">Layer Violations
        <span style="font-size:11px;font-weight:400;color:var(--dim)">
          upward = caller is in a lower layer than callee &bull;
          skipped = gap &gt; 1 layer
        </span>
      </div>
      {% if arch_violations %}
      <div style="margin-bottom:10px;color:var(--dim);font-size:12px">
        {{ arch_violations|length }} violation(s) detected
      </div>
      <div class="filter-row">
        <input type="text" id="arch-filter" placeholder="Filter by module or layer..." oninput="filterTable('arch-table', this.value)">
      </div>
      <table id="arch-table">
        <thead><tr>
          <th>From module</th><th>Layer</th>
          <th>To module</th><th>Layer</th>
          <th>Type</th>
        </tr></thead>
        <tbody>
        {% for v in arch_violations %}
        <tr>
          <td>{{ v.source_module }}</td>
          <td class="dim">{{ v.source_layer }}</td>
          <td>{{ v.target_module }}</td>
          <td class="dim">{{ v.target_layer }}</td>
          <td>
            {% if v.violation_type == 'skipped' %}
              <span class="badge badge-red">skipped</span>
            {% else %}
              <span class="badge badge-yellow">upward</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p style="color:var(--green)">&#10003; No layer violations detected.</p>
      {% endif %}
    </div>

    <div>
      <div class="section-title">Stable Abstractions Plot
        <span style="font-size:11px;font-weight:400;color:var(--dim)">I + A = 1 ideal line</span>
      </div>
      <div class="zone-legend">
        <div class="zone-item"><div class="zone-dot" style="background:#e05c5c"></div> Zone of Pain (pain &ge; 0.6)</div>
        <div class="zone-item"><div class="zone-dot" style="background:#e0b85c"></div> Far from line (MSD &ge; 0.5)</div>
        <div class="zone-item"><div class="zone-dot" style="background:#4f9cf9"></div> Moderate (MSD 0.3&ndash;0.5)</div>
        <div class="zone-item"><div class="zone-dot" style="background:#5ce07a"></div> On main sequence (MSD &lt; 0.3)</div>
      </div>
      <canvas id="scatter-canvas" width="420" height="380"></canvas>
    </div>
  </div>

  <div class="zone-tables">
    <div class="two-col">
      <div>
        <div class="section-title" style="margin-top:0">
          <span style="color:var(--red)">&#9679;</span> Zone of Pain
          <span style="font-size:11px;font-weight:400;color:var(--dim)">stable &amp; concrete -- hard to change, hard to extend</span>
        </div>
        {% set pain_mods = modules | selectattr('zone','equalto','pain') | list %}
        {% if pain_mods %}
        <p style="font-size:11px;color:var(--dim);margin-bottom:8px">
          Modules ranked by <strong>pain score</strong> -- a weighted composite of fan-in (35%),
          avg CC (25%), avg Halstead effort (20%), dependency cycle (15%), and avg magic number density (5%).
          High fan-in + high CC + high effort = hard to change and dangerous to get wrong.
        </p>
        <table>
          <thead><tr>
            <th>Module</th><th>Layer</th>
            <th title="Weighted composite: fan-in 35%, avg CC 25%, Halstead 20%, cycle 15%, magic 5%">Pain</th>
            <th title="Modules calling into this one -- blast radius of any change">Fan-in</th>
            <th title="Average cyclomatic complexity across functions">Avg CC</th>
            <th title="Average Halstead effort -- cognitive load while working in the code">Avg effort</th>
            <th title="Whether this module is in a dependency cycle">Cycle</th>
          </tr></thead>
          <tbody>
          {% for m in pain_mods | sort(attribute='pain_score', reverse=true) %}
          <tr>
            <td>{% if m.has_source %}<span class="clickable" onclick="showFile('{{ m.file_path }}')">{{ m.name }}</span>{% else %}{{ m.name }}{% endif %}</td>
            <td class="dim">{{ m.layer or 'Unknown' }}</td>
            <td class="red">{{ "%.2f"|format(m.pain_score) }}</td>
            <td>{{ m.fan_in }}</td>
            <td class="{{ 'yellow' if m.avg_cc > 5 else '' }}">{{ "%.1f"|format(m.avg_cc) }}</td>
            <td class="dim">{{ "%.0f"|format(m.avg_halstead_effort) }}</td>
            <td class="{{ 'red' if m.in_cycle else 'dim' }}">{{ 'Y' if m.in_cycle else 'N' }}</td>
          </tr>
          {% endfor %}
          </tbody>
        </table>
        {% else %}
        <p style="color:var(--green)">&#10003; No modules in Zone of Pain.</p>
        {% endif %}
      </div>
      <div>
        <div class="section-title" style="margin-top:0">
          <span style="color:var(--yellow)">&#9679;</span> Zone of Uselessness
          <span style="font-size:11px;font-weight:400;color:var(--dim)">unstable &amp; abstract -- not depended upon</span>
        </div>
        {% set useless_mods = modules | selectattr('zone','equalto','uselessness') | list %}
        {% if useless_mods %}
        <table>
          <thead><tr><th>Module</th><th>Layer</th><th>I</th><th>A</th><th>MSD</th></tr></thead>
          <tbody>
          {% for m in useless_mods | sort(attribute='main_sequence_distance', reverse=true) %}
          <tr>
            <td>{% if m.has_source %}<span class="clickable" onclick="showFile('{{ m.file_path }}')">{{ m.name }}</span>{% else %}{{ m.name }}{% endif %}</td>
            <td class="dim">{{ m.layer or 'Unknown' }}</td>
            <td>{{ "%.2f"|format(m.instability) }}</td>
            <td>{{ "%.2f"|format(m.abstractness) }}</td>
            <td class="yellow">{{ "%.2f"|format(m.main_sequence_distance) }}</td>
          </tr>
          {% endfor %}
          </tbody>
        </table>
        {% else %}
        <p style="color:var(--green)">&#10003; No modules in Zone of Uselessness.</p>
        {% endif %}
      </div>
    </div>
  </div>


  <div class="section-title" style="margin-top:24px">Architecture-Level Change Coupling
    <span style="font-size:11px;font-weight:400;color:var(--dim)">change_coupling rolled up by layer -- "surprising" = no direct #include either way</span>
  </div>
  {% if layer_coupling_rows %}
  <table id="layer-coupling-table">
    <thead><tr><th>Layer A</th><th>Layer B</th><th>File pairs</th><th>Co-changes</th><th>Avg coupling</th><th>Surprising</th></tr></thead>
    <tbody>
    {% for lp in layer_coupling_rows %}
    <tr>
      <td class="dim">{{ lp.layer_a }}</td>
      <td class="dim">{{ lp.layer_b }}</td>
      <td>{{ lp.file_pair_count }}</td>
      <td>{{ lp.total_co_changes }}</td>
      <td>{{ "%.0f"|format(lp.avg_coupling * 100) }}%</td>
      <td class="{{ 'red' if lp.surprising_pair_count > 0 else 'dim' }}">{{ lp.surprising_pair_count }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No cross-layer coupled file pairs.</p>
  {% endif %}

  <div class="subsection" style="margin-top:36px;padding-top:22px;border-top:1px solid var(--border)">
  <div class="section-title" style="margin-top:0">Include Hygiene</div>

  <details class="metric-info">
    <summary>About these checks</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Circular Includes</div><div class="mc-desc">A strongly-connected component (size &gt; 1) in the file-level #include graph -- file A includes B includes ... includes A, directly or transitively. The compiler tolerates this via include guards, but it means the two (or more) files can't be understood or reused independently, and can hide accidental coupling. <strong>Use it to:</strong> find header pairs worth breaking apart, usually by extracting the shared piece both sides actually need into a third header. <strong>Don't:</strong> panic over a cycle that's already guard-protected and stable -- it's a design smell to schedule, not necessarily an active bug.</div></div>
        <div class="metric-card"><div class="mc-name">Self-Includes</div><div class="mc-desc">A file that includes itself, directly or via a resolved path. Almost always either a copy-paste mistake or a symptom of a macro-based include trick gone wrong. Reported separately from Circular Includes because a strongly-connected-component check needs 2+ distinct files to count as a cycle and won't catch this on its own.</div></div>
        <div class="metric-card"><div class="mc-name">Missing Include Guards</div><div class="mc-desc">First-party headers with neither <code>#pragma once</code> nor a matching <code>#ifndef</code>/<code>#define</code> pair. Without one, including the header twice in the same translation unit (directly and transitively, which is easy to do by accident as a codebase grows) causes duplicate-declaration errors. SDK/third-party headers are excluded -- fwlens has no standing to flag vendor code.</div></div>
        <div class="metric-card"><div class="mc-name">Deepest Include Chains</div><div class="mc-desc">Transitive include depth per first-party file (longest path in the include graph reachable from that file). A deep chain means a small change to a low-level header can trigger a wide, slow rebuild, and makes it harder to reason about what a file actually pulls in. <strong>Use it to:</strong> find files that would benefit from forward declarations or an interface header instead of including the full implementation header.</div></div>
        <div class="metric-card"><div class="mc-name">Possibly Unused Includes</div><div class="mc-abbr">Heuristic -- worklist, not a verdict</div><div class="mc-desc">First-party-to-first-party includes where none of the header's declared names (macros, function prototypes, typedefs, extern globals -- extracted with single-line-oriented regexes, not a real parse) appear anywhere in the including file. False negatives are the expected failure mode: a declaration form the regexes miss, or a macro used only for a side effect, will read as "used" even if the visible include could be dropped. <strong>Don't:</strong> delete an include from this list without checking by eye first -- treat it as places to look, not a list to strip automatically.</div></div>
      </div>
    </div>
  </details>

  <div class="two-col">
    <div>
      <div class="section-title" style="margin-top:0">Circular Includes
        <span style="font-size:11px;font-weight:400;color:var(--dim)">{{ include_cycles|length }} cycle(s)</span>
      </div>
      {% if include_cycles %}
      <table>
        <thead><tr><th>Cycle</th><th>Length</th></tr></thead>
        <tbody>
        {% for c in include_cycles %}
        <tr>
          <td class="dim" style="font-size:11px">{{ c.files|join(' &rarr; ') }} &rarr; {{ c.files[0] }}</td>
          <td class="red">{{ c.length }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p style="color:var(--green)">&#10003; No circular includes detected.</p>
      {% endif %}

      <div class="section-title" style="margin-top:20px">Self-Includes
        <span style="font-size:11px;font-weight:400;color:var(--dim)">{{ self_includes|length }}</span>
      </div>
      {% if self_includes %}
      <table>
        <thead><tr><th>File</th></tr></thead>
        <tbody>
        {% for s in self_includes %}
        <tr><td class="red">{{ s.file }}</td></tr>
        {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p style="color:var(--green)">&#10003; No self-includes detected.</p>
      {% endif %}
    </div>

    <div>
      <div class="section-title" style="margin-top:0">Missing Include Guards
        <span style="font-size:11px;font-weight:400;color:var(--dim)">{{ missing_include_guards|length }} header(s)</span>
      </div>
      {% if missing_include_guards %}
      <table>
        <thead><tr><th>Header</th><th>Reason</th></tr></thead>
        <tbody>
        {% for g in missing_include_guards %}
        <tr>
          <td class="dim" style="font-size:11px">{{ g.file }}</td>
          <td class="yellow" style="font-size:11px">{{ g.reason }}</td>
        </tr>
        {% endfor %}
        </tbody>
      </table>
      {% else %}
      <p style="color:var(--green)">&#10003; All first-party headers are guard-protected.</p>
      {% endif %}
    </div>
  </div>

  <div class="section-title" style="margin-top:24px">Deepest Include Chains
    <span style="font-size:11px;font-weight:400;color:var(--dim)">top {{ deep_include_chains|length }} first-party files by transitive include depth</span>
  </div>
  {% if deep_include_chains %}
  <table style="max-width:640px" class="chain-table">
    <thead><tr><th></th><th>File</th><th>Depth</th></tr></thead>
    <tbody>
    {% for d in deep_include_chains %}
    <tr class="chain-row{{ ' has-chain' if d.chain }}" {% if d.chain %}onclick="this.classList.toggle('expanded')"{% endif %}>
      <td class="chain-toggle">{% if d.chain %}<span class="chain-arrow">&#9656;</span>{% endif %}</td>
      <td class="dim">{{ d.file }}</td>
      <td class="{{ 'red' if d.depth > 8 else 'yellow' if d.depth > 4 else '' }}">{{ d.depth }}</td>
    </tr>
    {% if d.chain %}
    <tr class="chain-detail">
      <td></td>
      <td colspan="2">
        <div class="chain-path">
        {% for f in d.chain %}<span class="chain-hop">{{ f }}</span>{% if not loop.last %}<span class="chain-sep">&#8594;</span>{% endif %}{% endfor %}
        </div>
      </td>
    </tr>
    {% endif %}
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No include-depth data available.</p>
  {% endif %}

  <div class="section-title" style="margin-top:24px">Possibly Unused Includes
    <span style="font-size:11px;font-weight:400;color:var(--dim)">{{ unused_includes|length }} flagged -- heuristic, verify before removing</span>
  </div>
  {% if unused_includes %}
  <input type="text" id="unused-inc-filter" placeholder="Filter by file..." oninput="filterTable('unused-inc-table', this.value)">
  <table id="unused-inc-table">
    <thead><tr><th>File</th><th>Possibly-unused include</th><th>Names checked</th></tr></thead>
    <tbody>
    {% for u in unused_includes %}
    <tr>
      <td class="dim">{{ u.file }}</td>
      <td class="yellow">{{ u.included }}</td>
      <td class="dim">{{ u.declared_name_count }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No possibly-unused first-party includes flagged.</p>
  {% endif %}

  </div>

</div>


<!-- MODULES -->
<div class="pane" id="pane-modules">
  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Fan-in</div><div class="mc-desc">Number of other modules that depend on this one. High fan-in means the module is widely used -- changes to it ripple broadly, so it should be stable and well-tested. <strong>Note:</strong> only counts callers within first-party analysed scope -- a module called heavily from SDK/Lib code shows a lower fan-in than its true usage.</div></div>
        <div class="metric-card"><div class="mc-name">Fan-out</div><div class="mc-desc">Number of other modules this one depends on. High fan-out means many dependencies and a large surface area for breakage.</div><div class="mc-thresh">Threshold: {{ thresholds.fan_out }}</div></div>
        <div class="metric-card"><div class="mc-name">Instability (I)</div><div class="mc-desc">I = fan-out / (fan-in + fan-out). Ranges 0-1. 0 = fully stable (depended on, depends on nothing). 1 = fully unstable (depends on others, nothing depends on it). Unstable modules are free to change; stable modules must not. <strong>Use it to:</strong> sanity-check that your most-depended-on modules (drivers, utility libraries) are also your most stable ones -- if a widely-depended module is also frequently changing, that's a real risk signal.</div></div>
        <div class="metric-card"><div class="mc-name">Main Sequence Distance (MSD)</div><div class="mc-desc">Distance from the ideal I + A = 1 line on the stable-abstractions plot. 0 is ideal. High MSD means either Zone of Pain (stable but concrete) or Zone of Uselessness (unstable but abstract).</div><div class="mc-thresh">Threshold: {{ thresholds.main_sequence_distance }}</div></div>
        <div class="metric-card"><div class="mc-name">Zone</div><div class="mc-desc">Classification on the stable-abstractions plane. Pain = stable and concrete (hard to change and hard to extend). Useless = unstable and abstract (hard to use, nobody depends on it). OK = near the main sequence. <strong>Don't</strong> treat a high Zone-of-Pain count as automatically bad -- in a .c-only file model, abstractness is near-zero for most implementation files by construction (types live in headers, not counted). Most Zone-of-Pain modules are simply "stable and concrete," which is a fine, even desirable, place for a driver or utility module to sit. It's only a real problem when the module <em>also</em> needs to change often despite the difficulty of doing so -- cross-check against the Change History tab's churn data before acting.</div></div>
        <div class="metric-card"><div class="mc-name">Avg CC</div><div class="mc-desc">Mean cyclomatic complexity across all functions in the module. A proxy for overall module complexity.</div></div>
        <div class="metric-card"><div class="mc-name">Include Depth</div><div class="mc-desc">Maximum depth of the transitive include chain rooted at this file. Deep include chains slow compilation and increase coupling surface.</div></div>
        <div class="metric-card"><div class="mc-name">Cycle</div><div class="mc-desc">Whether the module participates in a strongly-connected component. Cyclic modules cannot be independently compiled, tested, or replaced. <strong>Use it to:</strong> find candidates for breaking a mutual dependency (extract a shared interface, invert one direction to a callback). A codebase with many cyclic modules linked through callback/registration patterns (which fwlens recovers into the call graph) will show more cycles than a purely direct-call analysis would -- that's fwlens working as intended, not over-counting.</div></div>
      </div>
    </div>
  </details>
  <div class="filter-row">
    <input type="text" id="mod-filter" placeholder="Filter by name or layer..." oninput="filterTable('mod-table', this.value)">
  </div>
  <table id="mod-table">
    <thead><tr>
      <th onclick="sortTable('mod-table',0)">Module</th>
      <th onclick="sortTable('mod-table',1)">Layer</th>
      <th onclick="sortTable('mod-table',2)">LOC</th>
      <th onclick="sortTable('mod-table',3)">Funcs</th>
      <th onclick="sortTable('mod-table',4)">Fan-in</th>
      <th onclick="sortTable('mod-table',5)">Fan-out</th>
      <th onclick="sortTable('mod-table',6)">Instability</th>
      <th onclick="sortTable('mod-table',7)">MSD</th>
      <th onclick="sortTable('mod-table',8)">Zone</th>
      <th onclick="sortTable('mod-table',9)">Avg CC</th>
      <th onclick="sortTable('mod-table',10)">Inc depth</th>
      <th onclick="sortTable('mod-table',11)">Cycle</th>
    </tr></thead>
    <tbody>
    {% for m in modules %}
    <tr>
      <td>{% if m.has_source %}<span class="clickable" onclick="showFile('{{ m.file_path }}')">{{ m.name }}</span>{% else %}{{ m.name }}{% endif %}</td>
      <td class="dim">{{ m.layer or 'Unknown' }}</td>
      <td>{{ m.loc }}</td>
      <td>{{ m.function_count }}</td>
      <td>{{ m.fan_in }}</td>
      <td>{{ m.fan_out }}</td>
      <td class="{{ 'red' if m.instability > 0.8 else ('yellow' if m.instability > 0.6 else '') }}">{{ "%.2f"|format(m.instability) }}</td>
      <td class="{{ 'red' if m.msd_breach else '' }}">{{ "%.2f"|format(m.main_sequence_distance) }}</td>
      <td>
        {% if m.zone == 'pain' %}<span class="badge badge-red">Pain</span>
        {% elif m.zone == 'uselessness' %}<span class="badge badge-yellow">Useless</span>
        {% elif m.zone == 'main_sequence' %}<span class="badge badge-green">OK</span>
        {% elif m.zone == 'warning' %}<span class="badge badge-yellow">Warn</span>
        {% else %}<span class="badge">?</span>{% endif %}
      </td>
      <td class="{{ 'yellow' if m.avg_cc > 5 else '' }}">{{ "%.1f"|format(m.avg_cc) }}</td>
      <td>{{ m.include_depth }}</td>
      <td class="{{ 'red' if m.in_cycle else 'dim' }}">{{ 'Y' if m.in_cycle else 'N' }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>


  <div class="subsection" style="margin-top:36px;padding-top:22px;border-top:1px solid var(--border)">
  <div class="section-title" style="margin-top:0">Group / Directory Alignment</div>

  <details class="metric-info">
    <summary>About this analysis</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">What is a mismatch?</div><div class="mc-desc">A mismatch occurs when a source file's IAR project group name differs from the name of the directory it physically lives in. The IAR tree and the filesystem have diverged -- common when files are reorganised in the IDE without being moved on disk. <strong>Use it to:</strong> catch drift early, before it compounds -- one mismatch is a quick fix; dozens accumulated over years become a genuine "which view do I trust" problem. <strong>Don't:</strong> treat every mismatch as urgent -- a handful in an otherwise stable codebase is low risk; a large or fast-growing count is the actual signal worth acting on.</div></div>
        <div class="metric-card"><div class="mc-name">Why does it matter?</div><div class="mc-desc">Developers using VS Code, git, or any filesystem-based tool see only the directory structure, not the IAR group tree. If the two diverge, the logical architecture visible in the IDE is invisible to the rest of the toolchain -- including fwlens's own `layers` config, which matches by group name OR path fragment, so a badly-drifted codebase can also mean architecture-layer assignment is quietly wrong for the affected files.</div></div>
        <div class="metric-card"><div class="mc-name">Suggested path</div><div class="mc-desc">The suggested path shows where the file would live if directories mirrored IAR groups -- only the immediate parent directory name is changed. Use this as a refactoring guide, not an automated rename -- always verify the target directory doesn't already contain a same-named file before moving anything.</div></div>
        <div class="metric-card"><div class="mc-name">Layer</div><div class="mc-desc">The architecture layer assigned to this file's IAR group. If the layer is Unknown, the group is not covered by the layers config -- worth fixing before trusting Architecture Layer Violations results, since Unknown modules are excluded from that detection entirely.</div></div>
      </div>
    </div>
  </details>
  {% if group_dir_mismatches %}
  <p style="margin-bottom:12px;color:var(--dim)">
    {{ group_dir_mismatches|length }} file(s) whose IAR group name does not match their parent directory name.
  </p>
  {% set ns = namespace(current_group=None) %}
  {% for m in group_dir_mismatches %}
    {% if m.iar_group != ns.current_group %}
      {% if ns.current_group is not none %}</tbody></table>{% endif %}
      {% set ns.current_group = m.iar_group %}
      <h3 style="margin:20px 0 6px;font-size:0.95rem">
        IAR group: <code>{{ m.iar_group }}</code>
        <span class="badge" style="background:var(--layer-bg,#334);color:var(--dim);margin-left:8px">{{ m.layer }}</span>
      </h3>
      <table>
        <thead><tr>
          <th>File</th>
          <th>Actual directory</th>
          <th>Suggested directory</th>
        </tr></thead>
        <tbody>
    {% endif %}
    <tr>
      <td><code>{{ m.file_name }}</code></td>
      <td class="dim">{{ m.actual_dir }}</td>
      <td style="color:var(--yellow)"><code>{{ m.suggested_dir }}</code></td>
    </tr>
  {% endfor %}
  {% if ns.current_group is not none %}</tbody></table>{% endif %}
  {% else %}
  <p style="color:var(--green)">IAR groups and filesystem directories are fully aligned.</p>
  {% endif %}

  </div>

</div>


<div class="pane" id="pane-functions">
  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Cyclomatic Complexity (CC)</div><div class="mc-desc">Number of linearly independent paths through a function. Each branch, loop, or case adds 1. Directly predicts the minimum number of test cases needed for full branch coverage. <strong>Use it to:</strong> prioritise unit-test effort and flag functions that are structurally hard to fully exercise. <strong>Don't:</strong> treat a high CC as proof of a bug -- a long, flat <code>switch</code> dispatching on a well-defined enum is high-CC but often perfectly clear; look at the code before deciding it needs splitting.</div><div class="mc-thresh">Threshold: {{ thresholds.cyclomatic_complexity }}</div></div>
        <div class="metric-card"><div class="mc-name">Cognitive Complexity (Cog)</div><div class="mc-desc">A human-perceived difficulty score. Unlike CC it penalises nesting depth, so a deeply nested loop scores higher than a flat chain of conditions with the same CC. <strong>Use it to:</strong> find functions that are hard to *read*, as distinct from hard to *test* -- CC and Cog disagreeing on which function is "worse" is itself informative. <strong>Don't:</strong> forget it currently undercounts <code>break</code>/<code>continue</code>/<code>goto</code>/recursion -- treat the number as a floor, not a ceiling.</div><div class="mc-thresh">Threshold: {{ thresholds.cognitive_complexity }}</div></div>
        <div class="metric-card"><div class="mc-name">LOC</div><div class="mc-desc">Non-blank, non-comment lines of code in the function body. A rough size proxy; large functions are harder to understand and test. <strong>Use it to:</strong> spot functions doing too many things at once. <strong>Don't:</strong> use LOC alone to judge quality -- a long function that's a flat sequence of simple steps can be easier to follow than a short one with dense nested logic; cross-check against CC/Cog before acting.</div><div class="mc-thresh">Threshold: {{ thresholds.function_loc }}</div></div>
        <div class="metric-card"><div class="mc-name">Block Depth</div><div class="mc-desc">Maximum nesting depth of control structures (if/for/while/switch). Deep nesting is a strong predictor of defects and maintenance cost. <strong>Use it to:</strong> find candidates for guard-clause refactoring (early return instead of nested if). <strong>Don't:</strong> flatten nesting purely to satisfy this number -- if flattening requires duplicating a condition check, you may be trading one problem for another.</div><div class="mc-thresh">Threshold: {{ thresholds.block_depth }}</div></div>
        <div class="metric-card"><div class="mc-name">Returns</div><div class="mc-desc">Number of return statements. Multiple exits make control flow harder to follow and can leave resources un-freed in C. <strong>Use it to:</strong> check for missing cleanup on early-exit paths (unlocked mutex, unfreed buffer) in functions that acquire a resource. <strong>Don't:</strong> apply this rigidly to short validation functions -- a guard-clause style with several early returns for invalid input is often clearer than one return with accumulated flags.</div><div class="mc-thresh">Threshold: {{ thresholds.return_path_count }}</div></div>
        <div class="metric-card"><div class="mc-name">Magic Number Density</div><div class="mc-desc">Ratio of numeric literals to LOC. High density suggests missing named constants, which hinders readability and maintenance. <strong>Use it to:</strong> find hardware register/protocol code that would benefit from named constants. <strong>Don't:</strong> chase this on math-heavy or lookup-table-heavy functions (filter coefficients, CRC tables) where the literals *are* the meaningful content -- 0/1/-1/NULL/true/false are already excluded, but domain constants aren't.</div><div class="mc-thresh">Threshold: {{ thresholds.magic_number_density }}</div></div>
        <div class="metric-card"><div class="mc-name">Fan-out</div><div class="mc-desc">Number of distinct functions called by this function. High fan-out means many dependencies and broad blast radius for changes. <strong>Use it to:</strong> find orchestration/god-functions that might benefit from being split along responsibility lines. <strong>Don't:</strong> flag a genuine top-level dispatcher (e.g. a state machine's central switch calling one handler per state) as a problem purely for high fan-out -- that's often the correct shape for that role.</div><div class="mc-thresh">Threshold: {{ thresholds.fan_out }}</div></div>
        <div class="metric-card"><div class="mc-name">Halstead Effort</div><div class="mc-desc">Estimated mental effort to write or understand the function, derived from operator and operand counts. A composite of vocabulary, volume, and difficulty. <strong>Use it to:</strong> compare functions <em>within this codebase</em> against each other. <strong>Don't:</strong> compare the absolute number against external benchmarks or other tools (lizard, ccccc) -- fwlens derives operators/operands from AST cursor kinds, not token scanning, so the scale doesn't match.</div></div>
        <div class="metric-card"><div class="mc-name">Maintainability Index (MI)</div><div class="mc-desc">A composite score (0-100) combining Halstead volume, cyclomatic complexity, and LOC. Higher is more maintainable. Uses the SEI Without Comments (WoC) variant which omits the comment ratio. <strong>Use it to:</strong> get a single at-a-glance quality signal per function. <strong>Don't:</strong> trust MI = 100 blindly -- if Halstead collection failed for a function (parse issue, inline-assembly-only body), volume defaults to 0 and the formula resolves to exactly 100, which reads as "perfect" for a function fwlens actually couldn't analyse.</div></div>
        <div class="metric-card"><div class="mc-name">Structural Debt Index (SDI)</div><div class="mc-desc">A normalised 0-1 composite of CC, block depth, LOC, and fan-out breaches. Used to rank functions by overall structural risk. Above 0.5 is yellow; above 0.7 is red. <strong>Use it to:</strong> triage where to start when every metric looks bad at once -- SDI collapses four signals into one ranking. <strong>Don't:</strong> use SDI as the only signal for a go/no-go decision -- it says nothing about how often the function runs or how many callers depend on it (that's what the Risk tab's fan_in x SDI is for).</div></div>
      </div>
    </div>
  </details>
  <div class="filter-row">
    <input type="text" id="func-filter" placeholder="Filter by name or file..." oninput="filterTable('func-table', this.value)">
  </div>
  <table id="func-table">
    <thead><tr>
      <th onclick="sortTable('func-table',0)">Function</th>
      <th onclick="sortTable('func-table',1)">File</th>
      <th onclick="sortTable('func-table',2)"  title="Cyclomatic Complexity -- number of independent paths. Threshold: {{ thresholds.cyclomatic_complexity }}">CC</th>
      <th onclick="sortTable('func-table',3)"  title="Cognitive Complexity -- nesting-weighted difficulty score. Threshold: {{ thresholds.cognitive_complexity }}">Cog</th>
      <th onclick="sortTable('func-table',4)"  title="Lines of Code. Threshold: {{ thresholds.function_loc }}">LOC</th>
      <th onclick="sortTable('func-table',5)"  title="Maximum block nesting depth. Threshold: {{ thresholds.block_depth }}">Depth</th>
      <th onclick="sortTable('func-table',6)"  title="Number of return statements. Threshold: {{ thresholds.return_path_count }}">Returns</th>
      <th onclick="sortTable('func-table',7)"  title="Magic number density (literals / LOC). Threshold: {{ thresholds.magic_number_density }}">Magic</th>
      <th onclick="sortTable('func-table',8)"  title="Fan-out -- number of distinct functions called. Threshold: {{ thresholds.fan_out }}">Fan-out</th>
      <th onclick="sortTable('func-table',9)"  title="Halstead Effort -- estimated cognitive work to understand or write this function">Effort</th>
      <th onclick="sortTable('func-table',10)" title="Maintainability Index (0-100, higher is better). Below 20 is poor; above 80 is good.">MI</th>
      <th onclick="sortTable('func-table',11)" title="Structural Debt Index (0-1 percentile composite). Above 0.7 is high risk.">SDI</th>
    </tr></thead>
    <tbody>
    {% for f in functions %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td class="{{ 'red' if f.cc_breach else '' }}">{{ f.cyclomatic_complexity }}</td>
      <td class="{{ 'yellow' if f.cog_breach else '' }}">{{ f.cognitive_complexity }}</td>
      <td class="{{ 'yellow' if f.loc_breach else '' }}">{{ f.loc }}</td>
      <td class="{{ 'red' if f.depth_breach else '' }}">{{ f.block_depth }}</td>
      <td class="{{ 'yellow' if f.ret_breach else '' }}">{{ f.return_path_count }}</td>
      <td class="{{ 'yellow' if f.magic_breach else '' }}">{{ "%.2f"|format(f.magic_number_density) }}</td>
      <td class="{{ 'yellow' if f.fanout_breach else '' }}">{{ f.fan_out }}</td>
      <td>{{ "%.0f"|format(f.halstead_effort) }}</td>
      <td>{{ "%.1f"|format(f.mi_woc) }}</td>
      <td class="{{ 'red' if f.structural_debt_index > 0.7 else ('yellow' if f.structural_debt_index > 0.5 else '') }}">{{ "%.2f"|format(f.structural_debt_index) }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>


  <div class="subsection" style="margin-top:36px;padding-top:22px;border-top:1px solid var(--border)">
  <div class="section-title" style="margin-top:0">Dead Code Candidates</div>

  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Dead Candidates</div><div class="mc-desc">Functions with zero in-project callers. The analysis only sees calls within the project scope -- functions called from external code, linker scripts, or via function pointers will appear here falsely. Always verify before removing. <strong>Use it to:</strong> build a review worklist, not an automatic deletion list -- confirm each one manually against the caveats below before removing anything.</div></div>
        <div class="metric-card"><div class="mc-name">Common false positives</div><div class="mc-desc">Four patterns routinely produce false "dead" flags in real embedded codebases: functions called only via function pointer (check the Function Pointers tab -- dispatch tables it recovers are already correctly excluded, but a table it can't detect won't be); functions registered in a jump table built up at runtime rather than as a single static initializer; functions called only from SDK/Lib code, which isn't parsed; and RTOS task entry functions not yet added to <code>entry_points</code> in config.yaml. A large dead-code count is normal for RTOS firmware, not necessarily a sign of a bloated codebase -- see the Overview tab's Known Limitations section.</div></div>
        <div class="metric-card"><div class="mc-name">Entry Points &amp; ISRs</div><div class="mc-desc">Functions marked as entry points (e.g. <code>main</code>, linker-retained symbols) or interrupt service routines are excluded from dead code reporting even if they have no in-project callers.</div></div>
        <div class="metric-card"><div class="mc-name">LOC &amp; CC</div><div class="mc-desc">Shown to help prioritise removal effort. A high-CC dead function has accumulated test-unfriendly complexity for no active benefit and is worth removing promptly -- once confirmed genuinely unused.</div></div>
      </div>
    </div>
  </details>
  {% if dead_by_layer %}
  <div style="margin-bottom:20px">
    <div class="section-title" style="margin-bottom:8px">By Layer</div>
    <p style="font-size:11px;color:var(--dim);margin-bottom:8px">
      Modules classified as Unknown are not covered by your <code>layers</code> config.
      Resolve Unknown classifications before treating these as genuine dead code -- they may be
      legitimately unreachable <em>from the analysed scope</em> but called from external code.
    </p>
    <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px">
    {% for layer, count in dead_by_layer %}
      <div style="background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:8px 14px;min-width:120px">
        <div style="font-size:11px;color:var(--dim)">{{ layer }}</div>
        <div style="font-size:20px;font-weight:600;color:{% if layer == 'Unknown' %}var(--yellow){% else %}var(--accent){% endif %}">{{ count }}</div>
      </div>
    {% endfor %}
    </div>
  </div>
  {% endif %}
  {% if dead_funcs %}
  <p style="margin-bottom:12px;color:var(--dim)">
    {{ dead_funcs|length }} suspected dead functions (zero in-project callers, excluding entry points and ISRs).
    Verify before removing -- external callers outside project scope are not detected.
  </p>
  <input type="text" id="dead-filter" placeholder="Filter by name or file..." oninput="filterTable('dead-table', this.value)">
  <table id="dead-table">
    <thead><tr><th>Function</th><th>File</th><th>Line</th><th>LOC</th><th>CC</th></tr></thead>
    <tbody>
    {% for f in dead_funcs %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td>{{ f.line }}</td><td>{{ f.loc }}</td><td>{{ f.cyclomatic_complexity }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--green)">No dead code candidates detected.</p>
  {% endif %}

  </div>


  <div class="subsection" style="margin-top:36px;padding-top:22px;border-top:1px solid var(--border)">
  <div class="section-title" style="margin-top:0">Magic Numbers</div>

  <details class="metric-info">
    <summary>About this analysis</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Magic Number Density</div><div class="mc-desc">Ratio of unnamed integer literals to LOC. Values of 0 and 1 are excluded as they are structurally meaningful. High density indicates missing named constants. <strong>Use it to:</strong> find hardware register/protocol/timing code that would read better with named constants. <strong>Don't:</strong> chase every hit -- math-heavy code (filter coefficients, calibration tables, CRC polynomials) legitimately has many domain-meaningful literals that shouldn't become named constants just to lower this number.</div><div class="mc-thresh">Threshold: {{ thresholds.magic_number_density }}</div></div>
        <div class="metric-card"><div class="mc-name">Literals shown</div><div class="mc-desc">The actual literal values found in the function body, deduplicated. These are candidates for named constants. A value appearing in many functions is the highest priority to name.</div></div>
      </div>
    </div>
  </details>
  {% if magic_funcs %}
  <p style="margin-bottom:12px;color:var(--dim)">
    {{ magic_funcs|length }} function(s) with magic number density above threshold ({{ thresholds.magic_number_density }}).
  </p>
  <div class="filter-row">
    <input type="text" id="magic-filter" placeholder="Filter by name or file..." oninput="filterTable('magic-table', this.value)">
  </div>
  <table id="magic-table">
    <thead><tr>
      <th onclick="sortTable('magic-table',0)">Function</th>
      <th onclick="sortTable('magic-table',1)">File</th>
      <th onclick="sortTable('magic-table',2)">Density</th>
      <th onclick="sortTable('magic-table',3)">Count</th>
      <th onclick="sortTable('magic-table',4)">LOC</th>
      <th>Literals</th>
    </tr></thead>
    <tbody>
    {% for f in magic_funcs %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td class="yellow">{{ "%.2f"|format(f.magic_number_density) }}</td>
      <td>{{ f.magic_numbers|length }}</td>
      <td>{{ f.loc }}</td>
      <td class="dim" style="font-size:11px">{{ f.magic_numbers | join(', ') }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--green)">&#10003; No functions exceed the magic number density threshold.</p>
  {% endif %}

  </div>

</div>


<!-- FUNCTION POINTERS -->
<div class="pane" id="pane-fnptrs">
  <details class="metric-info">
    <summary>About this analysis</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Dispatch tables</div><div class="mc-desc">Global variables whose initialisers contain function pointers (command tables, callback structs, strategy arrays). Each entry shows what functions are stored and which functions dispatch them.</div></div>
        <div class="metric-card"><div class="mc-name">Dispatchers</div><div class="mc-desc">Functions that read a table variable and therefore execute its stored functions at runtime. These are the effective callers -- the call chain flows through the dispatcher into every stored function.</div></div>
        <div class="metric-card"><div class="mc-name">Indirect call sites</div><div class="mc-desc">Call sites where the callee is a function pointer (member access, array subscript, or dereferenced pointer) rather than a named function. High counts mean the static call graph understates real coupling and ISR latency estimates are less reliable. <strong>Use it to:</strong> understand how much of your call graph is only visible through the dispatch-table recovery below, rather than direct calls -- a high count is a signal to double-check dead-code and fan-in results against this tab before trusting them.</div></div>
        <div class="metric-card"><div class="mc-name">Impact on other metrics</div><div class="mc-desc">Synthetic call edges are added from each dispatcher to every stored function. This corrects fan-in counts, removes false dead-code candidates, and improves ISR latency estimates for functions that run via dispatch tables. <strong>Limitation:</strong> only tables detectable as a global variable's static initialiser are recovered -- a table built up at runtime (e.g. populated in a loop with individual assignments rather than a single initialiser) won't be, and its stored functions will still show as dead/zero-fan-in.</div></div>
      </div>
    </div>
  </details>

  <h3 style="margin:16px 0 8px;font-size:0.9rem">Dispatch Tables  <span class="dim" style="font-size:11px;font-weight:400">({{ dispatch_tables|length }} table(s) found)</span></h3>
  {% if dispatch_tables %}
  <div class="filter-row">
    <input type="text" id="dt-filter" placeholder="Filter by table name or function..." oninput="filterTable('dt-table', this.value)">
  </div>
  <table id="dt-table">
    <thead><tr>
      <th onclick="sortTable('dt-table',0)">Table variable</th>
      <th onclick="sortTable('dt-table',1)">File</th>
      <th>Stored functions</th>
      <th>Usage</th>
    </tr></thead>
    <tbody>
    {% for t in dispatch_tables %}
    <tr>
      <td>{% if t.has_source %}<span class="clickable" onclick="showFn('{{ t.file_path }}',{{ t.line }})"><code>{{ t.var_name }}</code></span>{% else %}<code>{{ t.var_name }}</code>{% endif %}</td>
      <td class="dim">{{ t.file_short }}:{{ t.line }}</td>
      <td style="font-size:11px">
        {% for fn in t.stored_fns %}<code>{{ fn }}</code>{% if not loop.last %}, {% endif %}{% endfor %}
      </td>
      <td style="font-size:11px">
        {% if t.dispatchers %}
          <span class="dim" style="font-size:10px">called via: </span>
          {% for fn in t.dispatchers %}<code class="yellow">{{ fn }}</code>{% if not loop.last %}, {% endif %}{% endfor %}
        {% elif t.registered_into %}
          <span class="dim" style="font-size:10px">embedded in: </span>
          {% for v in t.registered_into %}<code style="color:var(--accent)">{{ v }}</code>{% if not loop.last %}, {% endif %}{% endfor %}
        {% else %}
          <span class="dim">not referenced by name in analysed scope</span>
        {% endif %}
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No dispatch tables detected in the analysed scope.</p>
  {% endif %}

  <h3 style="margin:24px 0 8px;font-size:0.9rem">Functions with Indirect Call Sites</h3>
  {% set indirect_funcs = functions | selectattr('indirect_call_count', 'gt', 0) | sort(attribute='indirect_call_count', reverse=true) | list %}
  {% if indirect_funcs %}
  <p style="font-size:11px;color:var(--dim);margin-bottom:8px">
    {{ indirect_funcs|length }} function(s) contain indirect call sites. ISR latency estimates for these functions are marked non-estimable (~).
  </p>
  <table>
    <thead><tr>
      <th>Function</th><th>File</th><th>Indirect calls</th><th>Direct calls</th><th>Dispatches tables</th>
    </tr></thead>
    <tbody>
    {% for f in indirect_funcs %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td class="yellow">{{ f.indirect_call_count }}</td>
      <td class="dim">{{ f.fan_out }}</td>
      <td style="font-size:11px">
        {% if f.dispatch_table_reads %}
          {% for t in f.dispatch_table_reads %}<code>{{ t }}</code>{% if not loop.last %}, {% endif %}{% endfor %}
        {% else %}<span class="dim">--</span>{% endif %}
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No indirect call sites detected.</p>
  {% endif %}
</div>


<!-- DISTRIBUTIONS -->
<div class="pane" id="pane-distributions">
  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Percentile Bars</div><div class="mc-desc">Each bar shows the value at a given percentile across all first-party functions: p10, p25, p50 (median), p75, p90, p95, p99. The red line marks the configured threshold. <strong>Use it to:</strong> see the whole shape of the distribution at a glance, not just a single summary number -- a metric with a long tail (p99 far past p90) behaves very differently from one that's uniformly high.</div></div>
        <div class="metric-card"><div class="mc-name">Exceedance %</div><div class="mc-abbr">Fitted log-normal distribution</div><div class="mc-desc">fwlens fits a log-normal distribution to the population of first-party functions for each metric and computes P(X &gt; threshold) from the fit, rather than just counting raw breaches. Above 10% is red; 5-10% is yellow. <strong>Use it to:</strong> distinguish "a third of the codebase is over threshold" (systemic, worth revisiting the threshold or the coding standard) from "a handful of outliers" (worth reviewing individually) -- a raw breach count alone can't tell these apart as clearly. <strong>Don't:</strong> over-trust this on a small function population -- a log-normal fit needs enough data points to be meaningful; treat it as indicative on a small first-party codebase rather than precise.</div></div>
        <div class="metric-card"><div class="mc-name">p50 / p90 / p99</div><div class="mc-desc">Summary statistics for the distribution. p50 is the median. p90 and p99 show the tail -- if p99 is much larger than p90, a small number of outlier functions are driving the tail rather than the whole population trending high.</div></div>
        <div class="metric-card"><div class="mc-name">Bar Colour</div><div class="mc-desc">Green bars are at or below the median. Yellow bars are in the upper half. Red bars are above the threshold. The colour transitions are relative to the threshold line, not the chart maximum.</div></div>
      </div>
    </div>
  </details>

  <div class="section-title">Threshold Breaches
    <span style="font-size:11px;font-weight:400;color:var(--dim)">
      Raw counts against configured thresholds -- a plain sanity check alongside the fitted-distribution Exceedance % below
    </span>
  </div>
  <table style="max-width:600px">
    <thead><tr><th>Threshold</th><th>Breach count</th><th>% of functions</th></tr></thead>
    <tbody>
    {% for b in breach_rows %}
    <tr>
      <td>{{ b.label }} &gt; {{ b.threshold }}</td>
      <td class="{{ 'red' if b.count > 0 else 'green' }}">{{ b.count }}</td>
      <td class="dim">{{ b.pct }}%</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <div class="section-title" style="margin-top:24px">Metric Distributions
    <span style="font-size:11px;font-weight:400;color:var(--dim)">
      Percentile bars for first-party functions. Red line = configured threshold.
    </span>
  </div>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:24px">
  {% for d in distributions %}
  <div class="dist-metric">
    <div class="dist-label">
      <strong>{{ d.metric }}</strong>
      &nbsp;&nbsp;p50={{ d.p50 }}&nbsp; p90={{ d.p90 }}&nbsp; p99={{ d.p99 }}
      &nbsp;&nbsp;exceedance=<span class="{{ 'red' if d.exceedance_pct > 10 else ('yellow' if d.exceedance_pct > 5 else 'green') }}">{{ d.exceedance_pct }}%</span>
    </div>
    {% for bar in d.bars %}
    <div class="dist-bar-row">
      <div class="dist-bar-label">{{ bar.label }}</div>
      <div class="dist-bar-track">
        <div class="dist-bar-fill" style="width:{{ bar.width_pct }}%;background:{{ bar.colour }}"></div>
        {% if bar.threshold_pct is not none %}
        <div class="dist-threshold" style="left:{{ bar.threshold_pct }}%"></div>
        {% endif %}
      </div>
      <span style="font-size:11px;color:var(--dim);width:40px">{{ bar.value }}</span>
    </div>
    {% endfor %}
  </div>
  {% endfor %}
  </div>
  <div class="section-title" style="margin-top:28px">Exceedance Probabilities
    <span style="font-size:11px;font-weight:400;color:var(--dim)">P(random function exceeds threshold) &mdash; derived from fitted log-normal distribution</span>
  </div>
  <div style="max-width:600px">
  {% for metric, prob in exceedances.items() %}
  {% set pct = (prob * 100)|round(1) %}
  {% set colour = "var(--red)" if prob > 0.1 else ("var(--yellow)" if prob > 0.05 else "var(--green)") %}
  <div class="exceedance-bar">
    <span style="width:200px;color:var(--dim)">{{ metric }}</span>
    <div class="bar-track"><div class="bar-fill" style="width:{{ [pct,100]|min }}%;background:{{ colour }}"></div></div>
    <span style="width:50px;text-align:right;color:{{ colour }}">{{ pct }}%</span>
  </div>
  {% endfor %}
  </div>

  <div class="section-title" style="margin-top:28px">Metric Correlations
    <span style="font-size:11px;font-weight:400;color:var(--dim)">
      binned point density across first-party functions -- darker cells hold more functions
    </span>
  </div>
  <div style="display:flex;gap:24px;flex-wrap:wrap">
    <div>
      <canvas id="heatmap-cc-effort" width="300" height="260"></canvas>
      <div style="font-size:11px;color:var(--dim);text-align:center;margin-top:4px">Cyclomatic Complexity vs Halstead Effort</div>
    </div>
    <div>
      <canvas id="heatmap-cc-loc" width="300" height="260"></canvas>
      <div style="font-size:11px;color:var(--dim);text-align:center;margin-top:4px">Cyclomatic Complexity vs Function Length (LOC)</div>
    </div>
    <div>
      <canvas id="heatmap-mi-volume" width="300" height="260"></canvas>
      <div style="font-size:11px;color:var(--dim);text-align:center;margin-top:4px">Maintainability Index vs Halstead Volume</div>
    </div>
  </div>

</div>


<!-- RISK -->
<div class="pane" id="pane-risk">
  <details class="metric-info">
    <summary>About this analysis</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Critical Functions</div><div class="mc-desc">Ranked by fan-in × SDI. High fan-in means many callers will break; high SDI means the function is structurally complex to change correctly. This combination is the highest defect-risk in the codebase. <strong>Use it to:</strong> pick where a bug fix or refactor pays off most -- both dimensions have to be bad for a function to rank high here, so this list is naturally short and high-signal. <strong>Don't</strong> use it as the only prioritisation source -- it says nothing about how often the code path actually runs; combine with the Composite Risk table (Change History tab) which also factors in churn.</div></div>
        <div class="metric-card"><div class="mc-name">Assert Coverage</div><div class="mc-desc">Fraction of functions that contain at least one assert. Functions with high CC and zero asserts have no defensive checks -- parameter validation failures and impossible states are silent. Particularly important for functions called from many places. <strong>Note:</strong> only recognises the function names in config's <code>assert_names</code> (default assert/ASSERT/etc, plus OS_Error automatically when rtos.kind is embos). If your codebase wraps assertions in a different macro, add its expanded call target to <code>assert_names</code> or this reads as near-zero regardless of actual assertion usage.</div></div>
        <div class="metric-card"><div class="mc-name">Stack Depth</div><div class="mc-desc">Maximum call chain length from each function. Deep chains risk stack overflow, especially under RTOS where each task has a fixed stack. Functions reachable from ISR context with deep chains are the highest risk. <strong>Note:</strong> the frame-size estimate (LOC/4) is a rough proxy, not linker-accurate -- for a byte-accurate figure, correlate against your compiler's own stack usage reports (e.g. IAR's <code>--stack_usage</code>/.su files). Functions on a call-graph cycle (recursion, or indirect mutual calls through callback registration) are marked non-estimable (~) rather than given a wrong number.</div></div>
      </div>
    </div>
  </details>

  <!-- Critical Functions -->
  <h3 style="margin:16px 0 6px;font-size:0.9rem">Critical Functions
    <span class="dim" style="font-size:11px;font-weight:400"> -- ranked by fan-in &times; SDI</span>
  </h3>
  <p style="font-size:11px;color:var(--dim);margin-bottom:8px">
    Fan-in is the blast radius of any change. SDI is a percentile-ranked composite of structural complexity.
    Their product identifies functions where a defect will affect the most callers and is hardest to avoid introducing.
  </p>
  {% if critical_funcs %}
  <div class="filter-row">
    <input type="text" id="crit-filter" placeholder="Filter..." oninput="filterTable('crit-table', this.value)">
  </div>
  <table id="crit-table">
    <thead><tr>
      <th onclick="sortTable('crit-table',0)">Function</th>
      <th onclick="sortTable('crit-table',1)">File</th>
      <th onclick="sortTable('crit-table',2)" title="fan_in × SDI">Risk</th>
      <th onclick="sortTable('crit-table',3)" title="Number of distinct callers">Fan-in</th>
      <th onclick="sortTable('crit-table',4)">CC</th>
      <th onclick="sortTable('crit-table',5)" title="Structural Debt Index 0-1">SDI</th>
      <th onclick="sortTable('crit-table',6)" title="Halstead estimate of latent bugs">Bugs~</th>
      <th title="Number of assert() calls in this function">Asserts</th>
    </tr></thead>
    <tbody>
    {% for f in critical_funcs %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td class="red">{{ f.risk_score }}</td>
      <td>{{ f.fan_in }}</td>
      <td class="{{ 'red' if f.cyclomatic_complexity > 15 else 'yellow' if f.cyclomatic_complexity > 8 else '' }}">{{ f.cyclomatic_complexity }}</td>
      <td class="{{ 'red' if f.structural_debt_index > 0.8 else 'yellow' if f.structural_debt_index > 0.6 else '' }}">{{ "%.2f"|format(f.structural_debt_index) }}</td>
      <td class="dim">{{ f.halstead_bugs }}</td>
      <td class="{{ 'dim' if f.assert_count == 0 else 'green' }}">{{ f.assert_count }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No functions above risk threshold.</p>
  {% endif %}

  <!-- Assert Coverage Gaps -->
  <h3 style="margin:28px 0 6px;font-size:0.9rem">Assert Coverage Gaps
    <span class="dim" style="font-size:11px;font-weight:400"> -- high CC + high fan-in + zero asserts</span>
  </h3>
  <p style="font-size:11px;color:var(--dim);margin-bottom:8px">
    Assert coverage across all first-party functions:
    <strong style="color:{% if assert_coverage < 10 %}var(--red){% elif assert_coverage < 30 %}var(--yellow){% else %}var(--green){% endif %}">
      {{ assert_coverage }}%
    </strong>
    ({{ assert_total }} of {{ functions|length }} functions contain at least one assert).
    The table below shows high-risk functions with no defensive checks.
  </p>
  {% if assert_gap_funcs %}
  <table>
    <thead><tr>
      <th>Function</th><th>File</th>
      <th title="fan_in × CC risk product">Risk</th>
      <th>Fan-in</th><th>CC</th>
      <th title="Average Halstead effort -- cognitive load of the function">Effort</th>
    </tr></thead>
    <tbody>
    {% for f in assert_gap_funcs %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td class="yellow">{{ f.risk }}</td>
      <td>{{ f.fan_in }}</td>
      <td class="{{ 'red' if f.cyclomatic_complexity > 15 else 'yellow' }}">{{ f.cyclomatic_complexity }}</td>
      <td class="dim">{{ f.halstead_effort }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--green)">&#10003; No high-risk functions lack assert coverage.</p>
  {% endif %}

  <!-- Stack Depth -->
  <h3 style="margin:28px 0 6px;font-size:0.9rem">Deep Call Chains</h3>
  <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:10px 16px">
      <div style="font-size:11px;color:var(--dim)">Max depth</div>
      <div style="font-size:22px;font-weight:600;color:{% if stack_stats.max > 50 %}var(--red){% else %}var(--accent){% endif %}">{{ stack_stats.max }}</div>
    </div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:10px 16px">
      <div style="font-size:11px;color:var(--dim)">Mean depth</div>
      <div style="font-size:22px;font-weight:600;color:var(--accent)">{{ stack_stats.mean }}</div>
    </div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:10px 16px">
      <div style="font-size:11px;color:var(--dim)">Median depth</div>
      <div style="font-size:22px;font-weight:600;color:var(--accent)">{{ stack_stats.median }}</div>
    </div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:10px 16px">
      <div style="font-size:11px;color:var(--dim)">&gt;50 levels</div>
      <div style="font-size:22px;font-weight:600;color:{% if stack_stats.over50 > 0 %}var(--yellow){% else %}var(--green){% endif %}">{{ stack_stats.over50 }}</div>
    </div>
    <div style="background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:10px 16px">
      <div style="font-size:11px;color:var(--dim)">&gt;20 levels</div>
      <div style="font-size:22px;font-weight:600;color:var(--accent)">{{ stack_stats.over20 }}</div>
    </div>
  </div>
  <p style="font-size:11px;color:var(--dim);margin-bottom:8px">
    Depth is the maximum call chain length reachable from this function. Deep chains risk stack overflow
    under RTOS. ISR-reachable functions with deep chains are highest priority.
  </p>
  {% if stack_rows %}
  <table>
    <thead><tr>
      <th>Function</th><th>File</th>
      <th title="Maximum call chain length">Depth</th>
      <th title="Whether the full chain could be estimated (false = indirect calls present)">Est.</th>
      <th>ISR</th><th>Fan-in</th><th>CC</th>
    </tr></thead>
    <tbody>
    {% for f in stack_rows %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td class="{{ 'red' if f.depth > 50 else 'yellow' if f.depth > 20 else '' }}">{{ f.depth }}</td>
      <td class="dim">{{ '~' if not f.estimable else '&#10003;' }}</td>
      <td class="{{ 'yellow' if f.is_isr else 'dim' }}">{{ 'Y' if f.is_isr else 'N' }}</td>
      <td>{{ f.fan_in }}</td>
      <td>{{ f.cyclomatic_complexity }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <div class="section-title" style="margin-top:24px">Composite Risk Ranking
    <span style="font-size:11px;font-weight:400;color:var(--dim)">
      Weighted fusion of SDI, hotspot score, module pain, ISR risk, and stack depth --
      see the Defects &amp; Estimation and Metrics Reference tabs for the weighting
    </span>
  </div>
  {% if composite_risk_rows %}
  <input type="text" id="composite-risk-filter" placeholder="Filter by function or file..." oninput="filterTable('composite-risk-table', this.value)">
  <table id="composite-risk-table">
    <thead><tr>
      <th onclick="sortTable('composite-risk-table',0)">Function</th>
      <th onclick="sortTable('composite-risk-table',1)">File</th>
      <th onclick="sortTable('composite-risk-table',2)">Risk score</th>
    </tr></thead>
    <tbody>
    {% for f in composite_risk_rows %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td>
        <div class="score-bar">
          <span class="{{ 'red' if f.score >= 0.5 else 'yellow' if f.score >= 0.3 else '' }}">{{ "%.2f"|format(f.score) }}</span>
          <div class="score-bar-track"><div class="score-bar-fill" style="width:{{ (f.score*100)|round|int }}%;background:{{ 'var(--red)' if f.score >= 0.5 else 'var(--yellow)' if f.score >= 0.3 else 'var(--dim)' }}"></div></div>
        </div>
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No functions with a nonzero composite risk score.</p>
  {% endif %}
</div>


<!-- COUPLING / COHESION -->
<div class="pane" id="pane-coupling">
  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Coupling (Fan-out)</div><div class="mc-desc">A module is considered highly coupled when its fan-out exceeds the threshold. High coupling means the module depends on many others -- any change to a dependency can break it, and it cannot be tested in isolation. <strong>Use it to:</strong> find modules that would benefit from an interface/abstraction layer between them and their many dependencies. <strong>Don't:</strong> flag a genuine integration/glue module (one whose whole job is wiring other modules together, e.g. a top-level `main.c` or a hardware bring-up file) as a coupling problem -- that's often the correct shape for that specific role.</div><div class="mc-thresh">Threshold: fan-out &gt; {{ thresholds.fan_out }}</div></div>
        <div class="metric-card"><div class="mc-name">Cohesion (Internal Call Cohesion)</div><div class="mc-desc">The fraction of function calls within the module that stay within the module. A value near 1 means functions in the module mostly call each other -- they form a coherent unit. A low value means the functions are loosely related and the module may be a bag of unrelated utilities. <strong>Use it to:</strong> find "utils.c"-style files worth splitting along the lines of what actually calls what internally. <strong>Don't:</strong> expect cohesion near 1 from a module that's deliberately a flat collection of independent helper functions (e.g. a string-formatting utility file) -- low internal calling between unrelated helpers isn't a defect there, it's the design.</div><div class="mc-thresh">Threshold: cohesion &lt; {{ thresholds.cohesion_min }}</div></div>
        <div class="metric-card"><div class="mc-name">High Coupling &amp; Low Cohesion</div><div class="mc-desc">The intersection of the two lists. These modules depend heavily on the outside world while their own functions barely interact. They are the highest priority for structural refactoring: split the module into cohesive units and reduce outgoing dependencies. <strong>Use it to:</strong> triage where a refactor pays off most -- both conditions have to be true for a module to land here, so this list is naturally short and high-signal, similar to the Risk tab's Critical Functions ranking.</div></div>
        <div class="metric-card"><div class="mc-name">Instability</div><div class="mc-desc">Shown for context. A highly coupled module with high instability is free to change internally, but its broad dependency surface still presents risk. A highly coupled module with low instability is especially dangerous -- it is hard to change but exposes many dependencies. See the Modules tab for the full instability/abstractness explanation.</div></div>
      </div>
    </div>
  </details>

  <div class="section-title">High Coupling
    <span style="font-size:11px;font-weight:400;color:var(--dim)">
      fan-out &gt; {{ thresholds.fan_out }} -- modules with too many outgoing dependencies
    </span>
  </div>
  {% if high_coupling %}
  <div class="filter-row">
    <input type="text" id="hc-filter" placeholder="Filter by name or layer..." oninput="filterTable('hc-table', this.value)">
  </div>
  <table id="hc-table">
    <thead><tr>
      <th onclick="sortTable('hc-table',0)">Module</th>
      <th onclick="sortTable('hc-table',1)">Layer</th>
      <th onclick="sortTable('hc-table',2)">Fan-in</th>
      <th onclick="sortTable('hc-table',3)">Fan-out</th>
      <th onclick="sortTable('hc-table',4)">Instability</th>
      <th onclick="sortTable('hc-table',5)">Cohesion</th>
      <th onclick="sortTable('hc-table',6)">Cycle</th>
    </tr></thead>
    <tbody>
    {% for m in high_coupling %}
    <tr>
      <td>{% if m.has_source %}<span class="clickable" onclick="showFile('{{ m.file_path }}')">{{ m.name }}</span>{% else %}{{ m.name }}{% endif %}</td>
      <td class="dim">{{ m.layer or 'Unknown' }}</td>
      <td>{{ m.fan_in }}</td>
      <td class="red">{{ m.fan_out }}</td>
      <td class="{{ 'red' if m.instability > 0.8 else ('yellow' if m.instability > 0.6 else '') }}">{{ "%.2f"|format(m.instability) }}</td>
      <td>{{ "%.2f"|format(m.internal_call_cohesion) }}</td>
      <td class="{{ 'red' if m.in_cycle else 'dim' }}">{{ 'Y' if m.in_cycle else 'N' }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--green)">&#10003; No modules exceed the fan-out threshold.</p>
  {% endif %}

  <div class="section-title" style="margin-top:28px">Low Cohesion
    <span style="font-size:11px;font-weight:400;color:var(--dim)">
      internal-call cohesion &lt; {{ thresholds.cohesion_min }} -- modules whose functions rarely call each other
    </span>
  </div>
  {% if low_cohesion %}
  <div class="filter-row">
    <input type="text" id="lc-filter" placeholder="Filter by name or layer..." oninput="filterTable('lc-table', this.value)">
  </div>
  <table id="lc-table">
    <thead><tr>
      <th onclick="sortTable('lc-table',0)">Module</th>
      <th onclick="sortTable('lc-table',1)">Layer</th>
      <th onclick="sortTable('lc-table',2)">Fan-in</th>
      <th onclick="sortTable('lc-table',3)">Fan-out</th>
      <th onclick="sortTable('lc-table',4)">Instability</th>
      <th onclick="sortTable('lc-table',5)">Cohesion</th>
      <th onclick="sortTable('lc-table',6)">Cycle</th>
    </tr></thead>
    <tbody>
    {% for m in low_cohesion %}
    <tr>
      <td>{% if m.has_source %}<span class="clickable" onclick="showFile('{{ m.file_path }}')">{{ m.name }}</span>{% else %}{{ m.name }}{% endif %}</td>
      <td class="dim">{{ m.layer or 'Unknown' }}</td>
      <td>{{ m.fan_in }}</td>
      <td>{{ m.fan_out }}</td>
      <td class="{{ 'red' if m.instability > 0.8 else ('yellow' if m.instability > 0.6 else '') }}">{{ "%.2f"|format(m.instability) }}</td>
      <td class="red">{{ "%.2f"|format(m.internal_call_cohesion) }}</td>
      <td class="{{ 'red' if m.in_cycle else 'dim' }}">{{ 'Y' if m.in_cycle else 'N' }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--green)">&#10003; No modules fall below the cohesion threshold.</p>
  {% endif %}

  <div class="section-title" style="margin-top:28px">High Coupling <span style="color:var(--dim)">&amp;</span> Low Cohesion
    <span style="font-size:11px;font-weight:400;color:var(--dim)">
      fan-out &gt; {{ thresholds.fan_out }} and cohesion &lt; {{ thresholds.cohesion_min }} -- highest refactoring priority
    </span>
  </div>
  {% if high_coupling_low_cohesion %}
  <div class="filter-row">
    <input type="text" id="hclc-filter" placeholder="Filter by name or layer..." oninput="filterTable('hclc-table', this.value)">
  </div>
  <table id="hclc-table">
    <thead><tr>
      <th onclick="sortTable('hclc-table',0)">Module</th>
      <th onclick="sortTable('hclc-table',1)">Layer</th>
      <th onclick="sortTable('hclc-table',2)">Fan-in</th>
      <th onclick="sortTable('hclc-table',3)">Fan-out</th>
      <th onclick="sortTable('hclc-table',4)">Instability</th>
      <th onclick="sortTable('hclc-table',5)">Cohesion</th>
      <th onclick="sortTable('hclc-table',6)">Cycle</th>
    </tr></thead>
    <tbody>
    {% for m in high_coupling_low_cohesion %}
    <tr>
      <td>{% if m.has_source %}<span class="clickable" onclick="showFile('{{ m.file_path }}')">{{ m.name }}</span>{% else %}{{ m.name }}{% endif %}</td>
      <td class="dim">{{ m.layer or 'Unknown' }}</td>
      <td>{{ m.fan_in }}</td>
      <td class="red">{{ m.fan_out }}</td>
      <td class="{{ 'red' if m.instability > 0.8 else ('yellow' if m.instability > 0.6 else '') }}">{{ "%.2f"|format(m.instability) }}</td>
      <td class="red">{{ "%.2f"|format(m.internal_call_cohesion) }}</td>
      <td class="{{ 'red' if m.in_cycle else 'dim' }}">{{ 'Y' if m.in_cycle else 'N' }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--green)">&#10003; No modules have both high coupling and low cohesion.</p>
  {% endif %}

  <!-- Global Coupling -->
  <h3 style="margin:28px 0 6px;font-size:0.9rem">Global Variable Coupling
    <span class="dim" style="font-size:11px;font-weight:400"> -- hidden coupling not visible in the call graph</span>
  </h3>
  <p style="font-size:11px;color:var(--dim);margin-bottom:8px">
    Functions that read or write many global variables have hidden coupling that does not appear in
    fan-in/fan-out counts. A change to any shared global can break these functions without any call
    graph edge pointing to them.
  </p>
  {% if global_coupling %}
  <div class="filter-row">
    <input type="text" id="gc-filter" placeholder="Filter..." oninput="filterTable('gc-table', this.value)">
  </div>
  <table id="gc-table">
    <thead><tr>
      <th onclick="sortTable('gc-table',0)">Function</th>
      <th onclick="sortTable('gc-table',1)">File</th>
      <th onclick="sortTable('gc-table',2)" title="Total globals read + written">Total</th>
      <th onclick="sortTable('gc-table',3)">Reads</th>
      <th onclick="sortTable('gc-table',4)">Writes</th>
      <th onclick="sortTable('gc-table',5)">Fan-out</th>
      <th onclick="sortTable('gc-table',6)">Fan-in</th>
      <th>Sample globals read</th>
    </tr></thead>
    <tbody>
    {% for f in global_coupling %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td class="{{ 'red' if f.total > 10 else 'yellow' if f.total > 6 else '' }}">{{ f.total }}</td>
      <td>{{ f.reads }}</td>
      <td class="{{ 'yellow' if f.writes > 0 else 'dim' }}">{{ f.writes }}</td>
      <td>{{ f.fan_out }}</td>
      <td>{{ f.fan_in }}</td>
      <td style="font-size:11px;color:var(--dim)">
        {% for g in f.top_reads %}<code>{{ g }}</code>{% if not loop.last %}, {% endif %}{% endfor %}
        {% if f.reads > 6 %}<span class="dim"> +{{ f.reads - 6 }} more</span>{% endif %}
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No functions with significant global variable coupling detected.</p>
  {% endif %}

  <div class="section-title" style="margin-top:24px">Information Flow Complexity (IF4)
    <span style="font-size:11px;font-weight:400;color:var(--dim)">
      Henry &amp; Kafura -- length &times; (fan-in &times; fan-out)&sup2;. Needs nonzero fan-in
      AND fan-out; pure leaf functions and pure entry points always score 0 by construction.
    </span>
  </div>
  {% if information_flow_rows %}
  <table id="if4-table">
    <thead><tr>
      <th onclick="sortTable('if4-table',0)">Function</th>
      <th onclick="sortTable('if4-table',1)">File</th>
      <th onclick="sortTable('if4-table',2)">Fan-in</th>
      <th onclick="sortTable('if4-table',3)">Fan-out</th>
      <th onclick="sortTable('if4-table',4)">LOC</th>
      <th onclick="sortTable('if4-table',5)">IF4</th>
    </tr></thead>
    <tbody>
    {% for f in information_flow_rows %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td>{{ f.fan_in }}</td>
      <td>{{ f.fan_out }}</td>
      <td>{{ f.loc }}</td>
      <td class="{{ 'red' if f.if4 > 1000 else 'yellow' if f.if4 > 100 else '' }}">{{ "{:,.0f}".format(f.if4) }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No functions with nonzero fan-in and fan-out both -- IF4 needs both to score above 0.</p>
  {% endif %}

</div>


<!-- RTOS -->
<div class="pane" id="pane-rtos">
  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Tasks &amp; Priorities</div><div class="mc-desc">Extracted from RTOS task-creation call sites (config.rtos.task_functions). Priority and stack size are only resolved to real values when the call site uses a literal -- a #define'd macro shows as unresolved raw text, since fwlens doesn't run the preprocessor.</div></div>
        <div class="metric-card"><div class="mc-name">Priority Collisions</div><div class="mc-desc">Two or more tasks created at the same resolved priority. Not necessarily wrong (embOS round-robins same-priority tasks), but worth confirming it's intentional. <strong>Use it to:</strong> check whether tasks that share a priority genuinely have equal urgency -- if one is meant to preempt the other under load, a collision here means that assumption is currently false. <strong>Don't:</strong> assume every collision needs separate priorities -- several genuinely equal-urgency tasks round-robinning is a legitimate, common design.</div></div>
        <div class="metric-card"><div class="mc-name">Priority Inversion Candidates</div><div class="mc-abbr">Sha, Rajkumar, Lehoczky 1990</div><div class="mc-desc">A plain counting semaphore (OS_SEMAPHORE_Create -- no priority inheritance in embOS) waited on by tasks of different priority. A lower-priority task holding it can block a higher-priority waiter indefinitely if a medium-priority task preempts it. embOS's mutex (OS_MUTEX_Create, priority-inheriting) and reader/writer lock are not flagged. <strong>Use it to:</strong> find shared semaphores that would be safer as mutexes if what they're really protecting is a critical section (as opposed to genuinely counting available resources, which is what a semaphore is for). <strong>Don't:</strong> treat every flagged semaphore as a confirmed bug -- this identifies the structural precondition (non-inheriting object shared across priorities), not a proven schedulability violation; whether it actually causes unbounded blocking depends on real timing behaviour this static check can't see.</div></div>
        <div class="metric-card"><div class="mc-name">Unused Objects</div><div class="mc-desc">A sync object created but never touched by any configured usage function -- either dead code, or a usage function name missing from config.rtos.usage_functions.</div></div>
        <div class="metric-card"><div class="mc-name">Return-value handle APIs</div><div class="mc-desc">Some RTOSes (FreeRTOS) return the created handle via return value (<code>q = xQueueCreate(...)</code>) rather than writing to an output-pointer argument the way embOS does. List those creation functions in config.rtos.return_value_functions so the object's name is read from the assignment target instead of the first argument -- otherwise it would read a nonsense value like the queue length.</div></div>
        <div class="metric-card"><div class="mc-name">RTOS Object Graph</div><div class="mc-desc">Tasks (sorted by priority) and sync objects as separate node types, edges coloured by access kind (amber = wait/blocking-acquire, green = signal/release). A different architecture axis from the file/module dependency graph -- organised by runtime concurrency structure, not source layout.</div></div>
      </div>
    </div>
  </details>

  {% if meta.rtos_kind == 'none' %}
  <p style="color:var(--dim)">RTOS analysis is disabled (rtos.kind is "none" in config.yaml). Set rtos.kind: embos to enable task/synchronisation extraction.</p>
  {% elif not rtos_task_rows and not rtos_object_rows %}
  <p style="color:var(--dim)">RTOS analysis is enabled ({{ meta.rtos_kind }}) but no task or sync-object creation calls were found -- check config.rtos's function-name lists against your actual RTOS.h.</p>
  {% else %}

  <div class="section-title">RTOS Object Graph <span style="font-size:11px;font-weight:400;color:var(--dim)">({{ meta.rtos_kind }})</span></div>
  <div style="margin-bottom:24px">
    {{ rtos_object_graph_svg | safe }}
    <div style="display:flex;gap:16px;margin-top:8px;font-size:11px;color:var(--dim)">
      <span><span style="display:inline-block;width:16px;height:2px;background:#f59e0b;margin-right:4px;vertical-align:middle"></span>wait / blocking acquire</span>
      <span><span style="display:inline-block;width:16px;height:2px;background:#22c55e;margin-right:4px;vertical-align:middle"></span>signal / release</span>
      <span><span style="display:inline-block;width:16px;height:2px;background:#64748b;margin-right:4px;vertical-align:middle"></span>other</span>
    </div>
  </div>

  <div class="section-title">Tasks <span style="font-size:11px;font-weight:400;color:var(--dim)">{{ meta.rtos_task_count }}</span></div>
  <input type="text" id="rtos-task-filter" placeholder="Filter by task or entry function..." oninput="filterTable('rtos-task-table', this.value)">
  <table id="rtos-task-table">
    <thead><tr><th>Task</th><th>TCB</th><th>Priority</th><th>Entry function</th><th>Stack</th><th>Stack size</th></tr></thead>
    <tbody>
    {% for t in rtos_task_rows %}
    <tr>
      <td style="color:var(--accent)">{{ t.name }}</td>
      <td class="dim">{{ t.tcb_var }}</td>
      <td class="{{ '' if t.priority_value is not none else 'yellow' }}">{{ t.priority_value if t.priority_value is not none else t.priority_expr }}</td>
      <td>{% if t.has_source %}<span class="clickable" onclick="showFn('{{ t.file_path }}',{{ t.line }})">{{ t.entry_function }}</span>{% else %}{{ t.entry_function }}{% endif %}</td>
      <td class="dim">{{ t.stack_expr }}</td>
      <td class="{{ '' if t.stack_size_value is not none else 'yellow' }}">{{ t.stack_size_value if t.stack_size_value is not none else t.stack_size_expr }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <div class="section-title" style="margin-top:24px">Synchronisation Objects</div>
  <input type="text" id="rtos-obj-filter" placeholder="Filter by object or file..." oninput="filterTable('rtos-obj-table', this.value)">
  <table id="rtos-obj-table">
    <thead><tr><th>Object</th><th>Kind</th><th>File</th><th>Status</th></tr></thead>
    <tbody>
    {% for o in rtos_object_rows %}
    <tr>
      <td style="color:var(--accent)">{{ o.var_name }}</td>
      <td>{{ o.kind }}</td>
      <td class="dim">{{ o.file_short }}</td>
      <td>{% if o.unused %}<span class="yellow">unused</span>{% else %}<span class="dim">used</span>{% endif %}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  {% if rtos_collision_rows %}
  <div class="section-title" style="margin-top:24px">Priority Collisions <span style="font-size:11px;font-weight:400;color:var(--red)">{{ rtos_collision_rows|length }}</span></div>
  <table style="max-width:600px">
    <thead><tr><th>Priority</th><th>Tasks</th></tr></thead>
    <tbody>
    {% for c in rtos_collision_rows %}
    <tr><td>{{ c.priority_value }}</td><td>{{ c.task_names|join(', ') }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  {% if rtos_inversion_rows %}
  <div class="section-title" style="margin-top:24px">Priority Inversion Candidates <span style="font-size:11px;font-weight:400;color:var(--red)">{{ rtos_inversion_rows|length }}</span></div>
  <table style="max-width:600px">
    <thead><tr><th>Object</th><th>Tasks (priority)</th></tr></thead>
    <tbody>
    {% for r in rtos_inversion_rows %}
    <tr>
      <td class="red">{{ r.object_var }}</td>
      <td>{% for name, prio in r.pairs %}{{ name }}({{ prio }}){% if not loop.last %}, {% endif %}{% endfor %}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  {% endif %}


  <div class="subsection" style="margin-top:36px;padding-top:22px;border-top:1px solid var(--border)">
  <div class="section-title" style="margin-top:0">State Machines</div>

  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">State Machine Detection</div><div class="mc-desc">Switch-statement-based: the switch's controlling expression is the "state variable" (raw text, not semantic resolution), and an assignment to that same variable within a case body is a transition from that case's label to the assigned value. Needs 2+ cases and at least one detected transition. A heuristic, not semantic analysis -- doesn't resolve enum/macro values, so equivalent constants under different spellings show as different states.</div></div>
        <div class="metric-card"><div class="mc-name">How to use this tab</div><div class="mc-desc"><strong>Use it to:</strong> get a quick visual sanity-check of a state machine's shape without reading the whole switch -- spotting a state with no outgoing transition (a dead end) or an unexpected edge back to an earlier state is much faster from the diagram than from source. <strong>Don't:</strong> treat this as a formal state-machine verification tool -- it can't tell you whether every transition is actually reachable at runtime, only what transitions the source text contains.</div></div>
        <div class="metric-card"><div class="mc-name">Common false negatives</div><div class="mc-desc">A state machine driven by a struct field (<code>self->state = ...</code>) rather than a plain local/global variable, or one where the "state" is computed via a function call rather than a direct switch on a variable, won't be detected at all -- the heuristic only looks at the switch's controlling expression's raw text. Table-driven state machines (an array of function pointers indexed by state, with the next state returned by the handler) are also invisible to this detector -- see the Function Pointers tab's dispatch-table recovery for that pattern instead.</div></div>
      </div>
    </div>
  </details>

  {% if not state_machine_entries %}
  <p style="color:var(--dim)">No switch-based state machines detected.</p>
  {% else %}
  <p style="color:var(--dim);font-size:12px;margin-bottom:16px">
    {{ meta.state_machine_count }} detected{% if meta.state_machine_count > meta.state_machine_shown %}, showing the first {{ meta.state_machine_shown }} (see state_machines.csv for the rest){% endif %}.
  </p>
  {% for sm in state_machine_entries %}
  <div style="margin-bottom:28px;padding-bottom:20px;border-bottom:1px solid var(--border)">
    <div class="section-title">
      {% if sm.has_source %}<span class="clickable" onclick="showFn('{{ sm.file_path }}',{{ sm.line }})">{{ sm.function_name }}</span>{% else %}{{ sm.function_name }}{% endif %}
      <span style="font-size:11px;font-weight:400;color:var(--dim)">{{ sm.file_short }} -- state var: {{ sm.state_var }} -- {{ sm.state_count }} states, {{ sm.transition_count }} transitions</span>
    </div>
    {{ sm.svg | safe }}
  </div>
  {% endfor %}
  {% endif %}

  </div>


  <div class="subsection" style="margin-top:36px;padding-top:22px;border-top:1px solid var(--border)">
  <div class="section-title" style="margin-top:0">ISR Risk &amp; Races</div>

  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Own CC</div><div class="mc-desc">Cyclomatic complexity of the ISR function body itself, excluding callees. Even moderate CC in an ISR is a concern because all execution paths run at interrupt priority.</div></div>
        <div class="metric-card"><div class="mc-name">Transitive CC</div><div class="mc-desc">Sum of cyclomatic complexity of all functions reachable from the ISR via the call graph. Represents the total worst-case complexity executed at interrupt priority.</div></div>
        <div class="metric-card"><div class="mc-name">Call Depth</div><div class="mc-desc">Maximum depth of the call chain rooted at the ISR. Deep call chains in an ISR increase stack usage and make latency analysis harder.</div></div>
        <div class="metric-card"><div class="mc-name">Risk Score</div><div class="mc-desc">A composite score combining own CC, transitive CC, and call depth. Above 50 is red; 20-50 is yellow. The tilde badge (~) means one or more callees could not be analysed, so the score is a lower bound.</div></div>
        <div class="metric-card"><div class="mc-name">~ Badge</div><div class="mc-desc">Indicates the transitive analysis is incomplete -- at least one callee in the chain calls a function outside the project scope or via a function pointer. The reported score underestimates the true risk.</div></div>
        <div class="metric-card"><div class="mc-name">How to read the ranking</div><div class="mc-desc">Two ISRs sharing the same transitive CC pool is expected and not itself a concern -- e.g. UART and SPI handlers that both call the same underlying driver functions will naturally show similar transitive complexity. The real signal is an ISR calling into <em>business logic</em> with high own CC, or a call depth beyond 5-6 levels -- that's what actually risks jitter, re-entrancy bugs, and latency violations, not a high number by itself.</div></div>
      </div>
    </div>
  </details>
  {% if isr_risks %}
  <input type="text" id="isr-filter" placeholder="Filter by ISR or file..." oninput="filterTable('isr-table', this.value)">
  <table id="isr-table">
    <thead><tr>
      <th>ISR</th><th>File</th><th>Own CC</th>
      <th>Transitive CC</th><th>Call depth</th><th>Risk score</th>
    </tr></thead>
    <tbody>
    {% for r in isr_risks %}
    <tr>
      <td>{% if r.has_source %}<span class="clickable" onclick="showFn('{{ r.file_path }}',{{ r.line }})">{{ r.isr_name }}</span>{% else %}{{ r.isr_name }}{% endif %}{% if r.non_estimable %} <span class="badge badge-yellow">~</span>{% endif %}</td>
      <td class="dim">{{ r.file_short }}</td>
      <td>{{ r.own_cc }}</td>
      <td>{{ r.transitive_cc_sum }}</td>
      <td>{{ r.call_depth }}</td>
      <td class="{{ 'red' if r.risk_score > 50 else 'yellow' if r.risk_score > 20 else '' }}">{{ "%.0f"|format(r.risk_score) }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No ISR functions detected.</p>
  {% endif %}

  <div class="section-title" style="margin-top:24px">ISR / Main-Loop Shared-Variable Risk
    <span style="font-size:11px;font-weight:400;color:var(--dim)">
      Non-volatile variables accessed from both an ISR and normal code -- non-atomic shared-state risk
    </span>
  </div>
  {% if race_risk_rows %}
  <input type="text" id="race-filter" placeholder="Filter by variable or file..." oninput="filterTable('race-table', this.value)">
  <table id="race-table">
    <thead><tr><th>Variable</th><th>File</th><th>ISR access</th><th>Main-loop access</th></tr></thead>
    <tbody>
    {% for g in race_risk_rows %}
    <tr>
      <td class="red">{{ g.name }}</td>
      <td class="dim">{{ g.file_short }}</td>
      <td style="font-size:11px">{% for n in g.isr_side[:4] %}<code>{{ n }}</code>{% if not loop.last %}, {% endif %}{% endfor %}{% if g.isr_side|length > 4 %} <span class="dim">+{{ g.isr_side|length - 4 }}</span>{% endif %}</td>
      <td style="font-size:11px">{% for n in g.main_side[:4] %}<code>{{ n }}</code>{% if not loop.last %}, {% endif %}{% endfor %}{% if g.main_side|length > 4 %} <span class="dim">+{{ g.main_side|length - 4 }}</span>{% endif %}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No non-volatile dual-context global variables detected.</p>
  {% endif %}

  </div>

</div>


<!-- CHANGE HISTORY -->
<div class="pane" id="pane-gittrends">
  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Hotspots</div><div class="mc-abbr">Tornhill 2015; churn x structural debt</div><div class="mc-desc">Percentile rank of commit count multiplied by percentile rank of structural debt index, within the first-party population. Files that change often AND are already structurally risky score highest -- a better prioritisation signal in practice than complexity alone, since it points at where defects actually cluster rather than just where the code is hardest to read. <strong>Use it to:</strong> pick where a refactor pays off fastest -- a high-complexity file nobody touches is lower priority than a moderately complex one under constant change. <strong>Don't:</strong> chase a rank-one hotspot blindly if it's a recent addition still being actively developed -- expected high churn during initial development looks identical to churn on a long-stable file suddenly becoming unstable; check the churn heatmap below to tell the two apart.</div></div>
        <div class="metric-card"><div class="mc-name">Change Coupling</div><div class="mc-abbr">Tornhill 2015; logical coupling</div><div class="mc-desc">First-party file pairs that repeatedly change together in the same commit -- coupling the static call/include graph can miss entirely. Needs 3+ co-changes and 30%+ Jaccard coupling to be reported; mega-commits touching 20+ files are excluded as noise. <strong>Use it to:</strong> find missing abstractions -- two files that always change together probably belong together, or are both reaching around a shared concept that should be named and extracted. <strong>Don't:</strong> assume every pair is a design problem -- a header and its own .c file, or a driver and its own test file, are expected to co-change and aren't evidence of anything wrong.</div></div>
        <div class="metric-card"><div class="mc-name">Churn Heatmap</div><div class="mc-desc">Commit count per file per time bin (month by default). Shows when a file was hot, not just that its aggregate commit count is high -- a file with heavy churn two years ago and nothing since reads very differently from one under active rework now, but both look identical in a single aggregate number. <strong>Use it to:</strong> distinguish recently-destabilised files (worth investigating why) from files that were simply worked hard once and have been stable since. Bin size (month/week) is set via <code>git.heatmap_bin</code> in config.yaml.</div></div>
        <div class="metric-card"><div class="mc-name">Commit Activity</div><div class="mc-desc">GitHub-style calendar heatmap of total commits per day across the whole first-party codebase -- a commit touching several files counts once here, not once per file, unlike the Churn Heatmap above. Answers "when did work happen" rather than "which files were busy". Capped to the most recent 52 weeks for a readable grid; the full daily series is in commit_activity.csv regardless. <strong>Use it to:</strong> spot release crunches, long gaps (holidays, a team switching focus elsewhere), or a sudden resumption of activity on an otherwise-dormant project -- context worth having before trusting any of the churn-derived scores above at face value.</div></div>
        <div class="metric-card"><div class="mc-name">Composite Risk Ranking</div><div class="mc-desc">Fuses SDI, hotspot score, module pain, ISR risk, and stack depth into one ranked list -- see the Risk tab and Metrics Reference for the weighting. Repeated here in git-history context since hotspot score (churn-derived) is one of its five inputs.</div></div>
        <div class="metric-card"><div class="mc-name">Bug-Fix-Weighted Hotspots</div><div class="mc-abbr">Code Maat; fix-commit churn</div><div class="mc-desc">Same churn x structural-debt formula as Hotspots, but churn only counts commits whose message matches config.git.fix_keywords. A file rewritten often as features land isn't necessarily the same file that keeps needing bug fixes -- this list answers "what actually breaks", the plain hotspot list answers "what changes a lot". <strong>Use it to:</strong> prioritise when the two lists disagree -- a file high here but not on the plain hotspot list is quietly accumulating defects without a matching complexity signal yet.</div></div>
        <div class="metric-card"><div class="mc-name">Code Ownership</div><div class="mc-abbr">Tornhill 2015 Ch.11-13; knowledge maps</div><div class="mc-desc">main_author_share is the largest single contributor's fraction of commits touching the file; ownership_fragmentation is 1 minus that share. Ownership risk multiplies fragmentation by the file's churn percentile -- frequently changed AND no clear owner, the "bystander effect" case where nobody holds full context for the file. <strong>Don't:</strong> read a high fragmentation score as anything wrong with the people involved -- it's a coordination/context signal, not a performance one; see the disclaimer at the top of this report.</div></div>
        <div class="metric-card"><div class="mc-name">Complexity Trend in Top Hotspots</div><div class="mc-abbr">Tornhill 2015 Ch.6</div><div class="mc-desc">A regex decision-point count (if/for/while/case/&&/||/?:) summed per file, sampled at up to 12 evenly-spaced historical commits for the top 10 hotspot files. Distinguishes a hotspot that spiked once and has been flat since from one still climbing every commit -- only the latter is an active, worsening problem. Directional, not a substitute for the AST-derived cyclomatic_complexity used everywhere else in this report.</div></div>
        <div class="metric-card"><div class="mc-name">Architecture-Level Change Coupling</div><div class="mc-abbr">Tornhill 2015 Ch.8/10; architectural decay</div><div class="mc-desc">Change Coupling rolled up to the layer level. "Surprising" pairs have no direct #include either way -- co-change with no static dependency to explain it (a best-effort, direct-includes-only check, so treat it as a worklist, not a verdict). <strong>Use it to:</strong> catch layers drifting into an unintended dependency that the static layer-violation check (Architecture tab) can't see, since that check only looks at the call graph, not git history.</div></div>
      </div>
    </div>
  </details>

  {% if not hotspot_rows and not coupling_pair_rows and not churn_heatmap_grid and not bugfix_hotspot_rows and not ownership_rows and not complexity_trend_rows and not layer_coupling_rows and not commit_activity_grid %}
  <p style="color:var(--dim)">No git history available, or the project isn't a git repository -- every metric on this tab is git-derived and skipped gracefully outside a git repo.</p>
  {% else %}

  <div class="section-title">Hotspots
    <span style="font-size:11px;font-weight:400;color:var(--dim)">churn x structural debt</span>
  </div>
  {% if hotspot_rows %}
  <input type="text" id="hotspot-filter" placeholder="Filter by function or file..." oninput="filterTable('hotspot-table', this.value)">
  <table id="hotspot-table">
    <thead><tr>
      <th onclick="sortTable('hotspot-table',0)">Function</th>
      <th onclick="sortTable('hotspot-table',1)">File</th>
      <th onclick="sortTable('hotspot-table',2)">Commits</th>
      <th onclick="sortTable('hotspot-table',3)">SDI</th>
      <th onclick="sortTable('hotspot-table',4)">Hotspot score</th>
      <th>Name</th>
    </tr></thead>
    <tbody>
    {% for f in hotspot_rows %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td>{{ f.commit_count }}</td>
      <td>{{ f.sdi }}</td>
      <td>
        <div class="score-bar">
          <span class="{{ 'red' if f.hotspot_score >= 0.5 else 'yellow' }}">{{ f.hotspot_score }}</span>
          <div class="score-bar-track"><div class="score-bar-fill" style="width:{{ (f.hotspot_score*100)|round|int }}%;background:{{ 'var(--red)' if f.hotspot_score >= 0.5 else 'var(--yellow)' }}"></div></div>
        </div>
      </td>
      <td class="dim" style="font-size:11px">{{ f.vague_name if f.vague_name else '' }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No functions with a nonzero hotspot score -- either no git history, or not enough file-to-file variation to rank against (percentile rank against a population of one has nothing to rank against).</p>
  {% endif %}

  <div class="section-title" style="margin-top:24px">Bug-Fix-Weighted Hotspots
    <span style="font-size:11px;font-weight:400;color:var(--dim)">churn restricted to fix-flavoured commits (config.git.fix_keywords)</span>
  </div>
  {% if bugfix_hotspot_rows %}
  <table id="bugfix-hotspot-table">
    <thead><tr>
      <th>Function</th><th>File</th><th>Fix commits</th><th>SDI</th><th>Bugfix hotspot score</th>
    </tr></thead>
    <tbody>
    {% for f in bugfix_hotspot_rows %}
    <tr>
      <td>{% if f.has_source %}<span class="clickable" onclick="showFn('{{ f.file_path }}',{{ f.line }})">{{ f.name }}</span>{% else %}{{ f.name }}{% endif %}</td>
      <td class="dim">{{ f.file_short }}</td>
      <td>{{ f.bugfix_commit_count }}</td>
      <td>{{ f.sdi }}</td>
      <td>
        <div class="score-bar">
          <span class="{{ 'red' if f.bugfix_hotspot_score >= 0.5 else 'yellow' }}">{{ f.bugfix_hotspot_score }}</span>
          <div class="score-bar-track"><div class="score-bar-fill" style="width:{{ (f.bugfix_hotspot_score*100)|round|int }}%;background:{{ 'var(--red)' if f.bugfix_hotspot_score >= 0.5 else 'var(--yellow)' }}"></div></div>
        </div>
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No functions with a nonzero bug-fix-weighted hotspot score -- either no git history, or too few commits matched config.git.fix_keywords.</p>
  {% endif %}

  <div class="section-title" style="margin-top:24px">Code Ownership
    <span style="font-size:11px;font-weight:400;color:var(--dim)">churn x diffuse authorship -- the "bystander effect" risk signal</span>
  </div>
  {% if ownership_rows %}
  <table id="ownership-table">
    <thead><tr>
      <th>File</th><th>Commits</th><th>Main author</th><th>Main author share</th><th>Authors</th><th>Ownership risk</th>
    </tr></thead>
    <tbody>
    {% for m in ownership_rows %}
    <tr>
      <td class="dim">{{ m.file }}</td>
      <td>{{ m.commit_count }}</td>
      <td>{{ m.main_author }}</td>
      <td>{{ "%.0f"|format(m.main_author_share * 100) }}%</td>
      <td>{{ m.distinct_author_count }}</td>
      <td>
        <div class="score-bar">
          <span class="{{ 'red' if m.ownership_risk_score >= 0.5 else 'yellow' }}">{{ m.ownership_risk_score }}</span>
          <div class="score-bar-track"><div class="score-bar-fill" style="width:{{ (m.ownership_risk_score*100)|round|int }}%;background:{{ 'var(--red)' if m.ownership_risk_score >= 0.5 else 'var(--yellow)' }}"></div></div>
        </div>
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No files with a nonzero ownership risk score.</p>
  {% endif %}

  <div class="section-title" style="margin-top:24px">Complexity Trend in Top Hotspots
    <span style="font-size:11px;font-weight:400;color:var(--dim)">sampled from historical git blobs, up to 10 hotspot files</span>
  </div>
  {% if complexity_trend_rows %}
  <table id="complexity-trend-table">
    <thead><tr><th>File</th><th>Trend</th><th>Slope (per day)</th><th>R²</th><th>Samples</th></tr></thead>
    <tbody>
    {% for t in complexity_trend_rows %}
    <tr>
      <td class="dim">{{ t.file }}</td>
      <td class="{{ 'red' if t.trend == 'worsening' else ('green' if t.trend == 'improving' else 'dim') }}">{{ t.trend }}</td>
      <td>{{ "%+.3f"|format(t.slope) }}</td>
      <td>{{ t.r_squared }}</td>
      <td>{{ t.point_count }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">Not enough sampled history to fit a trend for any top hotspot file.</p>
  {% endif %}

  <div class="section-title" style="margin-top:24px">Change Coupling
    <span style="font-size:11px;font-weight:400;color:var(--dim)">files that change together in the same commit</span>
  </div>
  {% if coupling_pair_rows %}
  <input type="text" id="coupling-filter" placeholder="Filter by file..." oninput="filterTable('coupling-table', this.value)">
  <table id="coupling-table">
    <thead><tr><th>File A</th><th>File B</th><th>Co-changes</th><th>Coupling</th><th>Cross-layer</th></tr></thead>
    <tbody>
    {% for p in coupling_pair_rows %}
    <tr>
      <td class="dim">{{ p.file_a }}</td>
      <td class="dim">{{ p.file_b }}</td>
      <td>{{ p.co_changes }}</td>
      <td class="{{ 'red' if p.coupling >= 0.7 else 'yellow' }}">{{ "%.0f"|format(p.coupling * 100) }}%</td>
      <td class="{{ 'red' if p.surprising else 'dim' }}">{{ 'surprising' if p.surprising else ('cross-layer' if p.cross_layer else '') }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No file pairs met the co-change/coupling thresholds.</p>
  {% endif %}

    <div class="section-title" style="margin-top:24px">Change-Coupling Matrix
    <span style="font-size:11px;font-weight:400;color:var(--dim)">
      top {{ meta.output_top_n }} files by total coupling -- darker = files that change together more often
    </span>
  </div>
  {% if coupling_heatmap_grid %}
  <div style="overflow-x:auto">
  <table class="heatmap-table">
    <thead><tr><th>File</th>{% for f in coupling_heatmap_grid.files %}<th style="font-size:10px;white-space:nowrap">{{ f }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for row in coupling_heatmap_grid.rows %}
    <tr>
      <td class="dim" style="white-space:nowrap">{{ row.file }}</td>
      {% for c in row.cells %}
      <td style="background:{{ 'rgba(220,38,38,' ~ c.intensity ~ ')' if c.intensity > 0 else 'transparent' }};text-align:center;font-size:10px;color:{{ '#fff' if c.intensity > 0.5 else 'var(--dim)' }}" title="{{ row.file }} \u00d7 {{ coupling_heatmap_grid.files[loop.index0] }}: {{ c.pct }}%">{{ c.pct if c.pct > 0 else '' }}</td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
  </div>
  {% else %}
  <p style="color:var(--dim)">No file pairs met the co-change/coupling thresholds.</p>
  {% endif %}

<div class="section-title" style="margin-top:24px">Churn Heatmap
    <span style="font-size:11px;font-weight:400;color:var(--dim)">top {{ meta.output_top_n }} files by commit count, darker = more commits in that period</span>
  </div>
  {% if churn_heatmap_grid %}
  <div style="overflow-x:auto">
  <table class="heatmap-table">
    <thead><tr><th>File</th>{% for b in churn_heatmap_grid.bin_labels %}<th style="font-size:10px;white-space:nowrap">{{ b }}</th>{% endfor %}</tr></thead>
    <tbody>
    {% for row in churn_heatmap_grid.rows %}
    <tr>
      <td class="dim" style="white-space:nowrap">{{ row.file }}</td>
      {% for c in row.cells %}
      <td style="background:rgba(220,38,38,{{ c.intensity }});text-align:center;font-size:10px;color:{{ '#fff' if c.intensity > 0.5 else 'var(--dim)' }}">{{ c.count if c.count > 0 else '' }}</td>
      {% endfor %}
    </tr>
    {% endfor %}
    </tbody>
  </table>
  </div>
  {% else %}
  <p style="color:var(--dim)">No churn data available.</p>
  {% endif %}

  <div class="section-title" style="margin-top:24px">Commit Activity
    <span style="font-size:11px;font-weight:400;color:var(--dim)">whole codebase, one square per calendar day, last 52 weeks{% if commit_activity_grid %} ({{ commit_activity_grid.first_day }} to {{ commit_activity_grid.last_day }}, {{ commit_activity_grid.total_commits }} commits total){% endif %}</span>
  </div>
  {% if commit_activity_grid %}
  <div style="overflow-x:auto">
  <div style="display:flex;gap:3px">
    {% for week in commit_activity_grid.week_cols %}
    <div style="display:flex;flex-direction:column;gap:3px">
      {% for day in week %}
      <div title="{{ day.date }}{% if day.count is not none %}: {{ day.count }} commit(s){% endif %}"
           style="width:11px;height:11px;border-radius:2px;background:{{ 'rgba(34,197,94,' ~ (0.15 + day.intensity * 0.85) ~ ')' if day.count else (('var(--border)') if day.count is not none else 'transparent') }}"></div>
      {% endfor %}
    </div>
    {% endfor %}
  </div>
  <div style="display:flex;gap:3px;margin-top:4px">
    {% for label in commit_activity_grid.month_labels %}
    <div style="width:11px;font-size:9px;color:var(--dim);white-space:nowrap;overflow:visible">{{ label }}</div>
    {% endfor %}
  </div>
  </div>
  {% else %}
  <p style="color:var(--dim)">No commit activity data available.</p>
  {% endif %}

  {% endif %}
</div>


<!-- TECH DEBT -->
<div class="pane" id="pane-techdebt">
  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">TODO / FIXME / HACK / XXX Markers</div><div class="mc-desc">Every comment starting with one of these tags, collected with file/line/text. No external tool -- a regex over raw source, same as the other text-based scans below. <strong>Use it to:</strong> triage before a release -- sort by tag (FIXME/HACK usually indicate more urgency than a plain TODO) and check age via git blame on the surrounding line. <strong>Don't:</strong> assume every marker is still relevant -- some accumulate over years and describe a concern that's since been addressed elsewhere without the comment being removed.</div></div>
        <div class="metric-card"><div class="mc-name">Commented-Out Code</div><div class="mc-desc">Runs of 3+ consecutive comment-only lines that look code-shaped (semicolons, braces, assignment/comparison operators) rather than prose. A `/* */` block and a run of `//` line comments are evaluated separately even when adjacent, so unrelated trailing comments don't dilute a genuine commented-out block below the flag threshold. <strong>Use it to:</strong> find dead code worth deleting outright -- git history is the real record of "what this used to do," a commented-out block just clutters the file. <strong>Don't:</strong> flag large commented-out reference implementations or protocol examples deliberately kept as documentation -- read the block before deleting.</div></div>
        <div class="metric-card"><div class="mc-name">Preprocessor Complexity</div><div class="mc-desc">Max #ifdef/#ifndef/#if nesting depth, total conditional directive count, and count of distinct feature-flag macro names, per file. A text-based heuristic, not a true preprocessor evaluation. <strong>Use it to:</strong> find files where conditional compilation has grown organically into something hard to reason about -- deep nesting (4+) is a strong signal the file is effectively several different files interleaved. <strong>Don't:</strong> expect this to catch every configuration combination's actual behaviour -- fwlens parses with one fixed set of defines (config.iar_compat_defines + project defines), so branches gated on a define that's never set during analysis are invisible here just as they are to the rest of fwlens.</div></div>
        <div class="metric-card"><div class="mc-name">Near-Duplicate Functions</div><div class="mc-abbr">Normalised token shingling, Jaccard &gt;= 75%</div><div class="mc-desc">Type-2 clone detection: same structure, renamed identifiers/literals. Comments are stripped before comparison. Functions under 30 normalised tokens are skipped as too small to be meaningful. Pairs where either side is also a dead-code candidate are listed first and marked [dead] -- duplication that's also unreachable is safe to delete outright rather than merge. <strong>Use it to:</strong> find genuine copy-paste-and-tweak duplication worth extracting into a shared, parameterised function. <strong>Don't:</strong> assume every hit is a problem -- per-channel/per-peripheral variant handlers (e.g. near-identical ADC1_Handler/ADC2_Handler) are a common, often-reasonable pattern in firmware, especially when the underlying hardware genuinely requires separate entry points.</div></div>
      </div>
    </div>
  </details>

  <div class="section-title">TODO / FIXME / HACK / XXX Markers
    <span style="font-size:11px;font-weight:400;color:var(--dim)">{{ meta.todo_count }} total</span>
  </div>
  {% if todo_rows %}
  <div class="filter-row">
    <input type="text" id="todo-filter" placeholder="Filter by tag, file, or text..." oninput="filterTable('todo-table', this.value)">
  </div>
  <table id="todo-table">
    <thead><tr>
      <th onclick="sortTable('todo-table',0)">Tag</th>
      <th onclick="sortTable('todo-table',1)">File</th>
      <th onclick="sortTable('todo-table',2)">Line</th>
      <th>Text</th>
    </tr></thead>
    <tbody>
    {% for t in todo_rows %}
    <tr>
      <td class="{{ 'red' if t.tag in ('FIXME','HACK') else 'yellow' }}">{{ t.tag }}</td>
      <td class="dim">{% if t.has_source %}<span class="clickable" onclick="showFn('{{ t.file_path }}',{{ t.line }})">{{ t.file_short }}</span>{% else %}{{ t.file_short }}{% endif %}</td>
      <td>{{ t.line }}</td>
      <td style="font-size:12px">{{ t.text }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% if meta.todo_count > todo_rows|length %}
  <p style="color:var(--dim);font-size:11px;margin-top:6px">Showing {{ todo_rows|length }} of {{ meta.todo_count }} -- see todo_markers.csv for the rest.</p>
  {% endif %}
  {% else %}
  <p style="color:var(--dim)">No TODO/FIXME/HACK/XXX markers found.</p>
  {% endif %}

  <div class="section-title" style="margin-top:24px">Commented-Out Code
    <span style="font-size:11px;font-weight:400;color:var(--dim)">{{ meta.commented_code_count }} block(s) suspected</span>
  </div>
  {% if commented_code_rows %}
  <input type="text" id="commented-filter" placeholder="Filter by file..." oninput="filterTable('commented-table', this.value)">
  <table id="commented-table">
    <thead><tr><th>File</th><th>Lines</th><th>Line count</th></tr></thead>
    <tbody>
    {% for b in commented_code_rows %}
    <tr>
      <td class="dim">{% if b.has_source %}<span class="clickable" onclick="showFn('{{ b.file_path }}',{{ b.start_line }})">{{ b.file_short }}</span>{% else %}{{ b.file_short }}{% endif %}</td>
      <td>{{ b.start_line }}-{{ b.end_line }}</td>
      <td>{{ b.line_count }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No commented-out code blocks detected.</p>
  {% endif %}

  <div class="section-title" style="margin-top:24px">Preprocessor Complexity</div>
  {% if preprocessor_rows %}
  <input type="text" id="preproc-filter" placeholder="Filter by file..." oninput="filterTable('preproc-table', this.value)">
  <table id="preproc-table">
    <thead><tr><th>File</th><th>Max #ifdef depth</th><th>Directives</th><th>Distinct flags</th></tr></thead>
    <tbody>
    {% for m in preprocessor_rows %}
    <tr>
      <td class="dim">{{ m.file_short }}</td>
      <td class="{{ 'red' if m.depth >= 4 else 'yellow' if m.depth >= 2 else '' }}">{{ m.depth }}</td>
      <td>{{ m.directives }}</td>
      <td>{{ m.flags }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No conditional-compilation directives found.</p>
  {% endif %}

  <div class="section-title" style="margin-top:24px">Near-Duplicate Functions
    <span style="font-size:11px;font-weight:400;color:var(--dim)">{{ meta.clone_pair_count }} pair(s) &gt;= 75% similar</span>
  </div>
  {% if clone_rows %}
  <input type="text" id="clone-filter" placeholder="Filter by function or file..." oninput="filterTable('clone-table', this.value)">
  <table id="clone-table">
    <thead><tr><th>Function A</th><th>Function B</th><th>Similarity</th><th>Dead code</th></tr></thead>
    <tbody>
    {% for p in clone_rows %}
    <tr>
      <td>{% if p.has_source_a %}<span class="clickable" onclick="showFn('{{ p.file_a_path }}',{{ p.line_a }})">{{ p.function_a }}</span>{% else %}{{ p.function_a }}{% endif %} <span class="dim">({{ p.file_a }})</span>{% if p.is_dead_a %} <span class="red">[dead]</span>{% endif %}</td>
      <td>{% if p.has_source_b %}<span class="clickable" onclick="showFn('{{ p.file_b_path }}',{{ p.line_b }})">{{ p.function_b }}</span>{% else %}{{ p.function_b }}{% endif %} <span class="dim">({{ p.file_b }})</span>{% if p.is_dead_b %} <span class="red">[dead]</span>{% endif %}</td>
      <td class="{{ 'red' if p.similarity >= 0.9 else 'yellow' }}">{{ "%.0f"|format(p.similarity * 100) }}%</td>
      <td class="{{ 'red' if (p.is_dead_a or p.is_dead_b) else 'dim' }}">{{ 'both' if (p.is_dead_a and p.is_dead_b) else (p.function_a if p.is_dead_a else (p.function_b if p.is_dead_b else '')) }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No near-duplicate function pairs detected.</p>
  {% endif %}
</div>


<!-- DEFECTS & ESTIMATION -->
<div class="pane" id="pane-defects">
  <details class="metric-info">
    <summary>About these metrics</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Reliability Growth</div><div class="mc-abbr">Goel-Okumoto NHPP</div><div class="mc-desc">Fits mu(t) = a(1 - e^(-bt)) to cumulative "fix"-flavoured commits over time. 'a' is the asymptotic expected total defects, 'b' the discovery rate. Needs 8+ matching commits to attempt a fit. This is a defect-<em>discovery</em> curve, not a defect count -- treat it as a trend indicator. <strong>Use it to:</strong> get a rough read on whether defect discovery is climbing, flattening, or plateaued -- useful context before a release decision. <strong>Don't:</strong> treat 'a' as a precise total-bugs-remaining count -- commit-message keyword matching is coarse (some fixes aren't tagged as such, some tagged commits aren't really bug fixes), so this is order-of-magnitude at best.</div></div>
        <div class="metric-card"><div class="mc-name">COCOMO Effort Estimate</div><div class="mc-abbr">Boehm 1981, Basic COCOMO 81</div><div class="mc-desc">Effort/schedule estimate from total first-party SLOC. Constants were calibrated on 1970s-80s business/systems-software projects, not this codebase -- read as a rough historical baseline, not a committed schedule. <strong>Use it to:</strong> sanity-check a schedule estimate against an independent, if crude, outside reference point. <strong>Don't:</strong> use this for actual project planning without first calibrating your own a/b/c/d constants against your team's historical effort data on comparable past projects (see the guide's COCOMO section for how).</div></div>
        <div class="metric-card"><div class="mc-name">Complexity-vs-Defect Correlation</div><div class="mc-abbr">Spearman rank r</div><div class="mc-desc">Correlates each module-level complexity metric against its fix-commit touch count, <em>in this codebase</em>, rather than assuming a textbook metric's original calibration transfers unchanged. Needs 5+ files with at least one fix commit. <strong>Use it to:</strong> check whether the metrics fwlens is flagging elsewhere (CC, SDI, etc.) actually predict where defects have historically landed in <em>this specific codebase</em> -- a low correlation is a legitimate reason to weight those metrics less heavily in your own triage. <strong>Don't:</strong> expect a strong correlation on a small file population -- Spearman's r needs enough data points to be a stable estimate, not noise.</div></div>
        <div class="metric-card"><div class="mc-name">Cost/Benefit: Static vs. Field</div><div class="mc-abbr">Grady 1992; Boehm 1981</div><div class="mc-desc">Multiplies the reliability-growth estimated remaining defects by two configured per-defect cost figures (config.cost_benefit) to estimate the value of catching them statically vs. in the field. The defaults are placeholder order-of-magnitude figures -- this estimate is only as good as the two numbers you provide. <strong>Use it to:</strong> build a rough business case for investing in more static analysis/review time, once you've replaced the placeholder costs with your own organisation's real figures. <strong>Don't:</strong> quote this number externally with the default costs still in place -- it will look precise while being almost entirely a placeholder.</div></div>
      </div>
    </div>
  </details>

  {% if reliability or effort or cost_benefit %}
  <div class="issue-grid" style="margin-bottom:24px">
    {% if reliability %}
    <div class="issue-section">
      <div class="issue-section-title">Reliability Growth</div>
      {% if reliability.trend == 'insufficient_data' %}
      <p style="color:var(--dim);font-size:12px">{{ reliability.fix_commit_count }} fix-flavoured commit(s) found -- need at least 8 for a fit.</p>
      {% else %}
      <div class="issue-row issue-{{ 'red' if reliability.trend == 'climbing' else 'yellow' if reliability.trend == 'flattening' else 'ok' }}">
        <span class="issue-icon">{{ '&#9888;' if reliability.trend == 'climbing' else '&#9432;' if reliability.trend == 'flattening' else '&#10003;' }}</span>
        <span class="issue-label">Trend</span>
        <span class="issue-count" style="text-transform:capitalize">{{ reliability.trend }}</span>
      </div>
      <p style="color:var(--dim);font-size:12px;margin-top:8px">
        {{ reliability.cumulative_to_date }} fix commits over {{ reliability.days_span }} days &rarr;
        fitted total <strong>{{ "%.0f"|format(reliability.fitted_total_defects) }}</strong>
        (~<strong>{{ "%.0f"|format(reliability.estimated_remaining) }}</strong> estimated remaining),
        R&sup2;={{ "%.2f"|format(reliability.r_squared) }}
      </p>
      {% endif %}
    </div>
    {% endif %}

    {% if effort %}
    <div class="issue-section">
      <div class="issue-section-title">COCOMO Effort Estimate <span class="dim" style="font-weight:400;text-transform:none">({{ effort.mode }})</span></div>
      <p style="color:var(--text);font-size:13px;line-height:1.8">
        {{ effort.kloc }} KLOC &rarr; <strong>{{ effort.effort_person_months }}</strong> person-months /
        <strong>{{ effort.schedule_months }}</strong> months /
        <strong>{{ effort.average_staffing }}</strong> average staff
      </p>
      <p style="color:var(--dim);font-size:11px">1970s-80s-calibrated constants -- a rough historical baseline, not a committed schedule.</p>
    </div>
    {% endif %}

    {% if cost_benefit %}
    <div class="issue-section">
      <div class="issue-section-title">Cost/Benefit: Static vs. Field</div>
      <p style="color:var(--text);font-size:13px;line-height:1.8">
        ~{{ "%.0f"|format(cost_benefit.estimated_remaining_defects) }} estimated remaining defects &rarr;
        <span class="green">${{ "{:,.0f}".format(cost_benefit.cost_if_static_usd) }}</span> if caught statically vs.
        <span class="red">${{ "{:,.0f}".format(cost_benefit.cost_if_field_usd) }}</span> if found in the field
      </p>
      <p style="color:var(--dim);font-size:11px">
        Potential savings: <strong>${{ "{:,.0f}".format(cost_benefit.potential_savings_usd) }}</strong>
        (placeholder cost figures unless configured -- see guide).
      </p>
    </div>
    {% endif %}
  </div>
  {% endif %}

  <div class="section-title">Complexity-vs-Defect Correlation
    <span style="font-size:11px;font-weight:400;color:var(--dim)">Spearman r against fix-commit touch count, this codebase</span>
  </div>
  {% if defect_correlations %}
  <table style="max-width:600px">
    <thead><tr><th>Metric</th><th>Spearman r</th><th>p-value</th></tr></thead>
    <tbody>
    {% for c in defect_correlations %}
    <tr>
      <td>{{ c.label }}</td>
      <td class="{{ 'red' if c.spearman_r|abs >= 0.5 else 'yellow' if c.spearman_r|abs >= 0.3 else 'dim' }}">{{ "%+.2f"|format(c.spearman_r) }}</td>
      <td class="dim">{{ "%.3f"|format(c.p_value) }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">Not enough files with fix commits to compute a correlation (needs 5+).</p>
  {% endif %}

  {% if not reliability and not defect_correlations %}
  <p style="color:var(--dim);margin-top:16px">No git history available, or the project isn't a git repository -- all of the metrics on this tab are git-derived and are skipped gracefully outside a git repo.</p>
  {% endif %}
</div>


<!-- PARSE DIAGNOSTICS -->
<div class="pane" id="pane-parsediag">
  <details class="metric-info">
    <summary>About this tab</summary>
    <div class="metric-info-body">
      <div class="metric-grid">
        <div class="metric-card"><div class="mc-name">Parse Diagnostics</div><div class="mc-desc">Every libclang diagnostic raised while parsing this codebase, one row per affected file (worst diagnostic first), across ALL files -- not just the top offenders shown on Overview. Click a row to expand every diagnostic for that file. <strong>Fatal/error</strong> diagnostics mean part or all of that file's AST didn't build -- metrics derived from it may be incomplete or wrong. <strong>Warnings</strong> are usually real but non-blocking (the file still parsed); some are also just noise from spoofing an IAR-specific toolchain identity through a real compiler -- see the guide's Parse Diagnostics section for the difference.</div></div>
      </div>
    </div>
  </details>

  {% if all_diagnostic_rows %}
  <div class="section-title" style="margin-top:0">All Files With Diagnostics
    <span style="font-size:11px;font-weight:400;color:var(--dim)">{{ all_diagnostic_rows|length }} file(s) -- {{ meta.diag_fatal_count }} fatal, {{ meta.diag_error_count }} error(s), {{ meta.diag_warning_count }} warning(s) total</span>
  </div>
  <input type="text" id="parsediag-filter" placeholder="Filter by file or message..." oninput="filterTable('parsediag-table', this.value)">
  <table id="parsediag-table" class="chain-table">
    <thead><tr><th></th><th>File</th><th>Severity</th><th>Line</th><th>Message</th></tr></thead>
    <tbody>
    {% for d in all_diagnostic_rows %}
    <tr class="chain-row has-chain" onclick="this.classList.toggle('expanded')">
      <td class="chain-toggle"><span class="chain-arrow">&#9656;</span></td>
      <td>{% if d.has_source %}<span class="clickable" onclick="event.stopPropagation();showFn('{{ d.file_path }}',{{ d.line }})">{{ d.file_short }}</span>{% else %}{{ d.file_short }}{% endif %}</td>
      <td class="{{ 'red' if d.severity in ['fatal','error'] else 'yellow' }}">{{ d.severity }}</td>
      <td>{{ d.line }}</td>
      <td class="dim">{{ d.message }}{% if d.extra_count > 0 %} <span style="color:var(--dim)">(+{{ d.extra_count }} more)</span>{% endif %}</td>
    </tr>
    <tr class="chain-detail">
      <td></td>
      <td colspan="4">
        <table style="margin:4px 0 10px">
          <thead><tr><th>Severity</th><th>Line</th><th>Message</th></tr></thead>
          <tbody>
          {% for one in d.all %}
          <tr>
            <td class="{{ 'red' if one.severity in ['fatal','error'] else 'yellow' }}">{{ one.severity }}</td>
            <td>{{ one.line }}</td>
            <td class="dim">{{ one.message }}</td>
          </tr>
          {% endfor %}
          </tbody>
        </table>
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  {% else %}
  <p style="color:var(--dim)">No parse diagnostics -- every file parsed clean.</p>
  {% endif %}
</div>


<!-- METRICS REFERENCE -->
<div class="pane" id="pane-reference">
  <p style="color:var(--dim);font-size:12px;margin-bottom:16px">
    Complete reference for every metric computed by fwlens. Thresholds shown are the values configured for this run.
    Hover any column header in a table to see a brief tooltip. Click a header to sort.
  </p>
  <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:24px">
    <button onclick="show('functions',document.querySelector('[onclick*=functions]'))"   style="background:var(--surface);border:1px solid var(--border);color:var(--accent);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">&#8594; Functions</button>
    <button onclick="show('modules',document.querySelector('[onclick*=modules]'))"       style="background:var(--surface);border:1px solid var(--border);color:var(--accent);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">&#8594; Modules</button>
    <button onclick="show('architecture',document.querySelector('[onclick*=architecture]'))" style="background:var(--surface);border:1px solid var(--border);color:var(--accent);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">&#8594; Architecture</button>
    <button onclick="show('risk',document.querySelector('[onclick*=risk]'))"             style="background:var(--surface);border:1px solid var(--border);color:var(--red);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">&#8594; Risk</button>
    <button onclick="show('rtos',document.querySelector('[onclick*=rtos]'))"               style="background:var(--surface);border:1px solid var(--border);color:var(--accent);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">&#8594; ISR Risk</button>
    <button onclick="show('coupling',document.querySelector('[onclick*=coupling]'))"     style="background:var(--surface);border:1px solid var(--border);color:var(--accent);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">&#8594; Coupling / Cohesion</button>
    <button onclick="show('defects',document.querySelector('[onclick*=defects]'))"       style="background:var(--surface);border:1px solid var(--border);color:var(--accent);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">&#8594; Defects &amp; Estimation</button>
    <button onclick="show('techdebt',document.querySelector('[onclick*=techdebt]'))"     style="background:var(--surface);border:1px solid var(--border);color:var(--accent);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">&#8594; Tech Debt</button>
    <button onclick="show('gittrends',document.querySelector('[onclick*=gittrends]'))"   style="background:var(--surface);border:1px solid var(--border);color:var(--accent);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">&#8594; Change History</button>
    <button onclick="show('rtos',document.querySelector('[onclick*=rtos]'))"             style="background:var(--surface);border:1px solid var(--border);color:var(--accent);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">&#8594; RTOS</button>
    <button onclick="show('rtos',document.querySelector('[onclick*=rtos]'))" style="background:var(--surface);border:1px solid var(--border);color:var(--accent);padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">&#8594; State Machines</button>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">Function Complexity</div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">Cyclomatic Complexity (CC)</div>
        <div class="mc-abbr">McCabe 1976</div>
        <div class="mc-desc">Counts the number of linearly independent paths through a function. Starts at 1 and increments for each branch (<code>if</code>, <code>else if</code>, <code>case</code>, <code>while</code>, <code>for</code>, <code>&&</code>, <code>||</code>, ternary). Directly equals the minimum number of test cases for full branch coverage.</div>
        <div class="mc-thresh">Threshold: {{ thresholds.cyclomatic_complexity }}</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Cognitive Complexity</div>
        <div class="mc-abbr">SonarSource model</div>
        <div class="mc-desc">A human-perceived difficulty score. Unlike CC, it penalises nesting depth with a multiplier. A flat chain of 10 conditions scores lower than a single deeply nested loop, reflecting the effort of holding context while reading.</div>
        <div class="mc-thresh">Threshold: {{ thresholds.cognitive_complexity }}</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Block Depth</div>
        <div class="mc-abbr">Max nesting depth</div>
        <div class="mc-desc">Maximum nesting level of control structures in the function body. Each <code>if</code>, <code>for</code>, <code>while</code>, <code>switch</code>, or <code>do</code> block increments the depth. Empirically, depth above 4-5 is associated with significantly higher defect rates.</div>
        <div class="mc-thresh">Threshold: {{ thresholds.block_depth }}</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Return Path Count</div>
        <div class="mc-abbr">Multiple exits</div>
        <div class="mc-desc">Number of <code>return</code> statements in the function. Multiple return points can leave resources un-freed and make control flow harder to follow. Particularly risky in C where there is no RAII.</div>
        <div class="mc-thresh">Threshold: {{ thresholds.return_path_count }}</div>
      </div>
    </div>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">Halstead Metrics</div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">Halstead Volume (V)</div>
        <div class="mc-abbr">V = N &times; log&#8322;(&eta;)</div>
        <div class="mc-desc">Program length (N = total operator + operand occurrences) times the log of the vocabulary (&eta; = distinct operators + distinct operands). Estimates the information content of the function.</div>
        <div class="mc-thresh">Threshold: {{ thresholds.halstead_volume }}</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Halstead Difficulty (D)</div>
        <div class="mc-abbr">D = (n1/2) &times; (N2/n2)</div>
        <div class="mc-desc">How hard the program is to write or understand. Proportional to the number of distinct operators and the total operand usage density. High difficulty means the same operands appear in many different contexts.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Halstead Effort (E)</div>
        <div class="mc-abbr">E = D &times; V</div>
        <div class="mc-desc">Estimated mental effort to comprehend or write the function, in elementary mental discriminations. Correlates with code review time. This is the primary Halstead metric used for thresholding.</div>
        <div class="mc-thresh">Threshold: {{ thresholds.halstead_effort }}</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Halstead Bugs (B)</div>
        <div class="mc-abbr">B = V / 3000</div>
        <div class="mc-desc">Estimated number of latent defects in the function, from the original Halstead model. Treat as a relative ranking metric rather than an absolute prediction.</div>
      </div>
    </div>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">Maintainability</div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">Maintainability Index (MI WoC)</div>
        <div class="mc-abbr">SEI Without Comments variant</div>
        <div class="mc-desc">A 0-100 composite: <code>171 - 5.2&times;ln(V) - 0.23&times;CC - 16.2&times;ln(LOC)</code>, clamped to [0, 100]. Higher is more maintainable. The WoC variant omits the comment ratio term, making it suitable for codebases with variable comment density. Below 65 is considered low maintainability.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Magic Number Density</div>
        <div class="mc-abbr">Literals / LOC</div>
        <div class="mc-desc">Ratio of bare numeric literals (excluding 0 and 1) to lines of code. High density indicates missing named constants, which hinders readability and creates silent duplication when the value must change.</div>
        <div class="mc-thresh">Threshold: {{ thresholds.magic_number_density }}</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Structural Debt Index (SDI)</div>
        <div class="mc-abbr">Composite 0-1</div>
        <div class="mc-desc">A normalised composite of CC, block depth, LOC, and fan-out breach flags. Weights the number and severity of threshold violations into a single risk score used to rank functions. Above 0.5 = yellow; above 0.7 = red.</div>
      </div>
    </div>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">Function-Level Coupling</div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">Fan-out (function)</div>
        <div class="mc-abbr">Distinct callees</div>
        <div class="mc-desc">Number of distinct functions called by this function. A function with high fan-out is tightly coupled to many others -- changes to any callee can break it, and mocking becomes expensive for unit testing.</div>
        <div class="mc-thresh">Threshold: {{ thresholds.fan_out }}</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Fan-in (function)</div>
        <div class="mc-abbr">Distinct callers</div>
        <div class="mc-desc">Number of distinct functions that call this function. High fan-in means the function is reused widely. Changes to its signature or behaviour have a broad blast radius.</div>
      </div>
    </div>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">Module-Level Coupling &amp; Cohesion</div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">Fan-in (module)</div>
        <div class="mc-abbr">Afferent coupling (Ca)</div>
        <div class="mc-desc">Number of other first-party modules that include or call into this module. High fan-in modules should be stable -- they are widely depended upon and changes break many things.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Fan-out (module)</div>
        <div class="mc-abbr">Efferent coupling (Ce)</div>
        <div class="mc-desc">Number of other first-party modules that this module includes or calls into. High fan-out modules depend on many others and are susceptible to transitive breakage.</div>
        <div class="mc-thresh">Threshold: {{ thresholds.fan_out }}</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Instability (I)</div>
        <div class="mc-abbr">I = Ce / (Ca + Ce)</div>
        <div class="mc-desc">Ranges 0-1. 0 = maximally stable (everything depends on it, it depends on nothing). 1 = maximally unstable (depends on others, nothing depends on it). From Robert Martin's Stable Dependencies Principle: modules should depend in the direction of stability.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Abstractness (A)</div>
        <div class="mc-abbr">Abstract types / total types</div>
        <div class="mc-desc">Ratio of abstract type declarations to total type declarations in the module. In C, estimated from forward declarations and opaque-pointer usage patterns. Used with Instability to compute Main Sequence Distance.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Main Sequence Distance (MSD)</div>
        <div class="mc-abbr">|I + A - 1|</div>
        <div class="mc-desc">Perpendicular distance from the ideal I + A = 1 line. 0 is ideal. Modules far from the line are either in the Zone of Pain (low I, low A) or the Zone of Uselessness (high I, high A).</div>
        <div class="mc-thresh">Threshold: {{ thresholds.main_sequence_distance }}</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Internal Call Cohesion</div>
        <div class="mc-abbr">Internal calls / total calls</div>
        <div class="mc-desc">Fraction of function calls made within the module that stay within the same module. A value close to 1 means the module's functions are strongly related. A value near 0 means the module is a loose collection of unrelated functions -- a candidate for splitting.</div>
        <div class="mc-thresh">Threshold: &lt; {{ thresholds.cohesion_min }}</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Include Depth</div>
        <div class="mc-abbr">Transitive include chain</div>
        <div class="mc-desc">Maximum depth of the transitive <code>#include</code> chain rooted at this translation unit. Deep chains slow incremental compilation and widen the effective coupling surface beyond what the direct includes suggest.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Cycle (SCC)</div>
        <div class="mc-abbr">Strongly-connected component</div>
        <div class="mc-desc">Whether the module is part of a cycle in the include or call graph. Any cycle makes the involved modules mutually dependent -- they cannot be compiled, tested, or replaced independently. Cycles are eliminated by introducing abstractions or by splitting modules.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Information Flow Complexity (IF4)</div>
        <div class="mc-abbr">Henry &amp; Kafura 1981 -- length &times; (fan-in &times; fan-out)&sup2;</div>
        <div class="mc-desc">Function-level, not module-level: penalises a function that is both internally long (LOC as the length proxy) <em>and</em> heavily coupled through the call graph -- a different signal from cyclomatic complexity, which says nothing about coupling. Needs nonzero fan-in AND fan-out to score above 0; leaf functions and pure entry points always score 0 by construction. See the Coupling / Cohesion tab.</div>
      </div>
    </div>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">Estimation &amp; Reliability</div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">COCOMO Effort Estimate</div>
        <div class="mc-abbr">Boehm 1981, Basic COCOMO 81</div>
        <div class="mc-desc">effort_pm = a &times; KLOC^b, schedule_months = c &times; effort_pm^d, from total first-party SLOC. Constants were empirically fitted to ~60 1970s-80s business/systems-software projects, not this codebase -- read as a rough historical baseline, not a committed schedule. See the Defects &amp; Estimation tab.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Reliability Growth</div>
        <div class="mc-abbr">Goel &amp; Okumoto 1979 NHPP model</div>
        <div class="mc-desc">mu(t) = a(1 - e^(-bt)) fitted to cumulative fix-flavoured commits over time. 'a' is the asymptotic expected total defects, 'b' is the discovery rate. A defect-<em>discovery</em> curve, not a defect count -- fewer fix commits than actual bugs and fewer fix commits than total commits both apply. Needs 8+ matching commits.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Complexity-vs-Defect Correlation</div>
        <div class="mc-abbr">Spearman rank r; Grady 1992 Ch.6</div>
        <div class="mc-desc">Correlates each candidate module metric against its fix-commit touch count <em>in this codebase</em>, rather than assuming a textbook metric's calibration transfers unchanged. Spearman rank, not Pearson -- defect data is typically non-linear and outlier-heavy. Needs 5+ files with at least one fix commit.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Cost/Benefit: Static vs. Field</div>
        <div class="mc-abbr">Grady 1992; Boehm 1981</div>
        <div class="mc-desc">Estimated remaining defects (from the reliability growth fit) &times; two configured per-defect cost figures. fwlens has no way to know your organisation's actual costs -- the defaults are placeholder order-of-magnitude figures (a conservative 10x found-early-vs-found-late ratio), not real numbers.</div>
      </div>
    </div>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">Tech Debt &amp; Change History</div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">TODO / FIXME / HACK / XXX Markers</div>
        <div class="mc-desc">Every comment starting with one of these tags, collected with file/line/text. Text-based, no external tool. See the Tech Debt tab.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Commented-Out Code</div>
        <div class="mc-desc">Runs of 3+ consecutive comment-only lines that are code-shaped rather than prose. A `/* */` block and a run of `//` line comments are evaluated as separate runs even when adjacent, so unrelated trailing comments don't dilute a genuine block below the flag threshold.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Preprocessor Complexity</div>
        <div class="mc-desc">Max #ifdef/#ifndef/#if nesting depth, directive count, and distinct feature-flag count per file. A text heuristic, not a true preprocessor evaluation.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Near-Duplicate Functions</div>
        <div class="mc-abbr">Normalised token k-shingling, Jaccard similarity</div>
        <div class="mc-desc">Type-2 clone detection over 8-token shingles of normalised source (identifiers -&gt; ID, literals -&gt; LIT, comments stripped). Inverted shingle index means candidate pairs scale with actual duplication, not codebase size. 75% similarity threshold, 30-token minimum function size.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Hotspots</div>
        <div class="mc-abbr">Tornhill 2015, "Your Code as a Crime Scene"</div>
        <div class="mc-desc">Percentile rank of commit count &times; percentile rank of structural debt index, within the first-party population. Churn alone or complexity alone is a weaker signal than both together -- files that are frequently changed AND already structurally risky are where defects cluster in practice. See the Change History tab.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Change Coupling</div>
        <div class="mc-abbr">Tornhill 2015; "logical coupling"</div>
        <div class="mc-desc">File pairs that repeatedly change together in the same commit -- coupling the static call/include graph can miss entirely. Jaccard coupling: co_changes / (changes_a + changes_b - co_changes). Needs 3+ co-changes and 30%+ coupling; mega-commits (20+ files) excluded as noise.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">ISR / Main-Loop Shared-Variable Risk</div>
        <div class="mc-desc">Global variables read or written from both an ISR and normal code without a volatile qualifier -- non-atomic shared-state hazard. Cross-references each global's readers/writers (from the AST walk) against each accessing function's is_isr flag. See the ISR Risk &amp; Races tab.</div>
      </div>
    </div>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">RTOS &amp; State Machines</div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">RTOS Tasks &amp; Sync Objects</div>
        <div class="mc-desc">Extracted from RTOS API call sites matching config.rtos's configured function-name lists (embOS by default, verified against the real embOS V5.18.3.0 RTOS.h). Priority/stack size only resolve to real values when the call site uses a literal; a #define'd constant not resolvable via a plain literal shows as unresolved raw text instead.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Priority Inversion Candidates</div>
        <div class="mc-abbr">Sha, Rajkumar, Lehoczky 1990</div>
        <div class="mc-desc">A plain counting semaphore (OS_SEMAPHORE_Create -- no priority inheritance in embOS) waited on by tasks of different priority. embOS's mutex (OS_MUTEX_Create, priority-inheriting) and reader/writer lock are not flagged. See the RTOS tab.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">State Machine Detection</div>
        <div class="mc-desc">Switch-statement-based: the switch's controlling expression is the "state variable" (raw text, not semantic resolution); an assignment to that variable within a case body is a transition from that case's label to the assigned value. Needs 2+ cases and at least one detected transition. Doesn't resolve enum/macro values -- equivalent constants under different spellings show as different states. See the State Machines tab.</div>
      </div>
    </div>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">Architecture</div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">Layer Violation: Upward</div>
        <div class="mc-abbr">Lower layer depends on higher layer</div>
        <div class="mc-desc">A module in a lower architectural layer (e.g. HAL) includes or calls a module in a higher layer (e.g. Application). This inverts the intended dependency direction and creates a cycle at the layer level.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Layer Violation: Skipped</div>
        <div class="mc-abbr">Dependency jumps more than one layer</div>
        <div class="mc-desc">A module bypasses one or more intermediate layers. Even if the direction is correct, skipping layers breaks encapsulation and prevents the intermediate layer from fulfilling its abstraction role.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Zone of Pain</div>
        <div class="mc-abbr">Low I, Low A</div>
        <div class="mc-desc">Stable (nothing depends on it changing) but concrete (no abstract interface). Extremely hard to change without breaking dependents, and impossible to substitute. Common example: a utility module included by everything that has no header abstraction.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Zone of Uselessness</div>
        <div class="mc-abbr">High I, High A</div>
        <div class="mc-desc">Abstract but unstable -- it has abstract interfaces but nothing depends on it. The abstraction has no consumers, so it delivers no architectural benefit. Common example: a protocol interface that was defined speculatively but never used.</div>
      </div>
    </div>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">ISR Risk</div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">Transitive CC Sum</div>
        <div class="mc-abbr">Sum over call tree</div>
        <div class="mc-desc">Sum of cyclomatic complexity of all functions reachable from the ISR through the call graph. All of this complexity executes at interrupt priority. High values mean long worst-case execution paths in the ISR context.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">ISR Risk Score</div>
        <div class="mc-abbr">Composite heuristic</div>
        <div class="mc-desc">Weighted combination of own CC, transitive CC, and call depth. Intended to rank ISRs by latency risk rather than to predict absolute latency -- the codebase-specific weighting means scores are comparable within a project, not across projects.</div>
      </div>
    </div>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">Metrics Etiquette</div>
    <p style="color:var(--dim);font-size:12px;margin-bottom:12px">
      Grady &amp; Caswell (1987) and Grady (1992) devote real space to <em>how</em> to use metrics
      responsibly, not just how to compute them -- worth stating explicitly, since this report is
      easy to share more widely than a single engineer's own analysis.
    </p>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">Identifies code, not developers</div>
        <div class="mc-desc">Composite risk ranking, hotspots, and the structural debt index describe the code's accumulated history and structure, often across many contributors and years. A function scoring high on any of these is not a scorecard for whoever last touched the file.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Churn and coupling reflect history, not performance</div>
        <div class="mc-desc">A file with high commit count or change coupling was worked on a lot -- that alone says nothing about the quality of that work. Combine with structural metrics (as the Change History tab's hotspot score already does) before drawing any conclusion, and even then the conclusion is about the <em>file</em>.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Never for individual performance reviews</div>
        <div class="mc-desc">None of fwlens's metrics were designed or validated for attributing credit or blame to a person. Goodhart's law applies immediately once a metric is tied to evaluation: people optimise the number, not the underlying thing it was a proxy for.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Aggregate numbers are approximate -- say so</div>
        <div class="mc-desc">Defect correlations, reliability growth, and cost/benefit estimates are directional indicators from limited, heuristic data (commit-message keyword matching, small sample counts), not measured facts. A number without its confidence and method attached invites false precision.</div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Recalibrate before trusting defaults</div>
        <div class="mc-desc">COCOMO's constants, the cost/benefit placeholder figures, and the textbook complexity thresholds were all calibrated elsewhere, not on this codebase. The Defects &amp; Estimation tab's correlation analysis exists specifically to let you check whether the metrics that are supposed to predict risk actually do so here -- use it before treating any threshold as gospel.</div>
      </div>
    </div>
  </div>

  <div class="glossary-group">
    <div class="glossary-group-title">References</div>
    <p style="color:var(--dim);font-size:12px;margin-bottom:12px">
      The academic and industry sources behind fwlens's metrics -- what each source is, and which
      metric on this report it backs.
    </p>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="mc-name">Complexity</div>
        <div class="mc-desc">
          McCabe, T.J. (1976). "A Complexity Measure." <em>IEEE Transactions on Software Engineering</em>, SE-2(4), 308-320. -- Cyclomatic complexity.<br><br>
          Halstead, M.H. (1977). <em>Elements of Software Science</em>. Elsevier North-Holland. -- Halstead software science metrics and the maintainability index.<br><br>
          Campbell, G.A. (2018). "Cognitive Complexity: A New Way of Measuring Understandability." SonarSource whitepaper. -- Cognitive complexity; a structural-nesting-weighted successor to McCabe's metric aimed at matching human perception of difficulty, not just path count.
        </div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Coupling and structure</div>
        <div class="mc-desc">
          Henry, S., and Kafura, D. (1981). "Software Structure Metrics Based on Information Flow." <em>IEEE Transactions on Software Engineering</em>, SE-7(5), 510-518. -- Information flow complexity (IF4).<br><br>
          Martin, R.C. (1994). "OO Design Quality Metrics: An Analysis of Dependencies." -- Instability (I) and abstractness (A), the stable-abstractions model underlying instability, abstractness, main sequence distance, and the pain/uselessness zone classification.
        </div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Software process / hotspot analysis</div>
        <div class="mc-desc">
          Tornhill, A. (2015). <em>Your Code as a Crime Scene</em>. Pragmatic Bookshelf. -- Churn x complexity hotspot analysis and change coupling ("logical coupling") -- the actual methodological source for both.
        </div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Estimation</div>
        <div class="mc-desc">
          Boehm, B.W. (1981). <em>Software Engineering Economics</em>. Prentice-Hall. -- Basic COCOMO 81 effort/schedule model.<br><br>
          Grady, R.B., and Caswell, D.L. (1987). <em>Software Metrics: Establishing a Company-Wide Program</em>. Prentice-Hall. -- Original source for the cost/benefit-of-static-analysis framing, and much of the metrics-etiquette material above.
        </div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Reliability</div>
        <div class="mc-desc">
          Goel, A.L., and Okumoto, K. (1979). "Time-Dependent Error-Detection Rate Model for Software Reliability and Other Performance Measures." <em>IEEE Transactions on Reliability</em>, R-28(3), 206-211. -- Goel-Okumoto NHPP model.<br><br>
          Musa, J.D. (1999). <em>Software Reliability Engineering</em>. McGraw-Hill. -- Covers the Musa-Okumoto logarithmic Poisson NHPP model as an alternative; the natural next reference if the exponential discovery-rate assumption behind Goel-Okumoto doesn't fit your defect data well.
        </div>
      </div>
      <div class="metric-card">
        <div class="mc-name">RTOS / concurrency</div>
        <div class="mc-desc">
          Sha, L., Rajkumar, R., and Lehoczky, J.P. (1990). "Priority Inheritance Protocols: An Approach to Real-Time Synchronization." <em>IEEE Transactions on Computers</em>, 39(9), 1175-1185. -- The priority-inversion problem; the RTOS tab's inversion-risk detection is a static-analysis proxy for the structural precondition, not a schedulability proof.
        </div>
      </div>
      <div class="metric-card">
        <div class="mc-name">Defect analysis</div>
        <div class="mc-desc">
          Grady, R.B. (1992). <em>Practical Software Metrics for Project Management and Process Improvement</em>, Ch. 6 ("Complexity Increases Costs") and Ch. 11 ("Dissecting Software Failures"). Hewlett-Packard Professional Books, Prentice-Hall. -- Complexity-vs-defect correlation and commit-message-based root-cause categorisation -- fwlens's coarse, commit-history-based approximation of Grady's defect root-cause and correlation work.
        </div>
      </div>
      <div class="metric-card">
        <div class="mc-name">General reference / further reading</div>
        <div class="mc-desc">
          Fenton, N., and Bieman, J. (2014). <em>Software Metrics: A Rigorous and Practical Approach</em>, 3rd ed. CRC Press. -- Broad academic treatment of size, structure, and quality measurement.<br><br>
          Chidamber, S.R., and Kemerer, C.K. (1994). "A Metrics Suite for Object Oriented Design." <em>IEEE Transactions on Software Engineering</em>, 20(6), 476-493. -- The CK metrics suite (WMC, DIT, NOC, CBO, RFC, LCOM). Not implemented in fwlens -- this is C, not C++/OO, so class-coupling and inheritance-depth metrics don't apply -- but a natural next reference if the codebase ever gains a significant C++ component.
        </div>
      </div>
    </div>
  </div>

</div>


<div class="footer-etiquette">

  <strong>Using this report responsibly:</strong>
  Composite risk ranking, hotspots, and churn identify code to refactor, not developers to
  blame -- they describe the code's accumulated history and structure, often across many
  contributors, not the quality of any one person's work. Do not use any metric in this
  report for individual performance reviews; none were designed or validated for
  attributing credit or blame, and tying a metric to evaluation invites optimising the
  number instead of the thing it was meant to proxy for (Goodhart's law). Correlation,
  reliability, and cost/benefit figures are directional estimates from limited, heuristic
  data, not measured facts -- see the
  <span class="clickable" onclick="show('reference',document.querySelector('[onclick*=reference]'))" style="color:var(--accent)">Metrics Reference</span>
  tab's Metrics Etiquette and References sections for more.
</div>

</div>
</div>

<script>
// Theme toggle
function toggleTheme() {
  const root = document.documentElement;
  const btn  = document.getElementById('theme-btn');
  const isLight = root.classList.toggle('light');
  btn.innerHTML = isLight ? '&#9790; Dark' : '&#9788; Light';
  localStorage.setItem('fwlens-theme', isLight ? 'light' : 'dark');
  // Redraw scatter with new background
  scatterDrawn = false;
  densityHeatmapsDrawn = false;
  if (document.getElementById('pane-architecture').classList.contains('active')) {
    drawScatter();
  }
  if (document.getElementById('pane-distributions').classList.contains('active')) {
    drawDensityHeatmaps();
  }
}
// Restore saved theme
(function() {
  const saved = localStorage.getItem('fwlens-theme');
  if (saved === 'light') {
    document.documentElement.classList.add('light');
    document.addEventListener('DOMContentLoaded', () => {
      const btn = document.getElementById('theme-btn');
      if (btn) btn.innerHTML = '&#9790; Dark';
    });
  }
})();
// Tab switching
function show(name, el) {
  document.querySelectorAll('.pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('pane-' + name).classList.add('active');
  el.classList.add('active');
  if (name === 'architecture') drawScatter();
  if (name === 'distributions') drawDensityHeatmaps();
  buildSideNav();
}

// Left-hand section nav: rebuilt from the active pane's .section-title elements
// each time the tab changes, since each pane owns a different set of sections.
let sectionObserver = null;
function buildSideNav() {
  const nav = document.getElementById('side-nav');
  const activePane = document.querySelector('.pane.active');
  if (!nav || !activePane) return;

  // Pin only the first metric-info panel in this pane -- see the CSS comment on
  // .sticky-info for why the rest stay unpinned.
  document.querySelectorAll('details.metric-info.sticky-info').forEach(el => el.classList.remove('sticky-info'));
  const firstInfo = activePane.querySelector('details.metric-info');
  if (firstInfo) firstInfo.classList.add('sticky-info');

  const titles = activePane.querySelectorAll('.section-title');
  nav.querySelectorAll('a').forEach(a => a.remove());
  if (sectionObserver) sectionObserver.disconnect();

  if (!titles.length) {
    nav.classList.remove('has-links');
    return;
  }
  nav.classList.add('has-links');

  const links = [];
  titles.forEach((el, i) => {
    if (!el.id) el.id = 'sec-' + activePane.id + '-' + i;
    // First child text node only -- section titles often carry a trailing
    // <span> byline (counts, hints) that would otherwise clutter the link label.
    const label = (el.childNodes[0] && el.childNodes[0].textContent.trim())
                  || el.textContent.trim();
    const a = document.createElement('a');
    a.href = '#' + el.id;
    a.textContent = label;
    a.onclick = (e) => {
      e.preventDefault();
      el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };
    nav.appendChild(a);
    links.push(a);
  });

  sectionObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      const idx = Array.from(titles).indexOf(entry.target);
      if (idx === -1) return;
      if (entry.isIntersecting) {
        links.forEach(a => a.classList.remove('side-nav-active'));
        links[idx].classList.add('side-nav-active');
      }
    });
  }, { rootMargin: '-96px 0px -70% 0px', threshold: 0 });
  titles.forEach(el => sectionObserver.observe(el));
}

// Topbar height varies with theme/content, so measure it rather than hardcode --
// the side-nav's sticky offset and max-height both key off this custom property.
function setTopbarHeight() {
  const topbar = document.querySelector('.topbar');
  if (topbar) document.documentElement.style.setProperty('--topbar-h', topbar.offsetHeight + 'px');
}
window.addEventListener('resize', setTopbarHeight);
document.addEventListener('DOMContentLoaded', () => {
  setTopbarHeight();
  buildSideNav();
});

// Table filter
function filterTable(tableId, query) {
  const q = query.toLowerCase();
  document.querySelectorAll('#' + tableId + ' tbody tr').forEach(row => {
    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

// Table sort
function sortTable(tableId, col) {
  const tbl = document.getElementById(tableId);
  const tbody = tbl.tBodies[0];
  const rows = Array.from(tbody.rows);
  const asc = tbl.dataset.sortCol == col && tbl.dataset.sortDir == 'asc';
  tbl.dataset.sortCol = col;
  tbl.dataset.sortDir = asc ? 'desc' : 'asc';
  rows.sort((a, b) => {
    const av = a.cells[col].textContent.trim();
    const bv = b.cells[col].textContent.trim();
    const an = parseFloat(av), bn = parseFloat(bv);
    if (!isNaN(an) && !isNaN(bn)) return asc ? bn - an : an - bn;
    return asc ? bv.localeCompare(av) : av.localeCompare(bv);
  });
  rows.forEach(r => tbody.appendChild(r));
}

// Stable abstractions scatter plot
const scatterData = {{ scatter_data | tojson }};

// Vendored tiny-inflate (MIT licensed, ~3KB -- see vendor/tinyinflate.LICENSE) --
// decompresses the embedded source index below. Used instead of a full gzip/zlib-in-JS
// library to keep this report a single self-contained file with minimal added weight.
{{ tinyinflate_js | safe }}

// The source index (every first-party file's lines, keyed by path) is embedded
// compressed -- real C source compresses ~85-90% with raw deflate, which matters a
// lot once a codebase reaches hundreds of files, since embedded source text is by far
// the largest contributor to this file's size. Decompressed once, synchronously, here
// at load -- before any click handler (showFn) can reach it.
let sourceIndex = {};
try {
  const _b64 = "{{ source_index_compressed_b64 }}";
  const _bin = atob(_b64);
  const _compressed = new Uint8Array(_bin.length);
  for (let i = 0; i < _bin.length; i++) _compressed[i] = _bin.charCodeAt(i);
  const _output = new Uint8Array({{ source_index_uncompressed_len }});
  tinf_uncompress(_compressed, _output);
  sourceIndex = JSON.parse(new TextDecoder('utf-8').decode(_output));
} catch (e) {
  console.error('fwlens: failed to decompress embedded source index -- source viewer will be empty', e);
}

// Generic binned-density heatmap (Distributions tab -- metric correlations).
// Bins points into a grid client-side and colours each cell by count, the
// same idea as the matplotlib hexbin plots in plots.py but drawn natively so
// the report stays a single self-contained file with no sibling PNGs.
let densityHeatmapsDrawn = false;
function drawDensityHeatmap(canvasId, points, xLabel, yLabel) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !points || points.length === 0) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const pad = { l: 44, r: 14, t: 10, b: 34 };
  const pw = W - pad.l - pad.r, ph = H - pad.t - pad.b;
  const bins = 18;

  const xs = points.map(p => p.x), ys = points.map(p => p.y);
  const xMin = Math.min(...xs), xMax = Math.max(...xs);
  const yMin = Math.min(...ys), yMax = Math.max(...ys);
  const xSpan = (xMax - xMin) || 1, ySpan = (yMax - yMin) || 1;

  const grid = Array.from({length: bins}, () => new Array(bins).fill(0));
  points.forEach(p => {
    let bx = Math.floor(((p.x - xMin) / xSpan) * bins);
    let by = Math.floor(((p.y - yMin) / ySpan) * bins);
    if (bx >= bins) bx = bins - 1; if (bx < 0) bx = 0;
    if (by >= bins) by = bins - 1; if (by < 0) by = 0;
    grid[bx][by] += 1;
  });
  const maxCount = Math.max(...grid.map(col => Math.max(...col)));

  ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--canvas-bg').trim() || '#1a1d27';
  ctx.fillRect(0, 0, W, H);

  const cw = pw / bins, ch = ph / bins;
  for (let bx = 0; bx < bins; bx++) {
    for (let by = 0; by < bins; by++) {
      const c = grid[bx][by];
      if (c === 0) continue;
      const intensity = 0.12 + 0.88 * (c / maxCount);
      ctx.fillStyle = `rgba(220,38,38,${intensity.toFixed(2)})`;
      const px = pad.l + bx * cw;
      const py = pad.t + ph - (by + 1) * ch;
      ctx.fillRect(px, py, cw + 0.5, ch + 0.5);
    }
  }

  const dimCol = getComputedStyle(document.documentElement).getPropertyValue('--dim').trim() || '#6b7280';
  const borderCol = getComputedStyle(document.documentElement).getPropertyValue('--border').trim() || '#2a2d3a';
  ctx.strokeStyle = borderCol; ctx.lineWidth = 1;
  ctx.strokeRect(pad.l, pad.t, pw, ph);

  ctx.fillStyle = dimCol; ctx.font = '10px system-ui'; ctx.textAlign = 'center';
  ctx.fillText(xLabel, pad.l + pw / 2, H - 4);
  ctx.save(); ctx.translate(11, pad.t + ph / 2); ctx.rotate(-Math.PI / 2);
  ctx.fillText(yLabel, 0, 0); ctx.restore();

  ctx.font = '9px system-ui';
  ctx.textAlign = 'left';  ctx.fillText(xMin.toFixed(0), pad.l, pad.t + ph + 12);
  ctx.textAlign = 'right'; ctx.fillText(xMax.toFixed(0), pad.l + pw, pad.t + ph + 12);
  ctx.textAlign = 'right';
  ctx.fillText(yMax.toFixed(0), pad.l - 4, pad.t + 8);
  ctx.fillText(yMin.toFixed(0), pad.l - 4, pad.t + ph);
}

function drawDensityHeatmaps() {
  if (densityHeatmapsDrawn) return;
  densityHeatmapsDrawn = true;
  const data = {{ correlation_heatmap_data | tojson }};
  drawDensityHeatmap('heatmap-cc-effort', data.cc_effort, 'Cyclomatic Complexity', 'Halstead Effort');
  drawDensityHeatmap('heatmap-cc-loc',    data.cc_loc,    'Cyclomatic Complexity', 'Function LOC');
  drawDensityHeatmap('heatmap-mi-volume', data.mi_volume, 'Maintainability Index', 'Halstead Volume');
}

let scatterDrawn = false;

function drawScatter() {
  if (scatterDrawn) return;
  scatterDrawn = true;
  const canvas = document.getElementById('scatter-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const pad = { l: 40, r: 20, t: 20, b: 40 };
  const pw = W - pad.l - pad.r, ph = H - pad.t - pad.b;

  function toX(i) { return pad.l + i * pw; }
  function toY(a) { return pad.t + (1 - a) * ph; }

  function redraw(hovIdx) {
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--canvas-bg').trim() || '#1a1d27';
    ctx.fillRect(0, 0, W, H);

    // Zone fills
    ctx.fillStyle = 'rgba(224,92,92,0.12)';
    ctx.fillRect(toX(0), toY(0.3), toX(0.3)-toX(0), toY(0)-toY(0.3));
    ctx.fillStyle = 'rgba(224,184,92,0.12)';
    ctx.fillRect(toX(0.7), toY(1.0), toX(1.0)-toX(0.7), toY(0.7)-toY(1.0));

    // Main sequence line
    ctx.strokeStyle = 'rgba(79,156,249,0.4)'; ctx.lineWidth = 1;
    ctx.setLineDash([4,4]);
    ctx.beginPath(); ctx.moveTo(toX(0),toY(1)); ctx.lineTo(toX(1),toY(0));
    ctx.stroke(); ctx.setLineDash([]);

    const dimCol    = getComputedStyle(document.documentElement).getPropertyValue('--dim').trim()    || '#6b7280';
    const borderCol = getComputedStyle(document.documentElement).getPropertyValue('--border').trim() || '#2a2d3a';

    // Axes
    ctx.strokeStyle = borderCol; ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pad.l,pad.t); ctx.lineTo(pad.l,pad.t+ph);
    ctx.moveTo(pad.l,pad.t+ph); ctx.lineTo(pad.l+pw,pad.t+ph);
    ctx.stroke();

    // Axis labels
    ctx.fillStyle = dimCol; ctx.font = '11px system-ui'; ctx.textAlign = 'center';
    ctx.fillText('Instability (I)', pad.l+pw/2, H-4);
    ctx.save(); ctx.translate(12, pad.t+ph/2); ctx.rotate(-Math.PI/2);
    ctx.fillText('Abstractness (A)', 0, 0); ctx.restore();

    // Tick labels
    ctx.textAlign = 'center'; ctx.font = '10px system-ui';
    [0, 0.5, 1.0].forEach(v => {
      ctx.fillStyle = dimCol;
      ctx.textAlign = 'center';
      ctx.fillText(v.toFixed(1), toX(v), pad.t+ph+14);
      ctx.textAlign = 'right';
      ctx.fillText(v.toFixed(1), pad.l-5, toY(v)+4);
    });

    // Zone labels
    ctx.font = '10px system-ui'; ctx.textAlign = 'center';
    ctx.fillStyle = 'rgba(224,92,92,0.7)';
    ctx.fillText('Pain', toX(0.15), toY(0.05));
    ctx.fillStyle = 'rgba(224,184,92,0.7)';
    ctx.fillText('Useless', toX(0.85), toY(0.95));

    // Points -- colour by distance from main sequence (MSD) and pain score
    // green = on/near line (MSD < 0.2), blue = moderate (0.2-0.4),
    // yellow = far (0.4-0.6), red = pain zone (pain_score >= 0.6)
    function ptColour(pt) {
      if (pt.pain_score >= 0.6) return '#e05c5c';   // red: Zone of Pain
      if (pt.msd >= 0.5)        return '#e0b85c';   // yellow: far from line
      if (pt.msd >= 0.3)        return '#4f9cf9';   // blue: moderate distance
      return '#5ce07a';                              // green: on/near line
    }
    scatterData.forEach((pt, idx) => {
      const px = toX(pt.i), py = toY(pt.a);
      const hov = idx === hovIdx;
      if (hov) {
        ctx.beginPath(); ctx.arc(px, py, 10, 0, 2*Math.PI);
        ctx.fillStyle = 'rgba(255,255,255,0.15)'; ctx.fill();
      }
      ctx.beginPath(); ctx.arc(px, py, hov ? 6 : 5, 0, 2*Math.PI);
      ctx.fillStyle = ptColour(pt); ctx.fill();
      if (hov) {
        ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.5; ctx.stroke();
      }
    });
  }

  redraw(-1);

  const tip = document.getElementById('scatter-tip');
  const tipName = document.getElementById('tip-name');
  const tipVals = document.getElementById('tip-vals');
  const tipZone = document.getElementById('tip-zone');
  const zoneLabels = {
    pain:'Zone of Pain', main_sequence:'Main Sequence',
    warning:'Cyclic', unknown:'Unknown'
  };
  function tipColour(pt) {
    if (pt.pain_score >= 0.6) return '#e05c5c';
    if (pt.msd >= 0.5)        return '#e0b85c';
    if (pt.msd >= 0.3)        return '#4f9cf9';
    return '#5ce07a';
  }

  let lastHov = -1;
  canvas.addEventListener('mousemove', e => {
    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left, my = e.clientY - rect.top;
    let hitIdx = -1, hitDist = Infinity;
    scatterData.forEach((pt, idx) => {
      const d = Math.hypot(mx - toX(pt.i), my - toY(pt.a));
      if (d < 10 && d < hitDist) { hitDist = d; hitIdx = idx; }
    });
    if (hitIdx !== lastHov) { lastHov = hitIdx; redraw(hitIdx); }
    if (hitIdx >= 0) {
      const pt = scatterData[hitIdx];
      tipName.textContent = pt.name;
      tipVals.textContent = `I=${pt.i.toFixed(2)}  A=${pt.a.toFixed(2)}  MSD=${pt.msd.toFixed(2)}  pain=${pt.pain_score.toFixed(2)}  fan-in=${pt.fan_in}  ${pt.layer}`;
      tipZone.textContent = zoneLabels[pt.zone] || pt.zone;
      tipZone.style.color = tipColour(pt);
      tip.style.display = 'block';
      tip.style.left = (e.clientX + 14) + 'px';
      tip.style.top  = (e.clientY - 10) + 'px';
      canvas.style.cursor = 'crosshair';
    } else {
      tip.style.display = 'none';
      canvas.style.cursor = 'default';
    }
  });
  canvas.addEventListener('mouseleave', () => {
    tip.style.display = 'none';
    if (lastHov !== -1) { lastHov = -1; redraw(-1); }
  });
}

// ── C syntax tokeniser ──────────────────────────────────────────────────────
const C_KEYWORDS = new Set([
  'auto','break','case','char','const','continue','default','do','double',
  'else','enum','extern','float','for','goto','if','inline','int','long',
  'register','restrict','return','short','signed','sizeof','static','struct',
  'switch','typedef','union','unsigned','void','volatile','while','_Bool',
  '_Complex','_Imaginary','uint8_t','uint16_t','uint32_t','uint64_t',
  'int8_t','int16_t','int32_t','int64_t','bool','true','false','NULL',
  'size_t','ptrdiff_t'
]);

function tokeniseLine(line) {
  let out = '', i = 0;
  const esc = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  // Full-line preprocessor
  if (/^\s*#/.test(line)) return `<span class="tk-pp">${esc(line)}</span>`;

  while (i < line.length) {
    // Line comment
    if (line[i]==='/' && line[i+1]==='/') {
      out += `<span class="tk-cm">${esc(line.slice(i))}</span>`; break;
    }
    // Block comment start
    if (line[i]==='/' && line[i+1]==='*') {
      const end = line.indexOf('*/', i+2);
      if (end >= 0) {
        out += `<span class="tk-cm">${esc(line.slice(i, end+2))}</span>`; i = end+2;
      } else {
        out += `<span class="tk-cm">${esc(line.slice(i))}</span>`; break;
      }
      continue;
    }
    // String literal
    if (line[i]==='"') {
      let j = i+1;
      while (j < line.length && !(line[j]==='"' && line[j-1]!=='\\')) j++;
      out += `<span class="tk-str">${esc(line.slice(i, j+1))}</span>`; i = j+1; continue;
    }
    // Char literal
    if (line[i]==="'") {
      let j = i+1;
      while (j < line.length && !(line[j]==="'" && line[j-1]!=='\\')) j++;
      out += `<span class="tk-str">${esc(line.slice(i, j+1))}</span>`; i = j+1; continue;
    }
    // Number
    if (/[0-9]/.test(line[i]) || (line[i]==='.' && /[0-9]/.test(line[i+1]||''))) {
      let j = i;
      while (j < line.length && /[0-9a-fA-FxXuUlLeE._]/.test(line[j])) j++;
      out += `<span class="tk-num">${esc(line.slice(i,j))}</span>`; i = j; continue;
    }
    // Identifier or keyword
    if (/[a-zA-Z_]/.test(line[i])) {
      let j = i;
      while (j < line.length && /[a-zA-Z0-9_]/.test(line[j])) j++;
      const word = line.slice(i, j);
      // Function call: identifier followed by (
      const isCall = line[j] === '(';
      if (C_KEYWORDS.has(word)) {
        out += `<span class="tk-kw">${esc(word)}</span>`;
      } else if (isCall) {
        out += `<span class="tk-fn">${esc(word)}</span>`;
      } else {
        out += esc(word);
      }
      i = j; continue;
    }
    out += esc(line[i]); i++;
  }
  return out;
}

// ── Modal display ───────────────────────────────────────────────────────────
function closeModal() {
  document.getElementById('code-modal').classList.remove('open');
  document.getElementById('modal-code').innerHTML = '';
}
document.addEventListener('keydown', e => { if (e.key==='Escape') closeModal(); });

function renderSource(path, highlightLine) {
  const lines = sourceIndex[path];
  if (!lines) {
    document.getElementById('modal-code').innerHTML =
      '<tr><td colspan="2" style="padding:16px;color:var(--dim)">Source not available (file exceeds embed limit or was not found at analysis time).</td></tr>';
    return;
  }
  const frag = document.createDocumentFragment();
  lines.forEach((raw, idx) => {
    const lineNo = idx + 1;
    const tr = document.createElement('tr');
    if (lineNo === highlightLine) tr.className = 'hl';
    tr.innerHTML = `<td class="ln">${lineNo}</td><td class="lc">${tokeniseLine(raw)}</td>`;
    frag.appendChild(tr);
  });
  const tbl = document.getElementById('modal-code');
  tbl.innerHTML = '';
  tbl.appendChild(frag);
  if (highlightLine) {
    const hlRow = tbl.querySelector('tr.hl');
    if (hlRow) setTimeout(() => hlRow.scrollIntoView({block:'center'}), 50);
  }
}

function showFile(path) {
  document.getElementById('modal-title').textContent = path.split(/[/\\]/).pop();
  document.getElementById('code-modal').classList.add('open');
  renderSource(path, null);
}

function showFn(path, line) {
  document.getElementById('modal-title').textContent =
    path.split(/[/\\]/).pop() + (line ? '  :' + line : '');
  document.getElementById('code-modal').classList.add('open');
  renderSource(path, line);
}
</script>
</body>
</html>
"""


def _breach(value, threshold) -> bool:
    return value > threshold


def _build_distributions(model: ProjectModel, config) -> list[dict]:
    """Build per-metric distribution data for the Distributions tab."""
    from fwlens.stats.distributions import _fit_lognormal, _exceedance_probability

    t = config.thresholds
    fp_funcs = model.first_party_functions()
    if not fp_funcs:
        return []

    metrics = [
        ("cyclomatic_complexity", t.cyclomatic_complexity),
        ("cognitive_complexity",  t.cognitive_complexity),
        ("loc",                   t.function_loc),
        ("block_depth",           t.block_depth),
        ("halstead_effort",       t.halstead_effort),
        ("halstead_volume",       t.halstead_volume),
        ("return_path_count",     t.return_path_count),
        ("magic_number_density",  t.magic_number_density),
        ("fan_out",               t.fan_out),
    ]

    result = []
    for metric, threshold in metrics:
        values = [float(getattr(f, metric, 0)) for f in fp_funcs]
        if not values:
            continue
        fit = _fit_lognormal(values)
        exc = _exceedance_probability(float(threshold), fit)

        # Build percentile bars: p25, p50, p75, p90, p95, p99
        import numpy as np
        arr = sorted([v for v in values if v >= 0])
        if not arr:
            continue
        pcts = [25, 50, 75, 90, 95, 99]
        pct_vals = [float(np.percentile(arr, p)) for p in pcts]
        max_val = max(pct_vals[-1] * 1.1, float(threshold) * 1.1, 1.0)

        bars = []
        colours = ["#4f9cf9", "#4f9cf9", "#4f9cf9", "#e0b85c", "#e05c5c", "#e05c5c"]
        for pct, val, col in zip(pcts, pct_vals, colours):
            width_pct = min(100.0, 100.0 * val / max_val)
            threshold_pct = min(100.0, 100.0 * float(threshold) / max_val) \
                if threshold else None
            bars.append({
                "label":        f"p{pct}",
                "value":        f"{val:.1f}" if val < 100 else f"{val:.0f}",
                "width_pct":    round(width_pct, 1),
                "colour":       col,
                "threshold_pct": round(threshold_pct, 1) if threshold_pct else None,
            })

        result.append({
            "metric":          metric,
            "p50":             f"{fit.get('p50', 0):.1f}",
            "p90":             f"{fit.get('p90', 0):.1f}",
            "p99":             f"{fit.get('p99', 0):.1f}",
            "exceedance_pct":  round(exc * 100, 1),
            "bars":            bars,
        })
    return result


def _build_source_index(modules: list, max_file_loc: int =10000) -> dict:
    """Read source files and return {str(path): [lines]} for files within size limit."""
    index = {}
    for m in modules:
        path = m.path
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if len(lines) <= max_file_loc:
            index[str(path).replace("\\", "/")] = lines
    return index


def _compress_source_index(source_index: dict) -> tuple[str, int]:
    """
    Serialise + raw-deflate-compress the source index for embedding, then base64.
    Real C source compresses ~85-90% (measured against a 76-file/612KB sample), which
    matters a lot once a codebase reaches hundreds of files -- the embedded source text
    is by far the largest contributor to fwlens_report.html's file size. Uses raw
    deflate (zlib wbits=-15, no zlib/gzip header) paired with a small vendored pure-JS
    inflate implementation (tinyinflate, MIT licensed, ~3KB minified -- see
    fwlens/output/vendor/tinyinflate.LICENSE) rather than a full gzip/zlib-in-JS
    library, to keep the report a single self-contained file with minimal bundle
    weight added for the decompressor itself. Returns (base64_compressed, uncompressed_byte_length)
    -- tinyinflate needs the decompressed size upfront to pre-allocate its output buffer.
    """
    raw = json.dumps(source_index, ensure_ascii=False).encode("utf-8")
    compressor = zlib.compressobj(level=9, wbits=-15)
    compressed = compressor.compress(raw) + compressor.flush()
    return base64.b64encode(compressed).decode("ascii"), len(raw)


def generate_html_report(model: ProjectModel, config: FwLensConfig):
    t = config.thresholds
    fp_funcs  = model.first_party_functions()
    fp_modules = model.first_party_modules()

    # Threshold breach summary -- raw counts, same eight thresholds as the console
    # summary. Distinct from Exceedance %, which is a fitted-distribution estimate;
    # this is a plain count, useful as a sanity check against that estimate.
    _breach_defs = [
        ("Cyclomatic complexity", "cyclomatic_complexity", t.cyclomatic_complexity),
        ("Cognitive complexity", "cognitive_complexity", t.cognitive_complexity),
        ("Block depth", "block_depth", t.block_depth),
        ("Function LOC", "loc", t.function_loc),
        ("Parameter count", "parameter_count", t.parameter_count),
        ("Return paths", "return_path_count", t.return_path_count),
        ("Magic number density", "magic_number_density", t.magic_number_density),
        ("Fan-out", "fan_out", t.fan_out),
    ]
    _n_funcs = max(len(fp_funcs), 1)
    breach_rows = []
    for label, attr, threshold in _breach_defs:
        count = sum(1 for f in fp_funcs if getattr(f, attr) > threshold)
        breach_rows.append({
            "label": label, "threshold": threshold, "count": count,
            "pct": round(100 * count / _n_funcs, 1),
        })

    source_index = _build_source_index(fp_modules, max_file_loc=getattr(config, 'source_embed_loc_limit', 10000))
    source_index_compressed_b64, source_index_uncompressed_len = _compress_source_index(source_index)
    tinyinflate_js = (Path(__file__).parent / "vendor" / "tinyinflate.js").read_text(encoding="utf-8")

    # Function rows
    func_rows = []
    for f in sorted(fp_funcs, key=lambda x: x.structural_debt_index, reverse=True):
        func_rows.append({
            "name":                  f.name,
            "file_short":            f.file.name,
            "cyclomatic_complexity": f.cyclomatic_complexity,
            "cognitive_complexity":  f.cognitive_complexity,
            "loc":                   f.loc,
            "block_depth":           f.block_depth,
            "return_path_count":     f.return_path_count,
            "magic_number_density":  f.magic_number_density,
            "fan_out":               f.fan_out,
            "halstead_effort":       f.halstead_effort,
            "mi_woc":                f.mi_woc,
            "structural_debt_index": f.structural_debt_index,
            "cc_breach":    _breach(f.cyclomatic_complexity, t.cyclomatic_complexity),
            "cog_breach":   _breach(f.cognitive_complexity,  t.cognitive_complexity),
            "loc_breach":   _breach(f.loc,                   t.function_loc),
            "depth_breach": _breach(f.block_depth,           t.block_depth),
            "ret_breach":   _breach(f.return_path_count,     t.return_path_count),
            "magic_breach": _breach(f.magic_number_density,  t.magic_number_density),
            "fanout_breach":_breach(f.fan_out,               t.fan_out),
            "file_path":     str(f.file).replace("\\", "/"),
            "has_source":           str(f.file).replace("\\", "/") in source_index,
            "line":                 f.line,
            "magic_numbers":        sorted(set(f.magic_numbers)),
            "indirect_call_count":  f.indirect_call_count,
            "dispatch_table_reads": f.dispatch_table_reads,
        })

    # Module rows
    module_rows = []
    for m in sorted(fp_modules, key=lambda x: x.instability, reverse=True):
        module_rows.append({
            "name":                  m.path.name,
            "layer":                 m.layer,
            "loc":                   m.loc,
            "function_count":        m.function_count,
            "fan_in":                m.fan_in,
            "fan_out":               m.fan_out,
            "instability":           m.instability,
            "main_sequence_distance":m.main_sequence_distance,
            "avg_cc":                m.avg_cc,
            "avg_halstead_effort":   m.avg_halstead_effort,
            "avg_magic_density":     m.avg_magic_density,
            "internal_call_cohesion":m.internal_call_cohesion,
            "include_depth":         m.include_depth,
            "in_cycle":              m.in_cycle,
            "zone":                  getattr(m, "zone", "unknown"),
            "pain_score":            getattr(m, "pain_score", 0.0),
            "msd_breach":            m.main_sequence_distance > t.main_sequence_distance,
            "abstractness":          round(m.abstractness, 3),
            "file_path":             str(m.path).replace("\\", "/"),
            "has_source":            str(m.path).replace("\\", "/") in source_index,
        })

    # Architecture violation rows
    arch_rows = [
        {
            "source_module": v.source_module.name,
            "source_layer":  v.source_layer,
            "target_module": v.target_module.name,
            "target_layer":  v.target_layer,
            "violation_type":v.violation_type,
        }
        for v in model.arch_violations
    ]

    # Scatter data for stable abstractions plot
    scatter_data = [
        {
            "name":       m.path.name,
            "i":          round(m.instability, 3),
            "a":          round(m.abstractness, 3),
            "zone":       getattr(m, "zone", "unknown"),
            "msd":        round(m.main_sequence_distance, 3),
            "pain_score": round(getattr(m, "pain_score", 0.0), 3),
            "fan_in":     m.fan_in,
            "layer":      m.layer or "Unknown",
        }
        for m in fp_modules
    ]

    # Correlation heatmap data for the Distributions tab -- binned client-side
    # by drawDensityHeatmap(). Mirrors the (x, y) pairs plots.py already feeds
    # into its matplotlib hexbin PNGs (heatmap_effort_vs_cyclomatic.png etc.),
    # but those PNGs are never referenced by this report -- they're only
    # written to a sibling plots/ dir when "plots" is requested as an output
    # format. Rendering them natively here keeps the report self-contained.
    # Header include hygiene (fwlens.header_checks) -- display rows with short
    # filenames, matching every other table's file_short convention.
    def _short(p) -> str:
        return Path(p).name

    include_cycle_rows = [
        {"files": [_short(f) for f in c.files], "length": c.length}
        for c in model.include_cycles
    ]
    self_include_rows = [{"file": _short(s.file)} for s in model.self_includes]
    missing_guard_rows = [{"file": _short(g.file), "reason": g.reason} for g in model.missing_include_guards]
    deep_include_rows = [
        {"file": _short(d.file), "depth": d.depth, "chain": [_short(f) for f in d.chain]}
        for d in model.deep_include_chains
    ]
    unused_include_rows = [
        {"file": _short(u.file), "included": _short(u.included), "declared_name_count": u.declared_name_count}
        for u in model.unused_includes
    ]

    correlation_heatmap_data = {
        "cc_effort": [{"x": f.cyclomatic_complexity, "y": f.halstead_effort} for f in fp_funcs],
        "cc_loc":    [{"x": f.cyclomatic_complexity, "y": f.loc} for f in fp_funcs],
        "mi_volume": [{"x": f.mi_woc, "y": f.halstead_volume} for f in fp_funcs],
    }

    dead_rows = [
        {
            "name":                  f.name,
            "file_short":            f.file.name,
            "file_path":             str(f.file).replace("\\", "/"),
            "has_source":            str(f.file).replace("\\", "/") in source_index,
            "line":                  f.line,
            "loc":                   f.loc,
            "cyclomatic_complexity": f.cyclomatic_complexity,
        }
        for f in model.dead_candidates
    ]

    isr_rows = [
        {
            "isr_name":          r.isr_name,
            "file_short":        r.file.name,
            "file_path":         str(r.file).replace("\\", "/"),
            "has_source":        str(r.file).replace("\\", "/") in source_index,
            "line":              getattr(r, "line", 0),
            "own_cc":            r.own_cc,
            "transitive_cc_sum": r.transitive_cc_sum,
            "call_depth":        r.call_depth,
            "risk_score":        r.risk_score,
            "non_estimable":     r.non_estimable,
        }
        for r in model.isr_risks
    ]

    def _mod_row(m) -> dict:
        return {
            "name":                  m.path.name,
            "layer":                 m.layer,
            "fan_in":                m.fan_in,
            "fan_out":               m.fan_out,
            "instability":           m.instability,
            "internal_call_cohesion":m.internal_call_cohesion,
            "in_cycle":              m.in_cycle,
            "file_path":             str(m.path).replace("\\", "/"),
            "has_source":            str(m.path).replace("\\", "/") in source_index,
        }

    high_coupling_rows = [
        _mod_row(m) for m in sorted(fp_modules, key=lambda x: x.fan_out, reverse=True)
        if m.fan_out > t.fan_out
    ]
    low_cohesion_rows = [
        _mod_row(m) for m in sorted(fp_modules, key=lambda x: x.internal_call_cohesion)
        if m.internal_call_cohesion < t.cohesion_min
    ]
    high_coupling_low_cohesion_rows = [
        _mod_row(m) for m in sorted(fp_modules, key=lambda x: x.fan_out, reverse=True)
        if m.fan_out > t.fan_out and m.internal_call_cohesion < t.cohesion_min
    ]

    magic_rows = [
        {
            "name":                 f["name"],
            "file_short":           f["file_short"],
            "file_path":            f["file_path"],
            "has_source":           f["has_source"],
            "line":                 f["line"],
            "loc":                  f["loc"],
            "magic_number_density": f["magic_number_density"],
            "magic_numbers":        f["magic_numbers"],
        }
        for f in func_rows
        if f["magic_breach"]
    ]
    magic_rows.sort(key=lambda r: r["magic_number_density"], reverse=True)

    meta = {        "ewp":             model.ewp_path.name,
        "configuration":   model.configuration,
        "module_count":    len(fp_modules),
        "function_count":  len(fp_funcs),
        "total_loc":       sum(f.loc for f in fp_funcs),
        "dead_count":      len(model.dead_candidates),
        "cc_breaches":     sum(1 for f in fp_funcs if f.cyclomatic_complexity > t.cyclomatic_complexity),
        "magic_breaches":  len(magic_rows),
        "cyclic_modules":  sum(1 for m in fp_modules if m.in_cycle),
        "arch_violations": len(model.arch_violations),
        "zone_pain":       sum(1 for m in fp_modules if getattr(m, "zone", "") == "pain"),
        "unknown_layers":  sum(1 for m in fp_modules if not m.layer or m.layer == "Unknown"),
        "group_dir_mismatches": len(model.group_dir_mismatches),
        "assert_coverage": round(100 * len([f for f in fp_funcs if f.assert_count > 0]) / max(len(fp_funcs), 1), 1),
        "stack_over50":    len([f for f in fp_funcs if f.stack_depth_estimate is not None and f.stack_depth_estimate > 50]),
        "include_cycle_count": sum(c.length for c in model.include_cycles) + len(model.self_includes),
        "missing_guard_count": len(model.missing_include_guards),
        "unused_include_count": len(model.unused_includes),
    }

    group_dir_rows = [
        {
            "file":          m.file,
            "file_name":     m.file.name,
            "iar_group":     m.iar_group,
            "actual_dir":    m.actual_dir,
            "layer":         m.layer,
            "suggested_dir": str(m.suggested_dir),
        }
        for m in model.group_dir_mismatches
    ]

    dispatch_table_rows = [
        {
            "var_name":       t.var_name,
            "file_short":     t.file.name,
            "file_path":      str(t.file).replace("\\", "/"),
            "has_source":     str(t.file).replace("\\", "/") in source_index,
            "line":           t.line,
            "stored_fns":     t.stored_fns,
            "dispatchers":    t.dispatchers,
            "registered_into": t.registered_into,
        }
        for t in model.dispatch_tables
    ]

    # -----------------------------------------------------------------------
    # Critical functions: high fan_in × SDI, not dead
    # -----------------------------------------------------------------------
    critical_rows = []
    for f in fp_funcs:
        if f.is_dead_candidate or f.fan_in == 0:
            continue
        score = f.fan_in * f.structural_debt_index
        if score > 0:
            critical_rows.append({
                "name":                  f.name,
                "file_short":            f.file.name,
                "file_path":             str(f.file).replace("\\", "/"),
                "has_source":            str(f.file).replace("\\", "/") in source_index,
                "line":                  f.line,
                "fan_in":                f.fan_in,
                "fan_out":               f.fan_out,
                "cyclomatic_complexity": f.cyclomatic_complexity,
                "structural_debt_index": round(f.structural_debt_index, 3),
                "halstead_bugs":         round(f.halstead_bugs, 2),
                "assert_count":          f.assert_count,
                "risk_score":            round(score, 1),
            })
    critical_rows.sort(key=lambda r: r["risk_score"], reverse=True)
    critical_rows = critical_rows[:25]

    # -----------------------------------------------------------------------
    # Assert coverage gaps: high CC + high fan_in + zero asserts
    # -----------------------------------------------------------------------
    assert_gap_rows = []
    for f in fp_funcs:
        if f.assert_count > 0 or f.fan_in < 3 or f.cyclomatic_complexity < 8:
            continue
        risk = f.fan_in * f.cyclomatic_complexity
        assert_gap_rows.append({
            "name":                  f.name,
            "file_short":            f.file.name,
            "file_path":             str(f.file).replace("\\", "/"),
            "has_source":            str(f.file).replace("\\", "/") in source_index,
            "line":                  f.line,
            "fan_in":                f.fan_in,
            "cyclomatic_complexity": f.cyclomatic_complexity,
            "halstead_effort":       round(f.halstead_effort),
            "risk":                  risk,
        })
    assert_gap_rows.sort(key=lambda r: r["risk"], reverse=True)
    assert_gap_rows = assert_gap_rows[:20]

    assert_total    = len([f for f in fp_funcs if f.assert_count > 0])
    assert_coverage = round(100 * assert_total / max(len(fp_funcs), 1), 1)

    # -----------------------------------------------------------------------
    # Stack depth analysis
    # -----------------------------------------------------------------------
    stack_rows = []
    for f in fp_funcs:
        if f.stack_depth_estimate is None:
            continue
        stack_rows.append({
            "name":             f.name,
            "file_short":       f.file.name,
            "file_path":        str(f.file).replace("\\", "/"),
            "has_source":       str(f.file).replace("\\", "/") in source_index,
            "line":             f.line,
            "depth":            f.stack_depth_estimate,
            "estimable":        f.stack_estimable,
            "is_isr":           f.is_isr,
            "fan_in":           f.fan_in,
            "cyclomatic_complexity": f.cyclomatic_complexity,
        })
    stack_rows.sort(key=lambda r: r["depth"], reverse=True)

    all_depths  = [r["depth"] for r in stack_rows]
    stack_stats = {
        "max":    max(all_depths) if all_depths else 0,
        "mean":   round(sum(all_depths) / max(len(all_depths), 1), 1),
        "median": sorted(all_depths)[len(all_depths) // 2] if all_depths else 0,
        "over50": len([d for d in all_depths if d > 50]),
        "over20": len([d for d in all_depths if d > 20]),
        "total":  len(all_depths),
    }
    stack_rows = stack_rows[:30]

    # -----------------------------------------------------------------------
    # Global coupling: functions reading/writing the most globals
    # -----------------------------------------------------------------------
    global_coupling_rows = []
    for f in fp_funcs:
        reads  = len(f.global_reads)
        writes = len(f.global_writes)
        total  = reads + writes
        if total < 4:
            continue
        global_coupling_rows.append({
            "name":       f.name,
            "file_short": f.file.name,
            "file_path":  str(f.file).replace("\\", "/"),
            "has_source": str(f.file).replace("\\", "/") in source_index,
            "line":       f.line,
            "reads":      reads,
            "writes":     writes,
            "total":      total,
            "fan_out":    f.fan_out,
            "fan_in":     f.fan_in,
            "top_reads":  f.global_reads[:6],
            "top_writes": f.global_writes[:6],
        })
    global_coupling_rows.sort(key=lambda r: r["total"], reverse=True)
    global_coupling_rows = global_coupling_rows[:25]

    # -----------------------------------------------------------------------
    # Dead code by layer
    # -----------------------------------------------------------------------
    _dead_by_layer: dict = {}
    for f in model.dead_candidates:
        # find the module this function belongs to
        fn_path = str(f.file).replace("\\", "/")
        layer = "Unknown"
        for m in fp_modules:
            if str(m.path).replace("\\", "/") == fn_path:
                layer = m.layer or "Unknown"
                break
        _dead_by_layer[layer] = _dead_by_layer.get(layer, 0) + 1
    dead_by_layer = sorted(_dead_by_layer.items(), key=lambda x: x[1], reverse=True)

    # --- Estimation / reliability / defect analysis -----------------------------------
    reliability = None
    if model.reliability_growth:
        r = model.reliability_growth
        reliability = {
            "fix_commit_count":    r.fix_commit_count,
            "fitted_total_defects": r.fitted_total_defects,
            "fitted_discovery_rate": r.fitted_discovery_rate,
            "cumulative_to_date":  r.cumulative_to_date,
            "estimated_remaining": r.estimated_remaining,
            "trend":               r.trend,
            "r_squared":           r.r_squared,
            "days_span":           r.days_span,
        }

    effort = None
    if model.effort_estimate:
        e = model.effort_estimate
        effort = {
            "mode":                  e.mode,
            "kloc":                  e.kloc,
            "effort_person_months":  e.effort_person_months,
            "schedule_months":       e.schedule_months,
            "average_staffing":      e.average_staffing,
        }

    cost_benefit = None
    if model.cost_benefit:
        cb = model.cost_benefit
        cost_benefit = {
            "estimated_remaining_defects": cb.estimated_remaining_defects,
            "cost_per_defect_static_usd":  cb.cost_per_defect_static_usd,
            "cost_per_defect_field_usd":   cb.cost_per_defect_field_usd,
            "cost_if_static_usd":          cb.cost_if_static_usd,
            "cost_if_field_usd":           cb.cost_if_field_usd,
            "potential_savings_usd":       cb.potential_savings_usd,
        }

    defect_correlations = [
        {"label": c.label, "spearman_r": c.spearman_r, "p_value": c.p_value, "n": c.n}
        for c in model.defect_correlations
    ]

    # Information flow complexity (Henry & Kafura) -- needs nonzero fan-in AND fan-out
    information_flow_rows = [
        {
            "name":       f.name,
            "file_short": f.file.name,
            "file_path":  str(f.file).replace("\\", "/"),
            "has_source": str(f.file).replace("\\", "/") in source_index,
            "line":       f.line,
            "fan_in":     f.fan_in,
            "fan_out":    f.fan_out,
            "loc":        f.loc,
            "if4":        f.information_flow_complexity,
        }
        for f in sorted(fp_funcs, key=lambda x: x.information_flow_complexity, reverse=True)
        if f.information_flow_complexity > 0
    ][:30]

    meta["reliability_trend"] = reliability["trend"] if reliability else "no_data"
    meta["defect_correlation_count"] = len(defect_correlations)
    meta["cost_benefit_savings"] = cost_benefit["potential_savings_usd"] if cost_benefit else 0

    # --- Hotspots (churn x structural debt) --------------------------------------------
    hotspot_rows = []
    if model.git_available:
        commit_by_path = {m.path: m.commit_count for m in fp_modules}
        for f in model.hotspots:
            if f.hotspot_score <= 0:
                continue
            hotspot_rows.append({
                "name":          f.name,
                "file_short":    f.file.name,
                "file_path":     str(f.file).replace("\\", "/"),
                "has_source":    str(f.file).replace("\\", "/") in source_index,
                "line":          f.line,
                "commit_count":  commit_by_path.get(f.file, 0),
                "sdi":           round(f.structural_debt_index, 3),
                "hotspot_score": round(f.hotspot_score, 3),
                "vague_name":    f.vague_name_flag,
            })
        hotspot_rows = hotspot_rows[:30]

    # --- Bug-fix-weighted hotspots (churn restricted to fix-flavoured commits) ---------
    bugfix_hotspot_rows = []
    if model.git_available:
        bugfix_by_path = {m.path: m.bugfix_commit_count for m in fp_modules}
        for f in model.bugfix_hotspots:
            if f.bugfix_hotspot_score <= 0:
                continue
            bugfix_hotspot_rows.append({
                "name":          f.name,
                "file_short":    f.file.name,
                "file_path":     str(f.file).replace("\\", "/"),
                "has_source":    str(f.file).replace("\\", "/") in source_index,
                "line":          f.line,
                "bugfix_commit_count": bugfix_by_path.get(f.file, 0),
                "sdi":           round(f.structural_debt_index, 3),
                "bugfix_hotspot_score": round(f.bugfix_hotspot_score, 3),
            })
        bugfix_hotspot_rows = bugfix_hotspot_rows[:30]

    # --- Code ownership / knowledge map --------------------------------------------------
    ownership_rows = [
        {
            "file":                m.path.name,
            "commit_count":        m.commit_count,
            "main_author":         m.main_author,
            "main_author_share":   round(m.main_author_share, 3),
            "distinct_author_count": m.distinct_author_count,
            "ownership_risk_score": round(m.ownership_risk_score, 3),
        }
        for m in model.ownership_risks if m.ownership_risk_score > 0
    ][:30]

    # --- Complexity trend in top hotspots -------------------------------------------------
    complexity_trend_rows = [
        {
            "file":  t.file.name,
            "trend": t.trend,
            "slope": round(t.slope, 4),
            "r_squared": round(t.r_squared, 3),
            "point_count": len(t.points),
        }
        for t in model.complexity_trends if t.trend != "insufficient_data"
    ]

    # --- Composite risk ranking ---------------------------------------------------------
    composite_risk_rows = [
        {
            "name":       f.name,
            "file_short": f.file.name,
            "file_path":  str(f.file).replace("\\", "/"),
            "has_source": str(f.file).replace("\\", "/") in source_index,
            "line":       f.line,
            "score":      round(f.composite_risk_score, 3),
        }
        for f in model.composite_risk if f.composite_risk_score > 0
    ][:30]

    # --- Clone / near-duplicate function pairs ------------------------------------------
    clone_rows = [
        {
            "function_a":  p.function_a,
            "file_a":      p.file_a.name,
            "file_a_path": str(p.file_a).replace("\\", "/"),
            "has_source_a": str(p.file_a).replace("\\", "/") in source_index,
            "line_a":      p.line_a,
            "function_b":  p.function_b,
            "file_b":      p.file_b.name,
            "file_b_path": str(p.file_b).replace("\\", "/"),
            "has_source_b": str(p.file_b).replace("\\", "/") in source_index,
            "line_b":      p.line_b,
            "similarity":  p.similarity,
            "is_dead_a":   p.is_dead_a,
            "is_dead_b":   p.is_dead_b,
        }
        for p in model.clone_pairs
    ][:50]

    # --- Change coupling -----------------------------------------------------------------
    coupling_pair_rows = [
        {
            "file_a":     p.file_a.name,
            "file_b":     p.file_b.name,
            "co_changes": p.co_changes,
            "coupling":   p.coupling,
            "cross_layer": p.cross_layer,
            "surprising":  p.surprising,
        }
        for p in model.change_coupling
    ][:30]

    # --- Architecture-level change coupling (rolled up from change_coupling by layer) ---
    layer_coupling_rows = [
        {
            "layer_a": lp.layer_a, "layer_b": lp.layer_b,
            "file_pair_count": lp.file_pair_count, "total_co_changes": lp.total_co_changes,
            "avg_coupling": lp.avg_coupling, "surprising_pair_count": lp.surprising_pair_count,
        }
        for lp in model.layer_coupling
    ][:30]

    # --- Churn heatmap, rendered as an HTML/CSS grid (not an image -- keeps the report
    #     a single self-contained file with no sibling PNGs required) -------------------
    churn_heatmap_grid = None
    if model.churn_heatmap:
        totals: dict = {}
        for cell in model.churn_heatmap:
            totals[cell.file] = totals.get(cell.file, 0) + cell.commit_count
        top_files = sorted(totals, key=lambda f: totals[f], reverse=True)[:config.output.top_n]
        bin_labels = sorted({c.bin_label for c in model.churn_heatmap})
        by_key = {(c.file, c.bin_label): c.commit_count for c in model.churn_heatmap}
        max_count = max((v for v in by_key.values()), default=1)
        grid_rows = []
        for f in top_files:
            cells = []
            for b in bin_labels:
                count = by_key.get((f, b), 0)
                intensity = round(count / max_count, 2) if max_count else 0
                cells.append({"count": count, "intensity": intensity})
            grid_rows.append({"file": f.name, "cells": cells})
        churn_heatmap_grid = {"bin_labels": bin_labels, "rows": grid_rows}

    # --- Change-coupling matrix heatmap, rendered as an HTML/CSS grid (same
    #     pattern as churn_heatmap_grid above) -- top-N files by total coupling,
    #     symmetric matrix, intensity 0-1. Previously only reachable as
    #     change_coupling_heatmap.png in plots.py, which this report never
    #     linked to. -------------------------------------------------------
    coupling_heatmap_grid = None
    if model.change_coupling:
        totals: dict = {}
        for p in model.change_coupling:
            totals[p.file_a] = totals.get(p.file_a, 0.0) + p.coupling
            totals[p.file_b] = totals.get(p.file_b, 0.0) + p.coupling
        top_files = sorted(totals, key=lambda f: totals[f], reverse=True)[:config.output.top_n]
        top_set = set(top_files)
        by_pair = {}
        for p in model.change_coupling:
            if p.file_a in top_set and p.file_b in top_set:
                by_pair[(p.file_a, p.file_b)] = p.coupling
                by_pair[(p.file_b, p.file_a)] = p.coupling
        grid_rows = []
        for fa in top_files:
            cells = []
            for fb in top_files:
                coupling = 0.0 if fa == fb else by_pair.get((fa, fb), 0.0)
                cells.append({"intensity": round(coupling, 2), "pct": round(coupling * 100)})
            grid_rows.append({"file": fa.name, "cells": cells})
        coupling_heatmap_grid = {
            "files": [f.name for f in top_files],
            "rows": grid_rows,
        }

    # --- Commit activity calendar (whole codebase, not per file) -- rendered as an
    #     HTML/CSS grid for the same reason as churn_heatmap_grid: keeps the report a
    #     single self-contained file with no sibling PNGs required. Capped to the most
    #     recent 53 weeks (~1 year, GitHub contribution-graph convention); full daily
    #     data is in commit_activity.csv regardless of this cap. ------------------------
    commit_activity_grid = None
    if model.commit_activity:
        from datetime import date as _date, timedelta as _timedelta
        counts = {_date.fromisoformat(c.date): c.commit_count for c in model.commit_activity}
        last_day = max(counts)
        first_day = last_day - _timedelta(weeks=52)
        first_day -= _timedelta(days=first_day.weekday())  # snap back to a Monday
        n_weeks = (last_day - first_day).days // 7 + 1
        max_count = max(counts.values(), default=1)

        week_cols = []
        for w in range(n_weeks):
            week_start = first_day + _timedelta(weeks=w)
            days = []
            for wd in range(7):
                d = week_start + _timedelta(days=wd)
                count = counts.get(d, 0) if first_day <= d <= last_day else None
                intensity = round(count / max_count, 2) if count else 0
                days.append({"date": d.isoformat(), "count": count, "intensity": intensity})
            week_cols.append(days)
        month_labels = []
        seen_months = set()
        for w in range(n_weeks):
            d = first_day + _timedelta(weeks=w)
            key = (d.year, d.month)
            month_labels.append(d.strftime("%b") if key not in seen_months else "")
            seen_months.add(key)
        commit_activity_grid = {
            "week_cols": week_cols, "month_labels": month_labels,
            "first_day": first_day.isoformat(), "last_day": last_day.isoformat(),
            "total_commits": sum(counts.values()),
        }

    # --- Tech debt: TODO/FIXME/HACK/XXX markers -----------------------------------------
    todo_rows = [
        {
            "tag":        t.tag,
            "file_short": t.file.name,
            "file_path":  str(t.file).replace("\\", "/"),
            "has_source": str(t.file).replace("\\", "/") in source_index,
            "line":       t.line,
            "text":       t.text,
        }
        for t in model.todo_markers
    ][:100]

    # --- Tech debt: commented-out code ---------------------------------------------------
    commented_code_rows = [
        {
            "file_short": b.file.name,
            "file_path":  str(b.file).replace("\\", "/"),
            "has_source": str(b.file).replace("\\", "/") in source_index,
            "start_line": b.start_line,
            "end_line":   b.end_line,
            "line_count": b.line_count,
        }
        for b in model.commented_code_blocks
    ][:50]

    # --- Tech debt: preprocessor complexity (module-level) -------------------------------
    preprocessor_rows = [
        {
            "file_short": m.path.name,
            "depth":      m.max_ifdef_depth,
            "directives": m.ifdef_directive_count,
            "flags":      m.distinct_feature_flags,
        }
        for m in sorted(
            [m for m in fp_modules if m.max_ifdef_depth > 0],
            key=lambda m: (m.max_ifdef_depth, m.distinct_feature_flags), reverse=True,
        )
    ][:30]

    # --- ISR / main-loop shared-variable race risk ---------------------------------------
    race_risk_rows = []
    for g in model.globals:
        if not g.volatile_risk:
            continue
        isr_side = sorted(set(g.isr_readers) | set(g.isr_writers))
        main_side = sorted((set(g.readers) | set(g.writers)) - set(isr_side))
        race_risk_rows.append({
            "name":       g.name,
            "file_short": g.file.name,
            "isr_side":   isr_side,
            "main_side":  main_side,
        })

    meta["hotspot_count"] = len(hotspot_rows)
    meta["bugfix_hotspot_count"] = len(bugfix_hotspot_rows)
    meta["ownership_risk_count"] = len(ownership_rows)
    meta["complexity_trend_count"] = len(complexity_trend_rows)
    meta["clone_pair_count"] = len(clone_rows)
    meta["change_coupling_count"] = len(coupling_pair_rows)
    meta["layer_coupling_count"] = len(layer_coupling_rows)
    meta["todo_count"] = len(model.todo_markers)
    meta["commented_code_count"] = len(model.commented_code_blocks)
    meta["race_risk_count"] = len(race_risk_rows)

    architecture_svg = generate_architecture_svg_inline(model, config, source_index=source_index)

    # --- RTOS tasks & synchronisation -----------------------------------------------------
    rtos_task_rows = [
        {
            "name": t.name,
            "tcb_var": t.tcb_var,
            "priority_value": t.priority_value,
            "priority_expr": t.priority_expr,
            "entry_function": t.entry_function,
            "has_source": str(t.file).replace("\\", "/") in source_index,
            "file_path": str(t.file).replace("\\", "/"),
            "line": t.line,
            "stack_expr": t.stack_expr,
            "stack_size_value": t.stack_size_value,
            "stack_size_expr": t.stack_size_expr,
        }
        for t in sorted(
            model.rtos_tasks,
            key=lambda x: (x.priority_value is None, -(x.priority_value if x.priority_value is not None else 0)),
        )
    ]
    rtos_object_rows = [
        {"var_name": o.var_name, "kind": o.kind, "file_short": o.file.name,
         "unused": o.var_name in {u.var_name for u in model.rtos_unused_objects}}
        for o in model.rtos_sync_objects
    ]
    rtos_collision_rows = [
        {"priority_value": c.priority_value, "task_names": c.task_names}
        for c in model.rtos_priority_collisions
    ]
    rtos_inversion_rows = [
        {"object_var": r.object_var,
         "pairs": list(zip(r.task_names, [p if p is not None else "?" for p in r.priorities]))}
        for r in model.rtos_inversion_risks
    ]
    rtos_object_graph_svg = generate_rtos_object_graph_svg_inline(model) if model.rtos_kind != "none" else None

    meta["rtos_kind"] = model.rtos_kind
    meta["output_top_n"] = config.output.top_n

    # Parse diagnostics -- across all modules (not just first-party), so an
    # SDK/third-party header issue dragging down a first-party file's parse is
    # visible too.
    diag_modules = [m for m in model.modules if m.parse_diagnostics]
    meta["diag_module_count"] = len(diag_modules)
    meta["diag_fatal_count"] = sum(1 for m in diag_modules for d in m.parse_diagnostics if d["severity"] == "fatal")
    meta["diag_error_count"] = sum(1 for m in diag_modules for d in m.parse_diagnostics if d["severity"] == "error")
    meta["diag_warning_count"] = sum(1 for m in diag_modules for d in m.parse_diagnostics if d["severity"] == "warning")

    # Overview pane: errors/fatals only, capped -- warnings are numerous and rarely
    # block trusting a file's results the way an error does, so they'd otherwise
    # dominate the first thing anyone sees. Full detail (including every warning)
    # lives in the dedicated Parse Diagnostics tab below, not hidden, just not
    # first thing on the page.
    error_diag_modules = [
        m for m in diag_modules
        if any(d["severity"] in ("fatal", "error") for d in m.parse_diagnostics)
    ]
    meta["diag_error_module_count"] = len(error_diag_modules)
    diagnostic_rows = []
    for m in sorted(error_diag_modules, key=lambda m: -len(m.parse_diagnostics))[:20]:
        worst = next(d for d in m.parse_diagnostics if d["severity"] in ("fatal", "error"))
        diagnostic_rows.append({
            "file_short": m.path.name,
            "severity": worst["severity"],
            "line": worst["line"],
            "message": worst["message"][:120],
            "extra_count": len(m.parse_diagnostics) - 1,
        })

    # Parse Diagnostics tab: every file with any diagnostic (fatal/error/warning),
    # uncapped, one row per file with its full diagnostic list attached for
    # click-to-expand -- same interaction pattern as the Deepest Include Chains
    # table. Worst-severity files first (fatal > error > warning), then by count.
    _SEV_RANK = {"fatal": 0, "error": 1, "warning": 2}

    def _module_sev_rank(m):
        return min(_SEV_RANK.get(d["severity"], 3) for d in m.parse_diagnostics)

    all_diagnostic_rows = []
    for m in sorted(diag_modules, key=lambda m: (_module_sev_rank(m), -len(m.parse_diagnostics))):
        worst = m.parse_diagnostics[0]
        all_diagnostic_rows.append({
            "file_short": m.path.name,
            "file_path": str(m.path).replace("\\", "/"),
            "has_source": str(m.path).replace("\\", "/") in source_index,
            "severity": worst["severity"],
            "line": worst["line"],
            "message": worst["message"][:160],
            "extra_count": len(m.parse_diagnostics) - 1,
            "all": [
                {"severity": d["severity"], "line": d["line"], "message": d["message"][:200]}
                for d in m.parse_diagnostics
            ],
        })
    meta["rtos_task_count"] = len(rtos_task_rows)
    meta["rtos_collision_count"] = len(rtos_collision_rows)
    meta["rtos_inversion_count"] = len(rtos_inversion_rows)
    meta["rtos_unused_count"] = len(model.rtos_unused_objects)

    # --- State machines --------------------------------------------------------------------
    state_machine_entries = []
    for sm in model.state_machines[:20]:
        state_machine_entries.append({
            "function_name": sm.function_name,
            "file_short": sm.file.name,
            "file_path": str(sm.file).replace("\\", "/"),
            "has_source": str(sm.file).replace("\\", "/") in source_index,
            "line": sm.line,
            "state_var": sm.state_var,
            "state_count": len(sm.states),
            "transition_count": len(sm.transitions),
            "svg": generate_state_machine_svg_inline(sm),
        })
    meta["state_machine_count"] = len(model.state_machines)
    meta["state_machine_shown"] = len(state_machine_entries)

    env = Environment(loader=BaseLoader())
    tmpl = env.from_string(_TEMPLATE)
    html = tmpl.render(
        meta=meta,
        functions=func_rows,
        modules=module_rows,
        arch_violations=arch_rows,
        scatter_data=scatter_data,
        distributions=_build_distributions(model, config),
        breach_rows=breach_rows,
        dead_funcs=dead_rows,
        isr_risks=isr_rows,
        exceedances=model.exceedance_probabilities,
        high_coupling=high_coupling_rows,
        low_cohesion=low_cohesion_rows,
        high_coupling_low_cohesion=high_coupling_low_cohesion_rows,
        thresholds=t,
        group_dir_mismatches=group_dir_rows,
        magic_funcs=magic_rows,
        dispatch_tables=dispatch_table_rows,
        critical_funcs=critical_rows,
        assert_gap_funcs=assert_gap_rows,
        assert_coverage=assert_coverage,
        assert_total=assert_total,
        stack_rows=stack_rows,
        stack_stats=stack_stats,
        global_coupling=global_coupling_rows,
        dead_by_layer=dead_by_layer,
        reliability=reliability,
        effort=effort,
        cost_benefit=cost_benefit,
        defect_correlations=defect_correlations,
        information_flow_rows=information_flow_rows,
        hotspot_rows=hotspot_rows,
        bugfix_hotspot_rows=bugfix_hotspot_rows,
        ownership_rows=ownership_rows,
        complexity_trend_rows=complexity_trend_rows,
        composite_risk_rows=composite_risk_rows,
        clone_rows=clone_rows,
        coupling_pair_rows=coupling_pair_rows,
        layer_coupling_rows=layer_coupling_rows,
        churn_heatmap_grid=churn_heatmap_grid,
        coupling_heatmap_grid=coupling_heatmap_grid,
        correlation_heatmap_data=correlation_heatmap_data,
        include_cycles=include_cycle_rows,
        self_includes=self_include_rows,
        missing_include_guards=missing_guard_rows,
        deep_include_chains=deep_include_rows,
        unused_includes=unused_include_rows,
        commit_activity_grid=commit_activity_grid,
        todo_rows=todo_rows,
        commented_code_rows=commented_code_rows,
        preprocessor_rows=preprocessor_rows,
        race_risk_rows=race_risk_rows,
        architecture_svg=architecture_svg,
        rtos_task_rows=rtos_task_rows,
        rtos_object_rows=rtos_object_rows,
        rtos_collision_rows=rtos_collision_rows,
        rtos_inversion_rows=rtos_inversion_rows,
        rtos_object_graph_svg=rtos_object_graph_svg,
        state_machine_entries=state_machine_entries,
        diagnostic_rows=diagnostic_rows,
        source_index_compressed_b64=source_index_compressed_b64,
        source_index_uncompressed_len=source_index_uncompressed_len,
        tinyinflate_js=tinyinflate_js,
    )

    reports_dir = config.output.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "fwlens_report.html"
    report_path.write_text(html, encoding="utf-8")
    return report_path