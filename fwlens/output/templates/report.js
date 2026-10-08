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
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.remove('active');
    t.setAttribute('aria-selected', 'false');
    t.tabIndex = -1;
  });
  document.getElementById('pane-' + name).classList.add('active');
  el.classList.add('active');
  el.setAttribute('aria-selected', 'true');
  el.tabIndex = 0;
  if (name === 'architecture') drawScatter();
  if (name === 'distributions') drawDensityHeatmaps();
  buildSideNav();
  focusScrollRegions();
}

// Arrow keys, Home and End move between tabs (WAI-ARIA tabs pattern).
document.querySelector('.tabs').addEventListener('keydown', e => {
  const tabs = [...document.querySelectorAll('.tab')];
  const i = tabs.indexOf(document.activeElement);
  if (i < 0) return;
  let next = null;
  if (e.key === 'ArrowRight') next = tabs[(i + 1) % tabs.length];
  else if (e.key === 'ArrowLeft') next = tabs[(i - 1 + tabs.length) % tabs.length];
  else if (e.key === 'Home') next = tabs[0];
  else if (e.key === 'End') next = tabs[tabs.length - 1];
  if (next) { e.preventDefault(); next.focus(); next.click(); }
});

// A region that scrolls must be reachable by keyboard, or its overflow cannot be read.
function focusScrollRegions() {
  document.querySelectorAll('.pane.active table, .pane.active .metric-info-body, .tabs').forEach(el => {
    if (el.matches('.tabs')) return;   // its tab buttons are focusable already
    const scrolls = el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1;
    if (scrolls) { el.tabIndex = 0; } else if (el.getAttribute('tabindex') === '0') { el.removeAttribute('tabindex'); }
  });
}
window.addEventListener('resize', focusScrollRegions);

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
  focusScrollRegions();
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
const scatterData = FWLENS_DATA.scatter;

// Vendored tiny-inflate (MIT licensed, ~3KB -- see vendor/tinyinflate.LICENSE) --
// decompresses the embedded source index below. Used instead of a full gzip/zlib-in-JS
// library to keep this report a single self-contained file with minimal added weight.

// The source index (every first-party file's lines, keyed by path) is embedded
// compressed -- real C source compresses ~85-90% with raw deflate, which matters a
// lot once a codebase reaches hundreds of files, since embedded source text is by far
// the largest contributor to this file's size. Decompressed once, synchronously, here
// at load -- before any click handler (showFn) can reach it.
let sourceIndex = {};
try {
  const _b64 = FWLENS_DATA.sourceB64;
  const _bin = atob(_b64);
  const _compressed = new Uint8Array(_bin.length);
  for (let i = 0; i < _bin.length; i++) _compressed[i] = _bin.charCodeAt(i);
  const _output = new Uint8Array(FWLENS_DATA.sourceLen);
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
  const data = FWLENS_DATA.correlation;
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
    const mx = (e.clientX - rect.left) * (W / rect.width), my = (e.clientY - rect.top) * (H / rect.height);
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
