"use strict";

const COLUMNS = [
  { key: "ip_port", label: "IP / PORT", width: 170 },
  { key: "motd", label: "MOTD", width: 260 },
  { key: "players", label: "PLAYERS", width: 90 },
  { key: "version", label: "VERSION", width: 120 },
  { key: "cracked", label: "CRACKED", width: 75 },
  { key: "whitelist", label: "WHITELIST", width: 180 },
  { key: "online_names", label: "ONLINE NAMES", width: 200 },
  { key: "seen_names", label: "SEEN NAMES", width: 200 },
  { key: "first_seen", label: "FIRST SEEN", width: 165 },
  { key: "last_seen", label: "LAST SEEN", width: 165 },
  { key: "times_seen", label: "TIMES SEEN", width: 90 },
];

const COLUMN_KEYS = COLUMNS.map((column) => column.key);
const ROW_HEIGHT = 22;
const SEARCH_DELAY = 300;
const DEFAULT_HISTORY_WINDOW = 48 * 3600;

const HELP = `Select a row to see its full record.

SEARCH
anarchy
  anywhere in ip, motd, version,
  whitelist and player names
motd:"anarchy server"
  field contains text
ip:1.2.3.
  IP / port prefix
version~1.21   cracked=yes
players>=10    max<100
seen<7d        first>30d
  time windows use s/m/h/d/w
names:Notch
  player seen on the server
-motd:test
  exclude a term
times>3 players:0
  terms combine with AND`;

const searchInput = document.getElementById("search");
const copyBtn = document.getElementById("copyBtn");
const refreshBtn = document.getElementById("refreshBtn");
const statusEl = document.getElementById("status");
const gridScroll = document.getElementById("gridScroll");
const grid = document.getElementById("grid");
const headerRow = document.getElementById("headerRow");
const bodyEl = document.getElementById("body");
const rowsEl = document.getElementById("rows");
const detailEl = document.getElementById("detail");
const detailPane = document.querySelector(".detailPane");
const historyEl = document.getElementById("history");
const serverTitle = document.getElementById("serverTitle");
const playerTitle = document.getElementById("playerTitle");
const serverChart = document.getElementById("serverChart");
const playerChart = document.getElementById("playerChart");
const historyEmpty = document.getElementById("historyEmpty");
const historyTip = document.getElementById("historyTip");
const resetZoomBtn = document.getElementById("resetZoomBtn");

const CHART_COLORS = [
  "#6fa8dc", "#93c47d", "#e6b85c", "#e07b8f", "#b4a7d6",
  "#76a5af", "#f0a35e", "#c3d36c", "#d98cc4", "#8fb8e8",
];

let core = null;
let mc = null;
let rowCount = 0;
let totalCount = 0;
let sortStack = [];
let selected = new Set();
let anchorRow = -1;
let searchTimer = null;
let renderPending = false;
let refreshing = false;
let historyData = null;
let serverGeom = null;
let playerGeom = null;
let lastHistoryWidth = 0;
let chartViewStart = 0;
let chartViewEnd = 0;
let chartZoomed = false;
let chartDrag = null;
let chartRenderPending = false;

// ------------------------------------------------------------------ helpers

function setStatus(text) {
  statusEl.textContent = text;
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

function assetUrl(path) {
  return new URL(path, document.baseURI).href;
}

function loadScript(path) {
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = assetUrl(path);
    script.onload = () => resolve();
    script.onerror = () => reject(new Error(`could not load ${src}`));
    document.head.appendChild(script);
  });
}

function sortLabel(key) {
  return {
    ip_port: "ip",
    last_seen: "last seen",
    first_seen: "first seen",
    times_seen: "times seen",
    online_names: "online names",
    seen_names: "seen names",
  }[key] || key;
}

function sortSpec() {
  return sortStack
    .map((item) => `${item.key}:${item.desc ? "desc" : "asc"}`)
    .join(",");
}

function sortStackLabel() {
  return sortStack
    .slice()
    .reverse()
    .map((item) => `${sortLabel(item.key)} ${item.desc ? "▼" : "▲"}`)
    .join(", ");
}

const WIDTH_KEY = "mc-webui.column-widths";

function loadWidths() {
  try {
    const saved = JSON.parse(localStorage.getItem(WIDTH_KEY) || "null");
    if (!Array.isArray(saved) || saved.length !== COLUMNS.length) {
      return;
    }
    for (let i = 0; i < COLUMNS.length; i += 1) {
      const width = Number(saved[i]);
      if (Number.isFinite(width)) {
        COLUMNS[i].width = Math.max(40, Math.min(1200, Math.round(width)));
      }
    }
  } catch (error) {
    // Ignore unreadable/corrupt saved widths.
  }
}

function saveWidths() {
  try {
    localStorage.setItem(
      WIDTH_KEY,
      JSON.stringify(COLUMNS.map((column) => column.width)),
    );
  } catch (error) {
    // Storage can be disabled; resizing still works for this page.
  }
}

function setColumns() {
  const spec = COLUMNS.map((column) => `${column.width}px`).join(" ");
  grid.style.setProperty("--cols", spec);
  grid.style.width = `${COLUMNS.reduce((sum, column) => sum + column.width, 0)}px`;
}

function relayout() {
  bodyEl.style.height = `${rowCount * ROW_HEIGHT}px`;
}

function showDetail(row) {
  if (row < 0 || row >= rowCount) {
    detailEl.textContent = HELP;
    hideHistory();
    return;
  }
  detailEl.textContent = mc.detail(row);
  showHistory(row);
}

function showHelp() {
  detailEl.textContent = HELP;
  hideHistory();
}

// ------------------------------------------------------------ history charts

function hideHistory() {
  historyEl.hidden = true;
  historyTip.hidden = true;
  serverGeom = null;
  playerGeom = null;
  historyData = null;
  chartViewStart = 0;
  chartViewEnd = 0;
  chartZoomed = false;
  chartDrag = null;
  resetZoomBtn.hidden = true;
}

function chartTime(epoch) {
  if (!epoch || epoch <= 0) {
    return "-";
  }
  const d = new Date(epoch * 1000);
  let hours = d.getHours();
  const suffix = hours >= 12 ? "PM" : "AM";
  hours %= 12;
  if (hours === 0) {
    hours = 12;
  }
  const minutes = String(d.getMinutes()).padStart(2, "0");
  return `${d.getMonth() + 1}/${d.getDate()} ${hours}:${minutes} ${suffix}`;
}

function historyRange(points, players) {
  let lo = 0;
  let hi = 0;
  for (const point of points) {
    const t = Number(point.t) || 0;
    if (t <= 0) {
      continue;
    }
    if (!lo || t < lo) {
      lo = t;
    }
    if (t > hi) {
      hi = t;
    }
  }
  if (!lo) {
    for (const player of players) {
      for (const raw of player.times || []) {
        const t = Number(raw) || 0;
        if (t <= 0) {
          continue;
        }
        if (!lo || t < lo) {
          lo = t;
        }
        if (t > hi) {
          hi = t;
        }
      }
    }
  }
  if (!lo) {
    return [0, 0];
  }
  if (hi <= lo) {
    hi = lo + 3600;
  }
  return [lo, hi];
}

function fullChartRange() {
  return historyRange((historyData && historyData.points) || [],
                      (historyData && historyData.players) || []);
}

function defaultChartRange() {
  const full = fullChartRange();
  if (!full[0] && !full[1]) {
    return full;
  }
  return [Math.max(full[0], full[1] - DEFAULT_HISTORY_WINDOW), full[1]];
}

function resetChartViewToDefault() {
  const full = fullChartRange();
  const view = defaultChartRange();
  chartViewStart = view[0];
  chartViewEnd = view[1];
  chartZoomed = view[0] > full[0] + 0.001 || view[1] < full[1] - 0.001;
  renderHistory();
}

function currentChartRange() {
  const full = fullChartRange();
  let start = chartViewStart;
  let end = chartViewEnd;
  if (!start || !end || end <= start) {
    return full;
  }
  if (start < full[0]) {
    start = full[0];
  }
  if (end > full[1]) {
    end = full[1];
  }
  if (end <= start) {
    return full;
  }
  return [start, end];
}

function scheduleChartRender() {
  if (chartRenderPending) {
    return;
  }
  chartRenderPending = true;
  requestAnimationFrame(() => {
    chartRenderPending = false;
    renderHistory();
  });
}

function setChartView(start, end) {
  const full = fullChartRange();
  if (!full[0] && !full[1]) {
    return;
  }
  let span = Math.max(0.001, end - start);
  const fullSpan = Math.max(0.001, full[1] - full[0]);
  if (span >= fullSpan * 0.999) {
    chartViewStart = full[0];
    chartViewEnd = full[1];
    chartZoomed = false;
  } else {
    if (start < full[0]) {
      start = full[0];
      end = start + span;
    }
    if (end > full[1]) {
      end = full[1];
      start = end - span;
    }
    if (start < full[0]) {
      start = full[0];
      end = start + span;
    }
    chartViewStart = start;
    chartViewEnd = end;
    chartZoomed = true;
  }
  scheduleChartRender();
}

function resetChartView() {
  const full = fullChartRange();
  chartViewStart = full[0];
  chartViewEnd = full[1];
  chartZoomed = false;
  renderHistory();
}

function zoomChartAt(deltaY, x, width, left, right) {
  const full = fullChartRange();
  if ((!full[0] && !full[1]) || !deltaY) {
    return;
  }
  const view = currentChartRange();
  const plot = Math.max(1, width - left - right);
  const fraction = Math.max(0, Math.min(1, (x - left) / plot));
  const span = Math.max(0.001, view[1] - view[0]);
  const fullSpan = Math.max(0.001, full[1] - full[0]);
  const steps = Math.max(0.1, Math.min(4, Math.abs(deltaY) / 120));
  const factor = deltaY < 0 ? Math.pow(0.5, steps) : Math.pow(2.0, steps);
  const minSpan = Math.min(fullSpan, 0.5);
  let newSpan = span * factor;
  newSpan = Math.max(minSpan, Math.min(fullSpan, newSpan));
  const anchor = view[0] + fraction * span;
  const newStart = anchor - fraction * newSpan;
  setChartView(newStart, newStart + newSpan);
}

function panChartPixels(dx, width, left, right) {
  if (!chartZoomed) {
    return;
  }
  const view = currentChartRange();
  const span = Math.max(0.001, view[1] - view[0]);
  const plot = Math.max(1, width - left - right);
  const delta = (-dx / plot) * span;
  setChartView(view[0] + delta, view[1] + delta);
}

function chartSetup(canvas, height) {
  const dpr = window.devicePixelRatio || 1;
  const width = Math.max(80, canvas.clientWidth || 320);
  canvas.style.height = `${height}px`;
  canvas.width = Math.round(width * dpr);
  canvas.height = Math.round(height * dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);
  const style = getComputedStyle(canvas);
  return {
    ctx,
    w: width,
    h: height,
    text: style.color || "#cccccc",
  };
}

function peakPlayers(points) {
  let peak = 1;
  let counted = false;
  for (const point of points) {
    if (point.p !== null && point.p !== undefined) {
      peak = Math.max(peak, Number(point.p) || 0);
      counted = true;
    }
  }
  if (!counted) {
    // Backfilled rows have no observed count; use capacity for scale.
    for (const point of points) {
      if (point.m !== null && point.m !== undefined) {
        peak = Math.max(peak, Number(point.m) || 0);
      }
    }
  }
  return Math.max(1, peak);
}

function drawServerChart(points) {
  const { ctx, w, h, text } = chartSetup(serverChart, 150);
  if (!points.length) {
    serverGeom = null;
    return;
  }
  const left = 40;
  const right = 8;
  const top = 10;
  const bottom = 22;
  const pw = Math.max(1, w - left - right);
  const ph = Math.max(1, h - top - bottom);
  const [t0, t1] = currentChartRange();
  const span = Math.max(1, t1 - t0);
  const globalPeak = peakPlayers(points);
  let peak = 1;
  let counted = 0;
  let visible = 0;
  for (const point of points) {
    const t = Number(point.t) || 0;
    if (t < t0 || t > t1) {
      continue;
    }
    visible += 1;
    if (point.p !== null && point.p !== undefined) {
      peak = Math.max(peak, Number(point.p) || 0);
      counted += 1;
    }
  }
  if (!counted) {
    for (const point of points) {
      const t = Number(point.t) || 0;
      if (t < t0 || t > t1) {
        continue;
      }
      if (point.m !== null && point.m !== undefined) {
        peak = Math.max(peak, Number(point.m) || 0);
      }
    }
  }
  if (!counted) {
    peak = Math.max(peak, globalPeak);
  }
  const mid = "rgba(128,128,128,0.4)";

  ctx.font = "11px ui-monospace, monospace";
  ctx.textBaseline = "middle";
  for (let g = 0; g <= 2; g += 1) {
    const value = Math.round((peak * g) / 2);
    const y = top + ph - (ph * g) / 2;
    ctx.strokeStyle = mid;
    ctx.globalAlpha = g === 0 ? 0.8 : 0.45;
    ctx.beginPath();
    ctx.moveTo(left, y + 0.5);
    ctx.lineTo(left + pw, y + 0.5);
    ctx.stroke();
    ctx.globalAlpha = 0.75;
    ctx.fillStyle = text;
    ctx.textAlign = "right";
    ctx.fillText(String(value), left - 5, y);
  }
  ctx.globalAlpha = 1;

  const xAt = (point) => left + (((Number(point.t) || t0) - t0) / span) * pw;

  ctx.save();
  ctx.beginPath();
  ctx.rect(left, top, pw, ph + 8);
  ctx.clip();

  let drawing = false;
  ctx.strokeStyle = CHART_COLORS[0];
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  for (const point of points) {
    if (point.p === null || point.p === undefined) {
      if (drawing) {
        ctx.stroke();
        drawing = false;
        ctx.beginPath();
      }
      continue;
    }
    const x = xAt(point);
    const y = top + ph - Math.min(1, (Number(point.p) || 0) / peak) * ph;
    if (!drawing) {
      ctx.moveTo(x, y);
      drawing = true;
    } else {
      ctx.lineTo(x, y);
    }
  }
  if (drawing) {
    ctx.stroke();
  }

  // Every sighting is a dot and a tick.  Drawing all of them matters when
  // zoomed in: the whole point is to see the dense rescans.
  ctx.fillStyle = CHART_COLORS[0];
  for (const point of points) {
    if (point.p === null || point.p === undefined) {
      continue;
    }
    const x = xAt(point);
    const y = top + ph - Math.min(1, (Number(point.p) || 0) / peak) * ph;
    ctx.beginPath();
    ctx.arc(x, y, 1.6, 0, Math.PI * 2);
    ctx.fill();
  }

  // Every sighting is marked below the player-count graph.
  ctx.strokeStyle = "#7aa6cc";
  ctx.globalAlpha = 0.8;
  ctx.lineWidth = 1;
  for (const point of points) {
    const x = xAt(point);
    ctx.beginPath();
    ctx.moveTo(x + 0.5, top + ph + 2);
    ctx.lineTo(x + 0.5, top + ph + 6);
    ctx.stroke();
  }
  ctx.globalAlpha = 1;
  ctx.restore();

  ctx.fillStyle = text;
  ctx.globalAlpha = 0.7;
  ctx.textAlign = "left";
  ctx.fillText(chartTime(t0), left, h - 9);
  ctx.textAlign = "right";
  ctx.fillText(chartTime(t1), left + pw, h - 9);
  ctx.globalAlpha = 1;
  if (!visible) {
    ctx.fillStyle = text;
    ctx.globalAlpha = 0.6;
    ctx.textAlign = "center";
    ctx.fillText("No sightings in this zoom window",
                 left + pw / 2, top + ph / 2);
    ctx.globalAlpha = 1;
  } else if (!counted) {
    ctx.fillStyle = text;
    ctx.globalAlpha = 0.6;
    ctx.textAlign = "center";
    ctx.fillText("No player counts recorded for these sightings",
                 left + pw / 2, top + ph / 2);
    ctx.globalAlpha = 1;
  }

  serverGeom = { left, top, pw, ph, t0, span, points };
}

function drawPlayerChart(players) {
  const sorted = players.slice().sort((a, b) => {
    const at = (a.times || []).length;
    const bt = (b.times || []).length;
    return bt - at || String(a.name).localeCompare(String(b.name));
  });
  const maxRows = 10;
  const shown = Math.min(sorted.length, maxRows);
  const overflow = sorted.length - shown;
  const height = 24 + shown * 13 + (overflow ? 13 : 0);
  const { ctx, w, h, text } = chartSetup(playerChart, height);
  const left = 92;
  const right = 8;
  const top = 6;
  const rowHeight = 13;
  const pw = Math.max(1, w - left - right);
  const [t0, t1] = currentChartRange();
  const span = Math.max(1, t1 - t0);
  const mid = "rgba(128,128,128,0.35)";
  const rows = [];

  ctx.font = "11px ui-monospace, monospace";
  ctx.textBaseline = "middle";
  for (let r = 0; r < shown; r += 1) {
    const player = sorted[r];
    const centerY = top + rowHeight * r + rowHeight / 2;
    const color = CHART_COLORS[r % CHART_COLORS.length];

    ctx.strokeStyle = mid;
    ctx.beginPath();
    ctx.moveTo(left, centerY + 0.5);
    ctx.lineTo(left + pw, centerY + 0.5);
    ctx.stroke();

    let name = String(player.name || "");
    if (name.length > 13) {
      name = `${name.substring(0, 12)}…`;
    }
    ctx.fillStyle = text;
    ctx.globalAlpha = 0.9;
    ctx.textAlign = "left";
    ctx.fillText(name, 4, centerY);
    ctx.globalAlpha = 1;

    const times = (player.times || []).map(Number);
    const eventXs = times.map(
      (t) => left + (((t || t0) - t0) / span) * pw,
    );
    ctx.save();
    ctx.beginPath();
    ctx.rect(left, top, pw, h - top - 8);
    ctx.clip();
    ctx.fillStyle = color;
    for (let k = 0; k < times.length; k += 1) {
      const x = eventXs[k];
      ctx.beginPath();
      ctx.arc(x, centerY, 1.7, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.restore();
    rows.push({ player, centerY, times, xs: eventXs });
  }

  if (overflow > 0) {
    ctx.fillStyle = text;
    ctx.globalAlpha = 0.6;
    ctx.textAlign = "left";
    ctx.fillText(`+${overflow} more player(s)`, 4, top + rowHeight * shown + rowHeight / 2);
    ctx.globalAlpha = 1;
  }

  playerGeom = { left, pw, t0, span, rowHeight, rows };
}

function renderHistory() {
  if (!historyData) {
    return;
  }
  const points = historyData.points || [];
  const players = historyData.players || [];
  resetZoomBtn.hidden = !chartZoomed;
  if (!points.length && !players.length) {
    historyEl.hidden = false;
    serverTitle.hidden = true;
    serverChart.hidden = true;
    playerTitle.hidden = true;
    playerChart.hidden = true;
    historyEmpty.hidden = false;
    historyEmpty.textContent = "No sighting history recorded for this server.";
    hideTip();
    return;
  }

  historyEl.hidden = false;
  historyEmpty.hidden = true;

  if (points.length) {
    serverTitle.hidden = false;
    serverChart.hidden = false;
    const peak = peakPlayers(points);
    serverTitle.textContent = `SIGHTINGS ${points.length} • PEAK ${peak}` +
                              (chartZoomed ? " • ZOOMED" : "");
    drawServerChart(points);
  } else {
    serverTitle.hidden = true;
    serverChart.hidden = true;
    serverGeom = null;
  }

  if (players.length) {
    playerTitle.hidden = false;
    playerChart.hidden = false;
    playerTitle.textContent = `PLAYER ACTIVITY • ${players.length} SEEN` +
                              (chartZoomed ? " • ZOOMED" : "");
    drawPlayerChart(players);
  } else {
    playerTitle.hidden = true;
    playerChart.hidden = true;
    playerGeom = null;
  }
  hideTip();
}

function showHistory(row) {
  if (!mc || row < 0 || row >= rowCount) {
    hideHistory();
    return;
  }
  try {
    historyData = JSON.parse(mc.history(mc.ip(row)));
  } catch (error) {
    historyData = { points: [], players: [] };
  }
  if (!historyData || !Array.isArray(historyData.points)) {
    historyData = { points: [], players: [] };
  }
  if (!Array.isArray(historyData.players)) {
    historyData.players = [];
  }
  chartDrag = null;
  resetChartViewToDefault();
}

function hideTip() {
  historyTip.hidden = true;
}

function showTip(text, clientX, clientY) {
  historyTip.textContent = text;
  historyTip.hidden = false;
  const rect = historyEl.getBoundingClientRect();
  const x = Math.max(4, Math.min(rect.width - 12, clientX - rect.left + 10));
  historyTip.style.left = `${x}px`;
  historyTip.style.top = `${Math.max(4, clientY - rect.top - 22)}px`;
}

serverChart.addEventListener("mousemove", (event) => {
  if (chartDrag) {
    hideTip();
    return;
  }
  if (!serverGeom || !serverGeom.points.length) {
    hideTip();
    return;
  }
  const rect = serverChart.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const geom = serverGeom;
  if (x < geom.left || x > geom.left + geom.pw) {
    hideTip();
    return;
  }
  const target = geom.t0 + ((x - geom.left) / geom.pw) * geom.span;
  let best = null;
  let bestDistance = Infinity;
  for (const point of geom.points) {
    const distance = Math.abs((Number(point.t) || 0) - target);
    if (distance < bestDistance) {
      best = point;
      bestDistance = distance;
    }
  }
  if (!best) {
    hideTip();
    return;
  }
  const players = best.p === null || best.p === undefined
    ? "players unknown"
    : `${best.p} player${Number(best.p) === 1 ? "" : "s"}`;
  showTip(`${chartTime(best.t)} — ${players}`, event.clientX, event.clientY);
});

playerChart.addEventListener("mousemove", (event) => {
  if (chartDrag) {
    hideTip();
    return;
  }
  if (!playerGeom || !playerGeom.rows.length) {
    hideTip();
    return;
  }
  const rect = playerChart.getBoundingClientRect();
  const x = event.clientX - rect.left;
  const y = event.clientY - rect.top;
  if (x < playerGeom.left || x > playerGeom.left + playerGeom.pw) {
    hideTip();
    return;
  }
  const row = playerGeom.rows.find(
    (entry) => Math.abs(y - entry.centerY) <= playerGeom.rowHeight / 2,
  );
  if (!row || !row.times.length) {
    hideTip();
    return;
  }
  const target = playerGeom.t0 + ((x - playerGeom.left) / playerGeom.pw) *
                 playerGeom.span;
  let best = row.times[0];
  for (const time of row.times) {
    if (Math.abs(time - target) < Math.abs(best - target)) {
      best = time;
    }
  }
  showTip(`${row.player.name} — ${chartTime(best)}`,
          event.clientX, event.clientY);
});

serverChart.addEventListener("mouseleave", hideTip);
playerChart.addEventListener("mouseleave", hideTip);

function beginChartDrag(event, canvas, left, right) {
  if (event.pointerType === "mouse" && event.button !== 0) {
    return;
  }
  chartDrag = {
    pointerId: event.pointerId,
    lastX: event.clientX,
    canvas,
    left,
    right,
  };
  try {
    canvas.setPointerCapture(event.pointerId);
  } catch (error) {
    // Pointer capture is best-effort.
  }
  hideTip();
  event.preventDefault();
}

function moveChartDrag(event) {
  if (!chartDrag || event.pointerId !== chartDrag.pointerId) {
    return;
  }
  const dx = event.clientX - chartDrag.lastX;
  chartDrag.lastX = event.clientX;
  if (Math.abs(dx) >= 0.5) {
    panChartPixels(dx, chartDrag.canvas.clientWidth,
                   chartDrag.left, chartDrag.right);
  }
  event.preventDefault();
}

function endChartDrag(event) {
  if (!chartDrag || event.pointerId !== chartDrag.pointerId) {
    return;
  }
  try {
    chartDrag.canvas.releasePointerCapture(event.pointerId);
  } catch (error) {
    // Already released.
  }
  chartDrag = null;
}

function attachChartControls(canvas, left, right) {
  canvas.addEventListener("pointerdown", (event) => {
    beginChartDrag(event, canvas, left, right);
  });
  canvas.addEventListener("pointermove", moveChartDrag);
  canvas.addEventListener("pointerup", endChartDrag);
  canvas.addEventListener("pointercancel", endChartDrag);
  canvas.addEventListener("wheel", (event) => {
    event.preventDefault();
    const rect = canvas.getBoundingClientRect();
    zoomChartAt(event.deltaY, event.clientX - rect.left,
                canvas.clientWidth, left, right);
  }, { passive: false });
  canvas.addEventListener("dblclick", (event) => {
    event.preventDefault();
    resetChartView();
  });
}

attachChartControls(serverChart, 40, 8);
attachChartControls(playerChart, 92, 8);
resetZoomBtn.addEventListener("click", resetChartView);

new ResizeObserver((entries) => {
  const width = Math.round(entries[0].contentRect.width);
  if (width === lastHistoryWidth) {
    return;
  }
  lastHistoryWidth = width;
  if (historyData && !historyEl.hidden) {
    renderHistory();
  }
}).observe(detailPane);

// ------------------------------------------------------------------- table

function buildHeader() {
  headerRow.replaceChildren();
  for (let i = 0; i < COLUMNS.length; i += 1) {
    const column = COLUMNS[i];
    const cell = document.createElement("div");
    cell.className = "hcell";
    cell.dataset.key = column.key;
    cell.title = column.key;
    cell.addEventListener("click", () => sortByColumn(column.key));

    const label = document.createElement("span");
    label.className = "hlabel";
    cell.appendChild(label);

    const handle = document.createElement("span");
    handle.className = "resizer";
    handle.dataset.index = String(i);
    handle.title = "Drag to resize";
    handle.addEventListener("mousedown", beginResize);
    handle.addEventListener("click", (event) => event.stopPropagation());
    cell.appendChild(handle);

    headerRow.appendChild(cell);
  }
  updateHeader();
}

function beginResize(event) {
  if (event.button !== 0) {
    return;
  }
  event.preventDefault();
  event.stopPropagation();
  const index = Number(event.currentTarget.dataset.index);
  if (!Number.isInteger(index) || index < 0 || index >= COLUMNS.length) {
    return;
  }
  const startX = event.clientX;
  const startWidth = COLUMNS[index].width;
  document.body.classList.add("resizing");

  function move(moveEvent) {
    const width = Math.max(
      40,
      Math.min(1200, Math.round(startWidth + moveEvent.clientX - startX)),
    );
    if (COLUMNS[index].width !== width) {
      COLUMNS[index].width = width;
      setColumns();
    }
  }

  function finish() {
    window.removeEventListener("mousemove", move);
    window.removeEventListener("mouseup", finish);
    document.body.classList.remove("resizing");
    saveWidths();
  }

  window.addEventListener("mousemove", move);
  window.addEventListener("mouseup", finish);
}

function updateHeader() {
  const primary = sortStack.length ? sortStack[sortStack.length - 1].key : "";
  for (const cell of headerRow.children) {
    const key = cell.dataset.key;
    let text = COLUMNS.find((column) => column.key === key)?.label || key;
    if (key === primary) {
      text += sortStack[sortStack.length - 1].desc ? " ▼" : " ▲";
    }
    const label = cell.querySelector(".hlabel");
    if (label) {
      label.textContent = text;
    }
    cell.classList.toggle("active", key === primary);
  }
}

function renderRows() {
  if (!mc) {
    return;
  }
  const start = Math.max(0, Math.floor(gridScroll.scrollTop / ROW_HEIGHT) - 4);
  const visible = Math.ceil(gridScroll.clientHeight / ROW_HEIGHT) + 8;
  const end = Math.min(rowCount, start + visible);
  const fragment = document.createDocumentFragment();

  for (let row = start; row < end; row += 1) {
    const element = document.createElement("div");
    element.className = "row";
    if (row % 2 === 1) {
      element.classList.add("odd");
    }
    if (selected.has(row)) {
      element.classList.add("selected");
    }
    element.dataset.row = String(row);
    element.style.top = `${row * ROW_HEIGHT}px`;
    for (let column = 0; column < COLUMNS.length; column += 1) {
      const cell = document.createElement("div");
      cell.className = "cell";
      cell.textContent = mc.cell(row, column);
      element.appendChild(cell);
    }
    fragment.appendChild(element);
  }
  rowsEl.replaceChildren(fragment);
}

function scheduleRender() {
  if (renderPending) {
    return;
  }
  renderPending = true;
  requestAnimationFrame(() => {
    renderPending = false;
    renderRows();
  });
}

function resetView() {
  selected = new Set();
  anchorRow = -1;
  gridScroll.scrollTop = 0;
  showHelp();
  relayout();
  renderRows();
}

function selectRow(row, event) {
  if (row < 0 || row >= rowCount) {
    return;
  }
  if (event.shiftKey && anchorRow >= 0) {
    const first = Math.min(anchorRow, row);
    const last = Math.max(anchorRow, row);
    selected = new Set();
    for (let i = first; i <= last; i += 1) {
      selected.add(i);
    }
  } else if (event.ctrlKey || event.metaKey) {
    if (selected.has(row)) {
      selected.delete(row);
    } else {
      selected.add(row);
    }
    anchorRow = row;
  } else {
    selected = new Set([row]);
    anchorRow = row;
  }
  renderRows();
  if (selected.has(row)) {
    showDetail(row);
  } else {
    showHelp();
  }
}

rowsEl.addEventListener("mousedown", (event) => {
  const element = event.target.closest(".row");
  if (!element) {
    return;
  }
  event.preventDefault();
  // Tapping a row must not leave the search field focused; on mobile that
  // keeps the on-screen keyboard open over the table.
  if (document.activeElement && document.activeElement.blur) {
    document.activeElement.blur();
  }
  selectRow(Number(element.dataset.row), event);
});

gridScroll.addEventListener("scroll", scheduleRender, { passive: true });
new ResizeObserver(scheduleRender).observe(gridScroll);

// ------------------------------------------------------------- search/sort

function applySort() {
  if (!mc) {
    return;
  }
  const started = performance.now();
  if (sortStack.length) {
    const rc = mc.sort(sortSpec());
    if (rc < 0) {
      setStatus(`Sort error: ${mc.error()}`);
      return;
    }
  }
  updateHeader();
  setColumns();
  resetView();
  const millis = Math.round(performance.now() - started);
  setStatus(`${plural(rowCount, "row")} sorted by ${sortStackLabel()} in ${millis} ms`);
}

function sortByColumn(key) {
  const index = sortStack.findIndex((item) => item.key === key);
  let desc = false;
  if (index >= 0) {
    desc = !sortStack[index].desc;
    sortStack.splice(index, 1);
  }
  sortStack.push({ key, desc });
  applySort();
}

function applySearch(prefix = "") {
  if (!mc) {
    return;
  }
  const query = searchInput.value;
  const started = performance.now();
  const count = mc.apply(query);
  if (count < 0) {
    setStatus(`Search error: ${mc.error()}`);
    return;
  }
  rowCount = count;
  totalCount = mc.total();

  if (sortStack.length) {
    const sortStarted = performance.now();
    const rc = mc.sort(sortSpec());
    if (rc < 0) {
      setStatus(`Sort error: ${mc.error()}`);
      return;
    }
    const sortMs = Math.round(performance.now() - sortStarted);
    setStatus(`${prefix}${plural(rowCount, "row")} sorted by ${sortStackLabel()} in ${sortMs} ms`);
  } else {
    const millis = Math.round(performance.now() - started);
    setStatus(`${prefix}${rowCount} of ${totalCount} servers | loaded in ${millis} ms`);
  }
  updateHeader();
  setColumns();
  resetView();
}

searchInput.addEventListener("input", () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(applySearch, SEARCH_DELAY);
});

searchInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    clearTimeout(searchTimer);
    applySearch();
  }
});

// --------------------------------------------------------------- clipboard

function fallbackCopy(text) {
  const area = document.createElement("textarea");
  area.value = text;
  area.style.position = "fixed";
  area.style.left = "-1000px";
  document.body.appendChild(area);
  area.select();
  document.execCommand("copy");
  area.remove();
}

async function copyIps() {
  if (!mc) {
    return;
  }
  const rows = Array.from(selected).sort((a, b) => a - b);
  if (rows.length === 0) {
    setStatus("Select one or more server rows first.");
    return;
  }
  const text = rows.map((row) => mc.ip(row)).join("\n");
  try {
    await navigator.clipboard.writeText(text);
  } catch (error) {
    fallbackCopy(text);
  }
  setStatus(`Copied ${plural(rows.length, "IP")}.`);
}

copyBtn.addEventListener("click", copyIps);

// ----------------------------------------------------------------- database

async function decompressZstd(bytes) {
  // Prefer the browser's native (C/C++) zstd decoder. It is much faster
  // than any JS implementation; fzstd is only the compatibility fallback.
  if (typeof DecompressionStream === "function") {
    try {
      const stream = new Blob([bytes]).stream().pipeThrough(
        new DecompressionStream("zstd"));
      return new Uint8Array(await new Response(stream).arrayBuffer());
    } catch (error) {
      // Older browsers do not implement the zstd decompressor.
    }
  }
  if (typeof fzstd !== "undefined" && fzstd.decompress) {
    return fzstd.decompress(bytes);
  }
  throw new Error("no zstd decompressor available");
}

async function loadDatabase() {
  let compressed = false;
  try {
    setStatus("Loading compressed database…");
    const zst = await fetch(assetUrl(`servers.db.zst?ts=${Date.now()}`),
                            { cache: "no-store" });
    if (zst.ok && typeof fzstd !== "undefined" && fzstd.decompress) {
      const packed = new Uint8Array(await zst.arrayBuffer());
      const bytes = await decompressZstd(packed);
      core.FS.writeFile("/servers.db", bytes);
      try {
        core.FS.unlink("/servers.db-wal");
      } catch (error) {
        // No stale WAL to remove.
      }
      compressed = true;
    }
  } catch (error) {
    // A corrupt/missing .zst must not break the viewer; use the raw files.
    if (typeof console !== "undefined") {
      console.warn("compressed database unavailable:", error);
    }
  }
  if (!compressed) {
    setStatus("Loading database…");
    const response = await fetch(assetUrl(`servers.db?ts=${Date.now()}`),
                                 { cache: "no-store" });
    if (!response.ok) {
      const detail = (await response.text().catch(() => "")).trim();
      throw new Error(`HTTP ${response.status} loading servers.db${detail ? `: ${detail}` : ""}`);
    }
    const bytes = new Uint8Array(await response.arrayBuffer());
    core.FS.writeFile("/servers.db", bytes);

    // WAL mode keeps recent commits in servers.db-wal until a checkpoint.
    // Serve that existing file too; it is not a snapshot, just the live sidecar.
    const wal = await fetch(assetUrl(`servers.db-wal?ts=${Date.now()}`),
                            { cache: "no-store" });
    if (wal.ok) {
      core.FS.writeFile("/servers.db-wal", new Uint8Array(await wal.arrayBuffer()));
    } else {
      try {
        core.FS.unlink("/servers.db-wal");
      } catch (error) {
        // No stale WAL to remove.
      }
    }
  }

  if (mc.open("/servers.db") !== 0) {
    throw new Error(mc.error() || "could not open database");
  }
  const count = mc.apply("");
  if (count < 0) {
    throw new Error(mc.error() || "could not read database");
  }
  rowCount = count;
  totalCount = mc.total();
}

async function refreshDatabase() {
  if (refreshing || !core) {
    return;
  }
  refreshing = true;
  refreshBtn.disabled = true;
  refreshBtn.textContent = "Refreshing…";
  setStatus("Reloading servers.db…");
  try {
    await loadDatabase();
    applySearch("Reloaded: ");
  } catch (error) {
    setStatus(`Refresh failed: ${String(error)}`);
  } finally {
    refreshing = false;
    refreshBtn.disabled = false;
    refreshBtn.textContent = "Refresh";
  }
}

refreshBtn.addEventListener("click", refreshDatabase);

// -------------------------------------------------------------------- boot

document.addEventListener("keydown", (event) => {
  const key = event.key.toLowerCase();
  if ((event.ctrlKey || event.metaKey) && key === "f") {
    event.preventDefault();
    searchInput.focus();
    searchInput.select();
    return;
  }
  if (event.key === "Escape" && searchInput.value.length > 0) {
    searchInput.value = "";
    applySearch();
  }
});

async function boot() {
  try {
    setStatus("Starting WebAssembly…");
    if (typeof createCore !== "function") {
      // The script tag failed or was blocked; try once more explicitly.
      await loadScript("core.js?v=10-retry");
    }
    if (typeof createCore !== "function") {
      let detail = "";
      try {
        const probe = await fetch(assetUrl("core.js?v=10-probe"), { cache: "no-store" });
        const body = await probe.text();
        detail = ` — ${probe.status}, ${probe.headers.get("content-type") || "no content-type"}, ${body.length} bytes`;
      } catch (probeError) {
        detail = ` — ${String(probeError)}`;
      }
      throw new Error(
        `WebAssembly runtime failed to load (core.js${detail}). ` +
        "Make sure core.js is served as JavaScript with a 200 response.",
      );
    }
    core = await createCore({
      locateFile: (file) => assetUrl(file) + "?v=10",
      print: () => {},
      printErr: () => {},
    });
    mc = {
      open: core.cwrap("mc_open", "number", ["string"]),
      close: core.cwrap("mc_close", null, []),
      apply: core.cwrap("mc_apply", "number", ["string"]),
      sort: core.cwrap("mc_sort", "number", ["string"]),
      count: core.cwrap("mc_count", "number", []),
      total: core.cwrap("mc_total", "number", []),
      loadMs: core.cwrap("mc_load_ms", "number", []),
      error: core.cwrap("mc_error", "string", []),
      cell: core.cwrap("mc_cell", "string", ["number", "number"]),
      detail: core.cwrap("mc_detail", "string", ["number"]),
      history: core.cwrap("mc_history", "string", ["string"]),
      ip: core.cwrap("mc_ip", "string", ["number"]),
    };

    await loadDatabase();
    loadWidths();
    buildHeader();
    setColumns();
    relayout();
    showHelp();
    renderRows();
    setStatus(`${totalCount} servers | loaded in ${mc.loadMs()} ms`);
    // Only focus the search box on devices with a real pointer. Programmatic
    // focus on a phone can raise the keyboard before the user asks for it.
    if (window.matchMedia("(hover: hover) and (pointer: fine)").matches) {
      searchInput.focus();
    }
  } catch (error) {
    setStatus(`Load failed: ${String(error)}`);
    detailEl.textContent = `Could not load the database.\n\n${String(error)}`;
  }
}

boot();
