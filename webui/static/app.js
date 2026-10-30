"use strict";

const COLUMNS = [
  { key: "ip_port", label: "IP / PORT", width: 170 },
  { key: "motd", label: "MOTD", width: 260 },
  { key: "players", label: "PLAYERS", width: 110 },
  { key: "version", label: "VERSION", width: 120 },
  { key: "cracked", label: "CRACKED", width: 90 },
  { key: "whitelist", label: "WHITELIST", width: 180 },
  { key: "online_names", label: "ONLINE NAMES", width: 200 },
  { key: "seen_names", label: "SEEN NAMES", width: 200 },
  { key: "first_seen", label: "FIRST SEEN", width: 130 },
  { key: "last_seen", label: "LAST SEEN", width: 130 },
  { key: "times_seen", label: "TIMES SEEN", width: 90 },
];

const COLUMN_KEYS = COLUMNS.map((column) => column.key);
const ROW_HEIGHT = 22;
const SEARCH_DELAY = 300;

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
const searchBtn = document.getElementById("searchBtn");
const copyBtn = document.getElementById("copyBtn");
const refreshBtn = document.getElementById("refreshBtn");
const statusEl = document.getElementById("status");
const gridScroll = document.getElementById("gridScroll");
const grid = document.getElementById("grid");
const headerRow = document.getElementById("headerRow");
const bodyEl = document.getElementById("body");
const rowsEl = document.getElementById("rows");
const detailEl = document.getElementById("detail");

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

// ------------------------------------------------------------------ helpers

function setStatus(text) {
  statusEl.textContent = text;
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
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
    return;
  }
  detailEl.textContent = mc.detail(row);
}

function showHelp() {
  detailEl.textContent = HELP;
}

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
    headerRow.appendChild(cell);
  }
  updateHeader();
}

function updateHeader() {
  const primary = sortStack.length ? sortStack[sortStack.length - 1].key : "";
  for (const cell of headerRow.children) {
    const key = cell.dataset.key;
    let text = COLUMNS.find((column) => column.key === key)?.label || key;
    if (key === primary) {
      text += sortStack[sortStack.length - 1].desc ? " ▼" : " ▲";
    }
    cell.textContent = text;
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

searchBtn.addEventListener("click", () => {
  clearTimeout(searchTimer);
  applySearch();
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

async function loadDatabase() {
  setStatus("Loading database…");
  const response = await fetch(`/servers.db?ts=${Date.now()}`, { cache: "no-store" });
  if (!response.ok) {
    const detail = (await response.text().catch(() => "")).trim();
    throw new Error(`HTTP ${response.status} loading servers.db${detail ? `: ${detail}` : ""}`);
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  core.FS.writeFile("/servers.db", bytes);
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
    core = await createCore({
      locateFile: (file) => `/${file}`,
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
      ip: core.cwrap("mc_ip", "string", ["number"]),
    };

    const info = await fetch("/api/info", { cache: "no-store" })
      .then((response) => (response.ok ? response.json() : null))
      .catch(() => null);
    if (info && info.db_name) {
      document.title = `MC Server DB — ${info.db_name}`;
    }

    await loadDatabase();
    buildHeader();
    setColumns();
    relayout();
    showHelp();
    renderRows();
    setStatus(`${totalCount} servers | loaded in ${mc.loadMs()} ms`);
    searchInput.focus();
  } catch (error) {
    setStatus(`Load failed: ${String(error)}`);
    detailEl.textContent = `Could not load the database.\n\n${String(error)}`;
  }
}

boot();
