/**
 * Cybersecurity Incident Intelligence Dashboard — Application Logic
 * FULLY DYNAMIC: all charts re-aggregate from filtered incident data in real time
 */

// ─── Global State ───────────────────────────────────────────────────────────
let DATA = null;
let CHARTS = {};
let TABLE_STATE = {
  data: [],
  filtered: [],
  page: 0,
  pageSize: 25,
  sortCol: 'year',
  sortDir: 'desc',
  search: '',
};
let _refreshTimer = null;
let GLOBE = null;
let SELECTED_GLOBE_COUNTRY = 'India';

const DISGUISED = ['Not available', 'Unknown', 'Not attributed', '', 'nan', 'None'];

// ─── Chart.js Global Config ─────────────────────────────────────────────────
Chart.defaults.color = '#94a3b8';
Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';
Chart.defaults.font.family = "'Inter', sans-serif";
Chart.defaults.font.size = 12;
Chart.defaults.plugins.legend.labels.usePointStyle = true;
Chart.defaults.plugins.legend.labels.padding = 16;
Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(15,23,42,0.95)';
Chart.defaults.plugins.tooltip.borderColor = 'rgba(255,255,255,0.08)';
Chart.defaults.plugins.tooltip.borderWidth = 1;
Chart.defaults.plugins.tooltip.cornerRadius = 8;
Chart.defaults.plugins.tooltip.padding = 10;
Chart.defaults.plugins.tooltip.titleFont = { weight: '600' };

const C = {
  cyan: '#06b6d4', teal: '#14b8a6', emerald: '#10b981',
  blue: '#3b82f6', purple: '#8b5cf6', amber: '#f59e0b',
  red: '#ef4444', pink: '#ec4899', sky: '#0ea5e9',
  lime: '#84cc16', orange: '#f97316', indigo: '#6366f1',
};
const PALETTE = [C.cyan, C.blue, C.amber, C.red, C.purple, C.emerald, C.pink, C.sky, C.lime, C.orange, C.indigo, C.teal];

function alpha(hex, a) {
  const r = parseInt(hex.slice(1, 3), 16), g = parseInt(hex.slice(3, 5), 16), b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r},${g},${b},${a})`;
}

// ─── Aggregation Helpers ────────────────────────────────────────────────────
/** Count occurrences of a field, splitting semicolons. Returns sorted [[label, count], ...] */
function countField(incidents, field, topN = 999) {
  const counts = {};
  incidents.forEach(r => {
    const val = r[field];
    if (!val || val === '') return;
    val.toString().split(';').forEach(v => {
      v = v.trim();
      if (v && !DISGUISED.includes(v)) {
        counts[v] = (counts[v] || 0) + 1;
      }
    });
  });
  return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, topN);
}

/** Count by year, returns { year: count } */
function countByYear(incidents, yearMin, yearMax) {
  const counts = {};
  for (let y = yearMin; y <= yearMax; y++) counts[y] = 0;
  incidents.forEach(r => {
    if (r.year >= yearMin && r.year <= yearMax) counts[r.year] = (counts[r.year] || 0) + 1;
  });
  return counts;
}

/** Count initiator→receiver pairs */
function countCorridors(incidents, topN = 12) {
  const counts = {};
  incidents.forEach(r => {
    const from = (r.initiator_country || '').split(';')[0].trim();
    const to = (r.receiver_country || '').split(';')[0].trim();
    if (!from || !to || DISGUISED.includes(from) || DISGUISED.includes(to)) return;
    const key = `${from}→${to}`;
    counts[key] = (counts[key] || 0) + 1;
  });
  return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, topN);
}

/** Count incident types per year for trend chart */
function countTypeTrends(incidents, yearMin, yearMax) {
  const types = ['Data theft', 'Disruption', 'Hijacking with Misuse', 'Ransomware', 'Hijacking without Misuse'];
  const result = {};
  for (let y = yearMin; y <= yearMax; y++) {
    result[y] = {};
    types.forEach(t => result[y][t] = 0);
  }
  incidents.forEach(r => {
    if (!r.year || r.year < yearMin || r.year > yearMax) return;
    const itypes = (r.incident_type || '').split(';').map(s => s.trim());
    itypes.forEach(t => {
      if (types.includes(t)) result[r.year][t]++;
    });
  });
  return { types, result };
}

/** Compute attribution rate by year */
function computeAttributionByYear(incidents, yearMin, yearMax) {
  const byYear = {};
  for (let y = yearMin; y <= yearMax; y++) byYear[y] = { total: 0, unattr: 0 };
  incidents.forEach(r => {
    if (!r.year || r.year < yearMin || r.year > yearMax) return;
    byYear[r.year].total++;
    if (r.not_attributed) byYear[r.year].unattr++;
  });
  const labels = [], values = [];
  for (let y = yearMin; y <= yearMax; y++) {
    if (byYear[y].total > 0) {
      labels.push(y);
      values.push(Math.round(byYear[y].unattr / byYear[y].total * 1000) / 10);
    }
  }
  return { labels, values };
}

/** Compute intensity stats per initiator category */
function computeIntensity(incidents) {
  const cats = ['State', 'State affiliated actor', 'Non-state-group', 'Individual hacker(s)', 'Not attributed'];
  const data = {};
  cats.forEach(c => data[c] = []);
  incidents.forEach(r => {
    const cat = r.initiator_cat_clean;
    if (cat && data[cat] !== undefined && r.weighted_intensity !== '' && r.weighted_intensity !== null) {
      data[cat].push(r.weighted_intensity);
    }
  });
  const result = {};
  cats.forEach(c => {
    const vals = data[c].sort((a, b) => a - b);
    if (vals.length > 0) {
      const median = vals[Math.floor(vals.length / 2)];
      const mean = vals.reduce((s, v) => s + v, 0) / vals.length;
      result[c] = { median: Math.round(median * 100) / 100, mean: Math.round(mean * 100) / 100, count: vals.length };
    }
  });
  return result;
}

/** Build heatmap data: rows × cols counts from incidents */
function buildHeatmap(incidents, rowField, colField, topRows, topCols) {
  // Get top row values
  const rowCounts = countField(incidents, rowField, topRows);
  const rows = rowCounts.map(e => e[0]);
  // Get top col values (may need splitting)
  const colCounts = countField(incidents, colField, topCols);
  const cols = colCounts.map(e => e[0]);

  const data = {};
  rows.forEach(r => {
    data[r] = {};
    cols.forEach(c => data[r][c] = 0);
  });

  incidents.forEach(inc => {
    const rowVals = (inc[rowField] || '').split(';').map(s => s.trim()).filter(s => rows.includes(s));
    const colVals = (inc[colField] || '').split(';').map(s => s.trim()).filter(s => cols.includes(s));
    rowVals.forEach(rv => colVals.forEach(cv => {
      if (data[rv]) data[rv][cv] = (data[rv][cv] || 0) + 1;
    }));
  });
  return { rows, cols, data };
}


// ─── Filtering ──────────────────────────────────────────────────────────────
function getFilters() {
  return {
    yearMin: parseInt(document.getElementById('filterYearMin').value),
    yearMax: parseInt(document.getElementById('filterYearMax').value),
    initiator: document.getElementById('filterInitiator').value,
    receiver: document.getElementById('filterReceiver').value,
  };
}

function getFilteredIncidents() {
  const f = getFilters();
  return DATA.incidents.filter(r => {
    if (r.year !== '' && (r.year < f.yearMin || r.year > f.yearMax)) return false;
    if (r.year === '') return false;
    if (f.initiator !== 'all' && r.initiator_cat_clean !== f.initiator) return false;
    if (f.receiver !== 'all' && r.receiver_cat_clean !== f.receiver) return false;
    
    // Globe country selection filter
    if (SELECTED_GLOBE_COUNTRY) {
      const matchInit = (r.initiator_country || '').split(';').map(s => s.trim()).includes(SELECTED_GLOBE_COUNTRY);
      const matchRecv = (r.receiver_country || '').split(';').map(s => s.trim()).includes(SELECTED_GLOBE_COUNTRY);
      if (!matchInit && !matchRecv) return false;
    }
    return true;
  });
}

// ─── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  try {
    // Try fetch first (works with HTTP server)
    const res = await fetch('dashboard_data.json');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    DATA = await res.json();
  } catch (e) {
    console.warn('fetch failed, trying JSONP fallback:', e.message);
    // Fallback: check if data was loaded via <script> tag
    if (window.DASHBOARD_DATA) {
      DATA = window.DASHBOARD_DATA;
    } else {
      console.error('Failed to load dashboard data:', e);
      document.getElementById('loadingOverlay').innerHTML =
        '<div style="color:#ef4444;font-size:16px;padding:20px;">Failed to load data.<br>Run: <code>cd dashboard && python3 -m http.server 8000</code><br>Then open <a href="http://localhost:8000" style="color:#06b6d4">http://localhost:8000</a></div>';
      return;
    }
  }
  try {
    console.log('Data loaded:', DATA.incidents.length, 'incidents');
    initFilters();
    initAllCharts();
    bindEvents();
    console.log('Dashboard initialized successfully');
    setTimeout(() => document.getElementById('loadingOverlay').classList.add('hidden'), 400);
  } catch (initErr) {
    console.error('Dashboard init error:', initErr);
    document.getElementById('loadingOverlay').innerHTML =
      `<div style="color:#ef4444;font-size:16px;padding:20px;text-align:left;background:#1a1010;border:1px solid #ef4444;border-radius:8px;max-width:600px;margin:20px auto;font-family:monospace;white-space:pre-wrap;"><strong>Error initializing dashboard:</strong><br>${initErr.message}<br><br><strong>Stack:</strong><br>${initErr.stack}</div>`;
  }
});

function initFilters() {
  const initSel = document.getElementById('filterInitiator');
  Object.keys(DATA.initiator_categories).forEach(cat => {
    const opt = document.createElement('option');
    opt.value = cat; opt.textContent = cat;
    initSel.appendChild(opt);
  });
  const recvSel = document.getElementById('filterReceiver');
  Object.keys(DATA.receiver_categories).forEach(cat => {
    const opt = document.createElement('option');
    opt.value = cat; opt.textContent = cat;
    recvSel.appendChild(opt);
  });

  const countrySel = document.getElementById('filterCountry');
  if (countrySel && DATA.country_coords) {
    const sortedCountries = Object.keys(DATA.country_coords)
      .filter(c => c && !DISGUISED.includes(c))
      .sort((a, b) => a.localeCompare(b));
    sortedCountries.forEach(country => {
      const opt = document.createElement('option');
      opt.value = country;
      opt.textContent = country;
      countrySel.appendChild(opt);
    });
  }

  updateYearDisplay();
}

function updateYearDisplay() {
  const min = document.getElementById('filterYearMin').value;
  const max = document.getElementById('filterYearMax').value;
  document.getElementById('yearRangeDisplay').textContent = `${min}–${max}`;
  document.getElementById('yearChartBadge').textContent = `${min}–${max}`;
}

function bindEvents() {
  ['filterYearMin', 'filterYearMax'].forEach(id => {
    document.getElementById(id).addEventListener('input', () => {
      const min = document.getElementById('filterYearMin');
      const max = document.getElementById('filterYearMax');
      if (parseInt(min.value) > parseInt(max.value)) {
        if (id === 'filterYearMin') max.value = min.value;
        else min.value = max.value;
      }
      updateYearDisplay();
      // Debounce: slider fires on every pixel, avoid flooding chart updates
      clearTimeout(_refreshTimer);
      _refreshTimer = setTimeout(refreshAll, 60);
    });
  });

  ['filterInitiator', 'filterReceiver'].forEach(id => {
    document.getElementById(id).addEventListener('change', refreshAll);
  });

  const countrySel = document.getElementById('filterCountry');
  if (countrySel) {
    countrySel.addEventListener('change', (e) => {
      const val = e.target.value;
      if (val === 'all') {
        clearGlobeSelection();
      } else {
        selectGlobeCountry(val);
      }
    });
  }

  document.getElementById('resetFilters').addEventListener('click', () => {
    document.getElementById('filterYearMin').value = 2010;
    document.getElementById('filterYearMax').value = 2024;
    document.getElementById('filterInitiator').value = 'all';
    document.getElementById('filterReceiver').value = 'all';
    const cSel = document.getElementById('filterCountry');
    if (cSel) cSel.value = 'all';
    SELECTED_GLOBE_COUNTRY = null;
    updateYearDisplay();
    refreshAll();
  });

  document.getElementById('clearGlobeFilter').addEventListener('click', (e) => {
    e.stopPropagation();
    clearGlobeSelection();
  });

  document.getElementById('tableSearch').addEventListener('input', (e) => {
    TABLE_STATE.search = e.target.value.toLowerCase();
    TABLE_STATE.page = 0;
    filterTable();
    renderTable();
  });

  document.querySelectorAll('.data-table thead th[data-sort]').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.sort;
      if (TABLE_STATE.sortCol === col) TABLE_STATE.sortDir = TABLE_STATE.sortDir === 'asc' ? 'desc' : 'asc';
      else { TABLE_STATE.sortCol = col; TABLE_STATE.sortDir = 'desc'; }
      document.querySelectorAll('.data-table thead th').forEach(t => t.classList.remove('sorted-asc', 'sorted-desc'));
      th.classList.add(TABLE_STATE.sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');
      TABLE_STATE.page = 0;
      filterTable();
      renderTable();
    });
  });
}

// ─── Master Refresh — called on every filter change ─────────────────────────
function refreshAll() {
  const filtered = getFilteredIncidents();
  const f = getFilters();

  updateKPIs(filtered);
  updateIncidentsByYear(filtered, f);
  updateTypeTrends(filtered, f);
  updateAttribution(filtered, f);
  updateInitiatorCountries(filtered);
  updateReceiverCountries(filtered);
  updateCorridors(filtered);
  updateInitiatorCats(filtered);
  updateReceiverCats(filtered);
  updateMitre(filtered);
  updateIntensity(filtered);
  updateHeatmapConflict(filtered);
  updateHeatmapReceiver(filtered);
  updateGlobeData(filtered);

  TABLE_STATE.page = 0;
  filterTable();
  renderTable();
}

// ─── KPIs ───────────────────────────────────────────────────────────────────
function updateKPIs(filtered) {
  const total = filtered.length;
  const attributed = filtered.filter(r => !r.not_attributed).length;
  const attrRate = total > 0 ? Math.round(attributed / total * 1000) / 10 : 0;
  const initCounts = countField(filtered.filter(r => !r.not_attributed), 'initiator_country', 1);
  const topAtt = initCounts.length > 0 ? initCounts[0][0] : '—';
  const recvCountries = new Set();
  filtered.forEach(r => {
    (r.receiver_country || '').split(';').forEach(v => {
      v = v.trim();
      if (v && !DISGUISED.includes(v)) recvCountries.add(v);
    });
  });
  const stateCount = filtered.filter(r => r.initiator_cat_clean === 'State').length;
  const zdCount = filtered.filter(r => r.zero_days === 'Yes').length;

  document.getElementById('kpiTotal').textContent = total.toLocaleString();
  document.getElementById('kpiCountries').textContent = recvCountries.size.toLocaleString();
  document.getElementById('kpiAttribution').textContent = attrRate + '%';
  document.getElementById('kpiTopAttacker').textContent = topAtt;
  document.getElementById('kpiStateIncidents').textContent = stateCount.toLocaleString();
  document.getElementById('kpiZeroDays').textContent = zdCount.toLocaleString();

  document.getElementById('heroIncidentCount').textContent = total.toLocaleString();
  document.getElementById('heroCountryCount').textContent = recvCountries.size.toLocaleString() + '+';
}

// ─── Chart Init & Updates ───────────────────────────────────────────────────
function initAllCharts() {
  const filtered = getFilteredIncidents();
  const f = getFilters();

  // Create all charts
  createIncidentsByYear(filtered, f);
  createTypeTrends(filtered, f);
  createAttribution(filtered, f);
  createInitiatorCountries(filtered);
  createReceiverCountries(filtered);
  createCorridors(filtered);
  createInitiatorCats(filtered);
  createReceiverCats(filtered);
  createMitre(filtered);
  createIntensity(filtered);
  createHeatmapConflict(filtered);
  createHeatmapReceiver(filtered);
  initGlobe();
  initTable();

  // Initial KPIs with animation
  if (SELECTED_GLOBE_COUNTRY) {
    updateKPIs(filtered);
    const dateMin = document.getElementById('filterYearMin').value;
    const dateMax = document.getElementById('filterYearMax').value;
    document.getElementById('heroDateRange').textContent = `${dateMin} – ${dateMax}`;
  } else {
    const s = DATA.summary;
    animateValue('kpiTotal', s.total_incidents);
    animateValue('kpiCountries', s.countries_affected);
    animateText('kpiAttribution', s.attribution_rate + '%');
    animateText('kpiTopAttacker', s.top_attacker);
    animateValue('kpiStateIncidents', s.state_incidents);
    animateValue('kpiZeroDays', s.zero_day_incidents);
    document.getElementById('heroIncidentCount').textContent = s.total_incidents.toLocaleString();
    document.getElementById('heroCountryCount').textContent = s.countries_affected.toLocaleString() + '+';
    document.getElementById('heroDateRange').textContent =
      `${s.date_range_start.slice(0, 4)} – ${s.date_range_end.slice(0, 4)}`;
  }
}

function animateValue(id, target) {
  const el = document.getElementById(id);
  const duration = 1200, start = performance.now();
  const step = (now) => {
    const p = Math.min((now - start) / duration, 1);
    el.textContent = Math.round((1 - Math.pow(1 - p, 3)) * target).toLocaleString();
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function animateText(id, text) {
  const el = document.getElementById(id);
  el.style.animation = 'countUp 0.6s ease both';
  el.textContent = text;
}

// ── Helper: destroy+recreate or update a chart ──
function updateBarChart(chart, labels, data, colors) {
  chart.data.labels = labels;
  chart.data.datasets[0].data = data;
  if (colors) {
    chart.data.datasets[0].backgroundColor = colors.map(c => alpha(c, 0.7));
    chart.data.datasets[0].borderColor = colors;
  }
  chart.update();
}

// ── 1. Incidents by Year ──
function createIncidentsByYear(filtered, f) {
  const yearCounts = countByYear(filtered, f.yearMin, f.yearMax);
  const labels = Object.keys(yearCounts).map(Number);
  const values = labels.map(y => yearCounts[y]);
  CHARTS.yearly = new Chart(document.getElementById('chartIncidentsByYear').getContext('2d'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Incidents', data: values,
        backgroundColor: labels.map(y => y >= 2022 ? alpha(C.emerald, 0.7) : alpha(C.cyan, 0.6)),
        borderColor: labels.map(y => y >= 2022 ? C.emerald : C.cyan),
        borderWidth: 1, borderRadius: 4, borderSkipped: false,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: true, aspectRatio: 2.8,
      animation: { duration: 500, easing: 'easeOutQuart' },
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' } }, x: { grid: { display: false } } }
    }
  });
}

function updateIncidentsByYear(filtered, f) {
  const yearCounts = countByYear(filtered, f.yearMin, f.yearMax);
  const labels = Object.keys(yearCounts).map(Number);
  const values = labels.map(y => yearCounts[y]);
  CHARTS.yearly.data.labels = labels;
  CHARTS.yearly.data.datasets[0].data = values;
  CHARTS.yearly.data.datasets[0].backgroundColor = labels.map(y => y >= 2022 ? alpha(C.emerald, 0.7) : alpha(C.cyan, 0.6));
  CHARTS.yearly.data.datasets[0].borderColor = labels.map(y => y >= 2022 ? C.emerald : C.cyan);
  CHARTS.yearly.update();
}

// ── 2. Incident Type Trends ──
function createTypeTrends(filtered, f) {
  const { types, result } = countTypeTrends(filtered, Math.max(f.yearMin, 2010), f.yearMax);
  const labels = Object.keys(result).map(Number);
  const colors = [C.cyan, C.amber, C.purple, C.red, C.blue];
  const datasets = types.map((t, i) => ({
    label: t, data: labels.map(y => result[y][t]),
    borderColor: colors[i], backgroundColor: alpha(colors[i], 0.1),
    fill: false, tension: 0.3, pointRadius: 3, pointHoverRadius: 6, borderWidth: 2,
  }));
  CHARTS.typeTrends = new Chart(document.getElementById('chartTypeTrends').getContext('2d'), {
    type: 'line', data: { labels, datasets },
    options: {
      responsive: true, maintainAspectRatio: true, aspectRatio: 1.6,
      animation: { duration: 500 },
      plugins: { legend: { position: 'top' } },
      scales: { y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' } }, x: { grid: { display: false } } },
      interaction: { mode: 'index', intersect: false },
    }
  });
}

function updateTypeTrends(filtered, f) {
  const { types, result } = countTypeTrends(filtered, Math.max(f.yearMin, 2010), f.yearMax);
  const labels = Object.keys(result).map(Number);
  const colors = [C.cyan, C.amber, C.purple, C.red, C.blue];
  CHARTS.typeTrends.data.labels = labels;
  CHARTS.typeTrends.data.datasets = types.map((t, i) => ({
    label: t, data: labels.map(y => result[y][t]),
    borderColor: colors[i], backgroundColor: alpha(colors[i], 0.1),
    fill: false, tension: 0.3, pointRadius: 3, pointHoverRadius: 6, borderWidth: 2,
  }));
  CHARTS.typeTrends.update();
}

// ── 3. Attribution Over Time ──
function createAttribution(filtered, f) {
  const { labels, values } = computeAttributionByYear(filtered, Math.max(f.yearMin, 2011), f.yearMax);
  CHARTS.attribution = new Chart(document.getElementById('chartAttribution').getContext('2d'), {
    type: 'line',
    data: {
      labels,
      datasets: [{ label: '% Unattributed', data: values,
        borderColor: C.red, backgroundColor: alpha(C.red, 0.1),
        fill: true, tension: 0.3, pointRadius: 4, pointHoverRadius: 7, borderWidth: 2,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: true, aspectRatio: 1.6,
      animation: { duration: 500 },
      plugins: { legend: { display: false } },
      scales: { y: { min: 0, max: 100, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { callback: v => v + '%' } }, x: { grid: { display: false } } }
    }
  });
}

function updateAttribution(filtered, f) {
  const { labels, values } = computeAttributionByYear(filtered, Math.max(f.yearMin, 2011), f.yearMax);
  CHARTS.attribution.data.labels = labels;
  CHARTS.attribution.data.datasets[0].data = values;
  CHARTS.attribution.update();
}

// ── 4. Top Initiator Countries ──
function createInitiatorCountries(filtered) {
  const entries = countField(filtered.filter(r => !r.not_attributed), 'initiator_country', 10);
  const labels = entries.map(e => e[0]);
  const values = entries.map(e => e[1]);
  CHARTS.initCountries = new Chart(document.getElementById('chartInitiatorCountries').getContext('2d'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{ label: 'Incidents', data: values,
        backgroundColor: PALETTE.slice(0, labels.length).map(c => alpha(c, 0.7)),
        borderColor: PALETTE.slice(0, labels.length), borderWidth: 1, borderRadius: 4,
      }]
    },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: true, aspectRatio: 1.3,
      animation: { duration: 500 },
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' } }, y: { grid: { display: false } } }
    }
  });
}

function updateInitiatorCountries(filtered) {
  const entries = countField(filtered.filter(r => !r.not_attributed), 'initiator_country', 10);
  const labels = entries.map(e => e[0]);
  const values = entries.map(e => e[1]);
  updateBarChart(CHARTS.initCountries, labels, values, PALETTE.slice(0, labels.length));
}

// ── 5. Top Receiver Countries ──
function createReceiverCountries(filtered) {
  const entries = countField(filtered, 'receiver_country', 10);
  const labels = entries.map(e => e[0]);
  const values = entries.map(e => e[1]);
  CHARTS.recvCountries = new Chart(document.getElementById('chartReceiverCountries').getContext('2d'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{ label: 'Incidents', data: values,
        backgroundColor: PALETTE.slice(0, labels.length).map(c => alpha(c, 0.7)),
        borderColor: PALETTE.slice(0, labels.length), borderWidth: 1, borderRadius: 4,
      }]
    },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: true, aspectRatio: 1.3,
      animation: { duration: 500 },
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' } }, y: { grid: { display: false } } }
    }
  });
}

function updateReceiverCountries(filtered) {
  const entries = countField(filtered, 'receiver_country', 10);
  updateBarChart(CHARTS.recvCountries, entries.map(e => e[0]), entries.map(e => e[1]), PALETTE.slice(0, entries.length));
}

// ── 6. Attack Corridors ──
function createCorridors(filtered) {
  const entries = countCorridors(filtered, 12);
  const labels = entries.map(e => e[0]);
  const values = entries.map(e => e[1]);
  CHARTS.corridors = new Chart(document.getElementById('chartCorridors').getContext('2d'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{ label: 'Incidents', data: values,
        backgroundColor: labels.map((_, i) => alpha(PALETTE[i % PALETTE.length], 0.7)),
        borderColor: labels.map((_, i) => PALETTE[i % PALETTE.length]), borderWidth: 1, borderRadius: 4,
      }]
    },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: true, aspectRatio: 2,
      animation: { duration: 500 },
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' } }, y: { grid: { display: false }, ticks: { font: { size: 11 } } } }
    }
  });
}

function updateCorridors(filtered) {
  const entries = countCorridors(filtered, 12);
  const labels = entries.map(e => e[0]);
  const values = entries.map(e => e[1]);
  CHARTS.corridors.data.labels = labels;
  CHARTS.corridors.data.datasets[0].data = values;
  CHARTS.corridors.data.datasets[0].backgroundColor = labels.map((_, i) => alpha(PALETTE[i % PALETTE.length], 0.7));
  CHARTS.corridors.data.datasets[0].borderColor = labels.map((_, i) => PALETTE[i % PALETTE.length]);
  CHARTS.corridors.update();
}

// ── 7. Initiator Categories (Doughnut) ──
function createInitiatorCats(filtered) {
  const entries = countField(filtered, 'initiator_cat_clean', 8);
  CHARTS.initCats = new Chart(document.getElementById('chartInitiatorCats').getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: entries.map(e => e[0]),
      datasets: [{ data: entries.map(e => e[1]),
        backgroundColor: PALETTE.slice(0, entries.length).map(c => alpha(c, 0.75)),
        borderColor: 'rgba(10,14,26,0.8)', borderWidth: 2, hoverOffset: 8,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: true, aspectRatio: 1.2, cutout: '55%',
      animation: { duration: 500 },
      plugins: { legend: { position: 'right', labels: { font: { size: 11 }, padding: 10 } } }
    }
  });
}

function updateInitiatorCats(filtered) {
  const entries = countField(filtered, 'initiator_cat_clean', 8);
  CHARTS.initCats.data.labels = entries.map(e => e[0]);
  CHARTS.initCats.data.datasets[0].data = entries.map(e => e[1]);
  CHARTS.initCats.data.datasets[0].backgroundColor = PALETTE.slice(0, entries.length).map(c => alpha(c, 0.75));
  CHARTS.initCats.update();
}

// ── 8. Receiver Categories (Doughnut) ──
function createReceiverCats(filtered) {
  const entries = countField(filtered, 'receiver_cat_clean', 8);
  CHARTS.recvCats = new Chart(document.getElementById('chartReceiverCats').getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: entries.map(e => e[0]),
      datasets: [{ data: entries.map(e => e[1]),
        backgroundColor: PALETTE.slice(0, entries.length).map(c => alpha(c, 0.75)),
        borderColor: 'rgba(10,14,26,0.8)', borderWidth: 2, hoverOffset: 8,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: true, aspectRatio: 1.2, cutout: '55%',
      animation: { duration: 500 },
      plugins: { legend: { position: 'right', labels: { font: { size: 11 }, padding: 10 } } }
    }
  });
}

function updateReceiverCats(filtered) {
  const entries = countField(filtered, 'receiver_cat_clean', 8);
  CHARTS.recvCats.data.labels = entries.map(e => e[0]);
  CHARTS.recvCats.data.datasets[0].data = entries.map(e => e[1]);
  CHARTS.recvCats.data.datasets[0].backgroundColor = PALETTE.slice(0, entries.length).map(c => alpha(c, 0.75));
  CHARTS.recvCats.update();
}

// ── 9. MITRE ATT&CK ──
function createMitre(filtered) {
  const entries = countField(filtered, 'mitre_initial_access', 8);
  const labels = entries.map(e => e[0]);
  const values = entries.map(e => e[1]);
  CHARTS.mitre = new Chart(document.getElementById('chartMitre').getContext('2d'), {
    type: 'bar',
    data: {
      labels,
      datasets: [{ label: 'Incidents', data: values,
        backgroundColor: alpha(C.purple, 0.6), borderColor: C.purple, borderWidth: 1, borderRadius: 4,
      }]
    },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: true, aspectRatio: 1.3,
      animation: { duration: 500 },
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' } }, y: { grid: { display: false }, ticks: { font: { size: 10 } } } }
    }
  });
}

function updateMitre(filtered) {
  const entries = countField(filtered, 'mitre_initial_access', 8);
  CHARTS.mitre.data.labels = entries.map(e => e[0]);
  CHARTS.mitre.data.datasets[0].data = entries.map(e => e[1]);
  CHARTS.mitre.update();
}

// ── 10. Intensity by Category ──
function createIntensity(filtered) {
  const intData = computeIntensity(filtered);
  const cats = Object.keys(intData);
  CHARTS.intensity = new Chart(document.getElementById('chartIntensity').getContext('2d'), {
    type: 'bar',
    data: {
      labels: cats,
      datasets: [
        { label: 'Median', data: cats.map(c => intData[c].median),
          backgroundColor: alpha(C.cyan, 0.7), borderColor: C.cyan, borderWidth: 1, borderRadius: 4 },
        { label: 'Mean', data: cats.map(c => intData[c].mean),
          backgroundColor: alpha(C.amber, 0.7), borderColor: C.amber, borderWidth: 1, borderRadius: 4 },
      ]
    },
    options: {
      responsive: true, maintainAspectRatio: true, aspectRatio: 1.3,
      animation: { duration: 500 },
      plugins: { legend: { position: 'top' } },
      scales: {
        y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' }, title: { display: true, text: 'Weighted Intensity', color: '#94a3b8' } },
        x: { grid: { display: false }, ticks: { font: { size: 10 }, maxRotation: 20 } }
      }
    }
  });
}

function updateIntensity(filtered) {
  const intData = computeIntensity(filtered);
  const cats = Object.keys(intData);
  CHARTS.intensity.data.labels = cats;
  CHARTS.intensity.data.datasets[0].data = cats.map(c => intData[c].median);
  CHARTS.intensity.data.datasets[1].data = cats.map(c => intData[c].mean);
  CHARTS.intensity.update();
}

// ─── Heatmaps (CSS-rendered, re-rendered on filter) ─────────────────────────
function createHeatmapConflict(filtered) { updateHeatmapConflict(filtered); }
function createHeatmapReceiver(filtered) { updateHeatmapReceiver(filtered); }

function updateHeatmapConflict(filtered) {
  const hm = buildHeatmap(filtered, 'initiator_cat_clean', 'issue_clean', 6, 6);
  renderHeatmap('heatmapConflict', hm.rows, hm.cols, hm.data, 'YlGnBu');
}

function updateHeatmapReceiver(filtered) {
  const hm = buildHeatmap(filtered, 'receiver_cat_clean', 'incident_type', 8, 7);
  renderHeatmap('heatmapReceiver', hm.rows, hm.cols, hm.data, 'YlOrRd');
}

function renderHeatmap(containerId, rows, cols, data, scheme) {
  const container = document.getElementById(containerId);
  if (!rows.length || !cols.length) {
    container.innerHTML = '<div style="padding:40px;text-align:center;color:#64748b;">No data for current filters</div>';
    return;
  }

  const colorScales = {
    YlGnBu: (t) => {
      if (t < 0.25) return lerpColor('#1a2332', '#155e75', t * 4);
      if (t < 0.5) return lerpColor('#155e75', '#0d9488', (t - 0.25) * 4);
      if (t < 0.75) return lerpColor('#0d9488', '#10b981', (t - 0.5) * 4);
      return lerpColor('#10b981', '#6ee7b7', (t - 0.75) * 4);
    },
    YlOrRd: (t) => {
      if (t < 0.25) return lerpColor('#1a2332', '#92400e', t * 4);
      if (t < 0.5) return lerpColor('#92400e', '#d97706', (t - 0.25) * 4);
      if (t < 0.75) return lerpColor('#d97706', '#ef4444', (t - 0.5) * 4);
      return lerpColor('#ef4444', '#fca5a5', (t - 0.75) * 4);
    }
  };
  const colorFn = colorScales[scheme] || colorScales.YlGnBu;

  let maxVal = 0;
  rows.forEach(r => cols.forEach(c => {
    const v = (data[r] || {})[c] || 0;
    if (v > maxVal) maxVal = v;
  }));

  let html = `<div class="heatmap-grid" style="grid-template-columns: 120px repeat(${cols.length}, 1fr);">`;
  html += '<div class="heatmap-header"></div>';
  cols.forEach(c => {
    const short = c.length > 12 ? c.slice(0, 11) + '…' : c;
    html += `<div class="heatmap-header" title="${esc(c)}">${esc(short)}</div>`;
  });

  rows.forEach(r => {
    const short = r.length > 14 ? r.slice(0, 13) + '…' : r;
    html += `<div class="heatmap-row-label" title="${esc(r)}">${esc(short)}</div>`;
    cols.forEach(c => {
      const v = (data[r] || {})[c] || 0;
      const t = maxVal > 0 ? v / maxVal : 0;
      const bg = colorFn(t);
      const textColor = t > 0.5 ? '#fff' : '#94a3b8';
      html += `<div class="heatmap-cell" style="background:${bg};color:${textColor}" title="${esc(r)}: ${esc(c)} = ${v}">${v}</div>`;
    });
  });
  html += '</div>';
  container.innerHTML = html;
}

function lerpColor(c1, c2, t) {
  const r1 = parseInt(c1.slice(1, 3), 16), g1 = parseInt(c1.slice(3, 5), 16), b1 = parseInt(c1.slice(5, 7), 16);
  const r2 = parseInt(c2.slice(1, 3), 16), g2 = parseInt(c2.slice(3, 5), 16), b2 = parseInt(c2.slice(5, 7), 16);
  const r = Math.round(r1 + (r2 - r1) * t), g = Math.round(g1 + (g2 - g1) * t), b = Math.round(b1 + (b2 - b1) * t);
  return `rgb(${r},${g},${b})`;
}

// ─── Data Table ─────────────────────────────────────────────────────────────
function initTable() {
  TABLE_STATE.data = DATA.incidents || [];
  filterTable();
  renderTable();
}

function filterTable() {
  const f = getFilters();
  let rows = TABLE_STATE.data.filter(r => {
    if (!r.year || r.year === '') return false;
    if (r.year < f.yearMin || r.year > f.yearMax) return false;
    if (f.initiator !== 'all' && r.initiator_cat_clean !== f.initiator) return false;
    if (f.receiver !== 'all' && r.receiver_cat_clean !== f.receiver) return false;
    return true;
  });

  if (TABLE_STATE.search) {
    const q = TABLE_STATE.search;
    rows = rows.filter(r =>
      (r.name && r.name.toLowerCase().includes(q)) ||
      (r.initiator_country && r.initiator_country.toLowerCase().includes(q)) ||
      (r.receiver_country && r.receiver_country.toLowerCase().includes(q)) ||
      (r.incident_type_clean && r.incident_type_clean.toLowerCase().includes(q)) ||
      (r.initiator_cat_clean && r.initiator_cat_clean.toLowerCase().includes(q))
    );
  }

  const col = TABLE_STATE.sortCol;
  const dir = TABLE_STATE.sortDir === 'asc' ? 1 : -1;
  rows.sort((a, b) => {
    let va = a[col], vb = b[col];
    if (va === '' || va === undefined || va === null) va = dir > 0 ? Infinity : -Infinity;
    if (vb === '' || vb === undefined || vb === null) vb = dir > 0 ? Infinity : -Infinity;
    if (typeof va === 'string') return dir * va.localeCompare(vb);
    return dir * (va - vb);
  });
  TABLE_STATE.filtered = rows;
}

function renderTable() {
  const { filtered, page, pageSize } = TABLE_STATE;
  const totalPages = Math.ceil(filtered.length / pageSize);
  const start = page * pageSize;
  const pageData = filtered.slice(start, start + pageSize);

  document.getElementById('tableCount').textContent =
    filtered.length === 0 ? 'No matching incidents' :
    `Showing ${start + 1}–${Math.min(start + pageSize, filtered.length)} of ${filtered.length} incidents`;

  const tbody = document.getElementById('tableBody');
  if (pageData.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:40px;color:#64748b;">No incidents match the current filters</td></tr>';
  } else {
    tbody.innerHTML = pageData.map(r => {
      const intensity = r.weighted_intensity;
      let intClass = 'intensity-low';
      if (intensity >= 4) intClass = 'intensity-high';
      else if (intensity >= 2) intClass = 'intensity-med';
      const intBadge = intensity !== '' ? `<span class="intensity-badge ${intClass}">${intensity}</span>` : '—';
      return `<tr>
        <td>${r.incident_id || '—'}</td>
        <td title="${esc(r.name || '')}">${esc(truncate(r.name || '—', 50))}</td>
        <td>${r.year || '—'}</td>
        <td>${esc(truncate(r.incident_type_clean || '—', 25))}</td>
        <td>${esc(truncate(r.initiator_country || '—', 25))}</td>
        <td>${esc(truncate(r.receiver_country || '—', 25))}</td>
        <td>${esc(truncate(r.initiator_cat_clean || '—', 25))}</td>
        <td>${intBadge}</td>
      </tr>`;
    }).join('');
  }
  renderPagination(totalPages);
}

function renderPagination(totalPages) {
  const container = document.getElementById('pagination');
  if (totalPages <= 1) { container.innerHTML = ''; return; }
  let html = `<button ${TABLE_STATE.page === 0 ? 'disabled' : ''} onclick="goToPage(${TABLE_STATE.page - 1})">← Prev</button>`;
  const maxBtns = 7;
  let sp = Math.max(0, TABLE_STATE.page - 3);
  let ep = Math.min(totalPages - 1, sp + maxBtns - 1);
  if (ep - sp < maxBtns - 1) sp = Math.max(0, ep - maxBtns + 1);
  if (sp > 0) { html += `<button onclick="goToPage(0)">1</button>`; if (sp > 1) html += `<span class="page-info">…</span>`; }
  for (let i = sp; i <= ep; i++) html += `<button class="${i === TABLE_STATE.page ? 'active' : ''}" onclick="goToPage(${i})">${i + 1}</button>`;
  if (ep < totalPages - 1) { if (ep < totalPages - 2) html += `<span class="page-info">…</span>`; html += `<button onclick="goToPage(${totalPages - 1})">${totalPages}</button>`; }
  html += `<button ${TABLE_STATE.page === totalPages - 1 ? 'disabled' : ''} onclick="goToPage(${TABLE_STATE.page + 1})">Next →</button>`;
  container.innerHTML = html;
}

window.goToPage = function(p) {
  TABLE_STATE.page = p;
  renderTable();
  document.querySelector('.table-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
};

// ─── Utilities ──────────────────────────────────────────────────────────────
function truncate(str, max) { return str.length > max ? str.slice(0, max) + '…' : str; }
function esc(str) { const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }

// Helper to match GeoJSON country names to DATA.country_coords keys
function getDatasetCountryName(geojsonName) {
  if (!geojsonName) return null;
  const name = geojsonName.toLowerCase().trim();
  
  if (name === 'united states of america' || name === 'united states' || name === 'usa') {
    return 'United States';
  }
  if (name === 'russian federation' || name === 'russia') {
    return 'Russia';
  }
  if (name === 'south korea' || name.includes('korea, republic of') || name === 'korea' || name === 'republic of korea') {
    if (DATA && DATA.country_coords && DATA.country_coords['Korea, Republic of']) return 'Korea, Republic of';
    return 'South Korea';
  }
  if (name === 'north korea' || name.includes("democratic people's republic of korea") || name.includes("dem. rep. korea") || name.includes("north korea")) {
    if (DATA && DATA.country_coords && DATA.country_coords["Korea, Democratic People's Republic of"]) return "Korea, Democratic People's Republic of";
    return 'North Korea';
  }
  if (name === 'united kingdom' || name === 'great britain' || name === 'england' || name === 'uk') {
    return 'United Kingdom';
  }
  if (name === 'iran' || name.includes('iran, islamic republic of') || name.includes('iran')) {
    if (DATA && DATA.country_coords && DATA.country_coords['Iran, Islamic Republic of']) return 'Iran, Islamic Republic of';
    return 'Iran';
  }
  if (name === 'syria' || name.includes('syrian arab republic')) {
    return 'Syria';
  }
  if (name === 'vietnam' || name === 'viet nam') {
    return 'Vietnam';
  }
  
  if (!DATA || !DATA.country_coords) return null;
  const keys = Object.keys(DATA.country_coords);
  let match = keys.find(k => k.toLowerCase() === name);
  if (match) return match;
  
  match = keys.find(k => k.toLowerCase().includes(name) || name.includes(k.toLowerCase()));
  if (match) return match;
  
  return null;
}

// ─── 3D Globe Implementation ────────────────────────────────────────────────
function initGlobe() {
  const container = document.getElementById('3dGlobe');
  if (!container) return;

  GLOBE = Globe()
    (container)
    .backgroundColor('rgba(10,14,26,0)')
    .showAtmosphere(true)
    .atmosphereColor('#06b6d4')
    .atmosphereAltitude(0.2)
    .showGraticules(true) // Sci-fi grid
    .arcColor('color')
    .arcAltitude(d => d.altitude)
    .arcStroke(d => Math.min(1.8, 0.4 + d.weight * 0.04))
    .arcLabel(d => d.label)
    .labelAltitude(0.015) // Float labels above country polygons
    .onLabelHover(node => {
      container.style.cursor = node ? 'pointer' : null;
    })
    .onPolygonHover(polygon => {
      container.style.cursor = polygon ? 'pointer' : null;
    })
    .onGlobeClick(() => {
      clearGlobeSelection();
    });

  const globeMaterial = GLOBE.globeMaterial();
  if (globeMaterial) {
    globeMaterial.color.set('#070a13'); // Solid dark ocean background for the sphere
  }

  // Load high-contrast country borders (GeoJSON)
  fetch('https://unpkg.com/globe.gl/example/datasets/ne_110m_admin_0_countries.geojson')
    .then(res => {
      if (!res.ok) throw new Error('Failed to fetch country geojson');
      return res.json();
    })
    .then(countries => {
      if (!GLOBE) return;
      GLOBE.polygonsData(countries.features)
        .polygonCapColor(d => {
          const name = d.properties.NAME || d.properties.name || '';
          const matched = getDatasetCountryName(name);
          return (matched && matched === SELECTED_GLOBE_COUNTRY) ? 'rgba(6, 182, 212, 0.45)' : 'rgba(23, 27, 43, 0.7)';
        })
        .polygonSideColor(() => 'rgba(0, 0, 0, 0)')
        .polygonStrokeColor(() => 'rgba(6, 182, 212, 0.25)') // Glowing cyan border
        .polygonStrokeWidth(0.5)
        .polygonLabel(d => `<b>${d.properties.NAME || d.properties.name || ''}</b>`)
        .onPolygonClick(d => {
          const name = d.properties.NAME || d.properties.name || '';
          const matched = getDatasetCountryName(name);
          if (matched) {
            if (SELECTED_GLOBE_COUNTRY === matched) {
              clearGlobeSelection();
            } else {
              selectGlobeCountry(matched);
            }
          }
        });
    })
    .catch(err => {
      console.warn("Could not load country borders, falling back to default.", err);
    });

  resizeGlobe();
  window.addEventListener('resize', resizeGlobe);

  // Initial load
  updateGlobeData(getFilteredIncidents());

  // Center/Zoom on India by default on load
  if (SELECTED_GLOBE_COUNTRY && GLOBE) {
    const coords = DATA.country_coords[SELECTED_GLOBE_COUNTRY];
    if (coords) {
      GLOBE.pointOfView({ lat: coords[0], lng: coords[1], altitude: 1.8 }, 0);
    }
  }
}

function resizeGlobe() {
  if (!GLOBE) return;
  const container = document.getElementById('3dGlobe');
  if (container) {
    GLOBE.width(container.clientWidth).height(container.clientHeight);
  }
}

function updateGlobeData(filtered) {
  if (!GLOBE) return;

  const coords = DATA.country_coords;
  const activeCountries = new Set();
  const arcs = [];

  if (!SELECTED_GLOBE_COUNTRY) {
    // Top corridors view
    const corridors = countCorridors(filtered, 25);
    corridors.forEach(([corridor, count]) => {
      const [from, to] = corridor.split('→');
      const fromCoords = coords[from];
      const toCoords = coords[to];
      if (fromCoords && toCoords) {
        activeCountries.add(from);
        activeCountries.add(to);
        arcs.push({
          startLat: fromCoords[0],
          startLng: fromCoords[1],
          endLat: toCoords[0],
          endLng: toCoords[1],
          color: 'rgba(6, 182, 212, 0.6)',
          altitude: 0.25,
          weight: count,
          label: `${from} ➔ ${to} (${count} incidents)`
        });
      }
    });

    document.getElementById('globeFilterBadge').textContent = "Top Threat Corridors";
    document.getElementById('clearGlobeFilter').style.display = 'none';
  } else {
    // Focused country view (incoming/outgoing)
    const selected = SELECTED_GLOBE_COUNTRY;
    const incoming = {};
    const outgoing = {};

    filtered.forEach(r => {
      const initList = (r.initiator_country || '').split(';').map(s => s.trim());
      const recvList = (r.receiver_country || '').split(';').map(s => s.trim());

      const hasInit = initList.includes(selected);
      const hasRecv = recvList.includes(selected);

      if (hasInit) {
        recvList.forEach(to => {
          if (to && to !== selected && !DISGUISED.includes(to)) {
            outgoing[to] = (outgoing[to] || 0) + 1;
          }
        });
      }
      if (hasRecv) {
        initList.forEach(from => {
          if (from && from !== selected && !DISGUISED.includes(from)) {
            incoming[from] = (incoming[from] || 0) + 1;
          }
        });
      }
    });

    const selCoords = coords[selected];
    if (selCoords) {
      activeCountries.add(selected);

      // Outgoing attacks (Selected -> Target): Crimson/Red
      Object.entries(outgoing).forEach(([to, count]) => {
        const targetCoords = coords[to];
        if (targetCoords) {
          activeCountries.add(to);
          arcs.push({
            startLat: selCoords[0],
            startLng: selCoords[1],
            endLat: targetCoords[0],
            endLng: targetCoords[1],
            color: 'rgba(239, 68, 68, 0.6)',
            altitude: 0.35,
            weight: count,
            label: `OUTGOING: ${selected} ➔ ${to} (${count} incidents)`
          });
        }
      });

      // Incoming attacks (Source -> Selected): Cyan/Teal
      Object.entries(incoming).forEach(([from, count]) => {
        const sourceCoords = coords[from];
        if (sourceCoords) {
          activeCountries.add(from);
          arcs.push({
            startLat: sourceCoords[0],
            startLng: sourceCoords[1],
            endLat: selCoords[0],
            endLng: selCoords[1],
            color: 'rgba(6, 182, 212, 0.6)',
            altitude: 0.25,
            weight: count,
            label: `INCOMING: ${from} ➔ ${selected} (${count} incidents)`
          });
        }
      });
    }

    document.getElementById('globeFilterBadge').textContent = `Focused: ${selected}`;
    document.getElementById('clearGlobeFilter').style.display = 'inline-block';
  }

  // Bind Arcs
  GLOBE.arcsData(arcs);

  // Update polygon colors if polygon data is loaded
  if (GLOBE && GLOBE.polygonsData() && GLOBE.polygonsData().length > 0) {
    GLOBE.polygonCapColor(d => {
      const name = d.properties.NAME || d.properties.name || '';
      const matched = getDatasetCountryName(name);
      return (matched && matched === SELECTED_GLOBE_COUNTRY) ? 'rgba(6, 182, 212, 0.45)' : 'rgba(23, 27, 43, 0.7)';
    });
    GLOBE.polygonStrokeColor(d => {
      const name = d.properties.NAME || d.properties.name || '';
      const matched = getDatasetCountryName(name);
      return (matched && matched === SELECTED_GLOBE_COUNTRY) ? 'rgba(6, 182, 212, 0.8)' : 'rgba(6, 182, 212, 0.25)';
    });
    GLOBE.polygonsData(GLOBE.polygonsData());
  }

  // Build Country Labels/Nodes
  const labels = [];
  activeCountries.forEach(name => {
    const c = coords[name];
    if (c) {
      const isSelected = name === SELECTED_GLOBE_COUNTRY;
      labels.push({
        lat: c[0],
        lng: c[1],
        name: name,
        size: isSelected ? 1.4 : 0.8,
        color: isSelected ? '#ef4444' : '#06b6d4'
      });
    }
  });

  GLOBE.labelsData(labels)
    .labelLat(d => d.lat)
    .labelLng(d => d.lng)
    .labelText(d => d.name)
    .labelSize(d => d.size)
    .labelColor(d => d.color)
    .labelResolution(2)
    .onLabelClick(d => {
      selectGlobeCountry(d.name);
    });
}

function selectGlobeCountry(name) {
  const coords = DATA.country_coords[name];
  if (!coords) return;

  SELECTED_GLOBE_COUNTRY = name;

  const countrySel = document.getElementById('filterCountry');
  if (countrySel) {
    countrySel.value = name;
  }

  refreshAll();

  // Point camera to selected country
  if (GLOBE) {
    GLOBE.pointOfView({ lat: coords[0], lng: coords[1], altitude: 1.6 }, 1000);
  }
}

function clearGlobeSelection() {
  if (!SELECTED_GLOBE_COUNTRY) return;
  SELECTED_GLOBE_COUNTRY = null;

  const countrySel = document.getElementById('filterCountry');
  if (countrySel) {
    countrySel.value = 'all';
  }

  refreshAll();
  
  // Reset camera view
  if (GLOBE) {
    GLOBE.pointOfView({ lat: 20, lng: 0, altitude: 2.0 }, 1000);
  }
}
