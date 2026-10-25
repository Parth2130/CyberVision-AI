// CyberVision AI - Dashboard JS
// Supplements any inline script in dashboard.html

'use strict';

// ─── Module State ────────────────────────────────────────────────────────────
let _dashboardData    = null;   // Full analysis object loaded from storage
let _filteredRows     = [];     // Rows currently shown in the data table
let _currentPage      = 1;
const PAGE_SIZE       = 25;

// Chart instances (kept for update/destroy)
let _charts = {
  categoryPie:   null,
  trafficLine:   null,
  protocolBar:   null,
  featureScatter: null
};

// ─── Bootstrap ───────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  setActiveNav('dashboard');

  _dashboardData = loadAnalysis();
  if (!_dashboardData) {
    _showNoDataState();
    return;
  }

  _populateSummaryCards(_dashboardData.summary);
  _initCategoryPieChart(_dashboardData.category_counts);
  _initTrafficLineChart(_dashboardData.traffic_over_time);
  _initProtocolBarChart(_dashboardData.protocol_counts);
  _applyFilters();          // Populate table on first load

  _wireFilters();
  _wireExportButtons();
});

// ─── No-data State ───────────────────────────────────────────────────────────

function _showNoDataState() {
  const main = document.getElementById('dashboard-main');
  if (main) {
    renderEmptyState(
      main,
      'No analysis data found. Upload a dataset to get started.',
      '📊',
      'Upload Dataset',
      'upload.html'
    );
  }
}

// ─── Summary Cards ───────────────────────────────────────────────────────────

/**
 * Populate the KPI summary cards at the top of the dashboard.
 * @param {Object} summary - { total_records, attack_count, benign_count, anomaly_count, … }
 */
function _populateSummaryCards(summary) {
  if (!summary) return;

  _setText('stat-total',    formatNumber(summary.total_records));
  _setText('stat-attacks',  formatNumber(summary.attack_count));
  _setText('stat-benign',   formatNumber(summary.benign_count));
  _setText('stat-anomalies',formatNumber(summary.anomaly_count));

  const attackRate = formatPercent(summary.attack_count, summary.total_records);
  _setText('stat-attack-rate', attackRate);

  // Colour the attack rate badge by severity
  const ratePct = (summary.attack_count / summary.total_records) * 100;
  const badge   = document.getElementById('stat-attack-rate');
  if (badge) {
    badge.style.color = ratePct > 40 ? CHART_COLORS.danger
                       : ratePct > 15 ? CHART_COLORS.warning
                       : CHART_COLORS.success;
  }

  // File metadata
  _setText('meta-filename',   summary.filename   || '—');
  _setText('meta-filesize',   formatBytes(summary.file_size_bytes || 0));
  _setText('meta-rows',       formatNumber(summary.total_records));
  _setText('meta-columns',    formatNumber(summary.column_count));
  _setText('meta-analyzed-at',formatDate(summary.analyzed_at));
}

function _setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

// ─── Chart Initialisation ─────────────────────────────────────────────────────

/**
 * Render the attack-category donut/pie chart.
 * @param {Object} counts - { 'BENIGN': 1200, 'DoS Hulk': 340, … }
 */
function _initCategoryPieChart(counts) {
  const canvas = document.getElementById('chart-category-pie');
  if (!canvas || !counts) return;

  const labels = Object.keys(counts);
  const values = Object.values(counts);
  const colors = labels.map(l => CATEGORY_COLORS[l] || CATEGORY_COLORS['Unknown']);

  if (_charts.categoryPie) _charts.categoryPie.destroy();

  _charts.categoryPie = new Chart(canvas, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{
        data:            values,
        backgroundColor: colors,
        borderColor:     '#0f172a',
        borderWidth:     2,
        hoverOffset:     6
      }]
    },
    options: {
      responsive:         true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'right' },
        tooltip: {
          callbacks: {
            label: ctx => {
              const total = ctx.dataset.data.reduce((a, b) => a + b, 0);
              const pct   = ((ctx.parsed / total) * 100).toFixed(1);
              return ` ${ctx.label}: ${formatNumber(ctx.parsed)} (${pct}%)`;
            }
          }
        }
      }
    }
  });
}

/**
 * Render the traffic-over-time line chart.
 * @param {Array<{timestamp: string, count: number}>} timeSeries
 */
function _initTrafficLineChart(timeSeries) {
  const canvas = document.getElementById('chart-traffic-line');
  if (!canvas || !timeSeries) return;

  const labels = timeSeries.map(d => d.timestamp || d.label || '');
  const values = timeSeries.map(d => d.count);

  if (_charts.trafficLine) _charts.trafficLine.destroy();

  _charts.trafficLine = new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label:           'Traffic Volume',
        data:            values,
        borderColor:     CHART_COLORS.primary,
        backgroundColor: 'rgba(71,118,230,0.12)',
        borderWidth:     2,
        pointRadius:     3,
        pointHoverRadius: 5,
        fill:            true,
        tension:         0.35
      }]
    },
    options: {
      responsive:          true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { maxTicksLimit: 10, maxRotation: 30 } },
        y: { beginAtZero: true }
      },
      plugins: { legend: { display: false } }
    }
  });
}

/**
 * Render the protocol distribution bar chart.
 * @param {Object} counts - { 'TCP': 8900, 'UDP': 3200, … }
 */
function _initProtocolBarChart(counts) {
  const canvas = document.getElementById('chart-protocol-bar');
  if (!canvas || !counts) return;

  const labels = Object.keys(counts);
  const values = Object.values(counts);

  if (_charts.protocolBar) _charts.protocolBar.destroy();

  _charts.protocolBar = new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label:           'Packets',
        data:            values,
        backgroundColor: labels.map((_, i) =>
          Object.values(CHART_COLORS)[i % Object.keys(CHART_COLORS).length]
        ),
        borderRadius: 4,
        borderWidth:  0
      }]
    },
    options: {
      responsive:          true,
      maintainAspectRatio: false,
      scales: {
        y: { beginAtZero: true }
      },
      plugins: { legend: { display: false } }
    }
  });
}

/**
 * Re-render charts when underlying data changes (e.g. after filter applied).
 */
function updateCharts(newData) {
  if (newData.category_counts)  _initCategoryPieChart(newData.category_counts);
  if (newData.traffic_over_time) _initTrafficLineChart(newData.traffic_over_time);
  if (newData.protocol_counts)  _initProtocolBarChart(newData.protocol_counts);
}

// ─── Filters ─────────────────────────────────────────────────────────────────

function _wireFilters() {
  const categorySelect  = document.getElementById('filter-category');
  const protocolSelect  = document.getElementById('filter-protocol');
  const searchInput     = document.getElementById('filter-search');
  const applyBtn        = document.getElementById('btn-apply-filters');
  const clearBtn        = document.getElementById('btn-clear-filters');

  if (applyBtn) applyBtn.addEventListener('click', _applyFilters);
  if (clearBtn) clearBtn.addEventListener('click', () => {
    if (categorySelect) categorySelect.value = '';
    if (protocolSelect) protocolSelect.value = '';
    if (searchInput)    searchInput.value    = '';
    _applyFilters();
  });

  // Live search on keyup
  if (searchInput) {
    searchInput.addEventListener('keyup', _debounce(_applyFilters, 300));
  }
}

/**
 * Read filter controls and update _filteredRows + re-render table.
 */
function _applyFilters() {
  if (!_dashboardData || !_dashboardData.rows) return;

  const category = (document.getElementById('filter-category')?.value || '').toLowerCase();
  const protocol = (document.getElementById('filter-protocol')?.value || '').toLowerCase();
  const search   = (document.getElementById('filter-search')?.value   || '').toLowerCase();

  _filteredRows = _dashboardData.rows.filter(row => {
    if (category && (row.label || '').toLowerCase() !== category)    return false;
    if (protocol && (row.protocol || '').toLowerCase() !== protocol) return false;
    if (search) {
      const haystack = JSON.stringify(row).toLowerCase();
      if (!haystack.includes(search)) return false;
    }
    return true;
  });

  _currentPage = 1;
  _renderTable();
  _renderPagination();

  _setText('filter-result-count', `${formatNumber(_filteredRows.length)} records`);
}

// ─── Data Table ───────────────────────────────────────────────────────────────

/**
 * Render the current page of _filteredRows into #data-table-body.
 */
function _renderTable() {
  const tbody  = document.getElementById('data-table-body');
  const header = document.getElementById('data-table-header');
  if (!tbody) return;

  if (_filteredRows.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="100%" style="text-align:center;padding:2rem;color:#94a3b8;">
          No records match the current filters.
        </td>
      </tr>`;
    return;
  }

  // Build header from first row keys (if thead element is provided)
  const columns = Object.keys(_filteredRows[0]);
  if (header) {
    header.innerHTML = `<tr>${columns.map(c => `<th>${c}</th>`).join('')}</tr>`;
  }

  const start = (_currentPage - 1) * PAGE_SIZE;
  const slice = _filteredRows.slice(start, start + PAGE_SIZE);

  tbody.innerHTML = slice.map(row => {
    const label = (row.label || row.Label || '').trim();
    const color  = CATEGORY_COLORS[label] || CATEGORY_COLORS['Unknown'];
    return `<tr>${columns.map(col => {
      const val = row[col];
      if ((col === 'label' || col === 'Label') && label) {
        return `<td><span class="badge" style="background:${color}22;color:${color};padding:2px 8px;border-radius:999px;font-size:0.78rem;">${label}</span></td>`;
      }
      return `<td>${val ?? '—'}</td>`;
    }).join('')}</tr>`;
  }).join('');
}

/**
 * Render pagination controls below the table.
 */
function _renderPagination() {
  const container = document.getElementById('pagination');
  if (!container) return;

  const totalPages = Math.ceil(_filteredRows.length / PAGE_SIZE);
  if (totalPages <= 1) { container.innerHTML = ''; return; }

  const pages = _pagesToShow(_currentPage, totalPages);

  container.innerHTML = `
    <button class="page-btn" data-page="${_currentPage - 1}" ${_currentPage === 1 ? 'disabled' : ''}>‹ Prev</button>
    ${pages.map(p => p === '…'
      ? `<span style="padding:0.4rem 0.6rem;color:#94a3b8;">…</span>`
      : `<button class="page-btn ${p === _currentPage ? 'active' : ''}" data-page="${p}">${p}</button>`
    ).join('')}
    <button class="page-btn" data-page="${_currentPage + 1}" ${_currentPage === totalPages ? 'disabled' : ''}>Next ›</button>
  `;

  container.querySelectorAll('.page-btn:not([disabled])').forEach(btn => {
    btn.addEventListener('click', () => {
      _currentPage = parseInt(btn.dataset.page, 10);
      _renderTable();
      _renderPagination();
    });
  });
}

/**
 * Compute a compact list of page numbers with ellipsis.
 */
function _pagesToShow(current, total) {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const pages = [1];
  if (current > 3) pages.push('…');
  for (let p = Math.max(2, current - 1); p <= Math.min(total - 1, current + 1); p++) {
    pages.push(p);
  }
  if (current < total - 2) pages.push('…');
  pages.push(total);
  return pages;
}

// ─── Export Buttons ───────────────────────────────────────────────────────────

function _wireExportButtons() {
  const csvBtn  = document.getElementById('btn-export-csv');
  const jsonBtn = document.getElementById('btn-export-json');

  if (csvBtn) {
    csvBtn.addEventListener('click', () => {
      downloadCSV(_filteredRows, 'cybervision_dashboard');
      showToast('CSV download started.', 'success');
    });
  }

  if (jsonBtn) {
    jsonBtn.addEventListener('click', () => {
      downloadJSON(_dashboardData, 'cybervision_analysis');
      showToast('JSON download started.', 'success');
    });
  }
}

// ─── Utility ──────────────────────────────────────────────────────────────────

function _debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}
