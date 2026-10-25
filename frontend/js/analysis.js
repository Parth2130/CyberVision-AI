// CyberVision AI - Attack Analysis Page JS
// Category filtering, chart rendering, and table population

'use strict';

// ─── State ────────────────────────────────────────────────────────────────────
let _analysisData   = null;  // Full result object from localStorage
let _activeCategory = 'all'; // Current category filter
let _sortCol        = null;  // Column currently sorted
let _sortDir        = 'asc'; // 'asc' | 'desc'
let _currentPage    = 1;
const PAGE_SIZE     = 30;

// Chart instances
let _charts = {
  categoryBar:    null,
  featureRadar:   null,
  severityGauge:  null,
  topFlowsBar:    null
};

// ─── Bootstrap ────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  setActiveNav('analysis');

  _analysisData = loadAnalysis();
  if (!_analysisData) {
    _showNoData();
    return;
  }

  _buildCategoryFilterButtons();
  _renderCharts();
  _renderSeverityBadges();
  _renderTable();
  _renderPagination();
  _wireExportButtons();
});

// ─── No-data Guard ────────────────────────────────────────────────────────────

function _showNoData() {
  const main = document.getElementById('analysis-main');
  if (main) {
    renderEmptyState(
      main,
      'No analysis data found. Please upload and analyse a dataset first.',
      '🔍',
      'Upload Dataset',
      'upload.html'
    );
  }
}

// ─── Category Filter Buttons ─────────────────────────────────────────────────

/**
 * Build one filter button per category plus an "All" button.
 * Buttons are injected into #category-filter-bar.
 */
function _buildCategoryFilterButtons() {
  const bar = document.getElementById('category-filter-bar');
  if (!bar || !_analysisData?.category_counts) return;

  const categories = Object.keys(_analysisData.category_counts);

  const allBtn = _makeFilterBtn('All', 'all', true);
  bar.innerHTML = '';
  bar.appendChild(allBtn);

  categories.forEach(cat => {
    bar.appendChild(_makeFilterBtn(cat, cat, false));
  });

  bar.addEventListener('click', e => {
    const btn = e.target.closest('[data-category]');
    if (!btn) return;

    bar.querySelectorAll('[data-category]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    _activeCategory = btn.dataset.category;
    _currentPage    = 1;
    _renderTable();
    _renderPagination();
    _renderCharts();
  });
}

function _makeFilterBtn(label, value, isActive) {
  const btn = document.createElement('button');
  btn.textContent      = label;
  btn.dataset.category = value;
  btn.className        = `filter-btn${isActive ? ' active' : ''}`;

  const color = CATEGORY_COLORS[value] || CHART_COLORS.primary;
  if (!isActive) {
    btn.style.borderColor = color;
    btn.style.color       = color;
  }

  // Show count badge
  const count = _analysisData?.category_counts?.[value];
  if (count !== undefined) {
    const badge = document.createElement('span');
    badge.className   = 'filter-badge';
    badge.textContent = formatNumber(count);
    btn.appendChild(badge);
  }

  return btn;
}

// ─── Charts ───────────────────────────────────────────────────────────────────

/** Render / re-render all analysis charts. */
function _renderCharts() {
  _renderCategoryBarChart();
  _renderFeatureRadarChart();
  _renderTopFlowsChart();
}

/**
 * Horizontal bar chart — attack category breakdown.
 */
function _renderCategoryBarChart() {
  const canvas = document.getElementById('chart-category-bar');
  if (!canvas || !_analysisData?.category_counts) return;

  const filtered = _getFilteredCounts();
  const labels   = Object.keys(filtered);
  const values   = Object.values(filtered);
  const colors   = labels.map(l => CATEGORY_COLORS[l] || CATEGORY_COLORS['Unknown']);

  if (_charts.categoryBar) _charts.categoryBar.destroy();

  _charts.categoryBar = new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label:           'Records',
        data:            values,
        backgroundColor: colors.map(c => `${c}cc`),
        borderColor:     colors,
        borderWidth:     1,
        borderRadius:    4
      }]
    },
    options: {
      indexAxis:           'y',
      responsive:          true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ` ${formatNumber(ctx.parsed.x)} records`
          }
        }
      },
      scales: {
        x: { beginAtZero: true }
      }
    }
  });
}

/**
 * Radar chart — mean feature values per selected category.
 */
function _renderFeatureRadarChart() {
  const canvas = document.getElementById('chart-feature-radar');
  if (!canvas || !_analysisData?.feature_stats) return;

  const stats  = _analysisData.feature_stats;
  const labels = Object.keys(stats);
  if (!labels.length) return;

  // Normalise values 0–1 for readability across mixed-scale features
  const maxVals = labels.map(f => Math.max(...Object.values(stats[f]).map(v => Math.abs(v))) || 1);
  const cats    = _activeCategory === 'all'
    ? Object.keys(_analysisData.category_counts).slice(0, 4)
    : [_activeCategory];

  const datasets = cats.map((cat, i) => {
    const color = CATEGORY_COLORS[cat] || Object.values(CHART_COLORS)[i];
    const data  = labels.map((f, idx) => {
      const val = stats[f]?.[cat] ?? 0;
      return +(val / maxVals[idx]).toFixed(3);
    });
    return {
      label:           cat,
      data,
      borderColor:     color,
      backgroundColor: `${color}33`,
      borderWidth:     2,
      pointBackgroundColor: color
    };
  });

  if (_charts.featureRadar) _charts.featureRadar.destroy();

  _charts.featureRadar = new Chart(canvas, {
    type: 'radar',
    data: { labels, datasets },
    options: {
      responsive:          true,
      maintainAspectRatio: false,
      scales: {
        r: {
          beginAtZero: true,
          max:         1,
          grid:    { color: 'rgba(148,163,184,0.15)' },
          ticks:   { display: false },
          pointLabels: { color: '#cbd5e1', font: { size: 11 } }
        }
      }
    }
  });
}

/**
 * Bar chart — top 10 flows by packet count or byte volume.
 */
function _renderTopFlowsChart() {
  const canvas = document.getElementById('chart-top-flows');
  if (!canvas || !_analysisData?.top_flows) return;

  const flows  = _analysisData.top_flows.slice(0, 10);
  const labels = flows.map(f => `${f.src_ip || '?'} → ${f.dst_ip || '?'}`);
  const values = flows.map(f => f.total_bytes || f.packet_count || 0);
  const colors = flows.map(f => CATEGORY_COLORS[f.label] || CHART_COLORS.primary);

  if (_charts.topFlowsBar) _charts.topFlowsBar.destroy();

  _charts.topFlowsBar = new Chart(canvas, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label:           'Bytes',
        data:            values,
        backgroundColor: colors.map(c => `${c}cc`),
        borderColor:     colors,
        borderWidth:     1,
        borderRadius:    4
      }]
    },
    options: {
      responsive:          true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: ctx => ` ${formatBytes(ctx.parsed.y)}`
          }
        }
      },
      scales: {
        x: { ticks: { maxRotation: 35, font: { size: 10 } } },
        y: {
          beginAtZero: true,
          ticks: { callback: v => formatBytes(v) }
        }
      }
    }
  });
}

// ─── Severity Badges ──────────────────────────────────────────────────────────

/** Render risk/severity summary chips. */
function _renderSeverityBadges() {
  const container = document.getElementById('severity-badges');
  if (!container || !_analysisData?.category_counts) return;

  const severityMap = {
    'BENIGN':      { level: 'None',     color: CHART_COLORS.success  },
    'DoS Hulk':   { level: 'Critical', color: CHART_COLORS.danger   },
    'DDoS':       { level: 'High',     color: CHART_COLORS.warning  },
    'PortScan':   { level: 'Medium',   color: CHART_COLORS.secondary},
    'Brute Force':{ level: 'High',     color: CHART_COLORS.warning  },
    'Botnet':     { level: 'Critical', color: CHART_COLORS.danger   },
    'Unknown':    { level: 'Unknown',  color: '#94a3b8'             }
  };

  container.innerHTML = Object.entries(_analysisData.category_counts).map(([cat, count]) => {
    const sev   = severityMap[cat] || severityMap['Unknown'];
    return `
      <div class="severity-chip" style="border-color:${sev.color}22;background:${sev.color}11">
        <span class="sev-dot" style="background:${sev.color}"></span>
        <span class="sev-cat">${cat}</span>
        <span class="sev-level" style="color:${sev.color}">${sev.level}</span>
        <span class="sev-count">${formatNumber(count)}</span>
      </div>`;
  }).join('');
}

// ─── Data Table ───────────────────────────────────────────────────────────────

function _renderTable() {
  const tbody  = document.getElementById('analysis-table-body');
  const thead  = document.getElementById('analysis-table-head');
  if (!tbody) return;

  const rows = _getFilteredRows();

  if (!rows.length) {
    tbody.innerHTML = `
      <tr><td colspan="100%" style="text-align:center;padding:2rem;color:#94a3b8;">
        No records for this category.
      </td></tr>`;
    return;
  }

  const columns = Object.keys(rows[0]);

  // Build header with sortable columns
  if (thead) {
    thead.innerHTML = `<tr>${columns.map(col => {
      const arrow = col === _sortCol ? (_sortDir === 'asc' ? ' ↑' : ' ↓') : '';
      return `<th class="sortable-col" data-col="${col}">${col}${arrow}</th>`;
    }).join('')}</tr>`;

    thead.querySelectorAll('.sortable-col').forEach(th => {
      th.style.cursor = 'pointer';
      th.addEventListener('click', () => _sortBy(th.dataset.col));
    });
  }

  const start  = (_currentPage - 1) * PAGE_SIZE;
  const sorted = _sortRows(rows);
  const slice  = sorted.slice(start, start + PAGE_SIZE);

  tbody.innerHTML = slice.map(row => {
    const label  = row.label || row.Label || '';
    const color  = CATEGORY_COLORS[label.trim()] || CATEGORY_COLORS['Unknown'];
    return `<tr>${columns.map(col => {
      const val = row[col];
      if ((col === 'label' || col === 'Label') && label) {
        return `<td><span class="badge" style="background:${color}22;color:${color};padding:2px 8px;border-radius:999px;font-size:0.78rem;">${label}</span></td>`;
      }
      const num = parseFloat(val);
      if (!isNaN(num) && String(val).trim() !== '') {
        return `<td style="text-align:right;font-variant-numeric:tabular-nums">${num.toLocaleString(undefined, { maximumFractionDigits: 4 })}</td>`;
      }
      return `<td>${val ?? '—'}</td>`;
    }).join('')}</tr>`;
  }).join('');

  // Row count indicator
  const countEl = document.getElementById('table-row-count');
  if (countEl) countEl.textContent = `${formatNumber(rows.length)} records`;
}

function _renderPagination() {
  const container = document.getElementById('analysis-pagination');
  if (!container) return;

  const total = Math.ceil(_getFilteredRows().length / PAGE_SIZE);
  if (total <= 1) { container.innerHTML = ''; return; }

  const pages = _pagesToShow(_currentPage, total);

  container.innerHTML = `
    <button class="page-btn" data-page="${_currentPage - 1}" ${_currentPage === 1 ? 'disabled' : ''}>‹ Prev</button>
    ${pages.map(p => p === '…'
      ? `<span style="padding:0.4rem 0.6rem;color:#94a3b8;">…</span>`
      : `<button class="page-btn ${p === _currentPage ? 'active' : ''}" data-page="${p}">${p}</button>`
    ).join('')}
    <button class="page-btn" data-page="${_currentPage + 1}" ${_currentPage === total ? 'disabled' : ''}>Next ›</button>
  `;

  container.querySelectorAll('.page-btn:not([disabled])').forEach(btn => {
    btn.addEventListener('click', () => {
      _currentPage = parseInt(btn.dataset.page, 10);
      _renderTable();
      _renderPagination();
    });
  });
}

// ─── Sorting ──────────────────────────────────────────────────────────────────

function _sortBy(col) {
  if (_sortCol === col) {
    _sortDir = _sortDir === 'asc' ? 'desc' : 'asc';
  } else {
    _sortCol = col;
    _sortDir = 'asc';
  }
  _currentPage = 1;
  _renderTable();
  _renderPagination();
}

function _sortRows(rows) {
  if (!_sortCol) return rows;
  return [...rows].sort((a, b) => {
    const va = a[_sortCol];
    const vb = b[_sortCol];
    const na = parseFloat(va), nb = parseFloat(vb);
    const cmp = (!isNaN(na) && !isNaN(nb))
      ? na - nb
      : String(va ?? '').localeCompare(String(vb ?? ''));
    return _sortDir === 'asc' ? cmp : -cmp;
  });
}

// ─── Filter Helpers ───────────────────────────────────────────────────────────

function _getFilteredRows() {
  const rows = _analysisData?.rows || [];
  if (_activeCategory === 'all') return rows;
  return rows.filter(r =>
    (r.label || r.Label || '').trim() === _activeCategory
  );
}

function _getFilteredCounts() {
  const counts = _analysisData?.category_counts || {};
  if (_activeCategory === 'all') return counts;
  return { [_activeCategory]: counts[_activeCategory] || 0 };
}

// ─── Export ───────────────────────────────────────────────────────────────────

function _wireExportButtons() {
  const csvBtn = document.getElementById('btn-export-analysis-csv');
  const jsonBtn = document.getElementById('btn-export-analysis-json');

  if (csvBtn) {
    csvBtn.addEventListener('click', () => {
      downloadCSV(_getFilteredRows(), `cybervision_analysis_${_activeCategory}`);
      showToast('CSV download started.', 'success');
    });
  }

  if (jsonBtn) {
    jsonBtn.addEventListener('click', () => {
      downloadJSON(_analysisData, 'cybervision_analysis_full');
      showToast('JSON download started.', 'success');
    });
  }
}

// ─── Pagination Helper ────────────────────────────────────────────────────────

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
