/**
 * CYBERVISION AI - Cybersecurity Analytics & Visualization Platform
 * Frontend SPA Application Script
 */

// ==============================================================================
// Global Application State
// ==============================================================================
const state = {
  activeSection: 'overview',
  dataset: null,
  table: {
    allRows: [],
    filteredRows: [],
    columns: [],
    currentPage: 1,
    pageSize: 15,
    sortCol: null,
    sortAsc: true,
    filterText: '',
  },
  charts: {},
  settings: {
    theme: 'indigo',
    animation: 'normal',
  },
  modalSelectedFile: null,
};

// Accessible Color Palettes for Strict Light Theme Charts
const CHART_PALETTES = {
  primary: ['#635BFF', '#8B5CF6', '#3B82F6', '#10B981', '#F59E0B', '#DC2626', '#06B6D4', '#EC4899', '#84CC16'],
  severity: {
    Critical: '#DC2626',
    High: '#F59E0B',
    Medium: '#8B5CF6',
    Low: '#10B981',
    Informational: '#3B82F6',
    Unknown: '#9CA3AF'
  },
  protocols: {
    TCP: '#635BFF',
    UDP: '#06B6D4',
    ICMP: '#F59E0B',
    Other: '#9CA3AF'
  }
};

// ==============================================================================
// Helper Functions & Utilities
// ==============================================================================

/** Escape raw HTML to prevent injection */
function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/** Format numbers with localized commas */
function formatNum(num) {
  if (num === null || num === undefined || isNaN(num)) return 'Not available';
  return Number(num).toLocaleString();
}

/** Show Toast Notification */
function showToast(message, type = 'info', duration = 4000) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let iconClass = 'fa-solid fa-circle-info';
  if (type === 'success') iconClass = 'fa-solid fa-circle-check';
  if (type === 'error') iconClass = 'fa-solid fa-circle-exclamation';
  if (type === 'warning') iconClass = 'fa-solid fa-triangle-exclamation';

  toast.innerHTML = `
    <i class="${iconClass}"></i>
    <div>${escapeHtml(message)}</div>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease-out';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

/** Add Session Notification Log Entry */
function logSessionActivity(title, desc) {
  const list = document.getElementById('notificationList');
  if (!list) return;

  const item = document.createElement('div');
  item.className = 'notification-item';
  item.innerHTML = `
    <i class="fa-solid fa-bell"></i>
    <div>
      <strong>${escapeHtml(title)}</strong>
      <div style="font-size:0.7rem; color:var(--text-muted);">${escapeHtml(desc)}</div>
    </div>
  `;
  list.insertBefore(item, list.firstChild);
}

/** Show / Hide Global Loading Spinner */
function setLoading(active, title = 'Analyzing Dataset...', subtitle = 'Processing CSV records and generating metrics') {
  const overlay = document.getElementById('loadingOverlay');
  if (!overlay) return;

  if (active) {
    document.getElementById('loadingTitle').textContent = title;
    document.getElementById('loadingSubtitle').textContent = subtitle;
    overlay.classList.add('active');
  } else {
    overlay.classList.remove('active');
  }
}

/** Safe destruction and registration of Chart.js instances */
function createOrUpdateChart(chartId, config) {
  const canvas = document.getElementById(chartId);
  if (!canvas) return null;

  if (state.charts[chartId]) {
    state.charts[chartId].destroy();
    delete state.charts[chartId];
  }

  // Adjust animation duration based on user preference
  const animSetting = state.settings.animation;
  let duration = 750;
  if (animSetting === 'fast') duration = 300;
  if (animSetting === 'none') duration = 0;

  if (!config.options) config.options = {};
  config.options.animation = { duration: duration };
  config.options.responsive = true;
  config.options.maintainAspectRatio = false;

  try {
    const ctx = canvas.getContext('2d');
    const newChart = new Chart(ctx, config);
    state.charts[chartId] = newChart;
    return newChart;
  } catch (err) {
    console.error(`Error initializing chart ${chartId}:`, err);
    return null;
  }
}

/** Export chart canvas as PNG image */
function exportChart(chartId) {
  const canvas = document.getElementById(chartId);
  if (!canvas) return;

  try {
    const imageUri = canvas.toDataURL('image/png');
    const link = document.createElement('a');
    link.download = `${chartId}_cybervision.png`;
    link.href = imageUri;
    link.click();
    showToast(`Chart exported as ${link.download}`, 'success');
  } catch (e) {
    showToast('Failed to export chart image', 'error');
  }
}

// ==============================================================================
// Section Navigation & Routing
// ==============================================================================

const SECTION_TITLES = {
  overview: { title: 'Dashboard Overview', subtitle: 'Cybersecurity Telemetry & Event Analytics' },
  explorer: { title: 'Dataset Explorer', subtitle: 'Interactive Data Inspection & Filtering' },
  threats: { title: 'Threat Analytics', subtitle: 'Threat Classification & Anomaly Heuristics' },
  traffic: { title: 'Network Traffic Analysis', subtitle: 'Host Volumetrics, Protocols & Port Probing' },
  visualizations: { title: 'Data Visualizations Gallery', subtitle: 'Interactive Cybersecurity Charts' },
  reports: { title: 'Security Reports & Audits', subtitle: 'Structured JSON & CSV Analysis Exports' },
  about: { title: 'About CyberVision AI', subtitle: 'Architecture, Methodology & System Specifications' },
  settings: { title: 'Platform Settings', subtitle: 'Theme Accents, Chart Preferences & Dataset Session' },
};

function navigateTo(sectionId) {
  if (!SECTION_TITLES[sectionId]) sectionId = 'overview';
  state.activeSection = sectionId;

  // Update Sidebar Links
  document.querySelectorAll('.nav-link').forEach(link => {
    if (link.getAttribute('data-section') === sectionId) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });

  // Switch Sections
  document.querySelectorAll('.dashboard-section').forEach(sec => {
    sec.classList.remove('active-section');
  });
  const targetSection = document.getElementById(`section-${sectionId}`);
  if (targetSection) targetSection.classList.add('active-section');

  // Update Header Titles
  const meta = SECTION_TITLES[sectionId];
  document.getElementById('topNavTitle').textContent = meta.title;
  document.getElementById('topNavSubtitle').textContent = meta.subtitle;

  // Close Mobile Sidebar if Open
  closeMobileSidebar();

  // Scroll to Top
  window.scrollTo({ top: 0, behavior: 'smooth' });

  // Update URL Hash without triggering full reload
  if (window.location.hash !== `#${sectionId}`) {
    history.pushState(null, '', `#${sectionId}`);
  }

  // Trigger charts resize in active section
  setTimeout(() => {
    Object.values(state.charts).forEach(c => c && c.resize && c.resize());
  }, 100);
}

function openMobileSidebar() {
  document.getElementById('sidebar').classList.add('mobile-open');
  document.getElementById('sidebarOverlay').classList.add('mobile-open');
}

function closeMobileSidebar() {
  document.getElementById('sidebar').classList.remove('mobile-open');
  document.getElementById('sidebarOverlay').classList.remove('mobile-open');
}

// ==============================================================================
// Data Loading & API Calls
// ==============================================================================

/** Load Built-In Sample Dataset */
async function loadSampleDataset() {
  setLoading(true, 'Loading Sample Dataset...', 'Ingesting synthetic cybersecurity demonstration records');
  try {
    const formData = new FormData();
    formData.append('use_sample', 'true');

    const response = await fetch('/api/analyze', {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || 'Failed to load sample dataset');
    }

    const payload = await response.json();
    handleAnalysisSuccess(payload.data);
    showToast('Synthetic sample dataset loaded successfully!', 'success');
    logSessionActivity('Sample Dataset Loaded', `${payload.data.overview_metrics.total_records} demonstration records ingested`);
  } catch (error) {
    console.error('Sample loading error:', error);
    showToast(`Error: ${error.message}`, 'error');
  } finally {
    setLoading(false);
  }
}

/** Upload Custom CSV File */
async function uploadCsvFile(file) {
  if (!file) return;

  if (!file.name.toLowerCase().endsWith('.csv')) {
    showToast('Unsupported file type. Please upload a CSV (.csv) file.', 'error');
    return;
  }

  if (file.size > 50 * 1024 * 1024) {
    showToast('File size exceeds the 50MB maximum allowable limit.', 'error');
    return;
  }

  setLoading(true, 'Analyzing CSV Dataset...', `Parsing ${file.name} and detecting security columns`);
  try {
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('/api/analyze', {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.detail || 'Upload failed');
    }

    const payload = await response.json();
    handleAnalysisSuccess(payload.data);
    showToast(`Dataset '${file.name}' analyzed successfully!`, 'success');
    logSessionActivity('File Uploaded', `${file.name} (${payload.data.overview_metrics.total_records} rows) analyzed`);
  } catch (error) {
    console.error('Upload error:', error);
    showToast(`Upload failed: ${error.message}`, 'error');
  } finally {
    setLoading(false);
  }
}

/** Clear Current Active Dataset */
async function clearActiveDataset() {
  setLoading(true, 'Clearing Session...', 'Resetting active dataset state');
  try {
    const response = await fetch('/api/clear', { method: 'POST' });
    if (!response.ok) throw new Error('Failed to clear dataset on server');

    state.dataset = null;
    state.table.allRows = [];
    state.table.filteredRows = [];
    state.table.columns = [];
    
    // Destroy all active charts
    Object.keys(state.charts).forEach(id => {
      if (state.charts[id]) {
        state.charts[id].destroy();
        delete state.charts[id];
      }
    });

    renderEmptyDatasetState();
    showToast('Active dataset cleared successfully.', 'info');
    logSessionActivity('Dataset Cleared', 'Active dataset removed from session memory');
  } catch (error) {
    showToast(`Failed to clear dataset: ${error.message}`, 'error');
  } finally {
    setLoading(false);
    closeClearModal();
  }
}

/** Download CSV Analysis Summary Report */
async function downloadCsvSummaryReport() {
  if (!state.dataset) {
    showToast('No active dataset loaded to generate report.', 'warning');
    return;
  }

  try {
    const response = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format: 'csv' }),
    });

    if (!response.ok) throw new Error('Report generation failed');

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybervision_summary_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    showToast('CSV analysis report downloaded successfully!', 'success');
  } catch (error) {
    showToast(`Report download failed: ${error.message}`, 'error');
  }
}

/** Download Structured JSON Audit Report */
async function downloadJsonAuditReport() {
  if (!state.dataset) {
    showToast('No active dataset loaded to generate report.', 'warning');
    return;
  }

  try {
    const response = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ format: 'json' }),
    });

    if (!response.ok) throw new Error('Report generation failed');

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cybervision_audit_${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    showToast('JSON audit report downloaded successfully!', 'success');
  } catch (error) {
    showToast(`Report download failed: ${error.message}`, 'error');
  }
}

/** Download Pre-Packaged Sample CSV File */
function downloadSampleCsvFile() {
  window.open('/api/sample?download=true', '_blank');
  showToast('Downloading sample_cybersecurity.csv...', 'info');
}

// ==============================================================================
// State Update & UI Render Handlers
// ==============================================================================

function handleAnalysisSuccess(data) {
  state.dataset = data;
  state.table.allRows = data.preview_records || [];
  state.table.filteredRows = [...state.table.allRows];
  state.table.columns = data.columns || [];
  state.table.currentPage = 1;
  state.table.filterText = '';

  // Update Top Bar Pill
  const pill = document.getElementById('datasetStatusPill');
  const pillText = document.getElementById('datasetStatusText');
  if (pill && pillText) {
    pill.classList.add('active');
    const isSample = data.metadata.is_sample;
    pillText.textContent = isSample 
      ? `Sample Loaded (${formatNum(data.overview_metrics.total_records)} rows)`
      : `${escapeHtml(data.metadata.filename)} (${formatNum(data.overview_metrics.total_records)} rows)`;
  }

  // Show Clear button in Overview
  const clearBtn = document.getElementById('overviewClearBtn');
  if (clearBtn) clearBtn.style.display = 'inline-flex';

  // Render All Section Views
  renderOverview(data);
  renderExplorer();
  renderThreatAnalytics(data);
  renderTrafficAnalysis(data);
  renderVisualizations(data);
  renderReports(data);
  renderSettingsInfo(data);
}

function renderEmptyDatasetState() {
  // Reset Top Nav Status Pill
  const pill = document.getElementById('datasetStatusPill');
  const pillText = document.getElementById('datasetStatusText');
  if (pill && pillText) {
    pill.classList.remove('active');
    pillText.textContent = 'No Dataset Loaded';
  }

  // Hide Clear button
  const clearBtn = document.getElementById('overviewClearBtn');
  if (clearBtn) clearBtn.style.display = 'none';

  // Overview metrics
  document.getElementById('cardTotalRecords').textContent = '--';
  document.getElementById('cardSourceIps').textContent = '--';
  document.getElementById('cardDestIps').textContent = '--';
  document.getElementById('cardHighSeverity').textContent = '--';
  document.getElementById('cardMissingValues').textContent = '--';
  document.getElementById('cardSuspiciousRecords').textContent = '--';

  document.getElementById('bannerFilename').textContent = 'No Dataset Active';
  document.getElementById('bannerFileSize').textContent = '0 KB';
  document.getElementById('bannerRowsCols').textContent = '0 records, 0 columns';
  document.getElementById('bannerAnalyzedAt').textContent = 'Awaiting upload';
  document.getElementById('detectedColumnPills').innerHTML = '<span class="col-pill missing">No columns detected</span>';

  // Table reset
  document.getElementById('datasetTableHead').innerHTML = '<tr><th>No Data</th></tr>';
  document.getElementById('datasetTableBody').innerHTML = '<tr><td style="text-align:center; padding:30px; color:var(--text-muted);">Please upload a CSV dataset or click "Load Sample" to explore records.</td></tr>';
  document.getElementById('tablePaginationInfo').textContent = 'Showing 0 records';

  // Clear charts
  ['chartOverviewAttacks', 'chartOverviewProtocols', 'chartThreatSeverity', 'chartThreatAttacks',
   'chartTrafficTimeline', 'chartTopSources', 'chartTopPorts',
   'vizChart1', 'vizChart2', 'vizChart3', 'vizChart4', 'vizChart5', 'vizChart6', 'vizChart7', 'vizChart8'
  ].forEach(id => {
    if (state.charts[id]) {
      state.charts[id].destroy();
      delete state.charts[id];
    }
  });

  // Settings
  document.getElementById('settingsDatasetName').textContent = 'None';
  document.getElementById('settingsDatasetSize').textContent = '0 KB';
}

// ------------------------------------------------------------------------------
// 1. Overview Rendering
// ------------------------------------------------------------------------------
function renderOverview(data) {
  const m = data.overview_metrics;

  // Summary Metrics Cards
  document.getElementById('cardTotalRecords').textContent = formatNum(m.total_records);
  document.getElementById('cardSourceIps').textContent = m.unique_source_ips !== null ? formatNum(m.unique_source_ips) : 'Not available';
  document.getElementById('cardDestIps').textContent = m.unique_dest_ips !== null ? formatNum(m.unique_dest_ips) : 'Not available';
  document.getElementById('cardHighSeverity').textContent = m.high_severity_events !== null ? formatNum(m.high_severity_events) : 'Not available';
  document.getElementById('cardMissingValues').textContent = formatNum(m.missing_values_count);
  document.getElementById('cardSuspiciousRecords').textContent = m.suspicious_records_count !== null ? formatNum(m.suspicious_records_count) : 'Not available';

  // Dataset Profile Banner
  document.getElementById('bannerFilename').textContent = data.metadata.filename + (data.metadata.is_sample ? ' (Synthetic Demonstration)' : '');
  document.getElementById('bannerFileSize').textContent = data.metadata.file_size_formatted;
  document.getElementById('bannerRowsCols').textContent = `${formatNum(m.total_records)} rows, ${formatNum(m.total_columns)} columns`;
  document.getElementById('bannerAnalyzedAt').textContent = data.metadata.analyzed_at;

  // Detected Columns Pills
  const pillsContainer = document.getElementById('detectedColumnPills');
  pillsContainer.innerHTML = '';
  Object.entries(data.detected_columns).forEach(([key, matchedCol]) => {
    const span = document.createElement('span');
    span.className = `col-pill ${matchedCol ? 'detected' : 'missing'}`;
    span.textContent = matchedCol ? `${key}: ${matchedCol}` : `${key} (absent)`;
    pillsContainer.appendChild(span);
  });

  // Overview Attack Chart
  if (data.threat_analytics.available && data.threat_analytics.attack_types.available) {
    const topAtks = data.threat_analytics.attack_types.top_attacks;
    createOrUpdateChart('chartOverviewAttacks', {
      type: 'bar',
      data: {
        labels: topAtks.map(a => a.attack),
        datasets: [{
          label: 'Event Count',
          data: topAtks.map(a => a.count),
          backgroundColor: CHART_PALETTES.primary.slice(0, topAtks.length),
          borderRadius: 6,
        }]
      },
      options: {
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, grid: { color: '#F1F5F9' } } }
      }
    });
  }

  // Overview Protocol Chart
  if (data.traffic_analysis.available && data.traffic_analysis.protocols.available) {
    const protoData = data.traffic_analysis.protocols.breakdown;
    createOrUpdateChart('chartOverviewProtocols', {
      type: 'doughnut',
      data: {
        labels: Object.keys(protoData),
        datasets: [{
          data: Object.values(protoData),
          backgroundColor: Object.keys(protoData).map(k => CHART_PALETTES.protocols[k] || '#8B5CF6'),
          borderWidth: 2,
        }]
      },
      options: {
        plugins: { legend: { position: 'right' } },
        cutout: '65%'
      }
    });
  }

  // Quality Findings List
  const qContainer = document.getElementById('qualityFindingsContainer');
  qContainer.innerHTML = '';
  data.quality_findings.forEach(q => {
    const div = document.createElement('div');
    div.className = 'threat-finding-card';
    div.style.borderLeftColor = q.status === 'healthy' ? 'var(--success)' : 'var(--warning)';
    div.innerHTML = `
      <div class="finding-icon" style="background:${q.status === 'healthy' ? 'var(--mint)' : 'var(--warning-bg)'}; color:${q.status === 'healthy' ? 'var(--mint-dark)' : 'var(--warning)'};">
        <i class="fa-solid ${q.status === 'healthy' ? 'fa-check' : 'fa-triangle-exclamation'}"></i>
      </div>
      <div class="finding-content">
        <h4>${escapeHtml(q.title)}</h4>
        <p>${escapeHtml(q.desc)}</p>
      </div>
    `;
    qContainer.appendChild(div);
  });
}

// ------------------------------------------------------------------------------
// 2. Dataset Explorer Rendering & Pagination
// ------------------------------------------------------------------------------
function renderExplorer() {
  const table = state.table;
  const thead = document.getElementById('datasetTableHead');
  const tbody = document.getElementById('datasetTableBody');

  if (!thead || !tbody) return;

  if (table.columns.length === 0) {
    thead.innerHTML = '<tr><th>No Columns</th></tr>';
    tbody.innerHTML = '<tr><td style="text-align:center; padding:20px;">No dataset loaded.</td></tr>';
    return;
  }

  // Table Headers with click-to-sort
  let headHtml = '<tr><th style="width:50px;">#</th>';
  table.columns.forEach(col => {
    const isSorted = table.sortCol === col;
    const sortIcon = isSorted ? (table.sortAsc ? ' <i class="fa-solid fa-sort-up"></i>' : ' <i class="fa-solid fa-sort-down"></i>') : '';
    headHtml += `<th onclick="sortTableBy('${escapeHtml(col)}')">${escapeHtml(col)}${sortIcon}</th>`;
  });
  headHtml += '</tr>';
  thead.innerHTML = headHtml;

  // Pagination Slice
  const totalRows = table.filteredRows.length;
  const totalPages = Math.max(1, Math.ceil(totalRows / table.pageSize));
  if (table.currentPage > totalPages) table.currentPage = totalPages;
  const startIdx = (table.currentPage - 1) * table.pageSize;
  const endIdx = Math.min(startIdx + table.pageSize, totalRows);
  const pageRows = table.filteredRows.slice(startIdx, endIdx);

  // Table Rows (HTML-escaped for safety)
  if (pageRows.length === 0) {
    tbody.innerHTML = `<tr><td colspan="${table.columns.length + 1}" style="text-align:center; padding:30px; color:var(--text-muted);">No records match your filter criteria.</td></tr>`;
  } else {
    let bodyHtml = '';
    pageRows.forEach((row, i) => {
      bodyHtml += `<tr><td style="color:var(--text-light); font-size:0.75rem;">${startIdx + i + 1}</td>`;
      table.columns.forEach(col => {
        const val = row[col];
        let displayVal = escapeHtml(val !== null && val !== undefined ? val : '');

        // Severity tag styling
        if (col.toLowerCase() === 'severity') {
          const s = String(val).toLowerCase();
          if (s === 'critical') displayVal = `<span class="badge-tag badge-critical">${displayVal}</span>`;
          else if (s === 'high') displayVal = `<span class="badge-tag badge-high">${displayVal}</span>`;
          else if (s === 'medium') displayVal = `<span class="badge-tag badge-medium">${displayVal}</span>`;
          else if (s === 'low') displayVal = `<span class="badge-tag badge-low">${displayVal}</span>`;
          else displayVal = `<span class="badge-tag badge-info">${displayVal}</span>`;
        }

        bodyHtml += `<td>${displayVal}</td>`;
      });
      bodyHtml += '</tr>';
    });
    tbody.innerHTML = bodyHtml;
  }

  // Update Pagination Info
  document.getElementById('tablePaginationInfo').textContent = `Showing ${totalRows === 0 ? 0 : startIdx + 1} to ${endIdx} of ${formatNum(totalRows)} records`;
  document.getElementById('paginationCurrentPage').textContent = `Page ${table.currentPage} of ${totalPages}`;

  // Disable / Enable pagination buttons
  document.getElementById('paginationFirst').disabled = table.currentPage === 1;
  document.getElementById('paginationPrev').disabled = table.currentPage === 1;
  document.getElementById('paginationNext').disabled = table.currentPage >= totalPages;
  document.getElementById('paginationLast').disabled = table.currentPage >= totalPages;

  // Column Dtypes Pills
  if (state.dataset && state.dataset.column_dtypes) {
    const dtypesContainer = document.getElementById('columnDtypesContainer');
    dtypesContainer.innerHTML = '';
    Object.entries(state.dataset.column_dtypes).forEach(([c, dt]) => {
      const p = document.createElement('div');
      p.className = 'col-pill';
      p.style.background = '#FFFFFF';
      p.style.border = '1px solid var(--border)';
      p.style.color = 'var(--text-main)';
      p.innerHTML = `<strong>${escapeHtml(c)}</strong>: <span style="color:var(--primary); font-family:monospace;">${escapeHtml(dt)}</span>`;
      dtypesContainer.appendChild(p);
    });
  }
}

/** Sort dataset explorer table by column */
function sortTableBy(col) {
  const table = state.table;
  if (table.sortCol === col) {
    table.sortAsc = !table.sortAsc;
  } else {
    table.sortCol = col;
    table.sortAsc = true;
  }

  table.filteredRows.sort((a, b) => {
    let valA = a[col];
    let valB = b[col];

    if (valA === null || valA === undefined) return 1;
    if (valB === null || valB === undefined) return -1;

    if (typeof valA === 'number' && typeof valB === 'number') {
      return table.sortAsc ? valA - valB : valB - valA;
    }

    valA = String(valA).toLowerCase();
    valB = String(valB).toLowerCase();
    if (valA < valB) return table.sortAsc ? -1 : 1;
    if (valA > valB) return table.sortAsc ? 1 : -1;
    return 0;
  });

  renderExplorer();
}

/** Filter rows by search term */
function filterTableRows(text) {
  state.table.filterText = text.toLowerCase().trim();
  state.table.currentPage = 1;

  if (!state.table.filterText) {
    state.table.filteredRows = [...state.table.allRows];
  } else {
    state.table.filteredRows = state.table.allRows.filter(row => {
      return Object.values(row).some(val => {
        if (val === null || val === undefined) return false;
        return String(val).toLowerCase().includes(state.table.filterText);
      });
    });
  }

  renderExplorer();
}

// ------------------------------------------------------------------------------
// 3. Threat Analytics Rendering
// ------------------------------------------------------------------------------
function renderThreatAnalytics(data) {
  const threatNotice = document.getElementById('threatNoticeContainer');
  const t = data.threat_analytics;

  if (!t.available) {
    threatNotice.innerHTML = `
      <div class="empty-visual-state">
        <i class="fa-solid fa-shield-halved"></i>
        <h4>Threat Analytics Unavailable for This Dataset</h4>
        <p>No threat-specific columns (such as attack_type, severity, or event_type) were detected in the uploaded CSV. General statistical metrics remain available under Overview and Dataset Explorer.</p>
      </div>
    `;
    return;
  }

  threatNotice.innerHTML = '';

  // Severity Doughnut Chart
  if (t.severity.available) {
    const dist = t.severity.distribution;
    createOrUpdateChart('chartThreatSeverity', {
      type: 'doughnut',
      data: {
        labels: Object.keys(dist),
        datasets: [{
          data: Object.values(dist),
          backgroundColor: Object.keys(dist).map(k => CHART_PALETTES.severity[k] || '#9CA3AF'),
          borderWidth: 2,
        }]
      },
      options: {
        plugins: { legend: { position: 'bottom' } },
        cutout: '60%'
      }
    });
  }

  // Attack Types Bar Chart
  if (t.attack_types.available) {
    const atks = t.attack_types.top_attacks;
    createOrUpdateChart('chartThreatAttacks', {
      type: 'bar',
      data: {
        labels: atks.map(a => a.attack),
        datasets: [{
          label: 'Count',
          data: atks.map(a => a.count),
          backgroundColor: '#635BFF',
          borderRadius: 6,
        }]
      },
      options: {
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, grid: { color: '#F1F5F9' } } }
      }
    });
  }

  // Suspicious Patterns
  const patternsContainer = document.getElementById('threatPatternsList');
  patternsContainer.innerHTML = '';

  if (t.suspicious_patterns.length === 0) {
    patternsContainer.innerHTML = '<p style="color:var(--text-muted); font-size:0.88rem; padding:12px;">No automated suspicious patterns triggered for this dataset.</p>';
  } else {
    t.suspicious_patterns.forEach(p => {
      const card = document.createElement('div');
      card.className = `threat-finding-card threat-${p.severity.toLowerCase()}`;
      card.innerHTML = `
        <div class="finding-icon" style="background:var(--critical-bg); color:var(--critical);">
          <i class="fa-solid fa-triangle-exclamation"></i>
        </div>
        <div class="finding-content">
          <h4>${escapeHtml(p.rule)} (${p.count} events)</h4>
          <p>${escapeHtml(p.description)}</p>
        </div>
      `;
      patternsContainer.appendChild(card);
    });
  }

  // Flagged Threats Table (First 10 critical/high events)
  const flaggedBody = document.getElementById('flaggedThreatsBody');
  const previewRows = data.preview_records || [];
  const colMap = data.detected_columns;

  const sevCol = colMap.severity;
  const highSevRows = previewRows.filter(r => {
    if (!sevCol || !r[sevCol]) return false;
    const s = String(r[sevCol]).toLowerCase();
    return s.includes('high') || s.includes('crit');
  }).slice(0, 10);

  if (highSevRows.length === 0) {
    flaggedBody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:20px; color:var(--text-muted);">No High or Critical severity records present in preview.</td></tr>';
  } else {
    let rowsHtml = '';
    highSevRows.forEach(r => {
      rowsHtml += `
        <tr>
          <td>${escapeHtml(r[colMap.timestamp] || 'N/A')}</td>
          <td><code>${escapeHtml(r[colMap.source_ip] || 'N/A')}</code></td>
          <td><code>${escapeHtml(r[colMap.destination_ip] || 'N/A')}</code></td>
          <td>${escapeHtml(r[colMap.destination_port] || 'N/A')}</td>
          <td><strong>${escapeHtml(r[colMap.attack_type] || 'N/A')}</strong></td>
          <td><span class="badge-tag badge-critical">${escapeHtml(r[colMap.severity] || 'N/A')}</span></td>
          <td>${escapeHtml(r[colMap.event_type] || 'N/A')}</td>
        </tr>
      `;
    });
    flaggedBody.innerHTML = rowsHtml;
  }
}

// ------------------------------------------------------------------------------
// 4. Traffic Analysis Rendering
// ------------------------------------------------------------------------------
function renderTrafficAnalysis(data) {
  const trafficNotice = document.getElementById('trafficNoticeContainer');
  const tr = data.traffic_analysis;

  if (!tr.available) {
    trafficNotice.innerHTML = `
      <div class="empty-visual-state">
        <i class="fa-solid fa-network-wired"></i>
        <h4>Network Traffic Analysis Unavailable</h4>
        <p>No networking fields (source_ip, destination_ip, protocol, destination_port) were detected in the uploaded CSV. Upload a network log to activate traffic inspection.</p>
      </div>
    `;
    return;
  }

  trafficNotice.innerHTML = '';

  // Time Series Trend Line Chart
  if (tr.time_series.available && tr.time_series.points.length > 0) {
    const pts = tr.time_series.points;
    createOrUpdateChart('chartTrafficTimeline', {
      type: 'line',
      data: {
        labels: pts.map(p => p.time),
        datasets: [{
          label: 'Event Frequency',
          data: pts.map(p => p.count),
          borderColor: '#635BFF',
          backgroundColor: 'rgba(99, 91, 255, 0.08)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 3,
        }]
      },
      options: {
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, grid: { color: '#F1F5F9' } },
          x: { grid: { display: false } }
        }
      }
    });
  } else {
    document.getElementById('trafficTimelineContainer').innerHTML = `
      <div class="empty-visual-state" style="height:100%;">
        <i class="fa-regular fa-clock"></i>
        <h4>No Parseable Timestamp Column</h4>
        <p>Dataset does not contain recognized timestamp values for time-series aggregation.</p>
      </div>
    `;
  }

  // Top Sources Horizontal Bar Chart
  if (tr.source_ips.available) {
    const sources = tr.source_ips.top_sources;
    createOrUpdateChart('chartTopSources', {
      type: 'bar',
      data: {
        labels: sources.map(s => s.ip),
        datasets: [{
          label: 'Connections',
          data: sources.map(s => s.count),
          backgroundColor: '#3B82F6',
          borderRadius: 4,
        }]
      },
      options: {
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true, grid: { color: '#F1F5F9' } } }
      }
    });
  }

  // Top Ports Bar Chart
  if (tr.dest_ports.available) {
    const ports = tr.dest_ports.top_ports;
    createOrUpdateChart('chartTopPorts', {
      type: 'bar',
      data: {
        labels: ports.map(p => `${p.port} (${p.name})`),
        datasets: [{
          label: 'Requests',
          data: ports.map(p => p.count),
          backgroundColor: '#8B5CF6',
          borderRadius: 4,
        }]
      },
      options: {
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true, grid: { color: '#F1F5F9' } } }
      }
    });
  }

  // Bandwidth & Packet Cards
  const volGrid = document.getElementById('trafficVolumeSummaryGrid');
  volGrid.innerHTML = `
    <div style="background:var(--bg-main); padding:16px; border-radius:var(--radius-md);">
      <span style="font-size:0.75rem; color:var(--text-light); text-transform:uppercase;">Total Bandwidth</span>
      <h4 style="font-size:1.4rem; font-weight:800; color:var(--text-main); margin-top:4px;">
        ${tr.bytes.available ? `${(tr.bytes.total / (1024 * 1024)).toFixed(2)} MB` : 'Not available'}
      </h4>
    </div>
    <div style="background:var(--bg-main); padding:16px; border-radius:var(--radius-md);">
      <span style="font-size:0.75rem; color:var(--text-light); text-transform:uppercase;">Average Bytes / Flow</span>
      <h4 style="font-size:1.4rem; font-weight:800; color:var(--text-main); margin-top:4px;">
        ${tr.bytes.available ? `${formatNum(tr.bytes.mean)} B` : 'Not available'}
      </h4>
    </div>
    <div style="background:var(--bg-main); padding:16px; border-radius:var(--radius-md);">
      <span style="font-size:0.75rem; color:var(--text-light); text-transform:uppercase;">Total Transmitted Packets</span>
      <h4 style="font-size:1.4rem; font-weight:800; color:var(--text-main); margin-top:4px;">
        ${tr.packets.available ? formatNum(tr.packets.total) : 'Not available'}
      </h4>
    </div>
  `;
}

// ------------------------------------------------------------------------------
// 5. Data Visualizations Gallery (8 Charts)
// ------------------------------------------------------------------------------
function renderVisualizations(data) {
  const tr = data.traffic_analysis;
  const th = data.threat_analytics;

  // Chart 1: Protocol Distribution Donut
  if (tr.protocols.available) {
    const dist = tr.protocols.breakdown;
    createOrUpdateChart('vizChart1', {
      type: 'doughnut',
      data: {
        labels: Object.keys(dist),
        datasets: [{
          data: Object.values(dist),
          backgroundColor: Object.keys(dist).map(k => CHART_PALETTES.protocols[k] || '#8B5CF6'),
          borderWidth: 2,
        }]
      },
      options: { cutout: '60%', plugins: { legend: { position: 'bottom' } } }
    });
  }

  // Chart 2: Attack Type Frequency Bar
  if (th.attack_types.available) {
    const atks = th.attack_types.top_attacks;
    createOrUpdateChart('vizChart2', {
      type: 'bar',
      data: {
        labels: atks.map(a => a.attack),
        datasets: [{
          label: 'Frequency',
          data: atks.map(a => a.count),
          backgroundColor: CHART_PALETTES.primary.slice(0, atks.length),
          borderRadius: 6,
        }]
      },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });
  }

  // Chart 3: Security Event Trends Over Time
  if (tr.time_series.available && tr.time_series.points.length > 0) {
    const pts = tr.time_series.points;
    createOrUpdateChart('vizChart3', {
      type: 'line',
      data: {
        labels: pts.map(p => p.time),
        datasets: [{
          label: 'Events Count',
          data: pts.map(p => p.count),
          borderColor: '#10B981',
          backgroundColor: 'rgba(16, 185, 129, 0.1)',
          fill: true,
          tension: 0.35,
          borderWidth: 2,
        }]
      },
      options: { plugins: { legend: { display: false } } }
    });
  }

  // Chart 4: Threat Severity Breakdown Doughnut
  if (th.severity.available) {
    const dist = th.severity.distribution;
    createOrUpdateChart('vizChart4', {
      type: 'doughnut',
      data: {
        labels: Object.keys(dist),
        datasets: [{
          data: Object.values(dist),
          backgroundColor: Object.keys(dist).map(k => CHART_PALETTES.severity[k] || '#9CA3AF'),
        }]
      },
      options: { plugins: { legend: { position: 'bottom' } } }
    });
  }

  // Chart 5: Top Source IP Addresses Horizontal Bar
  if (tr.source_ips.available) {
    const sources = tr.source_ips.top_sources.slice(0, 8);
    createOrUpdateChart('vizChart5', {
      type: 'bar',
      data: {
        labels: sources.map(s => s.ip),
        datasets: [{
          label: 'Flow Count',
          data: sources.map(s => s.count),
          backgroundColor: '#635BFF',
          borderRadius: 4,
        }]
      },
      options: { indexAxis: 'y', plugins: { legend: { display: false } } }
    });
  }

  // Chart 6: Top Destination Ports Bar
  if (tr.dest_ports.available) {
    const ports = tr.dest_ports.top_ports.slice(0, 8);
    createOrUpdateChart('vizChart6', {
      type: 'bar',
      data: {
        labels: ports.map(p => `Port ${p.port}`),
        datasets: [{
          label: 'Probes',
          data: ports.map(p => p.count),
          backgroundColor: '#F59E0B',
          borderRadius: 4,
        }]
      },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });
  }

  // Chart 7: Security Event Types Breakdown
  if (th.event_types.available) {
    const dist = th.event_types.distribution;
    createOrUpdateChart('vizChart7', {
      type: 'bar',
      data: {
        labels: Object.keys(dist),
        datasets: [{
          label: 'Events',
          data: Object.values(dist),
          backgroundColor: '#3B82F6',
          borderRadius: 4,
        }]
      },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });
  }

  // Chart 8: Missing Values Audit per Column
  const missingData = data.missing_by_col;
  createOrUpdateChart('vizChart8', {
    type: 'bar',
    data: {
      labels: Object.keys(missingData).slice(0, 10),
      datasets: [{
        label: 'Missing Count',
        data: Object.values(missingData).slice(0, 10),
        backgroundColor: '#DC2626',
        borderRadius: 4,
      }]
    },
    options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
  });
}

// ------------------------------------------------------------------------------
// 6. Reports Live Preview
// ------------------------------------------------------------------------------
function renderReports(data) {
  document.getElementById('reportGeneratedTimestamp').textContent = new Date().toLocaleString();
  document.getElementById('repFilename').textContent = data.metadata.filename;
  document.getElementById('repTotalRows').textContent = formatNum(data.overview_metrics.total_records);
  document.getElementById('repTotalCols').textContent = formatNum(data.overview_metrics.total_columns);
  document.getElementById('repValidation').textContent = data.metadata.validation_status;

  const th = data.threat_analytics;
  const repThreatText = document.getElementById('repThreatSummaryText');
  const repBadges = document.getElementById('repThreatBadges');
  repBadges.innerHTML = '';

  if (th.available && th.severity.available) {
    repThreatText.textContent = `The dataset features ${formatNum(th.severity.high_critical_count)} High and Critical severity events representing ${th.severity.high_critical_pct}% of the total recorded volume.`;
    Object.entries(th.severity.distribution).forEach(([sev, count]) => {
      const b = document.createElement('span');
      b.className = 'badge-tag';
      b.style.background = CHART_PALETTES.severity[sev] || '#9CA3AF';
      b.style.color = '#FFFFFF';
      b.textContent = `${sev}: ${count}`;
      repBadges.appendChild(b);
    });
  } else {
    repThreatText.textContent = 'No explicit threat severity fields were present in this dataset for risk categorization.';
  }

  const repQualityText = document.getElementById('repQualitySummaryText');
  const missing = data.overview_metrics.missing_values_count;
  const dupes = data.overview_metrics.duplicate_records_count;
  repQualityText.textContent = `The dataset audit identified ${formatNum(missing)} missing value cells and ${formatNum(dupes)} duplicate records across ${data.overview_metrics.total_columns} attributes.`;
}

// ------------------------------------------------------------------------------
// 7. Settings Info
// ------------------------------------------------------------------------------
function renderSettingsInfo(data) {
  document.getElementById('settingsDatasetName').textContent = data.metadata.filename;
  document.getElementById('settingsDatasetSize').textContent = data.metadata.file_size_formatted;
}

// ==============================================================================
// Modal Controllers
// ==============================================================================

function openUploadModal() {
  state.modalSelectedFile = null;
  document.getElementById('modalSelectedFileNotice').style.display = 'none';
  document.getElementById('confirmUploadModalBtn').disabled = true;
  document.getElementById('uploadModal').classList.add('active');
}

function closeUploadModal() {
  document.getElementById('uploadModal').classList.remove('active');
}

function openClearModal() {
  document.getElementById('clearModal').classList.add('active');
}

function closeClearModal() {
  document.getElementById('clearModal').classList.remove('active');
}

// ==============================================================================
// Event Listeners & Application Bootstrapping
// ==============================================================================

document.addEventListener('DOMContentLoaded', () => {
  // 1. Initial Hash Route
  const initialHash = window.location.hash.replace('#', '') || 'overview';
  navigateTo(initialHash);

  // 2. Hash Change Handler
  window.addEventListener('hashchange', () => {
    const hash = window.location.hash.replace('#', '') || 'overview';
    navigateTo(hash);
  });

  // 3. Sidebar Navigation Links
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const sec = link.getAttribute('data-section');
      navigateTo(sec);
    });
  });

  // 4. Mobile Menu Toggle
  const menuToggle = document.getElementById('menuToggle');
  if (menuToggle) menuToggle.addEventListener('click', openMobileSidebar);
  const sidebarOverlay = document.getElementById('sidebarOverlay');
  if (sidebarOverlay) sidebarOverlay.addEventListener('click', closeMobileSidebar);

  // 5. Notifications Dropdown Toggle
  const notifBtn = document.getElementById('notificationBtn');
  const notifDropdown = document.getElementById('notificationDropdown');
  if (notifBtn && notifDropdown) {
    notifBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      notifDropdown.classList.toggle('show');
    });
    document.addEventListener('click', () => {
      notifDropdown.classList.remove('show');
    });
  }

  // 6. Action Buttons in Top Navbar
  const quickSampleBtn = document.getElementById('quickSampleBtn');
  if (quickSampleBtn) quickSampleBtn.addEventListener('click', loadSampleDataset);

  const quickUploadBtn = document.getElementById('quickUploadBtn');
  if (quickUploadBtn) quickUploadBtn.addEventListener('click', openUploadModal);

  // 7. Action Buttons in Overview
  const overviewLoadSampleBtn2 = document.getElementById('overviewLoadSampleBtn2');
  if (overviewLoadSampleBtn2) overviewLoadSampleBtn2.addEventListener('click', loadSampleDataset);

  const overviewDownloadSampleBtn = document.getElementById('overviewDownloadSampleBtn');
  if (overviewDownloadSampleBtn) overviewDownloadSampleBtn.addEventListener('click', downloadSampleCsvFile);

  const overviewClearBtn = document.getElementById('overviewClearBtn');
  if (overviewClearBtn) overviewClearBtn.addEventListener('click', openClearModal);

  // 8. Global Nav Search
  const globalNavSearch = document.getElementById('globalNavSearch');
  if (globalNavSearch) {
    globalNavSearch.addEventListener('input', (e) => {
      const val = e.target.value;
      if (state.activeSection !== 'explorer') navigateTo('explorer');
      const tableInput = document.getElementById('tableFilterInput');
      if (tableInput) tableInput.value = val;
      filterTableRows(val);
    });
  }

  // 9. Table Explorer Controls
  const tableFilterInput = document.getElementById('tableFilterInput');
  if (tableFilterInput) {
    tableFilterInput.addEventListener('input', (e) => filterTableRows(e.target.value));
  }

  const tablePageSizeSelect = document.getElementById('tablePageSizeSelect');
  if (tablePageSizeSelect) {
    tablePageSizeSelect.addEventListener('change', (e) => {
      state.table.pageSize = parseInt(e.target.value, 10);
      state.table.currentPage = 1;
      renderExplorer();
    });
  }

  const tableClearFilterBtn = document.getElementById('tableClearFilterBtn');
  if (tableClearFilterBtn) {
    tableClearFilterBtn.addEventListener('click', () => {
      if (tableFilterInput) tableFilterInput.value = '';
      if (globalNavSearch) globalNavSearch.value = '';
      filterTableRows('');
    });
  }

  // Table Pagination Buttons
  document.getElementById('paginationFirst').addEventListener('click', () => {
    state.table.currentPage = 1;
    renderExplorer();
  });
  document.getElementById('paginationPrev').addEventListener('click', () => {
    if (state.table.currentPage > 1) {
      state.table.currentPage--;
      renderExplorer();
    }
  });
  document.getElementById('paginationNext').addEventListener('click', () => {
    const totalPages = Math.ceil(state.table.filteredRows.length / state.table.pageSize);
    if (state.table.currentPage < totalPages) {
      state.table.currentPage++;
      renderExplorer();
    }
  });
  document.getElementById('paginationLast').addEventListener('click', () => {
    state.table.currentPage = Math.ceil(state.table.filteredRows.length / state.table.pageSize);
    renderExplorer();
  });

  const exportFilteredCsvBtn = document.getElementById('exportFilteredCsvBtn');
  if (exportFilteredCsvBtn) {
    exportFilteredCsvBtn.addEventListener('click', downloadCsvSummaryReport);
  }

  // 10. Reports Section Buttons
  const btnDownloadJsonReport = document.getElementById('btnDownloadJsonReport');
  if (btnDownloadJsonReport) btnDownloadJsonReport.addEventListener('click', downloadJsonAuditReport);

  const btnDownloadCsvReport = document.getElementById('btnDownloadCsvReport');
  if (btnDownloadCsvReport) btnDownloadCsvReport.addEventListener('click', downloadCsvSummaryReport);

  // 11. Settings Section Controls
  const settingsClearBtn = document.getElementById('settingsClearBtn');
  if (settingsClearBtn) settingsClearBtn.addEventListener('click', openClearModal);

  const themeAccentSelect = document.getElementById('themeAccentSelect');
  if (themeAccentSelect) {
    // Load from LocalStorage
    const savedTheme = localStorage.getItem('cybervision_theme') || 'indigo';
    themeAccentSelect.value = savedTheme;
    applyTheme(savedTheme);

    themeAccentSelect.addEventListener('change', (e) => {
      const val = e.target.value;
      localStorage.setItem('cybervision_theme', val);
      applyTheme(val);
      showToast(`Theme accent changed to ${val}`, 'info');
    });
  }

  const chartAnimationSelect = document.getElementById('chartAnimationSelect');
  if (chartAnimationSelect) {
    const savedAnim = localStorage.getItem('cybervision_anim') || 'normal';
    chartAnimationSelect.value = savedAnim;
    state.settings.animation = savedAnim;

    chartAnimationSelect.addEventListener('change', (e) => {
      state.settings.animation = e.target.value;
      localStorage.setItem('cybervision_anim', e.target.value);
      showToast('Chart animation preference updated', 'info');
      if (state.dataset) renderVisualizations(state.dataset);
    });
  }

  function applyTheme(theme) {
    document.body.classList.remove('theme-lavender', 'theme-pale-blue', 'theme-mint');
    if (theme === 'lavender') document.body.classList.add('theme-lavender');
    if (theme === 'pale-blue') document.body.classList.add('theme-pale-blue');
    if (theme === 'mint') document.body.classList.add('theme-mint');
  }

  // 12. Modal Handlers
  document.getElementById('closeUploadModalBtn').addEventListener('click', closeUploadModal);
  document.getElementById('cancelUploadModalBtn').addEventListener('click', closeUploadModal);
  document.getElementById('closeClearModalBtn').addEventListener('click', closeClearModal);
  document.getElementById('cancelClearModalBtn').addEventListener('click', closeClearModal);
  document.getElementById('confirmClearModalBtn').addEventListener('click', clearActiveDataset);

  // Drag and Drop for Overview Zone
  const overviewDropzone = document.getElementById('overviewUploadDropzone');
  const overviewFileInput = document.getElementById('overviewFileInput');

  if (overviewDropzone && overviewFileInput) {
    overviewDropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      overviewDropzone.classList.add('dragover');
    });
    overviewDropzone.addEventListener('dragleave', () => overviewDropzone.classList.remove('dragover'));
    overviewDropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      overviewDropzone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        uploadCsvFile(e.dataTransfer.files[0]);
      }
    });
    overviewFileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        uploadCsvFile(e.target.files[0]);
      }
    });
  }

  // Drag and Drop for Modal Zone
  const modalDropzone = document.getElementById('modalUploadDropzone');
  const modalFileInput = document.getElementById('modalFileInput');
  const confirmUploadBtn = document.getElementById('confirmUploadModalBtn');

  if (modalDropzone && modalFileInput && confirmUploadBtn) {
    modalDropzone.addEventListener('dragover', (e) => {
      e.preventDefault();
      modalDropzone.classList.add('dragover');
    });
    modalDropzone.addEventListener('dragleave', () => modalDropzone.classList.remove('dragover'));
    modalDropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      modalDropzone.classList.remove('dragover');
      if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleModalFileSelect(e.dataTransfer.files[0]);
      }
    });
    modalFileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length > 0) {
        handleModalFileSelect(e.target.files[0]);
      }
    });

    confirmUploadBtn.addEventListener('click', () => {
      if (state.modalSelectedFile) {
        closeUploadModal();
        uploadCsvFile(state.modalSelectedFile);
      }
    });
  }

  function handleModalFileSelect(file) {
    if (!file.name.toLowerCase().endsWith('.csv')) {
      showToast('Only CSV (.csv) files are supported.', 'error');
      return;
    }
    state.modalSelectedFile = file;
    document.getElementById('modalSelectedFileName').textContent = file.name;
    document.getElementById('modalSelectedFileSize').textContent = `${(file.size / 1024).toFixed(1)} KB`;
    document.getElementById('modalSelectedFileNotice').style.display = 'block';
    confirmUploadBtn.disabled = false;
  }

  // Auto-load sample dataset on initial page open for smooth instant demo
  loadSampleDataset();
});
