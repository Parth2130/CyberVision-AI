// CyberVision AI - Main Utilities
// Shared across all pages

// ─── Constants ───────────────────────────────────────────────────────────────
const API_BASE_URL = 'http://localhost:8000';
const STORAGE_KEY  = 'cybervision_analysis';

// ─── Chart Color Palettes ─────────────────────────────────────────────────────
const CHART_COLORS = {
  primary:   '#4776E6',
  secondary: '#8B5CF6',
  highlight: '#22C7D9',
  success:   '#34D399',
  warning:   '#F59E0B',
  danger:    '#F87171',
  navy:      '#23345D'
};

const CATEGORY_COLORS = {
  'BENIGN':      '#34D399',
  'DoS Hulk':    '#F87171',
  'DDoS':        '#F59E0B',
  'PortScan':    '#8B5CF6',
  'Brute Force': '#22C7D9',
  'Botnet':      '#4776E6',
  'Unknown':     '#94a3b8'
};

// ─── API Helpers ──────────────────────────────────────────────────────────────

/**
 * POST JSON data to a backend endpoint.
 * @param {string} endpoint - Path after API_BASE_URL (e.g. '/api/analyze')
 * @param {Object} data      - Plain object to serialize as JSON
 * @returns {Promise<Object>} Parsed JSON response
 */
async function apiPost(endpoint, data) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify(data)
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

/**
 * GET data from a backend endpoint.
 * @param {string} endpoint - Path after API_BASE_URL
 * @returns {Promise<Object>} Parsed JSON response
 */
async function apiGet(endpoint) {
  const response = await fetch(`${API_BASE_URL}${endpoint}`);
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(err.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

/**
 * POST a File as multipart/form-data to the backend.
 * @param {string} endpoint - Path after API_BASE_URL
 * @param {File}   file     - File object from an <input type="file"> or drop event
 * @param {function} [onProgress] - Optional progress callback receiving 0-100
 * @returns {Promise<Object>} Parsed JSON response
 */
async function apiPostFile(endpoint, file, onProgress) {
  return new Promise((resolve, reject) => {
    const formData = new FormData();
    formData.append('file', file);

    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${API_BASE_URL}${endpoint}`);

    if (typeof onProgress === 'function') {
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          onProgress(Math.round((e.loaded / e.total) * 100));
        }
      });
    }

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText));
        } catch {
          resolve({ raw: xhr.responseText });
        }
      } else {
        try {
          const err = JSON.parse(xhr.responseText);
          reject(new Error(err.detail || `HTTP ${xhr.status}`));
        } catch {
          reject(new Error(`HTTP ${xhr.status}`));
        }
      }
    };

    xhr.onerror = () => reject(new Error('Network error — is the backend running?'));
    xhr.send(formData);
  });
}

// ─── LocalStorage Helpers ─────────────────────────────────────────────────────

/** Persist analysis results to localStorage. */
function saveAnalysis(data) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch (e) {
    console.warn('Could not save to localStorage:', e);
  }
}

/** Load analysis results from localStorage. Returns null if absent. */
function loadAnalysis() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
  } catch {
    return null;
  }
}

/** Remove analysis results from localStorage. */
function clearAnalysis() {
  localStorage.removeItem(STORAGE_KEY);
}

// ─── Toast Notification System ────────────────────────────────────────────────

let _toastContainer = null;

function _getToastContainer() {
  if (!_toastContainer) {
    _toastContainer = document.createElement('div');
    _toastContainer.id = 'toast-container';
    Object.assign(_toastContainer.style, {
      position:      'fixed',
      bottom:        '1.5rem',
      right:         '1.5rem',
      zIndex:        '9999',
      display:       'flex',
      flexDirection: 'column',
      gap:           '0.5rem',
      maxWidth:      '360px'
    });
    document.body.appendChild(_toastContainer);
  }
  return _toastContainer;
}

/**
 * Show a floating toast notification.
 * @param {string} message
 * @param {'info'|'success'|'error'|'warning'} [type='info']
 * @param {number} [duration=4000] Auto-dismiss delay in ms (0 = sticky)
 */
function showToast(message, type = 'info', duration = 4000) {
  const iconMap = {
    info:    '💡',
    success: '✅',
    error:   '❌',
    warning: '⚠️'
  };
  const colorMap = {
    info:    '#4776E6',
    success: '#34D399',
    error:   '#F87171',
    warning: '#F59E0B'
  };

  const toast = document.createElement('div');
  Object.assign(toast.style, {
    display:      'flex',
    alignItems:   'center',
    gap:          '0.6rem',
    padding:      '0.75rem 1rem',
    borderRadius: '8px',
    background:   '#1e2a4a',
    border:       `1px solid ${colorMap[type] || colorMap.info}`,
    color:        '#e2e8f0',
    fontSize:     '0.875rem',
    boxShadow:    '0 4px 12px rgba(0,0,0,0.4)',
    opacity:      '0',
    transform:    'translateX(40px)',
    transition:   'opacity 0.3s ease, transform 0.3s ease',
    cursor:       'pointer'
  });

  toast.innerHTML = `<span>${iconMap[type] || iconMap.info}</span><span style="flex:1">${message}</span>`;
  toast.addEventListener('click', () => dismissToast(toast));

  const container = _getToastContainer();
  container.appendChild(toast);

  // Trigger entrance animation
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      toast.style.opacity   = '1';
      toast.style.transform = 'translateX(0)';
    });
  });

  if (duration > 0) {
    setTimeout(() => dismissToast(toast), duration);
  }

  return toast;
}

function dismissToast(toast) {
  toast.style.opacity   = '0';
  toast.style.transform = 'translateX(40px)';
  setTimeout(() => toast.remove(), 320);
}

// ─── Number / String Formatters ───────────────────────────────────────────────

/** Format a number with thousands separators.  1234567 → "1,234,567" */
function formatNumber(n) {
  if (n === null || n === undefined || isNaN(n)) return '—';
  return Number(n).toLocaleString();
}

/**
 * Format byte count into human-readable size.
 * 1048576 → "1.0 MB"
 */
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k     = 1024;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i     = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${units[i]}`;
}

/**
 * Format an ISO date string or timestamp into a readable local date/time.
 * @param {string|number|Date} dateStr
 * @returns {string}
 */
function formatDate(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  if (isNaN(d)) return String(dateStr);
  return d.toLocaleString(undefined, {
    year:   'numeric',
    month:  'short',
    day:    'numeric',
    hour:   '2-digit',
    minute: '2-digit'
  });
}

/**
 * Format a percentage.
 * @param {number} val   - Numerator
 * @param {number} total - Denominator
 * @param {number} [decimals=1]
 */
function formatPercent(val, total, decimals = 1) {
  if (!total || total === 0) return '0%';
  return `${((val / total) * 100).toFixed(decimals)}%`;
}

// ─── Navigation ───────────────────────────────────────────────────────────────

/**
 * Highlight the current page's nav link.
 * @param {string} pageName - e.g. 'dashboard', 'upload', 'analysis'
 */
function setActiveNav(pageName) {
  document.querySelectorAll('.nav-link, .sidebar-link').forEach(link => {
    const href  = (link.getAttribute('href') || '').replace(/\.html$/, '').replace(/^.*\//, '');
    const match = href === pageName || link.dataset.page === pageName;
    link.classList.toggle('active', match);
    if (match) link.setAttribute('aria-current', 'page');
    else        link.removeAttribute('aria-current');
  });
}

// ─── Mobile Menu ─────────────────────────────────────────────────────────────

/**
 * Wire up the hamburger / mobile menu toggle.
 * Expects a button with id="mobile-menu-btn" and a nav with id="mobile-menu".
 */
function initMobileMenu() {
  const btn  = document.getElementById('mobile-menu-btn');
  const menu = document.getElementById('mobile-menu');
  if (!btn || !menu) return;

  btn.addEventListener('click', () => {
    const open = menu.classList.toggle('open');
    btn.setAttribute('aria-expanded', String(open));
    btn.textContent = open ? '✕' : '☰';
  });

  // Close when a link is clicked
  menu.querySelectorAll('a').forEach(a => {
    a.addEventListener('click', () => {
      menu.classList.remove('open');
      btn.setAttribute('aria-expanded', 'false');
      btn.textContent = '☰';
    });
  });
}

// ─── Loading Overlay ──────────────────────────────────────────────────────────

let _loadingOverlay = null;

/** Show a full-screen loading overlay with an optional message. */
function showLoading(message = 'Processing…') {
  if (_loadingOverlay) {
    _loadingOverlay.querySelector('.loading-message').textContent = message;
    return;
  }

  _loadingOverlay = document.createElement('div');
  _loadingOverlay.id = 'loading-overlay';
  _loadingOverlay.innerHTML = `
    <div class="loading-box">
      <div class="loading-spinner"></div>
      <p class="loading-message">${message}</p>
    </div>
  `;
  Object.assign(_loadingOverlay.style, {
    position:       'fixed',
    inset:          '0',
    background:     'rgba(10,15,30,0.75)',
    display:        'flex',
    alignItems:     'center',
    justifyContent: 'center',
    zIndex:         '10000',
    backdropFilter: 'blur(4px)'
  });

  // Inline spinner style (avoids dependency on external CSS)
  const style = document.createElement('style');
  style.textContent = `
    .loading-box { text-align:center; color:#e2e8f0; }
    .loading-spinner {
      width:48px; height:48px; border-radius:50%;
      border:4px solid rgba(71,118,230,0.3);
      border-top-color:#4776E6;
      animation: cv-spin 0.8s linear infinite;
      margin: 0 auto 1rem;
    }
    .loading-message { font-size:0.95rem; opacity:0.85; }
    @keyframes cv-spin { to { transform: rotate(360deg); } }
  `;
  _loadingOverlay.appendChild(style);
  document.body.appendChild(_loadingOverlay);
}

/** Remove the loading overlay. */
function hideLoading() {
  if (_loadingOverlay) {
    _loadingOverlay.remove();
    _loadingOverlay = null;
  }
}

// ─── Empty State Renderer ─────────────────────────────────────────────────────

/**
 * Render a friendly empty-state message inside a container element.
 * @param {HTMLElement} container
 * @param {string} message  - Main message text
 * @param {string} icon     - Emoji or SVG string
 * @param {string} [ctaText]  - Call-to-action button text
 * @param {string} [ctaHref]  - URL for the CTA button
 */
function renderEmptyState(container, message, icon = '📂', ctaText = '', ctaHref = '') {
  const cta = ctaText && ctaHref
    ? `<a href="${ctaHref}" class="btn btn-primary" style="margin-top:1rem;">${ctaText}</a>`
    : '';

  container.innerHTML = `
    <div style="
      text-align:center;
      padding:3rem 1.5rem;
      color:#94a3b8;
    ">
      <div style="font-size:3rem;margin-bottom:1rem;">${icon}</div>
      <p style="font-size:1rem;margin:0;">${message}</p>
      ${cta}
    </div>
  `;
}

// ─── Chart.js Global Defaults ─────────────────────────────────────────────────

(function applyChartDefaults() {
  // Guard: Chart.js may not be loaded on every page
  if (typeof Chart === 'undefined') return;

  Chart.defaults.font.family = "'Inter', 'Segoe UI', sans-serif";
  Chart.defaults.font.size   = 12;
  Chart.defaults.color       = '#94a3b8';

  Chart.defaults.plugins.legend.labels.color    = '#cbd5e1';
  Chart.defaults.plugins.legend.labels.padding  = 16;
  Chart.defaults.plugins.tooltip.backgroundColor = 'rgba(15,23,42,0.92)';
  Chart.defaults.plugins.tooltip.borderColor     = 'rgba(71,118,230,0.5)';
  Chart.defaults.plugins.tooltip.borderWidth     = 1;
  Chart.defaults.plugins.tooltip.titleColor      = '#e2e8f0';
  Chart.defaults.plugins.tooltip.bodyColor       = '#cbd5e1';
  Chart.defaults.plugins.tooltip.padding         = 10;
  Chart.defaults.plugins.tooltip.cornerRadius    = 6;

  // Default scale styles
  const scaleDefaults = {
    grid:  { color: 'rgba(148,163,184,0.1)', drawBorder: false },
    ticks: { color: '#94a3b8' }
  };
  Chart.defaults.scales.linear   = Chart.defaults.scales.linear   || {};
  Chart.defaults.scales.category = Chart.defaults.scales.category || {};
  Object.assign(Chart.defaults.scales.linear,   scaleDefaults);
  Object.assign(Chart.defaults.scales.category, scaleDefaults);
})();

// ─── Export Utilities ─────────────────────────────────────────────────────────

/**
 * Trigger a CSV download from an array of objects.
 * @param {Object[]} data     - Array of row objects
 * @param {string}   filename - Without extension
 */
function downloadCSV(data, filename = 'export') {
  if (!data || data.length === 0) {
    showToast('No data to export.', 'warning');
    return;
  }

  const headers = Object.keys(data[0]);
  const escape  = (v) => {
    const s = String(v == null ? '' : v);
    return s.includes(',') || s.includes('"') || s.includes('\n')
      ? `"${s.replace(/"/g, '""')}"`
      : s;
  };

  const csv = [
    headers.map(escape).join(','),
    ...data.map(row => headers.map(h => escape(row[h])).join(','))
  ].join('\r\n');

  _triggerDownload(new Blob([csv], { type: 'text/csv;charset=utf-8;' }), `${filename}.csv`);
}

/**
 * Trigger a JSON download.
 * @param {*}      data     - Any JSON-serialisable value
 * @param {string} filename - Without extension
 */
function downloadJSON(data, filename = 'export') {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  _triggerDownload(blob, `${filename}.json`);
}

function _triggerDownload(blob, filename) {
  const url  = URL.createObjectURL(blob);
  const link = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

// ─── DOM-ready initialisation ─────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initMobileMenu();
});
