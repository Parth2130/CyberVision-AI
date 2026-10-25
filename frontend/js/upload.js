// CyberVision AI - Upload Page JS
// Handles drag-and-drop, CSV preview, and backend submission

'use strict';

// ─── State ────────────────────────────────────────────────────────────────────
let _selectedFile = null;
let _csvHeaders   = [];

// ─── DOM-ready bootstrap ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  setActiveNav('upload');
  _initDropZone();
  _wireFileInput();
  _wireUploadButton();
  _wireResetButton();
});

// ─── Drop Zone ────────────────────────────────────────────────────────────────

function _initDropZone() {
  const zone = document.getElementById('drop-zone');
  if (!zone) return;

  // Visual feedback on drag-over / drag-leave
  ['dragenter', 'dragover'].forEach(evt =>
    zone.addEventListener(evt, e => { e.preventDefault(); zone.classList.add('drag-over'); })
  );
  ['dragleave', 'dragend', 'drop'].forEach(evt =>
    zone.addEventListener(evt, () => zone.classList.remove('drag-over'))
  );

  zone.addEventListener('drop', e => {
    e.preventDefault();
    const file = e.dataTransfer?.files?.[0];
    if (file) _handleFileSelected(file);
  });

  // Clicking the zone opens the hidden file input
  zone.addEventListener('click', () => {
    document.getElementById('file-input')?.click();
  });
}

// ─── File Input ───────────────────────────────────────────────────────────────

function _wireFileInput() {
  const input = document.getElementById('file-input');
  if (!input) return;

  input.addEventListener('change', () => {
    const file = input.files?.[0];
    if (file) _handleFileSelected(file);
    input.value = ''; // reset so same file can be re-selected
  });
}

// ─── File Selection Handler ───────────────────────────────────────────────────

/**
 * Validate and prepare a selected file.
 * @param {File} file
 */
async function _handleFileSelected(file) {
  if (!file.name.toLowerCase().endsWith('.csv')) {
    showToast('Please select a CSV file (.csv).', 'error');
    return;
  }

  const maxBytes = 200 * 1024 * 1024; // 200 MB
  if (file.size > maxBytes) {
    showToast(`File too large (${formatBytes(file.size)}). Maximum is 200 MB.`, 'error');
    return;
  }

  _selectedFile = file;
  _updateDropZoneLabel(file);
  await _parseCSVHeaders(file);
  _showFilePreview(file);
  _setUploadEnabled(true);
}

function _updateDropZoneLabel(file) {
  const zone      = document.getElementById('drop-zone');
  const labelEl   = document.getElementById('drop-zone-label');
  const iconEl    = document.getElementById('drop-zone-icon');
  if (zone)    zone.classList.add('has-file');
  if (iconEl)  iconEl.textContent = '📄';
  if (labelEl) labelEl.textContent = file.name;
}

// ─── CSV Header Parser ────────────────────────────────────────────────────────

/**
 * Read the first two lines of the CSV file and extract header names.
 * @param {File} file
 */
async function _parseCSVHeaders(file) {
  return new Promise(resolve => {
    const reader = new FileReader();

    reader.onload = e => {
      const text    = e.target.result;
      const lines   = text.split('\n');
      const headerLine = lines[0] || '';
      _csvHeaders   = headerLine.split(',').map(h => h.trim().replace(/^"|"$/g, ''));
      resolve(_csvHeaders);
    };

    reader.onerror = () => {
      console.warn('Could not read CSV headers');
      _csvHeaders = [];
      resolve([]);
    };

    // Read only the first 4 KB — enough for headers
    reader.readAsText(file.slice(0, 4096));
  });
}

// ─── File Preview Panel ───────────────────────────────────────────────────────

/**
 * Populate the preview card with file info and detected columns.
 * @param {File} file
 */
function _showFilePreview(file) {
  const panel = document.getElementById('file-preview');
  if (!panel) return;

  panel.style.display = 'block';
  panel.classList.add('animate-in');

  _setPreviewText('preview-name',    file.name);
  _setPreviewText('preview-size',    formatBytes(file.size));
  _setPreviewText('preview-type',    file.type || 'text/csv');
  _setPreviewText('preview-columns', `${_csvHeaders.length} columns detected`);
  _setPreviewText('preview-date',    formatDate(new Date().toISOString()));

  // Render column chips
  const chipContainer = document.getElementById('preview-column-chips');
  if (chipContainer) {
    chipContainer.innerHTML = _csvHeaders.map(h =>
      `<span class="chip" title="${h}">${h}</span>`
    ).join('');
  }

  // Try to detect dataset type
  const detected = _detectDatasetType(_csvHeaders);
  _setPreviewText('preview-dataset-type', detected);
}

function _setPreviewText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}

/**
 * Heuristic: detect if the CSV looks like a known dataset.
 * @param {string[]} headers
 * @returns {string}
 */
function _detectDatasetType(headers) {
  const h = headers.map(s => s.toLowerCase());
  if (h.includes('flow duration') || h.includes('flow_duration')) return 'CIC-IDS2017 (detected)';
  if (h.includes('dur') && h.includes('proto') && h.includes('state'))    return 'UNSW-NB15 (detected)';
  if (h.some(x => x.includes('packet')))  return 'Network Flow (generic)';
  return 'CSV — Unknown format';
}

// ─── Upload Button ────────────────────────────────────────────────────────────

function _wireUploadButton() {
  const btn = document.getElementById('btn-upload');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    if (!_selectedFile) {
      showToast('No file selected.', 'warning');
      return;
    }
    await _submitUpload(_selectedFile);
  });
}

function _setUploadEnabled(enabled) {
  const btn = document.getElementById('btn-upload');
  if (btn) btn.disabled = !enabled;
}

// ─── Upload Submission ────────────────────────────────────────────────────────

/**
 * Upload the file to the backend with progress tracking.
 * @param {File} file
 */
async function _submitUpload(file) {
  _setUploadEnabled(false);
  _showProgressBar(0);
  showLoading('Uploading dataset…');

  try {
    const result = await apiPostFile('/api/upload', file, progress => {
      _showProgressBar(progress);
      if (progress === 100) showLoading('Analysing data… this may take a moment');
    });

    hideLoading();
    _showProgressBar(100);

    if (!result || result.error) {
      throw new Error(result?.error || 'Unexpected server response');
    }

    saveAnalysis(result);
    showToast('Analysis complete! Redirecting to dashboard…', 'success');

    setTimeout(() => {
      window.location.href = 'dashboard.html';
    }, 1500);

  } catch (err) {
    hideLoading();
    _showProgressBar(0, true);
    _setUploadEnabled(true);
    showToast(`Upload failed: ${err.message}`, 'error');
    console.error('[upload] Error:', err);
  }
}

// ─── Progress Bar ─────────────────────────────────────────────────────────────

/**
 * Update the upload progress bar.
 * @param {number}  pct   - 0–100
 * @param {boolean} error - If true, colour it red
 */
function _showProgressBar(pct, error = false) {
  const wrapper = document.getElementById('progress-wrapper');
  const bar     = document.getElementById('progress-bar');
  const label   = document.getElementById('progress-label');

  if (!wrapper || !bar) return;

  wrapper.style.display = pct > 0 ? 'block' : 'none';
  bar.style.width       = `${pct}%`;
  bar.style.background  = error ? CHART_COLORS.danger : CHART_COLORS.primary;

  if (label) {
    label.textContent = error ? 'Upload failed' : pct < 100 ? `Uploading… ${pct}%` : 'Processing…';
  }
}

// ─── Reset Button ─────────────────────────────────────────────────────────────

function _wireResetButton() {
  const btn = document.getElementById('btn-reset');
  if (!btn) return;

  btn.addEventListener('click', () => {
    _selectedFile = null;
    _csvHeaders   = [];

    const zone    = document.getElementById('drop-zone');
    const label   = document.getElementById('drop-zone-label');
    const icon    = document.getElementById('drop-zone-icon');
    const preview = document.getElementById('file-preview');
    const wrapper = document.getElementById('progress-wrapper');

    if (zone)    zone.classList.remove('has-file', 'drag-over');
    if (label)   label.textContent = 'Drag & drop your CSV here, or click to browse';
    if (icon)    icon.textContent  = '📂';
    if (preview) preview.style.display = 'none';
    if (wrapper) wrapper.style.display = 'none';

    _setUploadEnabled(false);
    showToast('File cleared.', 'info');
  });
}
