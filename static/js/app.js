/**
 * Fortis Intelligence Hub - Main Application JavaScript
 * OSINT Analysis Platform with black/purple punk theme
 *
 * Manages: Authentication, tool switching, file upload, API calls,
 * results rendering (markdown, map, graph, charts), Watch panel,
 * Knowledge Base panel, and export functionality.
 */

/* ====================================================================
   STATE
   ==================================================================== */

let sessionId = null;
let currentTool = 'ingest';
let chatMessages = [];
let mapInstance = null;
let graphInstance = null;
let watchRefreshTimer = null;
let watchPanelOpen = false;
let kbPanelOpen = false;
let lastAnalysisData = null;

/* ====================================================================
   UTILITY FUNCTIONS
   ==================================================================== */

/**
 * Escape HTML special characters to prevent XSS.
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
    if (text == null) return '';
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

/**
 * Show global loading scanline animation.
 */
function showLoading() {
    const el = document.getElementById('globalLoading');
    if (el) el.classList.add('active');
    const scanline = document.getElementById('resultsScanline');
    if (scanline) scanline.classList.add('active');
}

/**
 * Hide global loading scanline animation.
 */
function hideLoading() {
    const el = document.getElementById('globalLoading');
    if (el) el.classList.remove('active');
    const scanline = document.getElementById('resultsScanline');
    if (scanline) scanline.classList.remove('active');
}

/**
 * Display a toast notification.
 * @param {string} message
 * @param {'success'|'error'|'info'|'warning'} type
 */
function showToast(message, type) {
    type = type || 'info';
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast toast-' + type;
    toast.textContent = message;
    container.appendChild(toast);

    // Trigger animation
    requestAnimationFrame(function () {
        toast.classList.add('show');
    });

    setTimeout(function () {
        toast.classList.remove('show');
        setTimeout(function () {
            if (toast.parentNode) toast.parentNode.removeChild(toast);
        }, 300);
    }, 4000);
}

/**
 * API fetch wrapper with error handling and auth checks.
 * @param {string} url
 * @param {object} options - fetch options
 * @returns {Promise<Response>}
 */
async function fetchApi(url, options) {
    options = options || {};
    if (!options.headers) options.headers = {};

    // Default to JSON content type for non-FormData requests
    if (!(options.body instanceof FormData) && !options.headers['Content-Type']) {
        options.headers['Content-Type'] = 'application/json';
    }

    try {
        const response = await fetch(url, options);

        if (response.status === 401) {
            handleLogout();
            throw new Error('Session expired. Please sign in again.');
        }

        return response;
    } catch (error) {
        if (error.message !== 'Session expired. Please sign in again.') {
            console.error('[API]', url, error);
        }
        throw error;
    }
}

/**
 * Format a timestamp string into a human-readable date.
 * @param {string} ts - ISO 8601 timestamp
 * @returns {string}
 */
function formatTimestamp(ts) {
    if (!ts) return '';
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;

    const now = new Date();
    const diffMs = now - d;
    const diffSec = Math.floor(diffMs / 1000);

    if (diffSec < 60) return diffSec + 's ago';
    if (diffSec < 3600) return Math.floor(diffSec / 60) + 'm ago';
    if (diffSec < 86400) return Math.floor(diffSec / 3600) + 'h ago';
    if (diffSec < 604800) return Math.floor(diffSec / 86400) + 'd ago';

    return d.toLocaleDateString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: '2-digit', minute: '2-digit'
    });
}

/**
 * Auto-detect identifier type from user input.
 * @param {string} input
 * @returns {string} - 'email'|'username'|'domain'|'ip'|'phone'|'name'|'keyword'
 */
function autoDetectIdentifierType(input) {
    if (!input) return 'keyword';
    input = input.trim();

    // Email
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) return 'email';

    // IP address (v4)
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(input)) return 'ip';

    // IP address (v6)
    if (/^([0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}$/.test(input)) return 'ip';

    // Phone number
    if (/^\+?\d[\d\s\-()]{7,}$/.test(input)) return 'phone';

    // Domain
    if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(input)) return 'domain';

    // Username (starts with @)
    if (/^@/.test(input)) return 'username';

    // Username-like (no spaces, has special chars)
    if (/^[a-zA-Z0-9_.\-]{3,30}$/.test(input) && !/\s/.test(input)) return 'username';

    // Multi-word likely a name
    if (/^[A-Z][a-z]+ [A-Z][a-z]+/.test(input)) return 'name';

    return 'keyword';
}

/**
 * Render markdown text using the marked library.
 * Falls back to basic formatting if marked is not loaded.
 * @param {string} text
 * @returns {string} HTML
 */
function renderMarkdown(text) {
    if (!text) return '';
    if (typeof marked !== 'undefined' && marked.parse) {
        try {
            return marked.parse(text);
        } catch (e) {
            console.warn('[Markdown] Parsing failed, falling back:', e);
        }
    }
    // Basic fallback
    return escapeHtml(text)
        .replace(/\n\n/g, '<br><br>')
        .replace(/\n/g, '<br>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/\*([^*]+)\*/g, '<em>$1</em>')
        .replace(/`([^`]+)`/g, '<code>$1</code>');
}

/* ====================================================================
   AUTHENTICATION
   ==================================================================== */

/**
 * Check authentication status on page load.
 */
async function checkAuth() {
    try {
        const response = await fetch('/me');
        if (response.ok) {
            const user = await response.json();
            showApp(user);
        } else {
            showLoginModal();
        }
    } catch (error) {
        console.error('[Auth] Check failed:', error);
        showLoginModal();
    }
}

/**
 * Redirect to OAuth login.
 */
function handleLogin() {
    window.location.href = '/oauth/login';
}

/**
 * Log out: POST /logout, reset state, show login modal.
 */
async function handleLogout() {
    try {
        await fetch('/logout', { method: 'POST' });
    } catch (e) {
        console.error('[Auth] Logout error:', e);
    }

    sessionId = null;
    currentTool = 'ingest';
    chatMessages = [];
    mapInstance = null;
    graphInstance = null;
    stopWatchRefresh();

    showLoginModal();
}

/**
 * Show the login modal and hide the main app.
 */
function showLoginModal() {
    const modal = document.getElementById('loginModal');
    if (modal) modal.style.display = 'flex';

    // Hide main app container
    const appContainer = document.querySelector('.app-container');
    if (appContainer) appContainer.style.display = 'none';

    const topbar = document.querySelector('.topbar');
    if (topbar) topbar.style.display = 'none';
}

/**
 * Show the main app, populate user info, hide login modal.
 * @param {object} user - user data from /me
 */
function showApp(user) {
    const modal = document.getElementById('loginModal');
    if (modal) modal.style.display = 'none';

    const appContainer = document.querySelector('.app-container');
    if (appContainer) appContainer.style.display = '';

    const topbar = document.querySelector('.topbar');
    if (topbar) topbar.style.display = '';

    // Set user info
    const avatar = document.getElementById('userAvatar');
    const name = document.getElementById('userName');
    if (user.picture && avatar) {
        avatar.src = user.picture;
        avatar.style.display = 'block';
    } else if (avatar) {
        avatar.style.display = 'none';
    }
    if (name) name.textContent = user.name || user.email || '';
}

/* ====================================================================
   OSINT STATUS
   ==================================================================== */

/**
 * Fetch OSINT platform configuration status from backend.
 */
async function fetchOsintStatus() {
    try {
        const response = await fetch('/osint-status');
        if (!response.ok) return;

        const data = await response.json();
        const dot = document.getElementById('osintStatusDot');
        const text = document.getElementById('osintStatusText');

        if (!dot || !text) return;

        const configured = data.configured || [];
        const unconfigured = data.unconfigured || [];

        if (configured.length > 0) {
            dot.classList.add('online');
            dot.classList.remove('offline');
            text.textContent = 'OSINT Online (' + configured.length + ')';
            text.title = 'Configured: ' + configured.join(', ') +
                (unconfigured.length > 0 ? '\nUnconfigured: ' + unconfigured.join(', ') : '');
        } else {
            dot.classList.add('offline');
            dot.classList.remove('online');
            text.textContent = 'No OSINT Sources';
            text.title = 'No platforms configured. Check your environment variables.';
        }
    } catch (e) {
        console.warn('[OSINT] Status check failed:', e);
    }
}

/* ====================================================================
   TOOL CARD SWITCHING
   ==================================================================== */

/**
 * Names and titles mapping for each tool.
 */
const TOOL_TITLES = {
    ingest: 'Report Ingestion',
    investigate: 'Investigation',
    geo: 'Geolocation',
    batch: 'Batch Investigation',
    monitor: 'Feed Monitor',
    scenario: 'Scenarios',
    qa: 'Q&A (RAG)'
};

/**
 * Select a tool card, show its form, hide others.
 * @param {string} toolName
 */
function selectTool(toolName) {
    currentTool = toolName;

    // Update card active state
    document.querySelectorAll('.tool-card').forEach(function (card) {
        if (card.dataset.tool === toolName) {
            card.classList.add('active');
        } else {
            card.classList.remove('active');
        }
    });

    // Show matching form, hide others
    document.querySelectorAll('.tool-form').forEach(function (form) {
        if (form.id === 'form-' + toolName) {
            form.classList.add('active');
        } else {
            form.classList.remove('active');
        }
    });

    // Update panel title
    const title = document.getElementById('inputPanelTitle');
    if (title) title.textContent = TOOL_TITLES[toolName] || toolName;

    // Show/hide submit footer (Q&A has its own send button)
    const footer = document.getElementById('inputPanelFooter');
    if (footer) {
        footer.style.display = (toolName === 'qa') ? 'none' : '';
    }

    // Update submit button label
    const submitBtn = document.getElementById('btnSubmit');
    if (submitBtn) {
        const labels = {
            ingest: 'Upload & Ingest',
            investigate: 'Start Investigation',
            geo: 'Triangulate',
            batch: 'Run Batch',
            monitor: 'Create Monitor',
            scenario: 'Generate Scenario',
            qa: 'Send'
        };
        submitBtn.innerHTML = '&#x25B6; ' + (labels[toolName] || 'Execute');
    }

    // Clear results when switching tools
    clearResults();
}

/* ====================================================================
   FILE UPLOAD (Report Ingestion)
   ==================================================================== */

/**
 * Initialize drag-and-drop on an upload zone.
 * @param {string} zoneId - ID of the drop zone element
 * @param {string} inputId - ID of the file input element
 * @param {string} listId - ID of the file list display element
 * @param {string[]} acceptedTypes - MIME type prefixes or extensions
 */
function initDropZone(zoneId, inputId, listId, acceptedTypes) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    const list = document.getElementById(listId);

    if (!zone || !input) return;

    // Click to browse
    zone.addEventListener('click', function (e) {
        if (e.target === input) return; // Don't recurse
        input.click();
    });

    // Drag events
    zone.addEventListener('dragover', function (e) {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.add('dragover');
    });

    zone.addEventListener('dragleave', function (e) {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.remove('dragover');
    });

    zone.addEventListener('drop', function (e) {
        e.preventDefault();
        e.stopPropagation();
        zone.classList.remove('dragover');

        if (e.dataTransfer.files.length > 0) {
            input.files = e.dataTransfer.files;
            updateFileList(input, list);
        }
    });

    // File input change
    input.addEventListener('change', function () {
        updateFileList(input, list);
    });
}

/**
 * Update the file list display below a drop zone.
 * @param {HTMLInputElement} input
 * @param {HTMLElement} list
 */
function updateFileList(input, list) {
    if (!list) return;
    list.innerHTML = '';

    Array.from(input.files).forEach(function (file) {
        const item = document.createElement('div');
        item.className = 'upload-file-item';
        item.innerHTML = '<span class="upload-file-name">' + escapeHtml(file.name) + '</span>' +
            '<span class="upload-file-size">' + formatFileSize(file.size) + '</span>';
        list.appendChild(item);
    });
}

/**
 * Format bytes into human-readable file size.
 * @param {number} bytes
 * @returns {string}
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB'];
    var i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

/**
 * Upload files for report ingestion.
 */
async function uploadReport() {
    const input = document.getElementById('ingestFiles');
    if (!input || !input.files.length) {
        showToast('Please select a file to upload.', 'warning');
        return;
    }

    // Validate file types
    const allowedExtensions = ['.pdf', '.md', '.txt'];
    for (var i = 0; i < input.files.length; i++) {
        var file = input.files[i];
        var ext = '.' + file.name.split('.').pop().toLowerCase();
        if (allowedExtensions.indexOf(ext) === -1) {
            showToast('Invalid file type: ' + file.name + '. Only PDF, MD, and TXT are allowed.', 'error');
            return;
        }
    }

    showLoading();
    showToast('Uploading and processing report...', 'info');

    try {
        const formData = new FormData();
        for (var j = 0; j < input.files.length; j++) {
            formData.append('file', input.files[j]);
        }

        // Add tags if provided
        const tagsInput = document.getElementById('ingestTags');
        if (tagsInput && tagsInput.value.trim()) {
            formData.append('tags', tagsInput.value.trim());
        }

        const response = await fetchApi('/upload', {
            method: 'POST',
            body: formData,
            headers: {} // Let browser set multipart boundary
        });

        const data = await response.json();

        if (data.error) {
            showToast('Upload error: ' + data.error, 'error');
            hideLoading();
            return;
        }

        sessionId = data.session_id;
        showToast('Report ingested successfully.', 'success');

        // Store for export — backend resolves full content from session_id
        lastAnalysisData = {
            session_id: sessionId,
            analysis: 'Report ingested: ' + (data.char_count || 0) + ' characters',
            sensitivity_level: 'INTERNAL',
            identifier: sessionId
        };

        // Show results
        showResults();
        const content = document.getElementById('resultsContent');
        if (content) {
            var html = '<div class="result-section">';
            html += '<h3>Report Ingested</h3>';
            html += '<p>Session ID: <code>' + escapeHtml(sessionId) + '</code></p>';
            if (data.pages) html += '<p>Pages processed: ' + escapeHtml(String(data.pages)) + '</p>';
            if (data.chunks) html += '<p>Chunks created: ' + escapeHtml(String(data.chunks)) + '</p>';
            if (data.mitre_techniques && data.mitre_techniques.length > 0) {
                html += '<p>MITRE techniques detected: ' + data.mitre_techniques.length + '</p>';
                html += '<div class="tag-list">';
                data.mitre_techniques.forEach(function (t) {
                    html += '<span class="tag">' + escapeHtml(t) + '</span>';
                });
                html += '</div>';
            }
            if (data.osint_available) {
                html += '<div class="osint-enrich-prompt">';
                html += '<p>OSINT enrichment is available for this report.</p>';
                html += '<button class="btn btn-secondary" id="btnEnrichOsint">Enrich with OSINT</button>';
                html += '</div>';
            }
            html += '</div>';
            content.innerHTML = html;

            // Bind OSINT enrich button
            var enrichBtn = document.getElementById('btnEnrichOsint');
            if (enrichBtn) {
                enrichBtn.addEventListener('click', function () {
                    enrichWithOsint();
                });
            }
        }
    } catch (error) {
        showToast('Upload failed: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

/**
 * Enrich uploaded report with OSINT data.
 */
async function enrichWithOsint() {
    if (!sessionId) {
        showToast('No report uploaded yet.', 'warning');
        return;
    }

    showLoading();
    try {
        const response = await fetchApi('/enrich', {
            method: 'POST',
            body: JSON.stringify({ session_id: sessionId })
        });

        const data = await response.json();
        if (data.error) {
            showToast('Enrichment error: ' + data.error, 'error');
        } else {
            showToast('Report enriched with OSINT data.', 'success');
            if (data.analysis) {
                renderAnalysis(data);
            }
        }
    } catch (error) {
        showToast('Enrichment failed: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

/* ====================================================================
   INVESTIGATION
   ==================================================================== */

/**
 * Run an investigation against selected platforms.
 */
async function runInvestigation() {
    const subject = document.getElementById('investSubject');
    const idTypeSelect = document.getElementById('investIdType');
    const depthSelect = document.getElementById('investDepth');
    const purposeTextarea = document.getElementById('investPurpose');

    if (!subject || !subject.value.trim()) {
        showToast('Please enter a subject identifier.', 'warning');
        return;
    }

    // Gather selected platforms
    var platforms = [];
    document.querySelectorAll('#investPlatforms input[type="checkbox"]:checked').forEach(function (cb) {
        platforms.push(cb.value);
    });

    // Determine identifier type
    var idType = idTypeSelect ? idTypeSelect.value : 'auto';
    if (idType === 'auto') {
        idType = autoDetectIdentifierType(subject.value.trim());
    }

    showLoading();
    showResults();
    var content = document.getElementById('resultsContent');
    if (content) {
        var scopeMsg = platforms.length > 0
            ? 'across ' + platforms.length + ' platforms'
            : 'via web dorking (all platforms)';
        content.innerHTML = '<div class="result-section"><p>Investigating <strong>' +
            escapeHtml(subject.value.trim()) + '</strong> ' + scopeMsg + '...</p></div>';
    }

    try {
        const webSearchCb = document.getElementById('investWebSearch');
        const mediaInput = document.getElementById('investMediaFiles');
        const mediaFiles = mediaInput ? mediaInput.files : null;
        const hasMedia = mediaFiles && mediaFiles.length > 0;

        var requestBody;
        var requestHeaders = {};

        if (hasMedia) {
            // Use FormData for multipart upload when media files are attached
            var fd = new FormData();
            fd.append('identifier', subject.value.trim());
            fd.append('identifier_type', idType);
            fd.append('platforms', JSON.stringify(platforms));
            fd.append('depth', depthSelect ? depthSelect.value : 'standard');
            fd.append('investigation_purpose', purposeTextarea ? purposeTextarea.value.trim() : '');
            fd.append('web_search', webSearchCb ? webSearchCb.checked : true);
            for (var i = 0; i < mediaFiles.length; i++) {
                fd.append('media_files', mediaFiles[i]);
            }
            requestBody = fd;
            // Let browser set multipart Content-Type with boundary
        } else {
            requestBody = JSON.stringify({
                identifier: subject.value.trim(),
                identifier_type: idType,
                platforms: platforms,
                depth: depthSelect ? depthSelect.value : 'standard',
                investigation_purpose: purposeTextarea ? purposeTextarea.value.trim() : '',
                web_search: webSearchCb ? webSearchCb.checked : true
            });
        }

        const response = await fetchApi('/investigate', {
            method: 'POST',
            body: requestBody,
            headers: requestHeaders
        });

        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.error || 'Investigation failed');
        }

        const data = await response.json();

        if (data.error) {
            showToast('Investigation error: ' + data.error, 'error');
            hideLoading();
            return;
        }

        // Store session if returned
        if (data.session_id) sessionId = data.session_id;

        renderAnalysis(data);

    } catch (error) {
        showToast('Investigation failed: ' + error.message, 'error');
        if (content) {
            content.innerHTML = '<div class="result-section result-error"><p>Error: ' +
                escapeHtml(error.message) + '</p></div>';
        }
    } finally {
        hideLoading();
    }
}

/* ====================================================================
   GEOLOCATION
   ==================================================================== */

/**
 * Get the currently active geolocation tab.
 * @returns {string}
 */
function getActiveGeoTab() {
    var activeTab = document.querySelector('#geoTabs .tab.active');
    return activeTab ? activeTab.dataset.geoTab : 'images';
}

/**
 * Switch geolocation tabs.
 * @param {string} tabName
 */
function switchGeoTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('#geoTabs .tab').forEach(function (tab) {
        if (tab.dataset.geoTab === tabName) {
            tab.classList.add('active');
        } else {
            tab.classList.remove('active');
        }
    });

    // Show/hide tab content
    var tabIds = ['images', 'social', 'ip', 'manual'];
    tabIds.forEach(function (id) {
        var panel = document.getElementById('geoTab-' + id);
        if (panel) {
            if (id === tabName) {
                panel.classList.add('active');
            } else {
                panel.classList.remove('active');
            }
        }
    });
}

/**
 * Run geolocation triangulation based on active tab.
 */
async function runGeolocation() {
    var activeTab = getActiveGeoTab();
    var dataPoints = [];

    if (activeTab === 'images') {
        var imageInput = document.getElementById('geoImages');
        if (!imageInput || !imageInput.files.length) {
            showToast('Please select images for geolocation analysis.', 'warning');
            return;
        }

        showLoading();

        var formData = new FormData();
        for (var i = 0; i < imageInput.files.length; i++) {
            formData.append('images', imageInput.files[i]);
        }

        try {
            var response = await fetchApi('/triangulate', {
                method: 'POST',
                body: formData,
                headers: {}
            });

            if (!response.ok) {
                var errData = await response.json();
                throw new Error(errData.error || 'Geolocation failed');
            }

            var data = await response.json();
            renderAnalysis(data);
        } catch (error) {
            showToast('Geolocation failed: ' + error.message, 'error');
        } finally {
            hideLoading();
        }
        return;
    }

    // For text-based tabs: gather data points
    if (activeTab === 'social') {
        var socialInput = document.getElementById('geoSocialInput');
        if (socialInput && socialInput.value.trim()) {
            socialInput.value.trim().split('\n').forEach(function (line) {
                line = line.trim();
                if (line) dataPoints.push({ type: 'social_post', value: line });
            });
        }
    } else if (activeTab === 'ip') {
        var ipInput = document.getElementById('geoIpInput');
        if (ipInput && ipInput.value.trim()) {
            ipInput.value.trim().split('\n').forEach(function (line) {
                line = line.trim();
                if (line) dataPoints.push({ type: 'ip', value: line });
            });
        }
    } else if (activeTab === 'manual') {
        var manualInput = document.getElementById('geoManualInput');
        if (manualInput && manualInput.value.trim()) {
            manualInput.value.trim().split('\n').forEach(function (line) {
                line = line.trim();
                if (!line) return;
                // Try to parse as lat,lng
                var parts = line.split(',');
                if (parts.length === 2 && !isNaN(parseFloat(parts[0])) && !isNaN(parseFloat(parts[1]))) {
                    dataPoints.push({
                        type: 'coordinates',
                        lat: parseFloat(parts[0].trim()),
                        lng: parseFloat(parts[1].trim())
                    });
                } else {
                    dataPoints.push({ type: 'address', value: line });
                }
            });
        }
    }

    if (dataPoints.length === 0) {
        showToast('Please enter at least one data point.', 'warning');
        return;
    }

    showLoading();

    try {
        var response = await fetchApi('/triangulate', {
            method: 'POST',
            body: JSON.stringify({ data_points: dataPoints })
        });

        if (!response.ok) {
            var errData = await response.json();
            throw new Error(errData.error || 'Triangulation failed');
        }

        var data = await response.json();
        renderAnalysis(data);
    } catch (error) {
        showToast('Triangulation failed: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

/* ====================================================================
   BATCH INVESTIGATION
   ==================================================================== */

/**
 * Run batch investigation on multiple identifiers.
 */
async function runBatchInvestigation() {
    var textarea = document.getElementById('batchIdentifiers');
    var fileInput = document.getElementById('batchFile');
    var idTypeSelect = document.getElementById('batchIdType');

    var rawText = textarea ? textarea.value.trim() : '';
    var hasFile = fileInput && fileInput.files.length > 0;

    if (!rawText && !hasFile) {
        showToast('Please enter identifiers or upload a file.', 'warning');
        return;
    }

    // Gather platforms
    var platforms = [];
    document.querySelectorAll('#batchPlatforms input[type="checkbox"]:checked').forEach(function (cb) {
        platforms.push(cb.value);
    });

    showLoading();
    showResults();

    var content = document.getElementById('resultsContent');
    if (content) {
        content.innerHTML = '<div class="result-section"><p>Processing batch investigation...</p></div>';
        content.style.display = '';
    }

    try {
        var response;
        if (hasFile) {
            var formData = new FormData();
            formData.append('file', fileInput.files[0]);
            if (rawText) formData.append('identifiers', rawText);
            formData.append('identifier_type', idTypeSelect ? idTypeSelect.value : 'auto');
            formData.append('platforms', JSON.stringify(platforms));

            response = await fetchApi('/batch-investigate', {
                method: 'POST',
                body: formData,
                headers: {}
            });
        } else {
            var idType = idTypeSelect ? idTypeSelect.value : 'auto';
            var lines = rawText.split(/[\n,]+/).map(function(l) { return l.trim(); }).filter(Boolean);
            var identifiersList = lines.map(function(line) {
                return {
                    identifier: line,
                    identifier_type: idType === 'auto' ? autoDetectIdentifierType(line) : idType
                };
            });
            response = await fetchApi('/batch-investigate', {
                method: 'POST',
                body: JSON.stringify({
                    identifiers: identifiersList,
                    platforms: platforms
                })
            });
        }

        if (!response.ok) {
            var errData = await response.json();
            throw new Error(errData.error || 'Batch investigation failed');
        }

        var data = await response.json();

        if (data.error) {
            showToast('Batch error: ' + data.error, 'error');
            hideLoading();
            return;
        }

        // Render synthesis
        if (content) {
            var html = '';

            // Summary header
            if (data.summary) {
                html += '<div class="result-section batch-summary">';
                html += '<h3>Batch Summary</h3>';
                html += '<div class="batch-stats">';
                html += '<div class="batch-stat"><span class="batch-stat-value">' + (data.summary.total || 0) + '</span><span class="batch-stat-label">Total</span></div>';
                html += '<div class="batch-stat"><span class="batch-stat-value">' + (data.summary.successful || 0) + '</span><span class="batch-stat-label">Successful</span></div>';
                html += '<div class="batch-stat"><span class="batch-stat-value">' + (data.summary.failed || 0) + '</span><span class="batch-stat-label">Failed</span></div>';
                html += '</div>';
                html += '</div>';
            }

            // Synthesis
            if (data.synthesis) {
                html += '<div class="result-section">';
                html += '<h3>Synthesis</h3>';
                html += renderMarkdown(data.synthesis);
                html += '</div>';
            }

            // Per-entity results
            if (data.results && data.results.length > 0) {
                html += '<div class="result-section">';
                html += '<h3>Individual Results</h3>';
                data.results.forEach(function (r) {
                    html += '<details class="batch-entity-result">';
                    html += '<summary><strong>' + escapeHtml(r.identifier || 'Unknown') + '</strong>';
                    if (r.status) html += ' <span class="badge badge-' + (r.status === 'success' ? 'success' : 'error') + '">' + escapeHtml(r.status) + '</span>';
                    html += '</summary>';
                    html += '<div class="batch-entity-body">';
                    if (r.analysis) html += renderMarkdown(r.analysis);
                    if (r.error) html += '<p class="text-error">' + escapeHtml(r.error) + '</p>';
                    html += '</div>';
                    html += '</details>';
                });
                html += '</div>';
            }

            if (data.civilian_harm) {
                html += renderCivilianHarmSection(data.civilian_harm);
            }

            content.innerHTML = html;
        }

        // Use renderAnalysis to handle tabs/map/graph properly
        // We already set the content HTML above, so pass analysis=null
        var renderData = {
            map_data: data.map_data || null,
            graph_data: data.graph_data || null,
            chart_data: data.chart_data || null,
            sensitivity: data.sensitivity_level || null,
        };
        // Show tabs and views
        showResults();

        var hasMap = !!(renderData.map_data && ((renderData.map_data.markers && renderData.map_data.markers.length > 0) || renderData.map_data.triangulation));
        var hasGraph = !!renderData.graph_data;
        var hasCharts = !!renderData.chart_data;

        var tabMap = document.getElementById('tabMap');
        var tabGraph = document.getElementById('tabGraph');
        var tabCharts = document.getElementById('tabCharts');
        if (tabMap) tabMap.style.display = hasMap ? '' : 'none';
        if (tabGraph) tabGraph.style.display = hasGraph ? '' : 'none';
        if (tabCharts) tabCharts.style.display = hasCharts ? '' : 'none';

        if (renderData.graph_data) renderGraph(renderData.graph_data);
        if (renderData.chart_data) renderCharts(renderData.chart_data);

        switchResultTab('analysis');

        if (hasMap) {
            setTimeout(function () {
                renderMap(renderData.map_data);
                if (mapInstance) {
                    setTimeout(function () { mapInstance.invalidateSize(); }, 100);
                }
            }, 60);
        }

    } catch (error) {
        showToast('Batch investigation failed: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

/* ====================================================================
   FEED MONITOR
   ==================================================================== */

/**
 * Create a new feed monitor.
 */
async function createMonitor() {
    var typeSelect = document.getElementById('monitorType');
    var queryInput = document.getElementById('monitorQuery');
    var intervalSelect = document.getElementById('monitorInterval');
    var thresholdSelect = document.getElementById('monitorThreshold');

    if (!queryInput || !queryInput.value.trim()) {
        showToast('Please enter a search query.', 'warning');
        return;
    }

    // Gather platforms
    var platforms = [];
    document.querySelectorAll('#monitorPlatforms input[type="checkbox"]:checked').forEach(function (cb) {
        platforms.push(cb.value);
    });

    if (platforms.length === 0) {
        showToast('Please select at least one platform.', 'warning');
        return;
    }

    showLoading();

    try {
        var response = await fetchApi('/monitor/create', {
            method: 'POST',
            body: JSON.stringify({
                monitor_type: typeSelect ? typeSelect.value : 'keyword',
                query: queryInput.value.trim(),
                platforms: platforms,
                interval_minutes: intervalSelect ? parseInt(intervalSelect.value, 10) : 15,
                threshold: thresholdSelect ? thresholdSelect.value : 'high_confidence'
            })
        });

        if (!response.ok) {
            var errData = await response.json();
            throw new Error(errData.error || 'Monitor creation failed');
        }

        var data = await response.json();
        showToast('Monitor created: ' + (data.monitor_id || 'OK'), 'success');

        // Show in results
        showResults();
        var content = document.getElementById('resultsContent');
        if (content) {
            content.innerHTML = '<div class="result-section">' +
                '<h3>Monitor Created</h3>' +
                '<p>Monitor ID: <code>' + escapeHtml(data.monitor_id || '') + '</code></p>' +
                '<p>Watching for: <strong>' + escapeHtml(queryInput.value.trim()) + '</strong></p>' +
                '<p>Platforms: ' + escapeHtml(platforms.join(', ')) + '</p>' +
                '<p>Interval: every ' + escapeHtml(intervalSelect ? intervalSelect.value : '15') + ' minutes</p>' +
                '</div>';
            content.style.display = '';
        }

        // Refresh monitor list
        loadMonitorList();

    } catch (error) {
        showToast('Monitor creation failed: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

/**
 * Load the list of active monitors.
 */
async function loadMonitorList() {
    try {
        var response = await fetchApi('/monitor/list');
        if (!response.ok) return;
        var data = await response.json();
        // The monitor list could be displayed in results or a panel.
        // For now this is used internally.
        return data.monitors || [];
    } catch (e) {
        console.warn('[Monitor] List load failed:', e);
        return [];
    }
}

/* ====================================================================
   SCENARIO GENERATION
   ==================================================================== */

/**
 * Run a scenario analysis against the /scenario endpoint.
 */
async function runScenario() {
    var typeSelect = document.getElementById('scenarioType');
    var sessionInput = document.getElementById('scenarioSessionId');
    var subjectCtx = document.getElementById('scenarioSubjectCtx');
    var osintData = document.getElementById('scenarioOsintData');

    var scenarioType = typeSelect ? typeSelect.value : 'pattern_of_life';

    // Need at least a session reference or OSINT data
    var refSession = sessionInput ? sessionInput.value.trim() : '';
    var rawOsint = osintData ? osintData.value.trim() : '';
    var subjectContext = subjectCtx ? subjectCtx.value.trim() : '';

    if (!refSession && !rawOsint) {
        showToast('Provide a session reference or paste OSINT data for scenario analysis.', 'warning');
        return;
    }

    showLoading();
    showResults();

    var content = document.getElementById('resultsContent');
    if (content) {
        var typeLabel = {
            pattern_of_life: 'Pattern of Life',
            network_mapping: 'Network Mapping',
            location_prediction: 'Location Prediction',
            influence_analysis: 'Influence Analysis'
        };
        content.innerHTML = '<div class="result-section"><p>Generating <strong>' +
            escapeHtml(typeLabel[scenarioType] || scenarioType) +
            '</strong> scenario analysis...</p></div>';
        content.style.display = '';
    }

    try {
        var payload = {
            scenario_type: scenarioType,
            subject_context: subjectContext
        };
        if (refSession) payload.session_id = refSession;
        if (rawOsint) payload.osint_data = rawOsint;

        var response = await fetchApi('/scenario', {
            method: 'POST',
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            var errData = await response.json();
            throw new Error(errData.error || 'Scenario generation failed');
        }

        var data = await response.json();

        if (data.error) {
            showToast('Scenario error: ' + data.error, 'error');
            hideLoading();
            return;
        }

        // Store session if returned
        if (data.session_id) sessionId = data.session_id;

        // Render scenario analysis using renderAnalysis
        renderAnalysis({
            analysis: data.scenario || data.analysis || '',
            sensitivity_level: 'INTERNAL',
            session_id: data.session_id,
            identifier: scenarioType,
            identifier_type: 'scenario',
            civilian_harm: data.civilian_harm || null
        });

        // Store for export
        lastAnalysisData = {
            analysis: data.scenario || data.analysis || '',
            session_id: data.session_id || sessionId,
            sensitivity_level: 'INTERNAL',
            identifier: scenarioType,
            identifier_type: 'scenario',
            civilian_harm: data.civilian_harm || null
        };

        showToast('Scenario analysis complete.', 'success');

    } catch (error) {
        showToast('Scenario generation failed: ' + error.message, 'error');
        if (content) {
            content.innerHTML = '<div class="result-section result-error"><p>Error: ' +
                escapeHtml(error.message) + '</p></div>';
        }
    } finally {
        hideLoading();
    }
}

/* ====================================================================
   Q&A (RAG)
   ==================================================================== */

/**
 * Send a question to the RAG Q&A endpoint.
 */
async function sendChatMessage() {
    var input = document.getElementById('chatInput');
    if (!input || !input.value.trim()) return;

    var question = input.value.trim();
    input.value = '';

    appendChatMessage('user', question);
    var typingId = appendChatMessage('ai', '<span class="typing-indicator">Thinking...</span>', true);

    try {
        var response = await fetchApi('/ask', {
            method: 'POST',
            body: JSON.stringify({
                session_id: sessionId || '',
                question: question
            })
        });

        if (!response.ok) {
            var errData = await response.json();
            throw new Error(errData.error || 'Q&A failed');
        }

        var data = await response.json();
        removeChatMessage(typingId);

        if (data.error) {
            appendChatMessage('ai', 'Error: ' + data.error);
            return;
        }

        // ── Action dispatch: route to the appropriate pipeline ──
        if (data.action) {
            appendChatMessage('ai', renderMarkdown(data.message), false, true);
            await _dispatchChatAction(data.action, data.params, question);
            return;
        }

        // ── Standard Q&A answer ──
        if (data.answer) {
            var kbNote = '';
            if (data.kb_context) {
                kbNote = '<div class="kb-context-indicator">Based on Knowledge Base context</div>';
            }
            var harmNote = '';
            if (data.civilian_harm && data.civilian_harm.score >= 0.35) {
                var ch = data.civilian_harm;
                harmNote = '<div class="ch-inline-alert">' +
                    '<span class="wi-badge ch-badge-' + (ch.classification || 'none').toLowerCase() + '">' +
                    'CIVILIAN HARM: ' + ch.classification + ' (' + ((ch.score || 0) * 100).toFixed(0) + '%)</span>';
                if (ch.matched_concepts && ch.matched_concepts.length) {
                    harmNote += ' <span class="ch-concepts-inline">' +
                        ch.matched_concepts.map(function(c) { return escapeHtml(c); }).join(', ') +
                        '</span>';
                }
                harmNote += '</div>';
            }
            appendChatMessage('ai', kbNote + harmNote + renderMarkdown(data.answer), false, true);

            chatMessages.push({ role: 'user', text: question, timestamp: new Date().toISOString() });
            chatMessages.push({ role: 'assistant', text: data.answer, timestamp: new Date().toISOString(), kb_context: data.kb_context || false });

            lastAnalysisData = {
                analysis: data.answer,
                session_id: sessionId || data.session_id || '',
                sensitivity_level: 'INTERNAL',
                identifier: 'Q&A Session',
                identifier_type: 'qa'
            };

            showResults();
            var resultsContent = document.getElementById('resultsContent');
            if (resultsContent) {
                resultsContent.innerHTML = '<div class="result-section analysis-content">' +
                    renderMarkdown(data.answer) + '</div>';
            }
        } else {
            appendChatMessage('ai', 'No response returned.');
        }
    } catch (error) {
        removeChatMessage(typingId);
        appendChatMessage('ai', 'Error: ' + error.message);
    }
}

/**
 * Dispatch a chat action to the appropriate endpoint and render structured results.
 */
async function _dispatchChatAction(action, params, originalQuestion) {
    var progressId = appendChatMessage('ai', '<span class="typing-indicator">Running ' + action + '...</span>', true);

    try {
        var response, result;

        if (action === 'investigate') {
            response = await fetchApi('/investigate', {
                method: 'POST',
                body: JSON.stringify({
                    identifier: params.identifier,
                    identifier_type: params.identifier_type,
                    depth: params.depth || 'standard',
                    investigation_purpose: params.investigation_purpose || 'OSINT investigation',
                    platforms: Object.keys(window.SOCIAL_PLATFORMS || {}).length ?
                        Object.keys(window.SOCIAL_PLATFORMS) :
                        ['twitter', 'reddit', 'telegram', 'instagram', 'youtube', 'mastodon', 'facebook', 'tiktok']
                })
            });

        } else if (action === 'scenario') {
            response = await fetchApi('/scenario', {
                method: 'POST',
                body: JSON.stringify({
                    scenario_type: params.scenario_type,
                    subject_context: params.subject_context || '',
                    session_id: params.session_id || sessionId || '',
                    osint_data: params.osint_data || ''
                })
            });

        } else if (action === 'batch') {
            response = await fetchApi('/batch-investigate', {
                method: 'POST',
                body: JSON.stringify({
                    identifiers: params.identifiers,
                    platforms: ['twitter', 'reddit', 'telegram', 'instagram']
                })
            });

        } else if (action === 'monitor') {
            response = await fetchApi('/monitor/create', {
                method: 'POST',
                body: JSON.stringify({
                    monitor_type: params.monitor_type || 'keyword',
                    query: params.query,
                    interval_minutes: 15
                })
            });

        } else {
            removeChatMessage(progressId);
            appendChatMessage('ai', 'Unknown action: ' + action);
            return;
        }

        removeChatMessage(progressId);

        if (!response.ok) {
            var errData = await response.json();
            appendChatMessage('ai', 'Error: ' + (errData.error || errData.reason || 'Request failed'));
            return;
        }

        result = await response.json();

        if (result.error) {
            appendChatMessage('ai', 'Error: ' + result.error);
            return;
        }

        // Update session ID from result
        if (result.session_id) {
            sessionId = result.session_id;
        }

        // Render structured results through the standard analysis pipeline
        if (result.analysis || result.consolidated_analysis) {
            var analysisData = result;
            if (result.consolidated_analysis && !result.analysis) {
                analysisData.analysis = result.consolidated_analysis;
            }
            appendChatMessage('ai', '<div class="chat-action-complete">Analysis complete — results shown in the report panel.</div>', false, true);
            renderAnalysis(analysisData);
        } else if (action === 'monitor' && result.monitor_id) {
            appendChatMessage('ai', renderMarkdown(
                '**Monitor created successfully.**\n\n' +
                '- Monitor ID: `' + result.monitor_id + '`\n' +
                '- Type: ' + (params.monitor_type || 'keyword') + '\n' +
                '- Query: ' + params.query + '\n' +
                '- Interval: every 15 minutes'
            ), false, true);
        } else {
            appendChatMessage('ai', renderMarkdown('Action completed. Response:\n\n```json\n' +
                JSON.stringify(result, null, 2).substring(0, 500) + '\n```'), false, true);
        }

    } catch (error) {
        removeChatMessage(progressId);
        appendChatMessage('ai', 'Error running ' + action + ': ' + error.message);
    }
}

/**
 * Append a message to the Q&A chat panel.
 * @param {'user'|'ai'} role
 * @param {string} content - HTML content
 * @param {boolean} isRaw - if true, content is used as innerHTML directly
 * @param {boolean} isHtml - if true, content is already HTML (don't escape)
 * @returns {string} message element ID
 */
function appendChatMessage(role, content, isRaw, isHtml) {
    var container = document.getElementById('chatMessages');
    if (!container) return '';

    var msgId = 'chat-msg-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5);

    var msg = document.createElement('div');
    msg.className = 'chat-message ' + role;
    msg.id = msgId;

    var avatar = document.createElement('div');
    avatar.className = 'chat-avatar';
    avatar.textContent = role === 'user' ? 'U' : 'F';

    var bubble = document.createElement('div');
    bubble.className = 'chat-bubble';

    if (isRaw || isHtml) {
        bubble.innerHTML = content;
    } else {
        bubble.textContent = content;
    }

    msg.appendChild(avatar);
    msg.appendChild(bubble);
    container.appendChild(msg);

    // Scroll to bottom
    container.scrollTop = container.scrollHeight;

    return msgId;
}

/**
 * Remove a chat message by ID (e.g., typing indicator).
 * @param {string} msgId
 */
function removeChatMessage(msgId) {
    if (!msgId) return;
    var el = document.getElementById(msgId);
    if (el && el.parentNode) el.parentNode.removeChild(el);
}

/* ====================================================================
   RESULTS RENDERING
   ==================================================================== */

/**
 * Clear results panel and show empty state.
 */
var currentViewMode = 'tab'; // 'tab' or 'split'

function clearResults() {
    var content = document.getElementById('resultsContent');
    var empty = document.getElementById('resultsEmpty');
    var chartsContainer = document.getElementById('chartsContainer');
    var exportBar = document.getElementById('exportBar');
    var sensitivity = document.getElementById('resultsSensitivity');
    var resultViews = document.getElementById('resultViews');
    var resultTabs = document.getElementById('resultTabs');
    var viewToggle = document.getElementById('viewToggleBtn');

    if (content) content.innerHTML = '';
    if (empty) empty.style.display = '';
    if (chartsContainer) { chartsContainer.innerHTML = ''; chartsContainer.classList.remove('visible'); }
    if (exportBar) exportBar.classList.remove('visible');
    if (sensitivity) sensitivity.innerHTML = '';
    if (resultViews) { resultViews.style.display = 'none'; resultViews.classList.remove('split-view', 'tab-view'); }
    if (resultTabs) resultTabs.style.display = 'none';
    if (viewToggle) viewToggle.style.display = 'none';

    // Hide all tabs
    ['tabMap', 'tabGraph', 'tabCharts'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });

    // Destroy existing map
    if (mapInstance) {
        mapInstance.remove();
        mapInstance = null;
    }

    lastAnalysisData = null;
}

function showResults() {
    var empty = document.getElementById('resultsEmpty');
    var resultViews = document.getElementById('resultViews');
    var resultTabs = document.getElementById('resultTabs');
    var exportBar = document.getElementById('exportBar');

    if (empty) empty.style.display = 'none';
    if (resultViews) resultViews.style.display = '';
    if (resultTabs) resultTabs.style.display = 'flex';
    if (exportBar) exportBar.classList.add('visible');
}

function switchResultTab(tabName) {
    var tabs = document.querySelectorAll('.result-tab');
    var panes = document.querySelectorAll('.result-pane');
    var views = document.getElementById('resultViews');

    if (views) {
        views.classList.remove('split-view');
        views.classList.add('tab-view');
    }

    tabs.forEach(function (t) { t.classList.toggle('active', t.dataset.tab === tabName); });
    panes.forEach(function (p) {
        var paneTab = p.id.replace('pane', '').toLowerCase();
        p.classList.toggle('active', paneTab === tabName);
    });

    // Leaflet needs invalidateSize after becoming visible
    if (tabName === 'map' && mapInstance) {
        setTimeout(function () { mapInstance.invalidateSize(); }, 50);
    }

    currentViewMode = 'tab';
}

function enableSplitView() {
    var views = document.getElementById('resultViews');
    var paneAnalysis = document.getElementById('paneAnalysis');
    var paneMap = document.getElementById('paneMap');

    if (!views || !paneAnalysis || !paneMap) return;

    views.classList.remove('tab-view');
    views.classList.add('split-view');
    paneAnalysis.classList.add('active');
    paneMap.classList.add('active');

    // Highlight both tabs
    var tabs = document.querySelectorAll('.result-tab');
    tabs.forEach(function (t) {
        t.classList.toggle('active', t.dataset.tab === 'analysis' || t.dataset.tab === 'map');
    });

    currentViewMode = 'split';

    if (mapInstance) {
        setTimeout(function () { mapInstance.invalidateSize(); }, 50);
    }
}

function toggleViewMode() {
    if (currentViewMode === 'split') {
        switchResultTab('analysis');
    } else {
        enableSplitView();
    }
    var icon = document.getElementById('viewToggleIcon');
    if (icon) icon.innerHTML = currentViewMode === 'split' ? '&#x25A3;' : '&#x25A8;';
}

function renderAnalysis(data) {
    showResults();
    lastAnalysisData = data;

    var content = document.getElementById('resultsContent');
    var hasMap = false;
    var hasGraph = false;
    var hasCharts = false;

    // Render sensitivity badge
    var sensitivity = document.getElementById('resultsSensitivity');
    var sensLevel = data.sensitivity_level || data.sensitivity;
    if (sensitivity && sensLevel) {
        var badgeClass = 'badge-' + (sensLevel === 'RESTRICTED' || sensLevel === 'HIGH' ? 'error' :
            sensLevel === 'SENSITIVE' || sensLevel === 'MEDIUM' ? 'warning' : 'info');
        sensitivity.innerHTML = '<span class="badge ' + badgeClass + '">' +
            escapeHtml(sensLevel) + '</span>';
    }

    // Render analysis text
    if (content && data.analysis) {
        var html = '<div class="result-section analysis-content">' +
            renderMarkdown(data.analysis) + '</div>';

        var meta = data.metadata || data.findings_metadata || {};
        var domainIntel = meta.domain_intel || {};
        var ipIntel = meta.ip_intel || data.ip_intel || meta.ip_geolocation ? meta : null;

        if (domainIntel.domain) {
            html += renderDomainIntelSection(domainIntel);
        }
        if (ipIntel && (meta.ip_intel || meta.ip_geolocation)) {
            html += renderIpIntelSection(meta);
        }
        if (data.civilian_harm) {
            html += renderCivilianHarmSection(data.civilian_harm);
        }
        if (data.image_analysis && data.image_analysis.length > 0) {
            html += renderImageAnalysisSection(data.image_analysis);
        }

        content.innerHTML = html;
    }

    // Check for map data (defer rendering until pane is visible)
    if (data.map_data && (data.map_data.markers && data.map_data.markers.length > 0 || data.map_data.triangulation)) {
        hasMap = true;
    }

    // Render entity graph if present
    if (data.entity_graph) { renderGraph(data.entity_graph); hasGraph = true; }
    else if (data.graph_data) { renderGraph(data.graph_data); hasGraph = true; }

    // Render charts if present
    if (data.chart_data) { renderCharts(data.chart_data); hasCharts = true; }

    // Show relevant tabs
    var tabMap = document.getElementById('tabMap');
    var tabGraph = document.getElementById('tabGraph');
    var tabCharts = document.getElementById('tabCharts');
    if (tabMap) tabMap.style.display = hasMap ? '' : 'none';
    if (tabGraph) tabGraph.style.display = hasGraph ? '' : 'none';
    if (tabCharts) tabCharts.style.display = hasCharts ? '' : 'none';

    // Show split toggle only when we have both analysis + map
    var viewToggle = document.getElementById('viewToggleBtn');
    if (viewToggle) viewToggle.style.display = (data.analysis && hasMap) ? '' : 'none';

    // Default: split view if both analysis and map, otherwise tab view
    if (data.analysis && hasMap && window.innerWidth > 900) {
        enableSplitView();
    } else if (hasMap && !data.analysis) {
        switchResultTab('map');
    } else {
        switchResultTab('analysis');
    }

    // Render map AFTER pane is visible so Leaflet has real dimensions
    if (hasMap) {
        setTimeout(function () {
            renderMap(data.map_data);
            if (mapInstance) {
                setTimeout(function () { mapInstance.invalidateSize(); }, 100);
            }
        }, 60);
    }
}

/**
 * Render a Leaflet map with markers, triangulation overlay, heatmap.
 * @param {object} mapData - { markers, triangulation, heatmap, connections, center, zoom }
 */
function renderMap(mapData) {
    var mapContainer = document.getElementById('mapContainer');
    var mapDiv = document.getElementById('map');
    if (!mapContainer || !mapDiv) return;

    // Clear previous map
    if (mapInstance) {
        mapInstance.remove();
        mapInstance = null;
    }

    // Default center and zoom
    var center = mapData.center || [20, 0];
    var zoom = mapData.zoom || 3;

    // Initialize map
    mapInstance = L.map('map', {
        center: center,
        zoom: zoom,
        zoomControl: true,
        fullscreenControl: true,
        fullscreenControlOptions: { position: 'topright' }
    });

    // CartoDB Voyager — clean, professional basemap
    L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>',
        subdomains: 'abcd',
        maxZoom: 19
    }).addTo(mapInstance);

    // Layer groups for control — use markerClusterGroup for clustering
    var markerLayer = (typeof L.markerClusterGroup !== 'undefined')
        ? L.markerClusterGroup({
            maxClusterRadius: 50,
            spiderfyOnMaxZoom: true,
            showCoverageOnHover: false,
            zoomToBoundsOnClick: true,
            iconCreateFunction: function (cluster) {
                var count = cluster.getChildCount();
                var size = 'small';
                if (count >= 100) size = 'large';
                else if (count >= 10) size = 'medium';
                return L.divIcon({
                    html: '<div>' + count + '</div>',
                    className: 'marker-cluster marker-cluster-' + size,
                    iconSize: L.point(40, 40)
                });
            }
        })
        : L.layerGroup();
    markerLayer.addTo(mapInstance);
    var overlayLayers = { 'Markers': markerLayer };
    var bounds = [];

    // Color mapping by source type
    var sourceColors = {
        exif: '#16a34a',
        video_exif: '#15803d',
        video_landmark: '#f59e0b',
        nlp_mention: '#dc2626',
        ip_geolocation: '#2563eb',
        ip: '#2563eb',
        geotag: '#7c3aed',
        social: '#7c3aed',
        geocoding: '#0891b2',
        address: '#0891b2',
        mention: '#dc2626',
        manual: '#d97706',
        user_input: '#d97706',
        osint: '#7c3aed',
        default: '#2563eb'
    };

    // Render markers
    if (mapData.markers && mapData.markers.length > 0) {
        mapData.markers.forEach(function (m) {
            var lat = m.lat || m.latitude;
            var lng = m.lng || m.longitude;
            if (lat == null || lng == null) return;

            var srcType = m.source_type || m.type || 'default';
            var color = sourceColors[srcType] || sourceColors.default;

            // Outer glow ring
            L.circleMarker([lat, lng], {
                radius: 16,
                fillColor: color,
                color: 'transparent',
                fillOpacity: 0.12,
                interactive: false
            }).addTo(markerLayer);

            // Main marker
            var marker = L.circleMarker([lat, lng], {
                radius: 7,
                fillColor: color,
                color: '#ffffff',
                weight: 2,
                opacity: 1,
                fillOpacity: 0.9
            });

            // Popup
            var popupHtml = '<div class="map-popup">';
            if (m.label || m.name) popupHtml += '<div class="map-popup-title">' + escapeHtml(m.label || m.name) + '</div>';
            popupHtml += '<div class="map-popup-coords">' + lat.toFixed(5) + ', ' + lng.toFixed(5) + '</div>';
            if (srcType !== 'default') popupHtml += '<div class="map-popup-meta"><span class="map-popup-badge" style="background:' + color + '">' + escapeHtml(srcType.replace(/_/g, ' ')) + '</span></div>';
            if (m.confidence) popupHtml += '<div class="map-popup-meta">Confidence: ' + (typeof m.confidence === 'number' ? (m.confidence * 100).toFixed(0) + '%' : escapeHtml(String(m.confidence))) + '</div>';
            if (m.description) popupHtml += '<div class="map-popup-meta">' + escapeHtml(m.description) + '</div>';
            popupHtml += '</div>';
            marker.bindPopup(popupHtml);

            marker.addTo(markerLayer);
            bounds.push([lat, lng]);
        });
    }

    // Render triangulation overlay
    if (mapData.triangulation) {
        var tri = mapData.triangulation;
        var triLayer = L.layerGroup().addTo(mapInstance);
        overlayLayers['Triangulation'] = triLayer;

        // Source points to center lines
        if (tri.source_points && tri.center) {
            tri.source_points.forEach(function (pt) {
                L.polyline(
                    [[pt.lat || pt[0], pt.lng || pt[1]], [tri.center.lat || tri.center[0], tri.center.lng || tri.center[1]]],
                    { color: '#2563eb', weight: 1.5, dashArray: '6, 4', opacity: 0.5 }
                ).addTo(triLayer);
            });
        }

        // Confidence radius circle
        if (tri.center && tri.confidence_radius) {
            L.circle(
                [tri.center.lat || tri.center[0], tri.center.lng || tri.center[1]],
                {
                    radius: tri.confidence_radius,
                    color: '#2563eb',
                    fillColor: '#2563eb',
                    fillOpacity: 0.06,
                    weight: 1.5,
                    dashArray: '4, 4'
                }
            ).addTo(triLayer);
        }

        // Center marker with glow
        if (tri.center) {
            var centerLat = tri.center.lat || tri.center[0];
            var centerLng = tri.center.lng || tri.center[1];

            // Outer glow
            L.circleMarker([centerLat, centerLng], {
                radius: 22,
                fillColor: '#dc2626',
                color: 'transparent',
                fillOpacity: 0.1,
                interactive: false
            }).addTo(triLayer);

            L.circleMarker([centerLat, centerLng], {
                radius: 10,
                fillColor: '#dc2626',
                color: '#ffffff',
                weight: 2.5,
                opacity: 1,
                fillOpacity: 0.9,
                className: 'pulse-marker'
            }).bindPopup(
                '<div class="map-popup">' +
                '<div class="map-popup-title">Triangulated Center</div>' +
                '<div class="map-popup-coords">' + centerLat.toFixed(5) + ', ' + centerLng.toFixed(5) + '</div>' +
                (tri.method ? '<div class="map-popup-meta">Method: ' + escapeHtml(tri.method) + '</div>' : '') +
                (tri.confidence ? '<div class="map-popup-meta">Confidence: ' + (tri.confidence * 100).toFixed(0) + '%</div>' : '') +
                '</div>'
            ).addTo(triLayer);

            bounds.push([centerLat, centerLng]);
        }
    }

    // Render connections/lines
    if (mapData.connections && mapData.connections.length > 0) {
        var connLayer = L.layerGroup().addTo(mapInstance);
        overlayLayers['Connections'] = connLayer;

        mapData.connections.forEach(function (conn) {
            if (conn.from && conn.to) {
                L.polyline(
                    [[conn.from.lat, conn.from.lng], [conn.to.lat, conn.to.lng]],
                    { color: '#2563eb', weight: 1.5, opacity: 0.4 }
                ).addTo(connLayer);
            }
        });
    }

    // Render heatmap via Leaflet.heat
    if (mapData.heatmap && mapData.heatmap.length > 0 && typeof L.heatLayer !== 'undefined') {
        var heatPoints = mapData.heatmap.map(function (pt) {
            return [pt.lat || pt[0], pt.lng || pt[1], pt.intensity || pt[2] || 1];
        });

        var heatLayer = L.heatLayer(heatPoints, {
            radius: 25,
            blur: 18,
            maxZoom: 17,
            gradient: {
                0.0: 'rgba(37, 99, 235, 0)',
                0.2: 'rgba(37, 99, 235, 0.3)',
                0.4: 'rgba(124, 58, 237, 0.5)',
                0.6: 'rgba(220, 38, 38, 0.6)',
                0.8: 'rgba(234, 88, 12, 0.8)',
                1.0: 'rgba(250, 204, 21, 0.9)'
            }
        }).addTo(mapInstance);

        overlayLayers['Heatmap'] = heatLayer;
    }

    // Layer control
    if (Object.keys(overlayLayers).length > 1) {
        L.control.layers(null, overlayLayers, { collapsed: false, position: 'topright' }).addTo(mapInstance);
    }

    // Geo signal legend
    if (mapData.markers && mapData.markers.length > 0) {
        var usedSources = {};
        mapData.markers.forEach(function (m) {
            var st = m.source_type || m.type || 'default';
            usedSources[st] = sourceColors[st] || sourceColors.default;
        });
        var sourceLabels = {
            exif: 'EXIF GPS', video_exif: 'Video EXIF', video_landmark: 'Video Landmark',
            nlp_mention: 'NLP Location', ip_geolocation: 'IP Geolocation', ip: 'IP',
            geotag: 'Social Geotag', social: 'Social', geocoding: 'Geocoded',
            address: 'Address', mention: 'Mention', manual: 'Manual',
            user_input: 'User Input', osint: 'OSINT'
        };
        var LegendControl = L.Control.extend({
            options: { position: 'bottomright' },
            onAdd: function () {
                var div = L.DomUtil.create('div', 'leaflet-bar leaflet-control');
                div.style.cssText = 'background:#0f172a;padding:8px 12px;border-radius:6px;font-size:11px;color:#94a3b8;border:1px solid #1e293b;';
                var html = '<div style="font-weight:600;margin-bottom:4px;color:#e2e8f0;">Signal Sources</div>';
                Object.keys(usedSources).forEach(function (src) {
                    var label = sourceLabels[src] || src.replace(/_/g, ' ');
                    html += '<div style="display:flex;align-items:center;gap:6px;margin:2px 0;">' +
                        '<span style="width:10px;height:10px;border-radius:50%;background:' + usedSources[src] + ';display:inline-block;"></span>' +
                        '<span>' + label + '</span></div>';
                });
                var accepted = mapData.points_accepted || mapData.markers.length;
                var rejected = mapData.points_rejected || 0;
                if (rejected > 0) {
                    html += '<div style="margin-top:6px;padding-top:6px;border-top:1px solid #1e293b;color:#e2e8f0;">' +
                        '<span style="color:#22c55e;">' + accepted + ' accepted</span>' +
                        ' &middot; <span style="color:#ef4444;">' + rejected + ' rejected</span></div>';
                }
                div.innerHTML = html;
                L.DomEvent.disableClickPropagation(div);
                return div;
            }
        });
        mapInstance.addControl(new LegendControl());
    }

    // Fit bounds
    if (bounds.length > 0) {
        mapInstance.fitBounds(bounds, { padding: [40, 40], maxZoom: 14 });
    }

    // Add "Download Map" custom control
    var DownloadMapControl = L.Control.extend({
        options: { position: 'topright' },
        onAdd: function () {
            var container = L.DomUtil.create('div', 'leaflet-bar leaflet-control map-download-control');
            var btn = L.DomUtil.create('a', '', container);
            btn.href = '#';
            btn.title = 'Download Map Snapshot';
            btn.innerHTML = '&#x1F4F7;';
            btn.setAttribute('role', 'button');
            btn.setAttribute('aria-label', 'Download Map Snapshot');
            btn.style.cssText = 'display:flex;align-items:center;justify-content:center;width:30px;height:30px;font-size:16px;background:#ffffff;color:#1e293b;text-decoration:none;cursor:pointer;';
            L.DomEvent.disableClickPropagation(container);
            L.DomEvent.on(btn, 'click', function (e) {
                L.DomEvent.preventDefault(e);
                exportMapSnapshot();
            });
            return container;
        }
    });
    mapInstance.addControl(new DownloadMapControl());

    // Force resize (fix for hidden container)
    setTimeout(function () {
        if (mapInstance) mapInstance.invalidateSize();
    }, 200);
}

/**
 * Export the current map view as a PNG snapshot using html2canvas.
 * Falls back to posting map bounds to /export/map-snapshot if html2canvas is unavailable.
 */
function exportMapSnapshot() {
    if (!mapInstance) {
        showToast('No map to export.', 'warning');
        return;
    }

    var mapContainer = mapInstance.getContainer();

    if (typeof html2canvas !== 'undefined') {
        showToast('Capturing map snapshot...', 'info');

        html2canvas(mapContainer, {
            useCORS: true,
            allowTaint: true,
            backgroundColor: '#08081a',
            scale: 2
        }).then(function (canvas) {
            // Convert canvas to downloadable PNG
            var link = document.createElement('a');
            link.download = 'fortis_map_' + Date.now() + '.png';
            link.href = canvas.toDataURL('image/png');
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            showToast('Map snapshot downloaded.', 'success');
        }).catch(function (err) {
            console.error('[Map Snapshot] html2canvas failed:', err);
            showToast('Map snapshot failed: ' + err.message, 'error');
        });
    } else {
        // Fallback: post current bounds to backend
        var bounds = mapInstance.getBounds();
        var center = mapInstance.getCenter();

        fetchApi('/export/map-snapshot', {
            method: 'POST',
            body: JSON.stringify({
                center: { lat: center.lat, lng: center.lng },
                zoom: mapInstance.getZoom(),
                bounds: {
                    north: bounds.getNorth(),
                    south: bounds.getSouth(),
                    east: bounds.getEast(),
                    west: bounds.getWest()
                }
            })
        }).then(function (response) {
            if (!response.ok) throw new Error('Server snapshot failed');
            return response.blob();
        }).then(function (blob) {
            var url = URL.createObjectURL(blob);
            var a = document.createElement('a');
            a.href = url;
            a.download = 'fortis_map_' + Date.now() + '.png';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Map snapshot downloaded.', 'success');
        }).catch(function (err) {
            showToast('Map snapshot failed: ' + err.message, 'error');
        });
    }
}

/**
 * Render a Cytoscape.js entity graph.
 * @param {object} graphData - { nodes: [...], edges: [...] }
 */
function renderGraph(graphData) {
    var graphContainer = document.getElementById('graphContainer');
    var graphDiv = document.getElementById('graph');
    if (!graphContainer || !graphDiv) return;
    if (typeof cytoscape === 'undefined') {
        console.warn('[Graph] Cytoscape.js not loaded');
        return;
    }
    if (!graphData || !graphData.nodes || graphData.nodes.length === 0) return;

    // Destroy previous instance
    if (graphInstance) {
        graphInstance.destroy();
        graphInstance = null;
    }

    // Node colors by entity type
    var nodeColors = {
        person: '#9b59b6',
        org: '#8b5cf6',
        organization: '#8b5cf6',
        location: '#22c55e',
        account: '#bb6bd9',
        domain: '#6b3fa0',
        event: '#f59e0b',
        media: '#d946ef',
        ip: '#6366f1',
        email: '#ec4899',
        phone: '#14b8a6',
        threat_actor: '#ef4444',
        cve: '#f97316',
        malware: '#e11d48',
        default: '#9b59b6'
    };

    // Build Cytoscape elements
    var elements = [];

    graphData.nodes.forEach(function (node) {
        var nodeData = node.data || node;
        elements.push({
            group: 'nodes',
            data: {
                id: nodeData.id,
                label: nodeData.label || nodeData.name || nodeData.id,
                type: nodeData.type || 'default',
                color: nodeColors[nodeData.type] || nodeColors.default,
                confidence: nodeData.confidence || '',
                platform: nodeData.platform || '',
                source: nodeData.source || '',
                aliases: nodeData.aliases || '',
                url: nodeData.url || '',
                description: nodeData.description || ''
            }
        });
    });

    graphData.edges.forEach(function (edge) {
        var edgeData = edge.data || edge;
        elements.push({
            group: 'edges',
            data: {
                id: edgeData.id || (edgeData.source + '-' + edgeData.target),
                source: edgeData.source,
                target: edgeData.target,
                label: edgeData.label || edgeData.relationship || ''
            }
        });
    });

    graphInstance = cytoscape({
        container: graphDiv,
        elements: elements,
        style: [
            {
                selector: 'node',
                style: {
                    'background-color': 'data(color)',
                    'label': 'data(label)',
                    'color': '#e5e7eb',
                    'font-size': '10px',
                    'text-valign': 'bottom',
                    'text-margin-y': 5,
                    'text-max-width': '100px',
                    'text-wrap': 'ellipsis',
                    'width': 30,
                    'height': 30,
                    'border-width': 2,
                    'border-color': '#1a1a2e'
                }
            },
            {
                selector: 'node:selected',
                style: {
                    'border-width': 3,
                    'border-color': '#ffffff',
                    'width': 40,
                    'height': 40
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 1.5,
                    'line-color': 'rgba(155, 89, 182, 0.4)',
                    'target-arrow-color': 'rgba(155, 89, 182, 0.6)',
                    'target-arrow-shape': 'triangle',
                    'arrow-scale': 0.8,
                    'curve-style': 'bezier',
                    'label': 'data(label)',
                    'font-size': '8px',
                    'color': '#9ca3af',
                    'text-rotation': 'autorotate'
                }
            },
            {
                selector: 'edge:selected',
                style: {
                    'line-color': '#9b59b6',
                    'target-arrow-color': '#9b59b6',
                    'width': 3
                }
            }
        ],
        layout: {
            name: 'cose',
            animate: false,
            padding: 30,
            nodeRepulsion: function () { return 8000; },
            idealEdgeLength: function () { return 80; },
            nodeOverlap: 20
        },
        minZoom: 0.3,
        maxZoom: 3
    });

    // Node click for detail popup
    graphInstance.on('tap', 'node', function (evt) {
        var nodeData = evt.target.data();
        var edges = evt.target.connectedEdges();

        // Build detail popup HTML
        var popupHtml = '<div class="graph-detail-popup" id="graphDetailPopup">';
        popupHtml += '<div class="graph-detail-header">';
        popupHtml += '<span class="graph-detail-type-badge" style="background:' + escapeHtml(nodeData.color) + ';">' + escapeHtml(nodeData.type) + '</span>';
        popupHtml += '<button class="graph-detail-close" onclick="closeGraphDetail()">&times;</button>';
        popupHtml += '</div>';
        popupHtml += '<h4 class="graph-detail-label">' + escapeHtml(nodeData.label) + '</h4>';

        // Entity metadata
        popupHtml += '<div class="graph-detail-meta">';
        if (nodeData.confidence) popupHtml += '<div><span class="graph-detail-key">Confidence:</span> ' + escapeHtml(String(nodeData.confidence)) + '</div>';
        if (nodeData.platform) popupHtml += '<div><span class="graph-detail-key">Platform:</span> ' + escapeHtml(nodeData.platform) + '</div>';
        if (nodeData.source) popupHtml += '<div><span class="graph-detail-key">Source:</span> ' + escapeHtml(nodeData.source) + '</div>';
        if (nodeData.aliases) popupHtml += '<div><span class="graph-detail-key">Aliases:</span> ' + escapeHtml(nodeData.aliases) + '</div>';
        if (nodeData.description) popupHtml += '<div><span class="graph-detail-key">Description:</span> ' + escapeHtml(nodeData.description) + '</div>';
        if (nodeData.url) popupHtml += '<div><span class="graph-detail-key">URL:</span> <a href="' + escapeHtml(nodeData.url) + '" target="_blank" rel="noopener">' + escapeHtml(nodeData.url) + '</a></div>';
        popupHtml += '</div>';

        // Connected edges list
        if (edges.length > 0) {
            popupHtml += '<div class="graph-detail-connections">';
            popupHtml += '<div class="graph-detail-key">Connections (' + edges.length + '):</div>';
            popupHtml += '<ul>';
            edges.forEach(function (edge) {
                var ed = edge.data();
                var otherNodeId = ed.source === nodeData.id ? ed.target : ed.source;
                var otherNode = graphInstance.getElementById(otherNodeId);
                var otherLabel = otherNode.data('label') || otherNodeId;
                var relLabel = ed.label || 'connected';
                var direction = ed.source === nodeData.id ? ' -> ' : ' <- ';
                popupHtml += '<li>' + escapeHtml(relLabel) + direction + escapeHtml(otherLabel) + '</li>';
            });
            popupHtml += '</ul>';
            popupHtml += '</div>';
        }

        popupHtml += '</div>';

        // Remove existing popup
        closeGraphDetail();

        // Insert popup into graph container
        var graphContainer = document.getElementById('graphContainer');
        if (graphContainer) {
            var popupDiv = document.createElement('div');
            popupDiv.id = 'graphDetailWrapper';
            popupDiv.innerHTML = popupHtml;
            graphContainer.appendChild(popupDiv);
        }
    });

    // Click on background to close popup
    graphInstance.on('tap', function (evt) {
        if (evt.target === graphInstance) {
            closeGraphDetail();
        }
    });
}

/**
 * Close the graph detail popup overlay.
 */
function closeGraphDetail() {
    var existing = document.getElementById('graphDetailWrapper');
    if (existing && existing.parentNode) {
        existing.parentNode.removeChild(existing);
    }
}

/**
 * Render chart images (base64 PNGs) or Chart.js charts.
 * @param {object|Array} chartData - either an array of base64 images or chart config objects
 */
function renderCharts(chartData) {
    var container = document.getElementById('chartsContainer');
    if (!container) return;

    container.innerHTML = '';
    container.classList.add('visible');

    if (!chartData) return;

    // Handle array of base64 PNG images
    if (Array.isArray(chartData)) {
        chartData.forEach(function (chart) {
            if (chart.image_base64 || chart.image) {
                var img = document.createElement('img');
                img.className = 'chart-image';
                img.src = 'data:image/png;base64,' + (chart.image_base64 || chart.image);
                img.alt = chart.title || 'Chart';
                container.appendChild(img);
            } else if (chart.type && typeof Chart !== 'undefined') {
                // Chart.js configuration
                var wrapper = document.createElement('div');
                wrapper.className = 'chart-wrapper';
                var canvas = document.createElement('canvas');
                wrapper.appendChild(canvas);
                container.appendChild(wrapper);

                new Chart(canvas, chart);
            }
        });
    } else if (chartData.charts) {
        // Nested charts array
        renderCharts(chartData.charts);
    }
}

/* ====================================================================
   WATCH PANEL (Feed Monitor)
   ==================================================================== */

/**
 * Open the Watch (feed monitor) slide-in panel.
 */
function openWatchPanel() {
    var panel = document.getElementById('watchPanel');
    var overlay = document.getElementById('watchOverlay');

    if (panel) panel.classList.add('open');
    if (overlay) overlay.classList.add('open');

    watchPanelOpen = true;
    loadWatchFindings();
    startWatchRefresh();
}

/**
 * Close the Watch panel.
 */
function closeWatchPanel() {
    var panel = document.getElementById('watchPanel');
    var overlay = document.getElementById('watchOverlay');

    if (panel) panel.classList.remove('open');
    if (overlay) overlay.classList.remove('open');

    watchPanelOpen = false;
    stopWatchRefresh();
}

/**
 * Load watch findings from the API.
 */
async function loadWatchFindings() {
    var findingsEl = document.getElementById('watchFindings');
    var emptyState = document.querySelector('#watchBody .results-empty');

    try {
        var response = await fetchApi('/monitor/watch');
        if (!response.ok) return;

        var data = await response.json();
        var findings = data.findings || [];

        if (findings.length === 0) {
            if (findingsEl) findingsEl.style.display = 'none';
            if (emptyState) emptyState.style.display = '';
            return;
        }

        if (emptyState) emptyState.style.display = 'none';
        if (findingsEl) {
            findingsEl.style.display = '';
            findingsEl.innerHTML = findings.map(function (f) {
                return renderWatchFinding(f);
            }).join('');
        }
    } catch (e) {
        console.warn('[Watch] Load failed:', e);
    }
}

/**
 * Render a single watch finding card.
 * @param {object} finding
 * @returns {string} HTML
 */
function renderWatchFinding(finding) {
    var confidenceClass = (finding.confidence === 'high') ? 'confidence-high' :
        (finding.confidence === 'medium') ? 'confidence-medium' : 'confidence-low';

    return '<div class="watch-finding" data-id="' + escapeHtml(finding.id || '') + '">' +
        '<div class="watch-finding-header">' +
            '<span class="watch-finding-source">' + escapeHtml(finding.platform || finding.source || '') + '</span>' +
            '<span class="watch-finding-time">' + formatTimestamp(finding.timestamp || finding.created_at) + '</span>' +
        '</div>' +
        '<div class="watch-finding-body">' +
            '<span class="badge ' + confidenceClass + '">' + escapeHtml(finding.confidence || 'unknown') + '</span>' +
            '<p>' + escapeHtml(finding.summary || finding.content || '') + '</p>' +
        '</div>' +
        '<div class="watch-finding-actions">' +
            '<button class="btn btn-sm btn-primary watch-approve-btn" data-finding-id="' + escapeHtml(finding.id || '') + '">Approve</button>' +
            '<button class="btn btn-sm btn-ghost watch-dismiss-btn" data-finding-id="' + escapeHtml(finding.id || '') + '">Dismiss</button>' +
        '</div>' +
    '</div>';
}

/**
 * Approve a watch finding.
 * @param {string} findingId
 */
async function approveFinding(findingId) {
    try {
        var response = await fetchApi('/monitor/' + findingId + '/approve', {
            method: 'POST',
            body: JSON.stringify({})
        });

        if (response.ok) {
            showToast('Finding approved.', 'success');
            loadWatchFindings();
        } else {
            var data = await response.json();
            showToast('Approve failed: ' + (data.error || 'Unknown error'), 'error');
        }
    } catch (e) {
        showToast('Approve failed: ' + e.message, 'error');
    }
}

/**
 * Dismiss a watch finding.
 * @param {string} findingId
 */
async function dismissFinding(findingId) {
    try {
        var response = await fetchApi('/monitor/' + findingId + '/dismiss', {
            method: 'POST',
            body: JSON.stringify({})
        });

        if (response.ok) {
            showToast('Finding dismissed.', 'info');
            loadWatchFindings();
        } else {
            var data = await response.json();
            showToast('Dismiss failed: ' + (data.error || 'Unknown error'), 'error');
        }
    } catch (e) {
        showToast('Dismiss failed: ' + e.message, 'error');
    }
}

/**
 * Start auto-refreshing watch findings every 30 seconds.
 */
function startWatchRefresh() {
    stopWatchRefresh();
    watchRefreshTimer = setInterval(function () {
        if (watchPanelOpen) loadWatchFindings();
    }, 30000);
}

/**
 * Stop the watch auto-refresh timer.
 */
function stopWatchRefresh() {
    if (watchRefreshTimer) {
        clearInterval(watchRefreshTimer);
        watchRefreshTimer = null;
    }
}

/* ====================================================================
   KNOWLEDGE BASE PANEL
   ==================================================================== */

/**
 * Open the Knowledge Base slide-in panel.
 */
function openKbPanel() {
    var panel = document.getElementById('kbPanel');
    var overlay = document.getElementById('kbOverlay');

    if (panel) panel.classList.add('open');
    if (overlay) overlay.classList.add('open');

    kbPanelOpen = true;
    loadKbReports();
    loadKbStats();
}

/**
 * Close the KB panel.
 */
function closeKbPanel() {
    var panel = document.getElementById('kbPanel');
    var overlay = document.getElementById('kbOverlay');

    if (panel) panel.classList.remove('open');
    if (overlay) overlay.classList.remove('open');

    kbPanelOpen = false;
}

/**
 * Load reports from the Knowledge Base.
 */
async function loadKbReports() {
    var listEl = document.getElementById('kbReportList');
    if (!listEl) return;

    var searchVal = '';
    var searchInput = document.getElementById('kbSearch');
    if (searchInput) searchVal = searchInput.value.trim();

    try {
        var url = '/kb/reports';
        if (searchVal) url += '?q=' + encodeURIComponent(searchVal);

        var response = await fetchApi(url);
        if (!response.ok) return;

        var data = await response.json();
        var reports = data.reports || [];

        if (reports.length === 0) {
            listEl.innerHTML = '<div class="kb-empty">No reports found.</div>';
            return;
        }

        listEl.innerHTML = reports.map(function (report) {
            var activeClass = report.in_knowledge_base ? 'kb-report-active' : 'kb-report-inactive';
            return '<div class="kb-report-item ' + activeClass + '" data-report-id="' + escapeHtml(report.id || report.report_id || '') + '">' +
                '<div class="kb-report-info">' +
                    '<div class="kb-report-title">' + escapeHtml(report.title || report.indicator || report.filename || 'Untitled') + '</div>' +
                    '<div class="kb-report-meta">' +
                        escapeHtml(report.report_type || report.type || '') + ' &middot; ' +
                        formatTimestamp(report.created_at) + ' &middot; ' +
                        (report.kb_chunk_count || 0) + ' chunks' +
                    '</div>' +
                '</div>' +
                '<div class="kb-report-actions">' +
                    '<button class="btn btn-sm btn-ghost kb-toggle-btn" data-report-id="' + escapeHtml(report.id || report.report_id || '') + '">' +
                        (report.in_knowledge_base ? 'Remove' : 'Add') +
                    '</button>' +
                    '<button class="btn btn-sm btn-ghost kb-delete-btn" data-report-id="' + escapeHtml(report.id || report.report_id || '') + '">' +
                        'Delete' +
                    '</button>' +
                '</div>' +
            '</div>';
        }).join('');
    } catch (e) {
        console.warn('[KB] Load reports failed:', e);
        listEl.innerHTML = '<div class="kb-empty">Failed to load reports.</div>';
    }
}

/**
 * Toggle a report's inclusion in the Knowledge Base.
 * @param {string} reportId
 */
async function toggleKbReport(reportId) {
    try {
        var response = await fetchApi('/kb/reports/' + reportId + '/toggle', {
            method: 'POST',
            body: JSON.stringify({})
        });

        if (response.ok) {
            showToast('Report updated.', 'success');
            loadKbReports();
            loadKbStats();
        }
    } catch (e) {
        showToast('Toggle failed: ' + e.message, 'error');
    }
}

/**
 * Delete a report from the Knowledge Base.
 * @param {string} reportId
 */
async function deleteKbReport(reportId) {
    if (!confirm('Delete this report from the Knowledge Base?')) return;

    try {
        var response = await fetchApi('/kb/reports/' + reportId, {
            method: 'DELETE'
        });

        if (response.ok) {
            showToast('Report deleted.', 'success');
            loadKbReports();
            loadKbStats();
        }
    } catch (e) {
        showToast('Delete failed: ' + e.message, 'error');
    }
}

/**
 * Rebuild the Knowledge Base index.
 */
async function rebuildKb() {
    showToast('Rebuilding Knowledge Base index...', 'info');

    try {
        var response = await fetchApi('/kb/rebuild', {
            method: 'POST',
            body: JSON.stringify({})
        });

        if (response.ok) {
            var data = await response.json();
            showToast('Knowledge Base rebuilt: ' + (data.chunks || 0) + ' chunks indexed.', 'success');
            loadKbStats();
        } else {
            var errData = await response.json();
            showToast('Rebuild failed: ' + (errData.error || 'Unknown error'), 'error');
        }
    } catch (e) {
        showToast('Rebuild failed: ' + e.message, 'error');
    }
}

/**
 * Load Knowledge Base statistics.
 */
async function loadKbStats() {
    try {
        var response = await fetchApi('/kb/stats');
        if (!response.ok) return;

        var stats = await response.json();

        var docsEl = document.getElementById('kbStatDocs');
        var chunksEl = document.getElementById('kbStatChunks');

        if (docsEl) docsEl.textContent = stats.total_reports || 0;
        if (chunksEl) chunksEl.textContent = stats.total_chunks || 0;
    } catch (e) {
        console.warn('[KB] Stats load failed:', e);
    }
}

/* ====================================================================
   EXPORT FUNCTIONALITY
   ==================================================================== */

/**
 * Generic export handler. Downloads a file from the export endpoint.
 * @param {string} format - 'pdf'|'markdown'|'stix'|'csv'|'json'
 */
async function exportResults(format) {
    if (!sessionId && !currentTool) {
        showToast('No results to export.', 'warning');
        return;
    }

    showLoading();

    try {
        var exportPayload = {
            session_id: sessionId || '',
            tool: currentTool
        };

        if (lastAnalysisData) {
            if (lastAnalysisData.analysis) {
                exportPayload.content = lastAnalysisData.analysis;
            }
            if (lastAnalysisData.entities) {
                exportPayload.entities = lastAnalysisData.entities;
            }
            if (lastAnalysisData.sensitivity_level) {
                exportPayload.sensitivity_level = lastAnalysisData.sensitivity_level;
            }
            if (lastAnalysisData.identifier) {
                exportPayload.title = 'Fortis Report — ' + lastAnalysisData.identifier;
            }
            if (lastAnalysisData.charts) {
                exportPayload.chart_data = lastAnalysisData.charts;
            }
            if (lastAnalysisData.map_data) {
                exportPayload.map_data = lastAnalysisData.map_data;
            }
            if (lastAnalysisData.entity_graph) {
                exportPayload.entity_graph = lastAnalysisData.entity_graph;
            }
            if (lastAnalysisData.identifier || lastAnalysisData.identifier_type) {
                exportPayload.investigation = {
                    identifier: lastAnalysisData.identifier || '',
                    identifier_type: lastAnalysisData.identifier_type || '',
                    sensitivity_level: lastAnalysisData.sensitivity_level || 'INTERNAL'
                };
            }
            // Capture map snapshot if map is visible
            if (format === 'pdf' && mapInstance) {
                try {
                    var mapEl = document.getElementById('map');
                    if (mapEl && typeof html2canvas !== 'undefined') {
                        var canvas = await html2canvas(mapEl, {
                            useCORS: true, backgroundColor: '#08081a', scale: 2
                        });
                        exportPayload.map_snapshot = canvas.toDataURL('image/png');
                    }
                } catch (e) { /* map snapshot optional */ }
            }
        }

        var response = await fetchApi('/export/' + format, {
            method: 'POST',
            body: JSON.stringify(exportPayload)
        });

        if (!response.ok) {
            var errData = await response.json();
            throw new Error(errData.error || 'Export failed');
        }

        // Download as file
        var blob = await response.blob();
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;

        var extensions = {
            pdf: '.pdf',
            markdown: '.md',
            stix: '.stix.json',
            csv: '.csv',
            json: '.json'
        };

        a.download = 'fortis_export_' + Date.now() + (extensions[format] || '.txt');
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast('Export downloaded: ' + format.toUpperCase(), 'success');
    } catch (error) {
        showToast('Export failed: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

/**
 * Export to PDF.
 */
function exportPdf() {
    exportResults('pdf');
}

/**
 * Export as Markdown.
 */
function exportMarkdown() {
    exportResults('markdown');
}

/**
 * Export as STIX 2.1.
 */
function exportStix() {
    exportResults('stix');
}

/**
 * Export as CSV.
 */
function exportCsv() {
    exportResults('csv');
}

/**
 * Export as JSON.
 */
function exportJson() {
    exportResults('json');
}

/**
 * Export to Google Drive.
 * @param {string} format - export format to upload
 */
async function exportDrive(format) {
    format = format || 'pdf';
    showLoading();

    try {
        var exportPayload = {
            session_id: sessionId || '',
            tool: currentTool
        };

        if (lastAnalysisData) {
            if (lastAnalysisData.analysis) exportPayload.content = lastAnalysisData.analysis;
            if (lastAnalysisData.entities) exportPayload.entities = lastAnalysisData.entities;
            if (lastAnalysisData.sensitivity_level) exportPayload.sensitivity_level = lastAnalysisData.sensitivity_level;
            if (lastAnalysisData.identifier) exportPayload.title = 'Fortis Report — ' + lastAnalysisData.identifier;
            if (lastAnalysisData.charts) exportPayload.chart_data = lastAnalysisData.charts;
        }

        var response = await fetchApi('/export/drive/' + format, {
            method: 'POST',
            body: JSON.stringify(exportPayload)
        });

        var data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Drive upload failed');
        }

        var msg = 'Uploaded to Google Drive.';
        if (data.web_view_link) {
            msg += ' Opening...';
            window.open(data.web_view_link, '_blank');
        }
        showToast(msg, 'success');
    } catch (error) {
        showToast('Drive export failed: ' + error.message, 'error');
    } finally {
        hideLoading();
    }
}

/* ====================================================================
   SUBMIT DISPATCHER
   ==================================================================== */

/**
 * Dispatch the submit action based on the currently selected tool.
 */
function handleSubmit() {
    switch (currentTool) {
        case 'ingest':
            uploadReport();
            break;
        case 'investigate':
            runInvestigation();
            break;
        case 'geo':
            runGeolocation();
            break;
        case 'batch':
            runBatchInvestigation();
            break;
        case 'monitor':
            createMonitor();
            break;
        case 'scenario':
            runScenario();
            break;
        case 'qa':
            sendChatMessage();
            break;
        default:
            showToast('Unknown tool: ' + currentTool, 'error');
    }
}

/* ====================================================================
   EVENT BINDINGS (DOMContentLoaded)
   ==================================================================== */

document.addEventListener('DOMContentLoaded', function () {

    // ---- Authentication ----
    checkAuth();
    fetchOsintStatus();

    // ---- Tool Card Selection ----
    document.querySelectorAll('.tool-card').forEach(function (card) {
        card.addEventListener('click', function () {
            selectTool(this.dataset.tool);
        });
    });

    // ---- Submit Button ----
    var submitBtn = document.getElementById('btnSubmit');
    if (submitBtn) {
        submitBtn.addEventListener('click', function () {
            handleSubmit();
        });
    }

    // ---- Logout ----
    var logoutBtn = document.getElementById('btnLogout');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function () {
            handleLogout();
        });
    }

    // ---- Geolocation Tabs ----
    document.querySelectorAll('#geoTabs .tab').forEach(function (tab) {
        tab.addEventListener('click', function () {
            switchGeoTab(this.dataset.geoTab);
        });
    });

    // ---- Result Tabs ----
    document.querySelectorAll('.result-tab').forEach(function (tab) {
        tab.addEventListener('click', function () {
            switchResultTab(this.dataset.tab);
            var icon = document.getElementById('viewToggleIcon');
            if (icon) icon.innerHTML = '&#x25A8;';
        });
    });

    var viewToggleBtn = document.getElementById('viewToggleBtn');
    if (viewToggleBtn) {
        viewToggleBtn.addEventListener('click', toggleViewMode);
    }

    // ---- Q&A Chat ----
    var chatSendBtn = document.getElementById('chatSend');
    if (chatSendBtn) {
        chatSendBtn.addEventListener('click', function () {
            sendChatMessage();
        });
    }

    var chatInput = document.getElementById('chatInput');
    if (chatInput) {
        chatInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                e.preventDefault();
                sendChatMessage();
            }
        });
    }

    // ---- Watch Panel ----
    var watchBtn = document.getElementById('btnWatch');
    if (watchBtn) {
        watchBtn.addEventListener('click', function () {
            if (watchPanelOpen) {
                closeWatchPanel();
            } else {
                closeKbPanel(); // Close KB if open
                openWatchPanel();
            }
        });
    }

    var watchCloseBtn = document.getElementById('watchClose');
    if (watchCloseBtn) {
        watchCloseBtn.addEventListener('click', function () {
            closeWatchPanel();
        });
    }

    var watchOverlay = document.getElementById('watchOverlay');
    if (watchOverlay) {
        watchOverlay.addEventListener('click', function () {
            closeWatchPanel();
        });
    }

    // Watch finding actions (delegated)
    var watchBody = document.getElementById('watchBody');
    if (watchBody) {
        watchBody.addEventListener('click', function (e) {
            var approveBtn = e.target.closest('.watch-approve-btn');
            if (approveBtn) {
                approveFinding(approveBtn.dataset.findingId);
                return;
            }

            var dismissBtn = e.target.closest('.watch-dismiss-btn');
            if (dismissBtn) {
                dismissFinding(dismissBtn.dataset.findingId);
                return;
            }
        });
    }

    var clearFindingsBtn = document.getElementById('btnClearFindings');
    if (clearFindingsBtn) {
        clearFindingsBtn.addEventListener('click', function () {
            var findingsEl = document.getElementById('watchFindings');
            if (findingsEl) findingsEl.innerHTML = '';
            showToast('Findings cleared.', 'info');
        });
    }

    // ---- Knowledge Base Panel ----
    var kbBtn = document.getElementById('btnKnowledgeBase');
    if (kbBtn) {
        kbBtn.addEventListener('click', function () {
            if (kbPanelOpen) {
                closeKbPanel();
            } else {
                closeWatchPanel(); // Close watch if open
                openKbPanel();
            }
        });
    }

    var kbCloseBtn = document.getElementById('kbClose');
    if (kbCloseBtn) {
        kbCloseBtn.addEventListener('click', function () {
            closeKbPanel();
        });
    }

    var kbOverlay = document.getElementById('kbOverlay');
    if (kbOverlay) {
        kbOverlay.addEventListener('click', function () {
            closeKbPanel();
        });
    }

    // KB actions (delegated)
    var kbBody = document.getElementById('kbBody');
    if (kbBody) {
        kbBody.addEventListener('click', function (e) {
            var toggleBtn = e.target.closest('.kb-toggle-btn');
            if (toggleBtn) {
                toggleKbReport(toggleBtn.dataset.reportId);
                return;
            }

            var deleteBtn = e.target.closest('.kb-delete-btn');
            if (deleteBtn) {
                deleteKbReport(deleteBtn.dataset.reportId);
                return;
            }
        });
    }

    // KB search
    var kbSearchInput = document.getElementById('kbSearch');
    if (kbSearchInput) {
        var kbSearchDebounce = null;
        kbSearchInput.addEventListener('input', function () {
            clearTimeout(kbSearchDebounce);
            kbSearchDebounce = setTimeout(function () {
                loadKbReports();
            }, 300);
        });
    }

    // KB rebuild
    var rebuildBtn = document.getElementById('btnKbRebuild');
    if (rebuildBtn) {
        rebuildBtn.addEventListener('click', function () {
            rebuildKb();
        });
    }

    // KB stats refresh
    var kbStatsBtn = document.getElementById('btnKbStats');
    if (kbStatsBtn) {
        kbStatsBtn.addEventListener('click', function () {
            loadKbStats();
            showToast('KB stats refreshed.', 'info');
        });
    }

    // ---- Export Buttons ----
    var exportBar = document.getElementById('exportBar');
    if (exportBar) {
        exportBar.addEventListener('click', function (e) {
            var btn = e.target.closest('.export-btn');
            if (!btn) return;

            var format = btn.dataset.format;
            if (!format) return;

            if (format === 'drive') {
                exportDrive('pdf');
            } else {
                exportResults(format);
            }
        });
    }

    // ---- Drop Zones ----
    initDropZone('ingestDropZone', 'ingestFiles', 'ingestFileList', ['.pdf', '.md', '.txt']);
    initDropZone('geoImageDropZone', 'geoImages', 'geoImageFileList', ['image/*']);
    initDropZone('batchDropZone', 'batchFile', 'batchFileList', ['.csv', '.xlsx', '.xls']);

    // ---- Auto-detect Identifier Type ----
    var investSubject = document.getElementById('investSubject');
    var investIdType = document.getElementById('investIdType');
    if (investSubject && investIdType) {
        investSubject.addEventListener('input', function () {
            if (investIdType.value === 'auto') {
                var detected = autoDetectIdentifierType(investSubject.value);
                investSubject.title = 'Detected type: ' + detected;
            }
        });
    }

    // ---- Keyboard shortcut: Escape to close panels ----
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            if (watchPanelOpen) closeWatchPanel();
            if (kbPanelOpen) closeKbPanel();
        }
    });

    // ---- Initial tool selection ----
    selectTool('ingest');
});

// =========================================================================
// Domain / IP Intelligence Renderers
// =========================================================================

function renderDomainIntelSection(di) {
    var h = '<div class="result-section domain-intel-section">' +
        '<h4>Domain Intelligence: ' + escapeHtml(di.domain) + '</h4>';

    var w = di.whois || {};
    if (w.registrar || w.creation_date) {
        h += '<div class="intel-card"><h5>WHOIS</h5><table class="intel-table">';
        if (w.registrar) h += '<tr><td>Registrar</td><td>' + escapeHtml(w.registrar) + '</td></tr>';
        if (w.registrant) h += '<tr><td>Registrant</td><td>' + escapeHtml(w.registrant) + '</td></tr>';
        if (w.creation_date) h += '<tr><td>Created</td><td>' + escapeHtml(w.creation_date) + '</td></tr>';
        if (w.expiration_date) h += '<tr><td>Expires</td><td>' + escapeHtml(w.expiration_date) + '</td></tr>';
        if (w.name_servers && w.name_servers.length)
            h += '<tr><td>Name Servers</td><td>' + w.name_servers.map(escapeHtml).join('<br>') + '</td></tr>';
        h += '</table></div>';
    }

    var dns = di.dns || {};
    var dnsKeys = Object.keys(dns).filter(function (k) { return dns[k] && dns[k].length; });
    if (dnsKeys.length) {
        h += '<div class="intel-card"><h5>DNS Records</h5><table class="intel-table">';
        dnsKeys.forEach(function (k) {
            h += '<tr><td>' + escapeHtml(k) + '</td><td>' + dns[k].map(escapeHtml).join('<br>') + '</td></tr>';
        });
        h += '</table></div>';
    }

    var dd = di.dnsdumpster || {};
    var subs = dd.subdomains || [];
    if (subs.length) {
        h += '<div class="intel-card"><h5>Subdomains (DNSdumpster) &mdash; ' + subs.length + ' found</h5>' +
            '<table class="intel-table"><tr><th>Hostname</th><th>IP</th></tr>';
        subs.slice(0, 30).forEach(function (s) {
            h += '<tr><td>' + escapeHtml(s.hostname) + '</td><td>' + escapeHtml(s.ip) + '</td></tr>';
        });
        if (subs.length > 30) h += '<tr><td colspan="2"><em>... and ' + (subs.length - 30) + ' more</em></td></tr>';
        h += '</table></div>';
    }

    var hdrs = di.http_headers || {};
    var hdrKeys = Object.keys(hdrs);
    if (hdrKeys.length) {
        h += '<div class="intel-card"><h5>HTTP Headers</h5><table class="intel-table">';
        hdrKeys.slice(0, 15).forEach(function (k) {
            h += '<tr><td>' + escapeHtml(k) + '</td><td>' + escapeHtml(hdrs[k]) + '</td></tr>';
        });
        h += '</table></div>';
    }

    h += '</div>';
    return h;
}

function renderCivilianHarmSection(harm) {
    if (!harm || !harm.total_scored) return '';

    var dist = harm.distribution || {};
    var flagged = harm.flagged || [];
    var hasFlagged = flagged.length > 0;

    var h = '<div class="result-section civilian-harm-section">' +
        '<div class="ch-header" onclick="this.parentElement.classList.toggle(\'ch-collapsed\')">' +
        '<h4>Civilian Harm Analysis</h4>' +
        '<span class="ch-methodology">Bellingcat Methodology</span>' +
        '<span class="ch-summary">' + harm.total_scored + ' scored &middot; ' +
        harm.flagged_count + ' flagged' +
        (harm.max_score ? ' &middot; max ' + (harm.max_score * 100).toFixed(0) + '%' : '') +
        '</span>' +
        '<span class="ch-toggle">&#9660;</span></div>' +
        '<div class="ch-body">';

    // Distribution bar
    h += '<div class="ch-distribution">';
    var order = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'NONE'];
    var colors = {
        'CRITICAL': '#ef4444', 'HIGH': '#f97316',
        'MODERATE': '#eab308', 'LOW': '#6b7280', 'NONE': '#374151'
    };
    for (var i = 0; i < order.length; i++) {
        var cls = order[i];
        if (dist[cls]) {
            var pct = (dist[cls] / harm.total_scored * 100).toFixed(0);
            h += '<div class="ch-bar-segment" style="width:' + pct +
                '%;background:' + colors[cls] + '" title="' +
                cls + ': ' + dist[cls] + '">' +
                (pct >= 8 ? cls.charAt(0) + ' ' + dist[cls] : '') + '</div>';
        }
    }
    h += '</div>';

    // Distribution legend
    h += '<div class="ch-legend">';
    for (var j = 0; j < order.length; j++) {
        var c = order[j];
        if (dist[c]) {
            h += '<span class="ch-legend-item">' +
                '<span class="ch-dot" style="background:' + colors[c] + '"></span>' +
                c + ': ' + dist[c] + '</span>';
        }
    }
    h += '</div>';

    // Flagged items
    if (hasFlagged) {
        h += '<div class="intel-card"><h5>Flagged Content (' + flagged.length + ')</h5>';
        for (var k = 0; k < Math.min(flagged.length, 15); k++) {
            var item = flagged[k];
            var hs = item.harm_score || {};
            var badgeClass = 'ch-badge-' + (hs.classification || 'none').toLowerCase();
            h += '<div class="ch-item">' +
                '<span class="wi-badge ' + badgeClass + '">' +
                escapeHtml(hs.classification || '?') +
                ' ' + ((hs.score || 0) * 100).toFixed(0) + '%</span> ';

            if (item.platform) {
                h += '<span class="ch-platform">' + escapeHtml(item.platform) + '</span> ';
            }

            h += '<div class="ch-content">' + escapeHtml((item.content || '').substring(0, 300)) + '</div>';

            if (hs.matched_concepts && hs.matched_concepts.length) {
                h += '<div class="ch-concepts">';
                for (var m = 0; m < hs.matched_concepts.length; m++) {
                    h += '<span class="ch-concept">' + escapeHtml(hs.matched_concepts[m]) + '</span>';
                }
                h += '</div>';
            }

            if (item.url) {
                h += '<div class="wi-meta"><a href="' + escapeHtml(item.url) +
                    '" target="_blank" rel="noopener">' + escapeHtml(item.url) + '</a></div>';
            }
            h += '</div>';
        }
        h += '</div>';
    }

    h += '</div></div>';
    return h;
}

function renderImageAnalysisSection(images) {
    if (!images || !images.length) return '';

    var h = '<div class="result-section image-analysis-section">' +
        '<div class="ch-header" onclick="this.parentElement.classList.toggle(\'ch-collapsed\')">' +
        '<h4>Image Analysis</h4>' +
        '<span class="ch-summary">' + images.length + ' image' + (images.length > 1 ? 's' : '') + ' analysed</span>' +
        '<span class="ch-toggle">&#9660;</span></div>' +
        '<div class="ch-body">';

    for (var i = 0; i < images.length; i++) {
        var img = images[i];
        h += '<div class="intel-card"><h5>' + escapeHtml(img.filename || 'Image ' + (i + 1)) + '</h5>';

        // Forensics
        if (img.forensics && img.forensics.overall_verdict) {
            var fv = img.forensics.overall_verdict;
            var fClass = fv === 'LIKELY_MANIPULATED' ? 'ch-badge-critical' :
                fv === 'POSSIBLY_MANIPULATED' ? 'ch-badge-high' : 'ch-badge-low';
            h += '<div class="img-analysis-row"><strong>Forensics:</strong> ' +
                '<span class="wi-badge ' + fClass + '">' + escapeHtml(fv.replace(/_/g, ' ')) + '</span>' +
                ' <span class="ch-platform">' + ((img.forensics.confidence || 0) * 100).toFixed(0) + '% confidence</span></div>';
            if (img.forensics.flags && img.forensics.flags.length) {
                h += '<ul class="img-flags">';
                for (var f = 0; f < img.forensics.flags.length; f++) {
                    h += '<li>' + escapeHtml(img.forensics.flags[f]) + '</li>';
                }
                h += '</ul>';
            }
        }

        // Steganography
        if (img.steganography && img.steganography.overall_verdict) {
            var sv = img.steganography.overall_verdict;
            var sClass = sv === 'STEGANOGRAPHY_LIKELY' ? 'ch-badge-critical' :
                sv === 'STEGANOGRAPHY_POSSIBLE' ? 'ch-badge-high' : 'ch-badge-low';
            h += '<div class="img-analysis-row"><strong>Steganography:</strong> ' +
                '<span class="wi-badge ' + sClass + '">' + escapeHtml(sv.replace(/_/g, ' ')) + '</span>' +
                ' <span class="ch-platform">' + ((img.steganography.confidence || 0) * 100).toFixed(0) + '% confidence</span></div>';
        }

        // CLIP Vision
        if (img.vision && img.vision.classifications && img.vision.classifications.length) {
            h += '<div class="img-analysis-row"><strong>Classification:</strong> ';
            var cls = img.vision.classifications;
            for (var c = 0; c < Math.min(cls.length, 5); c++) {
                h += '<span class="ch-concept">' + escapeHtml(cls[c].category) +
                    ' ' + ((cls[c].confidence || 0) * 100).toFixed(0) + '%</span>';
            }
            h += '</div>';
        }
        if (img.vision && img.vision.landmarks && img.vision.landmarks.length) {
            h += '<div class="img-analysis-row"><strong>Landmarks:</strong> ';
            for (var l = 0; l < img.vision.landmarks.length; l++) {
                h += '<span class="ch-concept">' + escapeHtml(img.vision.landmarks[l].name) +
                    ' ' + ((img.vision.landmarks[l].confidence || 0) * 100).toFixed(0) + '%</span>';
            }
            h += '</div>';
        }
        if (img.vision && img.vision.safety && img.vision.safety.classification !== 'safe') {
            h += '<div class="img-analysis-row"><strong>Safety:</strong> ' +
                '<span class="wi-badge ch-badge-critical">' +
                escapeHtml(img.vision.safety.classification) + '</span></div>';
        }

        // Reverse search
        if (img.reverse_search) {
            var rs = img.reverse_search;
            if (rs.tineye_results && rs.tineye_results.length) {
                h += '<div class="img-analysis-row"><strong>TinEye:</strong> ' +
                    rs.tineye_results.length + ' match(es)</div>';
                for (var t = 0; t < Math.min(rs.tineye_results.length, 3); t++) {
                    var tm = rs.tineye_results[t];
                    h += '<div class="wi-meta">' + escapeHtml(tm.domain || '') +
                        (tm.crawl_date ? ' (' + escapeHtml(tm.crawl_date) + ')' : '') + '</div>';
                }
            }
            if (rs.similar_cached && rs.similar_cached.length) {
                h += '<div class="img-analysis-row"><strong>Similar cached:</strong> ' +
                    rs.similar_cached.length + ' image(s) with avg distance ' +
                    rs.similar_cached[0].distance + '</div>';
            }
        }

        h += '</div>';
    }

    h += '</div></div>';
    return h;
}

function renderWebIntelligenceSection(wi) {
    var initial = wi.initial_collection || {};
    var final_ = wi.final_validation || {};
    var initQueries = initial.queries || [];
    var initResults = initial.collection_results || [];
    var finalQueries = final_.queries || [];
    var gapResults = final_.gap_fill_results || [];
    var valResults = final_.validation_results || [];
    var deepScraped = final_.deep_scraped || [];

    var totalQueries = (wi.initial_queries_run || 0) + (wi.final_queries_run || 0);
    var totalResults = initResults.length + gapResults.length + valResults.length;

    var h = '<div class="result-section web-intelligence-section">' +
        '<div class="wi-header" onclick="this.parentElement.classList.toggle(\'wi-collapsed\')">' +
        '<h4>Web Intelligence</h4>' +
        '<span class="wi-summary">' + totalQueries + ' queries &middot; ' +
        totalResults + ' results' +
        (deepScraped.length ? ' &middot; ' + deepScraped.length + ' pages scraped' : '') +
        '</span>' +
        '<span class="wi-toggle">&#9660;</span></div>' +
        '<div class="wi-body">';

    // Initial Collection (Phase 1 — pre-OSINT)
    var scrapedPages = initial.scraped_pages || [];
    var scrapedUrls = {};
    scrapedPages.forEach(function (sp) { scrapedUrls[sp.url] = true; });

    if (initResults.length) {
        h += '<div class="intel-card"><h5>Initial Web Discovery (Pre-OSINT)</h5>';
        initResults.forEach(function (r) {
            var enriched = scrapedUrls[r.url];
            h += '<div class="wi-result' + (enriched ? ' wi-enriched' : '') + '">' +
                '<span class="wi-badge wi-badge-collection">DISCOVERY</span> ' +
                (enriched ? '<span class="wi-badge wi-badge-scraped">ENRICHED</span> ' : '') +
                '<strong>' + escapeHtml(r.title || '') + '</strong>' +
                '<div class="wi-snippet">' + escapeHtml(r.snippet || '') + '</div>' +
                '<div class="wi-meta">' +
                '<a href="' + escapeHtml(r.url || '') + '" target="_blank" rel="noopener">' +
                escapeHtml(r.url || '') + '</a>' +
                ' &middot; Query: <em>' + escapeHtml(r.query || '') + '</em>' +
                '</div></div>';
        });
        h += '</div>';
    }

    // Gap-fill (Phase 5 — post-analysis)
    if (gapResults.length) {
        h += '<div class="intel-card"><h5>New Intelligence (Gap Analysis)</h5>';
        gapResults.forEach(function (r) {
            h += '<div class="wi-result">' +
                '<span class="wi-badge wi-badge-new">NEW_INTEL</span> ' +
                '<strong>' + escapeHtml(r.title || '') + '</strong>' +
                '<div class="wi-snippet">' + escapeHtml(r.snippet || '') + '</div>' +
                '<div class="wi-meta">' +
                '<a href="' + escapeHtml(r.url || '') + '" target="_blank" rel="noopener">' +
                escapeHtml(r.url || '') + '</a>' +
                ' &middot; Query: <em>' + escapeHtml(r.query || '') + '</em>' +
                '</div></div>';
        });
        h += '</div>';
    }

    // Validation (Phase 5 — post-analysis)
    if (valResults.length) {
        h += '<div class="intel-card"><h5>Validation Results</h5>';
        valResults.forEach(function (r) {
            h += '<div class="wi-result">' +
                '<strong>' + escapeHtml(r.title || '') + '</strong>' +
                '<div class="wi-snippet">' + escapeHtml(r.snippet || '') + '</div>' +
                '<div class="wi-meta">' +
                '<a href="' + escapeHtml(r.url || '') + '" target="_blank" rel="noopener">' +
                escapeHtml(r.url || '') + '</a>' +
                ' &middot; Validates: <em>' + escapeHtml(r.ref || '') + '</em>' +
                '</div></div>';
        });
        h += '</div>';
    }

    // Deep scraped
    if (deepScraped.length) {
        h += '<div class="intel-card"><h5>Deep Scraped Sources</h5><ul>';
        deepScraped.forEach(function (s) {
            var confClass = s.confidence === 'HIGH' ? 'wi-badge-high' : 'wi-badge-moderate';
            h += '<li><span class="wi-badge ' + confClass + '">' +
                escapeHtml(s.confidence) + '</span> ' +
                '<a href="' + escapeHtml(s.url) + '" target="_blank" rel="noopener">' +
                escapeHtml(s.url) + '</a></li>';
        });
        h += '</ul></div>';
    }

    // All queries table (initial + final)
    var allQueries = initQueries.concat(finalQueries);
    if (allQueries.length) {
        h += '<div class="intel-card wi-queries-card"><h5>Dork Queries Used</h5>' +
            '<table class="intel-table"><tr><th>Phase</th><th>Query</th><th>Purpose</th></tr>';
        allQueries.forEach(function (q) {
            var typeLabel, typeClass;
            if (q.type === 'collection') {
                typeLabel = 'COLLECT';
                typeClass = 'wi-badge-collection';
            } else if (q.type === 'gap_fill') {
                typeLabel = 'GAP FILL';
                typeClass = 'wi-badge-new';
            } else {
                typeLabel = 'VALIDATE';
                typeClass = 'wi-badge-validate';
            }
            h += '<tr><td><span class="wi-badge ' + typeClass + '">' +
                escapeHtml(typeLabel) + '</span></td>' +
                '<td><code>' + escapeHtml(q.query) + '</code></td>' +
                '<td>' + escapeHtml(q.purpose) + '</td></tr>';
        });
        h += '</table></div>';
    }

    h += '</div></div>';
    return h;
}

function renderIpIntelSection(meta) {
    var ipGeo = meta.ip_geolocation || {};
    var ipInfo = meta.ip_intel || {};
    var ipRev = meta.ip_reverse || {};

    var h = '<div class="result-section ip-intel-section">' +
        '<h4>IP Intelligence' + (ipInfo.ip ? ': ' + escapeHtml(ipInfo.ip) : '') + '</h4>';

    if (ipGeo.ip || ipGeo.city) {
        h += '<div class="intel-card"><h5>Geolocation</h5><table class="intel-table">';
        if (ipGeo.ip) h += '<tr><td>IP</td><td>' + escapeHtml(ipGeo.ip) + '</td></tr>';
        if (ipGeo.city) h += '<tr><td>City</td><td>' + escapeHtml(ipGeo.city) + '</td></tr>';
        if (ipGeo.country) h += '<tr><td>Country</td><td>' + escapeHtml(ipGeo.country) + '</td></tr>';
        if (ipGeo.isp) h += '<tr><td>ISP</td><td>' + escapeHtml(ipGeo.isp) + '</td></tr>';
        if (ipGeo.region) h += '<tr><td>Region</td><td>' + escapeHtml(ipGeo.region) + '</td></tr>';
        h += '</table></div>';
    }

    if (ipInfo.reverse_dns) {
        h += '<div class="intel-card"><h5>Reverse DNS</h5><p>' + escapeHtml(ipInfo.reverse_dns) + '</p></div>';
    }

    var coHosted = ipInfo.co_hosted_domains || [];
    if (coHosted.length) {
        h += '<div class="intel-card"><h5>Co-Hosted Domains &mdash; ' +
            (ipInfo.co_hosted_count || coHosted.length) + ' found</h5><ul>';
        coHosted.slice(0, 20).forEach(function (d) {
            h += '<li>' + escapeHtml(d) + '</li>';
        });
        if (coHosted.length > 20) h += '<li><em>... and ' + (coHosted.length - 20) + ' more</em></li>';
        h += '</ul></div>';
    }

    if (ipRev.hostname) {
        h += '<div class="intel-card"><h5>Reverse Host: ' + escapeHtml(ipRev.hostname) + '</h5>';
        var rw = ipRev.whois || {};
        if (rw.registrar) {
            h += '<table class="intel-table">';
            h += '<tr><td>Registrar</td><td>' + escapeHtml(rw.registrar) + '</td></tr>';
            if (rw.creation_date) h += '<tr><td>Created</td><td>' + escapeHtml(rw.creation_date) + '</td></tr>';
            h += '</table>';
        }
        var rd = ipRev.dnsdumpster || {};
        var rSubs = rd.subdomains || [];
        if (rSubs.length) {
            h += '<p><strong>Subdomains:</strong> ' + rSubs.length + ' found</p>';
        }
        h += '</div>';
    }

    h += '</div>';
    return h;
}
