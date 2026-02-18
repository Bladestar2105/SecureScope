// ============================================
// SecureScope - Dashboard JavaScript
// ============================================

(function () {
    'use strict';

    // ============================================
    // Global State
    // ============================================
    let csrfToken = null;
    let currentUser = null;
    let currentScanId = null;
    let currentDetailScanId = null;
    let eventSource = null;
    let previousView = 'dashboard';
    let historyPage = 1;
    let detailPage = 1;
    let resultPage = 1;

    // ============================================
    // Toast Notification System
    // ============================================
    window.showToast = function (type, title, message) {
        const container = document.getElementById('toastContainer');
        const icons = {
            success: 'bi-check-circle-fill',
            error: 'bi-x-circle-fill',
            warning: 'bi-exclamation-triangle-fill',
            info: 'bi-info-circle-fill'
        };

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <i class="bi ${icons[type]} toast-icon"></i>
            <div class="toast-content">
                <div class="toast-title">${escapeHtml(title)}</div>
                <div class="toast-message">${escapeHtml(message)}</div>
            </div>
            <button class="toast-close" onclick="this.parentElement.classList.add('removing'); setTimeout(() => this.parentElement.remove(), 300);">
                <i class="bi bi-x"></i>
            </button>
        `;

        container.appendChild(toast);
        setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.add('removing');
                setTimeout(() => toast.remove(), 300);
            }
        }, 5000);
    };

    // ============================================
    // API Helper
    // ============================================
    async function apiRequest(url, method = 'GET', body = null) {
        const options = {
            method,
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin'
        };

        if (csrfToken) {
            options.headers['X-CSRF-Token'] = csrfToken;
        }

        if (body) {
            options.body = JSON.stringify(body);
        }

        const response = await fetch(url, options);

        // Handle session expiry
        if (response.status === 401) {
            const data = await response.json();
            if (data.sessionExpired) {
                showToast('warning', 'Sitzung abgelaufen', 'Bitte erneut einloggen');
            }
            setTimeout(() => { window.location.href = '/'; }, 1500);
            throw new Error('Nicht authentifiziert');
        }

        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Ein Fehler ist aufgetreten');
        }

        return data;
    }

    // ============================================
    // Authentication
    // ============================================
    async function checkAuth() {
        try {
            const data = await apiRequest('/api/auth/status');
            if (!data.authenticated) {
                window.location.href = '/';
                return;
            }

            currentUser = data.user;
            csrfToken = data.csrfToken;

            // Force password change
            if (data.user.forcePasswordChange) {
                window.location.href = '/';
                return;
            }

            // Update UI
            document.getElementById('sidebarUsername').textContent = currentUser.username;
            document.getElementById('userAvatar').textContent = currentUser.username.charAt(0).toUpperCase();

            // Load initial data
            loadDashboard();
            connectSSE();
        } catch (err) {
            window.location.href = '/';
        }
    }

    window.logout = async function () {
        try {
            await apiRequest('/api/auth/logout', 'POST');
        } catch (err) {
            // Ignore errors
        }
        window.location.href = '/';
    };

    window.changePassword = async function (e) {
        e.preventDefault();
        const currentPw = document.getElementById('modalCurrentPw').value;
        const newPw = document.getElementById('modalNewPw').value;
        const confirmPw = document.getElementById('modalConfirmPw').value;

        if (!currentPw || !newPw || !confirmPw) {
            showToast('error', 'Fehler', 'Bitte füllen Sie alle Felder aus');
            return;
        }

        if (newPw !== confirmPw) {
            showToast('error', 'Fehler', 'Passwörter stimmen nicht überein');
            return;
        }

        try {
            await apiRequest('/api/auth/change-password', 'POST', {
                currentPassword: currentPw,
                newPassword: newPw,
                confirmPassword: confirmPw
            });
            showToast('success', 'Erfolg', 'Passwort erfolgreich geändert');
            hidePasswordModal();
            document.getElementById('modalCurrentPw').value = '';
            document.getElementById('modalNewPw').value = '';
            document.getElementById('modalConfirmPw').value = '';
        } catch (err) {
            showToast('error', 'Fehler', err.message);
        }
    };

    // ============================================
    // Navigation
    // ============================================
    window.switchView = function (viewName) {
        // Hide all views
        document.querySelectorAll('.view-section').forEach(s => s.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

        // Show selected view
        const view = document.getElementById(`view-${viewName}`);
        if (view) view.classList.add('active');

        const navItem = document.querySelector(`.nav-item[data-view="${viewName}"]`);
        if (navItem) navItem.classList.add('active');

        // Update title
        const titles = {
            'dashboard': 'Dashboard',
            'new-scan': 'Neuer Scan',
            'history': 'Scan-Historie',
            'compare': 'Scan-Vergleich',
            'scan-detail': 'Scan Details'
        };
        document.getElementById('viewTitle').textContent = titles[viewName] || 'SecureScope';

        // Load data for specific views
        if (viewName === 'history') loadHistory();
        if (viewName === 'dashboard') loadDashboard();

        // Track previous view
        if (viewName !== 'scan-detail') previousView = viewName;

        // Close sidebar on mobile
        document.getElementById('sidebar').classList.remove('open');
    };

    window.toggleSidebar = function () {
        document.getElementById('sidebar').classList.toggle('open');
    };

    window.goBackFromDetail = function () {
        switchView(previousView);
    };

    // ============================================
    // Theme Toggle
    // ============================================
    window.toggleTheme = function () {
        const html = document.documentElement;
        const current = html.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);

        const icon = document.getElementById('themeIcon');
        icon.className = next === 'dark' ? 'bi bi-moon-stars' : 'bi bi-sun';
    };

    // Load saved theme
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    document.addEventListener('DOMContentLoaded', () => {
        const icon = document.getElementById('themeIcon');
        if (icon) icon.className = savedTheme === 'dark' ? 'bi bi-moon-stars' : 'bi bi-sun';
    });

    // ============================================
    // Password Modal
    // ============================================
    window.showPasswordModal = function () {
        document.getElementById('passwordModal').classList.remove('hidden');
    };

    window.hidePasswordModal = function () {
        document.getElementById('passwordModal').classList.add('hidden');
    };

    // ============================================
    // Dashboard
    // ============================================
    async function loadDashboard() {
        try {
            const data = await apiRequest('/api/scan/history?limit=10');

            // Calculate stats
            const scans = data.scans || [];
            const totalScans = data.pagination?.total || scans.length;
            const completed = scans.filter(s => s.status === 'completed').length;
            const running = scans.filter(s => s.status === 'running').length;
            let criticalCount = 0;

            document.getElementById('statTotalScans').textContent = totalScans;
            document.getElementById('statCompleted').textContent = completed;
            document.getElementById('statActive').textContent = running;

            // Render recent scans table
            const loading = document.getElementById('recentScansLoading');
            const table = document.getElementById('recentScansTable');
            const empty = document.getElementById('recentScansEmpty');
            const tbody = document.getElementById('recentScansTableBody');

            loading.classList.add('hidden');

            if (scans.length === 0) {
                table.classList.add('hidden');
                empty.classList.remove('hidden');
            } else {
                empty.classList.add('hidden');
                table.classList.remove('hidden');

                tbody.innerHTML = scans.map(scan => `
                    <tr>
                        <td class="text-mono">#${scan.id}</td>
                        <td class="text-mono">${escapeHtml(scan.target)}</td>
                        <td>${getScanTypeLabel(scan.scan_type)}</td>
                        <td>${getStatusBadge(scan.status)}</td>
                        <td>${scan.result_count || 0}</td>
                        <td>${formatDate(scan.started_at)}</td>
                        <td>
                            <button class="btn btn-outline btn-sm" onclick="viewScanDetail(${scan.id})" title="Details anzeigen">
                                <i class="bi bi-eye"></i>
                            </button>
                        </td>
                    </tr>
                `).join('');
            }

            // Update critical count from recent completed scans
            for (const scan of scans.filter(s => s.status === 'completed').slice(0, 5)) {
                try {
                    const results = await apiRequest(`/api/scan/results/${scan.id}?limit=100`);
                    criticalCount += (results.results || []).filter(r => r.risk_level === 'critical').length;
                } catch (e) { /* ignore */ }
            }
            document.getElementById('statCritical').textContent = criticalCount;

            // Check for active scans
            const activeScans = scans.filter(s => s.status === 'running');
            if (activeScans.length > 0) {
                showActiveScanPanel(activeScans[0]);
            } else {
                document.getElementById('activeScanPanel').classList.add('hidden');
            }

        } catch (err) {
            console.error('Failed to load dashboard:', err);
        }
    }

    function showActiveScanPanel(scan) {
        const panel = document.getElementById('activeScanPanel');
        panel.classList.remove('hidden');
        currentScanId = scan.id;

        document.getElementById('activeScanInfo').textContent =
            `Scan #${scan.id} - ${scan.target} (${getScanTypeLabel(scan.scan_type)})`;
        document.getElementById('activeScanTarget').textContent = scan.target;
        document.getElementById('activeScanProgress').style.width = `${scan.progress || 0}%`;
        document.getElementById('activeScanProgressText').textContent = `${scan.progress || 0}%`;
    }

    window.stopActiveScan = async function () {
        if (!currentScanId) return;
        try {
            await apiRequest(`/api/scan/stop/${currentScanId}`, 'POST');
            showToast('info', 'Scan abgebrochen', 'Der Scan wird gestoppt');
            document.getElementById('activeScanPanel').classList.add('hidden');
            currentScanId = null;
        } catch (err) {
            showToast('error', 'Fehler', err.message);
        }
    };

    // ============================================
    // Server-Sent Events (SSE)
    // ============================================
    function connectSSE() {
        if (eventSource) {
            eventSource.close();
        }

        eventSource = new EventSource('/api/scan/events');

        eventSource.onmessage = function (event) {
            try {
                const data = JSON.parse(event.data);
                handleSSEEvent(data);
            } catch (err) {
                console.error('SSE parse error:', err);
            }
        };

        eventSource.onerror = function () {
            // Reconnect after 5 seconds
            setTimeout(() => {
                if (eventSource.readyState === EventSource.CLOSED) {
                    connectSSE();
                }
            }, 5000);
        };
    }

    function handleSSEEvent(data) {
        switch (data.type) {
            case 'progress':
                updateScanProgress(data);
                break;
            case 'complete':
                handleScanComplete(data);
                break;
            case 'error':
                handleScanError(data);
                break;
        }
    }

    function updateScanProgress(data) {
        // Update active scan panel on dashboard
        if (currentScanId === data.scanId) {
            document.getElementById('activeScanProgress').style.width = `${data.progress}%`;
            document.getElementById('activeScanProgressText').textContent = `${data.progress}%`;
        }

        // Update new scan progress panel
        const progressBar = document.getElementById('scanProgressBar');
        const progressPercent = document.getElementById('scanProgressPercent');
        const progressDetail = document.getElementById('scanProgressDetail');
        const progressInfo = document.getElementById('scanProgressInfo');

        if (progressBar) {
            progressBar.style.width = `${data.progress}%`;
            progressPercent.textContent = `${data.progress}%`;
            if (data.completedTargets && data.totalTargets) {
                progressDetail.textContent = `${data.completedTargets} / ${data.totalTargets} Hosts`;
            }
            progressInfo.textContent = `Scan läuft... ${data.progress}% abgeschlossen`;
        }
    }

    function handleScanComplete(data) {
        showToast('success', 'Scan abgeschlossen',
            `Scan #${data.scanId} wurde mit ${data.resultCount} Ergebnissen abgeschlossen`);

        // Hide active scan panel
        if (currentScanId === data.scanId) {
            document.getElementById('activeScanPanel').classList.add('hidden');
            currentScanId = null;
        }

        // Update scan progress panel
        const progressPanel = document.getElementById('scanProgressPanel');
        const runningIndicator = document.getElementById('scanRunningIndicator');
        if (progressPanel && !progressPanel.classList.contains('hidden')) {
            runningIndicator.innerHTML = `
                <i class="bi bi-check-circle text-success" style="font-size: 1.25rem;"></i>
                <span>Scan abgeschlossen - ${data.resultCount} offene Ports gefunden</span>
            `;
            document.getElementById('stopScanBtn').classList.add('hidden');
            document.getElementById('scanProgressBar').style.width = '100%';
            document.getElementById('scanProgressBar').classList.remove('animated');
            document.getElementById('scanProgressPercent').textContent = '100%';

            // Load results
            loadScanResults(data.scanId);
        }

        // Refresh dashboard stats
        loadDashboard();
    }

    function handleScanError(data) {
        showToast('error', 'Scan fehlgeschlagen', data.error || 'Ein Fehler ist aufgetreten');

        if (currentScanId === data.scanId) {
            document.getElementById('activeScanPanel').classList.add('hidden');
            currentScanId = null;
        }
    }

    // ============================================
    // Scan Operations
    // ============================================
    window.toggleCustomPorts = function () {
        const scanType = document.getElementById('scanType').value;
        const customGroup = document.getElementById('customPortsGroup');
        const warning = document.getElementById('scanWarning');

        if (scanType === 'custom') {
            customGroup.classList.remove('hidden');
        } else {
            customGroup.classList.add('hidden');
        }

        if (scanType === 'full') {
            warning.classList.remove('hidden');
            document.getElementById('scanWarningText').textContent =
                'Ein Full Scan aller 65535 Ports kann sehr lange dauern. Empfohlen für detaillierte Analysen.';
        } else {
            warning.classList.add('hidden');
        }
    };

    window.startScan = async function (e) {
        e.preventDefault();

        const target = document.getElementById('scanTarget').value.trim();
        const scanType = document.getElementById('scanType').value;
        const customPorts = document.getElementById('customPorts').value.trim();

        if (!target) {
            showToast('error', 'Fehler', 'Bitte geben Sie ein Ziel ein');
            return;
        }

        const btn = document.getElementById('startScanBtn');
        const btnText = document.getElementById('startScanBtnText');
        const spinner = document.getElementById('startScanSpinner');

        btn.disabled = true;
        btnText.classList.add('hidden');
        spinner.classList.remove('hidden');

        try {
            const body = { target, scanType };
            if (scanType === 'custom') {
                body.customPorts = customPorts;
            }

            const data = await apiRequest('/api/scan/start', 'POST', body);

            if (data.success) {
                currentScanId = data.scan.id;
                showToast('success', 'Scan gestartet', `Scan #${data.scan.id} für ${target} wurde gestartet`);

                // Show progress panel
                document.getElementById('scanProgressPanel').classList.remove('hidden');
                document.getElementById('scanResultsPanel').classList.add('hidden');
                document.getElementById('stopScanBtn').classList.remove('hidden');
                document.getElementById('scanRunningIndicator').innerHTML = `
                    <div class="scan-pulse"></div>
                    <span id="scanProgressInfo">Scan wird gestartet...</span>
                `;
                document.getElementById('scanProgressBar').style.width = '0%';
                document.getElementById('scanProgressBar').classList.add('animated');
                document.getElementById('scanProgressPercent').textContent = '0%';
                document.getElementById('scanProgressDetail').textContent = '';

                // Poll for status updates
                pollScanStatus(data.scan.id);
            }
        } catch (err) {
            showToast('error', 'Scan fehlgeschlagen', err.message);
        } finally {
            btn.disabled = false;
            btnText.classList.remove('hidden');
            spinner.classList.add('hidden');
        }
    };

    async function pollScanStatus(scanId) {
        const poll = async () => {
            try {
                const data = await apiRequest(`/api/scan/status/${scanId}`);
                if (data.scan) {
                    const scan = data.scan;

                    // Update progress
                    updateScanProgress({
                        scanId: scanId,
                        progress: scan.progress || 0
                    });

                    if (scan.status === 'running') {
                        setTimeout(poll, 2000);
                    } else if (scan.status === 'completed') {
                        handleScanComplete({ scanId, resultCount: 0 });
                        loadScanResults(scanId);
                    } else if (scan.status === 'failed') {
                        handleScanError({ scanId, error: scan.error_message });
                    } else if (scan.status === 'aborted') {
                        showToast('warning', 'Scan abgebrochen', `Scan #${scanId} wurde abgebrochen`);
                        document.getElementById('scanProgressPanel').classList.add('hidden');
                    }
                }
            } catch (err) {
                console.error('Poll error:', err);
                setTimeout(poll, 5000);
            }
        };
        poll();
    }

    window.stopCurrentScan = async function () {
        if (!currentScanId) return;
        try {
            await apiRequest(`/api/scan/stop/${currentScanId}`, 'POST');
            showToast('info', 'Abbruch angefordert', 'Der Scan wird gestoppt...');
        } catch (err) {
            showToast('error', 'Fehler', err.message);
        }
    };

    async function loadScanResults(scanId, page = 1) {
        resultPage = page;
        try {
            const data = await apiRequest(`/api/scan/results/${scanId}?page=${page}&limit=50`);
            const results = data.results || [];
            const panel = document.getElementById('scanResultsPanel');
            const tbody = document.getElementById('resultsTableBody');
            const empty = document.getElementById('resultsEmpty');

            panel.classList.remove('hidden');

            if (results.length === 0 && page === 1) {
                empty.classList.remove('hidden');
                tbody.innerHTML = '';
            } else {
                empty.classList.add('hidden');
                renderResultsTable(tbody, results);
            }

            // Update summary
            const allResults = data.results || [];
            const critical = allResults.filter(r => r.risk_level === 'critical').length;
            const warning = allResults.filter(r => r.risk_level === 'warning').length;
            const safe = allResults.filter(r => r.risk_level === 'safe').length;

            document.getElementById('resultTotal').textContent = data.pagination?.total || results.length;
            document.getElementById('resultCritical').textContent = critical;
            document.getElementById('resultWarning').textContent = warning;
            document.getElementById('resultSafe').textContent = safe;

            // Pagination
            renderPagination(
                'resultsPagination', 'resultsPaginationBtns', 'resultsPaginationInfo',
                data.pagination, (p) => loadScanResults(scanId, p)
            );

            // Store current scan ID for export
            currentScanId = scanId;

        } catch (err) {
            showToast('error', 'Fehler', 'Ergebnisse konnten nicht geladen werden');
        }
    }

    // ============================================
    // Export Functions
    // ============================================
    window.exportResults = function (format) {
        if (!currentScanId) return;
        window.open(`/api/scan/export/${currentScanId}?format=${format}`, '_blank');
    };

    window.exportDetailResults = function (format) {
        if (!currentDetailScanId) return;
        window.open(`/api/scan/export/${currentDetailScanId}?format=${format}`, '_blank');
    };

    // ============================================
    // Scan History
    // ============================================
    window.loadHistory = async function (page = 1) {
        historyPage = page;
        const loading = document.getElementById('historyLoading');
        const empty = document.getElementById('historyEmpty');
        const tbody = document.getElementById('historyTableBody');

        loading.classList.remove('hidden');
        empty.classList.add('hidden');

        const params = new URLSearchParams();
        params.set('page', page);
        params.set('limit', 20);

        const dateFrom = document.getElementById('filterDateFrom').value;
        const dateTo = document.getElementById('filterDateTo').value;
        const scanType = document.getElementById('filterScanType').value;
        const status = document.getElementById('filterStatus').value;
        const target = document.getElementById('filterTarget').value;

        if (dateFrom) params.set('dateFrom', dateFrom);
        if (dateTo) params.set('dateTo', dateTo);
        if (scanType) params.set('scanType', scanType);
        if (status) params.set('status', status);
        if (target) params.set('target', target);

        try {
            const data = await apiRequest(`/api/scan/history?${params.toString()}`);
            const scans = data.scans || [];

            loading.classList.add('hidden');

            if (scans.length === 0) {
                empty.classList.remove('hidden');
                tbody.innerHTML = '';
            } else {
                empty.classList.add('hidden');
                tbody.innerHTML = scans.map(scan => `
                    <tr>
                        <td class="text-mono">#${scan.id}</td>
                        <td class="text-mono">${escapeHtml(scan.target)}</td>
                        <td>${getScanTypeLabel(scan.scan_type)}</td>
                        <td>${getStatusBadge(scan.status)}</td>
                        <td>${scan.result_count || 0}</td>
                        <td>${formatDate(scan.started_at)}</td>
                        <td>${calculateDuration(scan.started_at, scan.completed_at)}</td>
                        <td>
                            <div class="d-flex gap-1">
                                <button class="btn btn-outline btn-sm" onclick="viewScanDetail(${scan.id})" title="Details">
                                    <i class="bi bi-eye"></i>
                                </button>
                                <button class="btn btn-outline btn-sm" onclick="exportFromHistory(${scan.id}, 'csv')" title="CSV Export">
                                    <i class="bi bi-download"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                `).join('');
            }

            renderPagination(
                'historyPagination', 'historyPaginationBtns', 'historyPaginationInfo',
                data.pagination, loadHistory
            );

        } catch (err) {
            loading.classList.add('hidden');
            showToast('error', 'Fehler', 'Historie konnte nicht geladen werden');
        }
    };

    window.exportFromHistory = function (scanId, format) {
        window.open(`/api/scan/export/${scanId}?format=${format}`, '_blank');
    };

    // ============================================
    // Scan Detail View
    // ============================================
    window.viewScanDetail = async function (scanId) {
        currentDetailScanId = scanId;
        switchView('scan-detail');

        try {
            const statusData = await apiRequest(`/api/scan/status/${scanId}`);
            const scan = statusData.scan;

            document.getElementById('scanDetailTitle').textContent = `Scan #${scan.id} Details`;
            document.getElementById('detailId').textContent = `#${scan.id}`;
            document.getElementById('detailTarget').textContent = scan.target;
            document.getElementById('detailType').textContent = getScanTypeLabel(scan.scan_type);
            document.getElementById('detailStatus').innerHTML = getStatusBadge(scan.status);
            document.getElementById('detailStarted').textContent = formatDate(scan.started_at);
            document.getElementById('detailCompleted').textContent = scan.completed_at ? formatDate(scan.completed_at) : 'N/A';

            // Load results
            await loadDetailResults(scanId, 1);

        } catch (err) {
            showToast('error', 'Fehler', 'Scan-Details konnten nicht geladen werden');
        }
    };

    async function loadDetailResults(scanId, page = 1) {
        detailPage = page;
        try {
            const data = await apiRequest(`/api/scan/results/${scanId}?page=${page}&limit=50`);
            const results = data.results || [];
            const tbody = document.getElementById('detailResultsBody');
            const empty = document.getElementById('detailResultsEmpty');

            if (results.length === 0 && page === 1) {
                empty.classList.remove('hidden');
                tbody.innerHTML = '';
            } else {
                empty.classList.add('hidden');
                renderResultsTable(tbody, results);
            }

            // Summary
            const critical = results.filter(r => r.risk_level === 'critical').length;
            const warning = results.filter(r => r.risk_level === 'warning').length;
            const safe = results.filter(r => r.risk_level === 'safe').length;

            document.getElementById('detailSummary').innerHTML = `
                <div class="stat-card">
                    <div class="stat-icon blue"><i class="bi bi-hdd-network"></i></div>
                    <div class="stat-info">
                        <h4>Offene Ports</h4>
                        <div class="stat-value">${data.pagination?.total || results.length}</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon red"><i class="bi bi-shield-x"></i></div>
                    <div class="stat-info">
                        <h4>Kritisch</h4>
                        <div class="stat-value">${critical}</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon yellow"><i class="bi bi-shield-exclamation"></i></div>
                    <div class="stat-info">
                        <h4>Warnung</h4>
                        <div class="stat-value">${warning}</div>
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon green"><i class="bi bi-shield-check"></i></div>
                    <div class="stat-info">
                        <h4>Sicher</h4>
                        <div class="stat-value">${safe}</div>
                    </div>
                </div>
            `;

            renderPagination(
                'detailPagination', 'detailPaginationBtns', 'detailPaginationInfo',
                data.pagination, (p) => loadDetailResults(scanId, p)
            );

        } catch (err) {
            showToast('error', 'Fehler', 'Ergebnisse konnten nicht geladen werden');
        }
    }

    // ============================================
    // Scan Comparison
    // ============================================
    window.compareScans = async function () {
        const scan1 = document.getElementById('compareScan1').value;
        const scan2 = document.getElementById('compareScan2').value;

        if (!scan1 || !scan2) {
            showToast('error', 'Fehler', 'Bitte geben Sie zwei Scan-IDs ein');
            return;
        }

        try {
            const data = await apiRequest(`/api/scan/compare?scan1=${scan1}&scan2=${scan2}`);
            const comp = data.comparison;

            document.getElementById('comparisonResults').classList.remove('hidden');
            document.getElementById('compareNew').textContent = comp.newPorts;
            document.getElementById('compareClosed').textContent = comp.closedPorts;
            document.getElementById('compareUnchanged').textContent = comp.unchangedPorts;

            // Render new ports (only in scan 2)
            const newBody = document.getElementById('compareNewBody');
            if (comp.onlyInScan2.length > 0) {
                newBody.innerHTML = comp.onlyInScan2.map(r => `
                    <tr>
                        <td class="text-mono">${escapeHtml(r.ip_address)}</td>
                        <td class="text-mono">${r.port}</td>
                        <td>${escapeHtml(r.service || 'Unknown')}</td>
                        <td>${getRiskBadge(r.risk_level)}</td>
                    </tr>
                `).join('');
            } else {
                newBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Keine neuen Ports</td></tr>';
            }

            // Render removed ports (only in scan 1)
            const removedBody = document.getElementById('compareRemovedBody');
            if (comp.onlyInScan1.length > 0) {
                removedBody.innerHTML = comp.onlyInScan1.map(r => `
                    <tr>
                        <td class="text-mono">${escapeHtml(r.ip_address)}</td>
                        <td class="text-mono">${r.port}</td>
                        <td>${escapeHtml(r.service || 'Unknown')}</td>
                        <td>${getRiskBadge(r.risk_level)}</td>
                    </tr>
                `).join('');
            } else {
                removedBody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">Keine geschlossenen Ports</td></tr>';
            }

            showToast('success', 'Vergleich abgeschlossen', `${comp.newPorts} neue, ${comp.closedPorts} geschlossene Ports`);

        } catch (err) {
            showToast('error', 'Fehler', err.message);
        }
    };

    // ============================================
    // Rendering Helpers
    // ============================================
    function renderResultsTable(tbody, results) {
        tbody.innerHTML = results.map(r => `
            <tr>
                <td class="text-mono">${escapeHtml(r.ip_address)}</td>
                <td class="text-mono">${r.port}</td>
                <td>${escapeHtml(r.protocol || 'tcp')}</td>
                <td>${escapeHtml(r.service || 'Unknown')}</td>
                <td>${escapeHtml(r.state || 'open')}</td>
                <td>${getRiskBadge(r.risk_level)}</td>
            </tr>
        `).join('');
    }

    function renderPagination(containerId, btnsId, infoId, pagination, callback) {
        const container = document.getElementById(containerId);
        const btns = document.getElementById(btnsId);
        const info = document.getElementById(infoId);

        if (!pagination || pagination.totalPages <= 1) {
            container.classList.add('hidden');
            return;
        }

        container.classList.remove('hidden');

        let html = '';
        const { page, totalPages, total, limit } = pagination;

        // Previous button
        html += `<button class="page-btn" ${page <= 1 ? 'disabled' : ''} onclick="(${callback.toString()})(${page - 1})">
            <i class="bi bi-chevron-left"></i>
        </button>`;

        // Page numbers
        const startPage = Math.max(1, page - 2);
        const endPage = Math.min(totalPages, page + 2);

        if (startPage > 1) {
            html += `<button class="page-btn" onclick="(${callback.toString()})(1)">1</button>`;
            if (startPage > 2) html += `<span class="text-muted" style="padding: 0 0.25rem;">...</span>`;
        }

        for (let i = startPage; i <= endPage; i++) {
            html += `<button class="page-btn ${i === page ? 'active' : ''}" onclick="(${callback.toString()})(${i})">${i}</button>`;
        }

        if (endPage < totalPages) {
            if (endPage < totalPages - 1) html += `<span class="text-muted" style="padding: 0 0.25rem;">...</span>`;
            html += `<button class="page-btn" onclick="(${callback.toString()})(${totalPages})">${totalPages}</button>`;
        }

        // Next button
        html += `<button class="page-btn" ${page >= totalPages ? 'disabled' : ''} onclick="(${callback.toString()})(${page + 1})">
            <i class="bi bi-chevron-right"></i>
        </button>`;

        btns.innerHTML = html;

        const from = (page - 1) * limit + 1;
        const to = Math.min(page * limit, total);
        info.textContent = `Zeige ${from}-${to} von ${total} Einträgen`;
    }

    // ============================================
    // Utility Functions
    // ============================================
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function getScanTypeLabel(type) {
        const labels = {
            'quick': '<span class="badge badge-info">Quick</span>',
            'standard': '<span class="badge badge-info">Standard</span>',
            'full': '<span class="badge badge-warning">Full</span>',
            'custom': '<span class="badge badge-info">Custom</span>'
        };
        return labels[type] || type;
    }

    function getStatusBadge(status) {
        const badges = {
            'pending': '<span class="badge badge-status badge-info">Wartend</span>',
            'running': '<span class="badge badge-status badge-running"><i class="bi bi-broadcast"></i> Läuft</span>',
            'completed': '<span class="badge badge-status badge-completed"><i class="bi bi-check-circle"></i> Abgeschlossen</span>',
            'failed': '<span class="badge badge-status badge-failed"><i class="bi bi-x-circle"></i> Fehlgeschlagen</span>',
            'aborted': '<span class="badge badge-status badge-aborted"><i class="bi bi-stop-circle"></i> Abgebrochen</span>'
        };
        return badges[status] || status;
    }

    function getRiskBadge(risk) {
        const badges = {
            'safe': '<span class="badge badge-safe"><i class="bi bi-shield-check"></i> Sicher</span>',
            'warning': '<span class="badge badge-warning"><i class="bi bi-shield-exclamation"></i> Warnung</span>',
            'critical': '<span class="badge badge-critical"><i class="bi bi-shield-x"></i> Kritisch</span>',
            'info': '<span class="badge badge-info"><i class="bi bi-info-circle"></i> Info</span>'
        };
        return badges[risk] || risk;
    }

    function formatDate(dateStr) {
        if (!dateStr) return 'N/A';
        const date = new Date(dateStr);
        return date.toLocaleString('de-DE', {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    function calculateDuration(start, end) {
        if (!start || !end) return '-';
        const startDate = new Date(start);
        const endDate = new Date(end);
        const diff = Math.abs(endDate - startDate) / 1000; // seconds

        if (diff < 60) return `${Math.round(diff)}s`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ${Math.round(diff % 60)}s`;
        return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
    }

    // Debounce helper
    let debounceTimers = {};
    window.debounce = function (func, delay) {
        return function (...args) {
            const key = func.toString();
            clearTimeout(debounceTimers[key]);
            debounceTimers[key] = setTimeout(() => func.apply(this, args), delay);
        };
    };

    // ============================================
    // Initialize
    // ============================================
    checkAuth();

    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        if (eventSource) eventSource.close();
    });

})();