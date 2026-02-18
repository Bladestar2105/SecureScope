// ============================================
// SecureScope - Dashboard JavaScript (Extended)
// ============================================
(function () {
    'use strict';

    // Global State
    let csrfToken = null, currentUser = null, currentScanId = null;
    let currentDetailScanId = null, eventSource = null, previousView = 'dashboard';
    let userRoles = [], userPermissions = [];

    // ============================================
    // Toast System
    // ============================================
    window.showToast = function (type, title, message) {
        const container = document.getElementById('toastContainer');
        const icons = { success:'bi-check-circle-fill', error:'bi-x-circle-fill', warning:'bi-exclamation-triangle-fill', info:'bi-info-circle-fill' };
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `<i class="bi ${icons[type]} toast-icon"></i><div class="toast-content"><div class="toast-title">${esc(title)}</div><div class="toast-message">${esc(message)}</div></div><button class="toast-close" onclick="this.parentElement.classList.add('removing');setTimeout(()=>this.parentElement.remove(),300)"><i class="bi bi-x"></i></button>`;
        container.appendChild(toast);
        setTimeout(() => { if (toast.parentElement) { toast.classList.add('removing'); setTimeout(() => toast.remove(), 300); } }, 5000);
    };

    // ============================================
    // API Helper
    // ============================================
    async function api(url, method = 'GET', body = null) {
        const opts = { method, headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin' };
        if (csrfToken) opts.headers['X-CSRF-Token'] = csrfToken;
        if (body) opts.body = JSON.stringify(body);
        const res = await fetch(url, opts);
        if (res.status === 401) {
            const d = await res.json();
            if (d.sessionExpired) showToast('warning', 'Sitzung abgelaufen', 'Bitte erneut einloggen');
            setTimeout(() => { window.location.href = '/'; }, 1500);
            throw new Error('Nicht authentifiziert');
        }
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Fehler');
        return data;
    }

    // ============================================
    // Auth
    // ============================================
    async function checkAuth() {
        try {
            const d = await api('/api/auth/status');
            if (!d.authenticated) { window.location.href = '/'; return; }
            currentUser = d.user; csrfToken = d.csrfToken;
            if (d.user.forcePasswordChange) { window.location.href = '/'; return; }
            document.getElementById('sidebarUsername').textContent = currentUser.username;
            document.getElementById('userAvatar').textContent = currentUser.username.charAt(0).toUpperCase();
            // Load permissions
            try {
                const perms = await api('/api/users/me/permissions');
                userRoles = perms.roles || []; userPermissions = perms.permissions || [];
                document.getElementById('sidebarRole').textContent = userRoles.join(', ') || 'Benutzer';
                // Hide admin section if not admin
                if (!userRoles.includes('admin')) {
                    const adminItems = document.querySelectorAll('[data-view="users"]');
                    adminItems.forEach(el => el.style.display = 'none');
                }
            } catch (e) { /* ignore */ }
            loadDashboard(); connectSSE();
        } catch (e) { window.location.href = '/'; }
    }

    window.logout = async function () { try { await api('/api/auth/logout', 'POST'); } catch (e) {} window.location.href = '/'; };

    window.changePassword = async function (e) {
        e.preventDefault();
        const cur = document.getElementById('modalCurrentPw').value, nw = document.getElementById('modalNewPw').value, cf = document.getElementById('modalConfirmPw').value;
        if (!cur || !nw || !cf) { showToast('error', 'Fehler', 'Alle Felder ausfüllen'); return; }
        if (nw !== cf) { showToast('error', 'Fehler', 'Passwörter stimmen nicht überein'); return; }
        try {
            await api('/api/auth/change-password', 'POST', { currentPassword: cur, newPassword: nw, confirmPassword: cf });
            showToast('success', 'Erfolg', 'Passwort geändert'); hidePasswordModal();
            ['modalCurrentPw','modalNewPw','modalConfirmPw'].forEach(id => document.getElementById(id).value = '');
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // Navigation
    // ============================================
    window.switchView = function (v) {
        document.querySelectorAll('.view-section').forEach(s => s.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        const view = document.getElementById(`view-${v}`); if (view) view.classList.add('active');
        const nav = document.querySelector(`.nav-item[data-view="${v}"]`); if (nav) nav.classList.add('active');
        const titles = { 'dashboard':'Dashboard','new-scan':'Neuer Scan','history':'Scan-Historie','compare':'Scan-Vergleich','vulnerabilities':'Schwachstellen','schedules':'Geplante Scans','users':'Benutzerverwaltung','notifications':'Benachrichtigungen','scan-detail':'Scan Details' };
        document.getElementById('viewTitle').textContent = titles[v] || 'SecureScope';
        if (v === 'history') loadHistory(); if (v === 'dashboard') loadDashboard();
        if (v === 'vulnerabilities') loadVulnerabilities(); if (v === 'schedules') loadSchedules();
        if (v === 'users') loadUsers(); if (v === 'notifications') loadNotificationSettings();
        if (v !== 'scan-detail') previousView = v;
        document.getElementById('sidebar').classList.remove('open');
    };
    window.toggleSidebar = function () { document.getElementById('sidebar').classList.toggle('open'); };
    window.goBackFromDetail = function () { switchView(previousView); };

    // ============================================
    // Theme
    // ============================================
    window.toggleTheme = function () {
        const html = document.documentElement, next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next); localStorage.setItem('theme', next);
        document.getElementById('themeIcon').className = next === 'dark' ? 'bi bi-moon-stars' : 'bi bi-sun';
    };
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    document.addEventListener('DOMContentLoaded', () => { const i = document.getElementById('themeIcon'); if (i) i.className = savedTheme === 'dark' ? 'bi bi-moon-stars' : 'bi bi-sun'; });

    // Modals
    window.showPasswordModal = () => document.getElementById('passwordModal').classList.remove('hidden');
    window.hidePasswordModal = () => document.getElementById('passwordModal').classList.add('hidden');

    // ============================================
    // Dashboard
    // ============================================
    async function loadDashboard() {
        try {
            const d = await api('/api/scan/history?limit=10');
            const scans = d.scans || [], total = d.pagination?.total || scans.length;
            const completed = scans.filter(s => s.status === 'completed').length;
            const running = scans.filter(s => s.status === 'running').length;
            document.getElementById('statTotalScans').textContent = total;
            document.getElementById('statCompleted').textContent = completed;
            document.getElementById('statActive').textContent = running;

            const loading = document.getElementById('recentScansLoading'), table = document.getElementById('recentScansTable');
            const empty = document.getElementById('recentScansEmpty'), tbody = document.getElementById('recentScansTableBody');
            loading.classList.add('hidden');

            if (scans.length === 0) { table.classList.add('hidden'); empty.classList.remove('hidden'); }
            else {
                empty.classList.add('hidden'); table.classList.remove('hidden');
                // Load vuln counts for recent scans
                const vulnCounts = {};
                let totalVulns = 0;
                for (const s of scans.filter(s => s.status === 'completed').slice(0, 5)) {
                    try {
                        const vd = await api(`/api/vulnerabilities/scan/${s.id}`);
                        vulnCounts[s.id] = vd.summary?.total || 0;
                        totalVulns += vulnCounts[s.id];
                    } catch (e) { vulnCounts[s.id] = 0; }
                }
                document.getElementById('statVulns').textContent = totalVulns;
                document.getElementById('statCritical').textContent = scans.reduce((a, s) => a + (s.result_count || 0), 0);

                tbody.innerHTML = scans.map(s => `<tr>
                    <td class="text-mono">#${s.id}</td><td class="text-mono">${esc(s.target)}</td>
                    <td>${scanTypeBadge(s.scan_type)}</td><td>${statusBadge(s.status)}</td>
                    <td>${s.result_count || 0}</td><td>${vulnCounts[s.id] !== undefined ? vulnCounts[s.id] : '-'}</td>
                    <td>${fmtDate(s.started_at)}</td>
                    <td><button class="btn btn-outline btn-sm" onclick="viewScanDetail(${s.id})"><i class="bi bi-eye"></i></button></td>
                </tr>`).join('');
            }

            const activeScans = scans.filter(s => s.status === 'running');
            if (activeScans.length > 0) { showActiveScanPanel(activeScans[0]); }
            else { document.getElementById('activeScanPanel').classList.add('hidden'); }
        } catch (e) { console.error('Dashboard load failed:', e); }
    }

    function showActiveScanPanel(scan) {
        document.getElementById('activeScanPanel').classList.remove('hidden');
        currentScanId = scan.id;
        document.getElementById('activeScanInfo').textContent = `Scan #${scan.id} - ${scan.target} (${scan.scan_type})`;
        document.getElementById('activeScanTarget').textContent = scan.target;
        document.getElementById('activeScanProgress').style.width = `${scan.progress || 0}%`;
        document.getElementById('activeScanProgressText').textContent = `${scan.progress || 0}%`;
    }

    window.stopActiveScan = async function () {
        if (!currentScanId) return;
        try { await api(`/api/scan/stop/${currentScanId}`, 'POST'); showToast('info', 'Abgebrochen', 'Scan wird gestoppt');
            document.getElementById('activeScanPanel').classList.add('hidden'); currentScanId = null;
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // SSE
    // ============================================
    function connectSSE() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource('/api/scan/events');
        eventSource.onmessage = function (e) { try { handleSSE(JSON.parse(e.data)); } catch (err) {} };
        eventSource.onerror = function () { setTimeout(() => { if (eventSource.readyState === EventSource.CLOSED) connectSSE(); }, 5000); };
    }

    function handleSSE(data) {
        if (data.type === 'progress') updateProgress(data);
        else if (data.type === 'complete') handleComplete(data);
        else if (data.type === 'error') handleScanError(data);
    }

    function updateProgress(d) {
        if (currentScanId === d.scanId) {
            document.getElementById('activeScanProgress').style.width = `${d.progress}%`;
            document.getElementById('activeScanProgressText').textContent = `${d.progress}%`;
        }
        const bar = document.getElementById('scanProgressBar');
        if (bar) { bar.style.width = `${d.progress}%`; document.getElementById('scanProgressPercent').textContent = `${d.progress}%`;
            if (d.completedTargets && d.totalTargets) document.getElementById('scanProgressDetail').textContent = `${d.completedTargets}/${d.totalTargets} Hosts`;
            document.getElementById('scanProgressInfo').textContent = `Scan läuft... ${d.progress}%`;
        }
    }

    function handleComplete(d) {
        let msg = `Scan #${d.scanId}: ${d.resultCount} Ergebnisse`;
        if (d.vulnerabilities && d.vulnerabilities.total > 0) msg += `, ${d.vulnerabilities.total} Schwachstellen`;
        showToast('success', 'Scan abgeschlossen', msg);
        if (currentScanId === d.scanId) { document.getElementById('activeScanPanel').classList.add('hidden'); currentScanId = null; }
        const pp = document.getElementById('scanProgressPanel');
        if (pp && !pp.classList.contains('hidden')) {
            document.getElementById('scanRunningIndicator').innerHTML = `<i class="bi bi-check-circle text-success" style="font-size:1.25rem"></i><span>Scan abgeschlossen - ${d.resultCount} offene Ports</span>`;
            document.getElementById('stopScanBtn').classList.add('hidden');
            document.getElementById('scanProgressBar').style.width = '100%';
            document.getElementById('scanProgressBar').classList.remove('animated');
            document.getElementById('scanProgressPercent').textContent = '100%';
            loadScanResults(d.scanId);
        }
        loadDashboard();
    }

    function handleScanError(d) {
        showToast('error', 'Scan fehlgeschlagen', d.error || 'Fehler');
        if (currentScanId === d.scanId) { document.getElementById('activeScanPanel').classList.add('hidden'); currentScanId = null; }
    }

    // ============================================
    // Scan Operations
    // ============================================
    window.toggleCustomPorts = function () {
        const t = document.getElementById('scanType').value;
        document.getElementById('customPortsGroup').classList.toggle('hidden', t !== 'custom');
        const w = document.getElementById('scanWarning');
        if (t === 'full') { w.classList.remove('hidden'); document.getElementById('scanWarningText').textContent = 'Full Scan aller 65535 Ports kann sehr lange dauern.'; }
        else w.classList.add('hidden');
    };

    window.startScan = async function (e) {
        e.preventDefault();
        const target = document.getElementById('scanTarget').value.trim(), scanType = document.getElementById('scanType').value;
        const customPorts = document.getElementById('customPorts').value.trim();
        if (!target) { showToast('error', 'Fehler', 'Ziel eingeben'); return; }
        const btn = document.getElementById('startScanBtn'); btn.disabled = true;
        document.getElementById('startScanBtnText').classList.add('hidden'); document.getElementById('startScanSpinner').classList.remove('hidden');
        try {
            const body = { target, scanType }; if (scanType === 'custom') body.customPorts = customPorts;
            const d = await api('/api/scan/start', 'POST', body);
            if (d.success) {
                currentScanId = d.scan.id; showToast('success', 'Gestartet', `Scan #${d.scan.id} für ${target}`);
                document.getElementById('scanProgressPanel').classList.remove('hidden');
                document.getElementById('scanResultsPanel').classList.add('hidden');
                document.getElementById('stopScanBtn').classList.remove('hidden');
                document.getElementById('scanRunningIndicator').innerHTML = '<div class="scan-pulse"></div><span id="scanProgressInfo">Scan wird gestartet...</span>';
                document.getElementById('scanProgressBar').style.width = '0%';
                document.getElementById('scanProgressBar').classList.add('animated');
                document.getElementById('scanProgressPercent').textContent = '0%';
                document.getElementById('scanProgressDetail').textContent = '';
                pollScanStatus(d.scan.id);
            }
        } catch (e) { showToast('error', 'Fehler', e.message); }
        finally { btn.disabled = false; document.getElementById('startScanBtnText').classList.remove('hidden'); document.getElementById('startScanSpinner').classList.add('hidden'); }
    };

    async function pollScanStatus(scanId) {
        const poll = async () => {
            try {
                const d = await api(`/api/scan/status/${scanId}`);
                if (d.scan) {
                    updateProgress({ scanId, progress: d.scan.progress || 0 });
                    if (d.scan.status === 'running') setTimeout(poll, 2000);
                    else if (d.scan.status === 'completed') { handleComplete({ scanId, resultCount: 0 }); loadScanResults(scanId); }
                    else if (d.scan.status === 'failed') handleScanError({ scanId, error: d.scan.error_message });
                    else if (d.scan.status === 'aborted') { showToast('warning', 'Abgebrochen', `Scan #${scanId}`); document.getElementById('scanProgressPanel').classList.add('hidden'); }
                }
            } catch (e) { setTimeout(poll, 5000); }
        }; poll();
    }

    window.stopCurrentScan = async function () { if (!currentScanId) return; try { await api(`/api/scan/stop/${currentScanId}`, 'POST'); showToast('info', 'Abbruch', 'Wird gestoppt...'); } catch (e) { showToast('error', 'Fehler', e.message); } };

    async function loadScanResults(scanId, page = 1) {
        try {
            const d = await api(`/api/scan/results/${scanId}?page=${page}&limit=50`);
            const results = d.results || [], panel = document.getElementById('scanResultsPanel');
            panel.classList.remove('hidden');
            const tbody = document.getElementById('resultsTableBody'), empty = document.getElementById('resultsEmpty');
            if (results.length === 0 && page === 1) { empty.classList.remove('hidden'); tbody.innerHTML = ''; }
            else { empty.classList.add('hidden'); renderResultsTable(tbody, results); }
            const cr = results.filter(r => r.risk_level === 'critical').length, wr = results.filter(r => r.risk_level === 'warning').length, sf = results.filter(r => r.risk_level === 'safe').length;
            document.getElementById('resultTotal').textContent = d.pagination?.total || results.length;
            document.getElementById('resultCritical').textContent = cr; document.getElementById('resultWarning').textContent = wr; document.getElementById('resultSafe').textContent = sf;
            renderPagination('resultsPagination','resultsPaginationBtns','resultsPaginationInfo', d.pagination, (p) => loadScanResults(scanId, p));
            currentScanId = scanId;
            // Load vulnerabilities for this scan
            loadScanVulnerabilities(scanId);
        } catch (e) { showToast('error', 'Fehler', 'Ergebnisse nicht geladen'); }
    }

    async function loadScanVulnerabilities(scanId) {
        try {
            const d = await api(`/api/vulnerabilities/scan/${scanId}`);
            const vulns = d.vulnerabilities || [], tbody = document.getElementById('scanVulnTableBody'), empty = document.getElementById('scanVulnEmpty');
            if (vulns.length === 0) { empty.classList.remove('hidden'); tbody.innerHTML = ''; }
            else { empty.classList.add('hidden'); tbody.innerHTML = vulns.map(v => `<tr><td class="text-mono">${esc(v.ip_address)}:${v.port}</td><td class="text-mono">${esc(v.cve_id||'N/A')}</td><td>${esc(v.title)}</td><td>${severityBadge(v.severity)}</td><td>${v.cvss_score||'N/A'}</td></tr>`).join(''); }
        } catch (e) { /* ignore */ }
    }

    window.exportResults = (fmt) => { if (currentScanId) window.open(`/api/scan/export/${currentScanId}?format=${fmt}`, '_blank'); };
    window.exportDetailResults = (fmt) => { if (currentDetailScanId) window.open(`/api/scan/export/${currentDetailScanId}?format=${fmt}`, '_blank'); };

    // ============================================
    // History
    // ============================================
    window.loadHistory = async function (page = 1) {
        const loading = document.getElementById('historyLoading'), empty = document.getElementById('historyEmpty'), tbody = document.getElementById('historyTableBody');
        loading.classList.remove('hidden'); empty.classList.add('hidden');
        const p = new URLSearchParams(); p.set('page', page); p.set('limit', 20);
        ['filterDateFrom:dateFrom','filterDateTo:dateTo','filterScanType:scanType','filterStatus:status','filterTarget:target'].forEach(pair => {
            const [id, key] = pair.split(':'); const v = document.getElementById(id)?.value; if (v) p.set(key, v);
        });
        try {
            const d = await api(`/api/scan/history?${p.toString()}`); const scans = d.scans || [];
            loading.classList.add('hidden');
            if (scans.length === 0) { empty.classList.remove('hidden'); tbody.innerHTML = ''; }
            else { empty.classList.add('hidden'); tbody.innerHTML = scans.map(s => `<tr><td class="text-mono">#${s.id}</td><td class="text-mono">${esc(s.target)}</td><td>${scanTypeBadge(s.scan_type)}</td><td>${statusBadge(s.status)}</td><td>${s.result_count||0}</td><td>${fmtDate(s.started_at)}</td><td>${calcDuration(s.started_at,s.completed_at)}</td><td><div class="d-flex gap-1"><button class="btn btn-outline btn-sm" onclick="viewScanDetail(${s.id})"><i class="bi bi-eye"></i></button><button class="btn btn-outline btn-sm" onclick="window.open('/api/scan/export/${s.id}?format=csv','_blank')"><i class="bi bi-download"></i></button></div></td></tr>`).join(''); }
            renderPagination('historyPagination','historyPaginationBtns','historyPaginationInfo', d.pagination, loadHistory);
        } catch (e) { loading.classList.add('hidden'); showToast('error', 'Fehler', 'Historie nicht geladen'); }
    };

    // ============================================
    // Scan Detail
    // ============================================
    window.viewScanDetail = async function (scanId) {
        currentDetailScanId = scanId; switchView('scan-detail');
        try {
            const sd = await api(`/api/scan/status/${scanId}`), s = sd.scan;
            document.getElementById('scanDetailTitle').textContent = `Scan #${s.id}`;
            document.getElementById('detailId').textContent = `#${s.id}`; document.getElementById('detailTarget').textContent = s.target;
            document.getElementById('detailType').textContent = s.scan_type; document.getElementById('detailStatus').innerHTML = statusBadge(s.status);
            document.getElementById('detailStarted').textContent = fmtDate(s.started_at); document.getElementById('detailCompleted').textContent = s.completed_at ? fmtDate(s.completed_at) : 'N/A';
            await loadDetailResults(scanId, 1); await loadDetailVulnerabilities(scanId);
        } catch (e) { showToast('error', 'Fehler', 'Details nicht geladen'); }
    };

    async function loadDetailResults(scanId, page = 1) {
        try {
            const d = await api(`/api/scan/results/${scanId}?page=${page}&limit=50`), results = d.results || [];
            const tbody = document.getElementById('detailResultsBody'), empty = document.getElementById('detailResultsEmpty');
            if (results.length === 0 && page === 1) { empty.classList.remove('hidden'); tbody.innerHTML = ''; }
            else { empty.classList.add('hidden'); renderResultsTable(tbody, results); }
            const cr = results.filter(r => r.risk_level === 'critical').length, wr = results.filter(r => r.risk_level === 'warning').length, sf = results.filter(r => r.risk_level === 'safe').length;
            document.getElementById('detailSummary').innerHTML = `
                <div class="stat-card"><div class="stat-icon blue"><i class="bi bi-hdd-network"></i></div><div class="stat-info"><h4>Offene Ports</h4><div class="stat-value">${d.pagination?.total||results.length}</div></div></div>
                <div class="stat-card"><div class="stat-icon red"><i class="bi bi-shield-x"></i></div><div class="stat-info"><h4>Kritisch</h4><div class="stat-value">${cr}</div></div></div>
                <div class="stat-card"><div class="stat-icon yellow"><i class="bi bi-shield-exclamation"></i></div><div class="stat-info"><h4>Warnung</h4><div class="stat-value">${wr}</div></div></div>
                <div class="stat-card"><div class="stat-icon green"><i class="bi bi-shield-check"></i></div><div class="stat-info"><h4>Sicher</h4><div class="stat-value">${sf}</div></div></div>`;
            renderPagination('detailPagination','detailPaginationBtns','detailPaginationInfo', d.pagination, (p) => loadDetailResults(scanId, p));
        } catch (e) { showToast('error', 'Fehler', 'Ergebnisse nicht geladen'); }
    }

    async function loadDetailVulnerabilities(scanId) {
        try {
            const d = await api(`/api/vulnerabilities/scan/${scanId}`), vulns = d.vulnerabilities || [];
            const tbody = document.getElementById('detailVulnBody'), empty = document.getElementById('detailVulnEmpty');
            if (vulns.length === 0) { empty.classList.remove('hidden'); tbody.innerHTML = ''; }
            else { empty.classList.add('hidden'); tbody.innerHTML = vulns.map(v => `<tr><td class="text-mono">${esc(v.ip_address)}:${v.port}</td><td class="text-mono">${esc(v.cve_id||'N/A')}</td><td>${esc(v.title)}</td><td>${severityBadge(v.severity)}</td><td>${v.cvss_score||'N/A'}</td><td style="max-width:200px;font-size:.8rem">${esc(v.remediation||'-')}</td></tr>`).join(''); }
        } catch (e) { /* ignore */ }
    }

    // ============================================
    // Compare
    // ============================================
    window.compareScans = async function () {
        const s1 = document.getElementById('compareScan1').value, s2 = document.getElementById('compareScan2').value;
        if (!s1 || !s2) { showToast('error', 'Fehler', 'Zwei Scan-IDs eingeben'); return; }
        try {
            const d = await api(`/api/scan/compare?scan1=${s1}&scan2=${s2}`), c = d.comparison;
            document.getElementById('comparisonResults').classList.remove('hidden');
            document.getElementById('compareNew').textContent = c.newPorts; document.getElementById('compareClosed').textContent = c.closedPorts; document.getElementById('compareUnchanged').textContent = c.unchangedPorts;
            const nb = document.getElementById('compareNewBody'), rb = document.getElementById('compareRemovedBody');
            nb.innerHTML = c.onlyInScan2.length > 0 ? c.onlyInScan2.map(r => `<tr><td class="text-mono">${esc(r.ip_address)}</td><td>${r.port}</td><td>${esc(r.service||'?')}</td><td>${riskBadge(r.risk_level)}</td></tr>`).join('') : '<tr><td colspan="4" class="text-center text-muted">Keine</td></tr>';
            rb.innerHTML = c.onlyInScan1.length > 0 ? c.onlyInScan1.map(r => `<tr><td class="text-mono">${esc(r.ip_address)}</td><td>${r.port}</td><td>${esc(r.service||'?')}</td><td>${riskBadge(r.risk_level)}</td></tr>`).join('') : '<tr><td colspan="4" class="text-center text-muted">Keine</td></tr>';
            showToast('success', 'Vergleich', `${c.newPorts} neue, ${c.closedPorts} geschlossene Ports`);
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // Vulnerabilities
    // ============================================
    window.loadVulnerabilities = async function (page = 1) {
        const loading = document.getElementById('vulnLoading'), empty = document.getElementById('vulnEmpty'), tbody = document.getElementById('vulnTableBody');
        loading.classList.remove('hidden'); empty.classList.add('hidden');
        const p = new URLSearchParams(); p.set('page', page); p.set('limit', 50);
        const sev = document.getElementById('vulnFilterSeverity')?.value; if (sev) p.set('severity', sev);
        const svc = document.getElementById('vulnFilterService')?.value; if (svc) p.set('service', svc);
        const srch = document.getElementById('vulnFilterSearch')?.value; if (srch) p.set('search', srch);
        try {
            const d = await api(`/api/vulnerabilities?${p.toString()}`), vulns = d.vulnerabilities || [];
            loading.classList.add('hidden');
            if (vulns.length === 0) { empty.classList.remove('hidden'); tbody.innerHTML = ''; }
            else { empty.classList.add('hidden'); tbody.innerHTML = vulns.map(v => `<tr><td class="text-mono">${esc(v.cve_id||'N/A')}</td><td>${v.port}</td><td>${esc(v.service)}</td><td>${esc(v.title)}</td><td>${severityBadge(v.severity)}</td><td>${v.cvss_score||'N/A'}</td><td style="max-width:250px;font-size:.8rem">${esc(v.remediation||'-')}</td></tr>`).join(''); }
            renderPagination('vulnPagination','vulnPaginationBtns','vulnPaginationInfo', d.pagination, loadVulnerabilities);
        } catch (e) { loading.classList.add('hidden'); showToast('error', 'Fehler', 'Schwachstellen nicht geladen'); }
    };

    // ============================================
    // Scheduled Scans
    // ============================================
    window.loadSchedules = async function () {
        const loading = document.getElementById('schedulesLoading'), empty = document.getElementById('schedulesEmpty'), tbody = document.getElementById('schedulesTableBody');
        loading.classList.remove('hidden'); empty.classList.add('hidden');
        try {
            const d = await api('/api/schedules'), schedules = d.schedules || [];
            loading.classList.add('hidden');
            if (schedules.length === 0) { empty.classList.remove('hidden'); tbody.innerHTML = ''; }
            else { empty.classList.add('hidden'); tbody.innerHTML = schedules.map(s => `<tr>
                <td>${esc(s.name)}</td><td class="text-mono">${esc(s.target)}</td><td>${scanTypeBadge(s.scan_type)}</td>
                <td class="text-mono" style="font-size:.8rem">${esc(s.cron_expression)}</td>
                <td>${s.enabled ? '<span class="badge badge-safe">Aktiv</span>' : '<span class="badge badge-warning">Inaktiv</span>'}</td>
                <td>${s.last_run_at ? fmtDate(s.last_run_at) : 'Nie'}</td>
                <td><div class="d-flex gap-1">
                    <button class="btn btn-outline btn-sm" onclick="toggleSchedule(${s.id})" title="${s.enabled?'Deaktivieren':'Aktivieren'}"><i class="bi bi-${s.enabled?'pause':'play'}"></i></button>
                    <button class="btn btn-outline btn-sm" onclick="editSchedule(${s.id})" title="Bearbeiten"><i class="bi bi-pencil"></i></button>
                    <button class="btn btn-outline btn-sm" onclick="deleteSchedule(${s.id})" title="Löschen"><i class="bi bi-trash"></i></button>
                </div></td></tr>`).join(''); }
            // Load presets
            try { const pr = await api('/api/schedules/presets'); const sel = document.getElementById('schedulePreset');
                if (sel && sel.options.length <= 1) { pr.presets.forEach(p => { const o = document.createElement('option'); o.value = p.value; o.textContent = `${p.label} - ${p.description}`; sel.appendChild(o); }); }
            } catch (e) {}
        } catch (e) { loading.classList.add('hidden'); showToast('error', 'Fehler', 'Zeitpläne nicht geladen'); }
    };

    window.showScheduleModal = function (data) {
        document.getElementById('scheduleModal').classList.remove('hidden');
        document.getElementById('scheduleModalTitle').textContent = data ? 'Geplanten Scan bearbeiten' : 'Neuer geplanter Scan';
        document.getElementById('scheduleEditId').value = data?.id || '';
        document.getElementById('scheduleName').value = data?.name || '';
        document.getElementById('scheduleTarget').value = data?.target || '';
        document.getElementById('scheduleScanType').value = data?.scan_type || 'standard';
        document.getElementById('scheduleCron').value = data?.cron_expression || '';
        document.getElementById('scheduleNotifyComplete').checked = data ? data.notify_on_complete === 1 : true;
        document.getElementById('scheduleNotifyCritical').checked = data ? data.notify_on_critical === 1 : true;
    };
    window.hideScheduleModal = () => document.getElementById('scheduleModal').classList.add('hidden');
    window.applyCronPreset = function () { const v = document.getElementById('schedulePreset').value; if (v) document.getElementById('scheduleCron').value = v; };

    window.saveSchedule = async function () {
        const id = document.getElementById('scheduleEditId').value;
        const body = { name: document.getElementById('scheduleName').value, target: document.getElementById('scheduleTarget').value,
            scanType: document.getElementById('scheduleScanType').value, cronExpression: document.getElementById('scheduleCron').value,
            notifyOnComplete: document.getElementById('scheduleNotifyComplete').checked, notifyOnCritical: document.getElementById('scheduleNotifyCritical').checked, enabled: true };
        if (!body.name || !body.target || !body.cronExpression) { showToast('error', 'Fehler', 'Alle Pflichtfelder ausfüllen'); return; }
        try {
            if (id) await api(`/api/schedules/${id}`, 'PUT', body); else await api('/api/schedules', 'POST', body);
            showToast('success', 'Erfolg', id ? 'Zeitplan aktualisiert' : 'Zeitplan erstellt'); hideScheduleModal(); loadSchedules();
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.editSchedule = async function (id) {
        try { const d = await api(`/api/schedules/${id}`); showScheduleModal(d.schedule); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.toggleSchedule = async function (id) {
        try { const d = await api(`/api/schedules/${id}/toggle`, 'POST'); showToast('success', 'Erfolg', d.message); loadSchedules(); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.deleteSchedule = async function (id) {
        if (!confirm('Geplanten Scan wirklich löschen?')) return;
        try { await api(`/api/schedules/${id}`, 'DELETE'); showToast('success', 'Gelöscht', 'Zeitplan entfernt'); loadSchedules(); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // User Management
    // ============================================
    let availableRoles = [];
    window.loadUsers = async function () {
        const loading = document.getElementById('usersLoading'), tbody = document.getElementById('usersTableBody');
        loading.classList.remove('hidden');
        try {
            const [ud, rd] = await Promise.all([api('/api/users'), api('/api/users/roles')]);
            availableRoles = rd.roles || []; loading.classList.add('hidden');
            tbody.innerHTML = (ud.users || []).map(u => `<tr>
                <td class="text-mono">#${u.id}</td><td>${esc(u.username)}</td>
                <td>${(u.roles||[]).map(r => `<span class="badge badge-info">${esc(r)}</span>`).join(' ')}</td>
                <td>${fmtDate(u.created_at)}</td><td>${u.last_login ? fmtDate(u.last_login) : 'Nie'}</td>
                <td><div class="d-flex gap-1">
                    <button class="btn btn-outline btn-sm" onclick="editUser(${u.id},'${esc(u.username)}',${JSON.stringify(u.roles).replace(/"/g,'&quot;')})"><i class="bi bi-pencil"></i></button>
                    ${u.id !== 1 ? `<button class="btn btn-outline btn-sm" onclick="deleteUser(${u.id},'${esc(u.username)}')"><i class="bi bi-trash"></i></button>` : ''}
                </div></td></tr>`).join('');
        } catch (e) { loading.classList.add('hidden'); showToast('error', 'Fehler', e.message); }
    };

    window.showUserModal = function (data) {
        document.getElementById('userModal').classList.remove('hidden');
        document.getElementById('userModalTitle').textContent = data ? 'Benutzer bearbeiten' : 'Neuer Benutzer';
        document.getElementById('userEditId').value = data?.id || '';
        document.getElementById('userFormName').value = data?.username || '';
        document.getElementById('userFormName').disabled = !!data;
        document.getElementById('userFormPass').value = '';
        document.getElementById('userFormPass').required = !data;
        document.getElementById('userFormPass').placeholder = data ? 'Leer lassen = nicht ändern' : 'Mindestens 8 Zeichen';
        const rc = document.getElementById('userRoleCheckboxes');
        rc.innerHTML = availableRoles.map(r => `<label class="d-flex align-center gap-1 mb-1"><input type="checkbox" name="userRole" value="${esc(r.name)}" ${data?.roles?.includes(r.name)?'checked':''}> ${esc(r.name)} <small class="text-muted">(${esc(r.description||'')})</small></label>`).join('');
    };
    window.hideUserModal = () => document.getElementById('userModal').classList.add('hidden');

    window.editUser = function (id, username, roles) { showUserModal({ id, username, roles }); };

    window.saveUser = async function () {
        const id = document.getElementById('userEditId').value;
        const username = document.getElementById('userFormName').value, password = document.getElementById('userFormPass').value;
        const roles = Array.from(document.querySelectorAll('input[name="userRole"]:checked')).map(c => c.value);
        if (!id && (!username || !password)) { showToast('error', 'Fehler', 'Benutzername und Passwort erforderlich'); return; }
        try {
            if (id) { const body = { roles }; if (password) body.password = password; await api(`/api/users/${id}`, 'PUT', body); }
            else await api('/api/users', 'POST', { username, password, roles });
            showToast('success', 'Erfolg', id ? 'Benutzer aktualisiert' : 'Benutzer erstellt'); hideUserModal(); loadUsers();
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.deleteUser = async function (id, username) {
        if (!confirm(`Benutzer "${username}" wirklich löschen?`)) return;
        try { await api(`/api/users/${id}`, 'DELETE'); showToast('success', 'Gelöscht', `Benutzer "${username}" entfernt`); loadUsers(); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // Notifications
    // ============================================
    window.loadNotificationSettings = async function () {
        try {
            const d = await api('/api/notifications/settings'), s = d.settings;
            document.getElementById('emailEnabled').checked = s.emailEnabled;
            document.getElementById('notifEmail').value = s.emailAddress || '';
            document.getElementById('smtpHost').value = s.smtpHost || '';
            document.getElementById('smtpPort').value = s.smtpPort || 587;
            document.getElementById('smtpSecure').checked = s.smtpSecure;
            document.getElementById('smtpUser').value = s.smtpUser || '';
            document.getElementById('smtpPass').value = '';
            document.getElementById('smtpPass').placeholder = s.smtpPassSet ? '••••••• (gesetzt)' : 'Passwort';
            document.getElementById('notifScanComplete').checked = s.notifyScanComplete;
            document.getElementById('notifCritical').checked = s.notifyCriticalFound;
            document.getElementById('notifScheduled').checked = s.notifyScheduledReport;
            toggleEmailFields();
        } catch (e) { /* ignore */ }
    };

    window.toggleEmailFields = function () {
        const enabled = document.getElementById('emailEnabled').checked;
        document.getElementById('emailFields').style.opacity = enabled ? '1' : '0.4';
        document.getElementById('emailFields').style.pointerEvents = enabled ? 'auto' : 'none';
    };

    window.saveNotificationSettings = async function (e) {
        e.preventDefault();
        try {
            await api('/api/notifications/settings', 'POST', {
                emailEnabled: document.getElementById('emailEnabled').checked,
                emailAddress: document.getElementById('notifEmail').value,
                smtpHost: document.getElementById('smtpHost').value,
                smtpPort: parseInt(document.getElementById('smtpPort').value) || 587,
                smtpSecure: document.getElementById('smtpSecure').checked,
                smtpUser: document.getElementById('smtpUser').value,
                smtpPass: document.getElementById('smtpPass').value || null,
                notifyScanComplete: document.getElementById('notifScanComplete').checked,
                notifyCriticalFound: document.getElementById('notifCritical').checked,
                notifyScheduledReport: document.getElementById('notifScheduled').checked
            });
            showToast('success', 'Gespeichert', 'Benachrichtigungseinstellungen aktualisiert');
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.testEmail = async function () {
        try { const d = await api('/api/notifications/test', 'POST'); showToast('success', 'Gesendet', d.message); }
        catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // Rendering Helpers
    // ============================================
    function renderResultsTable(tbody, results) {
        tbody.innerHTML = results.map(r => `<tr><td class="text-mono">${esc(r.ip_address)}</td><td class="text-mono">${r.port}</td><td>${esc(r.protocol||'tcp')}</td><td>${esc(r.service||'Unknown')}</td><td>${esc(r.state||'open')}</td><td>${riskBadge(r.risk_level)}</td></tr>`).join('');
    }

    function renderPagination(cId, bId, iId, pg, cb) {
        const c = document.getElementById(cId), b = document.getElementById(bId), i = document.getElementById(iId);
        if (!pg || pg.totalPages <= 1) { c.classList.add('hidden'); return; }
        c.classList.remove('hidden');
        const { page, totalPages, total, limit } = pg;
        let h = `<button class="page-btn" ${page<=1?'disabled':''} onclick="(${cb.toString()})(${page-1})"><i class="bi bi-chevron-left"></i></button>`;
        const s = Math.max(1, page-2), e = Math.min(totalPages, page+2);
        if (s > 1) { h += `<button class="page-btn" onclick="(${cb.toString()})(1)">1</button>`; if (s > 2) h += '<span class="text-muted" style="padding:0 .25rem">...</span>'; }
        for (let x = s; x <= e; x++) h += `<button class="page-btn ${x===page?'active':''}" onclick="(${cb.toString()})(${x})">${x}</button>`;
        if (e < totalPages) { if (e < totalPages-1) h += '<span class="text-muted" style="padding:0 .25rem">...</span>'; h += `<button class="page-btn" onclick="(${cb.toString()})(${totalPages})">${totalPages}</button>`; }
        h += `<button class="page-btn" ${page>=totalPages?'disabled':''} onclick="(${cb.toString()})(${page+1})"><i class="bi bi-chevron-right"></i></button>`;
        b.innerHTML = h;
        const from = (page-1)*limit+1, to = Math.min(page*limit, total);
        i.textContent = `Zeige ${from}-${to} von ${total}`;
    }

    function esc(t) { if (!t) return ''; const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
    function scanTypeBadge(t) { return `<span class="badge badge-info">${t}</span>`; }
    function statusBadge(s) { const m = { pending:'<span class="badge badge-status badge-info">Wartend</span>', running:'<span class="badge badge-status badge-running"><i class="bi bi-broadcast"></i> Läuft</span>', completed:'<span class="badge badge-status badge-completed"><i class="bi bi-check-circle"></i> Fertig</span>', failed:'<span class="badge badge-status badge-failed"><i class="bi bi-x-circle"></i> Fehler</span>', aborted:'<span class="badge badge-status badge-aborted"><i class="bi bi-stop-circle"></i> Abbruch</span>' }; return m[s]||s; }
    function riskBadge(r) { const m = { safe:'<span class="badge badge-safe"><i class="bi bi-shield-check"></i> Sicher</span>', warning:'<span class="badge badge-warning"><i class="bi bi-shield-exclamation"></i> Warnung</span>', critical:'<span class="badge badge-critical"><i class="bi bi-shield-x"></i> Kritisch</span>', info:'<span class="badge badge-info"><i class="bi bi-info-circle"></i> Info</span>' }; return m[r]||r; }
    function severityBadge(s) { const m = { critical:'<span class="badge badge-critical">Kritisch</span>', high:'<span class="badge badge-critical">Hoch</span>', medium:'<span class="badge badge-warning">Mittel</span>', low:'<span class="badge badge-safe">Niedrig</span>' }; return m[s]||s; }
    function fmtDate(d) { if (!d) return 'N/A'; return new Date(d).toLocaleString('de-DE',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}); }
    function calcDuration(s, e) { if (!s||!e) return '-'; const d = Math.abs(new Date(e)-new Date(s))/1000; if (d<60) return `${Math.round(d)}s`; if (d<3600) return `${Math.floor(d/60)}m ${Math.round(d%60)}s`; return `${Math.floor(d/3600)}h ${Math.floor((d%3600)/60)}m`; }

    let debounceTimers = {};
    window.debounce = function (fn, delay) { return function (...args) { const k = fn.toString(); clearTimeout(debounceTimers[k]); debounceTimers[k] = setTimeout(() => fn.apply(this, args), delay); }; };

    // Init
    checkAuth();
    window.addEventListener('beforeunload', () => { if (eventSource) eventSource.close(); });
})();