// ============================================
// SecureScope - Dashboard JavaScript (Complete)
// ============================================
(function () {
    'use strict';

    // Global State
    let csrfToken = null, currentUser = null, currentScanId = null;
    let currentDetailScanId = null, eventSource = null, previousView = 'dashboard';
    let userRoles = [], userPermissions = [];
    let currentShellWs = null, currentTerm = null, fitAddon = null;
    let currentChainExecId = null;

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
            try {
                const perms = await api('/api/users/me/permissions');
                userRoles = perms.roles || []; userPermissions = perms.permissions || [];
                document.getElementById('sidebarRole').textContent = userRoles.join(', ') || 'Benutzer';
                if (!userRoles.includes('admin')) {
                    const adminItems = document.querySelectorAll('[data-view="users"]');
                    adminItems.forEach(el => el.style.display = 'none');
                }
            } catch (e) { /* ignore */ }
            loadDashboard(); connectSSE();
        } catch (e) { window.location.href = '/'; }
    }

    window.logout = async function () { try { await api('/api/auth/logout', 'POST'); } catch (e) {} window.location.href = '/'; };

    // ============================================
    // SSE (Server-Sent Events)
    // ============================================
    function connectSSE() {
        if (eventSource) eventSource.close();
        eventSource = new EventSource('/api/scan/events');
        eventSource.onmessage = (e) => {
            try {
                const data = JSON.parse(e.data);
                if (data.type === 'scan_progress') updateScanProgress(data);
                else if (data.type === 'scan_complete') handleScanComplete(data);
                else if (data.type === 'scan_error') handleScanError(data);
                else if (data.type === 'chain_progress') handleChainProgress(data);
                else if (data.type === 'chain_complete') handleChainComplete(data);
                else if (data.type === 'chain_error') handleChainError(data);
            } catch (err) {}
        };
        eventSource.onerror = () => { setTimeout(connectSSE, 5000); };
    }

    function updateScanProgress(data) {
        const bar = document.getElementById('scanProgressBar');
        const pct = document.getElementById('scanProgressPercent');
        const info = document.getElementById('scanProgressInfo');
        if (bar) bar.style.width = data.progress + '%';
        if (pct) pct.textContent = data.progress + '%';
        if (info) info.textContent = data.message || `Scan läuft... ${data.progress}%`;
        // Active scan panel on dashboard
        const aBar = document.getElementById('activeScanProgress');
        const aPct = document.getElementById('activeScanProgressText');
        if (aBar) aBar.style.width = data.progress + '%';
        if (aPct) aPct.textContent = data.progress + '%';
    }

    function handleScanComplete(data) {
        showToast('success', 'Scan abgeschlossen', `Scan #${data.scanId} wurde erfolgreich abgeschlossen.`);
        const panel = document.getElementById('scanProgressPanel');
        if (panel) panel.classList.add('hidden');
        if (data.scanId === currentScanId) loadScanResults(data.scanId);
        loadDashboard();
    }

    function handleScanError(data) {
        showToast('error', 'Scan-Fehler', data.message || 'Ein Fehler ist aufgetreten.');
        const panel = document.getElementById('scanProgressPanel');
        if (panel) panel.classList.add('hidden');
    }

    function handleChainProgress(data) {
        // If the modal is open for this chain, update it
        if (currentChainExecId && currentChainExecId === data.executionId) {
            // Update status badge
            const modal = document.getElementById('chainExecDetailModal');
            if (modal.classList.contains('active')) {
                // Ideally we just reload the content or append logs.
                // For smoother UX, let's just reload the detail view
                // Debounce to prevent flickering if updates are fast
                // But for now, direct update is fine
                showChainExecDetail(data.executionId);
            }
        }
    }

    function handleChainComplete(data) {
        showToast('success', 'Attack Chain abgeschlossen', `Execution #${data.executionId} completed. ${data.findingsCount} findings.`);
        if (currentChainExecId === data.executionId) {
            showChainExecDetail(data.executionId);
        }
        loadChainStats();
        loadChainExecutions();
    }

    function handleChainError(data) {
        showToast('error', 'Attack Chain Fehler', data.error || 'Unknown error');
        if (currentChainExecId === data.executionId) {
            showChainExecDetail(data.executionId);
        }
    }

    // ============================================
    // View Switching
    // ============================================
    window.switchView = function (view) {
        previousView = document.querySelector('.nav-item.active')?.dataset?.view || 'dashboard';
        document.querySelectorAll('.view-section').forEach(s => s.classList.remove('active'));
        document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
        const section = document.getElementById('view-' + view);
        if (section) section.classList.add('active');
        const navItem = document.querySelector(`.nav-item[data-view="${view}"]`);
        if (navItem) navItem.classList.add('active');

        const titles = {
            'dashboard': 'Dashboard', 'new-scan': 'Neuer Scan', 'history': 'Scan-Historie',
            'compare': 'Scan-Vergleich', 'vulnerabilities': 'Schwachstellen',
            'fingerprints': 'Fingerprinting & Service-Erkennung', 'exploits': 'Exploit-Datenbank',
            'attack-chains': 'Angriffsketten', 'audits': 'Security-Audit',
            'credentials': 'Credential-Verwaltung', 'schedules': 'Geplante Scans',
            'users': 'Benutzerverwaltung', 'notifications': 'Benachrichtigungen',
            'scan-detail': 'Scan-Details'
        };
        const titleEl = document.getElementById('viewTitle');
        if (titleEl) {
            titleEl.textContent = titles[view] || 'SecureScope';
            titleEl.setAttribute('tabindex', '-1');
            titleEl.focus();
        }

        // Load data for views
        switch (view) {
            case 'dashboard': loadDashboard(); break;
            case 'history': loadHistory(); break;
            // case 'vulnerabilities': loadVulnerabilities(); break; // Removed - redundant to CVE section
            case 'schedules': loadSchedules(); break;
            case 'users': loadUsers(); break;
            case 'notifications': loadNotifications(); break;
            case 'fingerprints': loadFingerprints(); loadFingerprintStats(); break;
            case 'exploits': loadExploits(); loadExploitStats(); break;
            case 'cve': loadCVEs(); loadCVEStats(); break;
            case 'attack-chains': loadAttackChains(); loadChainStats(); break;
            case 'audits': loadAuditHistory(); break;
            case 'credentials': loadCredentials(); loadCredentialStats(); break;
            case 'compare': loadCompareScans(); break;
        }
    };

    // ============================================
    // Utility Functions
    // ============================================
    function esc(str) { const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }

    // Debounce helper
    let _debounceTimers = {};
    window.debounce = function(fn, delay) {
        return function() {
            const key = fn.name || 'default';
            clearTimeout(_debounceTimers[key]);
            _debounceTimers[key] = setTimeout(() => { if (typeof fn === 'function') fn(); else if (typeof window[fn] === 'function') window[fn](); }, delay);
        };
    };
    function formatDate(d) { if (!d) return '-'; return new Date(d).toLocaleString('de-DE', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' }); }
    function severityBadge(s) {
        const colors = { critical:'red', high:'orange', medium:'yellow', low:'blue', info:'gray' };
        return `<span class="badge badge-${colors[s] || 'gray'}">${esc(s || 'info')}</span>`;
    }
    function riskBadge(r) { return severityBadge(r); }
    function statusBadge(s) {
        const colors = { completed:'green', running:'blue', pending:'yellow', failed:'red', cancelled:'gray', started: 'blue' };
        const labels = { completed:'Abgeschlossen', running:'Läuft', pending:'Wartend', failed:'Fehlgeschlagen', cancelled:'Abgebrochen', started: 'Gestartet' };
        return `<span class="badge badge-${colors[s] || 'gray'}">${labels[s] || s}</span>`;
    }
    function confidenceBar(val) {
        const color = val >= 80 ? 'var(--accent-green)' : val >= 60 ? 'var(--accent-yellow)' : 'var(--accent-red)';
        return `<div class="confidence-bar-container"><div class="confidence-bar" style="width:${val}%;background:${color}"></div><span class="confidence-text">${val}%</span></div>`;
    }

    // ============================================
    // Dashboard
    // ============================================
    async function loadDashboard() {
        try {
            const d = await api('/api/scan/dashboard');
            document.getElementById('statTotalScans').textContent = d.totalScans || 0;
            document.getElementById('statCompleted').textContent = d.completedScans || 0;
            document.getElementById('statCritical').textContent = d.criticalPorts || 0;
            document.getElementById('statVulns').textContent = d.totalVulnerabilities || 0;
            document.getElementById('statActive').textContent = d.activeScans || 0;

            // Active scan panel
            const activePanel = document.getElementById('activeScanPanel');
            if (d.activeScans > 0 && d.activeScan) {
                activePanel.classList.remove('hidden');
                document.getElementById('activeScanInfo').textContent = `Scan #${d.activeScan.id} - ${d.activeScan.target}`;
                document.getElementById('activeScanTarget').textContent = d.activeScan.target;
                document.getElementById('activeScanProgress').style.width = (d.activeScan.progress || 0) + '%';
                document.getElementById('activeScanProgressText').textContent = (d.activeScan.progress || 0) + '%';
            } else {
                activePanel.classList.add('hidden');
            }

            // Recent scans
            const tbody = document.getElementById('recentScansTableBody');
            const table = document.getElementById('recentScansTable');
            const empty = document.getElementById('recentScansEmpty');
            const loading = document.getElementById('recentScansLoading');
            loading.classList.add('hidden');

            if (d.recentScans && d.recentScans.length > 0) {
                table.classList.remove('hidden');
                empty.classList.add('hidden');
                tbody.innerHTML = d.recentScans.map(s => `<tr>
                    <td>#${s.id}</td><td>${esc(s.target)}</td><td><span class="badge badge-blue">${esc(s.scan_type)}</span></td>
                    <td>${statusBadge(s.status)}</td><td>${s.result_count || 0}</td><td>${s.vuln_count || 0}</td>
                    <td>${formatDate(s.started_at)}</td>
                    <td><button class="btn btn-outline btn-sm" onclick="viewScanDetail(${s.id})"><i class="bi bi-eye"></i></button></td>
                </tr>`).join('');
            } else {
                table.classList.add('hidden');
                empty.classList.remove('hidden');
            }
        } catch (e) {
            document.getElementById('recentScansLoading').classList.add('hidden');
            document.getElementById('recentScansEmpty').classList.remove('hidden');
        }
    }

    // ============================================
    // Scan Operations
    // ============================================
    window.startScan = async function (e) {
        if (e && e.preventDefault) e.preventDefault();
        const target = document.getElementById('scanTarget').value.trim();
        const scanType = document.getElementById('scanType').value;
        let portRange = null;
        if (scanType === 'custom') portRange = document.getElementById('customPorts').value.trim();
        if (!target) { showToast('error', 'Fehler', 'Bitte Ziel-IP eingeben'); return; }

        const btn = document.getElementById('startScanBtn');
        const spinner = document.getElementById('startScanSpinner');
        const btnText = document.getElementById('startScanBtnText');
        btn.disabled = true; spinner.classList.remove('hidden'); btnText.textContent = 'Wird gestartet...';

        try {
            const d = await api('/api/scan/start', 'POST', { target, scanType, portRange });
            currentScanId = d.scanId;
            showToast('success', 'Scan gestartet', `Scan #${d.scanId} für ${target}`);
            document.getElementById('scanProgressPanel').classList.remove('hidden');
            document.getElementById('scanResultsPanel').classList.add('hidden');
        } catch (e) {
            showToast('error', 'Fehler', e.message);
        } finally {
            btn.disabled = false; spinner.classList.add('hidden'); btnText.textContent = 'Scan starten';
        }
    };

    window.stopCurrentScan = async function () {
        if (!currentScanId) return;
        try { await api(`/api/scan/${currentScanId}/stop`, 'POST'); showToast('info', 'Scan gestoppt', 'Der Scan wurde abgebrochen.'); document.getElementById('scanProgressPanel').classList.add('hidden'); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.stopActiveScan = async function () {
        try {
            const d = await api('/api/scan/dashboard');
            if (d.activeScan) { await api(`/api/scan/${d.activeScan.id}/stop`, 'POST'); showToast('info', 'Scan gestoppt', 'Aktiver Scan wurde abgebrochen.'); loadDashboard(); }
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.toggleCustomPorts = function () {
        const g = document.getElementById('customPortsGroup');
        g.classList.toggle('hidden', document.getElementById('scanType').value !== 'custom');
    };

    async function loadScanResults(scanId) {
        try {
            const d = await api(`/api/scan/results/${scanId}`);
            document.getElementById('scanResultsPanel').classList.remove('hidden');
            const results = d.results || [];
            document.getElementById('resultTotal').textContent = results.length;
            document.getElementById('resultCritical').textContent = results.filter(r => r.risk_level === 'critical').length;
            document.getElementById('resultWarning').textContent = results.filter(r => r.risk_level === 'high' || r.risk_level === 'medium').length;
            document.getElementById('resultSafe').textContent = results.filter(r => r.risk_level === 'info' || r.risk_level === 'low').length;

            const tbody = document.getElementById('resultsTableBody');
            if (results.length > 0) {
                document.getElementById('resultsEmpty').classList.add('hidden');

                // Group by IP
                const grouped = {};
                results.forEach(r => {
                    if (!grouped[r.ip_address]) grouped[r.ip_address] = [];
                    grouped[r.ip_address].push(r);
                });

                let html = '';
                for (const [ip, ports] of Object.entries(grouped)) {
                    // Find first OS info
                    const osInfo = ports.find(p => p.os_name)?.os_name || 'Unbekannt';

                    html += `<tr style="background:var(--bg-tertiary);border-bottom:1px solid var(--border-color)">
                        <td colspan="6" style="padding:0.75rem 1rem">
                            <div class="d-flex justify-between align-center">
                                <div>
                                    <strong style="font-size:1rem">${esc(ip)}</strong>
                                    <span class="text-muted ml-2" style="font-size:0.85rem">OS: ${esc(osInfo)}</span>
                                </div>
                                <button class="btn btn-outline btn-sm" onclick="showCreateChainForTargetModal(${scanId}, '${esc(ip)}')">
                                    <i class="bi bi-diagram-3"></i> Chain erstellen
                                </button>
                                <button class="btn btn-danger btn-sm" onclick="showAutoAttackModal(${scanId}, '${esc(ip)}')">
                                    <i class="bi bi-lightning-charge-fill"></i> Angriff starten
                                </button>
                            </div>
                        </td>
                    </tr>`;

                    html += ports.map(r => {
                        let svcInfo = esc(r.service || '-');
                        if (r.banner) {
                            svcInfo = `<strong>${esc(r.service || '-')}</strong><br><span style="font-size:.8rem;color:var(--text-secondary)">${esc(r.banner)}</span>`;
                        } else if (r.service_product) {
                            let ver = r.service_product;
                            if (r.service_version) ver += ' ' + r.service_version;
                            svcInfo = `<strong>${esc(r.service || '-')}</strong><br><span style="font-size:.8rem;color:var(--text-secondary)">${esc(ver)}</span>`;
                        }
                        return `<tr>
                        <td style="padding-left:2rem">${esc(r.ip_address)}</td><td>${r.port}</td><td>${esc(r.protocol)}</td>
                        <td>${svcInfo}</td><td><span class="badge badge-green">offen</span></td>
                        <td>${riskBadge(r.risk_level)}</td>
                    </tr>`;
                    }).join('');
                }
                tbody.innerHTML = html;
            } else {
                document.getElementById('resultsEmpty').classList.remove('hidden');
                tbody.innerHTML = '';
            }

            // Load CVE matches for this scan (from Nmap service detection)
            try {
                const v = await api(`/api/scan/cves/${scanId}`);
                const vtbody = document.getElementById('scanVulnTableBody');
                const vempty = document.getElementById('scanVulnEmpty');
                const cves = v.cves || [];
                if (cves.length > 0) {
                    vempty.classList.add('hidden');
                    vtbody.innerHTML = cves.map(vl => `<tr>
                        <td>${esc(vl.ip_address || '')}:${vl.port || ''}</td>
                        <td><a href="https://nvd.nist.gov/vuln/detail/${esc(vl.cve_id)}" target="_blank" style="color:var(--accent-blue)">${esc(vl.cve_id)}</a></td>
                        <td>${esc(vl.title || '-')}</td>
                        <td>${esc(vl.matched_service || '-')}${vl.matched_version ? ' ' + esc(vl.matched_version) : ''}</td>
                        <td>${severityBadge(vl.severity)}</td>
                        <td>${vl.cvss_score || '-'}</td>
                        <td><span class="badge badge-${vl.match_confidence >= 80 ? 'green' : vl.match_confidence >= 50 ? 'yellow' : 'gray'}">${vl.match_confidence}%</span></td>
                    </tr>`).join('');
                } else {
                    vempty.classList.remove('hidden');
                    vtbody.innerHTML = '';
                }
            } catch (e) { console.error('CVE load error:', e); }
        } catch (e) { showToast('error', 'Fehler', e.message); }
    }

    // ============================================
    // Scan Detail
    // ============================================
    window.viewScanDetail = async function (scanId) {
        currentDetailScanId = scanId;
        switchView('scan-detail');
        try {
            const d = await api(`/api/scan/${scanId}`);
            const s = d.scan;
            document.getElementById('detailId').textContent = '#' + s.id;
            document.getElementById('detailTarget').textContent = s.target;
            document.getElementById('detailType').innerHTML = `<span class="badge badge-blue">${esc(s.scan_type)}</span>`;
            document.getElementById('detailStatus').innerHTML = statusBadge(s.status);
            document.getElementById('detailStarted').textContent = formatDate(s.started_at);
            document.getElementById('detailCompleted').textContent = formatDate(s.completed_at);

            // Results
            const results = d.results || [];
            const tbody = document.getElementById('detailResultsBody');
            if (results.length > 0) {
                // Group by IP
                const grouped = {};
                results.forEach(r => {
                    if (!grouped[r.ip_address]) grouped[r.ip_address] = [];
                    grouped[r.ip_address].push(r);
                });

                let html = '';
                for (const [ip, ports] of Object.entries(grouped)) {
                    // Find first OS info
                    const osInfo = ports.find(p => p.os_name)?.os_name || 'Unbekannt';

                    html += `<tr style="background:var(--bg-tertiary);border-bottom:1px solid var(--border-color)">
                        <td colspan="6" style="padding:0.75rem 1rem">
                            <div class="d-flex justify-between align-center">
                                <div>
                                    <strong style="font-size:1rem">${esc(ip)}</strong>
                                    <span class="text-muted ml-2" style="font-size:0.85rem">OS: ${esc(osInfo)}</span>
                                </div>
                                <button class="btn btn-outline btn-sm" onclick="showCreateChainForTargetModal(${scanId}, '${esc(ip)}')">
                                    <i class="bi bi-diagram-3"></i> Chain erstellen
                                </button>
                                <button class="btn btn-danger btn-sm" onclick="showAutoAttackModal(${scanId}, '${esc(ip)}')">
                                    <i class="bi bi-lightning-charge-fill"></i> Angriff starten
                                </button>
                            </div>
                        </td>
                    </tr>`;

                    html += ports.map(r => {
                        let svcInfo = esc(r.service || '-');
                        if (r.banner) {
                            svcInfo = `<strong>${esc(r.service || '-')}</strong><br><span style="font-size:.8rem;color:var(--text-secondary);display:inline-block;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(r.banner)}">${esc(r.banner)}</span>`;
                        } else if (r.service_product) {
                            let ver = r.service_product;
                            if (r.service_version) ver += ' ' + r.service_version;
                            svcInfo = `<strong>${esc(r.service || '-')}</strong><br><span style="font-size:.8rem;color:var(--text-secondary)">${esc(ver)}</span>`;
                        }

                        return `<tr>
                        <td style="padding-left:2rem">${esc(r.ip_address)}</td><td>${r.port}</td><td>${esc(r.protocol)}</td>
                        <td>${svcInfo}</td><td><span class="badge badge-green">offen</span></td>
                        <td>${riskBadge(r.risk_level)}</td>
                    </tr>`;
                    }).join('');
                }
                tbody.innerHTML = html;
            } else {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Keine Ergebnisse</td></tr>';
            }

            // CVE Matches from Nmap service detection
            try {
                const v = await api(`/api/scan/cves/${scanId}`);
                const vtbody = document.getElementById('detailVulnBody');
                const cves = v.cves || [];
                if (cves.length > 0) {
                    vtbody.innerHTML = cves.map(vl => `<tr>
                        <td>${esc(vl.ip_address || '')}:${vl.port || ''}</td>
                        <td><a href="https://nvd.nist.gov/vuln/detail/${esc(vl.cve_id)}" target="_blank" style="color:var(--accent-blue)">${esc(vl.cve_id)}</a></td>
                        <td>${esc(vl.title || '-')}</td>
                        <td>${esc(vl.matched_service || '-')}${vl.matched_version ? ' ' + esc(vl.matched_version) : ''}</td>
                        <td>${severityBadge(vl.severity)}</td>
                        <td>${vl.cvss_score || '-'}</td>
                        <td><span class="badge badge-${vl.match_confidence >= 80 ? 'green' : vl.match_confidence >= 50 ? 'yellow' : 'gray'}">${vl.match_confidence}%</span></td>
                    </tr>`).join('');
                } else {
                    vtbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">Keine CVE-Matches</td></tr>';
                }
            } catch (e) { console.error('Detail CVE load error:', e); }
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.goBackFromDetail = function () { switchView(previousView || 'dashboard'); };

    // ============================================
    // History
    // ============================================
    async function loadHistory() {
        try {
            const d = await api('/api/scan/history');
            const tbody = document.getElementById('historyTableBody');
            const empty = document.getElementById('historyEmpty');
            if (d.scans && d.scans.length > 0) {
                empty.classList.add('hidden');
                tbody.parentElement.parentElement.classList.remove('hidden');
                tbody.innerHTML = d.scans.map(s => `<tr>
                    <td>#${s.id}</td><td>${esc(s.target)}</td><td><span class="badge badge-blue">${esc(s.scan_type)}</span></td>
                    <td>${statusBadge(s.status)}</td><td>${s.result_count || 0}</td><td>${s.vuln_count || 0}</td>
                    <td>${formatDate(s.started_at)}</td>
                    <td><div class="d-flex gap-1"><button class="btn btn-outline btn-sm" onclick="viewScanDetail(${s.id})"><i class="bi bi-eye"></i></button>
                    <button class="btn btn-danger btn-sm" onclick="deleteScan(${s.id})"><i class="bi bi-trash"></i></button></div></td>
                </tr>`).join('');
            } else {
                empty.classList.remove('hidden');
            }
        } catch (e) { showToast('error', 'Fehler', e.message); }
    }

    window.deleteScan = async function (id) {
        if (!confirm('Scan wirklich löschen?')) return;
        try { await api(`/api/scan/${id}`, 'DELETE'); showToast('success', 'Gelöscht', 'Scan wurde gelöscht.'); loadHistory(); loadDashboard(); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // Vulnerabilities
    // ============================================
    async function loadVulnerabilities() {
        try {
            const d = await api('/api/vulnerabilities');
            const tbody = document.getElementById('vulnTableBody');
            const vulns = d.vulnerabilities || d || [];
            if (vulns.length > 0) {
                tbody.innerHTML = vulns.map(v => `<tr>
                    <td>${esc(v.cve_id || '-')}</td><td>${esc(v.title)}</td><td>${v.port || '-'}</td>
                    <td>${esc(v.service || '-')}</td><td>${severityBadge(v.severity)}</td><td>${v.cvss_score || '-'}</td>
                </tr>`).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Keine Schwachstellen in der Datenbank</td></tr>';
            }
        } catch (e) { showToast('error', 'Fehler', e.message); }
    }

    // ============================================
    // Compare
    // ============================================
    async function loadCompareScans() {
        try {
            const d = await api('/api/scan/history');
            const s1 = document.getElementById('compareScan1');
            const s2 = document.getElementById('compareScan2');
            if (!s1 || !s2) return;
            const opts = (d.scans || []).filter(s => s.status === 'completed').map(s =>
                `<option value="${s.id}">#${s.id} - ${esc(s.target)} (${formatDate(s.started_at)})</option>`
            ).join('');
            s1.innerHTML = '<option value="">Scan wählen...</option>' + opts;
            s2.innerHTML = '<option value="">Scan wählen...</option>' + opts;
        } catch (e) {}
    }

    window.compareScans = async function () {
        const id1 = document.getElementById('compareScan1').value;
        const id2 = document.getElementById('compareScan2').value;
        if (!id1 || !id2) { showToast('warning', 'Hinweis', 'Bitte zwei Scans auswählen'); return; }
        if (id1 === id2) { showToast('warning', 'Hinweis', 'Bitte zwei verschiedene Scans wählen'); return; }
        try {
            const [d1, d2] = await Promise.all([api(`/api/scan/${id1}`), api(`/api/scan/${id2}`)]);
            const r1 = (d1.results || []).map(r => r.port);
            const r2 = (d2.results || []).map(r => r.port);
            const onlyIn1 = r1.filter(p => !r2.includes(p));
            const onlyIn2 = r2.filter(p => !r1.includes(p));
            const both = r1.filter(p => r2.includes(p));
            const body = document.getElementById('compareResultsBody');
            body.classList.remove('hidden');
            body.innerHTML = `<div class="stats-grid mb-3">
                <div class="stat-card"><div class="stat-icon blue"><i class="bi bi-intersect"></i></div><div class="stat-info"><h4>Gemeinsam</h4><div class="stat-value">${both.length}</div></div></div>
                <div class="stat-card"><div class="stat-icon green"><i class="bi bi-plus-circle"></i></div><div class="stat-info"><h4>Nur in Scan 1</h4><div class="stat-value">${onlyIn1.length}</div></div></div>
                <div class="stat-card"><div class="stat-icon red"><i class="bi bi-dash-circle"></i></div><div class="stat-info"><h4>Nur in Scan 2</h4><div class="stat-value">${onlyIn2.length}</div></div></div>
            </div>
            <div class="table-container"><table class="data-table"><thead><tr><th>Port</th><th>Scan 1</th><th>Scan 2</th><th>Status</th></tr></thead><tbody>
            ${[...new Set([...r1, ...r2])].sort((a,b) => a-b).map(p => {
                const in1 = r1.includes(p), in2 = r2.includes(p);
                const status = in1 && in2 ? '<span class="badge badge-blue">Beide</span>' : in1 ? '<span class="badge badge-green">Nur Scan 1</span>' : '<span class="badge badge-red">Nur Scan 2</span>';
                return `<tr><td>${p}</td><td>${in1 ? '✓' : '✗'}</td><td>${in2 ? '✓' : '✗'}</td><td>${status}</td></tr>`;
            }).join('')}
            </tbody></table></div>`;
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // Schedules
    // ============================================
    async function loadSchedules() {
        try {
            const d = await api('/api/schedules');
            const tbody = document.getElementById('schedulesTableBody');
            const schedules = d.schedules || d || [];
            if (schedules.length > 0) {
                tbody.innerHTML = schedules.map(s => `<tr>
                    <td>${esc(s.name)}</td><td>${esc(s.target)}</td><td><span class="badge badge-blue">${esc(s.scan_type)}</span></td>
                    <td>${esc(s.cron_expression)}</td><td><span class="badge badge-${s.enabled ? 'green' : 'gray'}">${s.enabled ? 'Aktiv' : 'Inaktiv'}</span></td>
                    <td>${formatDate(s.next_run)}</td>
                    <td><div class="d-flex gap-1">
                        <button class="btn btn-outline btn-sm" onclick="toggleSchedule(${s.id}, ${!s.enabled})"><i class="bi bi-${s.enabled ? 'pause' : 'play'}"></i></button>
                        <button class="btn btn-danger btn-sm" onclick="deleteSchedule(${s.id})"><i class="bi bi-trash"></i></button>
                    </div></td>
                </tr>`).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">Keine geplanten Scans</td></tr>';
            }
        } catch (e) { showToast('error', 'Fehler', e.message); }
    }

    window.showScheduleModal = function () { document.getElementById('scheduleModal').classList.add('active'); };
    window.hideScheduleModal = function () { document.getElementById('scheduleModal').classList.remove('active'); };
    window.saveSchedule = async function (e) {
        if (e && e.preventDefault) e.preventDefault();
        try {
            await api('/api/schedules', 'POST', {
                name: document.getElementById('scheduleName').value,
                target: document.getElementById('scheduleTarget').value,
                scanType: document.getElementById('scheduleScanType').value,
                cronExpression: document.getElementById('scheduleCron').value,
                enabled: true
            });
            showToast('success', 'Erstellt', 'Geplanter Scan wurde erstellt.');
            hideScheduleModal(); loadSchedules();
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };
    window.toggleSchedule = async function (id, enabled) {
        try { await api(`/api/schedules/${id}`, 'PUT', { enabled }); loadSchedules(); } catch (e) { showToast('error', 'Fehler', e.message); }
    };
    window.deleteSchedule = async function (id) {
        if (!confirm('Geplanten Scan löschen?')) return;
        try { await api(`/api/schedules/${id}`, 'DELETE'); showToast('success', 'Gelöscht', 'Geplanter Scan gelöscht.'); loadSchedules(); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // Users
    // ============================================
    async function loadUsers() {
        try {
            const d = await api('/api/users');
            const tbody = document.getElementById('usersTableBody');
            const users = d.users || d || [];
            tbody.innerHTML = users.map(u => `<tr>
                <td>${u.id}</td><td>${esc(u.username)}</td><td>${esc((u.roles || []).join(', ') || '-')}</td>
                <td>${formatDate(u.last_login)}</td><td>${formatDate(u.created_at)}</td>
                <td><button class="btn btn-danger btn-sm" onclick="deleteUser(${u.id})" ${u.id === currentUser?.id ? 'disabled' : ''}><i class="bi bi-trash"></i></button></td>
            </tr>`).join('');
        } catch (e) { showToast('error', 'Fehler', e.message); }
    }

    window.showUserModal = function () { document.getElementById('userModal').classList.add('active'); };
    window.hideUserModal = function () { document.getElementById('userModal').classList.remove('active'); };
    window.saveUser = async function (e) {
        if (e && e.preventDefault) e.preventDefault();
        try {
            await api('/api/users', 'POST', {
                username: document.getElementById('newUsername').value,
                password: document.getElementById('newPassword').value,
                role: document.getElementById('newUserRole').value
            });
            showToast('success', 'Erstellt', 'Benutzer wurde erstellt.');
            hideUserModal(); loadUsers();
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };
    window.deleteUser = async function (id) {
        if (!confirm('Benutzer wirklich löschen?')) return;
        try { await api(`/api/users/${id}`, 'DELETE'); showToast('success', 'Gelöscht', 'Benutzer gelöscht.'); loadUsers(); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // Notifications
    // ============================================
    async function loadNotifications() {
        try {
            const d = await api('/api/notifications');
            const tbody = document.getElementById('notificationsTableBody');
            const notifs = d.notifications || d || [];
            if (notifs.length > 0) {
                tbody.innerHTML = notifs.map(n => `<tr>
                    <td>${severityBadge(n.type || 'info')}</td><td>${esc(n.title)}</td>
                    <td>${esc(n.message)}</td><td>${formatDate(n.created_at)}</td>
                    <td><span class="badge badge-${n.read ? 'gray' : 'blue'}">${n.read ? 'Gelesen' : 'Neu'}</span></td>
                </tr>`).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">Keine Benachrichtigungen</td></tr>';
            }
        } catch (e) {}
    }

    // ============================================
    // Password Change
    // ============================================
    window.showPasswordModal = function () { document.getElementById('passwordModal').classList.add('active'); };
    window.hidePasswordModal = function () { document.getElementById('passwordModal').classList.remove('active'); };
    window.changePassword = async function (e) {
        if (e && e.preventDefault) e.preventDefault();
        const current = document.getElementById('currentPassword').value;
        const newPw = document.getElementById('newPasswordField').value;
        const confirm = document.getElementById('confirmPassword').value;
        if (newPw !== confirm) { showToast('error', 'Fehler', 'Passwörter stimmen nicht überein'); return; }
        try {
            await api('/api/auth/change-password', 'POST', { currentPassword: current, newPassword: newPw });
            showToast('success', 'Erfolg', 'Passwort wurde geändert.');
            hidePasswordModal();
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // Export
    // ============================================
    window.exportResults = async function (format) {
        if (!currentScanId) return;
        try {
            const d = await api(`/api/scan/${currentScanId}/export?format=${format}`);
            if (d.downloadUrl) window.open(d.downloadUrl, '_blank');
            else if (d.data) {
                const blob = new Blob([typeof d.data === 'string' ? d.data : JSON.stringify(d.data, null, 2)], { type: format === 'json' ? 'application/json' : 'text/csv' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url; a.download = `scan_${currentScanId}.${format}`; a.click(); URL.revokeObjectURL(url);
            }
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // Theme & Sidebar
    // ============================================
    window.toggleTheme = function () {
        const html = document.documentElement;
        const current = html.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        html.setAttribute('data-theme', next);
        localStorage.setItem('theme', next);
        document.getElementById('themeIcon').className = next === 'dark' ? 'bi bi-moon-stars' : 'bi bi-sun';
    };

    window.toggleSidebar = function () {
        document.getElementById('sidebar').classList.toggle('collapsed');
    };

    // ============================================
    // ========== FINGERPRINTING MODULE ==========
    // ============================================
    let fpPage = 1;

    async function loadFingerprintStats() {
        try {
            const d = await api('/api/db-update/stats');
            const fp = d.fingerprints;
            document.getElementById('fpStatTotal').textContent = fp.total || 0;
            document.getElementById('fpStatLastUpdate').textContent = fp.lastSync ? formatDate(fp.lastSync) : (fp.lastUpdate ? formatDate(fp.lastUpdate) : 'Nie');
            // Count unique services and OS families
            try {
                const fpData = await api('/api/fingerprints?limit=200');
                const fps = fpData.fingerprints || [];
                const uniqueServices = new Set(fps.map(f => f.service_name).filter(Boolean));
                const uniqueOS = new Set(fps.map(f => f.os_family).filter(Boolean));
                document.getElementById('fpStatServices').textContent = uniqueServices.size;
                document.getElementById('fpStatOS').textContent = uniqueOS.size;
            } catch(e) {
                document.getElementById('fpStatServices').textContent = 0;
                document.getElementById('fpStatOS').textContent = 0;
            }
        } catch (e) { console.error('FP stats error:', e); }
    }

    async function loadFingerprints(page) {
        fpPage = page || fpPage || 1;
        try {
            const port = document.getElementById('fpFilterPort')?.value || '';
            const service = document.getElementById('fpFilterService')?.value || '';
            const os = document.getElementById('fpFilterOS')?.value || '';
            const search = document.getElementById('fpFilterSearch')?.value || '';
            let url = `/api/fingerprints?page=${fpPage}&limit=25`;
            if (port) url += `&port=${port}`;
            if (service) url += `&service=${encodeURIComponent(service)}`;
            if (os) url += `&os=${encodeURIComponent(os)}`;
            if (search) url += `&search=${encodeURIComponent(search)}`;

            const d = await api(url);
            const tbody = document.getElementById('fpTableBody');
            const fps = d.fingerprints || [];
            const pag = d.pagination || {};

            if (fps.length > 0) {
                tbody.innerHTML = fps.map(f => `<tr>
                    <td>${f.port}</td>
                    <td><strong>${esc(f.service_name)}</strong></td>
                    <td><code>${esc(f.version_pattern || '-')}</code></td>
                    <td>${esc(f.os_family || '-')}</td>
                    <td><code class="cpe-code">${esc(f.cpe || '-')}</code></td>
                    <td>${confidenceBar(f.confidence || 0)}</td>
                    <td><span class="badge badge-${f.source === 'nmap-db' ? 'blue' : f.source === 'nvd-cpe' ? 'green' : f.source === 'custom' ? 'yellow' : 'gray'}">${esc(f.source || 'seed')}</span></td>
                    <td>
                        <div class="d-flex gap-1">
                            <button class="btn btn-outline btn-sm" onclick="showFingerprintDetail(${f.id})" title="Details"><i class="bi bi-eye"></i></button>
                            <button class="btn btn-danger btn-sm" onclick="deleteFingerprint(${f.id})" title="Löschen"><i class="bi bi-trash"></i></button>
                        </div>
                    </td>
                </tr>`).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">Keine Fingerprints gefunden</td></tr>';
            }

            // Pagination & count
            renderPagination('fpPagination', pag, (p) => loadFingerprints(p));
            const fpCountEl = document.getElementById('fpCount');
            if (fpCountEl) fpCountEl.textContent = (pag.total || fps.length) + ' Einträge';
        } catch (e) { showToast('error', 'Fehler', e.message); }
    }

    window.loadFingerprints = function(p) { return loadFingerprints(p); };
    window.filterFingerprints = function () { fpPage = 1; loadFingerprints(1); };

    window.showFingerprintDetail = async function (id) {
        try {
            const fps = await api('/api/fingerprints?limit=200');
            const fp = (fps.fingerprints || []).find(f => f.id === id);
            if (!fp) { showToast('error', 'Fehler', 'Fingerprint nicht gefunden'); return; }
            const modal = document.getElementById('fpDetailModal');
            document.getElementById('fpDetailContent').innerHTML = `
                <div class="detail-grid">
                    <div class="detail-item"><label>ID</label><span>${fp.id}</span></div>
                    <div class="detail-item"><label>Port</label><span>${fp.port}</span></div>
                    <div class="detail-item"><label>Service</label><span>${esc(fp.service_name)}</span></div>
                    <div class="detail-item"><label>Version</label><span><code>${esc(fp.version_pattern || '-')}</code></span></div>
                    <div class="detail-item"><label>OS-Familie</label><span>${esc(fp.os_family || '-')}</span></div>
                    <div class="detail-item"><label>CPE</label><span><code>${esc(fp.cpe || '-')}</code></span></div>
                    <div class="detail-item"><label>Konfidenz</label><span>${confidenceBar(fp.confidence || 0)}</span></div>
                    <div class="detail-item"><label>Quelle</label><span>${esc(fp.source || 'seed')}</span></div>
                    <div class="detail-item full-width"><label>Banner-Pattern</label><span><code>${esc(fp.banner_pattern || '-')}</code></span></div>
                    <div class="detail-item full-width"><label>Beschreibung</label><span>${esc(fp.description || '-')}</span></div>
                </div>`;
            modal.classList.add('active');
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };
    window.hideFpDetailModal = function () { document.getElementById('fpDetailModal').classList.remove('active'); };

    window.showFingerprintModal = function () {
        document.getElementById('fpForm').reset();
        
        document.getElementById('fingerprintModal').classList.add('active');
    };
    window.hideFingerprintModal = function () { document.getElementById('fingerprintModal').classList.remove('active'); };

    window.saveFingerprint = async function (e) {
        if (e && e.preventDefault) e.preventDefault();
        try {
            const data = {
                port: parseInt(document.getElementById('fpFormPort').value),
                service_name: document.getElementById('fpFormService').value,
                version_pattern: document.getElementById('fpFormVersion').value,
                os_family: document.getElementById('fpFormOS').value,
                cpe: document.getElementById('fpFormCPE').value,
                banner_pattern: document.getElementById('fpFormBanner').value,
                description: document.getElementById('fpFormDescription').value,
                confidence: parseInt(document.getElementById('fpFormConfidence').value) || 70,
                source: 'custom'
            };
            await api('/api/fingerprints', 'POST', data);
            showToast('success', 'Erstellt', 'Fingerprint wurde hinzugefügt.');
            hideFingerprintModal(); loadFingerprints(); loadFingerprintStats();
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.deleteFingerprint = async function (id) {
        if (!confirm('Fingerprint wirklich löschen?')) return;
        try { await api(`/api/fingerprints/${id}`, 'DELETE'); showToast('success', 'Gelöscht', 'Fingerprint gelöscht.'); loadFingerprints(); loadFingerprintStats(); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.syncFingerprintDB = async function () {
        const btn = document.getElementById('fpSyncBtn');
        const origText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Lade Nmap-Daten...';

        // Show progress bar
        const progDiv = document.getElementById('fpSyncProgress');
        const progBar = document.getElementById('fpSyncProgressBar');
        const progPct = document.getElementById('fpSyncProgressPct');
        const progMsg = document.getElementById('fpSyncProgressMsg');
        const statusDiv = document.getElementById('fpSyncStatus');
        if (progDiv) progDiv.classList.remove('hidden');
        if (statusDiv) statusDiv.classList.add('hidden');

        // Connect SSE for progress
        let sse = null;
        try {
            sse = new EventSource('/api/db-update/progress/fingerprints');
            sse.onmessage = (e) => {
                try {
                    const data = JSON.parse(e.data);
                    if (data.percent >= 0 && progBar) progBar.style.width = data.percent + '%';
                    if (progPct) progPct.textContent = data.percent >= 0 ? data.percent + '%' : '...';
                    if (progMsg) progMsg.textContent = data.message || '';
                    if (data.phase === 'done') {
                        if (statusDiv) { statusDiv.classList.remove('hidden'); document.getElementById('fpSyncStatusText').textContent = data.message; }
                        if (progDiv) progDiv.classList.add('hidden');
                        if (sse) sse.close();
                        btn.disabled = false; btn.innerHTML = origText;
                        loadFingerprints(); loadFingerprintStats();
                    } else if (data.phase === 'error') {
                        showToast('error', 'Sync-Fehler', data.message);
                        if (progDiv) progDiv.classList.add('hidden');
                        if (sse) sse.close();
                        btn.disabled = false; btn.innerHTML = origText;
                    }
                } catch (err) {}
            };
            sse.onerror = () => { if (sse) sse.close(); };
        } catch (e) {}

        try {
            await api('/api/db-update/sync/fingerprints', 'POST');
        } catch (e) {
            showToast('error', 'Fehler', e.message);
            if (progDiv) progDiv.classList.add('hidden');
            btn.disabled = false; btn.innerHTML = origText;
            if (sse) sse.close();
        }
    };

    // ============================================
    // ========== EXPLOIT-DB MODULE ==========
    // ============================================
    let exPage = 1;

    async function loadExploitStats() {
        try {
            const d = await api('/api/db-update/stats');
            const ex = d.exploits;
            document.getElementById('exploitStatTotal').textContent = ex.total || 0;
            const critCount = (ex.bySeverity || []).find(s => s.severity === 'critical')?.count || 0;
            const highCount = (ex.bySeverity || []).find(s => s.severity === 'high')?.count || 0;
            document.getElementById('exploitStatCritical').textContent = critCount;
            document.getElementById('exploitStatHigh').textContent = highCount;
            const medCount = (ex.bySeverity || []).find(s => s.severity === 'medium')?.count || 0;
            const lowCount = (ex.bySeverity || []).find(s => s.severity === 'low')?.count || 0;
            document.getElementById('exploitStatOther').textContent = (ex.total || 0) - critCount - highCount;
        } catch (e) { console.error('EX stats error:', e); }
    }

    async function loadExploits(page) {
        exPage = page || exPage || 1;
        try {
            const severity = document.getElementById('exploitFilterSeverity')?.value || '';
            const platform = document.getElementById('exploitFilterPlatform')?.value || '';
            const type = document.getElementById('exploitFilterType')?.value || '';
            const search = document.getElementById('exploitFilterSearch')?.value || '';
            let url = `/api/exploits?page=${exPage}&limit=25`;
            if (severity) url += `&severity=${severity}`;
            if (platform) url += `&platform=${encodeURIComponent(platform)}`;
            if (type) url += `&type=${encodeURIComponent(type)}`;
            if (search) url += `&search=${encodeURIComponent(search)}`;

            const d = await api(url);
            const tbody = document.getElementById('exploitTableBody');
            const exps = d.exploits || [];
            const pag = d.pagination || {};

            if (exps.length > 0) {
                tbody.innerHTML = exps.map(ex => `<tr>
                    <td><code>${esc(ex.exploit_db_id || '-')}</code><br><small class="text-muted">${esc(ex.cve_id || '')}</small></td>
                    <td><strong>${esc(ex.title)}</strong></td>
                    <td>${esc(ex.service_name || '-')}</td>
                    <td>${ex.port || '-'}</td>
                    <td>${esc(ex.platform || '-')}</td>
                    <td><span class="badge badge-gray">${esc(ex.exploit_type || '-')}</span></td>
                    <td>${severityBadge(ex.severity)}</td>
                    <td>${ex.cvss_score || '-'}</td>
                    <td><span class="badge badge-${ex.reliability === 'excellent' || ex.reliability === 'verified' ? 'green' : ex.reliability === 'tested' || ex.reliability === 'good' ? 'blue' : 'yellow'}">${esc(ex.reliability || '-')}</span></td>
                    <td>
                        <div class="d-flex gap-1">
                            <button class="btn btn-outline btn-sm" onclick="showExploitDetail(${ex.id})" title="Details"><i class="bi bi-eye"></i></button>
                            ${ex.exploit_code ? `<button class="btn btn-outline btn-sm" onclick="showExploitCode(${ex.id})" title="Code anzeigen" data-exploit-id="${ex.id}" data-edb-id="${esc(ex.exploit_db_id || '')}"><i class="bi bi-code-slash"></i></button>` : ''}
                            ${ex.source_url ? `<a href="${esc(ex.source_url)}" target="_blank" class="btn btn-outline btn-sm" title="Referenz"><i class="bi bi-box-arrow-up-right"></i></a>` : ''}
                            <button class="btn btn-danger btn-sm" onclick="deleteExploit(${ex.id})" title="Löschen"><i class="bi bi-trash"></i></button>
                        </div>
                    </td>
                </tr>`).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="9" class="text-center text-muted">Keine Exploits gefunden</td></tr>';
            }

            renderPagination('exploitPagination', pag, (p) => loadExploits(p));
        } catch (e) { showToast('error', 'Fehler', e.message); }
    }

    window.loadExploits = function(p) { return loadExploits(p); };
    window.filterExploits = function () { exPage = 1; loadExploits(1); };

    window.showExploitDetail = async function (id) {
        try {
            const exps = await api('/api/exploits?limit=200');
            const ex = (exps.exploits || []).find(e => e.id === id);
            if (!ex) { showToast('error', 'Fehler', 'Exploit nicht gefunden'); return; }
            document.getElementById('exploitDetailContent').innerHTML = `
                <div class="detail-grid">
                    <div class="detail-item"><label>Exploit-ID</label><span><code>${esc(ex.exploit_db_id || ex.exploit_id || '-')}</code></span></div>
                    <div class="detail-item"><label>CVE</label><span><code>${esc(ex.cve_id || '-')}</code></span></div>
                    <div class="detail-item"><label>Titel</label><span><strong>${esc(ex.title)}</strong></span></div>
                    <div class="detail-item"><label>Severity</label><span>${severityBadge(ex.severity)}</span></div>
                    <div class="detail-item"><label>CVSS</label><span>${ex.cvss_score || '-'}</span></div>
                    <div class="detail-item"><label>Plattform</label><span>${esc(ex.platform || '-')}</span></div>
                    <div class="detail-item"><label>Typ</label><span>${esc(ex.exploit_type || '-')}</span></div>
                    <div class="detail-item"><label>Zuverlässigkeit</label><span>${esc(ex.reliability || '-')}</span></div>
                    <div class="detail-item"><label>Port</label><span>${ex.port || '-'}</span></div>
                    <div class="detail-item"><label>Service</label><span>${esc(ex.service_name || ex.service || '-')}</span></div>
                    <div class="detail-item"><label>Quelle</label><span>${esc(ex.source || '-')}</span></div>
                    <div class="detail-item full-width"><label>Beschreibung</label><span>${esc(ex.description || '-')}</span></div>
                    ${(ex.source_url || ex.reference_url) ? `<div class="detail-item full-width"><label>Referenz</label><span><a href="${esc(ex.source_url || ex.reference_url)}" target="_blank">${esc(ex.source_url || ex.reference_url)}</a></span></div>` : ''}
                </div>`;
            document.getElementById('exploitDetailModal').classList.add('active');
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };
    window.hideExDetailModal = function () { document.getElementById('exploitDetailModal').classList.remove('active'); };

    window.showExploitModal = function () {
        document.getElementById('exploitForm').reset();
        document.getElementById('exploitModal').classList.add('active');
    };
    window.hideExModal = function () { document.getElementById('exploitModal').classList.remove('active'); };

    window.saveExploit = async function (e) {
        if (e && e.preventDefault) e.preventDefault();
        try {
            const data = {
                exploit_db_id: document.getElementById('exploitFormEDB').value,
                cve_id: document.getElementById('exploitFormCVE').value,
                title: document.getElementById('exploitFormTitle').value,
                description: document.getElementById('exploitFormDesc').value,
                severity: document.getElementById('exploitFormSeverity').value,
                cvss_score: parseFloat(document.getElementById('exploitFormCVSS').value) || null,
                platform: document.getElementById('exploitFormPlatform').value,
                exploit_type: document.getElementById('exploitFormType').value,
                port: parseInt(document.getElementById('exploitFormPort').value) || null,
                service_name: document.getElementById('exploitFormService').value,
                reliability: document.getElementById('exploitFormReliability').value,
                source_url: document.getElementById('exploitFormURL').value,
                source: 'custom'
            };
            await api('/api/exploits', 'POST', data);
            showToast('success', 'Erstellt', 'Exploit wurde hinzugefügt.');
            hideExModal(); loadExploits(); loadExploitStats();
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.deleteExploit = async function (id) {
        if (!confirm('Exploit wirklich löschen?')) return;
        try { await api(`/api/exploits/${id}`, 'DELETE'); showToast('success', 'Gelöscht', 'Exploit gelöscht.'); loadExploits(); loadExploitStats(); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.syncExploitDB = async function () {
        const btn = document.getElementById('exploitSyncBtn');
        const origText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Klone ExploitDB...';

        const progDiv = document.getElementById('exploitSyncProgress');
        const progBar = document.getElementById('exploitSyncProgressBar');
        const progPct = document.getElementById('exploitSyncProgressPct');
        const progMsg = document.getElementById('exploitSyncProgressMsg');
        const statusDiv = document.getElementById('exploitSyncStatus');
        if (progDiv) progDiv.classList.remove('hidden');
        if (statusDiv) statusDiv.classList.add('hidden');

        let sse = null;
        try {
            sse = new EventSource('/api/db-update/progress/exploits');
            sse.onmessage = (e) => {
                try {
                    const data = JSON.parse(e.data);
                    if (data.percent >= 0 && progBar) progBar.style.width = data.percent + '%';
                    if (progPct) progPct.textContent = data.percent >= 0 ? data.percent + '%' : '...';
                    if (progMsg) progMsg.textContent = data.message || '';
                    if (data.phase === 'done') {
                        if (statusDiv) { statusDiv.classList.remove('hidden'); document.getElementById('exploitSyncStatusText').textContent = data.message; }
                        if (progDiv) progDiv.classList.add('hidden');
                        if (sse) sse.close();
                        btn.disabled = false; btn.innerHTML = origText;
                        loadExploits(); loadExploitStats();
                    } else if (data.phase === 'error') {
                        showToast('error', 'Sync-Fehler', data.message);
                        if (progDiv) progDiv.classList.add('hidden');
                        if (sse) sse.close();
                        btn.disabled = false; btn.innerHTML = origText;
                    }
                } catch (err) {}
            };
            sse.onerror = () => { if (sse) sse.close(); };
        } catch (e) {}

        try {
            await api('/api/db-update/sync/exploits', 'POST');
        } catch (e) {
            showToast('error', 'Fehler', e.message);
            if (progDiv) progDiv.classList.add('hidden');
            btn.disabled = false; btn.innerHTML = origText;
            if (sse) sse.close();
        }
    };

    // Exploit Code Viewer
    window.showExploitCode = async function (id) {
        try {
            const data = await api(`/api/db-update/exploits/code/${id}`);
            if (!data || !data.code) {
                showToast('warning', 'Kein Code', 'Exploit-Code nicht verfügbar. Bitte ExploitDB synchronisieren.');
                return;
            }
            document.getElementById('exploitCodeFileName').textContent = data.fileName || 'exploit';
            document.getElementById('exploitCodeLang').textContent = `Sprache: ${data.language || 'text'} | Größe: ${data.size ? (data.size / 1024).toFixed(1) + ' KB' : 'unbekannt'}`;
            document.getElementById('exploitCodeContent').textContent = data.code;
            // Find the exploit to get the URL
            const exploitRow = document.querySelector(`[data-exploit-id="${id}"]`);
            const extLink = document.getElementById('exploitCodeExtLink');
            if (extLink) {
                const edbId = exploitRow?.dataset?.edbId;
                if (edbId) extLink.href = `https://www.exploit-db.com/exploits/${edbId.replace('EDB-', '')}`;
                else extLink.href = '#';
            }
            document.getElementById('exploitCodeModal').classList.add('active');
        } catch (e) {
            showToast('error', 'Fehler', e.message);
        }
    };
    window.hideExploitCodeModal = function () { document.getElementById('exploitCodeModal').classList.remove('active'); };
    window.copyExploitCode = function () {
        const code = document.getElementById('exploitCodeContent').textContent;
        navigator.clipboard.writeText(code).then(() => showToast('success', 'Kopiert', 'Code in Zwischenablage kopiert.'));
    };

    // ============================================
    // ========== CVE MODULE ==========
    // ============================================
    let cvePage = 1;

    async function loadCVEStats() {
        try {
            const d = await api('/api/db-update/cve/stats');
            document.getElementById('cveStatTotal').textContent = d.total || 0;
            const critCount = (d.bySeverity || []).find(s => s.severity === 'critical')?.count || 0;
            const highCount = (d.bySeverity || []).find(s => s.severity === 'high')?.count || 0;
            document.getElementById('cveStatCritical').textContent = critCount;
            document.getElementById('cveStatHigh').textContent = highCount;
            document.getElementById('cveStatLastSync').textContent = d.lastSync ? formatDate(d.lastSync) : 'Nie';
            
            // Populate year filter dropdown dynamically
            const yearSelect = document.getElementById('cveFilterYear');
            if (yearSelect && d.byYear && d.byYear.length > 0) {
                yearSelect.innerHTML = '<option value="">Alle</option>';
                const sortedYears = d.byYear.sort((a, b) => b.year - a.year);
                sortedYears.forEach(y => {
                    yearSelect.innerHTML += `<option value="${y.year}">${y.year} (${y.count})</option>`;
                });
            }
        } catch (e) { console.error('CVE stats error:', e); }
    }

    async function loadCVEs(page) {
        cvePage = page || cvePage || 1;
        const loadEl = document.getElementById('cveLoading');
        const emptyEl = document.getElementById('cveEmpty');
        try {
            if (loadEl) loadEl.classList.remove('hidden');
            if (emptyEl) emptyEl.classList.add('hidden');

            const severity = document.getElementById('cveFilterSeverity')?.value || '';
            const year = document.getElementById('cveFilterYear')?.value || '';
            const search = document.getElementById('cveFilterSearch')?.value || '';
            let url = `/api/db-update/cve/search?page=${cvePage}&limit=25`;
            if (severity) url += `&severity=${severity}`;
            if (year) url += `&year=${year}`;
            if (search) url += `&search=${encodeURIComponent(search)}`;

            const d = await api(url);
            const tbody = document.getElementById('cveTableBody');
            const cves = d.cves || [];
            const pag = d.pagination || {};

            if (cves.length > 0) {
                tbody.innerHTML = cves.map(c => `<tr style="cursor:pointer" onclick="showCVEDetail('${esc(c.cve_id)}')">
                    <td><code style="color:var(--accent-blue)">${esc(c.cve_id)}</code></td>
                    <td><strong>${esc((c.title || '').substring(0, 80))}${(c.title || '').length > 80 ? '...' : ''}</strong></td>
                    <td>${severityBadge(c.severity)}</td>
                    <td>${c.cvss_score ? c.cvss_score.toFixed(1) : '-'}</td>
                    <td><small>${esc((c.affected_products || '-').substring(0, 60))}</small></td>
                    <td><small>${c.date_published ? formatDate(c.date_published) : '-'}</small></td>
                </tr>`).join('');
                if (emptyEl) emptyEl.classList.add('hidden');
            } else {
                tbody.innerHTML = '';
                if (emptyEl) emptyEl.classList.remove('hidden');
            }

            if (loadEl) loadEl.classList.add('hidden');
            renderPagination('cvePagination', pag, (p) => loadCVEs(p));
        } catch (e) {
            if (loadEl) loadEl.classList.add('hidden');
            console.error('CVE load error:', e);
        }
    }

    window.loadCVEs = function(p) { return loadCVEs(p); };

    window.showCVEDetail = async function (cveId) {
        try {
            const d = await api(`/api/db-update/cve/search?search=${encodeURIComponent(cveId)}&limit=1`);
            const cve = (d.cves || [])[0];
            if (!cve) { showToast('error', 'Fehler', 'CVE nicht gefunden'); return; }

            let refs = [];
            try { refs = JSON.parse(cve.references_json || '[]'); } catch (e) {}

            document.getElementById('cveDetailContent').innerHTML = `
                <div class="detail-grid">
                    <div class="detail-item"><label>CVE-ID</label><span><code style="font-size:1.1rem">${esc(cve.cve_id)}</code></span></div>
                    <div class="detail-item"><label>Status</label><span><span class="badge badge-${cve.state === 'PUBLISHED' ? 'green' : 'gray'}">${esc(cve.state)}</span></span></div>
                    <div class="detail-item"><label>Severity</label><span>${severityBadge(cve.severity)}</span></div>
                    <div class="detail-item"><label>CVSS Score</label><span>${cve.cvss_score ? cve.cvss_score.toFixed(1) : '-'}</span></div>
                    <div class="detail-item"><label>Veröffentlicht</label><span>${cve.date_published ? formatDate(cve.date_published) : '-'}</span></div>
                    <div class="detail-item"><label>Aktualisiert</label><span>${cve.date_updated ? formatDate(cve.date_updated) : '-'}</span></div>
                    ${cve.cvss_vector ? `<div class="detail-item full-width"><label>CVSS Vector</label><span><code>${esc(cve.cvss_vector)}</code></span></div>` : ''}
                    ${cve.affected_products ? `<div class="detail-item full-width"><label>Betroffene Produkte</label><span>${esc(cve.affected_products)}</span></div>` : ''}
                    <div class="detail-item full-width"><label>Beschreibung</label><span>${esc(cve.description || 'Keine Beschreibung verfügbar')}</span></div>
                    ${refs.length > 0 ? `<div class="detail-item full-width"><label>Referenzen</label><span>${refs.map(r => `<a href="${esc(r.url)}" target="_blank" style="display:block;margin-bottom:.25rem;color:var(--accent-blue);font-size:.85rem">${esc(r.url)}</a>`).join('')}</span></div>` : ''}
                </div>
                <div style="margin-top:1rem;display:flex;gap:.5rem">
                    <a href="https://nvd.nist.gov/vuln/detail/${esc(cve.cve_id)}" target="_blank" class="btn btn-outline btn-sm"><i class="bi bi-box-arrow-up-right"></i> NVD</a>
                    <a href="https://www.cve.org/CVERecord?id=${esc(cve.cve_id)}" target="_blank" class="btn btn-outline btn-sm"><i class="bi bi-box-arrow-up-right"></i> CVE.org</a>
                </div>`;
            document.getElementById('cveDetailModal').classList.add('active');
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };
    window.hideCVEDetailModal = function () { document.getElementById('cveDetailModal').classList.remove('active'); };

    window.syncCVEDB = async function () {
        const btn = document.getElementById('cveSyncBtn');
        const origText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Lade CVE-Daten...';

        const progDiv = document.getElementById('cveSyncProgress');
        const progBar = document.getElementById('cveSyncProgressBar');
        const progPct = document.getElementById('cveSyncProgressPct');
        const progMsg = document.getElementById('cveSyncProgressMsg');
        const statusDiv = document.getElementById('cveSyncStatus');
        if (progDiv) progDiv.classList.remove('hidden');
        if (statusDiv) statusDiv.classList.add('hidden');

        let sse = null;
        try {
            sse = new EventSource('/api/db-update/progress/cve');
            sse.onmessage = (e) => {
                try {
                    const data = JSON.parse(e.data);
                    if (data.percent >= 0 && progBar) progBar.style.width = data.percent + '%';
                    if (progPct) progPct.textContent = data.percent >= 0 ? data.percent + '%' : '...';
                    if (progMsg) progMsg.textContent = data.message || '';
                    if (data.phase === 'done') {
                        if (statusDiv) { statusDiv.classList.remove('hidden'); document.getElementById('cveSyncStatusText').textContent = data.message; }
                        if (progDiv) progDiv.classList.add('hidden');
                        if (sse) sse.close();
                        btn.disabled = false; btn.innerHTML = origText;
                        loadCVEs(); loadCVEStats();
                    } else if (data.phase === 'error') {
                        showToast('error', 'Sync-Fehler', data.message);
                        if (progDiv) progDiv.classList.add('hidden');
                        if (sse) sse.close();
                        btn.disabled = false; btn.innerHTML = origText;
                    }
                } catch (err) {}
            };
            sse.onerror = () => { if (sse) sse.close(); };
        } catch (e) {}

        try {
            await api('/api/db-update/sync/cve', 'POST');
        } catch (e) {
            showToast('error', 'Fehler', e.message);
            if (progDiv) progDiv.classList.add('hidden');
            btn.disabled = false; btn.innerHTML = origText;
            if (sse) sse.close();
        }
    };

    // ============================================
    // ========== AUTO-ATTACK MODULE (Simplified for Auditors) ==========
    // ============================================

    window.showAutoAttackModal = async function(scanId, targetIp) {
        try {
            const modal = document.getElementById('autoAttackModal');
            const content = document.getElementById('autoAttackContent');
            const startBtn = document.getElementById('autoAttackStartBtn');

            // Store context
            modal.dataset.scanId = scanId;
            modal.dataset.targetIp = targetIp;

            // Show modal with loading state
            content.innerHTML = '<div class="text-center" style="padding:2rem"><div class="spinner"></div><p class="text-muted mt-1">Analysiere Dienste und suche passende Exploits...</p></div>';
            startBtn.disabled = true;
            startBtn.innerHTML = '<i class="bi bi-lightning-charge-fill"></i> Angriff starten';
            document.getElementById('autoAttackProgress').classList.add('hidden');
            document.getElementById('autoAttackResult').classList.add('hidden');
            modal.classList.add('active');

            // Fetch attackable summary from backend
            const d = await api(`/api/exploits/attackable/${scanId}/${targetIp}`);
            const services = d.services || [];
            const attackable = services.filter(s => s.hasExploits);
            const notAttackable = services.filter(s => !s.hasExploits);

            if (attackable.length === 0) {
                content.innerHTML = `
                    <div class="text-center" style="padding:1.5rem">
                        <i class="bi bi-shield-check" style="font-size:3rem;color:var(--accent-green)"></i>
                        <h4 class="mt-1">Keine angreifbaren Dienste gefunden</h4>
                        <p class="text-muted">Für die erkannten Service-Versionen auf <strong>${esc(targetIp)}</strong> gibt es keine passenden Exploits in der Datenbank.</p>
                        ${notAttackable.length > 0 ? `
                        <div class="mt-2" style="text-align:left">
                            <h5 class="mb-1">Erkannte Dienste (keine Exploits verfügbar):</h5>
                            ${notAttackable.map(s => `
                                <div style="display:flex;align-items:center;gap:0.5rem;padding:0.4rem 0;border-bottom:1px solid var(--border-color)">
                                    <span class="badge badge-green"><i class="bi bi-shield-check"></i></span>
                                    <span><strong>Port ${s.port}</strong> – ${esc(s.service)} ${s.version ? esc(s.version) : ''}</span>
                                </div>
                            `).join('')}
                        </div>` : ''}
                        <p class="text-muted mt-2" style="font-size:0.85rem"><i class="bi bi-info-circle"></i> Tipp: Synchronisieren Sie die Exploit-Datenbank für aktuelle Exploits.</p>
                    </div>`;
                startBtn.style.display = 'none';
                return;
            }

            // Show attackable services
            startBtn.style.display = '';
            startBtn.disabled = false;
            content.innerHTML = `
                <div style="margin-bottom:1rem">
                    <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">
                        <i class="bi bi-crosshair" style="font-size:1.5rem;color:var(--accent-red)"></i>
                        <h4 style="margin:0">Ziel: ${esc(targetIp)}</h4>
                    </div>
                    <p class="text-muted" style="margin:0">Es wurden <strong>${attackable.length} angreifbare Dienste</strong> mit passenden Exploits gefunden.</p>
                </div>

                <h5 class="mb-1" style="color:var(--accent-red)"><i class="bi bi-exclamation-triangle-fill mr-1"></i> Angreifbare Dienste</h5>
                <div style="border:1px solid rgba(239,68,68,0.3);border-radius:var(--radius-sm);overflow:hidden;margin-bottom:1rem">
                    ${attackable.map(s => {
                        const sevColors = { critical: 'red', high: 'orange', medium: 'yellow', low: 'blue' };
                        const topSev = (s.severities || '').split(',')[0] || 'medium';
                        return `<div style="display:flex;align-items:center;justify-content:space-between;padding:0.6rem 0.8rem;border-bottom:1px solid var(--border-color);background:rgba(239,68,68,0.05)">
                            <div style="display:flex;align-items:center;gap:0.5rem">
                                <span class="badge badge-red"><i class="bi bi-bullseye"></i></span>
                                <div>
                                    <strong>Port ${s.port}</strong> – ${esc(s.service)} ${s.version ? '<code>' + esc(s.version) + '</code>' : ''}
                                    ${s.product ? '<br><small class="text-muted">' + esc(s.product) + '</small>' : ''}
                                </div>
                            </div>
                            <div style="display:flex;align-items:center;gap:0.5rem">
                                <span class="badge badge-${sevColors[topSev] || 'yellow'}">${s.exploitCount} Exploit${s.exploitCount > 1 ? 's' : ''}</span>
                                <span class="badge badge-gray">Confidence: ${s.maxConfidence}%</span>
                            </div>
                        </div>`;
                    }).join('')}
                </div>

                ${notAttackable.length > 0 ? `
                <details style="margin-bottom:1rem">
                    <summary class="text-muted" style="cursor:pointer;font-size:0.85rem"><i class="bi bi-shield-check mr-1"></i>${notAttackable.length} sichere Dienste (keine Exploits)</summary>
                    <div style="margin-top:0.5rem">
                        ${notAttackable.map(s => `
                            <div style="display:flex;align-items:center;gap:0.5rem;padding:0.3rem 0;font-size:0.85rem">
                                <span class="badge badge-green" style="font-size:0.7rem">OK</span>
                                <span>Port ${s.port} – ${esc(s.service)} ${s.version ? esc(s.version) : ''}</span>
                            </div>
                        `).join('')}
                    </div>
                </details>` : ''}

                <div style="background:var(--bg-tertiary);border-radius:var(--radius-sm);padding:0.8rem;font-size:0.85rem">
                    <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">
                        <i class="bi bi-gear"></i> <strong>Reverse Shell Konfiguration</strong>
                    </div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.5rem">
                        <div class="form-group" style="margin:0">
                            <label style="font-size:0.8rem">LHOST (Ihre IP)</label>
                            <input type="text" id="autoAttackLHOST" class="form-control" value="${window.location.hostname}" style="font-size:0.85rem">
                        </div>
                        <div class="form-group" style="margin:0">
                            <label style="font-size:0.8rem">LPORT (Listener Port)</label>
                            <input type="number" id="autoAttackLPORT" class="form-control" value="4444" style="font-size:0.85rem">
                        </div>
                    </div>
                </div>
            `;
        } catch (e) {
            showToast('error', 'Fehler', e.message);
            document.getElementById('autoAttackModal').classList.remove('active');
        }
    };

    window.hideAutoAttackModal = function() {
        document.getElementById('autoAttackModal').classList.remove('active');
    };

    window.startAutoAttack = async function() {
        const modal = document.getElementById('autoAttackModal');
        const scanId = parseInt(modal.dataset.scanId);
        const targetIp = modal.dataset.targetIp;
        const lhost = document.getElementById('autoAttackLHOST')?.value || window.location.hostname;
        const lport = document.getElementById('autoAttackLPORT')?.value || '4444';

        const startBtn = document.getElementById('autoAttackStartBtn');
        const progressDiv = document.getElementById('autoAttackProgress');
        const resultDiv = document.getElementById('autoAttackResult');

        // Disable button, show progress
        startBtn.disabled = true;
        startBtn.innerHTML = '<span class="spinner" style="width:16px;height:16px"></span> Angriff läuft...';
        progressDiv.classList.remove('hidden');
        progressDiv.innerHTML = `
            <div style="padding:1rem;background:var(--bg-tertiary);border-radius:var(--radius-sm);margin-top:1rem">
                <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem">
                    <span class="spinner" style="width:18px;height:18px"></span>
                    <strong id="autoAttackStatusText">Starte automatischen Angriff...</strong>
                </div>
                <div class="progress-bar-container" style="height:6px;background:var(--bg-secondary);border-radius:3px;overflow:hidden">
                    <div id="autoAttackProgressBar" style="width:10%;height:100%;background:var(--accent-red);transition:width 0.5s ease;border-radius:3px"></div>
                </div>
                <p id="autoAttackProgressDetail" class="text-muted" style="font-size:0.8rem;margin-top:0.5rem">Analysiere Dienste und bereite Exploits vor...</p>
            </div>`;
        resultDiv.classList.add('hidden');

        try {
            const d = await api('/api/attack-chains/auto-attack', 'POST', {
                scanId: scanId,
                targetIp: targetIp,
                params: { LHOST: lhost, LPORT: lport }
            });

            if (d.status === 'no_exploits' || d.status === 'no_executable_exploits') {
                progressDiv.innerHTML = `
                    <div style="padding:1rem;background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.2);border-radius:var(--radius-sm);margin-top:1rem;text-align:center">
                        <i class="bi bi-shield-check" style="font-size:2rem;color:var(--accent-green)"></i>
                        <h4 class="mt-1">Kein Angriff möglich</h4>
                        <p class="text-muted">${esc(d.message)}</p>
                    </div>`;
                startBtn.innerHTML = '<i class="bi bi-lightning-charge-fill"></i> Angriff starten';
                startBtn.disabled = false;
                return;
            }

            // Attack started - monitor execution
            const execId = d.executionId;
            currentChainExecId = execId;

            document.getElementById('autoAttackStatusText').textContent = `Angriff läuft... (${d.totalSteps} Schritte)`;
            document.getElementById('autoAttackProgressBar').style.width = '30%';
            document.getElementById('autoAttackProgressDetail').textContent = `${d.totalExploits} Exploits für ${d.attackableServices} Dienste werden getestet...`;

            // Poll for results
            let pollCount = 0;
            const maxPolls = 60; // Max 60 polls (2 minutes)
            const pollInterval = setInterval(async () => {
                pollCount++;
                try {
                    const execData = await api(`/api/attack-chains/executions/${execId}`);
                    const ex = execData.execution || execData;
                    const results = ex.results ? (typeof ex.results === 'string' ? JSON.parse(ex.results) : ex.results) : [];
                    const findings = ex.findings ? (typeof ex.findings === 'string' ? JSON.parse(ex.findings) : ex.findings) : [];
                    const progress = ex.total_steps > 0 ? Math.round((ex.current_step / ex.total_steps) * 100) : 0;

                    document.getElementById('autoAttackProgressBar').style.width = progress + '%';
                    document.getElementById('autoAttackStatusText').textContent = ex.status === 'completed' ? 'Angriff abgeschlossen' : ex.status === 'failed' ? 'Angriff fehlgeschlagen' : `Schritt ${ex.current_step} von ${ex.total_steps}...`;

                    if (results.length > 0) {
                        const lastResult = results[results.length - 1];
                        document.getElementById('autoAttackProgressDetail').textContent = lastResult.name || lastResult.details || '';
                    }

                    // Check if completed
                    if (ex.status === 'completed' || ex.status === 'failed' || pollCount >= maxPolls) {
                        clearInterval(pollInterval);
                        showAutoAttackResults(ex, findings, results, targetIp);
                    }
                } catch (pollErr) {
                    // Ignore poll errors, keep trying
                    if (pollCount >= maxPolls) {
                        clearInterval(pollInterval);
                        progressDiv.innerHTML = '<p class="text-muted" style="padding:1rem">Zeitüberschreitung. Prüfen Sie die Ergebnisse in der Angriffsketten-Übersicht.</p>';
                        startBtn.innerHTML = '<i class="bi bi-lightning-charge-fill"></i> Angriff starten';
                        startBtn.disabled = false;
                    }
                }
            }, 2000);

        } catch (e) {
            showToast('error', 'Fehler', e.message);
            progressDiv.innerHTML = `<div style="padding:1rem;color:var(--accent-red)"><i class="bi bi-x-circle"></i> ${esc(e.message)}</div>`;
            startBtn.innerHTML = '<i class="bi bi-lightning-charge-fill"></i> Erneut versuchen';
            startBtn.disabled = false;
        }
    };

    function showAutoAttackResults(execution, findings, results, targetIp) {
        const progressDiv = document.getElementById('autoAttackProgress');
        const startBtn = document.getElementById('autoAttackStartBtn');

        // Check for shell session
        const shellFinding = findings.find(f => f.sessionId && (f.type === 'exploit_success' || f.category === 'Remote Shell'));
        const exploitSuccesses = findings.filter(f => f.type === 'exploit_success');
        const vulnerabilities = findings.filter(f => f.type === 'vulnerability');
        const errors = findings.filter(f => f.type === 'error');

        let html = '';

        if (shellFinding) {
            // SUCCESS - Shell obtained!
            html += `
                <div style="padding:1.5rem;background:rgba(34,197,94,0.1);border:2px solid rgba(34,197,94,0.4);border-radius:var(--radius-sm);margin-top:1rem;text-align:center">
                    <i class="bi bi-terminal-fill" style="font-size:3rem;color:var(--accent-green)"></i>
                    <h3 style="color:var(--accent-green);margin:0.5rem 0">Reverse Shell erhalten!</h3>
                    <p>Zugriff auf <strong>${esc(targetIp)}</strong> über: <strong>${esc(shellFinding.title)}</strong></p>
                    <p class="text-muted" style="font-size:0.85rem">Session ID: ${shellFinding.sessionId}</p>
                    <button class="btn btn-primary btn-lg" onclick="hideAutoAttackModal();showShellModal('${shellFinding.sessionId}')" style="margin-top:0.5rem;font-size:1.1rem;padding:0.75rem 2rem">
                        <i class="bi bi-terminal-fill mr-1"></i> Terminal öffnen
                    </button>
                </div>`;
        } else if (execution.status === 'completed') {
            // Completed but no shell
            html += `
                <div style="padding:1.5rem;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);border-radius:var(--radius-sm);margin-top:1rem;text-align:center">
                    <i class="bi bi-shield-exclamation" style="font-size:3rem;color:var(--accent-yellow)"></i>
                    <h3 style="color:var(--accent-yellow);margin:0.5rem 0">Angriff abgeschlossen</h3>
                    <p>Kein Shell-Zugang erhalten. Die getesteten Exploits waren nicht erfolgreich.</p>
                    <p class="text-muted" style="font-size:0.85rem">${vulnerabilities.length} Schwachstellen erkannt, ${results.length} Schritte ausgeführt.</p>
                </div>`;
        } else {
            // Failed
            html += `
                <div style="padding:1.5rem;background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);border-radius:var(--radius-sm);margin-top:1rem;text-align:center">
                    <i class="bi bi-x-circle" style="font-size:3rem;color:var(--accent-red)"></i>
                    <h3 style="color:var(--accent-red);margin:0.5rem 0">Angriff fehlgeschlagen</h3>
                    <p class="text-muted">${errors.length > 0 ? esc(errors[0].details) : 'Ein unerwarteter Fehler ist aufgetreten.'}</p>
                </div>`;
        }

        // Show step results summary
        if (results.length > 0) {
            html += `
                <details style="margin-top:1rem" ${shellFinding ? '' : 'open'}>
                    <summary style="cursor:pointer;font-weight:600;padding:0.5rem 0"><i class="bi bi-list-check mr-1"></i> Detaillierte Ergebnisse (${results.length} Schritte)</summary>
                    <div style="margin-top:0.5rem">
                        ${results.map((r, i) => {
                            const icon = r.status === 'completed' ? 'bi-check-circle-fill' : 'bi-x-circle-fill';
                            const color = r.status === 'completed' ? 'var(--accent-green)' : 'var(--accent-red)';
                            const hasShell = r.findings && r.findings.some(f => f.type === 'exploit_success');
                            return `<div style="display:flex;align-items:flex-start;gap:0.5rem;padding:0.5rem 0;border-bottom:1px solid var(--border-color)">
                                <i class="bi ${icon}" style="color:${color};margin-top:2px"></i>
                                <div style="flex:1">
                                    <strong>${esc(r.name || 'Schritt ' + (i+1))}</strong>
                                    ${hasShell ? '<span class="badge badge-green ml-1"><i class="bi bi-terminal"></i> Shell!</span>' : ''}
                                    ${r.findings && r.findings.length > 0 ? `<div style="font-size:0.8rem;color:var(--text-secondary);margin-top:2px">${r.findings.map(f => esc(f.title)).join(' · ')}</div>` : ''}
                                </div>
                            </div>`;
                        }).join('')}
                    </div>
                </details>`;
        }

        progressDiv.innerHTML = html;
        startBtn.innerHTML = '<i class="bi bi-lightning-charge-fill"></i> Erneut angreifen';
        startBtn.disabled = false;

        // Refresh chain stats
        loadChainStats();
        loadChainExecutions();
    }

    // ============================================
    // ========== ATTACK CHAINS MODULE ==========
    // ============================================

    window.showCreateChainForTargetModal = async function(scanId, ip) {
        try {
            document.getElementById('chainTargetScanId').value = scanId;
            document.getElementById('chainTargetIP').value = ip;
            const container = document.getElementById('chainTargetServices');
            container.innerHTML = '<div class="text-center"><div class="spinner"></div> Lade Services...</div>';
            document.getElementById('chainTargetModal').classList.add('active');

            const d = await api(`/api/scan/results/${scanId}`);
            const results = (d.results || []).filter(r => r.ip_address === ip && r.state === 'open');

            if (results.length === 0) {
                container.innerHTML = '<div class="text-muted text-center">Keine offenen Ports gefunden.</div>';
                return;
            }

            container.innerHTML = results.map(r => {
                const svc = r.service || 'unknown';
                const label = `${r.port}/${r.protocol} - ${svc}${r.service_product ? ' (' + r.service_product + ')' : ''}`;
                return `<div class="form-group mb-1" style="display:flex;align-items:center;gap:0.5rem">
                    <input type="checkbox" class="chain-service-select" value="${r.port}" data-service="${esc(svc)}" id="chk_svc_${r.port}" checked>
                    <label for="chk_svc_${r.port}" style="margin:0;cursor:pointer">${esc(label)}</label>
                </div>`;
            }).join('');

        } catch (e) {
            showToast('error', 'Fehler', e.message);
            document.getElementById('chainTargetModal').classList.remove('active');
        }
    };

    window.hideChainTargetModal = function() {
        document.getElementById('chainTargetModal').classList.remove('active');
    };

    window.createChainFromTarget = async function() {
        const scanId = parseInt(document.getElementById('chainTargetScanId').value);
        const ip = document.getElementById('chainTargetIP').value;
        const checkboxes = document.querySelectorAll('.chain-service-select:checked');

        if (checkboxes.length === 0) {
            showToast('warning', 'Hinweis', 'Bitte mindestens einen Service auswählen.');
            return;
        }

        const selectedPorts = Array.from(checkboxes).map(cb => parseInt(cb.value));
        const selectedServices = Array.from(checkboxes).map(cb => cb.dataset.service);

        hideChainTargetModal();
        await generateChainForTargetInternal(scanId, ip, selectedPorts, selectedServices);
    };

    async function generateChainForTargetInternal(scanId, targetIp, targetPorts, targetServices) {
         try {
            showChainModal();

            // Populate form
            document.getElementById('chainFormName').value = `Chain for ${targetIp}`;
            document.getElementById('chainFormDesc').value = `Automatisch generiert für ${targetIp} (Ports: ${targetPorts.join(', ')})`;
            document.getElementById('chainFormServices').value = [...new Set(targetServices)].join(', ');
            document.getElementById('chainFormPorts').value = targetPorts.join(', ');

            // Generate steps
            const container = document.getElementById('chainStepsContainer');
            container.innerHTML = ''; // Clear default step

            // Add initial Recon step (always good)
            addChainStep();
            let step = container.lastElementChild;
            step.querySelector('[data-field="name"]').value = 'Initial Recon';
            step.querySelector('[data-field="type"]').value = 'recon';
            step.querySelector('[data-field="description"]').value = `Fingerprinting für ${targetIp}`;

            const uniqueServices = new Set(targetServices);

            if (uniqueServices.has('http') || uniqueServices.has('https') || uniqueServices.has('http-alt') || uniqueServices.has('ssl/http')) {
                addChainStep();
                step = container.lastElementChild;
                step.querySelector('[data-field="name"]').value = 'Web Audit';
                step.querySelector('[data-field="type"]').value = 'audit';
                step.querySelector('[data-field="description"]').value = 'Prüfung auf Web-Schwachstellen';
                step.querySelector('[data-field="tool"]').value = 'nikto';
            }

             if (uniqueServices.has('ssh')) {
                addChainStep();
                step = container.lastElementChild;
                step.querySelector('[data-field="name"]').value = 'SSH Audit';
                step.querySelector('[data-field="type"]').value = 'audit';
                step.querySelector('[data-field="description"]').value = 'SSH Konfigurationsprüfung';
            }

            if (uniqueServices.has('ftp')) {
                addChainStep();
                step = container.lastElementChild;
                step.querySelector('[data-field="name"]').value = 'FTP Check';
                step.querySelector('[data-field="type"]').value = 'auth_test';
                step.querySelector('[data-field="description"]').value = 'Prüfung auf anonymen Login';
            }

             if (uniqueServices.has('mysql') || uniqueServices.has('postgresql') || uniqueServices.has('mssql')) {
                 addChainStep();
                step = container.lastElementChild;
                step.querySelector('[data-field="name"]').value = 'DB Audit';
                step.querySelector('[data-field="type"]').value = 'audit';
                step.querySelector('[data-field="description"]').value = 'Datenbank-Sicherheitsprüfung';
            }

            // Fetch version-matched exploits for this scan and add steps
            try {
                const exploitData = await api(`/api/exploits/matched/${scanId}/${targetIp}`);
                const exploits = exploitData.exploits || [];

                // Filter exploits for selected ports only
                const filteredExploits = exploits.filter(ex =>
                    targetPorts.includes(ex.port)
                );

                // Deduplicate and sort by confidence
                const distinctExploits = [];
                const seenExploits = new Set();

                filteredExploits.sort((a, b) => (b.match_confidence || 0) - (a.match_confidence || 0));

                for (const ex of filteredExploits) {
                    const key = `${ex.port}-${ex.exploit_id}`;
                    if (!seenExploits.has(key)) {
                        seenExploits.add(key);
                        distinctExploits.push(ex);
                    }
                }

                // Limit to top 5 most promising exploits (version-matched)
                for (const ex of distinctExploits.slice(0, 5)) {
                    addChainStep();
                    step = container.lastElementChild;
                    const title = ex.exploit_title || ex.title || 'Exploit';
                    step.querySelector('[data-field="name"]').value = `Exploit: ${title.substring(0, 30)}`;
                    step.querySelector('[data-field="type"]').value = 'exploit';
                    step.querySelector('[data-field="description"]').value = `${title} (Port ${ex.port}, ${ex.service || ''} ${ex.service_version || ''}) [Confidence: ${ex.match_confidence || '?'}%]`;
                    step.querySelector('[data-field="tool"]').value = `exploit-db (ID: ${ex.exploit_db_id || ex.exploit_id})`;
                }

                if (distinctExploits.length > 0) {
                    showToast('info', 'Exploits gefunden', `${distinctExploits.length} version-kompatible Exploits wurden zur Kette hinzugefügt.`);
                } else {
                     showToast('info', 'Info', 'Keine version-kompatiblen Exploits für die ausgewählten Services gefunden. Nutzen Sie den "Angriff starten" Button für eine automatische Analyse.');
                }

            } catch(e) {
                console.warn('Failed to load exploits for chain generation', e);
            }

            // Renumber
            renumberSteps();

            showToast('info', 'Chain generiert', 'Angriffskette wurde vorbereitet.');

        } catch (e) {
            showToast('error', 'Fehler', e.message);
        }
    }

    async function loadChainStats() {
        try {
            const d = await api('/api/db-update/stats');
            const ac = d.attackChains;
            document.getElementById('chainStatTotal').textContent = ac.total || 0;
            document.getElementById('chainStatActive').textContent = ac.enabled || 0;
            document.getElementById('chainStatExecs').textContent = ac.executions || 0;
        } catch (e) { console.error('Chain stats error:', e); }
    }

    async function loadAttackChains() {
        try {
            const d = await api('/api/attack-chains');
            const chains = d.chains || d || [];
            const container = document.getElementById('chainsTableBody');

            if (chains.length > 0) {
                container.innerHTML = chains.map(c => {
                    const steps = c.steps || [];
                    const stratColors = { passive:'blue', standard:'green', aggressive:'yellow', thorough:'red' };
                    const stratLabels = { passive:'Passiv', standard:'Standard', aggressive:'Aggressiv', thorough:'Gründlich' };
                    return `<div class="chain-card">
                        <div class="chain-header">
                            <div>
                                <h4>${esc(c.name)}</h4>
                                <p class="text-muted">${esc(c.description || '')}</p>
                            </div>
                            <div class="d-flex gap-1 align-center">
                                <span class="badge badge-${stratColors[c.strategy] || 'gray'}">${stratLabels[c.strategy] || c.strategy}</span>
                                <span class="badge badge-${c.enabled ? 'green' : 'gray'}">${c.enabled ? 'Aktiv' : 'Inaktiv'}</span>
                            </div>
                        </div>
                        <div class="chain-steps">
                            ${steps.map((s, i) => `<div class="chain-step">
                                <div class="step-number">${i + 1}</div>
                                <div class="step-info">
                                    <strong>${esc(s.name || s.action || 'Schritt ' + (i+1))}</strong>
                                    <small class="text-muted">${esc(s.description || s.tool || '')}</small>
                                </div>
                            </div>${i < steps.length - 1 ? '<div class="step-arrow"><i class="bi bi-arrow-right"></i></div>' : ''}`).join('')}
                        </div>
                        <div class="chain-footer">
                            <div class="d-flex gap-1">
                                <span class="badge badge-${c.risk_level === 'critical' ? 'red' : c.risk_level === 'high' ? 'orange' : c.risk_level === 'medium' ? 'yellow' : 'blue'}">Risiko: ${esc(c.risk_level || 'medium')}</span>
                                <span class="text-muted">Tiefe: ${c.max_depth || steps.length}</span>
                            </div>
                            <div class="d-flex gap-1">
                                <button class="btn btn-primary btn-sm" onclick="showExecuteChainModal(${c.id})"><i class="bi bi-play-fill"></i> Ausführen</button>
                                <button class="btn btn-danger btn-sm" onclick="deleteChain(${c.id})"><i class="bi bi-trash"></i></button>
                            </div>
                        </div>
                    </div>`;
                }).join('');
            } else {
                container.innerHTML = '<div class="empty-state"><i class="bi bi-diagram-3"></i><h4>Keine Angriffsketten definiert</h4><p>Erstellen Sie eine neue Angriffskette.</p></div>';
            }

            // Load execution history
            loadChainExecutions();
        } catch (e) { showToast('error', 'Fehler', e.message); }
    }

    async function loadChainExecutions() {
        try {
            const d = await api('/api/attack-chains/executions/history');
            const execs = d.executions || d || [];
            const tbody = document.getElementById('chainHistoryBody');
            if (!tbody) return;
            if (execs.length > 0) {
                tbody.innerHTML = execs.map(ex => `<tr>
                    <td>#${ex.id}</td>
                    <td>${esc(ex.chain_name || 'Kette #' + ex.chain_id)}</td>
                    <td>${esc(ex.target_scan_id ? 'Scan #' + ex.target_scan_id : '-')}</td>
                    <td>${statusBadge(ex.status)}</td>
                    <td>${ex.steps_completed || 0}/${ex.steps_total || 0}</td>
                    <td>${formatDate(ex.started_at)}</td>
                    <td><button class="btn btn-outline btn-sm" onclick="showChainExecDetail(${ex.id})"><i class="bi bi-eye"></i></button></td>
                </tr>`).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">Keine Ausführungen</td></tr>';
            }
        } catch (e) { console.error('Chain exec error:', e); }
    }

    window.showChainModal = function () {
        document.getElementById('chainForm').reset();
        document.getElementById('chainStepsContainer').innerHTML = '';
        addChainStep();
        document.getElementById('chainModal').classList.add('active');
    };
    window.hideChainModal = function () { document.getElementById('chainModal').classList.remove('active'); };

    window.addChainStep = function () {
        const container = document.getElementById('chainStepsContainer');
        const idx = container.children.length;
        const div = document.createElement('div');
        div.className = 'chain-step-input';
        div.innerHTML = `
            <div class="d-flex gap-1 align-center mb-1">
                <span class="step-badge">${idx + 1}</span>
                <input type="text" class="form-control" placeholder="Schrittname" data-field="name" required>
                <select class="form-control" data-field="type" style="max-width:150px">
                    <option value="recon">Recon</option><option value="enum">Enumeration</option>
                    <option value="audit">Audit</option><option value="auth_test">Auth-Test</option>
                    <option value="vuln_scan">Vuln-Scan</option><option value="exploit">Exploit</option>
                </select>
                <button type="button" class="btn btn-danger btn-sm" onclick="this.closest('.chain-step-input').remove();renumberSteps()"><i class="bi bi-trash"></i></button>
            </div>
            <input type="text" class="form-control mb-1" placeholder="Beschreibung" data-field="description">
            <input type="text" class="form-control" placeholder="Tool (z.B. nmap, nikto)" data-field="tool">
        `;
        container.appendChild(div);
    };

    window.renumberSteps = function () {
        document.querySelectorAll('#chainStepsContainer .chain-step-input').forEach((el, i) => {
            el.querySelector('.step-badge').textContent = i + 1;
        });
    };

    window.saveChain = async function (e) {
        if (e && e.preventDefault) e.preventDefault();
        try {
            const steps = [];
            document.querySelectorAll('#chainStepsContainer .chain-step-input').forEach(el => {
                steps.push({
                    name: el.querySelector('[data-field="name"]').value,
                    type: el.querySelector('[data-field="type"]').value,
                    description: el.querySelector('[data-field="description"]').value,
                    tool: el.querySelector('[data-field="tool"]').value
                });
            });
            const data = {
                name: document.getElementById('chainFormName').value,
                description: document.getElementById('chainFormDesc').value,
                strategy: document.getElementById('chainFormStrategy').value,
                risk_level: document.getElementById('chainFormRisk').value,
                max_depth: parseInt(document.getElementById('chainFormDepth').value) || 3,
                steps_json: JSON.stringify(steps),
                preconditions_json: '[]',
                target_services: '[]',
                enabled: 1
            };
            await api('/api/attack-chains', 'POST', data);
            showToast('success', 'Erstellt', 'Angriffskette wurde erstellt.');
            hideChainModal(); loadAttackChains(); loadChainStats();
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.deleteChain = async function (id) {
        if (!confirm('Angriffskette wirklich löschen?')) return;
        try { await api(`/api/attack-chains/${id}`, 'DELETE'); showToast('success', 'Gelöscht', 'Angriffskette gelöscht.'); loadAttackChains(); loadChainStats(); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.showExecuteChainModal = function (chainId, preSelectedScanId, preSelectedTargetIp) {
        // Clear previous state
        const chainSel = document.getElementById('chainExecChainId');
        if (chainId) {
            // Ensure chains are loaded
            api('/api/attack-chains').then(d => {
                const chains = d.chains || d || [];
                chainSel.innerHTML = '<option value="">Chain wählen...</option>' +
                    chains.map(c => `<option value="${c.id}">${esc(c.name)}</option>`).join('');
                chainSel.value = chainId;
            }).catch(() => {});
        } else {
            // Load chains if dropdown empty
            if (chainSel.options.length <= 1) {
                api('/api/attack-chains').then(d => {
                    const chains = d.chains || d || [];
                    chainSel.innerHTML = '<option value="">Chain wählen...</option>' +
                        chains.map(c => `<option value="${c.id}">${esc(c.name)}</option>`).join('');
                });
            }
        }

        document.getElementById('chainExecLHOST').value = window.location.hostname;
        document.getElementById('chainExecLPORT').value = '4444';
        document.getElementById('chainExecPanel').classList.remove('hidden');

        // Setup Scan ID Dropdown
        const scanSel = document.getElementById('chainExecScanId');
        const ipSel = document.getElementById('chainExecTargetIp');

        // Reset IP selector
        ipSel.innerHTML = '<option value="">Bitte Scan wählen...</option>';

        // Setup listener for Scan ID change
        scanSel.onchange = async () => {
            const sid = scanSel.value;
            if (!sid) {
                ipSel.innerHTML = '<option value="">Bitte Scan wählen...</option>';
                return;
            }
            try {
                ipSel.innerHTML = '<option>Lade IPs...</option>';
                const res = await api(`/api/scan/results/${sid}`);
                const uniqueIPs = [...new Set((res.results || []).map(r => r.ip_address))];

                if (uniqueIPs.length > 0) {
                    ipSel.innerHTML = uniqueIPs.map(ip => `<option value="${esc(ip)}">${esc(ip)}</option>`).join('');
                    // Auto-select if only one
                    if (uniqueIPs.length === 1) ipSel.value = uniqueIPs[0];
                } else {
                    ipSel.innerHTML = '<option value="">Keine IPs gefunden</option>';
                }
            } catch(e) {
                ipSel.innerHTML = '<option value="">Fehler beim Laden</option>';
            }
        };

        // Load scans
        api('/api/scan/history').then(async d => {
            scanSel.innerHTML = '<option value="">Scan wählen...</option>' +
                (d.scans || []).filter(s => s.status === 'completed').map(s =>
                    `<option value="${s.id}">#${s.id} - ${esc(s.target)} (${formatDate(s.started_at)})</option>`
                ).join('');

            // Handle Pre-Selection
            if (preSelectedScanId) {
                scanSel.value = preSelectedScanId;
                // Trigger change to load IPs
                await scanSel.onchange();
                if (preSelectedTargetIp) {
                    ipSel.value = preSelectedTargetIp;
                }
            }
        }).catch(() => {});
    };
    window.hideExecuteChainModal = function () { document.getElementById('chainExecPanel').classList.add('hidden'); };

    window.executeChain = async function (e) {
        if (e && e.preventDefault) e.preventDefault();
        const chainId = document.getElementById('chainExecChainId').value;
        const scanId = document.getElementById('chainExecScanId').value;
        const targetIp = document.getElementById('chainExecTargetIp').value;
        const targetPort = document.getElementById('chainExecTargetPort').value;
        const lhost = document.getElementById('chainExecLHOST').value;
        const lport = document.getElementById('chainExecLPORT').value;

        if (!chainId) { showToast('warning', 'Hinweis', 'Bitte eine Angriffskette auswählen'); return; }
        if (!scanId) { showToast('warning', 'Hinweis', 'Bitte einen Scan auswählen'); return; }
        if (!targetIp) { showToast('warning', 'Hinweis', 'Bitte eine Ziel-IP auswählen'); return; }

        try {
            const params = { LHOST: lhost, LPORT: lport };
            const payload = {
                scanId: parseInt(scanId),
                targetIp: targetIp,
                params: params
            };
            if (targetPort) payload.targetPort = parseInt(targetPort);

            const d = await api(`/api/attack-chains/${chainId}/execute`, 'POST', payload);
            showToast('success', 'Gestartet', `Angriffskette wird ausgeführt. Execution #${d.executionId || d.id || ''}`);

            // Set current exec ID to allow auto-refresh
            currentChainExecId = d.executionId || d.id;

            // Show details immediately
            showChainExecDetail(currentChainExecId);

            hideExecuteChainModal();
            loadAttackChains(); loadChainStats();
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    window.showChainExecDetail = async function (execId) {
        // Update global
        currentChainExecId = execId;

        try {
            const d = await api(`/api/attack-chains/executions/${execId}`);
            const ex = d.execution || d;
            const results = ex.results ? (typeof ex.results === 'string' ? JSON.parse(ex.results) : ex.results) : [];
            const findings = ex.findings ? (typeof ex.findings === 'string' ? JSON.parse(ex.findings) : ex.findings) : [];

            // Check for shell sessions
            const shellFinding = findings.find(f => f.sessionId && (f.type === 'exploit_success' || f.category === 'Remote Shell'));

            document.getElementById('chainExecDetailContent').innerHTML = `
                <div class="detail-grid">
                    <div class="detail-item"><label>Execution ID</label><span>#${ex.id}</span></div>
                    <div class="detail-item"><label>Status</label><span>${statusBadge(ex.status)}</span></div>
                    <div class="detail-item"><label>Gestartet</label><span>${formatDate(ex.started_at)}</span></div>
                    <div class="detail-item"><label>Abgeschlossen</label><span>${formatDate(ex.completed_at)}</span></div>
                    <div class="detail-item"><label>Schritte</label><span>${ex.steps_completed || 0} / ${ex.steps_total || 0}</span></div>
                </div>

                ${shellFinding ? `
                <div class="alert alert-success mt-2 d-flex justify-between align-center" style="background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.2);padding:1rem;border-radius:var(--radius-sm)">
                    <div><strong><i class="bi bi-terminal-fill mr-1"></i> Remote Shell verfügbar!</strong><br><small>Session ID: ${shellFinding.sessionId}</small></div>
                    <button class="btn btn-primary" onclick="showShellModal('${shellFinding.sessionId}')"><i class="bi bi-terminal"></i> Verbinden</button>
                </div>` : ''}

                ${results.length > 0 ? `<h4 class="mt-2 mb-1">Ergebnisse</h4>
                <div class="chain-exec-results">${results.map((r, i) => `
                    <div class="exec-result-step">
                        <div class="step-number">${i + 1}</div>
                        <div class="step-result-info">
                            <strong>${esc(r.step || r.name || 'Schritt ' + (i+1))}</strong>
                            <span class="badge badge-${r.status === 'completed' ? 'green' : r.status === 'failed' ? 'red' : 'yellow'}">${r.status || 'pending'}</span>
                            ${r.findings && r.findings.length > 0 ?
                                `<ul class="text-muted mt-1" style="font-size:0.85rem;padding-left:1rem">${r.findings.map(f => `<li>${esc(f.title || f.category)}</li>`).join('')}</ul>`
                                : '<p class="text-muted mt-1">Keine Befunde.</p>'}
                        </div>
                    </div>
                `).join('')}</div>` : '<p class="text-muted mt-2">Keine Ergebnisse verfügbar.</p>'}`;
            document.getElementById('chainExecDetailModal').classList.add('active');
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // ========== SHELL MODULE ==========
    // ============================================
    window.showShellModal = function(sessionId) {
        document.getElementById('shellModal').classList.add('active');
        // Wait for modal to be visible for xterm to calculate size
        setTimeout(() => initShellSession(sessionId), 100);
    };

    window.hideShellModal = function() {
        document.getElementById('shellModal').classList.remove('active');
        if (currentShellWs) {
            currentShellWs.close();
            currentShellWs = null;
        }
        if (currentTerm) {
            currentTerm.dispose();
            currentTerm = null;
        }
        document.getElementById('terminal-container').innerHTML = '';
        document.getElementById('shellStatus').className = 'badge badge-gray';
        document.getElementById('shellStatus').textContent = 'Getrennt';
    };

    function initShellSession(sessionId) {
        const container = document.getElementById('terminal-container');
        if (!container) return;
        container.innerHTML = '';

        // Check if xterm is loaded
        if (typeof Terminal === 'undefined') {
            container.innerHTML = '<div style="color:red;padding:1rem">Fehler: Terminal-Bibliothek nicht geladen.</div>';
            return;
        }

        const term = new Terminal({
            cursorBlink: true,
            theme: {
                background: '#000000',
                foreground: '#ffffff'
            }
        });

        fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);

        term.open(container);
        fitAddon.fit();
        currentTerm = term;

        window.addEventListener('resize', () => fitAddon.fit());

        // Connect WebSocket
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/api/shell/${sessionId}`;
        const ws = new WebSocket(wsUrl);
        currentShellWs = ws;

        term.write('\r\n\x1b[33mConnecting to shell session...\x1b[0m\r\n');

        ws.onopen = () => {
            term.write('\r\n\x1b[32mConnected!\x1b[0m\r\n');
            document.getElementById('shellStatus').className = 'badge badge-green';
            document.getElementById('shellStatus').textContent = 'Verbunden';
            term.focus();
        };

        ws.onmessage = (event) => {
            term.write(event.data);
        };

        ws.onclose = () => {
            term.write('\r\n\x1b[31mConnection closed.\x1b[0m\r\n');
            document.getElementById('shellStatus').className = 'badge badge-red';
            document.getElementById('shellStatus').textContent = 'Getrennt';
        };

        ws.onerror = (err) => {
            term.write('\r\n\x1b[31mConnection error.\x1b[0m\r\n');
        };

        term.onData((data) => {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(data);
            }
        });
    }
    window.hideChainExecDetailModal = function () {
        document.getElementById('chainExecDetailModal').classList.remove('active');
        currentChainExecId = null; // Reset monitoring
    };

    // ============================================
    // ========== SECURITY AUDIT MODULE ==========
    // ============================================

    window.generateAudit = async function () {
        const scanId = document.getElementById('auditScanId').value;
        const auditType = document.getElementById('auditType').value;
        if (!scanId) { showToast('warning', 'Hinweis', 'Bitte einen Scan auswählen'); return; }

        const btn = document.getElementById('generateAuditBtn');
        const origText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Generiere Audit...';

        try {
            const d = await api('/api/audits/generate', 'POST', { scanId: parseInt(scanId), auditType });
            const aid = d.auditId || d.id;
            showToast('success', 'Audit erstellt', `Security-Audit #${aid} wurde generiert.`);
            loadAuditHistory();
            if (aid) showAuditDetail(aid);
        } catch (e) { showToast('error', 'Fehler', e.message); }
        finally { btn.disabled = false; btn.innerHTML = origText; }
    };

    async function loadAuditHistory() {
        try {
            const d = await api('/api/audits');
            const audits = d.audits || d || [];
            const tbody = document.getElementById('auditHistoryBody');

            // Load scans for the generator dropdown
            try {
                const scans = await api('/api/scan/history');
                const sel = document.getElementById('auditScanId');
                if (sel) {
                    sel.innerHTML = '<option value="">Scan wählen...</option>' +
                        (scans.scans || []).filter(s => s.status === 'completed').map(s =>
                            `<option value="${s.id}">#${s.id} - ${esc(s.target)} (${formatDate(s.started_at)})</option>`
                        ).join('');
                }
            } catch (e) {}

            if (audits.length > 0) {
                tbody.innerHTML = audits.map(a => {
                    const scoreColor = a.overall_score >= 80 ? 'green' : a.overall_score >= 60 ? 'yellow' : a.overall_score >= 40 ? 'orange' : 'red';
                    return `<tr>
                        <td>#${a.id}</td>
                        <td>Scan #${a.scan_id}</td>
                        <td><span class="badge badge-blue">${esc(a.audit_type || 'full')}</span></td>
                        <td><span class="audit-score-inline badge badge-${scoreColor}">${Math.round(a.overall_score || 0)}/100</span></td>
                        <td>${severityBadge(a.risk_rating)}</td>
                        <td>${a.findings_count || 0}</td>
                        <td>${formatDate(a.generated_at)}</td>
                        <td>
                            <div class="d-flex gap-1">
                                <button class="btn btn-outline btn-sm" onclick="showAuditDetail(${a.id})"><i class="bi bi-eye"></i> Details</button>
                                <button class="btn btn-danger btn-sm" onclick="deleteAudit(${a.id})"><i class="bi bi-trash"></i></button>
                            </div>
                        </td>
                    </tr>`;
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">Keine Audits vorhanden. Generieren Sie einen Audit aus einem abgeschlossenen Scan.</td></tr>';
            }
        } catch (e) { showToast('error', 'Fehler', e.message); }
    }

    window.showAuditDetail = async function (auditId) {
        try {
            const d = await api(`/api/audits/${auditId}`);
            const a = d.audit || d;
            const findings = a.findings || [];
            const recommendations = a.recommendations_json ? (typeof a.recommendations_json === 'string' ? JSON.parse(a.recommendations_json) : a.recommendations_json) : [];
            const compliance = a.compliance_json ? (typeof a.compliance_json === 'string' ? JSON.parse(a.compliance_json) : a.compliance_json) : {};

            const scoreColor = a.overall_score >= 80 ? '#22c55e' : a.overall_score >= 60 ? '#f59e0b' : a.overall_score >= 40 ? '#f97316' : '#ef4444';

            document.getElementById('auditDetailContent').innerHTML = `
                <div class="audit-detail-header">
                    <div class="audit-score-circle" style="--score-color: ${scoreColor}">
                        <svg viewBox="0 0 120 120" width="120" height="120">
                            <circle cx="60" cy="60" r="54" fill="none" stroke="var(--bg-tertiary)" stroke-width="8"/>
                            <circle cx="60" cy="60" r="54" fill="none" stroke="${scoreColor}" stroke-width="8"
                                stroke-dasharray="${(a.overall_score / 100) * 339.3} 339.3"
                                stroke-linecap="round" transform="rotate(-90 60 60)"/>
                            <text x="60" y="55" text-anchor="middle" fill="${scoreColor}" font-size="28" font-weight="bold">${Math.round(a.overall_score || 0)}</text>
                            <text x="60" y="75" text-anchor="middle" fill="var(--text-secondary)" font-size="12">von 100</text>
                        </svg>
                    </div>
                    <div class="audit-summary-info">
                        <h3>Security-Audit #${a.id}</h3>
                        <p>Risikobewertung: ${severityBadge(a.risk_rating)}</p>
                        <p>${esc(a.executive_summary || '')}</p>
                        <div class="audit-counts">
                            <span class="badge badge-red">Kritisch: ${a.critical_count || 0}</span>
                            <span class="badge badge-orange">Hoch: ${a.high_count || 0}</span>
                            <span class="badge badge-yellow">Mittel: ${a.medium_count || 0}</span>
                            <span class="badge badge-blue">Niedrig: ${a.low_count || 0}</span>
                            <span class="badge badge-gray">Info: ${a.info_count || 0}</span>
                        </div>
                    </div>
                </div>

                ${Object.keys(compliance).length > 0 ? `
                <h4 class="mt-2 mb-1"><i class="bi bi-shield-check mr-1"></i>Compliance-Prüfungen</h4>
                <div class="compliance-grid">
                    ${Object.entries(compliance).map(([key, val]) => `
                        <div class="compliance-item ${val.status === 'pass' ? 'pass' : val.status === 'fail' ? 'fail' : 'warn'}">
                            <i class="bi bi-${val.status === 'pass' ? 'check-circle-fill' : val.status === 'fail' ? 'x-circle-fill' : 'exclamation-triangle-fill'}"></i>
                            <span>${esc(val.label || key)}</span>
                        </div>
                    `).join('')}
                </div>` : ''}

                ${findings.length > 0 ? `
                <h4 class="mt-2 mb-1"><i class="bi bi-bug mr-1"></i>Findings (${findings.length})</h4>
                <div class="table-container"><table class="data-table"><thead><tr>
                    <th>Severity</th><th>Kategorie</th><th>Titel</th><th>Asset</th><th>Port</th><th>Remediation</th>
                </tr></thead><tbody>
                ${findings.map(f => `<tr>
                    <td>${severityBadge(f.severity)}</td>
                    <td>${esc(f.category || '-')}</td>
                    <td><strong>${esc(f.title)}</strong><br><small class="text-muted">${esc(f.description || '')}</small></td>
                    <td>${esc(f.affected_asset || '-')}</td>
                    <td>${f.affected_port || '-'}</td>
                    <td>${esc(f.remediation || '-')}</td>
                </tr>`).join('')}
                </tbody></table></div>` : ''}

                ${recommendations.length > 0 ? `
                <h4 class="mt-2 mb-1"><i class="bi bi-lightbulb mr-1"></i>Empfehlungen</h4>
                <div class="recommendations-list">
                    ${recommendations.map((r, i) => `
                        <div class="recommendation-item">
                            <div class="rec-number">${i + 1}</div>
                            <div class="rec-content">
                                <strong>${esc(typeof r === 'string' ? r : r.title || r.text || '')}</strong>
                                ${r.description ? `<p class="text-muted">${esc(r.description)}</p>` : ''}
                                ${r.priority ? `<span class="badge badge-${r.priority === 'high' ? 'red' : r.priority === 'medium' ? 'yellow' : 'blue'}">Priorität: ${r.priority}</span>` : ''}
                            </div>
                        </div>
                    `).join('')}
                </div>` : ''}
            `;
            document.getElementById('auditDetailModal').classList.add('active');
        } catch (e) { showToast('error', 'Fehler', e.message); }
    };
    window.hideAuditDetailModal = function () { document.getElementById('auditDetailModal').classList.remove('active'); };

    window.deleteAudit = async function (id) {
        if (!confirm('Audit wirklich löschen?')) return;
        try { await api(`/api/audits/${id}`, 'DELETE'); showToast('success', 'Gelöscht', 'Audit gelöscht.'); loadAuditHistory(); } catch (e) { showToast('error', 'Fehler', e.message); }
    };

    // ============================================
    // ========== DB UPDATE HISTORY ==========
    // ============================================
    async function loadDbUpdateHistory() {
        try {
            const d = await api('/api/db-update/history');
            const logs = d.logs || [];
            // Update fingerprint view
            const fpHist = document.getElementById('fpUpdateHistory');
            if (fpHist) {
                const fpLogs = logs.filter(l => l.database_type === 'fingerprints');
                fpHist.innerHTML = fpLogs.length > 0 ? fpLogs.slice(0, 5).map(l => `
                    <div class="update-log-item">
                        <span class="badge badge-${l.status === 'completed' ? 'green' : l.status === 'failed' ? 'red' : 'yellow'}">${l.status}</span>
                        <span>+${l.records_added || 0} Einträge</span>
                        <span class="text-muted">${formatDate(l.completed_at || l.started_at)}</span>
                    </div>
                `).join('') : '<p class="text-muted">Keine Updates durchgeführt</p>';
            }
            // Update exploit view
            const exHist = document.getElementById('exploitUpdateHistory');
            if (exHist) {
                const exLogs = logs.filter(l => l.database_type === 'exploits');
                exHist.innerHTML = exLogs.length > 0 ? exLogs.slice(0, 5).map(l => `
                    <div class="update-log-item">
                        <span class="badge badge-${l.status === 'completed' ? 'green' : l.status === 'failed' ? 'red' : 'yellow'}">${l.status}</span>
                        <span>+${l.records_added || 0} Einträge</span>
                        <span class="text-muted">${formatDate(l.completed_at || l.started_at)}</span>
                    </div>
                `).join('') : '<p class="text-muted">Keine Updates durchgeführt</p>';
            }
        } catch (e) { console.error('DB update history error:', e); }
    }

    // ============================================
    // Pagination Helper
    // ============================================
    function renderPagination(containerId, pag, callback) {
        const container = document.getElementById(containerId);
        if (!container || !pag || !pag.totalPages) { if (container) container.innerHTML = ''; return; }
        if (pag.totalPages <= 1) { container.innerHTML = ''; return; }

        let html = '<div class="pagination">';
        // Previous
        if (pag.page > 1) html += `<button class="btn btn-outline btn-sm" onclick="window._pagCb_${containerId}(${pag.page - 1})"><i class="bi bi-chevron-left"></i></button>`;

        // Page numbers
        const start = Math.max(1, pag.page - 2);
        const end = Math.min(pag.totalPages, pag.page + 2);
        if (start > 1) html += `<button class="btn btn-outline btn-sm" onclick="window._pagCb_${containerId}(1)">1</button>`;
        if (start > 2) html += '<span class="pagination-dots">...</span>';
        for (let i = start; i <= end; i++) {
            html += `<button class="btn ${i === pag.page ? 'btn-primary' : 'btn-outline'} btn-sm" onclick="window._pagCb_${containerId}(${i})">${i}</button>`;
        }
        if (end < pag.totalPages - 1) html += '<span class="pagination-dots">...</span>';
        if (end < pag.totalPages) html += `<button class="btn btn-outline btn-sm" onclick="window._pagCb_${containerId}(${pag.totalPages})">${pag.totalPages}</button>`;

        // Next
        if (pag.page < pag.totalPages) html += `<button class="btn btn-outline btn-sm" onclick="window._pagCb_${containerId}(${pag.page + 1})"><i class="bi bi-chevron-right"></i></button>`;

        html += `</div><div class="pagination-info">Seite ${pag.page} von ${pag.totalPages} (${pag.total} Einträge)</div>`;
        container.innerHTML = html;
        window[`_pagCb_${containerId}`] = callback;
    }

    // ============================================
    // Initialize
    // ============================================
    function init() {
        // Apply saved theme
        const savedTheme = localStorage.getItem('theme') || 'dark';
        document.documentElement.setAttribute('data-theme', savedTheme);
        document.getElementById('themeIcon').className = savedTheme === 'dark' ? 'bi bi-moon-stars' : 'bi bi-sun';

        // Enhance accessibility for sidebar navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.setAttribute('role', 'button');
            item.setAttribute('tabindex', '0');
            item.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    item.click();
                }
            });
        });

        checkAuth();
    }

    // Close modals on outside click
    document.addEventListener('click', (e) => {
        if (e.target.classList.contains('modal-overlay')) {
            e.target.classList.remove('active');
        }
    });

    // Close modals on Escape
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
        }
    });

    init();
})();