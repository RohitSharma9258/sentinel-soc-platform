/**
 * Smart WiFi Intruder Detection System - Main JavaScript
 * Dashboard interactions, API calls, and UI management.
 */

// ── Toast Notifications ─────────────────────────────────────────────────────
function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    
    const toast = document.createElement('div');
    const icons = { 
        success: '✓', 
        error: '⚠', 
        info: 'ℹ', 
        warning: '⚡' 
    };
    
    toast.className = `toast toast-${type} animate-slide-in`;
    toast.innerHTML = `
        <div class="toast-icon">${icons[type] || 'ℹ'}</div>
        <div class="toast-content">
            <div class="toast-title">${type.toUpperCase()}</div>
            <div class="toast-message">${message}</div>
        </div>
        <div class="toast-close" onclick="this.parentElement.remove()">×</div>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove after 5 seconds
    setTimeout(() => { 
        toast.classList.add('animate-fade-out');
        setTimeout(() => toast.remove(), 500); 
    }, 5000);
}

// ── API Helper ──────────────────────────────────────────────────────────────
async function api(url, method = 'GET', body = null) {
    try {
        const opts = { 
            method, 
            headers: { 'Content-Type': 'application/json' } 
        };
        
        if (body) {
            opts.body = JSON.stringify(body);
        } else if (method !== 'GET') {
            opts.body = JSON.stringify({});
        }

        const res = await fetch(url, opts);
        const data = await res.json().catch(() => ({}));
        
        if (!res.ok) {
            // Handle both data.error and data.message from backend
            const errorMsg = data.error || data.message || `HTTP ${res.status}: ${res.statusText}`;
            throw new Error(errorMsg);
        }
        
        return data;
    } catch (e) {
        console.error(`API Error [${method} ${url}]:`, e);
        // Show exact backend reason in toast
        showToast(e.message, 'error');
        return { success: false, error: e.message };
    }
}

// ── Scan Network ────────────────────────────────────────────────────────────
async function triggerScan() {
    const btn = document.getElementById('scan-btn');
    if (btn) { 
        btn.disabled = true; 
        btn.innerHTML = '<span class="spinner"></span> Scanning Subnet...'; 
    }
    
    showToast('Initiating network discovery...', 'info');
    
    const data = await api('/scan', 'POST');
    
    if (data.success) {
        showToast(`Scan complete: ${data.devices_found} devices found in ${data.scan_time}s`, 'success');
        refreshAll();
    } else {
        showToast('Scan failed: ' + (data.error || 'Unknown network error'), 'error');
    }
    
    if (btn) { 
        btn.disabled = false; 
        btn.innerHTML = '🔍 Scan Now'; 
    }
}

// ── Block / Unblock ─────────────────────────────────────────────────────────
async function blockDevice(ip) {
    if (!confirm(`⚠️ WARNING: Are you sure you want to BLOCK ${ip}?\n\nThis will trigger firewall isolation and gateway-level disruption.`)) return;
    
    showToast(`Deploying block on ${ip}...`, 'warning');
    const data = await api(`/block/${ip}`, 'POST', { reason: 'Manual block from dashboard' });
    
    if (data.success) {
        // Show the success message from the backend (message or details)
        showToast(data.message || `Device ${ip} isolated successfully.`, 'success');
        refreshAll();
    } else {
        // Backend returns error reason in data.message or data.error
        showToast('Block Failed: ' + (data.error || data.message || 'Unknown network error'), 'error');
    }
}

async function unblockDevice(ip) {
    showToast(`Restoring access for ${ip}...`, 'info');
    const data = await api(`/unblock/${ip}`, 'POST');
    
    if (data.success) {
        // Use exact backend message
        showToast(data.message || `${ip} unblocked and isolation stopped.`, 'success');
        refreshAll();
    } else {
        // Prioritize data.message as it contains the human-readable explanation
        const errorReason = data.message || data.error || 'Unknown network error';
        showToast('Unblock failed: ' + errorReason, 'error');
    }
}

// ── Trust / Untrust Device ──────────────────────────────────────────────────
async function trustDevice(mac, name) {
    const deviceName = prompt('Enter a name for this trusted device:', name || 'My Device');
    if (!deviceName) return;
    const data = await api('/known-devices/add', 'POST', { mac, name: deviceName, device_type: 'personal' });
    if (data.success) {
        showToast(`Device ${mac} marked as trusted`, 'success');
        refreshAll();
    } else {
        showToast('Failed to trust device: ' + (data.error || ''), 'error');
    }
}

async function untrustDevice(mac) {
    if (!confirm(`Remove ${mac} from trusted list?`)) return;
    const data = await api('/known-devices/remove', 'POST', { mac });
    if (data.success) {
        showToast('Device removed from trusted list', 'success');
        refreshAll();
    } else {
        showToast('Failed to remove device', 'error');
    }
}

// ── Resolve Threat ──────────────────────────────────────────────────────────
async function resolveThreat(id) {
    const data = await api(`/resolve-threat/${id}`, 'POST');
    if (data.success) { 
        showToast('Threat resolved and dismissed', 'success'); 
        refreshAll(); 
    }
}

// ── Load Devices Table ──────────────────────────────────────────────────────
let _currentDevices = [];

// NDR: OS type → icon mapping
const OS_ICONS = {
    'Windows':  '🪟',
    'Linux':    '🐧',
    'macOS':    '🍎',
    'Android':  '🤖',
    'iPhone':   '📱',
    'Router':   '📡',
    'IoT':      '💡',
    'Printer':  '🖨️',
    'Smart TV': '📺',
    'Unknown':  '❓',
};

function showDeviceDetails(mac) {
    const d = _currentDevices.find(dev => dev.mac === mac);
    if (!d) return;
    const osInfo = d.os_type && d.os_type !== 'Unknown' ? `${d.os_type} (${d.os_confidence || 0}% conf.)` : 'Unknown';
    const vendorRisk = d.vendor_risk ? d.vendor_risk.toUpperCase() : '—';
    const rogueFlag = d.is_randomized_mac ? '⚠️ RANDOMIZED MAC' : '';
    alert(`🛡️ NetGuard NDR Device Intelligence
────────────────────────────────────────
IP Address:    ${d.ip}
MAC Address:   ${d.mac} ${rogueFlag}
Hostname:      ${d.hostname || 'Unknown'}
Vendor:        ${d.vendor || 'Unknown'} [Risk: ${vendorRisk}]
OS / Type:     ${osInfo}
Device Class:  ${d.device_class || 'unknown'}
Status:        ${(d.status || 'unknown').toUpperCase()} ${d.is_blocked ? '(BLOCKED)' : ''}
Threat Level:  ${(d.threat_level || 'none').toUpperCase()}
AI Risk Score: ${d.ai_risk_score || 0}%

AI Factors:
${d.ai_reasons && d.ai_reasons.length ? d.ai_reasons.map(r => `• ${r}`).join('\n') : '• No anomalies detected'}`);
}

async function loadDevices(filter = 'all', search = '') {
    const params = new URLSearchParams({ filter, search });
    const data = await api(`/devices?${params}`);
    const tbody = document.getElementById('devices-tbody');
    if (!tbody || !data.success) return;

    if (!data.devices.length) {
        tbody.innerHTML = `<tr><td colspan="10" class="empty-state"><div class="icon">📡</div><p>No active devices found in current subnet.</p></td></tr>`;
        return;
    }

    _currentDevices = data.devices || [];

    tbody.innerHTML = data.devices.map(d => {
        let statusBadge = '';
        if (d.is_blocked) {
            statusBadge = `<span class="badge" style="background: rgba(255, 159, 67, 0.15); color: var(--orange); border: 1px solid rgba(255, 159, 67, 0.2);">● BLOCKED</span>`;
        } else if (d.status === 'threat' || (d.threat_level && d.threat_level !== 'none')) {
            statusBadge = `<span class="badge" style="background: rgba(255, 59, 92, 0.15); color: var(--red); border: 1px solid rgba(255, 59, 92, 0.25);">● THREAT</span>`;
        } else if (d.status === 'online') {
            statusBadge = `<span class="badge badge-online" style="border: 1px solid rgba(0, 255, 136, 0.2);">● ONLINE</span>`;
        } else if (d.status === 'idle') {
            statusBadge = `<span class="badge" style="background: rgba(255, 159, 67, 0.1); color: var(--orange); border: 1px solid rgba(255, 159, 67, 0.15);">● IDLE</span>`;
        } else {
            statusBadge = `<span class="badge badge-offline" style="border: 1px solid rgba(255, 255, 255, 0.05);">● OFFLINE</span>`;
        }
        
        let threatBadge = '<span style="color:var(--text-muted)">—</span>';
        if (d.threat_level && d.threat_level !== 'none') {
            const lvl = d.threat_level.toLowerCase();
            threatBadge = `<span class="badge badge-${lvl}">${lvl.toUpperCase()}</span>`;
        }
            
        let riskColor = 'var(--text-muted)';
        if (d.ai_risk_score >= 75) riskColor = 'var(--red)';
        else if (d.ai_risk_score >= 40) riskColor = 'var(--orange)';
        else if (d.ai_risk_score > 0) riskColor = 'var(--cyan)';
        const riskHtml = `<span style="color:${riskColor}; font-weight:700;">${d.ai_risk_score || 0}%</span>`;

        let lastSeenStr = '—';
        let lastSeenTitle = '';
        if (d.last_seen) {
            try {
                const dt = new Date(d.last_seen);
                if (!isNaN(dt.getTime())) {
                    lastSeenTitle = dt.toLocaleString();
                    const diffSeconds = Math.floor((new Date() - dt) / 1000);
                    if (diffSeconds < 10) {
                        lastSeenStr = 'Just now';
                    } else if (diffSeconds < 60) {
                        lastSeenStr = `${diffSeconds}s ago`;
                    } else if (diffSeconds < 3600) {
                        const mins = Math.floor(diffSeconds / 60);
                        lastSeenStr = `${mins}m ago`;
                    } else if (diffSeconds < 86400) {
                        const hrs = Math.floor(diffSeconds / 3600);
                        lastSeenStr = `${hrs}h ago`;
                    } else {
                        lastSeenStr = dt.toLocaleDateString();
                    }
                }
            } catch (e) {
                lastSeenStr = d.last_seen;
            }
        }

        let actions = '<div class="actions-cell">';
        if (d.is_blocked) {
            actions += `<button class="table-btn-action" onclick="unblockDevice('${d.ip}')" title="Unblock IP">🔓</button>`;
        } else {
            actions += `<button class="table-btn-action danger" onclick="blockDevice('${d.ip}')" title="Block IP">🚫</button>`;
        }
        
        if (d.is_known) {
            actions += `<button class="table-btn-action" onclick="untrustDevice('${d.mac}')" title="Untrust Device">🌟</button>`;
        } else {
            actions += `<button class="table-btn-action" onclick="trustDevice('${d.mac}','${d.hostname}')" title="Trust Device">⭐</button>`;
        }
        
        actions += `<button class="table-btn-action" onclick="showDeviceDetails('${d.mac}')" title="View Info">👁️</button>`;
        actions += '</div>';

        // NDR: OS Fingerprint badge
        const osType = d.os_type || 'Unknown';
        const osIcon = OS_ICONS[osType] || '❓';
        const osConf = d.os_confidence || 0;
        let osBadge = `<span style="color:var(--text-muted)">—</span>`;
        if (osType && osType !== 'Unknown') {
            const osColor = osConf >= 70 ? 'var(--cyan)' : 'var(--text-secondary)';
            osBadge = `<span style="color:${osColor}; font-size:11px; display:flex; align-items:center; gap:4px;">
                ${osIcon} <span style="font-weight:600;">${osType}</span>
                <span style="color:var(--text-muted); font-size:10px;">${osConf}%</span>
            </span>`;
        }

        // NDR: Rogue device indicator overlay
        const isRogue = d.is_randomized_mac || (d.vendor_risk === 'high');
        const rogueTag = isRogue
            ? `<span style="margin-left:4px; font-size:9px; padding:1px 5px; border-radius:3px; background:rgba(239,68,68,0.15); color:#f87171; border:1px solid rgba(239,68,68,0.3);">ROGUE?</span>`
            : '';

        return `<tr class="${isRogue ? 'row-rogue-highlight' : ''}">
            <td class="font-mono">${d.ip}</td>
            <td class="font-mono" style="font-size:11px;">${d.mac}${rogueTag}</td>
            <td class="text-col">${d.hostname || '—'}</td>
            <td class="text-col" style="font-size:11px;">${d.vendor || 'Unknown'}</td>
            <td>${osBadge}</td>
            <td>${statusBadge}</td>
            <td>${threatBadge}</td>
            <td>${riskHtml}</td>
            <td title="${lastSeenTitle}">${lastSeenStr}</td>
            <td>${actions}</td>
        </tr>`;
    }).join('');
}

// ── Load Threats Table ──────────────────────────────────────────────────────
async function loadThreats(level = 'all') {
    const params = level !== 'all' ? `?level=${level}` : '';
    const data = await api(`/threats${params}`);
    const tbody = document.getElementById('threats-tbody');
    if (!tbody || !data.success) return;

    if (!data.threats.length) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state"><div class="icon">🛡️</div><p>No active threats detected.</p></td></tr>`;
        return;
    }

    tbody.innerHTML = data.threats.map(t => {
        const levelBadge = `<span class="badge badge-${t.threat_level}">${t.threat_level.toUpperCase()}</span>`;
        const statusBadge = t.resolved
            ? '<span class="badge badge-online">● RESOLVED</span>'
            : '<span class="badge badge-critical" style="animation: pulse 2s infinite;">● ACTIVE</span>';
        const time = t.detected_at ? new Date(t.detected_at).toLocaleString() : '—';
        
        let actions = '<div class="actions-cell">';
        if (!t.resolved) {
            actions += `<button class="table-btn-action" onclick="resolveThreat(${t.id})" title="Dismiss Threat">✓</button>`;
            if (t.device_ip) {
                actions += `<button class="table-btn-action danger" onclick="blockDevice('${t.device_ip}')" title="Block Device">🚫</button>`;
            }
        } else {
            actions += '<span style="color:var(--text-muted)">Resolved</span>';
        }
        actions += '</div>';

        return `<tr>
            <td class="font-mono">${time}</td>
            <td class="font-mono">${t.device_ip || '—'}</td>
            <td class="font-mono">${t.device_mac || '—'}</td>
            <td class="text-col">${t.threat_type}</td>
            <td>${levelBadge}</td>
            <td><b style="color:var(--orange)">${t.threat_score}</b></td>
            <td>${statusBadge}</td>
            <td>${actions}</td>
        </tr>`;
    }).join('');
}

// ── Load Logs ───────────────────────────────────────────────────────────────
let logFilterLevel = 'ALL';

function filterLogs(level) {
    logFilterLevel = level;
    loadLogs(25);
}

async function loadLogs(limit = 100) {
    const data = await api(`/logs?limit=${limit}`);
    const container = document.getElementById('logs-container');
    if (!container || !data.success) return;

    let logs = data.logs || [];
    if (logFilterLevel !== 'ALL') {
        logs = logs.filter(l => {
            if (logFilterLevel === 'CRITICAL') return l.level === 'CRITICAL' || l.level === 'ERROR';
            if (logFilterLevel === 'WARNING') return l.level === 'WARNING';
            if (logFilterLevel === 'INFO') return l.level === 'INFO';
            return true;
        });
    }

    container.innerHTML = logs.map(l => {
        const time = l.timestamp ? new Date(l.timestamp).toLocaleTimeString() : '';
        
        let icon = 'ℹ️';
        let iconClass = 'info';
        let sevBadgeClass = 'info';
        
        if (l.level === 'CRITICAL') {
            icon = '💀';
            iconClass = 'crit';
            sevBadgeClass = 'critical';
        } else if (l.level === 'ERROR') {
            icon = '⚠️';
            iconClass = 'crit';
            sevBadgeClass = 'high';
        } else if (l.level === 'WARNING') {
            icon = '⚡';
            iconClass = 'warn';
            sevBadgeClass = 'medium';
        }
        
        return `<div class="timeline-entry">
            <span class="timeline-time">${time}</span>
            <span class="timeline-icon-wrap ${iconClass}">${icon}</span>
            <div class="timeline-content-wrap">
                <span class="timeline-desc">${l.message}</span>
                <span class="timeline-sev-badge ${sevBadgeClass}">${l.level}</span>
            </div>
        </div>`;
    }).join('');
    
    // Auto scroll to bottom
    container.scrollTop = container.scrollHeight;
}

// ── Threat Donut Chart Renderer ─────────────────────────────────────────────
function drawThreatDonut(canvasId, activeCount) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    
    canvas.width = canvas.clientWidth * window.devicePixelRatio;
    canvas.height = canvas.clientHeight * window.devicePixelRatio;
    
    const ctx = canvas.getContext('2d');
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);
    ctx.clearRect(0, 0, canvas.clientWidth, canvas.clientHeight);
    
    const cx = canvas.clientWidth / 2;
    const cy = canvas.clientHeight / 2;
    const outerRadius = Math.min(canvas.clientWidth, canvas.clientHeight) / 2 - 4;
    const innerRadius = outerRadius - 10;
    
    const slices = [
        { val: Math.round(activeCount * 0.25) || (activeCount > 0 ? 1 : 0), color: '#ff3b5c', label: 'Critical' },
        { val: Math.round(activeCount * 0.35) || (activeCount > 0 ? 1 : 0), color: '#ff9f43', label: 'High' },
        { val: Math.round(activeCount * 0.30) || 0, color: '#ffd93d', label: 'Medium' },
        { val: Math.round(activeCount * 0.10) || 0, color: '#00ff88', label: 'Low' }
    ];
    
    let total = slices.reduce((acc, s) => acc + s.val, 0);
    if (activeCount > 0 && total === 0) {
        slices[0].val = activeCount;
        total = activeCount;
    }
    
    const donutThreatEl = document.getElementById('donut-threat-count');
    if (donutThreatEl) {
        donutThreatEl.textContent = activeCount;
    }
    
    let currentAngle = -Math.PI / 2;
    
    if (total === 0) {
        ctx.beginPath();
        ctx.arc(cx, cy, outerRadius, 0, 2 * Math.PI);
        ctx.arc(cx, cy, innerRadius, 2 * Math.PI, 0, true);
        ctx.closePath();
        ctx.fillStyle = 'rgba(255, 255, 255, 0.05)';
        ctx.fill();
    } else {
        slices.forEach(slice => {
            if (slice.val === 0) return;
            const sliceAngle = (slice.val / total) * 2 * Math.PI;
            
            ctx.beginPath();
            ctx.arc(cx, cy, outerRadius, currentAngle, currentAngle + sliceAngle);
            ctx.arc(cx, cy, innerRadius, currentAngle + sliceAngle, currentAngle, true);
            ctx.closePath();
            
            ctx.fillStyle = slice.color;
            ctx.fill();
            
            currentAngle += sliceAngle;
        });
    }
    
    const legendContainer = document.getElementById('donut-legend-container');
    if (legendContainer) {
        legendContainer.innerHTML = slices.map(s => {
            return `<span class="legend-item">
                <span class="legend-color-dot" style="background:${s.color}"></span>
                ${s.label}: <b>${s.val}</b>
            </span>`;
        }).join('');
    }
}

// ── Traffic Chart Mode toggle ───────────────────────────────────────────────
let trafficChartMode = 'pps';
function setTrafficMode(mode) {
    trafficChartMode = mode;
    document.querySelectorAll('.toggle-pills .pill').forEach(pill => {
        pill.classList.toggle('active', pill.textContent.trim() === mode);
    });
}

// ── Update Dashboard Stats ──────────────────────────────────────────────────
async function updateStats() {
    const data = await api('/live-status');
    if (!data.success) return;

    const s = data.stats;
    const setVal = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };

    setVal('stat-total', s.total_devices);
    setVal('stat-online', s.online_devices);
    setVal('stat-threats', s.active_threats);
    setVal('stat-blocked', s.blocked_devices);
    setVal('stat-known', s.known_devices);

    if (data.ai_predictions) setVal('stat-ai', data.ai_predictions.length);
    if (data.sniffer) setVal('stat-packets', data.sniffer.total_packets.toLocaleString());

    const statusEl = document.getElementById('scanner-status');
    if (statusEl) {
        statusEl.className = `status-dot ${data.scanner_running ? 'online' : 'offline'}`;
    }
    
    // Draw threat donut chart
    drawThreatDonut('threat-donut-canvas', s.active_threats || 0);
    
    // Update SVG health ring progress
    const healthRing = document.getElementById('health-ring');
    const healthVal = document.getElementById('stat-health');
    if (healthVal && healthRing) {
        const score = s.active_threats > 0 ? Math.max(12, Math.round(100 - s.active_threats * 11)) : 98.6;
        healthVal.textContent = score + '%';
        const circumference = 2 * Math.PI * 24;
        const strokeDashoffset = circumference - (score / 100) * circumference;
        healthRing.style.strokeDashoffset = strokeDashoffset;
        
        const descEl = document.querySelector('.health-status-desc');
        if (descEl) {
            if (score > 90) { descEl.textContent = 'Excellent'; descEl.style.color = '#00ff88'; }
            else if (score > 70) { descEl.textContent = 'Good'; descEl.style.color = '#00d4ff'; }
            else if (score > 50) { descEl.textContent = 'Warning'; descEl.style.color = '#ff9f43'; }
            else { descEl.textContent = 'Critical'; descEl.style.color = '#ff3b5c'; }
        }
    }
}

async function toggleAntigravity() {
    const btn = document.getElementById('antigravity-btn');
    if (!btn) return;
    
    btn.disabled = true;
    const data = await api('/antigravity/toggle', 'POST');
    btn.disabled = false;
    
    if (data.success) {
        const mode = data.mode;
        btn.textContent = mode ? '🚀 Antigravity: ON' : '🛡️ Antigravity: OFF';
        btn.className = mode ? 'btn btn-warning' : 'btn btn-ghost';
        showToast(data.message, mode ? 'warning' : 'info');
    }
}

// ── Export Functions ─────────────────────────────────────────────────────────
function exportCSV(type = 'devices') {
    window.open(`/export/csv?type=${type}`, '_blank');
    showToast(`Exporting ${type} report...`, 'info');
}

function exportPDF() {
    window.open('/export/pdf', '_blank');
    showToast('Generating security report...', 'info');
}

// ── Filter Handling ─────────────────────────────────────────────────────────
let currentFilter = 'all';
let currentSearch = '';

function setFilter(filter) {
    currentFilter = filter;
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });
    loadDevices(filter, currentSearch);
}

function handleSearch(e) {
    currentSearch = e.target.value;
    loadDevices(currentFilter, currentSearch);
}

// ── AI Predictions Panel ─────────────────────────────────────────────────────
let _aiPredictionsData = [];

function aiFilterTab(btn, level) {
    document.querySelectorAll('.ai-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderAICards(_aiPredictionsData, level);
}

function _aiScoreDial(score, color) {
    const r = 26, cx = 30, cy = 30;
    const circ = 2 * Math.PI * r;
    const filled = circ * (score / 100);
    return `<svg width="60" height="60" style="transform:rotate(-90deg)">
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="rgba(255,255,255,0.07)" stroke-width="5"/>
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${color}" stroke-width="5"
            stroke-dasharray="${filled} ${circ}" stroke-linecap="round"
            style="transition:stroke-dasharray 0.8s ease"/>
    </svg>
    <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">
        <div style="font-size:14px;font-weight:800;color:${color};line-height:1">${score}</div>
        <div style="font-size:8px;color:${color};font-weight:600;opacity:0.8">RISK</div>
    </div>`;
}

function _aiFactorBar(label, val, max, color) {
    const pct = Math.min(100, (val / max) * 100);
    return `<div style="margin-bottom:5px">
        <div style="display:flex;justify-content:space-between;font-size:10px;color:var(--text-muted);margin-bottom:2px">
            <span>${label}</span><span style="color:${pct > 50 ? color : 'var(--text-muted)'}">${val}/${max}</span>
        </div>
        <div style="height:3px;border-radius:2px;background:rgba(255,255,255,0.07)">
            <div style="height:100%;width:${pct}%;background:${color};border-radius:2px;transition:width 0.6s ease"></div>
        </div>
    </div>`;
}

function renderAICards(predictions, filterLevel = 'all') {
    const container = document.getElementById('ai-predictions-container');
    if (!container) return;

    const filtered = filterLevel === 'all'
        ? predictions
        : predictions.filter(p => p.threat_level === filterLevel);

    if (!filtered.length) {
        const msg = filterLevel === 'all'
            ? 'No devices scanned yet. Click <strong>Scan Now</strong> to discover devices.'
            : `No <strong>${filterLevel}</strong> risk devices found.`;
        container.innerHTML = `<div class="empty-state" style="padding:30px"><div class="icon">🤖</div><p>${msg}</p></div>`;
        return;
    }

    const levelColors = { critical:'#ef4444', high:'#f97316', medium:'#eab308', none:'#22c55e' };
    const levelIcons  = { critical:'💀', high:'⚠️', medium:'🟡', none:'✅' };

    container.innerHTML = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px">
        ${filtered.map(p => {
            const color = levelColors[p.threat_level] || '#94a3b8';
            const icon  = levelIcons[p.threat_level]  || '❓';
            const fb    = p.factor_breakdown || {};
            const confPct = Math.round(p.risk_score);

            const reasonsHtml = p.reasons.length
                ? `<ul style="list-style:none;margin:10px 0 0;padding:0;border-top:1px solid rgba(255,255,255,0.05);padding-top:10px">
                    ${p.reasons.map(r => `<li style="font-size:10.5px;color:var(--text-muted);padding:2px 0;display:flex;align-items:flex-start;gap:6px">
                        <span style="color:${color};margin-top:1px;flex-shrink:0">▸</span>${r}
                    </li>`).join('')}
                  </ul>`
                : `<div style="font-size:10.5px;color:#22c55e;margin-top:10px;padding-top:10px;border-top:1px solid rgba(255,255,255,0.05)">✓ No anomalies detected — device appears safe</div>`;

            const blockBtn = (p.threat_level === 'critical' || p.threat_level === 'high')
                ? `<button class="btn btn-sm btn-danger" onclick="blockDevice('${p.ip}')" style="font-size:10px;padding:3px 10px">🚫 Block</button>`
                : '';
            const trustBtn = !p.is_known
                ? `<button class="btn btn-sm btn-ghost" onclick="trustDevice('${p.mac}','${p.hostname}')" style="font-size:10px;padding:3px 10px">✓ Trust</button>`
                : `<span style="font-size:10px;color:#22c55e;padding:3px 6px">✓ Trusted</span>`;

            return `<div class="ai-device-card" data-level="${p.threat_level}"
                style="background:rgba(255,255,255,0.02);border:1px solid ${color}28;border-radius:12px;padding:16px;transition:border-color 0.2s,box-shadow 0.2s"
                onmouseenter="this.style.borderColor='${color}60';this.style.boxShadow='0 4px 20px ${color}18'"
                onmouseleave="this.style.borderColor='${color}28';this.style.boxShadow='none'">

                <!-- Top Row: Dial + Info + Actions -->
                <div style="display:flex;align-items:flex-start;gap:12px;margin-bottom:12px">
                    <!-- Score Dial -->
                    <div style="position:relative;width:60px;height:60px;flex-shrink:0">
                        ${_aiScoreDial(p.risk_score, color)}
                    </div>

                    <!-- Device Info -->
                    <div style="flex:1;min-width:0">
                        <div style="display:flex;align-items:center;gap:6px;margin-bottom:2px">
                            <span style="font-size:14px">${icon}</span>
                            <div style="font-weight:700;font-size:13px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${p.hostname !== 'Unknown' ? p.hostname : p.ip}</div>
                        </div>
                        <div style="font-size:10px;color:var(--text-muted);font-family:monospace;margin-bottom:6px">${p.ip} · ${p.mac}</div>
                        <div style="font-size:10px;color:var(--text-muted)">${p.vendor !== 'Unknown' ? p.vendor : 'Unknown Vendor'}</div>
                    </div>

                    <!-- Level Badge + Actions -->
                    <div style="display:flex;flex-direction:column;align-items:flex-end;gap:5px;flex-shrink:0">
                        <span style="font-size:10px;font-weight:700;text-transform:uppercase;color:${color};background:${color}18;padding:3px 8px;border-radius:8px;letter-spacing:0.5px">${p.threat_level}</span>
                        ${blockBtn}
                        ${trustBtn}
                    </div>
                </div>

                <!-- Factor Breakdown -->
                <div style="background:rgba(0,0,0,0.2);border-radius:8px;padding:10px;margin-bottom:0">
                    <div style="font-size:10px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Factor Breakdown</div>
                    ${_aiFactorBar('Trust Status',    fb.trust_status    || 0, 25, color)}
                    ${_aiFactorBar('Threat History',  fb.threat_history  || 0, 30, color)}
                    ${_aiFactorBar('Device Age',      fb.device_age      || 0, 15, '#60a5fa')}
                    ${_aiFactorBar('Hostname',        fb.hostname_analysis || 0, 20, '#a78bfa')}
                    ${_aiFactorBar('Vendor',          fb.vendor_reputation || 0, 10, '#94a3b8')}
                    <div style="display:flex;justify-content:space-between;margin-top:8px;padding-top:8px;border-top:1px solid rgba(255,255,255,0.05);font-size:10px;color:var(--text-muted)">
                        <span>Rules Score: <b style="color:var(--text)">${p.rule_score}</b></span>
                        <span>ML Anomaly: <b style="color:var(--text)">${p.ml_score > 0 ? (p.ml_score * 100).toFixed(0)+'%' : 'N/A'}</b></span>
                        <span>Seen: <b style="color:var(--text)">${p.appearance_count}×</b></span>
                    </div>
                </div>

                ${reasonsHtml}
            </div>`;
        }).join('')}
    </div>`;
}

async function loadAIPredictions() {
    const container = document.getElementById('ai-predictions-container');
    const modeBadge = document.getElementById('ai-mode-badge');
    const refreshBtn = document.getElementById('ai-refresh-btn');
    if (!container) return;

    if (refreshBtn) { refreshBtn.disabled = true; refreshBtn.textContent = '↻ Loading…'; }
    container.innerHTML = `<div class="empty-state" style="padding:24px"><div style="font-size:28px;margin-bottom:8px">🤖</div><p>Analyzing network devices…</p></div>`;

    const data = await api('/ai-predictions');

    if (refreshBtn) { refreshBtn.disabled = false; refreshBtn.textContent = '↻ Refresh'; }

    if (!data.success) {
        container.innerHTML = `<div class="empty-state"><p>Failed to load AI analysis. Is the server running?</p></div>`;
        return;
    }

    _aiPredictionsData = data.predictions || [];

    // Update mode badge
    if (modeBadge) {
        if (data.ml_model_trained) {
            modeBadge.textContent = `Hybrid ML · ${data.ml_training_samples} samples`;
            modeBadge.style.background = 'rgba(0,255,136,0.12)';
            modeBadge.style.color = '#00ff88';
        } else {
            const need = Math.max(0, 20 - (data.ml_training_samples || 0));
            modeBadge.textContent = `Rules Only · ML needs ${need} more sample${need !== 1 ? 's' : ''}`;
            modeBadge.style.background = 'rgba(139,92,246,0.15)';
            modeBadge.style.color = '#a78bfa';
        }
    }

    // Update summary bar
    const counts = { critical:0, high:0, medium:0, none:0 };
    _aiPredictionsData.forEach(p => { if (counts[p.threat_level] !== undefined) counts[p.threat_level]++; });

    const summaryBar = document.getElementById('ai-summary-bar');
    const filterTabs = document.getElementById('ai-filter-tabs');
    if (summaryBar && _aiPredictionsData.length) {
        summaryBar.style.display = 'block';
        filterTabs && (filterTabs.style.display = 'block');
        document.querySelector('#ai-sum-total .ai-sum-val').textContent = _aiPredictionsData.length;
        document.querySelector('#ai-sum-crit .ai-sum-val').textContent  = counts.critical;
        document.querySelector('#ai-sum-high .ai-sum-val').textContent  = counts.high;
        document.querySelector('#ai-sum-medium .ai-sum-val').textContent = counts.medium;
        document.querySelector('#ai-sum-safe .ai-sum-val').textContent  = counts.none;
    }

    // Get active tab filter
    const activeTab = document.querySelector('.ai-tab.active');
    const activeLevel = activeTab ? activeTab.dataset.level : 'all';
    renderAICards(_aiPredictionsData, activeLevel);
}

// ── Top Threat Targets ──────────────────────────────────────────────────────
async function loadTopThreatTargets() {
    const container = document.getElementById('top-threat-targets-container');
    if (!container) return;
    
    const res = await api('/threats');
    if (!res.success) return;
    
    // Count active threats per IP
    const counts = {};
    res.threats.forEach(t => {
        if (t.resolved) return;
        const ip = t.device_ip || 'Unknown';
        counts[ip] = (counts[ip] || 0) + 1;
    });
    
    const sorted = Object.entries(counts)
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);
        
    if (sorted.length === 0) {
        container.innerHTML = `<div class="empty-state" style="padding:15px;"><p>No active threat targets</p></div>`;
        return;
    }
    
    const maxCount = Math.max(...sorted.map(s => s.count)) || 1;
    
    container.innerHTML = sorted.map(s => {
        const pct = Math.min(100, (s.count / maxCount) * 100);
        return `<div class="target-row" style="margin-bottom:12px; padding: 0 10px;">
            <div style="display:flex; justify-content:space-between; font-size:11px; margin-bottom:4px; font-family:monospace;">
                <span style="color:#e2e8f0; font-weight:600;">🎯 ${s.ip}</span>
                <span style="color:#ff3b5c; font-weight:700;">${s.count} alerts</span>
            </div>
            <div class="threat-bar" style="height:6px; background:rgba(255,255,255,0.06); border-radius:3px;">
                <div class="threat-bar-fill critical" style="width:${pct}%; height:100%; border-radius:3px; background:#ff3b5c; box-shadow: 0 0 8px #ff3b5c;"></div>
            </div>
        </div>`;
    }).join('');
}

// ── Update Dashboard Sparklines ─────────────────────────────────────────────
function updateDashboardSparklines() {
    if (typeof drawSparkline !== 'function') return;
    
    drawSparkline('sparkline-total', null, '#00d4ff');
    drawSparkline('sparkline-online', null, '#00ff88');
    drawSparkline('sparkline-threats', null, '#ff3b5c');
    drawSparkline('sparkline-blocked', null, '#ff3b5c');
    drawSparkline('sparkline-known', null, '#00ff88');
    drawSparkline('sparkline-pps-card', null, '#00d4ff');
    
    // Side widgets
    drawSparkline('sparkline-bandwidth', null, '#00d4ff');
    drawSparkline('sparkline-pps', null, '#00ff88');
}

// ── Refresh All ─────────────────────────────────────────────────────────────
function refreshAll() {
    updateStats();
    const page = document.body.dataset.page;
    if (page === 'dashboard' || page === 'devices') loadDevices(currentFilter, currentSearch);
    if (page === 'dashboard' || page === 'threats') loadThreats();
    if (page === 'dashboard') {
        loadLogs(25);
        loadAIPredictions();
        loadTopThreatTargets();
        updateDashboardSparklines();
    }
    if (page === 'settings') loadLogs(100);
    
    // Refresh premium SOC visualizations
    if (page === 'dashboard') {
        if (typeof initNetworkGraph === 'function') initNetworkGraph();
        if (typeof initSubnetHeatmap === 'function') initSubnetHeatmap();
        if (typeof initAttackHeatmap === 'function') initAttackHeatmap();
        if (typeof initTrafficChart === 'function') initTrafficChart();
    }
}

// ── Initialize ──────────────────────────────────────────────────────────────
// ── Initialize ──────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    refreshAll();

    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        let timeout;
        searchInput.addEventListener('input', (e) => {
            clearTimeout(timeout);
            timeout = setTimeout(() => handleSearch(e), 300);
        });
    }

    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => setFilter(btn.dataset.filter));
    });
});
