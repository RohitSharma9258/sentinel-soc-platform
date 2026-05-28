/**
 * Smart WiFi Intruder Detection System - Live WebSocket Engine
 * Handles real-time streaming updates from the backend with throttling and state reconciliation.
 */

let socket = null;
let lastDevicesRefreshTime = 0;
let lastStatsRefreshTime = 0;
let lastThreatsRefreshTime = 0;
let devicesRefreshTimeout = null;
let statsRefreshTimeout = null;
let threatsRefreshTimeout = null;

// Safe wrapper functions to call main.js functions if loaded
function refreshDevices() {
    if (typeof loadDevices === 'function') {
        loadDevices(typeof currentFilter !== 'undefined' ? currentFilter : 'all', typeof currentSearch !== 'undefined' ? currentSearch : '');
    }
}

function refreshThreats() {
    if (typeof loadThreats === 'function') {
        loadThreats('all');
    }
}

function safeUpdateStats() {
    if (typeof updateStats === 'function') {
        updateStats();
    }
}

function safeRefreshAll() {
    if (typeof refreshAll === 'function') {
        refreshAll();
    } else {
        safeUpdateStats();
    }
}

function refreshAIPredictions() {
    if (typeof loadAIPredictions === 'function') {
        loadAIPredictions();
    }
}

// Throttled UI refresh functions to prevent layout thrashing and browser UI freeze during network storms
function throttledRefreshDevices() {
    const now = Date.now();
    const wait = 1500; // Throttle devices table update to at most once per 1.5 seconds
    if (now - lastDevicesRefreshTime >= wait) {
        if (devicesRefreshTimeout) clearTimeout(devicesRefreshTimeout);
        refreshDevices();
        lastDevicesRefreshTime = now;
    } else if (!devicesRefreshTimeout) {
        devicesRefreshTimeout = setTimeout(() => {
            refreshDevices();
            lastDevicesRefreshTime = Date.now();
            devicesRefreshTimeout = null;
        }, wait - (now - lastDevicesRefreshTime));
    }
}

function throttledRefreshStats() {
    const now = Date.now();
    const wait = 1000; // Throttle stats cards update to at most once per 1.0 second
    if (now - lastStatsRefreshTime >= wait) {
        if (statsRefreshTimeout) clearTimeout(statsRefreshTimeout);
        safeUpdateStats();
        lastStatsRefreshTime = now;
    } else if (!statsRefreshTimeout) {
        statsRefreshTimeout = setTimeout(() => {
            safeUpdateStats();
            lastStatsRefreshTime = Date.now();
            statsRefreshTimeout = null;
        }, wait - (now - lastStatsRefreshTime));
    }
}

function throttledRefreshThreats() {
    const now = Date.now();
    const wait = 2000; // Throttle threat table update to at most once per 2.0 seconds
    if (now - lastThreatsRefreshTime >= wait) {
        if (threatsRefreshTimeout) clearTimeout(threatsRefreshTimeout);
        refreshThreats();
        lastThreatsRefreshTime = now;
    } else if (!threatsRefreshTimeout) {
        threatsRefreshTimeout = setTimeout(() => {
            refreshThreats();
            lastThreatsRefreshTime = Date.now();
            threatsRefreshTimeout = null;
        }, wait - (now - lastThreatsRefreshTime));
    }
}

let lastAIPredictionsRefreshTime = 0;
let aiPredictionsRefreshTimeout = null;

function throttledRefreshAIPredictions() {
    const now = Date.now();
    const wait = 3000; // Throttle AI updates to at most once per 3.0 seconds
    if (now - lastAIPredictionsRefreshTime >= wait) {
        if (aiPredictionsRefreshTimeout) clearTimeout(aiPredictionsRefreshTimeout);
        refreshAIPredictions();
        lastAIPredictionsRefreshTime = now;
    } else if (!aiPredictionsRefreshTimeout) {
        aiPredictionsRefreshTimeout = setTimeout(() => {
            refreshAIPredictions();
            lastAIPredictionsRefreshTime = Date.now();
            aiPredictionsRefreshTimeout = null;
        }, wait - (now - lastAIPredictionsRefreshTime));
    }
}

function connectSocket() {
    if (typeof io === 'undefined') {
        console.warn('[Socket] Socket.io not loaded. Falling back to periodic UI polling.');
        setInterval(safeRefreshAll, 5000);
        return;
    }
    
    if (socket) return;
    
    // Connect to the Socket.IO server
    socket = io();

    socket.on('connect', () => {
        console.log('[Socket] Connected to server');
        const indicator = document.getElementById('live-indicator');
        if (indicator) {
            indicator.classList.add('online');
            indicator.classList.remove('offline');
        }
        showToast('Live stream connected', 'success');

        // RE-SYNC ARCHITECTURE: Pull fresh server state upon socket connection or recovery loop
        console.log('[Socket] Reconciling state with backend...');
        refreshDevices();
        refreshThreats();
        safeUpdateStats();
        refreshAIPredictions();
    });

    socket.on('disconnect', () => {
        console.log('[Socket] Disconnected');
        const indicator = document.getElementById('live-indicator');
        if (indicator) {
            indicator.classList.remove('online');
            indicator.classList.add('offline');
        }
        showToast('Live stream disconnected', 'warning');
    });

    // Handle real-time discovery events (from app.py ui_refresh_devices)
    socket.on('ui_refresh_devices', (data) => {
        console.log('[Socket] Device seen/updated:', data);
        throttledRefreshDevices();
        throttledRefreshStats();
        throttledRefreshAIPredictions();
    });

    // Handle stats updates (from app.py ui_refresh_stats)
    socket.on('ui_refresh_stats', (data) => {
        throttledRefreshStats();
    });

    // Handle threat alerts (from app.py threat_detected)
    socket.on('threat_detected', (data) => {
        console.log('[Socket] Threat alert:', data);
        showToast(`NEW THREAT: ${data.threat_type || data.type} from ${data.device_ip || 'unknown'}`, 'error');
        throttledRefreshThreats();
        throttledRefreshStats();
        throttledRefreshAIPredictions();
    });

    // Handle generic system updates (from app.py trust_updated)
    socket.on('trust_updated', (data) => {
        console.log('[Socket] Trust updated:', data);
        throttledRefreshDevices();
    });

    // Handle high-frequency packet updates (from app.py ui_refresh_packets)
    socket.on('ui_refresh_packets', (data) => {
        const packetsVal = document.getElementById('stat-packets');
        if (packetsVal && data) {
            packetsVal.textContent = (data.total || 0).toLocaleString();
        }
        const sidebarPpsVal = document.getElementById('sidebar-pps');
        if (sidebarPpsVal && data && typeof data.pps !== 'undefined') {
            sidebarPpsVal.textContent = Math.round(data.pps).toLocaleString() + ' pps';
        }
    });

    // NDR: Threat Intelligence IOC match alert
    socket.on('threat_intel_alert', (alert) => {
        const banner = document.getElementById('threat-intel-banner');
        const msg = document.getElementById('threat-intel-banner-msg');
        if (banner) banner.style.display = 'block';
        if (msg) msg.textContent = `IOC Match: ${alert.ip} → ${alert.dst_ip} (${alert.category || 'malicious'})`;
        showToast(`🚨 THREAT INTEL: ${alert.ip} → known ${alert.category || 'malicious'} host`, 'error');
        throttledRefreshThreats();
        throttledRefreshStats();
    });

    // NDR: Beaconing / C2 alert
    socket.on('beacon_alert', (alert) => {
        showToast(`📡 BEACON DETECTED: ${alert.src_ip} → ${alert.dst_ip}:${alert.dst_port} every ~${alert.interval_sec}s`, 'warning');
        throttledRefreshThreats();
    });

    // NDR: ARP Monitor alerts
    socket.on('arp_alert', (alert) => {
        const sev = alert.severity === 'critical' ? 'error' : 'warning';
        showToast(`🔴 ARP: ${alert.type.toUpperCase()} — ${alert.description}`, sev);
        throttledRefreshThreats();
        throttledRefreshStats();
    });

    // Expose socket globally for index.html inline handlers
    window._socket = socket;
    document.dispatchEvent(new Event('socket_connected'));
}

function toggleLiveRefresh() {
    if (socket) {
        socket.disconnect();
        socket = null;
        showToast('Live stream paused', 'info');
    } else {
        connectSocket();
    }
}

// Start WebSocket connection on page load
document.addEventListener('DOMContentLoaded', () => {
    connectSocket();
});
