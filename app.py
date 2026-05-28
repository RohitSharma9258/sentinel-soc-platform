"""
Smart WiFi Intruder Detection System - Flask Application
Main web application with all API routes and page rendering.
"""

import os
import io
import csv
import json
import time
import logging
import threading
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, jsonify, request, Response,
    send_file, redirect, url_for
)
from flask_socketio import SocketIO, emit

from config import (
    FLASK_HOST, FLASK_PORT, FLASK_DEBUG, SECRET_KEY,
    SCAN_INTERVAL, LOG_LEVEL, LOG_FORMAT, LOG_FILE, BASE_DIR
)
from database import db
from scanner import scan_network, get_last_scan_result
from detector import detector
from blocker import blocker
from packet_sniffer import sniffer
from ai_predictor import predictor
from identity_engine import identity_engine
from event_bus import bus
from utils import validate_ip, get_network_cidr, get_local_ip
from auth import require_api_key, require_local_or_api_key
from report_generator import generate_report_html
# ARCH: Added net_ctx import
from network_context import net_ctx

# NDR: New detection module imports (graceful: all optional)
try:
    from mac_vendor import mac_vendor as _mac_vendor_engine
except Exception:
    _mac_vendor_engine = None

try:
    from fingerprinter import fingerprinter as _fingerprinter
except Exception:
    _fingerprinter = None

try:
    from arp_monitor import arp_monitor as _arp_monitor
except Exception:
    _arp_monitor = None

try:
    from threat_intel import threat_intel as _threat_intel
except Exception:
    _threat_intel = None

try:
    from beaconing_detector import beaconing_detector as _beaconing
except Exception:
    _beaconing = None

try:
    from mitre_mapper import get_all_mappings as _get_mitre_map
except Exception:
    _get_mitre_map = lambda: {}

# ─── Logging Setup ───────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler(),
    ]
)
logger = logging.getLogger("app")

# ─── Flask App ────────────────────────────────────────────────────────────────
app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)
app.secret_key = SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ─── Background Scanner Thread ───────────────────────────────────────────────
_scanner_running = False
_scanner_thread = None
antigravity_lock = threading.Lock()


def _background_scanner():
    """Continuous background scanning loop."""
    global _scanner_running
    logger.info("Background scanner started")
    while _scanner_running:
        try:
            # Perform network scan
            result = scan_network()

            # Analyze scan results for threats
            devices = db.get_all_devices()
            detector.analyze_scan_results(devices)

            # Process sniffer alerts
            alerts = sniffer.get_alerts(clear=True)
            if alerts:
                detector.process_sniffer_alerts(alerts)

        except Exception as e:
            logger.error(f"Background scan error: {e}")

        # Wait for next scan interval
        for _ in range(SCAN_INTERVAL):
            if not _scanner_running:
                break
            time.sleep(1)

    logger.info("Background scanner stopped")


def start_background_services():
    """Start all background services."""
    global _scanner_running, _scanner_thread

    # ARCH: Initialize NetworkContext singleton (will be a no-op if already initialized by run.py)
    try:
        if not net_ctx.is_initialized:
            net_ctx.initialize(refresh_interval=300)
        else:
            logger.info("NetworkContext is already initialized.")
    except Exception as e:
        logger.warning(f"Could not initialize NetworkContext: {e}")

    # ARCH: Start Blocker event listener
    try:
        blocker.start()
    except Exception as e:
        logger.warning(f"Could not start blocker event listener: {e}")

    # Start packet sniffer
    try:
        sniffer.start()
    except Exception as e:
        logger.warning(f"Could not start sniffer: {e}")

    # Start AI predictor
    try:
        predictor.start()
    except Exception as e:
        logger.warning(f"Could not start AI predictor: {e}")

    # Start Identity Engine
    try:
        identity_engine.start()
    except Exception as e:
        logger.warning(f"Could not start Identity Engine: {e}")

    # Start background scanner
    _scanner_running = True
    _scanner_thread = threading.Thread(target=_background_scanner, daemon=True, name="BGScanner")
    _scanner_thread.start()

    # NDR: Start ARP Monitor watchdog
    try:
        if _arp_monitor:
            _arp_monitor.start(
                gateway_ip=net_ctx.gateway_ip,
                gateway_mac=""   # populated dynamically from ARP traffic
            )
            logger.info("ARP Monitor started")
    except Exception as e:
        logger.warning(f"Could not start ARP Monitor: {e}")

    # NDR: Start Threat Intel auto-refresh (background, non-blocking)
    try:
        if _threat_intel:
            _threat_intel.start_auto_refresh()
            logger.info(f"Threat Intel started ({_threat_intel.get_stats()['total_iocs']} IOCs loaded)")
    except Exception as e:
        logger.warning(f"Could not start Threat Intel: {e}")

    # Subscribe WebSockets to Event Bus
    _setup_event_handlers()

    # Run security audit
    _security_audit_startup()

    db.add_log("INFO", "app", "All background services started")
    logger.info("All background services started successfully")

def _setup_event_handlers():
    """Connect Event Bus events to specific WebSocket channels."""
    def stream_event(event_type, data):
        try:
            with app.app_context():
                # Standard Event Bus to WebSocket mapping
                socketio.emit(event_type, data)
                
                # Special handling for granular updates to keep UI responsive
                if event_type == "device_seen" or event_type == "device_update":
                    socketio.emit("ui_refresh_devices", {"mac": data.get("mac")})
                elif event_type == "stats_update":
                    socketio.emit("ui_refresh_stats", data)
                elif event_type == "packet_update":
                    socketio.emit("ui_refresh_packets", data)
        except Exception as e:
            # Silent fail for stream events to prevent log flooding
            pass
    
    bus.subscribe("*", stream_event)

# THREAD-FIX: Global tracker to store socket connection stop events, preventing stream_logs thread leak on disconnect.
_active_log_streams = {}  # sid -> threading.Event (stop_event)


@socketio.on('connect')
def handle_antigravity_updates():
    """Stream ANTIGRAVITY events to connected clients."""
    # THREAD-FIX: Associate stop event with the client's SocketIO session ID (sid)
    sid = request.sid
    stop_event = threading.Event()
    _active_log_streams[sid] = stop_event

    def stream_logs():
        last_id = 0
        # THREAD-FIX: Loop checks stop_event to exit the thread when disconnect is received
        while not stop_event.is_set():
            try:
                logs = db.get_logs(limit=100, is_audit=1)
                # Filter for ANTIGRAVITY events and newer than last_id
                new_logs = [l for l in logs if l.get("id", 0) > last_id and "ANTIGRAVITY" in l["message"]]
                
                for log in new_logs:
                    if stop_event.is_set():
                        break
                    socketio.emit('antigravity_event', {
                        "timestamp": log["timestamp"],
                        "action": log["message"],
                        "level": log["level"]
                    }, room=sid)
                    last_id = max(last_id, log.get("id", 0))
            except Exception:
                pass
            # THREAD-FIX: Use stop_event.wait(timeout=2) instead of time.sleep(2) to terminate thread immediately
            stop_event.wait(timeout=2)
    
    thread = threading.Thread(
        target=stream_logs,
        daemon=True,
        name=f"LogStream-{sid}"
    )
    thread.start()
    logger.info(f"Log stream started for client {sid}")


@socketio.on('disconnect')
def handle_disconnect():
    """Clean up resources on SocketIO client disconnection."""
    # THREAD-FIX: Trigger stop event and delete reference to terminate the stream_logs thread on client disconnect
    sid = request.sid
    if sid in _active_log_streams:
        _active_log_streams[sid].set()  # signal thread to stop
        del _active_log_streams[sid]
        logger.info(f"Log stream stopped for client {sid}")


def stop_background_services():
    """Stop all background services."""
    # THREAD-FIX: Stop the identity engine to unsubscribe callbacks and avoid thread leaks on exit
    global _scanner_running
    _scanner_running = False
    sniffer.stop()
    predictor.stop()
    identity_engine.stop()
    logger.info("All background services stopped")


# ═══════════════════════════════════════════════════════════════════════════════
#  PAGE ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    """Main dashboard page."""
    stats = db.get_stats()
    return render_template("index.html", stats=stats)


@app.route("/devices-page")
def devices_page():
    """Devices management page."""
    return render_template("devices.html")


@app.route("/threats-page")
def threats_page():
    """Threats monitoring page."""
    return render_template("threats.html")


@app.route("/settings-page")
def settings_page():
    """Settings page."""
    return render_template("settings.html")


# ═══════════════════════════════════════════════════════════════════════════════
#  API ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/scan", methods=["POST"])
def api_scan():
    """Trigger a manual network scan."""
    logger.info(f"Scan request received: method={request.method}")
    try:
        data = request.get_json(silent=True) or {}
        logger.info(f"Scan request data: {data}")
        
        network = data.get("network")
        logger.info(f"Starting network scan on: {network or 'default'}")
        
        result = scan_network(network)
        
        # Analyze for threats
        devices = db.get_all_devices()
        new_threats = detector.analyze_scan_results(devices)

        # Process sniffer alerts
        alerts = sniffer.get_alerts(clear=True)
        if alerts:
            sniffer_threats = detector.process_sniffer_alerts(alerts)
            new_threats.extend(sniffer_threats)

        logger.info(f"Scan completed: found {len(result.devices)} devices")
        
        return jsonify({
            "success": True,
            "scan_time": result.scan_time,
            "devices_found": len(result.devices),
            "new_threats": len(new_threats),
            "network": result.network,
        })
    except Exception as e:
        logger.exception(f"Scan API exception: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/devices", methods=["GET"])
def api_devices():
    """Get discovered devices, focused on current network session."""
    try:
        filter_type = request.args.get("filter", "all")
        search = request.args.get("search", "").lower()

        # Get devices from current subnet
        devices = db.get_all_devices(filter_subnet=True)

        # Apply filtering
        if filter_type == "online":
            devices = [d for d in devices if d["is_online"]]
        elif filter_type == "offline":
            devices = [d for d in devices if not d["is_online"]]
        elif filter_type == "threats":
            devices = [d for d in devices if d["threat_level"] not in ("none", "")]
        
        # By default, if no filter is specified, we prioritize showing online devices
        # to ensure the UI matches the "current network session" requirement.

        # Apply search
        if search:
            devices = [
                d for d in devices
                if search in d["ip"].lower()
                or search in d["mac"].lower()
                or search in d.get("hostname", "").lower()
                or search in d.get("vendor", "").lower()
            ]

        # Enrich with block status, AI risk, and dynamic status
        for d in devices:
            d["is_blocked"] = db.is_blocked(d["ip"])
            ai_risk = predictor.get_device_risk(d["mac"])
            d["ai_risk_score"] = ai_risk["risk_score"]
            d["ai_reasons"] = ai_risk["reasons"]
            # status and is_online are already calculated in get_all_devices()

        return jsonify({"success": True, "devices": devices, "count": len(devices)})
    except Exception as e:
        logger.error(f"Devices API error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/threats", methods=["GET"])
def api_threats():
    """Get all threats."""
    try:
        filter_level = request.args.get("level", "all")
        threats = db.get_all_threats()

        if filter_level != "all":
            threats = [t for t in threats if t["threat_level"] == filter_level]

        return jsonify({"success": True, "threats": threats, "count": len(threats)})
    except Exception as e:
        logger.error(f"Threats API error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500






@app.route("/unblock/<ip>", methods=["POST"])
@require_local_or_api_key
def api_unblock(ip):
    """Unblock a device by IP."""
    try:
        logger.info(f"API Request: Unblock {ip}")
        # Call the blocker's unblock logic which handles FW, ARP, and DB
        result = blocker.unblock_ip(ip)
        
        if result.get("success"):
            return jsonify(result)
        else:
            # Provide more specific error info if available
            error_msg = result.get("message", "Unblock failed")
            if result.get("error") == "db_update_failed":
                error_msg = f"Critical: Database update failed for {ip}"
            
            return jsonify({
                "success": False,
                "message": error_msg,
                "details": result.get("details", {})
            }), 400
    except Exception as e:
        logger.error(f"Unblock API error for {ip}: {e}")
        return jsonify({"success": False, "error": str(e), "message": "Internal server error during unblock"}), 500


@app.route("/block/<ip>", methods=["POST"])
@require_local_or_api_key
def api_block(ip):
    """
    Block a device by IP with validation and duplicate prevention.
    Permissive validation: Allow if IP is valid and part of current network or history.
    """
    try:
        if not validate_ip(ip):
            return jsonify({"success": False, "message": f"Invalid IP address format: {ip}"}), 400

        # 1. Safety: Refuse to block Gateway, Localhost, or Self
        from utils import is_critical_infrastructure
        if is_critical_infrastructure(ip):
            return jsonify({
                "success": False, 
                "message": "Security Policy: Blocking of critical infrastructure (Gateway/Localhost) is strictly prohibited."
            }), 403

        # 2. Validation: Ensure IP is part of current network or known history

        # 2. Duplicate Prevention
        if db.is_blocked(ip):
            return jsonify({
                "success": True, 
                "message": f"Device {ip} is already blocked."
            })

        # 3. Get reason from JSON or default
        data = request.json or {}
        reason = data.get("reason", "Manual block from dashboard")
        
        logger.info(f"API Request: Block {ip} - Reason: {reason}")
        
        # 4. Execute Block
        result = blocker.block_ip(ip, reason)
        
        if result.get("success"):
            return jsonify(result)
        else:
            return jsonify(result), 400
    except Exception as e:
        logger.error(f"Block API error for {ip}: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/live-status", methods=["GET"])
def api_live_status():
    """Get real-time system status for live dashboard updates."""
    try:
        stats = db.get_stats()
        sniffer_stats = sniffer.get_stats()
        ai_stats = predictor.get_stats()
        threat_summary = detector.get_threat_summary()
        blocked = db.get_blocked_devices()
        recent_threats = db.get_active_threats()[:10]
        ai_predictions = predictor.get_predictions()

        return jsonify({
            "success": True,
            "timestamp": datetime.now().isoformat(),
            "stats": stats,
            "sniffer": sniffer_stats,
            "ai": ai_stats,
            "threat_summary": threat_summary,
            "blocked_devices": blocked,
            "recent_threats": recent_threats,
            "ai_predictions": ai_predictions,
            "scanner_running": _scanner_running,
            # ARCH: Use NetworkContext for local IP and subnet
            "local_ip": net_ctx.local_ip,
            "network": net_ctx.network_cidr,
        })
    except Exception as e:
        logger.error(f"Live status error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/ai-predictions", methods=["GET"])
def api_ai_predictions():
    """Get AI risk scores for all currently tracked devices."""
    try:
        # Force an immediate analysis pass so UI always gets fresh data
        predictor._analyze_device_behaviors()
        predictor._detect_anomalies()

        devices = db.get_all_devices(filter_subnet=True)
        results = []
        for device in devices:
            risk = predictor.get_device_risk(device["mac"])
            results.append({
                "mac": device["mac"],
                "ip": device["ip"],
                "hostname": device.get("hostname", "Unknown"),
                "vendor": device.get("vendor", "Unknown"),
                "is_known": device.get("is_known", False),
                "risk_score": risk["risk_score"],
                "rule_score": risk["rule_score"],
                "ml_score": round(float(risk["ml_score"]), 3),
                "threat_level": risk["threat_level"],
                "reasons": risk["reasons"],
                "factor_breakdown": risk["factor_breakdown"],
                "appearance_count": risk["appearance_count"],
            })

        # Sort by risk score descending
        results.sort(key=lambda x: x["risk_score"], reverse=True)

        ai_stats = predictor.get_stats()
        return jsonify({
            "success": True,
            "predictions": results,
            "count": len(results),
            "ml_model_trained": ai_stats["ml_model_trained"],
            "scoring_mode": ai_stats["scoring_mode"],
            "ml_training_samples": ai_stats["ml_training_samples"],
        })
    except Exception as e:
        logger.error(f"AI predictions API error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/logs", methods=["GET"])
def api_logs():
    """Get system logs with audit filtering."""
    try:
        limit = int(request.args.get("limit", 100))
        level = request.args.get("level")
        module = request.args.get("module")
        is_audit = request.args.get("audit") == "1"

        logs = db.get_logs(limit=limit, level=level, module=module, is_audit=is_audit)
        return jsonify({"success": True, "logs": logs, "count": len(logs)})
    except Exception as e:
        logger.error(f"Logs API error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/antigravity/stats", methods=["GET"])
def api_antigravity_stats():
    """Get ANTIGRAVITY protocol stats."""
    try:
        import config
        logs = db.get_logs(limit=1000, is_audit=1)
        antigravity_logs = [l for l in logs if "ANTIGRAVITY" in l["message"]]
        
        exempt_count = sum(1 for l in antigravity_logs if "EXEMPTED" in l["message"])
        blocked_count = sum(1 for l in antigravity_logs if "AUTO-BLOCK" in l["message"])
        
        return jsonify({
            "success": True,
            "enabled": config.ANTIGRAVITY_MODE,
            "threats_suppressed": exempt_count,
            "auto_blocks_triggered": blocked_count,
            "recent_actions": antigravity_logs[-20:]
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/known-devices", methods=["GET"])
def api_known_devices():
    """Get all known/trusted devices."""
    try:
        known = db.get_known_devices()
        return jsonify({"success": True, "devices": known})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/known-devices/add", methods=["POST"])
@require_local_or_api_key
def api_add_known_device():
    """Add a device to the trusted list."""
    try:
        data = request.json
        mac = data.get("mac", "").upper()
        name = data.get("name", "My Device")
        device_type = data.get("device_type", "personal")
        notes = data.get("notes", "")

        if not mac:
            return jsonify({"success": False, "error": "MAC address required"}), 400

        success = db.add_known_device(mac, name, device_type, notes)
        return jsonify({"success": success})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/known-devices/remove", methods=["POST"])
@require_local_or_api_key
def api_remove_known_device():
    """Remove a device from the trusted list."""
    try:
        data = request.json
        mac = data.get("mac", "").upper()
        if not mac:
            return jsonify({"success": False, "error": "MAC address required"}), 400
        db.remove_known_device(mac)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/resolve-threat/<int:threat_id>", methods=["POST"])
@require_local_or_api_key
def api_resolve_threat(threat_id):
    """Resolve/dismiss a threat."""
    try:
        db.resolve_threat(threat_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  EXPORT ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/export/csv", methods=["GET"])
def export_csv():
    """Export devices and threats data as CSV."""
    try:
        export_type = request.args.get("type", "devices")
        output = io.StringIO()
        writer = csv.writer(output)

        if export_type == "devices":
            devices = db.get_all_devices()
            writer.writerow(["IP", "MAC", "Hostname", "Vendor", "Status",
                             "Threat Level", "Threat Score", "Known", "First Seen", "Last Seen"])
            for d in devices:
                writer.writerow([
                    d["ip"], d["mac"], d["hostname"], d["vendor"],
                    "Online" if d["is_online"] else "Offline",
                    d["threat_level"], d["threat_score"],
                    "Yes" if d["is_known"] else "No",
                    d["first_seen"], d["last_seen"]
                ])

        elif export_type == "threats":
            threats = db.get_all_threats()
            writer.writerow(["Device MAC", "Device IP", "Type", "Level",
                             "Score", "Description", "Detected At", "Resolved"])
            for t in threats:
                writer.writerow([
                    t["device_mac"], t["device_ip"], t["threat_type"],
                    t["threat_level"], t["threat_score"], t["description"],
                    t["detected_at"], "Yes" if t["resolved"] else "No"
                ])

        elif export_type == "blocked":
            blocked = db.get_blocked_devices()
            writer.writerow(["IP", "MAC", "Reason", "Blocked At", "Method"])
            for b in blocked:
                writer.writerow([
                    b["ip"], b["mac"], b["reason"], b["blocked_at"], b["block_method"]
                ])

        elif export_type == "logs":
            logs = db.get_logs(limit=500)
            writer.writerow(["Timestamp", "Level", "Module", "Message"])
            for l in logs:
                writer.writerow([l["timestamp"], l["level"], l["module"], l["message"]])

        output.seek(0)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"intruder_{export_type}_{timestamp}.csv"

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        logger.error(f"CSV export error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/export/pdf", methods=["GET"])
def export_pdf():
    """Export a PDF report of the system status."""
    try:
        export_type = request.args.get("type", "report")
        stats = db.get_stats()
        devices = db.get_all_devices()
        threats = db.get_all_threats()
        blocked = db.get_blocked_devices()

        # Build HTML report for PDF-like output
        html = generate_report_html(stats, devices, threats, blocked)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"intruder_report_{timestamp}.html"

        return Response(
            html,
            mimetype="text/html",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
    except Exception as e:
        logger.error(f"PDF export error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500



# ═══════════════════════════════════════════════════════════════════════════════
#  ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"success": False, "error": "Internal server error"}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  NDR API ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/ndr/vendor/<mac>", methods=["GET"])
def api_vendor_lookup(mac):
    """NDR: Lookup MAC vendor info and risk classification."""
    try:
        if _mac_vendor_engine:
            info = _mac_vendor_engine.lookup(mac)
        else:
            info = {"vendor": "Unknown", "oui": mac[:8], "is_randomized": False, "risk": "medium", "risk_score": 20}
        return jsonify({"success": True, "mac": mac, "vendor_info": info})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/ndr/fingerprint/<mac>", methods=["GET"])
def api_fingerprint(mac):
    """NDR: Get OS fingerprint for a device."""
    try:
        if _fingerprinter:
            fp = _fingerprinter.get_fingerprint(mac)
        else:
            fp = {"os_type": "Unknown", "confidence": 0, "device_class": "unknown"}
        return jsonify({"success": True, "mac": mac, "fingerprint": fp})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/ndr/threat-intel", methods=["GET"])
def api_threat_intel_stats():
    """NDR: Get threat intelligence feed statistics."""
    try:
        if _threat_intel:
            stats = _threat_intel.get_stats()
        else:
            stats = {"total_iocs": 0, "by_category": {}, "by_severity": {}, "last_updated": None}
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/ndr/beaconing", methods=["GET"])
def api_beaconing_status():
    """NDR: Get current beaconing alerts and flagged IPs."""
    try:
        if _beaconing:
            alerts = _beaconing.get_alerts(clear=False)
            flagged = list(_beaconing.get_beaconing_ips())
        else:
            alerts, flagged = [], []
        return jsonify({"success": True, "alerts": alerts, "flagged_ips": flagged})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/ndr/mitre", methods=["GET"])
def api_mitre_mappings():
    """NDR: Return full MITRE ATT&CK mapping table."""
    try:
        return jsonify({"success": True, "mappings": _get_mitre_map()})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/ndr/status", methods=["GET"])
def api_ndr_status():
    """NDR: Overall status of all NDR modules."""
    try:
        intel_stats = _threat_intel.get_stats() if _threat_intel else {"total_iocs": 0}
        beacon_ips  = list(_beaconing.get_beaconing_ips()) if _beaconing else []
        return jsonify({
            "success": True,
            "modules": {
                "mac_vendor_engine":    _mac_vendor_engine is not None,
                "device_fingerprinter": _fingerprinter is not None,
                "arp_monitor":          _arp_monitor is not None,
                "threat_intel":         _threat_intel is not None,
                "beaconing_detector":   _beaconing is not None,
            },
            "threat_intel": intel_stats,
            "beaconing_ips": beacon_ips,
            "sniffer_stats": sniffer.get_stats(),
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/antigravity/toggle", methods=["POST"])
@require_local_or_api_key
def api_toggle_antigravity():
    """Toggle the ANTIGRAVITY protocol state and persist it."""
    try:
        with antigravity_lock:
            import config
            config.ANTIGRAVITY_MODE = not config.ANTIGRAVITY_MODE
            
            # Persist to DB
            db.save_antigravity_state(config.ANTIGRAVITY_MODE)
            
            mode_enabled = config.ANTIGRAVITY_MODE
        
        msg = f"ANTIGRAVITY Protocol: {'ENABLED' if mode_enabled else 'DISABLED'}"
        db.add_log("WARNING", "system", msg, is_audit=1)
        return jsonify({"success": True, "mode": mode_enabled, "message": msg})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


def _security_audit_startup():
    """Run comprehensive security checks on startup."""
    logger.info("Running ANTIGRAVITY startup security audit...")
    # ARCH: Use NetworkContext for audit values
    try:
        # 1. Verify no critical infrastructure is blocked
        blocked = db.get_blocked_devices()
        critical = ["127.0.0.1", "0.0.0.0", net_ctx.gateway_ip, net_ctx.local_ip]
        
        for block in blocked:
            if block["ip"] in critical:
                logger.critical(f"SECURITY VIOLATION: {block['ip']} is blocked but critical!")
                db.remove_blocked_device(block["ip"])
                db.add_log("CRITICAL", "security", 
                          f"Removed erroneous block on {block['ip']}", is_audit=1)
        
        # 2. Verify ANTIGRAVITY mode state from DB
        import config
        db_state = db.load_antigravity_state()
        if config.ANTIGRAVITY_MODE != db_state:
            logger.warning(f"ANTIGRAVITY state mismatch, syncing to {db_state}")
            config.ANTIGRAVITY_MODE = db_state
        
        logger.info(f"Startup audit complete. ANTIGRAVITY: {'ENABLED' if config.ANTIGRAVITY_MODE else 'DISABLED'}")
    except Exception as e:
        logger.error(f"Startup security audit failed: {e}")

def create_app():
    """Factory function to create and configure the Flask app."""
    # Load persisted ANTIGRAVITY state
    import config
    config.ANTIGRAVITY_MODE = db.load_antigravity_state()
    return app
