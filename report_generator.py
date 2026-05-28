import html
from datetime import datetime

def _e(value) -> str:
    """
    Helper function to escape HTML characters and handle None values.
    """
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def generate_report_html(stats, devices, threats, blocked):
    """
    Generates a secure HTML report with all user-controlled fields escaped,
    Unicode emojis replaced by HTML entities, and Content-Security-Policy headers added.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    device_rows = ""
    for d in devices:
        # Use HTML entities for status emojis
        status = "&#x1F7E2; Online" if d.get("is_online") else "&#x1F534; Offline"
        device_rows += f"""<tr>
            <td>{_e(d.get('ip'))}</td><td>{_e(d.get('mac'))}</td><td>{_e(d.get('hostname'))}</td>
            <td>{_e(d.get('vendor'))}</td><td>{status}</td><td>{_e(d.get('threat_level'))}</td>
        </tr>"""

    threat_rows = ""
    for t in threats[:50]:
        threat_rows += f"""<tr>
            <td>{_e(t.get('device_ip'))}</td><td>{_e(t.get('device_mac'))}</td><td>{_e(t.get('threat_type'))}</td>
            <td>{_e(t.get('threat_level'))}</td><td>{_e(t.get('threat_score'))}</td><td>{_e(t.get('detected_at'))}</td>
        </tr>"""

    blocked_rows = ""
    for b in blocked:
        blocked_rows += f"""<tr>
            <td>{_e(b.get('ip'))}</td><td>{_e(b.get('mac', 'N/A'))}</td><td>{_e(b.get('reason'))}</td>
            <td>{_e(b.get('blocked_at'))}</td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline';">
<title>Intruder Detection Report</title>
<style>
body{{font-family:Arial,sans-serif;margin:40px;background:#0a0a0f;color:#e0e0e0}}
h1{{color:#00ff88;border-bottom:2px solid #00ff88;padding-bottom:10px}}
h2{{color:#00d4ff;margin-top:30px}}
table{{width:100%;border-collapse:collapse;margin:15px 0}}
th{{background:#1a1a2e;color:#00ff88;padding:10px;text-align:left;border:1px solid #333}}
td{{padding:8px 10px;border:1px solid #333;background:#0d0d1a}}
.stat-box{{display:inline-block;background:#1a1a2e;padding:15px 25px;margin:5px;border-radius:8px;border:1px solid #333}}
.stat-box .num{{font-size:24px;font-weight:bold;color:#00ff88}}
.stat-box .label{{font-size:12px;color:#888;margin-top:5px}}
</style></head><body>
<h1>&#x1F6E1;&#xFE0F; WiFi Intruder Detection Report</h1>
<p>Generated: {_e(now)}</p>
<div>
<div class="stat-box"><div class="num">{_e(stats.get('total_devices'))}</div><div class="label">Total Devices</div></div>
<div class="stat-box"><div class="num">{_e(stats.get('online_devices'))}</div><div class="label">Online</div></div>
<div class="stat-box"><div class="num">{_e(stats.get('active_threats'))}</div><div class="label">Active Threats</div></div>
<div class="stat-box"><div class="num">{_e(stats.get('blocked_devices'))}</div><div class="label">Blocked</div></div>
</div>
<h2>&#x1F4E1; Discovered Devices ({_e(len(devices))})</h2>
<table><tr><th>IP</th><th>MAC</th><th>Hostname</th><th>Vendor</th><th>Status</th><th>Threat</th></tr>{device_rows}</table>
<h2>&#x26A0;&#xFE0F; Threats ({_e(len(threats))})</h2>
<table><tr><th>IP</th><th>MAC</th><th>Type</th><th>Level</th><th>Score</th><th>Detected</th></tr>{threat_rows}</table>
<h2>&#x1F6AB; Blocked Devices ({_e(len(blocked))})</h2>
<table><tr><th>IP</th><th>MAC</th><th>Reason</th><th>Blocked At</th></tr>{blocked_rows}</table>
</body></html>"""
