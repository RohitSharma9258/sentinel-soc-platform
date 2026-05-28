# 🛡️ ANTIGRAVITY Deployment Checklist

This document outlines the steps required to verify and deploy the ANTIGRAVITY protocol to production.

## 1. Pre-Deployment Verification
- [ ] Run `python3 -m py_compile app.py detector.py blocker.py database.py ai_predictor.py packet_sniffer.py` to ensure no syntax errors.
- [ ] Verify `config.py` has `ANTIGRAVITY_MODE = True`.
- [ ] Ensure `data/` and `logs/` directories have write permissions.

## 2. Functional Testing
- [ ] **Gateway Protection**: Attempt to block the gateway IP manually via API. System should reject it.
- [ ] **Localhost Protection**: Verify `127.0.0.1` cannot be blocked.
- [ ] **Trusted Device Bypass**: Trigger a low-severity threat from a "Known" device. Verify it is logged but NOT blocked.
- [ ] **Multi-Signal Block**: Trigger 3 "Low" threats from an unknown device. Verify auto-block triggers.

## 3. Production Launch
- [ ] Backup existing database: `cp data/intruder.db data/intruder.db.bak`
- [ ] Start the system: `python3 run.py`
- [ ] Check logs for `[ANTIGRAVITY] Startup audit complete`.

## 4. Emergency Procedures
- **Malfunction**: Disable via `sqlite3 data/intruder.db "UPDATE settings SET value='0' WHERE key='antigravity_mode';"`
- **Critical Block**: If a critical IP is blocked, run `sqlite3 data/intruder.db "DELETE FROM blocked_devices WHERE ip='<IP>';"`
