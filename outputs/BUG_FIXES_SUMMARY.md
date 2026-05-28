# 🐞 Bug Fixes Summary - Smart WiFi Intruder Detection System

The following critical and high-severity bugs were identified and fixed during the stabilization phase.

## 1. Packet Sniffer Logic Bugs
- **Issue**: `_check_arp_spoof()` was using undefined `elapsed` and `now` variables.
- **Fix**: Extracted detection window logic into a separate `_check_detection_window()` method and ensured proper state management.
- **Impact**: Resolved periodic sniffer crashes.

## 2. Model Definition Duplication
- **Issue**: `ScanResult` dataclass was defined twice with conflicting fields.
- **Fix**: Merged into a single robust dataclass with support for `scan_timestamp` and `timestamp` alias.
- **Impact**: Unified data structure across the app.

## 3. Database Inconsistency
- **Issue**: `get_threat_count_by_mac()` and `cleanup_stale_devices()` had duplicate, conflicting implementations.
- **Fix**: Merged methods, standardized on seconds-based windows, and added logic to remove foreign subnet devices.
- **Impact**: Improved database hygiene and query accuracy.

## 4. Performance Bottlenecks
- **Issue**: `get_default_gateway()` was being called repeatedly, spawning subprocesses.
- **Fix**: Cached gateway IP in `Blocker.__init__()` and implemented periodic re-validation.
- **Impact**: Significant reduction in CPU usage during active blocking.

## 5. False Positive Reduction
- **Issue**: Hostname suspicious check was using simple substring matching (e.g., "kali" in "kali-linux" would match "skali").
- **Fix**: Implemented word-splitting matching for hostnames.
- **Impact**: Fewer false-positive threat detections.
