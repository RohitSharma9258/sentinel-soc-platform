"""
NetGuard NDR - Beaconing / C2 Communication Detector
=====================================================
Detects periodic outbound communication patterns indicative of:
  - Malware beaconing
  - Botnet C2 callbacks
  - Scheduled data exfiltration

Algorithm:
  - Track per (src_ip, dst_ip, dst_port) connection timestamps
  - Compute inter-arrival time coefficient of variation (CV)
  - Low CV (<0.25) + high repetition (>5) = beacon alert
  - Uses entropy scoring for additional confidence
"""

import time
import math
import logging
import threading
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger("beaconing")

# ─── Configuration ────────────────────────────────────────────────────────────
BEACON_MIN_SAMPLES      = 5       # minimum observations to evaluate
BEACON_CV_THRESHOLD     = 0.25    # coefficient of variation; below = regular = suspicious
BEACON_MIN_INTERVAL_SEC = 5       # ignore beacons faster than this (normal keep-alives)
BEACON_MAX_INTERVAL_SEC = 3600    # ignore intervals longer than 1 hour
CLEANUP_INTERVAL_SEC    = 300     # purge old entries every 5 minutes
MAX_TRACKED_FLOWS       = 2000    # cap memory usage


class BeaconingDetector:
    """
    Tracks network flow timing patterns and detects C2 beaconing.
    Thread-safe singleton; called from the packet sniffer's detection window.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # (src_ip, dst_ip, dst_port) → list of timestamps
        self._flow_times: dict[tuple, list] = defaultdict(list)
        self._alerted_flows: set = set()   # already-alerted flows (suppress duplicates)
        self._last_cleanup = time.time()
        self._alerts = []

    # ── Public API ─────────────────────────────────────────────────────────────

    def observe(self, src_ip: str, dst_ip: str, dst_port: int):
        """
        Record a packet observation for a given flow.
        Call this for every outbound packet in the sniffer.
        """
        if not src_ip or not dst_ip:
            return
        now = time.time()
        key = (src_ip, dst_ip, dst_port)

        with self._lock:
            self._flow_times[key].append(now)
            # Keep only the last 60 samples to bound memory
            if len(self._flow_times[key]) > 60:
                self._flow_times[key] = self._flow_times[key][-60:]

            # Periodic cleanup
            if now - self._last_cleanup > CLEANUP_INTERVAL_SEC:
                self._cleanup(now)

    def analyze(self) -> list:
        """
        Analyze all tracked flows for beaconing patterns.
        Returns list of alert dicts for newly detected beacons.
        """
        new_alerts = []
        with self._lock:
            for flow_key, timestamps in list(self._flow_times.items()):
                if len(timestamps) < BEACON_MIN_SAMPLES:
                    continue
                if flow_key in self._alerted_flows:
                    continue

                result = self._score_flow(timestamps)
                if result["is_beacon"]:
                    src_ip, dst_ip, dst_port = flow_key
                    alert = {
                        "type":           "beaconing",
                        "src_ip":         src_ip,
                        "dst_ip":         dst_ip,
                        "dst_port":       dst_port,
                        "interval_sec":   round(result["mean_interval"], 1),
                        "cv":             round(result["cv"], 3),
                        "samples":        len(timestamps),
                        "confidence":     result["confidence"],
                        "description": (
                            f"Beaconing detected: {src_ip} → {dst_ip}:{dst_port} "
                            f"every ~{round(result['mean_interval'], 0)}s "
                            f"(CV={round(result['cv'], 3)}, "
                            f"confidence={result['confidence']}%)"
                        ),
                        "detected_at": datetime.now().isoformat(),
                    }
                    new_alerts.append(alert)
                    self._alerted_flows.add(flow_key)
                    self._alerts.append(alert)
                    logger.warning(
                        f"[BEACON] {src_ip} → {dst_ip}:{dst_port} | "
                        f"interval={round(result['mean_interval'],1)}s | "
                        f"CV={round(result['cv'],3)} | conf={result['confidence']}%"
                    )

        return new_alerts

    def get_alerts(self, clear=False) -> list:
        """Return accumulated beacon alerts."""
        with self._lock:
            alerts = list(self._alerts)
            if clear:
                self._alerts.clear()
        return alerts

    def get_beaconing_ips(self) -> set:
        """Return set of source IPs currently flagged as beaconing."""
        return {k[0] for k in self._alerted_flows}

    # ── Internal Scoring ───────────────────────────────────────────────────────

    def _score_flow(self, timestamps: list) -> dict:
        """Compute beacon score for a flow's timestamp sequence."""
        if len(timestamps) < BEACON_MIN_SAMPLES:
            return {"is_beacon": False}

        # Compute inter-arrival times
        sorted_ts = sorted(timestamps)
        intervals = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts)-1)]

        # Filter out unrealistic intervals
        intervals = [
            iv for iv in intervals
            if BEACON_MIN_INTERVAL_SEC <= iv <= BEACON_MAX_INTERVAL_SEC
        ]
        if len(intervals) < BEACON_MIN_SAMPLES - 1:
            return {"is_beacon": False}

        mean_iv = sum(intervals) / len(intervals)
        if mean_iv == 0:
            return {"is_beacon": False}

        # Coefficient of Variation (lower = more regular = more suspicious)
        variance = sum((iv - mean_iv) ** 2 for iv in intervals) / len(intervals)
        std_dev  = math.sqrt(variance)
        cv       = std_dev / mean_iv

        # Confidence score: inversely proportional to CV, boosted by sample count
        sample_bonus = min(30, len(intervals) * 2)
        base_confidence = max(0, int((1 - cv) * 70)) + sample_bonus
        confidence = min(100, base_confidence)

        is_beacon = cv < BEACON_CV_THRESHOLD and len(intervals) >= BEACON_MIN_SAMPLES - 1

        return {
            "is_beacon":     is_beacon,
            "cv":            cv,
            "mean_interval": mean_iv,
            "std_dev":       std_dev,
            "confidence":    confidence,
        }

    def _cleanup(self, now: float):
        """Remove stale flow entries."""
        cutoff = now - BEACON_MAX_INTERVAL_SEC * 2
        stale = [k for k, ts in self._flow_times.items() if not ts or ts[-1] < cutoff]
        for k in stale:
            del self._flow_times[k]
            self._alerted_flows.discard(k)

        # Hard cap on tracked flows
        if len(self._flow_times) > MAX_TRACKED_FLOWS:
            # Remove the oldest (by last seen)
            sorted_flows = sorted(self._flow_times.items(), key=lambda x: x[1][-1] if x[1] else 0)
            for k, _ in sorted_flows[:len(self._flow_times) - MAX_TRACKED_FLOWS]:
                del self._flow_times[k]

        self._last_cleanup = now


# ─── Module Singleton ──────────────────────────────────────────────────────────
beaconing_detector = BeaconingDetector()
