"""
Smart WiFi Intruder Detection System - AI Threat Predictor
Machine learning-based threat prediction using device behavior patterns.
"""

import logging
import threading
import time
import os
from datetime import datetime, timedelta
from collections import defaultdict

from config import AUTO_BLOCK_THREAT_LEVEL, AI_MODEL_PATH, AI_TRAINING_INTERVAL
from database import db
from models import Threat

logger = logging.getLogger("ai_predictor")

# ML: Optional sklearn imports for anomaly detection
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import numpy as np
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


# RULES: Helper function to inspect hostname for penetration testing or suspicious terms
def _analyze_hostname(hostname):
    """
    Check device hostname against known security tools or suspicious patterns.
    Returns the count of matching patterns.
    """
    if not hostname or hostname == "Unknown":
        return 0
    
    hostname_lower = hostname.lower()
    suspicious_patterns = [
        "kali", "metasploit", "hack", "evil", "attack",
        "pentest", "nmap", "burp", "exploit", "pwn",
        "poison", "spoof", "mitm", "intercept"
    ]
    matches = sum(1 for p in suspicious_patterns if p in hostname_lower)
    return matches


class AIPredictor:
    """
    AI-based threat prediction engine.
    Uses behavioral analysis and a hybrid of rule-based scoring 
    and a scikit-learn Isolation Forest anomaly detector.
    """

    def __init__(self):
        self._device_profiles = {}   # mac -> behavioral profile
        self._predictions = []
        self._lock = threading.Lock()
        self._running = False
        self._thread = None
        self._last_training_time = 0

        # ML: ML-based anomaly detection state
        self._ml_model = None
        self._ml_scaler = None
        self._training_data = []   # list of feature vectors
        self._min_samples = 20     # need 20 samples to train

        # Behavioral baselines
        self._baselines = defaultdict(lambda: {
            "avg_packets": 0,
            "avg_ports": 0,
            "avg_connections": 0,
            "normal_hours": set(),
            "normal_ips": set(),
            "samples": 0,
        })

    def start(self):
        """Start the AI prediction engine."""
        if self._running:
            return
        self._running = True

        # ML: Try loading the saved model and scaler on startup
        if ML_AVAILABLE:
            try:
                if os.path.exists(AI_MODEL_PATH):
                    self._ml_model, self._ml_scaler = joblib.load(AI_MODEL_PATH)
                    logger.info("ML: Loaded existing model and scaler from storage.")
                else:
                    logger.info("ML: No saved model found, will train from data.")
            except Exception as e:
                logger.warning(f"ML: Failed to load saved model: {e}")

        self._thread = threading.Thread(target=self._prediction_loop, daemon=True, name="AIPredictor")
        self._thread.start()
        logger.info("AI Predictor started")

    def stop(self):
        """Stop the AI prediction engine."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _prediction_loop(self):
        """Continuous prediction analysis loop."""
        self._last_training_time = time.time()
        while self._running:
            try:
                self._analyze_device_behaviors()
                self._detect_anomalies()
                self._predict_threats()

                # ML: Rebuild training data list from currently tracked device profiles
                if ML_AVAILABLE:
                    new_training_data = []
                    devices = db.get_all_devices()
                    for device in devices:
                        mac = device["mac"]
                        profile = self._device_profiles.get(mac)
                        if profile:
                            features = self._extract_features(device, profile)
                            new_training_data.append(features)
                    
                    self._training_data = new_training_data
                    
                    # ML: Train the model when training interval has elapsed
                    now = time.time()
                    if now - self._last_training_time >= AI_TRAINING_INTERVAL:
                        self._train_model()
                        self._last_training_time = now

            except Exception as e:
                logger.error(f"AI prediction error: {e}")
            time.sleep(30)  # Analyze every 30 seconds

    def _analyze_device_behaviors(self):
        """Build behavioral profiles for all devices."""
        devices = db.get_all_devices()

        for device in devices:
            mac = device["mac"]
            profile = self._device_profiles.get(mac, {
                "first_seen": device["first_seen"],
                "appearance_count": 0,
                "threat_history": [],
                "online_times": [],
                "risk_score": 0,
                "is_known": device.get("is_known", False),
            })

            profile["appearance_count"] += 1
            profile["last_ip"] = device["ip"]
            profile["is_known"] = device.get("is_known", False)
            profile["online_times"].append(datetime.now().hour)

            # Keep only last 100 online times
            if len(profile["online_times"]) > 100:
                profile["online_times"] = profile["online_times"][-100:]

            self._device_profiles[mac] = profile

    # RULES: Calculate rule-based anomaly score using weighted factors
    def _calculate_weighted_score(self, device, profile):
        """
        Calculates a rule-based risk score using weighted conditions.
        Returns (score: int, reasons: list, factor_breakdown: dict).
        """
        reasons = []
        breakdown = {}
        
        # ── Factor 1: Device Trust Status (weight: 0.25, max: 25) ────
        is_known = device.get("is_known", False) or profile.get("is_known", False)
        trust_score = device.get("trust_score", 100)
        f1_score = 0
        if not is_known:
            if trust_score < 30:
                f1_score = 25
                reasons.append("Untrusted device with critical trust score")
            elif trust_score <= 60:
                f1_score = 15
                reasons.append("Untrusted device with low trust score")
            else:
                f1_score = 8
                reasons.append("Untrusted device on network")
        breakdown["trust_status"] = f1_score

        # ── Factor 2: Device Age on Network (weight: 0.15, max: 15) ──
        f2_score = 0
        try:
            first_seen_str = device.get("first_seen") or profile.get("first_seen")
            first_seen = datetime.fromisoformat(first_seen_str)
            age_sec = (datetime.now() - first_seen).total_seconds()
            if age_sec < 120:  # < 2 minutes
                f2_score = 15
                reasons.append("Recently joined network (< 2 minutes ago)")
            elif age_sec < 600:  # < 10 minutes
                f2_score = 10
                reasons.append("Recently joined network (< 10 minutes ago)")
            elif age_sec < 1800:  # < 30 minutes
                f2_score = 5
                reasons.append("Recently joined network (< 30 minutes ago)")
        except Exception:
            pass
        breakdown["device_age"] = f2_score

        # ── Factor 3: Threat History (weight: 0.30, max: 30) ─────────
        f3_score = 0
        mac = device.get("mac", "").upper()
        threat_count = db.get_threat_count_by_mac(mac, window_seconds=3600)
        if threat_count >= 3:
            f3_score = 30
            reasons.append("Frequent threats detected in last hour")
        elif threat_count == 2:
            f3_score = 20
            reasons.append("Multiple threats detected in last hour")
        elif threat_count == 1:
            f3_score = 10
            reasons.append("Recent threat detected in last hour")
        breakdown["threat_history"] = f3_score

        # ── Factor 4: Hostname Analysis (weight: 0.20, max: 20) ───────
        f4_score = 0
        hostname = device.get("hostname", "Unknown")
        matches = _analyze_hostname(hostname)
        if matches >= 2:
            f4_score = 20
            reasons.append(f"Highly suspicious hostname ({matches} attack signatures): {hostname}")
        elif matches == 1:
            f4_score = 12
            reasons.append(f"Suspicious hostname pattern matched: {hostname}")
        breakdown["hostname_analysis"] = f4_score

        # ── Factor 5: Vendor Reputation (weight: 0.10, max: 10) ───────
        f5_score = 0
        vendor = device.get("vendor", "Unknown")
        if vendor == "Unknown":
            if not is_known:
                f5_score = 10
                reasons.append("Unknown vendor for untrusted device")
            else:
                f5_score = 3
                reasons.append("Unknown vendor for trusted device")
        breakdown["vendor_reputation"] = f5_score

        # ── Factor 6: Time-based Activity (weight: 0.10, max: 10) ─────
        f6_score = 0
        current_hour = datetime.now().hour
        if 1 <= current_hour <= 4:
            if not is_known:
                f6_score = 10
                reasons.append("Untrusted device active during late night hours")
            else:
                f6_score = 2
                reasons.append("Trusted device active during late night hours")
        breakdown["time_activity"] = f6_score

        total_score = min(f1_score + f2_score + f3_score + f4_score + f5_score + f6_score, 100)
        return total_score, reasons, breakdown

    # ML: Extract feature vector from device and profile
    def _extract_features(self, device, profile):
        """Extracts the 8-feature representation for ML models."""
        try:
            is_known = 1.0 if (device.get("is_known", False) or profile.get("is_known", False)) else 0.0
            trust_score = float(device.get("trust_score", 100))
            
            # Age in minutes
            try:
                first_seen_str = device.get("first_seen") or profile.get("first_seen")
                first_seen = datetime.fromisoformat(first_seen_str)
                device_age_minutes = (datetime.now() - first_seen).total_seconds() / 60.0
            except Exception:
                device_age_minutes = 0.0

            mac = device.get("mac", "").upper()
            threat_count_1h = float(db.get_threat_count_by_mac(mac, window_seconds=3600))
            appearance_count = float(profile.get("appearance_count", 0))
            hour_of_day = float(datetime.now().hour)
            vendor_known = 0.0 if device.get("vendor", "Unknown") == "Unknown" else 1.0
            
            hostname = device.get("hostname", "Unknown")
            hostname_suspicious = 1.0 if _analyze_hostname(hostname) > 0 else 0.0
            
            return [
                is_known,
                trust_score,
                device_age_minutes,
                threat_count_1h,
                appearance_count,
                hour_of_day,
                vendor_known,
                hostname_suspicious
            ]
        except Exception as e:
            logger.error(f"ML: Feature extraction error: {e}")
            return [0.0, 100.0, 0.0, 0.0, 1.0, float(datetime.now().hour), 0.0, 0.0]

    # ML: Train the scikit-learn IsolationForest model
    def _train_model(self):
        """Train Isolation Forest on accumulated device feature profiles."""
        if not ML_AVAILABLE:
            return
        
        try:
            if len(self._training_data) < self._min_samples:
                logger.info(f"ML: Not enough samples to train model ({len(self._training_data)}/{self._min_samples})")
                return

            logger.info(f"ML: Training anomaly detector on {len(self._training_data)} samples...")
            X = np.array(self._training_data)
            
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            model = IsolationForest(contamination=0.1, random_state=42)
            model.fit(X_scaled)
            
            # Save model and scaler to storage
            joblib.dump((model, scaler), AI_MODEL_PATH)
            
            self._ml_model = model
            self._ml_scaler = scaler
            logger.info(f"ML model trained on {len(self._training_data)} samples and saved to {AI_MODEL_PATH}")
        except Exception as e:
            logger.error(f"ML: Model training failed: {e}")

    # ML: Predict anomaly score using the ML model
    def _ml_predict(self, features):
        """Returns anomaly score 0.0 to 1.0 (1.0 = most anomalous)."""
        if not ML_AVAILABLE or self._ml_model is None or self._ml_scaler is None:
            return 0.0
            
        try:
            X = np.array([features])
            X_scaled = self._ml_scaler.transform(X)
            
            raw_score = self._ml_model.decision_function(X_scaled)[0]
            # Normalization: map typical raw range [-0.5, 0.5] to [1.0, 0.0]
            ml_score = 0.5 - raw_score
            ml_score = max(0.0, min(1.0, ml_score))
            return ml_score
        except Exception as e:
            logger.error(f"ML: Prediction error: {e}")
            return 0.0

    # RULES / ML: Combine rule-based score and ML anomaly score
    def _calculate_hybrid_score(self, rule_score, ml_score):
        """
        Weighted combination:
        - If ML model not trained: 100% rule-based
        - If ML model trained:
            final = (rule_score * 0.6) + (ml_score * 100 * 0.4)
        Returns int 0-100
        """
        if not ML_AVAILABLE or self._ml_model is None:
            return int(round(rule_score))
        
        final_score = (rule_score * 0.6) + (ml_score * 100.0 * 0.4)
        return int(round(max(0, min(100, final_score))))

    def _detect_anomalies(self):
        """Detect behavioral anomalies across all devices using hybrid rules + ML."""
        devices = db.get_all_devices()

        for device in devices:
            mac = device["mac"]
            profile = self._device_profiles.get(mac)
            if not profile:
                continue

            # RULES: 1. Calculate weighted rules score
            rule_score, reasons, breakdown = self._calculate_weighted_score(device, profile)
            
            # ML: 2. Extract features and predict using IsolationForest
            features = self._extract_features(device, profile)
            ml_score = self._ml_predict(features)
            
            # Hybrid: 3. Compute final weighted score
            hybrid_score = self._calculate_hybrid_score(rule_score, ml_score)
            
            # Save results back to profile
            profile["risk_score"] = hybrid_score
            profile["rule_score"] = rule_score
            profile["ml_score"] = ml_score
            profile["anomaly_reasons"] = reasons
            profile["factor_breakdown"] = breakdown

    def _predict_threats(self):
        """Generate AI-based threat predictions."""
        predictions = []

        for mac, profile in self._device_profiles.items():
            risk = profile.get("risk_score", 0)

            # classification thresholds
            if risk >= 50:
                level = "critical" if risk >= 75 else "high"
                prediction = {
                    "mac": mac,
                    "ip": profile.get("last_ip", ""),
                    "risk_score": risk,
                    "rule_score": profile.get("rule_score", 0),
                    "ml_score": profile.get("ml_score", 0.0),
                    "threat_level": level,
                    "reasons": profile.get("anomaly_reasons", []),
                    "factor_breakdown": profile.get("factor_breakdown", {}),
                    "predicted_at": datetime.now().isoformat(),
                    "confidence": min(risk / 100.0, 0.95),
                }
                predictions.append(prediction)

                # Record as threat if not already recorded recently
                recent_count = db.get_threat_count_by_mac(mac, window_seconds=300)
                if recent_count == 0:
                    from detector import detector
                    threat = Threat(
                        device_mac=mac,
                        device_ip=profile.get("last_ip", ""),
                        threat_type="ai_predicted",
                        threat_level=level,
                        threat_score=risk,
                        description=f"AI predicted threat: {', '.join(profile.get('anomaly_reasons', []))}",
                        details={
                            "risk_score": risk,
                            "rule_score": profile.get("rule_score", 0),
                            "ml_score": profile.get("ml_score", 0.0),
                            "confidence": prediction["confidence"],
                            "factors": profile.get("anomaly_reasons", []),
                            "factor_breakdown": profile.get("factor_breakdown", {}),
                        }
                    )
                    detector._record_threat(threat)
                    logger.warning(
                        f"AI PREDICTION: {level} risk for {mac} (hybrid_score: {risk}, "
                        f"rule_score: {profile.get('rule_score', 0)}, ml_score: {profile.get('ml_score', 0.0):.2f})"
                    )

            elif risk >= 25:
                prediction = {
                    "mac": mac,
                    "ip": profile.get("last_ip", ""),
                    "risk_score": risk,
                    "rule_score": profile.get("rule_score", 0),
                    "ml_score": profile.get("ml_score", 0.0),
                    "threat_level": "medium",
                    "reasons": profile.get("anomaly_reasons", []),
                    "factor_breakdown": profile.get("factor_breakdown", {}),
                    "predicted_at": datetime.now().isoformat(),
                    "confidence": risk / 100.0,
                }
                predictions.append(prediction)

        with self._lock:
            self._predictions = predictions

    # ═══════════════════════════════════════════════════════════════════════
    #  PUBLIC API
    # ═══════════════════════════════════════════════════════════════════════

    def get_predictions(self):
        """Get current AI predictions."""
        with self._lock:
            return list(self._predictions)

    def get_device_risk(self, mac):
        """Get AI risk assessment for a specific device."""
        profile = self._device_profiles.get(mac.upper(), {})
        risk = profile.get("risk_score", 0)
        
        # Determine threat level
        if risk >= 75:
            level = "critical"
        elif risk >= 50:
            level = "high"
        elif risk >= 25:
            level = "medium"
        else:
            level = "none"

        return {
            "mac": mac.upper(),
            "risk_score": risk,
            "rule_score": profile.get("rule_score", 0),
            "ml_score": float(profile.get("ml_score", 0.0)),
            "threat_level": level,
            "reasons": profile.get("anomaly_reasons", []),
            "factor_breakdown": profile.get("factor_breakdown", {}),
            "is_known": profile.get("is_known", False),
            "appearance_count": profile.get("appearance_count", 0),
        }

    def get_stats(self):
        """Get AI predictor stats."""
        with self._lock:
            high_risk = sum(1 for p in self._predictions if p["risk_score"] >= 50)
            medium_risk = sum(1 for p in self._predictions if 25 <= p["risk_score"] < 50)
            
        if ML_AVAILABLE and self._ml_model is not None:
            accuracy_str = f"IsolationForest(n={len(self._training_data)})"
            scoring_mode = "hybrid"
            model_trained = True
        else:
            accuracy_str = "N/A"
            scoring_mode = "rules_only"
            model_trained = False

        return {
            "running": self._running,
            "profiles_tracked": len(self._device_profiles),
            "active_predictions": len(self._predictions),
            "high_risk_devices": high_risk,
            "medium_risk_devices": medium_risk,
            "ml_model_trained": model_trained,
            "ml_training_samples": len(self._training_data),
            "ml_model_accuracy": accuracy_str,
            "scoring_mode": scoring_mode,
        }


# Module singleton
predictor = AIPredictor()
