# 🛡️ ANTIGRAVITY Technical Report

## Overview
The ANTIGRAVITY protocol is a multi-layered security wrapper designed to protect critical network infrastructure from automated defense actions.

## 1. Multi-Layer Protection Logic
The protocol employs four layers of verification before any blocking action:
1. **Permanent Infrastructure**: Localhost, Broadcast, and loopback IPs are hard-exempted.
2. **Dynamic Infrastructure**: The default gateway is detected and validated via ping.
3. **Identity Verification**: Known/Trusted devices are identified by MAC and IP.
4. **Policy Enforcement**: `ANTIGRAVITY_MODE` toggle provides a global safety switch.

## 2. Multi-Signal Threat Analysis
Instead of blocking on a single event, the system now requires:
- **High-Confidence Signals**: MAC spoofing or Flood attacks trigger instant blocks.
- **Aggregated Risk**: 3+ threats in 5 minutes trigger a block.
- **Repeated Critical Threats**: 2+ critical threats in 10 minutes trigger a block.

## 3. Audit and Visibility
Every exemption is recorded in the `logs` table with `is_audit=1`. These can be queried via the `/antigravity/stats` endpoint or viewed live on the dashboard.

## 4. Self-Healing Startup Audit
On boot, the system verifies that no critical IPs are present in the `blocked_devices` table. If any are found, they are automatically unblocked to ensure network connectivity.
