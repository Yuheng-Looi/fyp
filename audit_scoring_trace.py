#!/usr/bin/env python3
"""
audit_scoring_trace.py — Audit and trace every score component to raw JSON fields and values.
"""

import glob
import json
import os
import sys

BASE_DIR = "/home/fyp2025/fyp/backend/benchmark/results/controlled_4_runs"


def audit_run_trace(fpath):
    with open(fpath) as f:
        data = json.load(f)

    meta = data.get("run_metadata", {})
    scores = data.get("scores", {})
    logs = data.get("per_second_logs", [])

    print("\n" + "=" * 110)
    print(f"  SCORE TRACE AUDIT: {meta.get('controller', '').upper()} | Topology: {meta.get('topology', '').upper()} | Scenario: {meta.get('scenario', '').upper()}")
    print(f"  JSON Path: {fpath}")
    print("=" * 110)

    # Trace QPS
    print("\n[QPS TRACE]")
    print(f"  - Field: scores.QPS_tp           | Raw Value: {scores.get('QPS_tp')} | Formula: avg_attack_tp / avg_base_tp")
    print(f"  - Field: scores.QPS_lat          | Raw Value: {scores.get('QPS_lat')} | Formula: base_lat / att_lat")
    print(f"  - Field: scores.QPS_lat_25ms     | Raw Value: {scores.get('QPS_lat_25ms')} | Sensitivity SLA: 25ms cap")
    print(f"  - Field: scores.QPS_lat_50ms     | Raw Value: {scores.get('QPS_lat_50ms')} | Sensitivity SLA: 50ms cap")
    print(f"  - Field: scores.QPS_lat_100ms    | Raw Value: {scores.get('QPS_lat_100ms')} | Sensitivity SLA: 100ms cap")
    print(f"  - Field: scores.QPS              | Final Value: {scores.get('QPS')} | Weighting: 0.50*QPS_tp + 0.50*QPS_lat")

    # Trace SCS & UIS
    print("\n[SCS & UIS TRACE]")
    print(f"  - Field: scores.SCS              | Final Value: {scores.get('SCS')} | Empirical State Map: ACTIVE=1.0, DEGRADED=0.5, DOWN=0.0")
    print(f"  - Field: scores.UIS              | Final Value: {scores.get('UIS')} | Duration-Weighted User Impact Ratio")

    # Trace RES, WS, DB, SPS, NRS, OFS
    print("\n[RES, SPS, NRS, OFS TRACE]")
    print(f"  - Field: scores.RES              | Final Value: {scores.get('RES')} | Mitigation Recovery Score (Unmitigated=0.0)")
    print(f"  - Field: scores.WS               | Final Value: {scores.get('WS')} | Web Server Survival Outcome")
    print(f"  - Field: scores.DB               | Final Value: {scores.get('DB')} | Database Preservation Outcome")
    print(f"  - Field: scores.SPS              | Final Value: {scores.get('SPS')} | Security Preservation Score (0.50*WS + 0.50*DB)")
    print(f"  - Field: scores.NRS              | Final Value: {scores.get('NRS')} | Network Resilience Score (0.30*SCS + 0.25*QPS + 0.25*UIS + 0.20*RES)")
    print(f"  - Field: scores.OFS              | Final Value: {scores.get('OFS')} | Overall Framework Score (0.50*NRS + 0.50*SPS)")


def main():
    files = sorted(glob.glob(os.path.join(BASE_DIR, "*.json")))
    if not files:
        files = sorted(glob.glob("/home/fyp2025/fyp/backend/benchmark/results/controlled_4_runs/*.json"))
    for f in files:
        audit_run_trace(f)


if __name__ == "__main__":
    main()
