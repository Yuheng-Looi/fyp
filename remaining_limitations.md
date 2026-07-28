> [!WARNING]
> **SUPERSEDED REPORT — DO NOT USE FOR FINAL PRESENTATION OR EVIDENCE**
> This document contains outdated single-seed (N=1) or 24-run benchmark statistics.
> Refer strictly to the canonical 72-run multi-seed (N=3) report: [FINAL_ATDM_RESULTS_REPORT.md](file:///home/fyp2025/fyp/FINAL_ATDM_RESULTS_REPORT.md).

# Remaining System Limitations & Technical Evaluation

**Project**: Adaptive Threat Detection & Mitigation (ATDM) System  
**Date**: July 24, 2026  
**Purpose**: Objective, Empirical Assessment of Current System Constraints & Remaining Performance Boundaries

---

## 1. Executive Summary

Following the comprehensive multi-seed benchmark rerun ($N=3$) and technical debugging phase, all implementation bugs (destination meter traps, ephemeral port matching leaks, silent daemon process terminations, missing scoring dictionary keys, unclipped Tri-Channel scalers) have been resolved.

This document presents an honest, empirical analysis of remaining architectural boundaries and system performance limitations.

---

## 2. Empirical Performance Assessment & Technical Findings

### A. Results That Improved Significantly
1. **Large Topology DoS Latency**:
   - Resolved the 2,105 ms latency trap caused by global destination-subnet metering (`ipv4_dst = ip_dst`). By matching offending source flows (`ipv4_src = ip_src`), benign probe latency during DoS dropped to **28.6 ms** (a **98.6% reduction**).
2. **Volumetric DDoS Bandwidth Mitigation**:
   - Updating rate-limiting and honeypot redirect rules to target malicious source IPs at the switch datapath reduced peak DDoS bandwidth utilization from **98.2% to 62.5%** in the Large Topology.
3. **Application-Layer Protection Scores**:
   - Integrating `WS` (Web Server Survival) and `DB` (Database Preservation) into `ScoringEngine.evaluate()` restored valid non-zero scoring (**0.500** and **0.417** respectively).

---

### B. Remaining System & Architectural Limitations

#### 1. Aggregate Bandwidth Saturation Under High Ingress Volume
- **Observation**: While ATDM suppresses DDoS peak bandwidth utilization to 62.5% on multi-switch topologies, bandwidth utilization remains above 60% during high-volume distributed attack windows.
- **Root Cause**: Open vSwitch meters apply rate limits at the switch ingress port, but attack packets still traverse the physical link from the host interface to the switch before being dropped or metered. In topologies with single inter-switch link bottlenecks, aggregate link capacity is still partially consumed by physical packet arrival.
- **System Limitation**: Edge switch rate-limiting cannot prevent upstream physical link capacity consumption if the upstream link itself is overloaded prior to entering the OpenFlow datapath.

#### 2. Tri-Channel Feature Scaling Under Domain Shift
- **Observation**: Tri-Channel rescaling performs poorly when evaluated across different dataset distributions (achieving only **4.09% F1 score** on DNS when rescaled without retraining, compared to **64.63% F1 score** for StandardScaler).
- **Root Cause**: Tri-Channel scaling decomposes features into original value, ratio channel, and temporal delta channel. For zero-variance features or unobserved target domains (such as DNS where feature ranges differ by order of magnitude), ratio divisions magnify distribution shifts rather than smoothing them out.
- **System Limitation**: Tri-Channel rescaling is **NOT supported** by corrected experimental results as a universal domain transfer mechanism. StandardScaler feature normalization is significantly more robust for zero-shot domain adaptation.

#### 3. Scope of Zero-Shot Rescaling vs Full Model Retraining
- **Observation**: Direct feature rescaling (without model weight fine-tuning or retraining) is only effective under minor dataset shifts (e.g. FRIDAY dataset shift, where all scalers achieve >99.9% F1). Under major distribution shifts (e.g. DNS dataset shift), feature rescaling fails to achieve acceptable detection accuracy (maximum 64.63% F1 for StandardScaler).
- **System Limitation**: Zero-shot feature rescaling is **insufficient** under major domain shifts. **Full model retraining remains strictly necessary** when deploying GNN models to drastically different network environments (achieving **99.995% F1 score** when retrained).

#### 4. Controller Inference Overhead in Multi-Switch Topologies
- **Observation**: When processing first-packet asynchronous inference requests across multiple OpenFlow 1.3 switches (`s1`, `s2`), controller-to-switch control channel latency introduces a minor delay (up to 12.8 ms) before flow rules are pushed.
- **System Limitation**: First-packet PacketIn processing introduces transient control plane latency prior to datapath flow rule installation.

---

## 3. Summary Matrix of Findings & Technical Recommendations

| Component / Mechanism | Claimed Benefit | Verified Reality (Empirical Evidence) | Recommendation |
|---|---|---|---|
| **ATDM Source Rate-Limiting** | Suppress DoS/DDoS impact | **Verified**: Reduces DoS latency by 98.6% and DDoS peak bandwidth by 35.7%. | Maintain source IP flow matching (`ipv4_src = ip_src`). |
| **Tri-Channel Scaler** | Universal domain transfer | **Unsupported**: Achieves only 4.09% F1 on DNS (vs 64.63% for StandardScaler). | Prefer StandardScaler for feature normalization; avoid Tri-Channel for unknown domains. |
| **Zero-Shot Rescaling** | Avoid model retraining | **Partial**: Works for minor shifts (FRIDAY: 99.98% F1), fails on major shifts (DNS: 64.63% F1). | Require full GNN retraining when deploying across distinct network domains (DNS retrained F1 = 99.995%). |
| **Ingress Switch Metering** | Eliminate link congestion | **Partial**: Reduces switch internal load, but upstream link capacity is partially consumed prior to ingress drop. | Implement upstream edge filtering at host network interfaces or ISP ingress points. |
