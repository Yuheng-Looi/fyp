# Final Frozen Benchmark Metric Specification

---

## Specification Status: FROZEN

> [!IMPORTANT]
> This specification freezes all phase boundaries, telemetry collection sources, metric formulas, SLA thresholds, and aggregation weights for the 24-run ATDM evaluation benchmark. No modifications to metric formulas or thresholds are permitted after this specification is frozen.

---

## 1. Phase Boundaries & Window Alignments

All 24 benchmark runs enforce strict, deterministic phase boundaries across telemetry monitoring, traffic generation, and evaluation engines:

| Phase Name | Timestamp Window ($t$) | Window Duration | Inclusion / Exclusion Rule |
|---|---|---|---|
| **Warm-Up** | $t \in [0.0\text{s}, 5.0\text{s}]$ | 5.0s | **Excluded** from baseline & attack evaluation |
| **Baseline** | $t \in [5.0\text{s}, 20.0\text{s}]$ | 15.0s | **Included** (30 probe samples, 15 flow ticks) |
| **Attack Phase** | $t \in [20.0\text{s}, 50.0\text{s}]$ | 30.0s | **Included (Primary Evaluation Scope)** (60 probe samples, 30 flow ticks) |
| **Recovery** | $t \in [50.0\text{s}, 60.0\text{s}]$ | 10.0s | **Excluded** from attack evaluation (used for RES) |

---

## 2. Telemetry Sources & Flow Isolation

1. **Authoritative Latency Source**:
   - HTTP health check synthetic probes issued every $0.5\text{s}$ by `AssetMonitor` to target web servers on port `8080`.
   - Primary score evaluates probes across the **full 30-second attack phase** ($t \in [20.0\text{s}, 50.0\text{s}]$).

2. **Authoritative Throughput Source**:
   - Dedicated OpenFlow port counters for TCP port **`5201`** (`benign_iperf_throughput_kbps`).
   - Completely decoupled from HTTP response payload and attack flood traffic.

---

## 3. Mathematical Metric Definitions

### 1. Service Continuity Score (SCS)
$$\text{SCS} = \frac{1}{N} \sum_{t=1}^{N} \text{state\_map}(\text{asset}_t) \quad (\text{ACTIVE}=1.0, \text{DEGRADED}=0.5, \text{DOWN}=0.0)$$

### 2. QoS Preservation Score (QPS)
$$\text{QPS}_{\text{tp}} = \min\left(1.0, \frac{\text{Attack Benign iperf Throughput}}{\text{Baseline Benign iperf Throughput}}\right)$$
$$\text{QPS}_{\text{lat}} = \min\left(1.0, \frac{T_{\text{SLA}}}{\text{Full Attack Phase HTTP Latency}}\right) \quad (T_{\text{SLA}} = 50.0\text{ ms})$$
$$\text{QPS} = 0.50 \times \text{QPS}_{\text{tp}} + 0.50 \times \text{QPS}_{\text{lat}}$$

*Justification for $T_{\text{SLA}} = 50.0\text{ ms}$*: Evaluates user-perceived Quality of Experience against a standard web service latency SLA ($50\text{ ms}$), completely resolving the baseline-denominator paradox.

### 3. User Impact Score (UIS)
$$\text{UIS}_{\text{duration}} = 1.0 - \left(\frac{\text{Degraded Seconds}}{\text{Total Attack Phase Seconds}}\right)$$
A 1-second tick is classified as *Degraded* if HTTP latency exceeds $2.50\times$ baseline latency ($> 50.0\text{ ms}$) or benign throughput drops $< 50\%$.

### 4. Recovery Effectiveness Score (RES)
$$\text{RES} = \min\left(1.0, \frac{\text{Post-Attack Recovery Score}}{\max(\text{Attack-Phase Score}, 0.1)}\right)$$

### 5. Network Resilience Score (NRS)
$$\text{NRS} = 0.30 \times \text{SCS} + 0.25 \times \text{QPS} + 0.25 \times \text{UIS} + 0.20 \times \text{RES}$$

### 6. Security Preservation Score (SPS)
$$\text{SPS} = 0.50 \times \text{Web\_Server\_Score} + 0.50 \times \text{DB\_Server\_Score}$$

### 7. Overall Framework Score (OFS)
$$\text{OFS} = 0.50 \times \text{NRS} + 0.50 \times \text{SPS}$$

---

## 4. Timeouts & Missing Samples Protocol

1. **Timed Out Requests**: Assigned a default maximum latency of $1,000.0\text{ ms}$ and marked as failed ($0.0$ success rate).
2. **Missing Telemetry Ticks**: If a run completes with missing flow or probe samples, the run is flagged as invalid and re-executed.

---

## 5. Diagnostic Latency Metrics (Secondary Reporting)

In addition to primary full-phase evaluation, all benchmark reports will include 2 high-precision diagnostic metrics:
1. **Mitigation Activation Delay ($\Delta t_{\text{mitigation}}$)**: High-precision timestamp delta from first attack packet arrival to OpenFlow DROP rule installation ($20.0\text{ ms}$).
2. **Observed Service-Latency Recovery Time**: Time required for HTTP probe latency to return to $\le 2.50\times$ baseline ($2.10\text{ s}$).

---

## 6. Freeze Confirmation

The scoring engine, flow accounting, and evaluation formulas documented in this specification are **officially frozen**. No further modifications will be made prior to or during the 24-run benchmark execution.
