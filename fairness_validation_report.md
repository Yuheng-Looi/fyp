# Fairness Validation & System Fix Report

**Project**: Adaptive Threat Detection & Mitigation (ATDM) System  
**Date**: July 24, 2026  
**Scope**: Implementation & Measurement Bug Fixes, Fair Evaluation, and Reproducibility Validation

---

## 1. Executive Summary

This report documents all technical modifications made to the ATDM controller (`controller_4.py`), the SDN benchmark runner (`experiment_runner.py`), the scoring engine (`scoring_engine.py`), the monitoring asset probe engine (`asset_monitor.py`), and the GNN feature scaling evaluation pipeline (`scaler_utils.py` & `fig1_rescale_retrain.py`).

All modifications were strictly performed to fix confirmed technical bugs, correct measurement/aggregation flaws, and preserve absolute experimental fairness across controllers, topologies, scenarios, and random seeds.

---

## 2. Comprehensive Before-and-After Modification Audit

| # | File / Component Changed | Identified Problem / Bug | Technical Justification | Classification | Affected Controllers | Evidence of Preserved Fairness |
|---|---|---|---|---|---|---|
| **1** | `backend/benchmark/controllers/controller_4.py` (lines 843–851) | `DEST_SUBNET_METER` rule matched `ipv4_dst = ip_dst` tied to a 128 kbps meter. In Large Topology, this trapped ALL legitimate HTTP traffic and latency probes to `ip_dst` under 16 KB/s, driving latency to 2,105 ms. | Rate-limiting must target offending malicious source flows (`ipv4_src = ip_src, ipv4_dst = ip_dst`) rather than throttling the entire destination server for all benign hosts. | **Controller Correctness Fix** | ATDM (`controller_4`) only | Simple Switch 13 has no rate-limiting; ATDM now limits attack flows without starving benign user probes. |
| **2** | `backend/benchmark/controllers/controller_4.py` (lines 878–941) | `RATE_LIMIT` and `GLOBAL_RATE_LIMIT` matched over-specific 5-tuples including randomized source ports (`sport`). Attack packets with new ports bypassed flow rules, flooding switch PacketIn to the controller. | Malicious source rate-limiting must match `ipv4_src = ip_src` to block/throttle all attack traffic from an offending IP at the switch datapath without controller queue congestion. | **Controller Correctness Fix** | ATDM (`controller_4`) only | Applies standard SDN ingress rate-limiting matching source IP; does not alter traffic for non-attacking hosts. |
| **3** | `backend/benchmark/core/experiment_runner.py` (line 148) | Missing static ARP population after Mininet network startup (`self._net.staticArp()`), causing initial HTTP probes to fail with `[Errno 113] No route to host`. | In Mininet topologies, static ARP table population (`arp -s`) prevents initial ARP broadcast lookup delays and packet drops before switch flow rules are installed. | **Experimental Fairness Fix** | Both (`simple_switch_13` & `controller_4`) | Applied identically to all benchmark runs for both controllers across all topologies. |
| **4** | `backend/benchmark/topology/small.py` & `large.py` (line 37) | `python3 -m http.server 80 &` launched background HTTP servers without `nohup` or process isolation, causing services to die or fail silently during test execution. | HTTP asset services (`web_server` and `internal_db`) must run as persistent daemons (`nohup python3 -m http.server 80 &`) to respond to health probes throughout the 65s timeline. | **Bug Fix** | Both (`simple_switch_13` & `controller_4`) | Standardizes service availability across both controller benchmark runs. |
| **5** | `backend/benchmark/monitoring/asset_monitor.py` (lines 105–125) | `_probe_http_via_host` executed complex `python3 -c "exec(...)"` strings inside host namespaces with 1–2s max-time timeouts, causing false `ERR <urlopen error timed out>` failures. | Replaced custom python `exec` with native lightweight `curl` probing (`curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 5`), providing accurate millisecond latency and status codes. | **Measurement Fix** | Both (`simple_switch_13` & `controller_4`) | Uses identical `curl` measurement logic for all probe requests in both controllers. |
| **6** | `backend/benchmark/evaluation/scoring_engine.py` (lines 77–92) | `WS` (Web Server) and `DB` (Database) scores were omitted from `self.scores` dictionary returned by `ScoringEngine.evaluate()`, causing scores to default to `0.0`. | Explicitly added `WS`, `DB`, `SPS`, and `OFS` calculations into `ScoringEngine` return dictionary based on health probe history. | **Measurement Fix** | Both (`simple_switch_13` & `controller_4`) | Scores calculated using identical formulas for both controllers. |
| **7** | `backend/scaler_utils.py` (lines 134–149) | `TriChannelScaler` did not clip negative special network values (e.g. `Init Bwd Win Byts = -1`) to $\ge 0$ before ratio division, producing extreme unclipped outputs (`mean = -5331.02`). | Added non-negative clipping (`np.clip(x, 0.0, None)`) for ratio channel and array-level symmetric clipping (`[-10.0, +10.0]`) for delta channel. | **Bug Fix** | GNN Scaler Comparison Pipeline | Ensures Tri-Channel scaler generates bounded, valid feature representations. |
| **8** | `backend/gnn_compare/fig1_rescale_retrain.py` (lines 405–480) | Evaluated GNN models trained on source scaler representation against target datasets without training separate architecturally equivalent GNNs per scaler format. | Enforced fairness rule: A GNN trained with one scaler representation (15 or 45 features) must be trained and evaluated with the same representation structure. | **Experimental Fairness Fix** | GNN Scaler Comparison Pipeline | All 3 scalers (StandardScaler, RobustScaler, Tri-Channel) train separate, architecturally identical GNNs ($N=3$ seeds). |
| **9** | `backend/benchmark/benchmark_runner.py` (line 49) | Single-run execution per condition ($N=1$). | Configured `NUM_SEEDS = 3` to execute 3 independent random seed repetitions ($N=3$) for all 2 Controllers $\times$ 2 Topologies $\times$ 6 Scenarios = 72 total benchmark runs. | **Experimental Fairness Fix** | Both (`simple_switch_13` & `controller_4`) | Evaluates all conditions across 3 seeds ($N=3$) with reported Mean, Std Dev, Min, Max, and 95% CIs. |

---

## 3. Experimental Fairness Verification Checklist

- [x] **Equal Network & Topology**: `simple_switch_13` and `controller_4` were tested on identical Mininet topology definitions (`small.py` and `large.py`) with identical link bandwidths (20 Mbps) and delay settings.
- [x] **Equal Traffic & Attack Triggers**: Both controllers executed identical 65-second timeline schedules (5s warmup, 15s baseline, 30s attack, 15s recovery) using identical traffic generators (`h1` benign client, attack scripts).
- [x] **Equal Service Health & Monitoring**: Probe interval (1s), timeout (5s), and target URLs (`http://10.0.0.2:80/` and `http://10.0.0.3:80/`) were identical.
- [x] **Equal Scoring Engine**: Both controllers were evaluated using the exact same `ScoringEngine` instance and metric formulas (SCS, QPS, UIS, RES, NRS, WS, DB, SPS, OFS).
- [x] **Equal Random Seeds**: Both controllers and GNN models were evaluated across seeds `1, 2, 3` (benchmark) and `42, 52, 62` (GNN scaling).
