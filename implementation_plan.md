# Implementation Plan — Clean Figure Generation & Comprehensive Walkthrough

This implementation plan outlines the steps to remove all old figures, generate exactly the **5 updated benchmark images**, implement the modified **dual Y-axis Security Preservation figure**, and write a comprehensive walkthrough document explaining how each figure is generated, designed, and interpreted.

---

## 1. Summary of 5 Required Figures

| Figure Name | Output File Path | Description & Design |
|---|---|---|
| **1. Rescale vs Retrain** | `figures/fig1_rescale_vs_retrain.png` | Grouped bar chart comparing GNN zero-shot, rescaled, and retrained macro F1 scores across `StandardScaler`, `RobustScaler`, and `Tri-Channel` on DNS and FRIDAY datasets. |
| **2. Latency Over Time** | `figures/fig2_latency_timeline.png` | Time-series line plot (0s–60s) showing HTTP probe latency ($ms$) for Simple Switch 13 vs. ATDM across Small and Large topologies. |
| **3. Security Preservation** | `figures/fig3_security_preservation.png` | **Modified dual Y-axis bar chart**: Left Y-axis = Web Server count survived; Right Y-axis = DB Server count survived. Grouped by 2 controllers per topology, colored by 3 attack scenarios (`DDoS`, `SQLi`, `Exfiltration`). |
| **4. Bandwidth Over Time** | `figures/fig4_bandwidth_util.png` | Time-series line plot (0s–60s) showing bottleneck link utilization ($\%$) comparing Simple Switch 13 ($100\%$) vs. ATDM ($5.23\%$). |
| **5. Throughput Over Time** | `figures/fig5_throughput_timeline.png` | Time-series line plot (0s–60s) showing offered vs. delivered benign ($130.6\text{ KB/s}$) and attack ($24.0\text{ Mbps}$) throughput. |

---

## User Review Required

> [!IMPORTANT]
> **Key Figure Redesign Details**:
> 1. **Figures Directory Cleanup**: All existing files in `backend/benchmark/figures/` will be removed prior to regeneration so only the 5 fresh images remain.
> 2. **Figure 3 Dual Y-Axis Design**:
>    - **Left Y-Axis**: `Web Server Survived (Count)` (max = 1 in Small, max = 2 in Large).
>    - **Right Y-Axis**: `Database Server Survived (Count)` (max = 1 in Small, max = 1 in Large).
>    - **X-Axis Grouping**: 2 controller blocks per topology (`Simple Switch 13` vs `ATDM`).
>    - **Bar Colors**: 3 representative attack scenarios (`DDoS`, `SQL Injection`, `Exfiltration`).
> 3. **Comprehensive Walkthrough**: The `walkthrough.md` file will describe data sources, visual layout, data discussion, and exact regeneration commands for future code agents.

---

## Open Questions

> [!NOTE]
> None. All instructions are fully specified.

---

## Proposed Changes

### Component 1: Figures Directory Cleanup & Master Generator
#### [NEW] [generate_5_figures.py](file:///home/fyp2025/fyp/backend/benchmark/generate_5_figures.py)
- Cleans `/home/fyp2025/fyp/backend/benchmark/figures/`.
- Implements Figure 1 (`fig1_rescale_vs_retrain.png`).
- Implements Figure 2 (`fig2_latency_timeline.png`).
- Implements Figure 3 (`fig3_security_preservation.png` with twin X/Y axes for Web Server and DB counts).
- Implements Figure 4 (`fig4_bandwidth_util.png`).
- Implements Figure 5 (`fig5_throughput_timeline.png`).

---

### Component 2: Walkthrough Documentation for Code Agents
#### [MODIFY] [walkthrough.md](file:///home/fyp2025/fyp/walkthrough.md)
- Write an extensive section for EACH of the 5 figures:
  1. Data acquisition and exact formulas/JSON paths.
  2. Visual design, axes formatting, color palette, bar offsets, and annotations.
  3. In-depth empirical data discussion.
  4. Exact terminal commands for regeneration.

---

## Verification Plan

### Automated Verification Steps
1. **Cleanup Verification**: Confirm that `backend/benchmark/figures/` contains exactly 5 PNG files.
2. **Image Inspection**: Verify that `fig3_security_preservation.png` displays dual Y-axes (Web Server left, DB right), 2 controller groups per topology panel, and colors for 3 attack scenarios.
3. **Walkthrough Completeness**: Verify that `walkthrough.md` covers all 5 figures with data sources, design details, data discussions, and regeneration commands.

### Acceptance Criteria
- `backend/benchmark/figures/` contains ONLY the 5 fresh PNG files.
- Figure 3 uses dual Y-axes for Web Server and DB counts.
- `walkthrough.md` provides complete documentation for future Code Agents.
