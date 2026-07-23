# Paper Figures — Data Availability & TODO Report

> **Generated**: 2026-07-13  
> **Purpose**: Documents which metrics are available and which additional
> experiments must be executed before all figures are complete.

---

## Figure Status

| Figure | Status | Notes |
|--------|--------|-------|
| Fig 1: Rescale vs Retrain | ⚠️ Partial | Missing StandardScaler & RobustScaler binary GNN experiments |
| Fig 2: Latency Comparison | ✅ Complete | Uses `latency_avg` from `summary.csv` |
| Fig 3: Security Preservation | ✅ Complete | Uses WS/DB from `summary.csv` |
| Fig 4: Service Availability | ✅ Complete | Uses SCS from `summary.csv` |

---

## Figure 1: Missing Experiments

### What Exists

- **MODEL1 (TriChannelScaler, 45 features)**: Binary GNN trained and evaluated
  - Rescale vs Retrain results on DNS and FRIDAY datasets
  - Source: `gnn_compare/ablation_study_results.csv`
  - Model: `gnn_compare/model1_binary_model.pt`
  - Config: `gnn_compare/model1_binary_config.json`

- **MODEL3 (Raw, 15 features)**: Binary GNN trained and evaluated
  - Rescale vs Retrain results on DNS and FRIDAY datasets
  - Source: `gnn_compare/ablation_study_results.csv`

### What Is Missing

1. **StandardScaler Binary GNN (15 features)**
   - Training script: `gnn_compare/train_model_standard.py` ✅ Created
   - Model output: `gnn_compare/model_standard_binary_model.pt` ❌ Not yet trained
   - Scaler: `scalers/standard_scaler_15feat.pkl` ❌ Not yet fitted
   - **Action required**: Run `python3 gnn_compare/train_model_standard.py`

2. **RobustScaler Binary GNN (15 features)**
   - Training script: `gnn_compare/train_model_robust.py` ✅ Created
   - Model output: `gnn_compare/model_robust_binary_model.pt` ❌ Not yet trained
   - Scaler: `scalers/robust_scaler_15feat.pkl` ❌ Not yet fitted
   - **Action required**: Run `python3 gnn_compare/train_model_robust.py`

3. **Rescale vs Retrain evaluation for new models on DNS and FRIDAY**
   - Evaluation script: `gnn_compare/evaluate_adaptive.py` needs updating to
     support the new StandardScaler and RobustScaler models
   - **Action required**: After training, run the adapted evaluation and append
     results to `gnn_compare/ablation_study_results.csv`

### Execution Order

```bash
# Step 1: Train StandardScaler model
cd /home/fyp2025/fyp/backend
python3 gnn_compare/train_model_standard.py

# Step 2: Train RobustScaler model
python3 gnn_compare/train_model_robust.py

# Step 3: Run rescale/retrain evaluation on DNS and FRIDAY
python3 gnn_compare/evaluate_adaptive.py --dataset dns --models model_standard model_robust
python3 gnn_compare/evaluate_adaptive.py --dataset friday --models model_standard model_robust

# Step 4: Regenerate all figures
python3 benchmark/images/paper_figures.py
```

---

## Figure 2: Latency Data Notes

### Available Data
- `summary.csv` contains `latency_avg` per (controller × topology × scenario)
- Small topology runs have real ping latency (70–590 ms range)
- Large topology runs report 0 ms (ping monitoring was disabled for large topology)

### Known Limitation
- **Per-tick timeline latency** is not persisted in the raw JSON outputs
- The `probe_history` data (per-second latency) is consumed by the scoring
  engine during evaluation but not saved to `results/benchmark_runs/`
- To generate a proper latency-over-time line chart, the experiment runner
  must be modified to persist `probe_history` into the JSON output

### To Enable Per-Tick Latency Export

Modify `core/experiment_runner.py` at the `export_results()` call to also
include `self._asset_monitor.probe_history` in the JSON output:

```python
# In experiment_runner.py, after scoring evaluation:
scores = self._scoring.get_scores()
scores["probe_history"] = self._asset_monitor.probe_history  # Add this
return scores
```

---

## Figure 3 & 4: Complete

All required metrics (WS, DB, SPS, SCS) are available in `summary.csv` for
all 9 controllers × 2 topologies × 6 scenarios × 5 seeds.

---

## Benchmark Runner Changes

The benchmark runner has been streamlined:
- **Before**: 5 controllers × 2 topologies × 6 scenarios × 5 seeds = **300 runs**
- **After**: 5 controllers × 2 topologies × 6 scenarios × 1 seed = **60 runs**
- **Speedup**: ~5× faster execution time

Existing results from 5-seed runs remain valid and are still used for figure
generation. The 1-seed configuration is for any future re-runs.

---

## Reproducibility

To regenerate all figures from existing data:

```bash
cd /home/fyp2025/fyp/backend/benchmark/images
python3 paper_figures.py
```

Output files:
- `fig1_rescale_vs_retrain.png`
- `fig2_latency_comparison.png`
- `fig3_security_preservation.png`
- `fig4_service_availability.png`
