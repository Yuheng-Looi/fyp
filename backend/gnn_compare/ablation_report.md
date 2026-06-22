# Adaptive IDS — Rescale vs Retrain Ablation Study Report

## Dataset: DNS

### Table A: Calibration Strategy Selection (DNS)
*Evaluated on the first 20,000 flows. Objective: avoid extreme ratio collapse.*

| Strategy | XGB threshold | IF threshold | Attack ratio | Confidence score | Selected strategy |
| --- | --- | --- | --- | --- | --- |
| Strategy A (AND) | 0.70 | 0.60 | 0.0008 | 0.9306 | No |
| Strategy B (OR) | 0.70 | 0.60 | 0.6449 | 0.3944 | No |
| Strategy C (AND) | 0.80 | 0.65 | 0.0001 | 0.9300 | No |
| Strategy D (OR) | 0.60 | 0.65 | 0.4748 | 0.5621 | Yes |

### Table B: Rescale vs Retrain Comparison (DNS)
*Evaluated on the next 40,000 test flows.*

| Model (Task) | Mode | Accuracy | F1 | Recall | FPR | Absolute F1 Improvement | Training cost |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MODEL1 (BINARY) | Baseline | 0.176525 | 0.300079 | 0.176548 | 1.000000 | - | 0.00s |
| MODEL1 (BINARY) | Rescale | 0.936223 | 0.967058 | 0.936267 | 0.400000 | +0.6670 | 0.00s |
| MODEL1 (BINARY) | Retrain | 0.000132 | 0.000000 | 0.000000 | 0.000000 | -0.3001 | 0.17s |
| MODEL1 (MULTICLASS) | Baseline | 0.000026 | 0.000011 | 0.002883 | 0.800000 | - | 0.00s |
| MODEL1 (MULTICLASS) | Rescale | 0.000079 | 0.036364 | 0.999339 | 0.400000 | +0.0364 | 0.00s |
| MODEL1 (MULTICLASS) | Retrain | 0.935350 | 0.484520 | 0.935394 | 0.400000 | +0.4845 | 0.10s |
| MODEL2 (BINARY) | Baseline | 0.412518 | 0.584026 | 0.412466 | 0.200000 | - | 0.00s |
| MODEL2 (BINARY) | Rescale | 0.013327 | 0.026303 | 0.013328 | 1.000000 | -0.5577 | 0.00s |
| MODEL2 (BINARY) | Retrain | 0.000450 | 0.000846 | 0.000423 | 0.800000 | -0.5832 | 0.12s |
| MODEL2 (MULTICLASS) | Baseline | 0.000053 | 0.000019 | 0.215079 | 0.600000 | - | 0.00s |
| MODEL2 (MULTICLASS) | Rescale | 0.000079 | 0.000032 | 0.028244 | 1.000000 | +0.0000 | 0.00s |
| MODEL2 (MULTICLASS) | Retrain | 0.000661 | 0.000661 | 0.000661 | 1.000000 | +0.0006 | 0.10s |
| MODEL3 (BINARY) | Baseline | 0.996721 | 0.998358 | 0.996747 | 0.200000 | - | 0.00s |
| MODEL3 (BINARY) | Rescale | 0.999868 | 0.999934 | 1.000000 | 1.000000 | +0.0016 | 0.00s |
| MODEL3 (BINARY) | Retrain | 0.000450 | 0.000899 | 0.000450 | 1.000000 | -0.9975 | 0.11s |
| MODEL3 (MULTICLASS) | Baseline | 0.001349 | 0.000544 | 0.912704 | 0.400000 | - | 0.00s |
| MODEL3 (MULTICLASS) | Rescale | 0.000159 | 0.000063 | 0.694637 | 1.000000 | -0.0005 | 0.00s |
| MODEL3 (MULTICLASS) | Retrain | 0.000582 | 0.000581 | 0.000582 | 1.000000 | +0.0000 | 0.09s |

---
## Dataset: FRIDAY

### Table A: Calibration Strategy Selection (FRIDAY)
*Evaluated on the first 20,000 flows. Objective: avoid extreme ratio collapse.*

| Strategy | XGB threshold | IF threshold | Attack ratio | Confidence score | Selected strategy |
| --- | --- | --- | --- | --- | --- |
| Strategy A (AND) | 0.70 | 0.60 | 0.0001 | 0.0060 | No |
| Strategy B (OR) | 0.70 | 0.60 | 0.9961 | 0.9953 | No |
| Strategy C (AND) | 0.80 | 0.65 | 0.0001 | 0.0060 | No |
| Strategy D (OR) | 0.60 | 0.65 | 0.9961 | 0.9954 | Yes |

### Table B: Rescale vs Retrain Comparison (FRIDAY)
*Evaluated on the next 40,000 test flows.*

| Model (Task) | Mode | Accuracy | F1 | Recall | FPR | Absolute F1 Improvement | Training cost |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MODEL1 (BINARY) | Baseline | 0.999250 | 0.999625 | 0.999625 | 0.750000 | - | 0.00s |
| MODEL1 (BINARY) | Rescale | 0.959775 | 0.979470 | 0.960030 | 0.550000 | -0.0202 | 0.00s |
| MODEL1 (BINARY) | Retrain | 0.998450 | 0.999224 | 0.998624 | 0.350000 | -0.0004 | 0.03s |
| MODEL1 (MULTICLASS) | Baseline | 0.999500 | 0.499875 | 1.000000 | 1.000000 | - | 0.00s |
| MODEL1 (MULTICLASS) | Rescale | 0.036825 | 0.120796 | 0.999475 | 0.650000 | -0.3791 | 0.00s |
| MODEL1 (MULTICLASS) | Retrain | 0.999250 | 0.785527 | 0.999250 | 0.000000 | +0.2857 | 0.02s |
| MODEL2 (BINARY) | Baseline | 0.999000 | 0.999500 | 0.999375 | 0.750000 | - | 0.00s |
| MODEL2 (BINARY) | Rescale | 0.999025 | 0.999512 | 0.999375 | 0.700000 | +0.0000 | 0.00s |
| MODEL2 (BINARY) | Retrain | 0.999325 | 0.999662 | 0.999600 | 0.550000 | +0.0002 | 0.12s |
| MODEL2 (MULTICLASS) | Baseline | 0.005400 | 0.003769 | 0.812881 | 0.000000 | - | 0.00s |
| MODEL2 (MULTICLASS) | Rescale | 0.001600 | 0.008608 | 0.969960 | 0.000000 | +0.0048 | 0.00s |
| MODEL2 (MULTICLASS) | Retrain | 0.999450 | 0.822443 | 0.999450 | 0.000000 | +0.8187 | 0.05s |
| MODEL3 (BINARY) | Baseline | 0.998375 | 0.999187 | 0.998599 | 0.450000 | - | 0.00s |
| MODEL3 (BINARY) | Rescale | 0.998450 | 0.999224 | 0.998674 | 0.450000 | +0.0000 | 0.00s |
| MODEL3 (BINARY) | Retrain | 0.999650 | 0.999825 | 0.999875 | 0.450000 | +0.0006 | 0.12s |
| MODEL3 (MULTICLASS) | Baseline | 0.207000 | 0.089783 | 0.998849 | 0.450000 | - | 0.00s |
| MODEL3 (MULTICLASS) | Rescale | 0.195775 | 0.088647 | 0.998899 | 0.450000 | -0.0011 | 0.00s |
| MODEL3 (MULTICLASS) | Retrain | 0.999300 | 0.793942 | 0.999300 | 0.000000 | +0.7042 | 0.04s |

---
## Table C: Key Insight Summary (Computed from Data)

| Question | Computed Insight |
| --- | --- |
| Which dataset benefits more from rescale? | DNS (average Model 1 F1 improvement: +0.3517 vs Friday: -0.1996) |
| Which model collapses without adaptation? | MODEL1 on DNS (F1 score: 0.1500) |
| Does retraining consistently outperform rescale? | Yes (Retraining was better in 9/12 model configurations) |
| When is rescale sufficient? | Rescale is sufficient in 8/12 configurations (F1 diff <= 0.05): MODEL1 BINARY on DNS, MODEL2 BINARY on DNS, MODEL2 MULTICLASS on DNS, MODEL3 BINARY on DNS, MODEL3 MULTICLASS on DNS, MODEL1 BINARY on FRIDAY, MODEL2 BINARY on FRIDAY, MODEL3 BINARY on FRIDAY |
