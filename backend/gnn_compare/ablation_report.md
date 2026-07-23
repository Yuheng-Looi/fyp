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
| MODEL1 (BINARY) | Baseline | 0.160872 | 0.277025 | 0.160787 | 0.200000 | - | 0.00s |
| MODEL1 (BINARY) | Rescale | 0.929321 | 0.963363 | 0.929365 | 0.400000 | +0.6863 | 0.00s |
| MODEL1 (BINARY) | Retrain | 0.000132 | 0.000159 | 0.000079 | 0.600000 | -0.2769 | 0.15s |
| MODEL1 (MULTICLASS) | Baseline | 0.000000 | 0.000000 | 0.101047 | 1.000000 | - | 0.00s |
| MODEL1 (MULTICLASS) | Rescale | 0.000079 | 0.036585 | 0.999127 | 0.400000 | +0.0366 | 0.00s |
| MODEL1 (MULTICLASS) | Retrain | 0.936566 | 0.484454 | 0.936637 | 0.600000 | +0.4845 | 0.06s |
| MODEL2 (BINARY) | Baseline | 0.412518 | 0.584026 | 0.412466 | 0.200000 | - | 0.00s |
| MODEL2 (BINARY) | Rescale | 0.013327 | 0.026303 | 0.013328 | 1.000000 | -0.5577 | 0.00s |
| MODEL2 (BINARY) | Retrain | 0.000317 | 0.000634 | 0.000317 | 1.000000 | -0.5834 | 0.13s |
| MODEL2 (MULTICLASS) | Baseline | 0.000053 | 0.000019 | 0.215079 | 0.600000 | - | 0.00s |
| MODEL2 (MULTICLASS) | Rescale | 0.000079 | 0.000032 | 0.028244 | 1.000000 | +0.0000 | 0.00s |
| MODEL2 (MULTICLASS) | Retrain | 0.000635 | 0.000634 | 0.000635 | 1.000000 | +0.0006 | 0.11s |
| MODEL3 (BINARY) | Baseline | 0.981649 | 0.990739 | 0.981673 | 0.200000 | - | 0.00s |
| MODEL3 (BINARY) | Rescale | 0.744573 | 0.853588 | 0.744671 | 1.000000 | -0.1372 | 0.00s |
| MODEL3 (BINARY) | Retrain | 0.000159 | 0.000317 | 0.000159 | 1.000000 | -0.9904 | 0.13s |
| MODEL3 (MULTICLASS) | Baseline | 0.000159 | 0.000262 | 0.918390 | 0.400000 | - | 0.00s |
| MODEL3 (MULTICLASS) | Rescale | 0.000159 | 0.000063 | 0.349818 | 1.000000 | -0.0002 | 0.00s |
| MODEL3 (MULTICLASS) | Retrain | 0.000635 | 0.000634 | 0.000635 | 1.000000 | +0.0004 | 0.10s |

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
| MODEL1 (BINARY) | Baseline | 0.999350 | 0.999675 | 0.999600 | 0.500000 | - | 0.00s |
| MODEL1 (BINARY) | Rescale | 0.998825 | 0.999412 | 0.999150 | 0.650000 | -0.0003 | 0.00s |
| MODEL1 (BINARY) | Retrain | 0.997950 | 0.998974 | 0.998374 | 0.850000 | -0.0007 | 0.03s |
| MODEL1 (MULTICLASS) | Baseline | 0.999500 | 0.499875 | 1.000000 | 1.000000 | - | 0.00s |
| MODEL1 (MULTICLASS) | Rescale | 0.000200 | 0.000133 | 0.000850 | 0.650000 | -0.4997 | 0.00s |
| MODEL1 (MULTICLASS) | Retrain | 0.999000 | 0.705632 | 0.999150 | 0.300000 | +0.2058 | 0.02s |
| MODEL2 (BINARY) | Baseline | 0.999000 | 0.999500 | 0.999375 | 0.750000 | - | 0.00s |
| MODEL2 (BINARY) | Rescale | 0.999025 | 0.999512 | 0.999375 | 0.700000 | +0.0000 | 0.00s |
| MODEL2 (BINARY) | Retrain | 0.999650 | 0.999825 | 0.999950 | 0.600000 | +0.0003 | 0.14s |
| MODEL2 (MULTICLASS) | Baseline | 0.005400 | 0.003769 | 0.812881 | 0.000000 | - | 0.00s |
| MODEL2 (MULTICLASS) | Rescale | 0.001600 | 0.008608 | 0.969960 | 0.000000 | +0.0048 | 0.00s |
| MODEL2 (MULTICLASS) | Retrain | 0.999300 | 0.793942 | 0.999300 | 0.000000 | +0.7902 | 0.04s |
| MODEL3 (BINARY) | Baseline | 0.999225 | 0.999612 | 0.999725 | 1.000000 | - | 0.00s |
| MODEL3 (BINARY) | Rescale | 0.999200 | 0.999600 | 0.999700 | 1.000000 | -0.0000 | 0.00s |
| MODEL3 (BINARY) | Retrain | 0.999175 | 0.999587 | 0.999550 | 0.750000 | -0.0000 | 0.14s |
| MODEL3 (MULTICLASS) | Baseline | 0.306025 | 0.116035 | 0.999175 | 0.450000 | - | 0.00s |
| MODEL3 (MULTICLASS) | Rescale | 0.243375 | 0.118119 | 0.999175 | 0.500000 | +0.0021 | 0.00s |
| MODEL3 (MULTICLASS) | Retrain | 0.999450 | 0.822443 | 0.999450 | 0.000000 | +0.7064 | 0.03s |

---
## Table C: Key Insight Summary (Computed from Data)

| Question | Computed Insight |
| --- | --- |
| Which dataset benefits more from rescale? | DNS (average Model 1 F1 improvement: +0.3615 vs Friday: -0.2500) |
| Which model collapses without adaptation? | MODEL1 on DNS (F1 score: 0.1385) |
| Does retraining consistently outperform rescale? | Yes (Retraining was better in 7/12 model configurations) |
| When is rescale sufficient? | Rescale is sufficient in 8/12 configurations (F1 diff <= 0.05): MODEL1 BINARY on DNS, MODEL2 BINARY on DNS, MODEL2 MULTICLASS on DNS, MODEL3 BINARY on DNS, MODEL3 MULTICLASS on DNS, MODEL1 BINARY on FRIDAY, MODEL2 BINARY on FRIDAY, MODEL3 BINARY on FRIDAY |
