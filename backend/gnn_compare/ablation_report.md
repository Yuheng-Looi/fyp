# Adaptive IDS — Rescale vs Retrain Ablation Study Report

## Dataset: DNS

### Table A: Calibration Strategy Selection (DNS)
*Evaluated on the first 20,000 flows. Objective: avoid extreme ratio collapse.*

| Strategy | XGB threshold | IF threshold | Attack ratio | Confidence score | Selected strategy |
| --- | --- | --- | --- | --- | --- |
| Strategy A (AND) | 0.70 | 0.60 | 0.0008 | 0.9276 | No |
| Strategy B (OR) | 0.70 | 0.60 | 0.6420 | 0.3911 | No |
| Strategy C (AND) | 0.80 | 0.65 | 0.0001 | 0.9270 | No |
| Strategy D (OR) | 0.60 | 0.65 | 0.4739 | 0.5594 | Yes |

### Table B: Rescale vs Retrain Comparison (DNS)
*Evaluated on the next 40,000 test flows.*

| Model (Task) | Mode | Accuracy | F1 | Recall | FPR | Absolute F1 Improvement | Training cost |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MODEL1 (BINARY) | Baseline | 0.160872 | 0.277025 | 0.160787 | 0.200000 | - | 0.00s |
| MODEL1 (BINARY) | Rescale | 0.176631 | 0.300106 | 0.176548 | 0.200000 | +0.0231 | 0.00s |
| MODEL1 (BINARY) | Retrain | 0.935614 | 0.966736 | 0.935738 | 1.000000 | +0.6897 | 0.35s |
| MODEL1 (MULTICLASS) | Baseline | 0.000000 | 0.000000 | 0.101100 | 1.000000 | - | 0.00s |
| MODEL1 (MULTICLASS) | Rescale | 0.000079 | 0.000053 | 0.000106 | 0.400000 | +0.0001 | 0.00s |
| MODEL1 (MULTICLASS) | Retrain | 0.004627 | 0.004607 | 0.004575 | 0.600000 | +0.0046 | 0.11s |
| MODEL2 (BINARY) | Baseline | 0.570983 | 0.726875 | 0.570953 | 0.200000 | - | 0.00s |
| MODEL2 (BINARY) | Rescale | 0.019435 | 0.038128 | 0.019437 | 1.000000 | -0.6887 | 0.00s |
| MODEL2 (BINARY) | Retrain | 0.000502 | 0.000951 | 0.000476 | 0.800000 | -0.7259 | 0.12s |
| MODEL2 (MULTICLASS) | Baseline | 0.000053 | 0.000021 | 0.280214 | 0.600000 | - | 0.00s |
| MODEL2 (MULTICLASS) | Rescale | 0.000079 | 0.000032 | 0.060163 | 1.000000 | +0.0000 | 0.00s |
| MODEL2 (MULTICLASS) | Retrain | 0.000714 | 0.000713 | 0.000714 | 1.000000 | +0.0007 | 0.12s |
| MODEL3 (BINARY) | Baseline | 0.981649 | 0.990739 | 0.981673 | 0.200000 | - | 0.00s |
| MODEL3 (BINARY) | Rescale | 0.744599 | 0.853605 | 0.744698 | 1.000000 | -0.1371 | 0.00s |
| MODEL3 (BINARY) | Retrain | 0.000159 | 0.000317 | 0.000159 | 1.000000 | -0.9904 | 0.26s |
| MODEL3 (MULTICLASS) | Baseline | 0.000159 | 0.000262 | 0.918390 | 0.400000 | - | 0.00s |
| MODEL3 (MULTICLASS) | Rescale | 0.000159 | 0.000063 | 0.349580 | 1.000000 | -0.0002 | 0.00s |
| MODEL3 (MULTICLASS) | Retrain | 0.000687 | 0.000687 | 0.000688 | 1.000000 | +0.0004 | 0.15s |

---
## Dataset: FRIDAY

### Table A: Calibration Strategy Selection (FRIDAY)
*Evaluated on the first 20,000 flows. Objective: avoid extreme ratio collapse.*

| Strategy | XGB threshold | IF threshold | Attack ratio | Confidence score | Selected strategy |
| --- | --- | --- | --- | --- | --- |
| Strategy A (AND) | 0.70 | 0.60 | 0.0001 | 0.0058 | No |
| Strategy B (OR) | 0.70 | 0.60 | 0.9961 | 0.9951 | Yes |
| Strategy C (AND) | 0.80 | 0.65 | 0.0001 | 0.0058 | No |
| Strategy D (OR) | 0.60 | 0.65 | 0.9981 | 0.9956 | No |

### Table B: Rescale vs Retrain Comparison (FRIDAY)
*Evaluated on the next 40,000 test flows.*

| Model (Task) | Mode | Accuracy | F1 | Recall | FPR | Absolute F1 Improvement | Training cost |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MODEL1 (BINARY) | Baseline | 0.999350 | 0.999675 | 0.999600 | 0.500000 | - | 0.00s |
| MODEL1 (BINARY) | Rescale | 0.998825 | 0.999412 | 0.999150 | 0.650000 | -0.0003 | 0.00s |
| MODEL1 (BINARY) | Retrain | 0.998750 | 0.999374 | 0.999025 | 0.550000 | -0.0003 | 0.16s |
| MODEL1 (MULTICLASS) | Baseline | 0.999500 | 0.499875 | 1.000000 | 1.000000 | - | 0.00s |
| MODEL1 (MULTICLASS) | Rescale | 0.000325 | 0.000217 | 0.000550 | 0.450000 | -0.4997 | 0.00s |
| MODEL1 (MULTICLASS) | Retrain | 0.999375 | 0.807536 | 0.999375 | 0.000000 | +0.3077 | 0.06s |
| MODEL2 (BINARY) | Baseline | 0.999100 | 0.999550 | 0.999475 | 0.750000 | - | 0.00s |
| MODEL2 (BINARY) | Rescale | 0.999225 | 0.999612 | 0.999450 | 0.450000 | +0.0001 | 0.00s |
| MODEL2 (BINARY) | Retrain | 0.998725 | 0.999362 | 0.998749 | 0.050000 | -0.0002 | 0.04s |
| MODEL2 (MULTICLASS) | Baseline | 0.220875 | 0.090953 | 0.990295 | 0.000000 | - | 0.00s |
| MODEL2 (MULTICLASS) | Rescale | 0.012750 | 0.033228 | 0.991796 | 0.000000 | -0.0577 | 0.00s |
| MODEL2 (MULTICLASS) | Retrain | 0.999275 | 0.789674 | 0.999275 | 0.000000 | +0.6987 | 0.04s |
| MODEL3 (BINARY) | Baseline | 0.999225 | 0.999612 | 0.999725 | 1.000000 | - | 0.00s |
| MODEL3 (BINARY) | Rescale | 0.999200 | 0.999600 | 0.999700 | 1.000000 | -0.0000 | 0.00s |
| MODEL3 (BINARY) | Retrain | 0.999650 | 0.999825 | 1.000000 | 0.700000 | +0.0002 | 0.20s |
| MODEL3 (MULTICLASS) | Baseline | 0.306025 | 0.116035 | 0.999175 | 0.450000 | - | 0.00s |
| MODEL3 (MULTICLASS) | Rescale | 0.243375 | 0.118119 | 0.999175 | 0.500000 | +0.0021 | 0.00s |
| MODEL3 (MULTICLASS) | Retrain | 0.999275 | 0.789674 | 0.999275 | 0.000000 | +0.6736 | 0.03s |

---
## Table C: Key Insight Summary (Computed from Data)

| Question | Computed Insight |
| --- | --- |
| Which dataset benefits more from rescale? | DNS (average Model 1 F1 improvement: +0.0116 vs Friday: -0.2500) |
| Which model collapses without adaptation? | MODEL1 on DNS (F1 score: 0.1385) |
| Does retraining consistently outperform rescale? | Yes (Retraining was better in 8/12 model configurations) |
| When is rescale sufficient? | Rescale is sufficient in 8/12 configurations (F1 diff <= 0.05): MODEL1 MULTICLASS on DNS, MODEL2 BINARY on DNS, MODEL2 MULTICLASS on DNS, MODEL3 BINARY on DNS, MODEL3 MULTICLASS on DNS, MODEL1 BINARY on FRIDAY, MODEL2 BINARY on FRIDAY, MODEL3 BINARY on FRIDAY |
