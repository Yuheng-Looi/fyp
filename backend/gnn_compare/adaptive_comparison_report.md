# Adaptive GNN IDS Calibration Experiment Report

## Dataset: DNS

### Table X: Pseudo-label calibration strategy comparison
*Tested on the first 20,000 flows. Strategy selected based on high confidence and viable Normal ratio.*

| Strategy | XGB threshold | IF threshold | Attack ratio | Normal ratio | Pseudo confidence | Selected? |
| --- | --- | --- | --- | --- | --- | --- |
| Option A (AND) | 0.70 | 0.55 | 0.0020 | 0.9980 | 0.9315 | No |
| Option A (AND) | 0.70 | 0.60 | 0.0008 | 0.9992 | 0.9306 | No |
| Option A (AND) | 0.70 | 0.65 | 0.0001 | 1.0000 | 0.9300 | No |
| Option B (OR) | 0.70 | 0.55 | 0.9402 | 0.0598 | 0.1163 | No |
| Option B (OR) | 0.70 | 0.60 | 0.6449 | 0.3551 | 0.3944 | No |
| Option B (OR) | 0.70 | 0.65 | 0.4736 | 0.5264 | 0.5617 | No |
| Option C (AND) | 0.80 | 0.55 | 0.0019 | 0.9980 | 0.9315 | No |
| Option C (AND) | 0.80 | 0.60 | 0.0008 | 0.9992 | 0.9306 | No |
| Option C (AND) | 0.80 | 0.65 | 0.0001 | 1.0000 | 0.9300 | No |
| Option D (OR) | 0.60 | 0.55 | 0.9414 | 0.0586 | 0.1167 | No |
| Option D (OR) | 0.60 | 0.60 | 0.6462 | 0.3538 | 0.3949 | No |
| Option D (OR) | 0.60 | 0.65 | 0.4748 | 0.5252 | 0.5621 | Yes |

### Table Y: Adaptive external dataset evaluation
*Evaluated on the next 40,000 test flows. Normal labels mapped: BENIGN &rarr; Normal, DrDoS_DNS / DoS attacks &rarr; Attack.*

| Model | Task | Accuracy | Test F1 | Attack Recall | FPR | Calibration Method |
| --- | --- | --- | --- | --- | --- | --- |
| MODEL1 | BINARY | 0.176525 | 0.300079 | 0.176548 | 1.000000 | Original |
| MODEL1 | BINARY | 0.936223 | 0.967058 | 0.936267 | 0.400000 | Adaptive |
| MODEL1 | MULTICLASS | 0.000026 | 0.000011 | 0.002883 | 0.800000 | Original |
| MODEL1 | MULTICLASS | 0.000079 | 0.036364 | 0.999339 | 0.400000 | Adaptive |
| MODEL2 | BINARY | 0.412518 | 0.584026 | 0.412466 | 0.200000 | Original |
| MODEL2 | BINARY | 0.000423 | 0.000793 | 0.000397 | 0.800000 | Adaptive |
| MODEL2 | MULTICLASS | 0.000053 | 0.000019 | 0.215079 | 0.600000 | Original |
| MODEL2 | MULTICLASS | 0.000079 | 0.000032 | 0.004549 | 1.000000 | Adaptive |
| MODEL3 | BINARY | 0.996721 | 0.998358 | 0.996747 | 0.200000 | Original |
| MODEL3 | BINARY | 0.619265 | 0.764872 | 0.619347 | 1.000000 | Adaptive |
| MODEL3 | MULTICLASS | 0.001349 | 0.000544 | 0.912704 | 0.400000 | Original |
| MODEL3 | MULTICLASS | 0.000106 | 0.000053 | 0.411884 | 1.000000 | Adaptive |

---
## Dataset: FRIDAY

### Table X: Pseudo-label calibration strategy comparison
*Tested on the first 20,000 flows. Strategy selected based on high confidence and viable Normal ratio.*

| Strategy | XGB threshold | IF threshold | Attack ratio | Normal ratio | Pseudo confidence | Selected? |
| --- | --- | --- | --- | --- | --- | --- |
| Option A (AND) | 0.70 | 0.55 | 0.0003 | 0.9998 | 0.0062 | No |
| Option A (AND) | 0.70 | 0.60 | 0.0001 | 1.0000 | 0.0060 | No |
| Option A (AND) | 0.70 | 0.65 | 0.0001 | 1.0000 | 0.0060 | No |
| Option B (OR) | 0.70 | 0.55 | 0.9982 | 0.0018 | 0.9953 | No |
| Option B (OR) | 0.70 | 0.60 | 0.9961 | 0.0039 | 0.9953 | No |
| Option B (OR) | 0.70 | 0.65 | 0.9961 | 0.0039 | 0.9954 | Yes |
| Option C (AND) | 0.80 | 0.55 | 0.0002 | 0.9998 | 0.0062 | No |
| Option C (AND) | 0.80 | 0.60 | 0.0001 | 1.0000 | 0.0060 | No |
| Option C (AND) | 0.80 | 0.65 | 0.0001 | 1.0000 | 0.0060 | No |
| Option D (OR) | 0.60 | 0.55 | 0.9982 | 0.0018 | 0.9953 | No |
| Option D (OR) | 0.60 | 0.60 | 0.9961 | 0.0039 | 0.9953 | No |
| Option D (OR) | 0.60 | 0.65 | 0.9961 | 0.0039 | 0.9954 | No |

### Table Y: Adaptive external dataset evaluation
*Evaluated on the next 40,000 test flows. Normal labels mapped: BENIGN &rarr; Normal, DrDoS_DNS / DoS attacks &rarr; Attack.*

| Model | Task | Accuracy | Test F1 | Attack Recall | FPR | Calibration Method |
| --- | --- | --- | --- | --- | --- | --- |
| MODEL1 | BINARY | 0.999250 | 0.999625 | 0.999625 | 0.750000 | Original |
| MODEL1 | BINARY | 0.959775 | 0.979470 | 0.960030 | 0.550000 | Adaptive |
| MODEL1 | MULTICLASS | 0.999500 | 0.499875 | 1.000000 | 1.000000 | Original |
| MODEL1 | MULTICLASS | 0.036825 | 0.120796 | 0.999475 | 0.650000 | Adaptive |
| MODEL2 | BINARY | 0.999000 | 0.999500 | 0.999375 | 0.750000 | Original |
| MODEL2 | BINARY | 0.999025 | 0.999512 | 0.999375 | 0.700000 | Adaptive |
| MODEL2 | MULTICLASS | 0.005400 | 0.003769 | 0.812881 | 0.000000 | Original |
| MODEL2 | MULTICLASS | 0.001600 | 0.008608 | 0.969960 | 0.000000 | Adaptive |
| MODEL3 | BINARY | 0.998375 | 0.999187 | 0.998599 | 0.450000 | Original |
| MODEL3 | BINARY | 0.998450 | 0.999224 | 0.998674 | 0.450000 | Adaptive |
| MODEL3 | MULTICLASS | 0.207000 | 0.089783 | 0.998849 | 0.450000 | Original |
| MODEL3 | MULTICLASS | 0.195775 | 0.088647 | 0.998899 | 0.450000 | Adaptive |

---
