# GNN Models Evaluation & Comparison Report

This report compares the performance of three GNN models trained differently:
- **MODEL 1**: 15 features scaled via pre-trained **TriChannelScaler** (45 total features).
- **MODEL 2**: 51 raw features scaled via **StandardScaler**.
- **MODEL 3**: 15 raw features scaled via **StandardScaler**.

---

## Table 1: Original Validation/Test Results (Training Environment)
The metrics below are from the original GNN training runs on the validation/test sets.

| Model | Task | Architecture | Strategy | Test F1 | Attack Recall | FPR | Train Time (s) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| MODEL1 | BINARY | GAT | hybrid | 0.999492 | 0.999201 | 0.000877 | 4.89 |
| MODEL1 | MULTICLASS | SAGE | src_ip_temporal | 0.647618 | 0.999831 | 0.023675 | 1.63 |
| MODEL2 | BINARY | GAT | hybrid | 0.999092 | 0.998475 | 0.001169 | 1.85 |
| MODEL2 | MULTICLASS | SAGE | src_ip_temporal | 0.636985 | 0.999758 | 0.011302 | 1.27 |
| MODEL3 | BINARY | GAT | hybrid | 0.998584 | 0.998403 | 0.004969 | 1.71 |
| MODEL3 | MULTICLASS | SAGE | src_ip_temporal | 0.589259 | 0.999201 | 0.019486 | 1.42 |

---

## Table 2: Performance on External DNS Attack Dataset (`DrDoS_DNS_data_1_per.csv`)
Evaluated on a contiguous sample of **100000** flows. 
Labels mapped: `BENIGN` &rarr; `Normal`, `DrDoS_DNS` &rarr; `DDoS`.

| Model | Task | Accuracy | Test F1 | Attack Recall | FPR |
| --- | --- | --- | --- | --- | --- |
| MODEL1 | BINARY | 0.172652 | 0.280065 | 0.163822 | 0.336873 |
| MODEL1 | MULTICLASS | 0.012875 | 0.003395 | 0.066085 | 0.271976 |
| MODEL2 | BINARY | 0.332836 | 0.492214 | 0.329173 | 0.463717 |
| MODEL2 | MULTICLASS | 0.007178 | 0.002808 | 0.285552 | 0.602360 |
| MODEL3 | BINARY | 0.987960 | 0.993906 | 0.999480 | 0.651917 |
| MODEL3 | MULTICLASS | 0.007648 | 0.008657 | 0.870485 | 0.776401 |

---

## Table 3: Performance on External Friday DoS Dataset (`Friday-16-02-2018_TrafficForML_CICFlowMeter.csv`)
Evaluated on a contiguous sample of **100000** flows.
Labels mapped: `Benign` &rarr; `Normal`, `DoS attacks-Hulk` &rarr; `DoS`, `DoS attacks-SlowHTTPTest` &rarr; `DoS`.

| Model | Task | Accuracy | Test F1 | Attack Recall | FPR |
| --- | --- | --- | --- | --- | --- |
| MODEL1 | BINARY | 0.998120 | 0.999058 | 0.999840 | 0.646617 |
| MODEL1 | MULTICLASS | 0.915010 | 0.218954 | 1.000000 | 0.781955 |
| MODEL2 | BINARY | 0.930290 | 0.963828 | 0.931217 | 0.417293 |
| MODEL2 | MULTICLASS | 0.002540 | 0.008655 | 0.918443 | 0.169173 |
| MODEL3 | BINARY | 0.916790 | 0.956516 | 0.917621 | 0.394737 |
| MODEL3 | MULTICLASS | 0.020410 | 0.009975 | 0.918593 | 0.481203 |

*Note: For Binary tasks, Test F1 represents Binary F1 score; for Multiclass tasks, it represents Macro F1 score.*
