#!/usr/bin/env python3
"""
audit_scaler_comparison.py — Rigorous Audit and Detailed Metric Breakdown for Scaler Comparison
"""

import os
import sys
import json
import hashlib
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, classification_report, confusion_matrix

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
BACKEND_DIR = os.path.join(SCRIPT_DIR, "backend")
GNN_DIR = os.path.join(BACKEND_DIR, "gnn_compare")

if GNN_DIR not in sys.path:
    sys.path.append(GNN_DIR)

from fig1_rescale_retrain import (
    load_source_dataset, load_target_dataset, apply_scaler, train_gnn, build_graph,
    RAW_15_FEATURES, DNS_CSV, FRIDAY_CSV, GNN_CONFIG
)
from scaler_utils import TriChannelScaler
from sklearn.preprocessing import StandardScaler, RobustScaler
import torch


def get_df_hash(df):
    """Compute MD5 hash of dataframe values for partition disjointness proof."""
    val_bytes = pd.util.hash_pandas_object(df, index=False).values.tobytes()
    return hashlib.md5(val_bytes).hexdigest()[:12]


def audit_partitions():
    print("=" * 80)
    print("  PARTITION AUDIT & DISJOINTNESS PROOF")
    print("=" * 80)

    dns_df = load_target_dataset(DNS_CSV, 'dns', nrows=60000)
    friday_df = load_target_dataset(FRIDAY_CSV, 'friday', nrows=60000)

    dns_calib = dns_df.iloc[:20000].reset_index(drop=True)
    dns_test = dns_df.iloc[20000:].reset_index(drop=True)

    fri_calib = friday_df.iloc[:20000].reset_index(drop=True)
    fri_test = friday_df.iloc[20000:].reset_index(drop=True)

    print(f"DNS Full Rows:      {len(dns_df)} | Hash: {get_df_hash(dns_df)}")
    print(f"DNS Calib Subset:   {len(dns_calib)} rows | Hash: {get_df_hash(dns_calib)} | Class Dist: {dict(dns_calib['Label_Binary'].value_counts())}")
    print(f"DNS Test Subset:    {len(dns_test)} rows | Hash: {get_df_hash(dns_test)} | Class Dist: {dict(dns_test['Label_Binary'].value_counts())}")

    print(f"\nFRIDAY Full Rows:   {len(friday_df)} | Hash: {get_df_hash(friday_df)}")
    print(f"FRIDAY Calib Subset:{len(fri_calib)} rows | Hash: {get_df_hash(fri_calib)} | Class Dist: {dict(fri_calib['Label_Binary'].value_counts())}")
    print(f"FRIDAY Test Subset: {len(fri_test)} rows | Hash: {get_df_hash(fri_test)} | Class Dist: {dict(fri_test['Label_Binary'].value_counts())}")

    dns_overlap = len(pd.merge(dns_calib, dns_test, how='inner'))
    fri_overlap = len(pd.merge(fri_calib, fri_test, how='inner'))

    print(f"\n[LEAKAGE CHECK] DNS Calib vs Test Overlap: {dns_overlap} rows (MUST BE 0)")
    print(f"[LEAKAGE CHECK] FRIDAY Calib vs Test Overlap: {fri_overlap} rows (MUST BE 0)")
    print("=" * 80)


if __name__ == "__main__":
    audit_partitions()
