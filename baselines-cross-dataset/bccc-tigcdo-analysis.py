#!/usr/bin/env python3
"""
TIG-CDO Comparative Analysis on BCCC-Cloud-2024 Dataset
Maps cloud DDoS attack characteristics to TIG-CDO threat model phases.
Produces comparative table for Paper 2 Section VII.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, precision_score, recall_score, classification_report
import time
import json
from pathlib import Path

DATA_PATH = Path("/Volumes/1TB-SSD/ddos-data/07-sdn-cloud/bccc-cloud-2024/bccc-cpacket-cloud-ddos-2024-merged.parquet")
RESULTS_DIR = Path("/Users/rohinirangari/amit/papers/ddos/scripts")

def load_data():
    """Load BCCC-Cloud-2024."""
    df = pd.read_parquet(DATA_PATH)
    print(f"Loaded {len(df)} records, {len(df.columns)} features")
    print(f"Label distribution:\n{df['label'].value_counts().to_string()}")
    return df

def prepare_features(df):
    """Prepare features for ML analysis."""
    # Binary classification: Benign=0, Attack/Suspicious=1
    y = (df['label'] != 'Benign').astype(int).values

    # Select numeric features only
    feature_cols = [c for c in df.columns if c != 'label' and df[c].dtype.kind in ('i', 'f')]
    X = df[feature_cols].values.astype(np.float32)

    # Handle NaN/Inf
    X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)

    print(f"\nFeatures: {len(feature_cols)}")
    print(f"Attack: {y.sum()}, Benign: {len(y)-y.sum()}")

    return X, y, feature_cols

def tigcdo_phase_mapping(df):
    """Map BCCC attack patterns to TIG-CDO CSDA phases."""
    print("\n" + "=" * 60)
    print("TIG-CDO Phase Mapping: BCCC-Cloud-2024")
    print("=" * 60)

    attacks = df[df['label'] != 'Benign']
    benign = df[df['label'] == 'Benign']

    # Phase 1: Reconnaissance — low-volume probing
    # Indicators: short duration, few packets, diverse dst_ports
    recon_mask = (attacks['duration'] < 1.0) & (attacks['packets_count'] < 10)
    recon = attacks[recon_mask]

    # Phase 2: Baseline Poisoning — traffic mimicking benign but subtly different
    suspicious = df[df['label'] == 'Suspicious']

    # Phase 3: Composite Attack Execution — high-volume, multi-vector
    exec_mask = (attacks['packets_count'] > 100) | (attacks['total_payload_bytes'] > 10000)
    execution = attacks[exec_mask]

    # Phase 4: Sustained Degradation — sustained traffic causing performance drop
    sustained_mask = attacks['duration'] > 10.0
    sustained = attacks[sustained_mask]

    print(f"\nCSDA Phase Mapping:")
    print(f"  Phase 1 (Reconnaissance): {len(recon)} flows ({100*len(recon)/len(attacks):.1f}% of attacks)")
    print(f"  Phase 2 (Baseline Poisoning proxy): {len(suspicious)} suspicious flows")
    print(f"  Phase 3 (Composite Execution): {len(execution)} flows ({100*len(execution)/len(attacks):.1f}% of attacks)")
    print(f"  Phase 4 (Sustained Degradation): {len(sustained)} flows ({100*len(sustained)/len(attacks):.1f}% of attacks)")

    # Feature comparison: attack vs benign
    key_features = ['duration', 'packets_count', 'total_payload_bytes', 'src_port', 'dst_port']
    available = [f for f in key_features if f in df.columns]

    print(f"\n--- Key Feature Comparison (mean) ---")
    print(f"{'Feature':<25} {'Benign':>12} {'Attack':>12} {'Ratio':>8}")
    print("-" * 60)
    for feat in available:
        b_mean = benign[feat].mean()
        a_mean = attacks[feat].mean()
        ratio = a_mean / b_mean if b_mean > 0 else float('inf')
        print(f"{feat:<25} {b_mean:>12.2f} {a_mean:>12.2f} {ratio:>8.2f}x")

    return {
        "total_attacks": int(len(attacks)),
        "phase1_recon": int(len(recon)),
        "phase2_poisoning_proxy": int(len(suspicious)),
        "phase3_execution": int(len(execution)),
        "phase4_sustained": int(len(sustained)),
    }

def run_detection_comparison(X, y):
    """Run LBMD-style detection on BCCC data."""
    print("\n" + "=" * 60)
    print("Detection Performance (LBMD Framework Applied to BCCC)")
    print("=" * 60)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    models = {
        "LogReg": LogisticRegression(max_iter=1000, random_state=42),
        "RF": RandomForestClassifier(n_estimators=50, max_depth=15, random_state=42, n_jobs=-1),
        "XGBoost": GradientBoostingClassifier(n_estimators=50, max_depth=6, random_state=42),
    }

    results = []
    for name, model in models.items():
        print(f"\n--- {name} ---")
        t0 = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - t0

        y_pred = model.predict(X_test)
        f1 = f1_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)

        # Latency
        latencies = []
        for _ in range(200):
            idx = np.random.randint(0, len(X_test))
            t_start = time.perf_counter()
            model.predict(X_test[idx:idx+1])
            latencies.append((time.perf_counter() - t_start) * 1000)
        p99 = np.percentile(latencies, 99)

        print(f"  F1={f1:.4f}, Precision={prec:.4f}, Recall={rec:.4f}")
        print(f"  P99 latency: {p99:.3f}ms")
        print(f"  Train time: {train_time:.1f}s")

        results.append({
            "model": name,
            "dataset": "BCCC-Cloud-2024",
            "f1": round(f1, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "p99_ms": round(p99, 4),
        })

    return results

def main():
    df = load_data()
    phase_mapping = tigcdo_phase_mapping(df)

    X, y, feature_cols = prepare_features(df)
    detection_results = run_detection_comparison(X, y)

    # Print comparative summary
    print("\n" + "=" * 60)
    print("Cross-Dataset Comparison: BCCC vs CICDDoS2019 vs UNSW-NB15")
    print("=" * 60)

    # Reference results from other datasets
    cic = {"LogReg": 0.995, "RF": 0.271, "XGBoost": 0.960}
    unsw = {"LogReg": 0.902, "RF": 0.921, "XGBoost": 0.923}

    print(f"\n{'Model':<10} {'CICDDoS2019':>12} {'UNSW-NB15':>12} {'BCCC-2024':>12}")
    print("-" * 50)
    for r in detection_results:
        name = r['model']
        print(f"{name:<10} {cic.get(name, 'N/A'):>12.3f} {unsw.get(name, 'N/A'):>12.3f} {r['f1']:>12.3f}")

    # Save all results
    output = {
        "phase_mapping": phase_mapping,
        "detection_results": detection_results,
        "cross_dataset_f1": {
            "CICDDoS2019": cic,
            "UNSW-NB15": unsw,
            "BCCC-Cloud-2024": {r['model']: r['f1'] for r in detection_results},
        }
    }

    out_path = RESULTS_DIR / "bccc-tigcdo-results.json"
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")

if __name__ == "__main__":
    main()
