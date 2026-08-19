#!/usr/bin/env python3
"""
LBMD Cross-Dataset Validation on UNSW-NB15
Adapts the Latency-Bounded ML Detection framework from Paper 1
to UNSW-NB15 dataset for cross-dataset validation.

Produces a DER comparison table matching the CICDDoS2019 results.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
import time
import json
from pathlib import Path

DATA_DIR = Path("/Volumes/1TB-SSD/ddos-data/01-benchmark/unsw-nb15")
RESULTS_DIR = Path("/Users/rohinirangari/amit/papers/ddos/scripts")

# LBMD latency budgets (from Paper 1)
LATENCY_BUDGETS_MS = [1, 2, 5, 10, 50]

def load_unsw_nb15():
    """Load UNSW-NB15 training and testing sets."""
    train_path = DATA_DIR / "UNSW_NB15_training-set.csv"
    test_path = DATA_DIR / "UNSW_NB15_testing-set.csv"

    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    print(f"Training set: {len(train_df)} records")
    print(f"Testing set: {len(test_df)} records")
    print(f"Attack categories: {train_df['attack_cat'].nunique()}")
    print(f"Attack distribution (train):")
    print(train_df['attack_cat'].value_counts().to_string())

    return train_df, test_df

def prepare_features(train_df, test_df):
    """Prepare features for LBMD models."""
    # Drop non-feature columns
    drop_cols = ['id', 'attack_cat', 'label']
    feature_cols = [c for c in train_df.columns if c not in drop_cols]

    # Encode categorical features
    for col in feature_cols:
        if train_df[col].dtype == 'object':
            le = LabelEncoder()
            combined = pd.concat([train_df[col], test_df[col]], axis=0).astype(str)
            le.fit(combined)
            train_df[col] = le.transform(train_df[col].astype(str))
            test_df[col] = le.transform(test_df[col].astype(str))

    X_train = train_df[feature_cols].values.astype(np.float32)
    X_test = test_df[feature_cols].values.astype(np.float32)
    y_train = train_df['label'].values
    y_test = test_df['label'].values

    # Handle NaN/Inf
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=1e6, neginf=-1e6)
    X_test = np.nan_to_num(X_test, nan=0.0, posinf=1e6, neginf=-1e6)

    # Scale
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    print(f"\nFeatures: {X_train.shape[1]}")
    print(f"Train: {len(X_train)} ({y_train.sum()} attacks, {len(y_train)-y_train.sum()} benign)")
    print(f"Test: {len(X_test)} ({y_test.sum()} attacks, {len(y_test)-y_test.sum()} benign)")

    return X_train, X_test, y_train, y_test, feature_cols

def measure_latency(model, X_sample, n_trials=100):
    """Measure per-sample prediction latency (P50, P95, P99) in ms."""
    latencies = []
    for _ in range(n_trials):
        idx = np.random.randint(0, len(X_sample))
        sample = X_sample[idx:idx+1]
        start = time.perf_counter()
        model.predict(sample)
        elapsed = (time.perf_counter() - start) * 1000  # ms
        latencies.append(elapsed)
    arr = np.array(latencies)
    return {
        "p50_ms": float(np.percentile(arr, 50)),
        "p95_ms": float(np.percentile(arr, 95)),
        "p99_ms": float(np.percentile(arr, 99)),
        "mean_ms": float(arr.mean()),
    }

def compute_der(p99_ms, budget_ms):
    """Detection Effectiveness Ratio: 1 if within budget, degraded otherwise."""
    if p99_ms <= budget_ms:
        return 1.0
    else:
        return max(0.0, 1.0 - (p99_ms - budget_ms) / budget_ms)

def run_lbmd_evaluation():
    """Run full LBMD evaluation on UNSW-NB15."""
    print("=" * 60)
    print("LBMD Cross-Dataset Validation: UNSW-NB15")
    print("=" * 60)

    train_df, test_df = load_unsw_nb15()
    X_train, X_test, y_train, y_test, feature_cols = prepare_features(train_df, test_df)

    # LBMD model suite (matching Paper 1)
    models = {
        "LogReg": LogisticRegression(max_iter=1000, random_state=42, C=1.0),
        "RF": RandomForestClassifier(n_estimators=100, max_depth=15, random_state=42, n_jobs=1),
        "XGBoost": GradientBoostingClassifier(n_estimators=100, max_depth=6, random_state=42),
    }

    results = []

    for name, model in models.items():
        print(f"\n--- {name} ---")

        # Train
        t0 = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - t0
        print(f"  Training time: {train_time:.1f}s")

        # Predict
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else y_pred

        # Metrics
        f1 = f1_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_prob)

        print(f"  F1={f1:.4f}, Precision={precision:.4f}, Recall={recall:.4f}, AUC={auc:.4f}")

        # Latency measurement
        latency = measure_latency(model, X_test, n_trials=500)
        print(f"  Latency: P50={latency['p50_ms']:.3f}ms, P95={latency['p95_ms']:.3f}ms, P99={latency['p99_ms']:.3f}ms")

        # DER at each latency budget
        der_results = {}
        for budget in LATENCY_BUDGETS_MS:
            der = compute_der(latency['p99_ms'], budget)
            der_results[f"DER@{budget}ms"] = der

        print(f"  DER: " + ", ".join(f"@{b}ms={der_results[f'DER@{b}ms']:.3f}" for b in LATENCY_BUDGETS_MS))

        results.append({
            "model": name,
            "dataset": "UNSW-NB15",
            "f1": round(f1, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "auc": round(auc, 4),
            "p50_ms": round(latency['p50_ms'], 4),
            "p95_ms": round(latency['p95_ms'], 4),
            "p99_ms": round(latency['p99_ms'], 4),
            **{k: round(v, 4) for k, v in der_results.items()},
        })

    # Print comparison table
    print("\n" + "=" * 60)
    print("LBMD Cross-Dataset Comparison: CICDDoS2019 vs UNSW-NB15")
    print("=" * 60)

    # CICDDoS2019 results from Paper 1 (iteration 8)
    cic_results = {
        "XGBoost": {"f1": 0.960, "p99_ms": 0.170, "DER@5ms": 0.960},
        "LogReg": {"f1": 0.995, "p99_ms": 0.026, "DER@5ms": 0.995},
        "RF": {"f1": 0.271, "p99_ms": 3.643, "DER@5ms": 0.271},
    }

    print(f"\n{'Model':<10} {'Dataset':<15} {'F1':>6} {'P99(ms)':>9} {'DER@5ms':>8}")
    print("-" * 52)
    for r in results:
        name = r['model']
        print(f"{name:<10} {'UNSW-NB15':<15} {r['f1']:>6.3f} {r['p99_ms']:>9.3f} {r['DER@5ms']:>8.3f}")
        if name in cic_results:
            c = cic_results[name]
            print(f"{name:<10} {'CICDDoS2019':<15} {c['f1']:>6.3f} {c['p99_ms']:>9.3f} {c['DER@5ms']:>8.3f}")
        print()

    # Save results
    output = {
        "unsw_nb15_results": results,
        "cicdddos2019_reference": cic_results,
        "latency_budgets_ms": LATENCY_BUDGETS_MS,
        "dataset_info": {
            "name": "UNSW-NB15",
            "train_size": int(len(X_train)),
            "test_size": int(len(X_test)),
            "features": int(X_train.shape[1]),
        }
    }

    output_path = RESULTS_DIR / "lbmd-unsw-nb15-results.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {output_path}")

    return results

if __name__ == "__main__":
    run_lbmd_evaluation()
