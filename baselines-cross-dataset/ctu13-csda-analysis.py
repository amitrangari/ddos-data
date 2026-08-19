#!/usr/bin/env python3
"""
CTU-13 Botnet Pattern Analysis for CSDA Reconnaissance Validation
Maps C2 communication and DDoS patterns to TIG-CDO CSDA phases.

Focuses on Scenario 4 (rbot-dos) and Scenario 9 (Neris DDoS).
"""

import pandas as pd
import numpy as np
import json
from pathlib import Path
from collections import Counter

DATA_DIR = Path("/Volumes/1TB-SSD/ddos-data/01-benchmark/ctu-13/CTU-13-Dataset")
RESULTS_DIR = Path("/Users/rohinirangari/amit/papers/ddos/scripts")

def load_binetflow(scenario_num):
    """Load a CTU-13 binetflow file."""
    scenario_dir = DATA_DIR / str(scenario_num)
    binetflow_files = list(scenario_dir.glob("*.binetflow"))
    if not binetflow_files:
        print(f"  No binetflow file found for scenario {scenario_num}")
        return None

    path = binetflow_files[0]
    print(f"  Loading {path.name}...")

    # CTU-13 binetflow is tab-separated with a header
    try:
        df = pd.read_csv(path, sep=',', low_memory=False)
        df.columns = [c.strip() for c in df.columns]
    except Exception as e:
        print(f"  Error loading: {e}")
        return None

    print(f"  Records: {len(df)}")
    print(f"  Columns: {list(df.columns)}")
    return df

def analyze_csda_patterns(df, scenario_name):
    """Map CTU-13 botnet flows to CSDA phases."""
    print(f"\n--- CSDA Phase Mapping: {scenario_name} ---")

    # Check for label column
    label_col = None
    for c in df.columns:
        if 'label' in c.lower():
            label_col = c
            break

    if label_col:
        labels = df[label_col].value_counts()
        print(f"\nLabel distribution ({label_col}):")
        for label, count in labels.head(10).items():
            print(f"  {str(label)[:60]}: {count}")

        # Classify by label patterns
        botnet_mask = df[label_col].str.contains('Botnet', case=False, na=False)
        normal_mask = df[label_col].str.contains('Normal', case=False, na=False)
        background_mask = df[label_col].str.contains('Background', case=False, na=False)

        botnet_flows = df[botnet_mask]
        normal_flows = df[normal_mask]

        print(f"\nBotnet flows: {len(botnet_flows)} ({100*len(botnet_flows)/len(df):.1f}%)")
        print(f"Normal flows: {len(normal_flows)} ({100*len(normal_flows)/len(df):.1f}%)")
    else:
        botnet_flows = df
        normal_flows = pd.DataFrame()
        print("No label column found; analyzing all flows")

    # Analyze botnet C2 patterns (CSDA Phase 1 analogue)
    if len(botnet_flows) > 0 and 'DstAddr' in botnet_flows.columns:
        # C2 communication: few unique destinations contacted repeatedly
        dst_counts = botnet_flows['DstAddr'].value_counts()
        print(f"\nC2 Pattern Analysis (top destinations):")
        for dst, count in dst_counts.head(5).items():
            print(f"  {dst}: {count} flows")

        # Port distribution (C2 often uses specific ports)
        if 'Dport' in botnet_flows.columns:
            port_counts = botnet_flows['Dport'].value_counts()
            print(f"\nPort distribution (top 10):")
            for port, count in port_counts.head(10).items():
                print(f"  Port {port}: {count} flows")

    # Temporal analysis (Phase 1→2→3 transition)
    if 'StartTime' in df.columns:
        try:
            df['StartTime'] = pd.to_datetime(df['StartTime'], errors='coerce')
            if df['StartTime'].notna().sum() > 0:
                time_range = df['StartTime'].max() - df['StartTime'].min()
                print(f"\nCapture duration: {time_range}")

                if label_col and len(botnet_flows) > 0:
                    botnet_times = pd.to_datetime(botnet_flows['StartTime'], errors='coerce')
                    first_botnet = botnet_times.min()
                    last_botnet = botnet_times.max()
                    print(f"Botnet activity window: {first_botnet} to {last_botnet}")
        except Exception as e:
            print(f"  Time parsing error: {e}")

    # Protocol distribution
    if 'Proto' in df.columns:
        print(f"\nProtocol distribution (botnet flows):")
        if len(botnet_flows) > 0:
            proto_counts = botnet_flows['Proto'].value_counts()
            for proto, count in proto_counts.head(5).items():
                print(f"  {proto}: {count} ({100*count/len(botnet_flows):.1f}%)")

    # Flow duration analysis (short flows = probing/scanning = CSDA Phase 1)
    if 'Dur' in df.columns and len(botnet_flows) > 0:
        try:
            durs = pd.to_numeric(botnet_flows['Dur'], errors='coerce').dropna()
            if len(durs) > 0:
                short_flows = (durs < 1.0).sum()
                medium_flows = ((durs >= 1.0) & (durs < 30.0)).sum()
                long_flows = (durs >= 30.0).sum()
                print(f"\nFlow duration analysis (botnet):")
                print(f"  Short (<1s, recon/scanning): {short_flows} ({100*short_flows/len(durs):.1f}%)")
                print(f"  Medium (1-30s, C2/attack): {medium_flows} ({100*medium_flows/len(durs):.1f}%)")
                print(f"  Long (>30s, sustained): {long_flows} ({100*long_flows/len(durs):.1f}%)")
        except Exception:
            pass

    return {
        "scenario": scenario_name,
        "total_flows": int(len(df)),
        "botnet_flows": int(len(botnet_flows)),
        "normal_flows": int(len(normal_flows)),
    }

def main():
    print("=" * 60)
    print("CTU-13 Botnet Pattern Analysis for CSDA Validation")
    print("=" * 60)

    results = []

    # DDoS-specific scenarios
    for scenario in [4, 1, 9, 10, 11]:
        print(f"\n{'='*40}")
        print(f"Scenario {scenario}")
        print(f"{'='*40}")

        df = load_binetflow(scenario)
        if df is not None:
            r = analyze_csda_patterns(df, f"CTU-13 Scenario {scenario}")
            results.append(r)

    # Summary
    print("\n" + "=" * 60)
    print("Summary: CTU-13 → CSDA Phase Mapping")
    print("=" * 60)
    print(f"\n{'Scenario':<25} {'Total':>10} {'Botnet':>10} {'%':>6}")
    print("-" * 55)
    for r in results:
        pct = 100 * r['botnet_flows'] / r['total_flows'] if r['total_flows'] > 0 else 0
        print(f"{r['scenario']:<25} {r['total_flows']:>10,} {r['botnet_flows']:>10,} {pct:>5.1f}%")

    # Save
    out_path = RESULTS_DIR / "ctu13-csda-results.json"
    with open(out_path, "w") as f:
        json.dump({"scenarios": results}, f, indent=2)
    print(f"\nResults saved to {out_path}")

if __name__ == "__main__":
    main()
