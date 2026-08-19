#!/usr/bin/env python3
"""
calibrate_scale_from_real_data.py  (Paper 2 TIG-CDO — gap G5, PSRG)

Per-source-rate sanity check for PSRG's distributed-attack claim, on real
IoT-23 botnet flows (Zeek conn.log.labeled). PSRG's premise (§IV.F) is that
volumetric attacks spread load across many sources each at low per-source rate,
defeating per-IP limits. This measures the real per-source flow-rate
distribution of a labelled attack capture to sanity-check that premise.

NOTE (honest scope): IoT-23 is a FALLBACK analog — tens of devices, not the
100K–500K sources of the CSDA scenario. The load-bearing G5 evidence is the
CCS'22 residential-proxy study (9.08M distinct IPs, cited in §IV.F/§VIII.B).
This script only confirms the shape: many sources, low per-source rate, attack
concentrated on few destinations.
"""
import sys
import os
import json
import numpy as np
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
# Pass the path to an IoT-23 conn.log.labeled file as argv[1] (e.g. a local copy
# of CTU-IoT-Malware-Capture-34-1, Stratosphere Lab / Zenodo), or set
# DDOS_RAW_DATA_ROOT and place it at $DDOS_RAW_DATA_ROOT/16-botnet-scale/conn.log.labeled.
DATA_ROOT = os.environ.get("DDOS_RAW_DATA_ROOT", os.path.join(HERE, "raw-data"))
SRC = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DATA_ROOT, "16-botnet-scale", "conn.log.labeled")
OUT = os.path.join(HERE, "scale_calibration.json")

ts, orig, resp, labels = [], [], [], []
with open(SRC, errors="replace") as f:
    for line in f:
        if line.startswith("#") or not line.strip():
            continue
        p = line.rstrip("\n").split("\t")
        if len(p) < 5:
            continue
        try:
            ts.append(float(p[0]))
        except ValueError:
            continue
        orig.append(p[2])       # id.orig_h
        resp.append(p[4])       # id.resp_h
        labels.append(p[-1].strip().lower())  # detailed-label (last col)

ts = np.array(ts)
n = len(ts)
span = float(ts.max() - ts.min()) if n > 1 else 1.0

# attack vs benign split (label contains malicious/ddos/attack markers)
is_attack = np.array([("malicious" in l or "ddos" in l or "attack" in l
                       or "part" in l or "c&c" in l) for l in labels])
atk_idx = np.where(is_attack)[0]
ben_idx = np.where(~is_attack)[0]

def source_stats(idx):
    if len(idx) == 0:
        return None
    srcs = [orig[i] for i in idx]
    dsts = [resp[i] for i in idx]
    c = Counter(srcs)
    counts = np.array(list(c.values()))
    sub_span = float(np.ptp(ts[idx])) if len(idx) > 1 else 1.0
    sub_span = max(sub_span, 1.0)
    # per-source flow rate (flows/sec) using each source's own active span
    dst_c = Counter(dsts)
    dst_counts = np.array(sorted(dst_c.values(), reverse=True))
    top_dst_share = float(dst_counts[0] / dst_counts.sum())
    return {
        "n_flows": int(len(idx)),
        "n_unique_sources": int(len(c)),
        "n_unique_dests": int(len(dst_c)),
        "flows_per_source_mean": round(float(counts.mean()), 1),
        "flows_per_source_p50_p90_max": [int(np.percentile(counts, 50)),
                                         int(np.percentile(counts, 90)),
                                         int(counts.max())],
        "mean_per_source_rate_flows_per_s": round(float(counts.mean() / sub_span), 3),
        "top_destination_flow_share": round(top_dst_share, 3),
        "capture_span_s": round(sub_span, 1),
    }

result = {
    "dataset": "IoT-23 (CTU-IoT-Malware-Capture-34-1, Zeek conn.log.labeled)",
    "purpose": "Gap G5 — per-source-rate sanity check for PSRG distributed-attack premise",
    "scope": "FALLBACK analog; load-bearing G5 evidence is CCS'22 RESIP 9.08M IPs",
    "total_flows": n,
    "capture_span_s": round(span, 1),
    "label_breakdown": dict(Counter(labels).most_common(6)),
    "attack": source_stats(atk_idx),
    "benign": source_stats(ben_idx),
}
with open(OUT, "w") as f:
    json.dump(result, f, indent=2)
print(json.dumps(result, indent=2))
print(f"\nWrote {OUT}")
