#!/usr/bin/env python3
"""
Calibrate the application-layer (Layer-7) DDoS attack vector of the TIG-CDO
simulator against the real APA-DDoS dataset (ACK / PUSH-ACK application-layer
floods, 151.2K packets, microsecond timestamps).

This dataset's license is unconfirmed ("unknown" on both its Kaggle page and its
Hugging Face mirror), so it is NOT bundled in this package. Run
`download_apa_ddos.py` first (see that script's docstring, and README.md's
"If the download script fails" section for a manual fallback) to fetch it into
../data/apa-ddos/apa-ddos.parquet before running this script.

Motivation
----------
The simulator's only *network*-traffic calibration anchor is CICDDoS2019
(network-layer inter-arrival times, Cohen's d = 0.71 benign vs attack). But
TIG-CDO's stated threat is the *application-layer* payment-API flood (the paper
cites 83% of API-endpoint attacks targeting banking, HTTP/2 Rapid Reset, and
models a GET-flood vector). APA-DDoS is an application-layer (ACK / PUSH-ACK)
DDoS capture and provides an independent, L7 anchor for:
  - the benign-vs-attack inter-arrival-time (IAT) separation used to seed the
    Poisson arrival / attack-intensity model (§V.B), and
  - a per-vector packet-rate / flag-signature severity ordering.

Output: ../outputs/applayer_calibration.json + stdout report.
Seed 42 per paper convention.
Requires: pandas, numpy (pip install pandas numpy)
"""
import json
import numpy as np
import pandas as pd
from pathlib import Path

SEED = 42
np.random.seed(SEED)

HERE = Path(__file__).resolve().parent
DATA = HERE.parent / "data" / "apa-ddos" / "apa-ddos.parquet"
OUT = HERE.parent / "outputs" / "applayer_calibration.json"


def parse_seconds(s: pd.Series) -> pd.Series:
    """Extract wall-clock seconds-of-day from 'DD-Mon YYYY HH:MM:SS.frac TZ' strings."""
    # token 3 is HH:MM:SS.frac
    hms = s.str.split().str[2]
    h = pd.to_numeric(hms.str.slice(0, 2), errors="coerce")
    m = pd.to_numeric(hms.str.slice(3, 5), errors="coerce")
    sec = pd.to_numeric(hms.str.slice(6), errors="coerce")
    return h * 3600 + m * 60 + sec


def cohens_d(a: np.ndarray, b: np.ndarray) -> float:
    a, b = np.asarray(a), np.asarray(b)
    na, nb = len(a), len(b)
    sp = np.sqrt(((na - 1) * a.var(ddof=1) + (nb - 1) * b.var(ddof=1)) / (na + nb - 2))
    return float((a.mean() - b.mean()) / sp) if sp > 0 else float("nan")


def iats_per_source(df: pd.DataFrame) -> np.ndarray:
    """Per-source inter-arrival times (ms), pooled across sources."""
    out = []
    for _, g in df.sort_values("t").groupby("ip.src"):
        if len(g) < 2:
            continue
        d = np.diff(g["t"].values) * 1000.0  # -> ms
        d = d[(d >= 0) & (d < 60000)]        # drop day-wrap / idle gaps
        out.append(d)
    return np.concatenate(out) if out else np.array([])


def main():
    if not DATA.exists():
        raise FileNotFoundError(
            f"Dataset not found at {DATA}\n"
            "Run download_apa_ddos.py first to fetch it (this dataset's license is "
            "unconfirmed, so it is not bundled directly in this package). "
            "See README.md's manual-download fallback if the download script fails."
        )
    df = pd.read_parquet(DATA)
    df["t"] = parse_seconds(df["frame.time"])
    df = df.dropna(subset=["t"])
    df["is_attack"] = (df["Label"] != "Benign").astype(int)

    benign = df[df["is_attack"] == 0]
    attack = df[df["is_attack"] == 1]

    b_iat = iats_per_source(benign)
    a_iat = iats_per_source(attack)

    # log-IAT is the seed feature (heavy-tailed); guard against log(0)
    b_log = np.log10(b_iat + 1e-3)
    a_log = np.log10(a_iat + 1e-3)
    d_log = cohens_d(b_log, a_log)

    # per-vector packet-rate severity: mean packets/flow-second per label
    vec = {}
    for lab, g in df.groupby("Label"):
        span = g["t"].max() - g["t"].min()
        pkts = len(g)
        vec[lab] = {
            "packets": int(pkts),
            "pkts_per_sec": round(pkts / span, 1) if span > 0 else None,
            "mean_frame_len_bytes": round(float(g["frame.len"].mean()), 1),
            "psh_ack_frac": round(float(((g["tcp.flags.push"] == 1) & (g["tcp.flags.ack"] == 1)).mean()), 3),
        }
    # severity relative to benign packet rate
    base_rate = vec["Benign"]["pkts_per_sec"]
    for lab in vec:
        r = vec[lab]["pkts_per_sec"]
        vec[lab]["rate_x_over_benign"] = round(r / base_rate, 2) if (r and base_rate) else None

    result = {
        "dataset": "APA-DDoS (orig. Kaggle yashwanthkumbam/apaddos-dataset; HF mirror A7K/APA-DDoS)",
        "capture_date": "2020-06-16",
        "attack_class": "application-layer (ACK / PUSH-ACK) flood",
        "license": "unknown (research use; confirm before redistribution)",
        "seed": SEED,
        "n_packets": int(len(df)),
        "n_benign": int(len(benign)),
        "n_attack": int(len(attack)),
        "iat_ms": {
            "benign_median": round(float(np.median(b_iat)), 4) if len(b_iat) else None,
            "attack_median": round(float(np.median(a_iat)), 4) if len(a_iat) else None,
            "benign_mean": round(float(np.mean(b_iat)), 4) if len(b_iat) else None,
            "attack_mean": round(float(np.mean(a_iat)), 4) if len(a_iat) else None,
            "cohens_d_log_iat": round(d_log, 3),
            "note": "L7 anchor; compare to CICDDoS2019 network-IAT d=0.71 (§V.A)",
        },
        "per_vector_severity": vec,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2))

    print(f"APA-DDoS application-layer calibration (seed {SEED})")
    print(f"  packets: {len(df):,}  benign={len(benign):,}  attack={len(attack):,}")
    print(f"  benign IAT median = {result['iat_ms']['benign_median']} ms | "
          f"attack IAT median = {result['iat_ms']['attack_median']} ms")
    print(f"  Cohen's d (log-IAT, benign vs attack) = {d_log:.3f}  "
          f"(cf. CICDDoS2019 network-IAT d=0.71)")
    print("  per-vector packet-rate severity (x over benign):")
    for lab, v in vec.items():
        print(f"    {lab:14s} {v['pkts_per_sec']:>10} pkt/s  "
              f"x{v['rate_x_over_benign']}  psh_ack={v['psh_ack_frac']}")
    print(f"  -> {OUT}")


if __name__ == "__main__":
    main()
