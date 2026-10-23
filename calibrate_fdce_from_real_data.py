"""
FDCE decline-mix check against a SYNTHETIC card-authorization dataset.

v1.3.0 (review R3-025): the bundled 3.0M-record dataset is synthetic (see its
dataset card and data/manifests); earlier versions of this script and its reports
called it real. The file name is kept for continuity of citations. Part 4 (an FDCE
SLA re-run with a stale 0.72 block rate and a hard-coded 93.8% reference) was
removed: the FDCE SLA comes from run_tigcdo_eval.py. This script checks the v1.2
R-11 statistic (pooled watched-code share per merchant-category day); the v1.3.0
R-11 statistic is calibrated by calibrate_r11_multilook.py.

Grounds the §VI.I FDCE numbers and the R-11 decline-concentration threshold (0.80)
in an empirical decline-code distribution instead of configured constants.

Data: research-data/ddos-data/10-payment-fraud/ng-card-auth/ (3M card auths,
      electricsheepafrica/nigerian-banking-card-transactions, Apache-2.0).
      Columns used: authorization_result, decline_reason, merchant_category_code,
      timestamp, card_id, 3ds_authenticated.

What this script computes (from the SYNTHETIC dataset unless marked):
  1. Empirical legitimate decline-code mix (replaces the assumed 60/25/15 split).
  2. R-11 false-positive floor: among organic (legitimate) (merchant-cluster, window)
     blocks with >= V declines, the fraction whose FDCE-code share exceeds 0.80.
     This is the false-alarm rate on the synthetic organic mix.
  3. Detection separability: organic FDCE-share distribution vs. an FDCE attack
     (which drives FDCE-share -> ~1.0), with Cohen's d, mirroring the CICDDoS2019
     d=0.71 calibration already in the paper.

Output:
  - calibration JSON  -> research-data/ddos-data/10-payment-fraud/fdce_calibration.json
  - human report      -> printed to stdout (capture into reviews/ if desired)

Run:  python3 calibrate_fdce_from_real_data.py
Seed: 42 (paper convention).
"""
import json, os, random, math
import pyarrow.parquet as pq
import pandas as pd
import numpy as np

random.seed(42); np.random.seed(42)

HERE = os.path.dirname(os.path.abspath(__file__))
# Bundled as 4 row-sliced parquet parts (each < GitHub's 100 MB limit, so the archive holds
# the data rather than a Git LFS pointer); pyarrow reads the directory as one table.
DATA = os.path.join(HERE, "data", "ng-card-auth", "parts")
OUT_JSON = os.path.join(HERE, "fdce_calibration.json")

# decline_reason -> (ISO 8583 DE39 code, is it in the FDCE card-damage set?)
# Paper FDCE set (R-11): {14 no-account, 54 expired, 57 not-permitted, 82 CVV}.
REASON_MAP = {
    "expired_card":       ("54", True),   # expired -> classic FDCE
    "suspected_fraud":    ("57", True),   # transaction not permitted to cardholder
    "invalid_pin":        ("55", False),  # PIN error -> NOT an FDCE card-damage signal
    "insufficient_funds": ("51", False),  # NSF -> ordinary organic decline
}
R11_THRESHOLD = 0.80   # paper's FDCE decline-concentration threshold
VOLUME_GATE   = 20     # min declines in a window for R-11 to be eligible (matches R-03 burst scale)
GATE_SWEEP    = [5, 10, 20, 50]  # report R-11 FP across volume gates
WINDOW        = "D"    # per-merchant-cluster daily window (hourly is too sparse: ~2 declines/win)


def cohens_d(a, b):
    a, b = np.asarray(a, float), np.asarray(b, float)
    na, nb = len(a), len(b)
    sp = math.sqrt(((na-1)*a.var(ddof=1) + (nb-1)*b.var(ddof=1)) / (na+nb-2))
    return (b.mean() - a.mean()) / sp if sp > 0 else float("nan")


def main():
    print("="*72)
    print("FDCE DECLINE-MIX CHECK ON A SYNTHETIC CARD-AUTH DATASET")
    print("="*72)
    df = pq.read_table(DATA, columns=[
        "authorization_result","decline_reason","merchant_category_code",
        "timestamp","card_id","3ds_authenticated"]).to_pandas()
    n = len(df)
    print(f"Loaded {n:,} card authorizations  ({df['timestamp'].min()} -> {df['timestamp'].max()})")

    # ---- 1. base rates ----
    appr = (df["authorization_result"]=="approved").mean()
    decl = (df["authorization_result"]=="declined").mean()
    tds  = bool(df["3ds_authenticated"].mean() > 0)  # presence
    tds_rate = df["3ds_authenticated"].mean()
    dec = df[df["authorization_result"]=="declined"].copy()
    mix = dec["decline_reason"].value_counts(normalize=True).round(4).to_dict()
    dec["iso"] = dec["decline_reason"].map(lambda r: REASON_MAP[r][0])
    dec["fdce"] = dec["decline_reason"].map(lambda r: REASON_MAP[r][1])
    fdce_share_overall = dec["fdce"].mean()
    print(f"\n[1] Base rates: approved={appr:.4f}  declined={decl:.4f}  3DS-auth={tds_rate:.4f}")
    print(f"    Empirical decline mix (replaces assumed 60/25/15): {mix}")
    print(f"    FDCE-code share among all organic declines: {fdce_share_overall:.4f}")

    # ---- 2. R-11 false-positive floor (organic windows, volume-gated) ----
    dec["win"] = pd.to_datetime(dec["timestamp"]).dt.floor(WINDOW)
    grp = dec.groupby(["merchant_category_code","win"])
    wsize = grp.size()
    fdce_share = grp["fdce"].mean()
    print(f"\n[2] R-11 false-positive floor  (window={WINDOW}, sweeping volume gate)")
    print(f"    populated windows: {len(wsize):,}  | declines/window: "
          f"mean={wsize.mean():.1f} p50={wsize.median():.0f} max={wsize.max():.0f}")
    gate_fp = {}
    for g in GATE_SWEEP:
        elig = wsize >= g
        shares = fdce_share[elig]
        fp = float((shares > R11_THRESHOLD).mean()) if len(shares) else float("nan")
        gate_fp[g] = {"eligible_windows": int(elig.sum()),
                      "fp_rate": (round(fp,6) if not math.isnan(fp) else None),
                      "share_mean": (round(float(shares.mean()),4) if len(shares) else None),
                      "share_p99": (round(float(shares.quantile(.99)),4) if len(shares) else None)}
        fpstr = f"{fp:.4%}" if not math.isnan(fp) else "n/a"
        sm = f"{shares.mean():.3f}" if len(shares) else "n/a"
        print(f"      gate>={g:>3} declines: eligible={int(elig.sum()):>6,}  "
              f"organic FDCE-share mean={sm}  R-11 FP@0.80={fpstr}")
    # headline gate = VOLUME_GATE
    elig = wsize >= VOLUME_GATE
    organic_fdce_share = fdce_share[elig]
    r11_fp = float((organic_fdce_share > R11_THRESHOLD).mean()) if len(organic_fdce_share) else 0.0
    print(f"    -> headline (gate>={VOLUME_GATE}): organic FDCE-share centers at "
          f"{organic_fdce_share.mean():.3f}; R-11 FP@0.80 = {r11_fp:.4%}")

    # ---- 3. separability vs. FDCE attack (FDCE-share -> ~1.0) ----
    # Attack windows modeled as Beta(50,1) ~ 0.98 mean (near-total FDCE concentration),
    # matching the paper's "all sequences terminate AUTH_DECLINED" claim. Organic = synthetic dataset.
    nsamp = max(2000, len(organic_fdce_share))
    attack_share = np.random.beta(50, 1, size=nsamp)
    d = cohens_d(organic_fdce_share.values, attack_share)
    sep_at_080 = float((attack_share > R11_THRESHOLD).mean())
    print(f"\n[3] Separability organic(synthetic) vs FDCE(modeled): Cohen's d={d:.2f} "
          f"(cf. CICDDoS2019 d=0.71)")
    print(f"    FDCE windows above {R11_THRESHOLD}: {sep_at_080:.2%}  -> R-11 recall proxy")

    out = {
        "source_dataset": "electricsheepafrica/nigerian-banking-card-transactions",
        "rows": int(n), "seed": 42,
        "base_rates": {"approved": round(appr,4), "declined": round(decl,4),
                       "three_ds_auth_rate": round(float(tds_rate),4)},
        "empirical_decline_mix": mix,
        "decline_reason_to_iso8583": {k:v[0] for k,v in REASON_MAP.items()},
        "fdce_code_set": ["14","54","57","82"],
        "fdce_share_among_organic_declines": round(float(fdce_share_overall),4),
        "r11": {"threshold": R11_THRESHOLD, "window": WINDOW, "headline_volume_gate": VOLUME_GATE,
                "gate_sweep": gate_fp,
                "organic_fdce_share_mean": (round(float(organic_fdce_share.mean()),4) if len(organic_fdce_share) else None),
                "organic_fdce_share_p99": (round(float(organic_fdce_share.quantile(.99)),4) if len(organic_fdce_share) else None),
                "false_positive_rate": round(r11_fp,6)},
        "separability": {"cohens_d_organic_vs_fdce": round(float(d),3),
                         "fdce_recall_proxy_at_0.80": round(sep_at_080,4),
                         "reference_cicddos2019_d": 0.71},
        "data_status": "SYNTHETIC dataset (not real issuer data)",
        "caveats": ["synthetic data", "single 6-digit BIN prefix",
                    "issuer_response_code collapsed to 00/05/01; decline_reason used for FDCE class",
                    "FDCE attack concentration modeled Beta(50,1); organic side is the synthetic dataset"],
    }
    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    with open(OUT_JSON,"w") as f: json.dump(out,f,indent=2)
    print(f"\nWrote calibration -> {OUT_JSON}")
    print("="*72)


if __name__ == "__main__":
    main()
