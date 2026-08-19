# TIG-CDO (Paper 2) — Payment-Data Calibration Replication Package

This directory is a **self-contained, upload-ready** package for the two real-data
calibrations behind `paper2-solution/main_v2.md`'s FDCE / R-11 analysis (§VI.I) and
application-layer arrival-model anchor (§VI.A). It exists as its own directory —
separate from the working `research-data/ddos/10-payment-fraud/` and
`12-app-layer-ddos/` trees — specifically so it can be zipped and uploaded (Zenodo,
GitHub release, etc.) without dragging in anything license-encumbered.

```
paper2-replication-package/
├── README.md                          ← this file
├── data/
│   └── ng-card-auth/
│       ├── nigerian-banking-card-transactions.parquet   (bundled — Apache-2.0)
│       ├── LICENSE                    (Apache License 2.0, full text)
│       └── NOTICE.md                  (attribution, per Apache-2.0 §4)
├── scripts/
│   ├── calibrate_fdce_from_real_data.py       (uses the bundled card-auth data)
│   ├── download_apa_ddos.py                   (fetches APA-DDoS — see below)
│   └── calibrate_applayer_from_real_data.py   (uses the downloaded APA-DDoS data)
└── outputs/
    ├── fdce_calibration.json          (already generated — re-run to reproduce)
    └── applayer_calibration.json      (already generated — re-run to reproduce)
```

## Why one dataset is bundled and the other is not

| Dataset | License | Included as data? |
|---|---|---|
| **Nigerian Banking Card Transactions** (`ng-card-auth`) | **Apache-2.0**, confirmed on the [Hugging Face dataset page](https://huggingface.co/datasets/electricsheepafrica/nigerian-banking-card-transactions) | **Yes** — Apache-2.0 explicitly permits redistribution. The file is bundled under `data/ng-card-auth/`, unmodified, with the required `LICENSE` and `NOTICE.md`. |
| **APA-DDoS** (`apa-ddos`) | **Unknown** — not stated on its [Kaggle page](https://www.kaggle.com/datasets/yashwanthkumbam/apaddos-dataset) or its Hugging Face mirror | **No.** An unstated license is not the same as permission to redistribute. Instead, `scripts/download_apa_ddos.py` fetches it directly from its original public sources at run time, so you receive it under whatever terms the host platform/creator actually offer — not a copy redistributed by us. |

This mirrors the caution already documented in `paper2-solution/main_v2.md`'s Data
Availability Statement: don't ship data you haven't confirmed you're allowed to
redistribute; ship derived statistics and a retrieval script instead.

## How to reproduce

```bash
pip install pandas numpy pyarrow datasets   # `kaggle` too, if you want the Kaggle fallback route

cd scripts/
python3 calibrate_fdce_from_real_data.py       # uses the bundled data/ng-card-auth/ file directly

python3 download_apa_ddos.py                   # fetches data/apa-ddos/apa-ddos.parquet
python3 calibrate_applayer_from_real_data.py   # then calibrates against it
```

Both calibration scripts write their output to `outputs/*.json` and print a
human-readable report to stdout. Random seed is 42 throughout, matching the paper's
convention; both scripts are deterministic given the same input data.

**Numbers you should get** (already verified by re-running these exact scripts
against these exact files): R-11 false-positive rate at the 0.80 threshold =
**0.0230%**, organic-vs-FDCE Cohen's *d* = **7.67** (`fdce_calibration.json`);
benign IAT median = **12.746 ms**, attack IAT median = **0.013 ms**, Cohen's *d*
(log-IAT) = **11.597** (`applayer_calibration.json`). These are the values cited in
`main_v2.md` §VI.I and §VI.A.

## If the download script fails

`download_apa_ddos.py` tries the Hugging Face mirror first (no account needed),
then falls back to the Kaggle API (needs a Kaggle account and API token). If
**both** fail — no internet access, a package version mismatch, the mirror having
moved, etc. — download it manually:

**Option A — Hugging Face (no account needed):**
1. Visit https://huggingface.co/datasets/A7K/APA-DDoS
2. Click "Files and versions" and download the parquet file directly, **or** run:
   ```bash
   pip install datasets
   python3 -c "
   from datasets import load_dataset
   ds = load_dataset('A7K/APA-DDoS', split='train')
   ds.to_pandas().to_parquet('data/apa-ddos/apa-ddos.parquet', index=False)
   "
   ```

**Option B — Kaggle (original source, needs a free Kaggle account):**
1. Go to https://www.kaggle.com/datasets/yashwanthkumbam/apaddos-dataset
2. Click "Download" (top right) — this requires being signed in to Kaggle.
3. Unzip the download; it contains a CSV. Convert it to parquet at the expected
   path:
   ```bash
   python3 -c "
   import pandas as pd
   df = pd.read_csv('APA-DDoS-Dataset.csv')   # adjust filename if different
   df.to_parquet('data/apa-ddos/apa-ddos.parquet', index=False)
   "
   ```

Either way, once `data/apa-ddos/apa-ddos.parquet` exists, run
`calibrate_applayer_from_real_data.py` as normal — it doesn't care how the file
got there.

## Provenance

- **`ng-card-auth` data added:** 2026-06-17. **`fdce_calibration.json` first
  generated:** 2026-06-18.
- **`apa-ddos` calibration added:** 2026-07-08.
- **This package assembled:** 2026-08-18, in response to the paper's own Data
  Availability Statement flagging both datasets' provenance/license as
  pre-submission action items. See `paper2-solution/CHANGELOG.md` for the dated
  entry.
- Full working copies of both datasets (and four other payment/microservice
  datasets not used in these two specific calibrations) remain at
  `research-data/ddos/10-payment-fraud/` and `research-data/ddos/12-app-layer-ddos/`
  for internal use; this package is the trimmed, redistribution-safe subset of
  that work.
