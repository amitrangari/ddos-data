# data/

| Path | Status | Notes |
|---|---|---|
| `ng-card-auth/parts/part-00{0..3}.parquet` | **Bundled** (Apache-2.0) | Nigerian Banking Card Transactions, 3,000,000 records. Read with `pd.read_parquet("data/ng-card-auth/parts")`. Provenance, license, and the split-file note are in `ng-card-auth/NOTICE.md`. |
| `manifests/PAPER2_TIGCDO_*_MANIFEST.md` | **Bundled** (documentation) | One per external dataset group: what was downloaded, which files and fields each calibration script reads, and which paper constant each grounds. Local paths in them refer to the authors' working copy; with this package, point `DDOS_RAW_DATA_ROOT` at your copy instead. |

## External datasets (not redistributed)

These are fetched from their original source, either because their license does not clearly
permit redistribution or because they are large public benchmarks. Each calibration script's
output JSON is checked in at the repository root, so the cited numbers can be inspected without
fetching anything.

| Dataset | Script | Source | Checked-in output |
|---|---|---|---|
| APA-DDoS | `calibrate_applayer_from_real_data.py` | `download_apa_ddos.py` (Hugging Face `A7K/APA-DDoS`; Kaggle `yashwanthkumbam/apaddos-dataset`) | `applayer_calibration.json` |
| CESNET-TLS-Year22 | `calibrate_drift_from_real_data.py` | doi:10.5281/zenodo.10608607 (CC-BY-4.0) | `drift_calibration.json` |
| Denial-of-Wallet serverless | `calibrate_edos_from_real_data.py` | doi:10.17632/g8g9vdxyvn.1 (CC-BY-4.0) | `edos_calibration.json` |
| Retailrocket | `calibrate_tcs_from_real_data.py` | Kaggle `retailrocket/ecommerce-dataset` | `tcs_calibration.json` |
| IoT-23 | `calibrate_scale_from_real_data.py` | Stratosphere Laboratory | `scale_calibration.json` |
| RCAEval RE2-TT, microservices-ddos, Alibaba cluster-trace-v2021 | `calibrate_latency_from_real_data.py` | `phamquiluan/RCAEval`; `alibaba/clusterdata` | `latency_calibration.json`, `followup_analyses.json` |
| CICDDoS2019, UNSW-NB15, BCCC-cPacket-Cloud-DDoS-2024, CTU-13 | `baselines-cross-dataset/*.py` | CIC (UNB); UNSW; BCCC; Stratosphere Laboratory | `baselines-cross-dataset/*-results.{json,md}` |

Expected local layout: `$DDOS_RAW_DATA_ROOT/<nn>-<name>/...` (default `./raw-data/`, git-ignored);
each script prints the exact path it looked for if the file is missing.
