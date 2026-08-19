# TIG-CDO Replication Package

Code, calibration scripts, checked-in results, and figures behind:

> A. J. Rangari, L. N. Mishra, and B. Senapati, "Transaction Intent Graph:
> Semantic Cross-Layer Defense Orchestration for Microservices Payment
> Systems," *IEEE Transactions on Network and Service Management*, 2026.

**DOI:** [10.5281/zenodo.22005891](https://doi.org/10.5281/zenodo.22005891)
**Manuscript DOI:** `[to be filled in once assigned]`

This repository is the archival artifact cited in that paper's Data
Availability Statement. See **[REPRODUCTION.md](REPRODUCTION.md)** for the
exact command that regenerates each table and figure in Section VI.

## What's here

```
ddos-data/
├── bim/bim.py                    Baseline Integrity Monitor (JS-divergence CUSUM)
├── clcs/clcs.py                  Cross-Layer Composite Score engine
├── fdce/{fdce.py,scenario.py}    Federated Declined-Card Exhaustion detector (R-11/R-12) + traffic simulator
├── pado/pado.py                  Pre-Authorized Defense Orchestrator
├── psrg/psrg.py                  Payment-Semantic Rate Governor
├── stc/stc.py                    Semantic Transaction Correlator
│
├── run_tigcdo_eval.py            Main evaluation harness (270-scenario CSDA + 30-scenario FDCE + phase detection)
├── run_followup_analyses.py      Round-3 follow-on analyses (block-rate x latency sweep, heavy-tailed FPR, 50-seed dispersion)
├── generate_paper_figures.py     Regenerates Figures 2-5 (vector PDF) from checked-in results
│
├── calibrate_bim_js_cusum.py             Monte Carlo BIM threshold calibration (no external data needed)
├── calibrate_fdce_from_real_data.py      FDCE/R-11 grounding — uses bundled data/ng-card-auth/
├── calibrate_applayer_from_real_data.py  Arrival-model grounding — uses fetched data/apa-ddos/
├── download_apa_ddos.py                  Retrieval script for APA-DDoS (see "Public datasets" below)
├── calibrate_drift_from_real_data.py     BIM organic-drift grounding — needs external CESNET-TLS-Year22
├── calibrate_edos_from_real_data.py      Anti-EDoS grounding — needs external Mendeley DoW dataset
├── calibrate_scale_from_real_data.py     PSRG per-source-rate check — needs external IoT-23
├── calibrate_tcs_from_real_data.py       TCS separation grounding — needs external Retailrocket
├── calibrate_latency_from_real_data.py   Latency/saturation grounding — needs external RCAEval + Alibaba trace
│
├── *_RESULTS.json, *_CALIBRATION.json,   Checked-in harness/calibration output (the numbers the paper
│   *_REPORT.md, *_MANUSCRIPT_INSERTS.md  cites directly — see REPRODUCTION.md for provenance of each)
│
├── figures/                      Figures 1-5 as shipped in the paper (vector PDF; Fig. 1 is a hand-drawn
│                                  architecture diagram, Figs. 2-5 are generate_paper_figures.py output)
│
├── baselines-cross-dataset/      Companion-survey baselines (TAADA, ACS-GUARD, BIN-WATCH, LBMD) and the
│                                  cross-dataset validation scripts (CICDDoS2019, UNSW-NB15,
│                                  BCCC-cPacket-Cloud-DDoS-2024, CTU-13) used in Section VII.C
│
├── artifacts/tigcdo-simulator.html   Standalone interactive browser demo of the TIG-CDO scoring pipeline
│
├── data/ng-card-auth/             Bundled dataset (Apache-2.0 — see below)
│
├── requirements.txt, Dockerfile   Reproduction environment
└── REPRODUCTION.md                Table/figure -> exact command map
```

## Quick start

```bash
git clone https://github.com/amitrangari/ddos-data.git
cd ddos-data
git lfs pull                      # fetches data/ng-card-auth/*.parquet (185 MB, LFS-tracked)
pip install -r requirements.txt

python3 calibrate_fdce_from_real_data.py   # -> fdce_calibration.json (real R-11 FPR = 0.0230%, Cohen's d = 7.67)
python3 generate_paper_figures.py          # -> figures/fig{2,3,4,5}-*.pdf
python3 run_tigcdo_eval.py                 # -> Tables I/II/FDCE-sub-variant, printed to stdout
```

Or via Docker: `docker build -t tig-cdo-repro . && docker run --rm -it -v "$PWD:/repro" tig-cdo-repro bash`.

Every script is deterministic (seed 42, stated at the top of each file).

## Public datasets used, not bundled

Per the manuscript's Data Availability Statement, the following public
datasets ground specific paper constants (Section VII.D / VI.J) but are
**not redistributed here** — either because their license doesn't clearly
permit it, or because they are large, well-known public benchmarks better
fetched from their canonical source:

| Dataset | Used by | Source |
|---|---|---|
| APA-DDoS | `calibrate_applayer_from_real_data.py` | `download_apa_ddos.py` fetches it (HF mirror, Kaggle fallback) — see "Why one dataset is bundled and the other isn't" below |
| CESNET-TLS-Year22 | `calibrate_drift_from_real_data.py` | Zenodo doi:10.5281/zenodo.10608607 (CC-BY-4.0) |
| Denial-of-Wallet serverless dataset | `calibrate_edos_from_real_data.py` | Mendeley Data doi:10.17632/g8g9vdxyvn.1 (CC-BY-4.0) |
| Retailrocket | `calibrate_tcs_from_real_data.py` | Kaggle `retailrocket/ecommerce-dataset` |
| IoT-23 | `calibrate_scale_from_real_data.py` | Stratosphere Laboratory / Zenodo |
| RCAEval RE2-TT, Alibaba cluster-trace-v2021 | `calibrate_latency_from_real_data.py` | RCAEval benchmark; Alibaba public cluster traces |
| CICDDoS2019, UNSW-NB15, BCCC-cPacket-Cloud-DDoS-2024, CTU-13 | `baselines-cross-dataset/*.py` | Canadian Institute for Cybersecurity; UNSW; BCCC; Stratosphere Lab |

For any of these five `calibrate_*_from_real_data.py` scripts, either set
`DDOS_RAW_DATA_ROOT=/path/to/your/copy` or place the dataset under
`./raw-data/<n>-<name>/...` — the exact expected subpath is printed by the
script and documented in its top-of-file docstring.

## Why one dataset is bundled and the other isn't (`data/ng-card-auth/`)

| Dataset | License | Included as data? |
|---|---|---|
| **Nigerian Banking Card Transactions** (`ng-card-auth`) | **Apache-2.0**, confirmed on the [Hugging Face dataset page](https://huggingface.co/datasets/electricsheepafrica/nigerian-banking-card-transactions) | **Yes** — Apache-2.0 explicitly permits redistribution. Bundled unmodified under `data/ng-card-auth/`, with the required `LICENSE` and `NOTICE.md`. |
| **APA-DDoS** | **Unknown** — not stated on its [Kaggle page](https://www.kaggle.com/datasets/yashwanthkumbam/apaddos-dataset) or its Hugging Face mirror | **No.** An unstated license is not permission to redistribute. `download_apa_ddos.py` fetches it directly from its original public sources at run time instead, so you receive it under whatever terms the host platform/creator actually offer. |

If `download_apa_ddos.py`'s automated routes both fail (no internet, missing
API token, mirror moved), fetch manually:

**Hugging Face (no account needed):**
```bash
pip install datasets
python3 -c "
from datasets import load_dataset
ds = load_dataset('A7K/APA-DDoS', split='train')
ds.to_pandas().to_parquet('data/apa-ddos/apa-ddos.parquet', index=False)
"
```

**Kaggle (needs a free account):** download from
https://www.kaggle.com/datasets/yashwanthkumbam/apaddos-dataset, then
`df = pd.read_csv(...); df.to_parquet('data/apa-ddos/apa-ddos.parquet', index=False)`.

## What the package reproduces, and what it does not

Stated explicitly rather than left for a reader to discover by trial:

- **Reproduced exactly:** the FDCE aggregate SLA and 30-scenario detection
  grid; the Section VII.D calibrations (TCS, secular drift, Vector E
  separability); the Section VI.I FDCE decline calibration (organic p99,
  FPR, Cohen's *d*); the Phase-3 CLCS computation; the Phase-2 JS-CUSUM
  trajectory (Table X, detection Day 14).
- **Reproduced approximately** (Monte Carlo, seed-dependent): Table XI's SLA,
  FPR, and legitimate-TPS values, which vary within the reported seed bands.
- **Consumed as configured input, not computed:** the main 270-scenario
  evaluation's per-configuration attack block rates, base false-positive
  probabilities, and detection latencies (outside FDCE) — `run_tigcdo_eval.py`
  states this in its own module docstring. Treat those numbers as calibrated
  design targets with Monte Carlo sampling noise, not independent
  measurements.
- **Specified but not implemented:** cluster-level (vs. per-merchant) R-12
  blocking; the PSRG stale-cache fail-open policy; the cold-start standby
  instance.

## License

Code (this repository, excluding `data/ng-card-auth/`) is MIT-licensed — see
[LICENSE](LICENSE). The bundled `data/ng-card-auth/` dataset is Apache-2.0,
per its original author — see `data/ng-card-auth/LICENSE` and
`data/ng-card-auth/NOTICE.md`.

## Software versions

Python 3.9.7 (3.9-3.11 expected equivalent), Neo4j 5.x, Kafka 3.4, Envoy
1.27, Kubernetes 1.28, scikit-learn 1.0.2, XGBoost 1.5.0. Full Python
dependency list in `requirements.txt`. Random seed 42 throughout.

## Citing

See [CITATION.cff](CITATION.cff). Cite the manuscript for the method; cite
this repository's DOI for the code/data artifact itself.
