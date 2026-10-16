# TIG-CDO Replication Package

Code, calibration scripts, checked-in results, and figures behind:

> A. J. Rangari, L. N. Mishra, and B. Senapati, "Transaction Intent Graph:
> Semantic Cross-Layer Defense Orchestration for Microservices Payment
> Systems," manuscript under review, 2026.

**DOI (concept — always resolves to the latest version):** [10.5281/zenodo.22005891](https://doi.org/10.5281/zenodo.22005891)
**Manuscript DOI:** `[to be filled in once assigned]`

> **v1.2.0 note.** Corrects the evaluation harness's false-positive-rate
> denominator, describes the CSDA comparison as the 4 conditions it actually
> computes (39 replicate runs per configuration, not "270 scenarios"), adds
> writers for the Figure 2 trajectory and the FDCE grid, and relabels the
> PSRG and PADO latencies as design or configured values. Seed-42 SLA values
> are unchanged. See [CHANGELOG.md](CHANGELOG.md).
>
> **v1.1.0 note.** v1.0.0 (10.5281/zenodo.22005892) archived the bundled
> card-authorization dataset as a Git LFS pointer, so the Zenodo copy did not
> contain the data. From v1.1.0 the dataset is stored as four ordinary parquet
> parts under `data/ng-card-auth/parts/`. v1.1.0 also adds the Kubernetes
> testbed, the CSDA scenario definitions, the remaining calibration outputs,
> and the per-dataset manifests. See `CHANGELOG` below.

This repository is the archival artifact cited in that paper's Data
Availability Statement. See **[REPRODUCTION.md](REPRODUCTION.md)** for the
exact command that regenerates each table and figure (JCP numbering).

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
├── run_tigcdo_eval.py            Main evaluation harness (CSDA comparison: 4 conditions x 39 runs; 30-scenario FDCE; phase detection)
│                                  -> tigcdo_eval_results.json
├── run_followup_analyses.py      Follow-on analyses (block-rate x latency sweep, heavy-tailed FPR, 50-seed dispersion)
├── trace_bim_phase2.py           Phase-2 BIM JS/C+ trace -> BIM_PHASE2_TRACE.json (Table 8, Figure 2)
├── write_fdce_results.py         Writes FDCE_RULE_ENGINE_RESULTS.json (30-scenario and adversarial grids)
├── generate_paper_figures.py     Regenerates Figures 2-4 (vector PDF) from the result files
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
├── *_RESULTS.json, *_calibration.json,   Checked-in harness/calibration output (the numbers the paper
│   *_REPORT.md, *_MANUSCRIPT_INSERTS.md  cites directly — see REPRODUCTION.md for provenance of each)
│
├── figures/                      Figures 1-4 as shipped in the paper (vector PDF; Fig. 1 is a hand-drawn
│                                  architecture diagram, Figs. 2-4 are generate_paper_figures.py output)
│
├── baselines-cross-dataset/      Companion-survey baselines (TAADA, ACS-GUARD, BIN-WATCH, LBMD) and the
│                                  cross-dataset validation scripts (CICDDoS2019, UNSW-NB15,
│                                  BCCC-cPacket-Cloud-DDoS-2024, CTU-13) used in Section VII.C
│
├── k8s-testbed/                  Kubernetes payment-microservices testbed: k8s/ manifests, docker/ service
│                                  sources (gateway, auth, ACS, BIN lookup, rate limiter, metrics, load +
│                                  attack generators), docker-compose single-host variant
├── scenarios/                    CSDA kill-chain scenario definitions (YAML) + payment-protocol state machine
│
├── artifacts/tigcdo-simulator.html   Standalone interactive browser demo of the TIG-CDO scoring pipeline
│
├── data/ng-card-auth/parts/       Bundled dataset, 4 parquet parts (Apache-2.0 — see below)
├── data/manifests/                Per-external-dataset manifests: which file/fields each calibration
│                                  script reads and which paper constant it grounds
│
├── requirements.txt, Dockerfile   Reproduction environment
└── REPRODUCTION.md                Table/figure -> exact command map
```

## Quick start

```bash
git clone https://github.com/amitrangari/ddos-data.git
cd ddos-data
pip install -r requirements.txt

python3 calibrate_fdce_from_real_data.py   # -> fdce_calibration.json (R-11 FPR 0.0230% on the bundled synthetic card dataset)
python3 run_tigcdo_eval.py                 # -> tigcdo_eval_results.json (+ stdout)
python3 trace_bim_phase2.py                # -> BIM_PHASE2_TRACE.json
python3 write_fdce_results.py              # -> FDCE_RULE_ENGINE_RESULTS.json
python3 generate_paper_figures.py          # -> figures/fig{2,3,4}-*.pdf
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
| **Nigerian Banking Card Transactions** (`ng-card-auth`) | **Apache-2.0**, confirmed on the [Hugging Face dataset page](https://huggingface.co/datasets/electricsheepafrica/nigerian-banking-card-transactions) | **Yes** — Apache-2.0 explicitly permits redistribution. Bundled under `data/ng-card-auth/parts/` (records unmodified; file split into 4 parts to stay under GitHub's 100 MB limit — see `NOTICE.md`), with the required `LICENSE` and `NOTICE.md`. |
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
  trajectory (Table 8, detection Day 14); the seed-42 CSDA comparison
  (Table 9, `tigcdo_eval_results.json`) and its 50-seed bands.
- **Seed-dependent** (Monte Carlo): other seeds give Table 9 values within
  the reported 50-seed bands.
- **Consumed as configured input, not computed:** the CSDA comparison's
  per-configuration attack block rates, base false-positive
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

## Changelog

Full history in [CHANGELOG.md](CHANGELOG.md).

- **v1.2.0** (2026-10): FPR denominator corrected; CSDA grid described as 4
  conditions x 39 replicate runs; Figure 2 and the FDCE grid generated by
  committed writers; PSRG/PADO latencies relabeled; pyarrow pinned below 16.
- **v1.1.0** (2026-10) — Card-authorization dataset moved off Git LFS into four
  ordinary parquet parts, so the Zenodo archive holds the data (v1.0.0 held
  only an LFS pointer); `calibrate_fdce_from_real_data.py` reads the parts and
  produces a byte-identical `fdce_calibration.json`. Added `k8s-testbed/`,
  `scenarios/`, `data/manifests/`, the four remaining calibration outputs
  (`tcs_`, `drift_`, `edos_`, `scale_calibration.json`),
  `baselines-cross-dataset/requirements.txt` and
  `acs-guard-sensitivity-results.csv`, `.zenodo.json`, and `SHA256SUMS`.
- **v1.0.0** (2026-08-19) — Initial archived release (10.5281/zenodo.22005892).
