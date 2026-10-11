# TIG-CDO (paper2) — Distributed-Source / Botnet-Scale Anchor (PSRG)

**Paper:** `research-papers/ddos/paper2-solution/mainv4.md` / `ddos/paper2-solution/main.md`
**Added:** 2026-07-28 · **Dir:** `research-data/ddos-data/16-botnet-scale/`
**Gap addressed:** **G5** (from `DATA_GROUNDING_REVIEW.md`) — the PSRG **500K-IP collective-throttling** scenario was illustrative, with no real large-source-count distribution behind it.

## Why this data was needed
PSRG replaces per-IP limits with transaction-context limits to defeat distributed attacks (500,000+ IPs, 1–2 req/min each). The paper had no real distributed-source dataset to characterize the many-source, low-per-source volume distribution.

## Dataset added
### `iot-23/iot_23_datasets_small.tar.gz` — Aposemat IoT-23 (labeled flows, lighter version)
Stratosphere Lab, CTU Prague · research use · **8.8 GB** (conn.log.labeled only, no pcaps) · **23 captures** (20 malware `CTU-IoT-Malware-Capture-*` + 3 honeypot/benign `CTU-Honeypot-Capture-*`).
Zeek `conn.log.labeled` with Benign / DDoS / C&C / PartOfAHorizontalPortScan / Okiru / Mirai labels.
Source: https://www.stratosphereips.org/datasets-iot23 · Zenodo 10.5281/zenodo.4743746

**Maps to paper concepts:** DDoS-labeled multi-source flows give a **volumetric distributed-attack analog** — per-source rate and source-count distributions to sanity-check PSRG's collective-throttling behavior.

**Caveat (honest framing):** IoT-23 is **under-sized for the 500K-source claim** (tens of devices, not 100K–500K sources) and is IoT-botnet, not payment traffic. It is a *fallback analog*, not a direct anchor.

## Calibration run (2026-07-30)
Script `ddos/paper2-solution/implementation/calibrate_scale_from_real_data.py` → `scale_calibration.json`. On CTU-IoT-Malware-Capture-34-1 (23,145 flows: 14,394 DDoS + 6,706 C&C + 1,923 benign):

| Signal | Attack flows | What it shows |
|---|---|---|
| Per-source flow rate | **0.247 flows/s** (~15/min) | Low per-source rate — consistent with the sub-threshold "1–2 req/min/IP" premise |
| Top-destination share | **67.2%** | Attack is destination-concentrated (analog of CSDA targeting few BIN ranges/services) |
| Unique attack sources | **1** per capture | **IoT-23 is single-source per capture** — confirms the shape caveat: it CANNOT demonstrate the many-source distribution |

**Honest reading:** the per-source-rate and destination-concentration *shapes* transfer (low rate, few targets), but IoT-23 has one malicious source per capture, so it structurally cannot ground the 500K-source count. This *confirms* the review's caveat and pushes the scale claim entirely onto the RESIP citation below.

## The real G5 evidence is a study, not a dataset
Per the review, the load-bearing G5 citation is the **CCS'22 residential-proxy (RESIP) study** (dl.acm.org/doi/10.1145/3548606.3559377), which documents **9.08M distinct RESIP IPs** — 18–90× the 100–500K target — proving a real distributed source pool of that scale exists. **Recommended paper move:** cite the CCS'22 RESIP study to justify the 500K-IP scenario's realism, and use IoT-23 only as a per-source-rate distributional sanity check. No public dataset packages 100K–500K distinct sources as per-context flows.

## Citation
- Parmisano, A., Garcia, S., Erquiaga, M.J. *Aposemat IoT-23: A labeled dataset with malicious and benign IoT network traffic.* Stratosphere Lab, 2020. Zenodo 10.5281/zenodo.4743746.
- (G5 primary) Yang et al. *Residential proxies* study, ACM CCS 2022, doi:10.1145/3548606.3559377.
