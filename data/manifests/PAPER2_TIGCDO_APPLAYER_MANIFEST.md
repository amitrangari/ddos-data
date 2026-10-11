# TIG-CDO (paper2) — Application-Layer (L7) DDoS Anchor

**Paper:** `research-papers/ddos/paper2-solution/mainv3.md` — *Transaction Intent Graph:
Semantic Cross-Layer Defense Orchestration for Microservices Payment Systems* (IEEE TNSM, rev v9)
**Added:** 2026-07-08 · **Dir:** `research-data/ddos-data/12-app-layer-ddos/`

---

## Why this data was needed (the gap it fills)

Across the v5–v8 reviews the simulator's **only network-traffic calibration anchor** was
**CICDDoS2019** — a *network-layer* (L3/4) inter-arrival-time reference (Cohen's *d* = 0.71 benign vs
attack, `01-benchmark/cic-ddos2019/`). But TIG-CDO's stated threat is the **application-layer (L7)
payment-API flood**: the paper's own introduction cites *83% of API-endpoint attacks target banking*,
HTTP/2 Rapid Reset, and it models a GET-flood vector. That L7 attack class had **no dedicated anchor**
— it was inherited from the network-layer figure. This dataset closes that specific gap.

## Dataset added

### `apa-ddos/` — application-layer ACK / PUSH-ACK flood capture
`A7K/APA-DDoS` on HuggingFace (auto-parquet, public) · original **Kaggle
`yashwanthkumbam/apaddos-dataset`** · 151,200 packets · 23 cols · 3.6 MB
HF: https://hf.co/datasets/A7K/APA-DDoS

Packet-level capture (Wireshark export) with microsecond `frame.time`, full TCP flag set
(`syn/reset/push/ack`), IP flags, `frame.len`, per-flow `Packets/Bytes/Tx/Rx`, and a 3-class `Label`:

| Label | Packets | What it is |
|---|---|---|
| `Benign` | 75,600 | normal application traffic |
| `DDoS-ACK` | 37,800 | ACK-flood (L7 application-layer) |
| `DDoS-PSH-ACK` | 37,800 | PUSH-ACK flood (L7 application-layer) |

**Maps to paper concepts:**
- microsecond `frame.time` → real **application-layer inter-arrival-time (IAT)** distribution to seed
  the Poisson arrival / attack-intensity model (§V.B), an **independent L7 anchor** alongside the
  network-layer CICDDoS2019 IAT reference (§V.A).
- TCP flag signatures (`push`,`ack`,`syn`,`reset`) → per-vector flag profile for the GET-flood / L7
  attack model; complements the resource-saturation view from `11-microservice-latency/microservices-ddos`.
- per-flow packet/byte rates → per-vector **severity ordering** complementing the network-volume
  saturation ratios [79] (Classic ×114.7 / Slow ×62.1 / SYN ×4.75 / GET ×1.32).

**Caveat:** SDN-testbed capture (2020-06-16), **not payment-specific** and **not sub-threshold** — the
attack here is a pure high-rate flood, so it anchors the *easy/volumetric* end of the L7 space, not the
coordinated sub-threshold composite (CSDA) the paper's hard case targets. **License: `unknown`** on the
HF mirror — research use only; confirm terms (and prefer citing the original Kaggle source) before
redistribution.

---

## Calibration run (2026-07-08)
Script `paper2-solution/implementation/calibrate_applayer_from_real_data.py` →
artifact `applayer_calibration.json` (this dir). Seed 42.

Headline results:
- **Application-layer benign IAT median = 12.75 ms vs attack = 0.013 ms** (~1000× compression) →
  real L7 arrival-rate separation to seed the attack-intensity model.
- **Cohen's *d* (log-IAT, benign vs attack) = 11.6** — far larger than the network-layer CICDDoS2019
  *d* = 0.71, i.e. a pure L7 flood is *trivially* separable in IAT space. Honest reading: this bounds
  the **easy end**; TIG-CDO's contribution is the *hard* sub-threshold composite this capture does not
  contain, so the figure corroborates (does not inflate) the arrival model.
- **Per-vector packet-rate severity vs benign:** PSH-ACK ×6.49 (psh_ack=1.0), ACK ×5.09 (psh_ack=0.0)
  → grounds a per-vector L7 ordering complementing the network-volume ratios [79].

## Citation to add
- APA-DDoS (ACK/PUSH-ACK application-layer DDoS) dataset. Kaggle: `yashwanthkumbam/apaddos-dataset`;
  HF mirror `A7K/APA-DDoS`. Capture 2020-06-16. (License unstated — cite as research dataset.)
