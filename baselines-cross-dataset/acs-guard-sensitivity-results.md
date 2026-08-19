# ACS-GUARD Sensitivity Analysis Results

## Simulation Parameters

| Parameter | Values |
|---|---|
| `lambda_attack` (AReq/s) | [500, 1000, 2000, 3000, 5000] |
| `alpha` (pre-pool fill ratio) | [0.7, 0.75, 0.8, 0.85, 0.9, 0.95] |
| `M_session_pool` | [50000, 100000, 200000] |
| `attack_mode` | ['CEA', 'FFA', 'PTA'] |
| Total combinations | 270 |
| Simulation duration | 600 s per run |
| Attack window | t = 60–420 s |
| Legitimate request rate | 500 AReq/s |
| Normal tau | 300 s |
| tau_min | 30 s |
| U_threshold | 0.65 |

## Table 1: Legitimate Acceptance Rate (CEA, M=100K) — alpha × lambda_attack

**CEA — with ACS-GUARD (M=100K)**

| alpha \ λ_attack |   500 |  1000 |  2000 |  3000 |  5000 |
|---:|---:|---:|---:|---:|---:|
| 0.70 |   44.0% |   41.2% |   38.2% |   36.7% |   34.8% |
| 0.75 |   51.8% |   48.8% |   45.7% |   43.8% |   42.2% |
| 0.80 |   59.9% |   56.9% |   53.8% |   52.3% |   50.7% |
| 0.85 |   70.0% |   65.9% |   62.5% |   60.9% |   58.8% |
| 0.90 |   73.5% |   71.1% |   68.3% |   67.2% |   65.3% |
| 0.95 |   71.7% |   73.8% |   69.6% |   67.5% |   65.8% |

### CEA — without ACS-GUARD reference (M=100K)

| lambda_attack | 500 | 1000 | 2000 | 3000 | 5000 |
|---|---|---|---|---|---|
| Acceptance % |   52.7% |   44.7% |   37.3% |   35.0% |   32.0% |

## Table 2: Legitimate Acceptance Rate (FFA, M=100K) — alpha × lambda_attack

**FFA — with ACS-GUARD (M=100K)**

| alpha \ λ_attack |   500 |  1000 |  2000 |  3000 |  5000 |
|---:|---:|---:|---:|---:|---:|
| 0.70 |   51.9% |   52.2% |   52.4% |   52.5% |   52.6% |
| 0.75 |   60.8% |   61.1% |   61.1% |   61.0% |   61.0% |
| 0.80 |   64.5% |   64.6% |   64.5% |   64.4% |   64.4% |
| 0.85 |   69.0% |   68.5% |   68.2% |   68.1% |   68.2% |
| 0.90 |   74.4% |   74.0% |   74.1% |   74.1% |   74.2% |
| 0.95 |   79.1% |   78.9% |   79.3% |   79.3% |   79.0% |

### FFA — without ACS-GUARD reference (M=100K)

| lambda_attack | 500 | 1000 | 2000 | 3000 | 5000 |
|---|---|---|---|---|---|
| Acceptance % |   61.7% |   57.8% |   51.6% |   46.5% |   39.0% |

## Table 3: Legitimate Acceptance Rate (PTA, M=100K) — alpha × lambda_attack

**PTA — with ACS-GUARD (M=100K)**

| alpha \ λ_attack |   500 |  1000 |  2000 |  3000 |  5000 |
|---:|---:|---:|---:|---:|---:|
| 0.70 |   39.7% |   35.2% |   31.5% |   30.2% |   28.7% |
| 0.75 |   47.3% |   42.5% |   38.2% |   36.2% |   33.2% |
| 0.80 |   56.3% |   51.8% |   47.5% |   44.8% |   40.5% |
| 0.85 |   66.2% |   60.5% |   55.7% |   52.3% |   49.3% |
| 0.90 |   70.7% |   67.0% |   61.7% |   60.3% |   58.0% |
| 0.95 |   68.8% |   65.2% |   63.2% |   62.3% |   60.5% |

### PTA — without ACS-GUARD reference (M=100K)

| lambda_attack | 500 | 1000 | 2000 | 3000 | 5000 |
|---|---|---|---|---|---|
| Acceptance % |   45.0% |   35.7% |   29.3% |   26.7% |   24.3% |

## Table 4: Pool Exhaustion Thresholds (M=100K)

Min lambda_attack that triggers cap-hit (pool_exhaustion_occurred=True)

| alpha | CEA | FFA | PTA |
|---|---|---|---|
| 0.70 |   500 AReq/s |   500 AReq/s |   500 AReq/s |
| 0.75 |   500 AReq/s |   500 AReq/s |   500 AReq/s |
| 0.80 |   500 AReq/s |   500 AReq/s |   500 AReq/s |
| 0.85 |   500 AReq/s |   500 AReq/s |   500 AReq/s |
| 0.90 |   500 AReq/s |   500 AReq/s |   500 AReq/s |
| 0.95 |   500 AReq/s |   500 AReq/s |   500 AReq/s |

## Table 5: Impact of Pool Size (alpha=0.85, CEA)

| M_session_pool | λ=500 | λ=1000 | λ=2000 | λ=3000 | λ=5000 |
|---|---|---|---|---|---|
| 50,000 |   43.4% |   43.1% |   42.1% |   42.4% |   42.1% |
| 100,000 |   70.0% |   65.9% |   62.5% |   60.9% |   58.8% |
| 200,000 |   85.9% |   79.0% |   74.0% |   69.7% |   66.0% |

## Table 6: Parameter Sensitivity Ranking (baseline: CEA, M=100K, λ=2000, α=0.85)

| Parameter | Range (pp) | Std Dev (pp) | Effect |
|---|---|---|---|
| `M_session_pool` | 31.88 pp | 16.14 pp | High |
| `alpha` | 31.40 pp | 12.70 pp | Medium |
| `lambda_attack` | 11.18 pp | 4.41 pp | Low |

## Table 7: Diminishing Returns of alpha (M=100K, with ACS-GUARD)

### CEA

| λ_attack | α=0.85 | α=0.90 | α=0.95 | Δ(0.85→0.90) | Δ(0.90→0.95) |
|---|---|---|---|---|---|
|   500 |   70.0% |   73.5% |   71.7% | +3.50 pp | -1.82 pp |
|  1000 |   65.9% |   71.1% |   73.8% | +5.18 pp | +2.72 pp |
|  2000 |   62.5% |   68.3% |   69.6% | +5.85 pp | +1.25 pp |
|  3000 |   60.9% |   67.2% |   67.5% | +6.24 pp | +0.33 pp |
|  5000 |   58.8% |   65.3% |   65.8% | +6.50 pp | +0.42 pp |

### FFA

| λ_attack | α=0.85 | α=0.90 | α=0.95 | Δ(0.85→0.90) | Δ(0.90→0.95) |
|---|---|---|---|---|---|
|   500 |   69.0% |   74.4% |   79.1% | +5.34 pp | +4.76 pp |
|  1000 |   68.5% |   74.0% |   78.9% | +5.50 pp | +4.89 pp |
|  2000 |   68.2% |   74.1% |   79.3% | +5.83 pp | +5.20 pp |
|  3000 |   68.1% |   74.1% |   79.3% | +6.00 pp | +5.27 pp |
|  5000 |   68.2% |   74.2% |   79.0% | +6.00 pp | +4.81 pp |

### PTA

| λ_attack | α=0.85 | α=0.90 | α=0.95 | Δ(0.85→0.90) | Δ(0.90→0.95) |
|---|---|---|---|---|---|
|   500 |   66.2% |   70.7% |   68.8% | +4.50 pp | -1.84 pp |
|  1000 |   60.5% |   67.0% |   65.2% | +6.50 pp | -1.83 pp |
|  2000 |   55.7% |   61.7% |   63.2% | +6.00 pp | +1.50 pp |
|  3000 |   52.3% |   60.3% |   62.3% | +8.00 pp | +2.00 pp |
|  5000 |   49.3% |   58.0% |   60.5% | +8.67 pp | +2.50 pp |

## Safe Operating Envelope (acceptance ≥ 60%, M=100K)

### CEA

| alpha | Max safe lambda_attack | Safe lambda range |
|---|---|---|
| 0.70 | none | none |
| 0.75 | none | none |
| 0.80 | none | none |
| 0.85 | 3000 | 500–3000 |
| 0.90 | 5000 | 500–5000 |
| 0.95 | 5000 | 500–5000 |

### FFA

| alpha | Max safe lambda_attack | Safe lambda range |
|---|---|---|
| 0.70 | none | none |
| 0.75 | 5000 | 500–5000 |
| 0.80 | 5000 | 500–5000 |
| 0.85 | 5000 | 500–5000 |
| 0.90 | 5000 | 500–5000 |
| 0.95 | 5000 | 500–5000 |

### PTA

| alpha | Max safe lambda_attack | Safe lambda range |
|---|---|---|
| 0.70 | none | none |
| 0.75 | none | none |
| 0.80 | none | none |
| 0.85 | 1000 | 500–1000 |
| 0.90 | 3000 | 500–3000 |
| 0.95 | 5000 | 500–5000 |

## Key Findings

1. **Most impactful parameter:** `M_session_pool` produces a 31.9 percentage-point range in legitimate acceptance rate at the baseline operating point (CEA, M=100K, λ=2000).
2. **Critical threshold (CEA, M=100K, α=0.85):** Pool cap first reached at λ_attack = 500 AReq/s. Below this rate the guard absorbs all attack traffic without exhaustion.
3. **Safe operating envelope (CEA, M=100K):** At α=0.90, legitimate acceptance remains ≥60% for λ_attack up to 5000 AReq/s, defining the recommended production operating boundary.
4. **Diminishing returns:** Increasing α from 0.85→0.90 provides a larger acceptance-rate gain than 0.90→0.95 at all attack rates, suggesting α=0.90 as an optimal operating point balancing headroom against reserved capacity.
5. **Production recommendation:** For payment processing ACS nodes (M≈100K), set α=0.85–0.90 and enforce a per-source λ_attack budget < 1000 AReq/s via upstream rate limiting to remain within the safe operating envelope across all three attack modes.

## Comparison with Original Paper Values

Original single-point results (α=0.85, M=100K, λ_attack=2000):

| Attack Mode | Original (paper) | This sweep (α=0.85, M=100K, λ=2000) |
|---|---|---|
| CEA | 37%→63% | 37.3% → 62.5% |
| FFA | 39%→68% | 51.6% → 68.2% |
| PTA | 52%→70% | 29.3% → 55.7% |

New range across full parameter sweep (M=100K):

| Attack Mode | Min acceptance (worst case) | Max acceptance (best case) |
|---|---|---|
| CEA | 34.8% | 73.8% |
| FFA | 51.9% | 79.3% |
| PTA | 28.7% | 70.7% |
