"""
Cross-Layer Composite Score (CLCS) Engine — TIG-CDO Component 2

Aggregates normalized anomaly scores from five defense layers using a
TCS-amplified weighted sum into a single composite attack indicator.

CLCS Formula (from paper Section IV-D):

    CLCS(t) = min(1.0, W(t) · A(TCS_b))

    where:
      W(t)    = Σᵢ wᵢ_base · sᵢ(t)      [base weighted sum]
      A(TCS)  = 1 + β · (1 - TCS_b)      [TCS amplification factor, β ≈ 4.5]

The TCS acts as a multiplicative amplifier. When TCS_b is low (incoherent
transaction sequences — CSDA Phase 3), A(TCS) inflates the composite score,
enabling detection of composite attacks where no individual layer score
exceeds its standalone threshold (θᵢ = 0.50 for all layers).

Calibration:
  - β = 4.5 such that at TCS=0.23 with CSDA Phase 3 scores
    [s1=0.12, s2=0.18, s3=0.22, s4=0.31, s5=0.14], CLCS = 0.87 > θ_CLCS.
  - At TCS=0.92 (legitimate), CLCS ≈ 0.10 (below threshold → no false positive).

Layer scores:
  s₁ = WAF anomaly score (normalized [0,1])
  s₂ = LBMD inline ML score (XGBoost probability, P99=0.170ms)
  s₃ = BIN-WATCH entropy deviation (BES normalized vs baseline)
  s₄ = ACS-GUARD session ratio (active/cap)
  s₅ = HPA scaling delta (current pods / baseline pods - 1, clamped [0,1])

Threshold θ_CLCS = 0.75 is a configured value (v1.3.0: earlier comments said it
came from a ROC analysis on a 54-scenario validation set; no such analysis exists
in this package).
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import time

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Layer score input structure
# ---------------------------------------------------------------------------

@dataclass
class LayerScores:
    """Normalized anomaly scores from all five defense layers at time t."""
    timestamp: float
    s1_waf: float           # [0, 1] WAF rule match severity
    s2_lbmd: float          # [0, 1] LBMD XGBoost attack probability
    s3_bin_watch: float     # [0, 1] BIN entropy deviation (BES normalized)
    s4_acs_guard: float     # [0, 1] ACS session pool ratio (active/cap)
    s5_hpa_delta: float     # [0, 1] HPA scaling delta (pods/baseline_pods - 1, clamped)
    bin_prefix: Optional[str] = None  # for TCS lookup

    def as_vector(self) -> List[float]:
        return [self.s1_waf, self.s2_lbmd, self.s3_bin_watch,
                self.s4_acs_guard, self.s5_hpa_delta]

# ---------------------------------------------------------------------------
# CLCS configuration
# ---------------------------------------------------------------------------

@dataclass
class CLCSConfig:
    # Static baseline weights for each layer (must sum to 1.0)
    w_base: List[float] = field(default_factory=lambda: [0.20, 0.25, 0.20, 0.20, 0.15])
    # TCS amplification factor β
    # Calibrated: at TCS=0.23, Phase 3 scores → CLCS=0.87
    # Derivation: W_phase3 = 0.196; A = 1 + β*(1-0.23) = 4.46 → β ≈ 4.5
    beta_tcs: float = 4.5
    # Detection threshold (configured; see module docstring)
    theta_clcs: float = 0.75
    # Individual layer standalone thresholds
    theta_individual: List[float] = field(default_factory=lambda: [0.50, 0.50, 0.50, 0.50, 0.50])
    # Layer names for reporting
    layer_names: List[str] = field(default_factory=lambda: [
        "WAF", "LBMD(XGBoost)", "BIN-WATCH", "ACS-GUARD", "HPA-delta"
    ])

    def __post_init__(self):
        assert abs(sum(self.w_base) - 1.0) < 1e-9, "Baseline weights must sum to 1.0"
        assert len(self.w_base) == 5

# ---------------------------------------------------------------------------
# CLCS result
# ---------------------------------------------------------------------------

@dataclass
class CLCSResult:
    timestamp: float
    clcs: float
    triggered: bool                    # CLCS > θ_CLCS
    base_weighted_sum: float           # W(t) = Σ wᵢ · sᵢ
    tcs_amplification: float           # A(TCS) = 1 + β·(1-TCS)
    layer_scores: List[float]
    tcs: float
    bin_prefix: Optional[str]
    individual_exceeded: List[bool]    # which layers exceeded standalone threshold
    composite_only: bool               # True if composite triggered but no individual did
    detection_note: str = ""

# ---------------------------------------------------------------------------
# CLCS Engine
# ---------------------------------------------------------------------------

class CLCSEngine:
    """
    Evaluates the Cross-Layer Composite Score every evaluation cycle.
    Consumes LayerScores objects and TCS values from the STC.
    """

    def __init__(self, config: Optional[CLCSConfig] = None):
        self.config = config or CLCSConfig()
        self.history: List[CLCSResult] = []
        self._activation_count = 0

    def compute_amplification(self, tcs: float) -> float:
        """A(TCS) = 1 + β · (1 - TCS)"""
        return 1.0 + self.config.beta_tcs * (1.0 - tcs)

    def evaluate(self, scores: LayerScores, tcs: float) -> CLCSResult:
        """
        Compute CLCS for the given layer scores and TCS value.

        CLCS = min(1.0, W · A(TCS))
        where W = Σᵢ wᵢ_base · sᵢ and A(TCS) = 1 + β·(1-TCS)
        """
        cfg = self.config
        s_vec = scores.as_vector()

        # Base weighted sum
        w_sum = sum(cfg.w_base[i] * s_vec[i] for i in range(5))

        # TCS amplification
        amplification = self.compute_amplification(tcs)

        # CLCS (capped at 1.0)
        clcs = min(1.0, w_sum * amplification)
        triggered = clcs > cfg.theta_clcs

        individual_exceeded = [s_vec[i] > cfg.theta_individual[i] for i in range(5)]
        composite_only = triggered and not any(individual_exceeded)

        if triggered:
            self._activation_count += 1

        note = ""
        if composite_only:
            note = (
                "COMPOSITE DETECTION: CLCS triggered but no individual layer exceeded "
                "standalone threshold — classic CSDA Phase 3 signature. "
                f"W={w_sum:.3f}, A(TCS={tcs:.2f})={amplification:.2f}, "
                f"CLCS={clcs:.3f} > θ={cfg.theta_clcs}."
            )
        elif triggered:
            exceeding = [cfg.layer_names[i] for i, ex in enumerate(individual_exceeded) if ex]
            note = f"Triggered. Individual exceedances: {exceeding}. CLCS={clcs:.3f}."

        result = CLCSResult(
            timestamp=scores.timestamp,
            clcs=clcs,
            triggered=triggered,
            base_weighted_sum=w_sum,
            tcs_amplification=amplification,
            layer_scores=s_vec,
            tcs=tcs,
            bin_prefix=scores.bin_prefix,
            individual_exceeded=individual_exceeded,
            composite_only=composite_only,
            detection_note=note,
        )
        self.history.append(result)
        return result

    def evaluate_batch(
        self,
        scores_list: List[LayerScores],
        tcs_by_bin: Dict[str, float],
        default_tcs: float = 1.0,
    ) -> List[CLCSResult]:
        """Evaluate a batch of layer score samples."""
        results = []
        for scores in scores_list:
            tcs = tcs_by_bin.get(scores.bin_prefix, default_tcs) if scores.bin_prefix else default_tcs
            results.append(self.evaluate(scores, tcs))
        return results

    def summary(self) -> Dict:
        if not self.history:
            return {"evaluations": 0}
        clcs_vals = [r.clcs for r in self.history]
        triggered = [r for r in self.history if r.triggered]
        composite_only = [r for r in triggered if r.composite_only]
        return {
            "evaluations": len(self.history),
            "activations": self._activation_count,
            "composite_only_detections": len(composite_only),
            "clcs_mean": sum(clcs_vals) / len(clcs_vals),
            "clcs_max": max(clcs_vals),
            "clcs_min": min(clcs_vals),
        }


# ---------------------------------------------------------------------------
# Detection mode comparison helper (Table VIII)
# ---------------------------------------------------------------------------

def compare_detection_modes(
    scores_list: List[LayerScores],
    tcs_by_bin: Dict[str, float],
    config: Optional[CLCSConfig] = None,
) -> Dict:
    """
    Compare detection performance under three CLCS configurations:
    1. Static equal weights, no TCS amplification
    2. An alternative weight vector, no TCS amplification (v1.3.0: earlier
       comments called it "grid-search optimized"; no search exists in this
       package, the vector is illustrative)
    3. TCS-amplified CLCS (TIG-CDO)
    For population-level comparisons of fusion rules see fusion_score() and
    experiments/d0b_fusion_ablation.py.
    """
    cfg = config or CLCSConfig()

    equal_cfg = CLCSConfig(
        w_base=[0.20, 0.20, 0.20, 0.20, 0.20],
        beta_tcs=0.0,  # no amplification
    )
    optimized_cfg = CLCSConfig(
        w_base=[0.18, 0.27, 0.22, 0.21, 0.12],  # illustrative alternative weights
        beta_tcs=0.0,
    )

    results = {}
    for name, engine_cfg in [("equal", equal_cfg), ("optimized", optimized_cfg), ("tcs_amplified", cfg)]:
        engine = CLCSEngine(config=engine_cfg)
        engine.evaluate_batch(scores_list, tcs_by_bin)
        results[name] = engine.summary()

    return results


# ---------------------------------------------------------------------------
# Fusion rules for the formula-level comparison (v1.3.0, review R3-011, D0-b)
# ---------------------------------------------------------------------------

FUSION_MODES = ("weighted", "multiplicative", "additive", "or_path", "coherence_only")


def fusion_score(mode: str, s_vec: List[float], tcs: float, w: Optional[List[float]] = None,
                 beta: float = 4.5, gamma: float = 1.0) -> float:
    """Score of one fusion rule; each rule is then thresholded at a value chosen
    for a target false-positive rate.
      weighted:        W = sum_i w_i s_i (no coherence)
      multiplicative:  min(1, W * (1 + beta (1 - TCS)))   (TIG-CDO, Eq. CLCS)
      additive:        W + gamma (1 - TCS)
      or_path:         max(W, 1 - TCS)  (two activation paths on one scale)
      coherence_only:  max(max_i s_i, 1 - TCS)  (any single signal, coherence included)
    """
    w = w or [0.20, 0.25, 0.20, 0.20, 0.15]
    W = sum(wi * si for wi, si in zip(w, s_vec))
    if mode == "weighted":
        return W
    if mode == "multiplicative":
        return min(1.0, W * (1.0 + beta * (1.0 - tcs)))
    if mode == "additive":
        return W + gamma * (1.0 - tcs)
    if mode == "or_path":
        return max(W, 1.0 - tcs)
    if mode == "coherence_only":
        return max(max(s_vec), 1.0 - tcs)
    raise ValueError(mode)


# ---------------------------------------------------------------------------
# Demo / self-test
# ---------------------------------------------------------------------------

def _demo():
    import random
    random.seed(42)
    logging.basicConfig(level=logging.INFO)

    cfg = CLCSConfig()
    engine = CLCSEngine(config=cfg)
    now = time.time()

    # === Verify β calibration ===
    print("\n=== CLCS β Calibration Verification ===")
    print("Paper claim: at TCS=0.23 with Phase 3 scores [0.12,0.18,0.22,0.31,0.14], CLCS=0.87")
    phase3_scores = LayerScores(
        timestamp=now, s1_waf=0.12, s2_lbmd=0.18, s3_bin_watch=0.22,
        s4_acs_guard=0.31, s5_hpa_delta=0.14, bin_prefix="555555"
    )
    phase3_result = engine.evaluate(phase3_scores, tcs=0.23)
    print(f"W(t) = {phase3_result.base_weighted_sum:.4f}")
    print(f"A(TCS=0.23) = {phase3_result.tcs_amplification:.4f}")
    print(f"CLCS = {phase3_result.clcs:.4f}  (paper: 0.87)")
    print(f"Triggered: {phase3_result.triggered}")
    print(f"Composite-only: {phase3_result.composite_only}")

    # === Scenario 1: Legitimate traffic — all scores low ===
    print("\n=== Scenario 1: Legitimate Traffic (TCS=0.92) ===")
    legit_scores = [
        LayerScores(
            timestamp=now + i,
            s1_waf=random.uniform(0.02, 0.08),
            s2_lbmd=random.uniform(0.03, 0.10),
            s3_bin_watch=random.uniform(0.02, 0.07),
            s4_acs_guard=random.uniform(0.10, 0.20),
            s5_hpa_delta=random.uniform(0.01, 0.05),
            bin_prefix="411111",
        )
        for i in range(2500)  # 2500 legitimate evaluations (paper: 2500 1-hour windows)
    ]
    tcs_legit = {"411111": 0.92}
    legit_results = engine.evaluate_batch(legit_scores, tcs_legit)
    legit_triggered = sum(1 for r in legit_results if r.triggered)
    fpr = legit_triggered / len(legit_results) * 100
    print(f"False activations: {legit_triggered}/2500 ({fpr:.3f}%)  (paper: 0.08% = 2/2500)")

    # === Table VIII comparison ===
    all_scenarios = legit_scores + [phase3_scores]
    tcs_all = {"411111": 0.92, "555555": 0.23}
    comparison = compare_detection_modes(all_scenarios, tcs_all)
    print("\n=== Table VIII: CLCS Weight Configuration Comparison ===")
    for mode, stats in comparison.items():
        print(f"  {mode:20s}: activations={stats['activations']}, "
              f"composite_only={stats['composite_only_detections']}, "
              f"clcs_max={stats['clcs_max']:.3f}")

    # Assertions
    assert phase3_result.triggered, f"CLCS should trigger: {phase3_result.clcs:.3f}"
    assert phase3_result.composite_only, "Should be composite-only"
    assert not any(phase3_result.individual_exceeded), "No individual should exceed θ=0.50"
    assert abs(phase3_result.clcs - 0.87) < 0.05, f"CLCS should be ≈0.87: got {phase3_result.clcs:.3f}"
    assert fpr < 1.0, f"FPR on legitimate traffic too high: {fpr:.3f}%"
    print("\nAll assertions passed.")


if __name__ == "__main__":
    _demo()
