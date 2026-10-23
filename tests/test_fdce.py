"""Unit tests for the v1.3.0 FDCE detector (reviews R3-003, R3-004), PADO (R3-015)
and PSRG (R3-014)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fdce.fdce import FDCEDetector  # noqa: E402
from fdce.scenario import simulate_fdce_scenario, OrganicProfile, simulate  # noqa: E402


def feed(det, m, b, n, rate, code, start=0.0, capture_delay=None, prefix="t"):
    """n authorizations from merchant m in BIN b at `rate` per second."""
    caps = []
    for i in range(n):
        ts = start + i / rate
        tid = f"{prefix}{i}"
        det.observe_auth_request(m, ts, tid)
        det.observe_auth_response(b, ts, code, m, tid)
        if capture_delay is not None and code == "00":
            caps.append((ts + capture_delay, tid))
        caps.sort()
        while caps and caps[0][0] <= ts:
            t, x = caps.pop(0)
            det.observe_completion(m, t, x)
        det.check_r11(b, ts)
        det.check_r12(m, ts)
    return det


def test_r12_delayed_capture_does_not_fire():
    """R3-004: approved authorizations whose 0220 arrives 45 s later must not look
    like failures (v1.2 fired on every such merchant)."""
    det = FDCEDetector(flow="dual_0220", r11c_delta=9.0)
    feed(det, "m1", "B1", 600, 3.0, "00", capture_delay=45.0)
    assert det.r12_fires == []


def test_r12_same_window_estimator_fires_on_delayed_capture():
    det = FDCEDetector(flow="dual_0220", r12_estimator="same_window", r11c_delta=9.0)
    feed(det, "m1", "B1", 600, 3.0, "00", capture_delay=70.0)
    assert det.r12_fires, "the v1.2 estimator is expected to false-fire here"


def test_r12_fires_on_declines_above_gate():
    det = FDCEDetector(flow="dual_0220", r11c_delta=9.0)
    feed(det, "bot", "B1", 300, 3.0, "54")
    assert det.r12_fires and det.r12_fires[0][1] < 60.0


def test_r12_lagged_cohort_waits_for_deadline():
    det = FDCEDetector(flow="single", r12_estimator="lagged_cohort", r11c_delta=9.0)
    feed(det, "bot", "B1", 300, 3.0, "54")
    assert det.r12_fires and det.r12_fires[0][1] >= 5.0


def test_r12_counts_reversal_as_non_completion():
    det = FDCEDetector(flow="single", r11c_delta=9.0)
    for i in range(300):
        ts = i / 3.0
        tid = f"r{i}"
        det.observe_auth_request("m", ts, tid)
        det.observe_auth_response("B", ts, "00", "m", tid)
        det.observe_reversal("m", ts + 0.01, tid)
        det.check_r12("m", ts + 0.01)
    assert det.r12_fires


def test_r11_baseline_excess_ignores_heavy_05_51_family():
    det = FDCEDetector(baseline_init={"B": 0.40})
    import random
    rng = random.Random(1)
    for i in range(3000):
        ts = i / 5.0
        code = ("05" if rng.random() < 0.6 else "51") if rng.random() < 0.40 else "00"
        det.observe_auth_response("B", ts, code)
        det.check_r11("B", ts)
    assert det.r11_fires == []


def test_r11_baseline_excess_ignores_issuer_outage_91():
    det = FDCEDetector(baseline_init={"B": 0.10})
    for i in range(1000):
        det.observe_auth_response("B", i / 5.0, "91")
        det.check_r11("B", i / 5.0)
    assert det.r11_fires == []


def test_r11_fires_on_substitution_declines():
    det = FDCEDetector(baseline_init={"B": 0.10})
    for i in range(200):
        det.observe_auth_response("B", i / 5.0, "05" if i % 2 else "51")
        det.check_r11("B", i / 5.0)
    assert det.r11_fires


def test_block_expires_and_is_re_earned():
    det = FDCEDetector(block_ttl_s=100.0, baseline_init={"B": 0.10})
    for i in range(50):
        det.observe_auth_response("B", i * 0.1, "54")
        det.check_r11("B", i * 0.1)
    assert det.is_blocked("B", "m", 10.0)
    assert not det.is_blocked("B", "m", 200.0)


def test_scenario_no_look_ahead_and_spread_adversary_runs_whole_window():
    r = simulate_fdce_scenario(50, "spread", 0.2, seed=7, flow="dual_0220")
    assert r.detection_latency_s is not None
    assert r.n_organic_r12_false_positives == 0


def test_organic_only_zipf_no_r12_false_fires_censoring_bound():
    r = simulate(None, OrganicProfile(kind="zipf", n_bins=50, n_merchants=50, total_tps=40.0,
                                      new_merchant_share=0.3), seed=3, duration_s=900.0, flow="dual_0220")
    assert r.organic_r12_false_fires == 0


def test_pado_phase1_reachable_and_stamp():
    from pado.pado import PreAuthorizedDefenseOrchestrator, TIGContext
    p = PreAuthorizedDefenseOrchestrator()
    assert len(p.catalog) == 12
    ctx = TIGContext(timestamp=0.0, clcs=0.40, tcs_distribution={"x": 0.20}, mean_tcs=0.2, min_tcs=0.2,
                     active_vectors={"bin_recon"}, bim_alarm_active=False, hpa_scaling_active=False, tps_tier="1k")
    rec = p.activate(ctx, current_sla_pct=50.0, current_tps=500.0)
    assert rec is not None and rec.bundle_id.startswith("BUNDLE-PHASE1")
    assert rec.governance_dora_article == "DORA Art. 11(2)(c)"


def test_psrg_unseen_prior_and_history():
    from psrg.psrg import PaymentSemanticRateGovernor
    g = PaymentSemanticRateGovernor(r_base_per_s=100.0)
    ok, cid, rate = g.allow_request("1.1.1.1", "123456", 0.0)
    assert rate == 50.0      # unseen context: prior 0.5
